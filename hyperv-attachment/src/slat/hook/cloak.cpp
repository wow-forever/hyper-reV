#include "cloak.hpp"
#include "hide.hpp"
#include "info.hpp"
#include "../cr3/cr3.hpp"
#include "../cr3/split.hpp"
#include "../../arch/current.hpp"
#include "cache.hpp"

#include <intrin.h>

namespace
{
	// Factored out of hook::add — we need the same "shadow EPT exists" guarantee.
	// If no hook / cloak has been added before, the shadow root hasn't been
	// deep-copied yet. Lazy init on first cloak.
	bool ensure_shadow_root() noexcept
	{
		if (slat::cr3::shadow.flags)
			return true;

		slat::cr3::init_shadow();
		if (!slat::cr3::shadow.flags)
			return false;

		// init_shadow() strips X from every entry. We also need HV heap hidden
		// in the shadow root so a page walk from a cloaked region can't see it.
		return slat::hook::hide_heap();
	}

	// ----- CR3 "last seen on any VCPU" map ----------------------------------
	//
	// Small direct-mapped array. Every VMEXIT writes {current-cr3-pfn, tsc}
	// to its hash slot. Lookup from the sweeper tests "is the slot still
	// tagged with this cr3, and how fresh is its tsc?".
	//
	// Collisions are tolerated because they resolve to a different cr3 on
	// lookup — cr3_map_get_tsc returns 0 ("never seen") when the slot now
	// holds some other CR3. Benign: worst case the cloak sweep expires a
	// still-alive cloak slightly early; the installing process just re-adds.
	//
	// 64 slots × 16 bytes = 1 KiB. Direct-mapped → O(1) touch, no allocations.
	constexpr std::size_t   kCr3MapSize = 64;
	constexpr std::uint64_t kCr3MapMask = kCr3MapSize - 1;

	struct cr3_slot
	{
		std::uint64_t cr3_pfn;   // 0 = empty
		std::uint64_t tsc;
	};

	cr3_slot g_cr3_map[kCr3MapSize] = {};

	constexpr std::size_t slot_index(const std::uint64_t cr3_pfn) noexcept
	{
		return (cr3_pfn >> page_shift) & kCr3MapMask;
	}

	std::uint64_t cr3_map_get_tsc(const std::uint64_t cr3_pfn) noexcept
	{
		const auto& slot = g_cr3_map[slot_index(cr3_pfn)];
		return (slot.cr3_pfn == cr3_pfn) ? slot.tsc : 0;
	}

	// ----- TTL / sweep tuning ------------------------------------------------
	//
	// Baseline 2 GHz for the TSC rate. On anything faster (Alder Lake base is
	// ~2.5 GHz and runs well above that most of the time) this maps to a
	// SHORTER real-time window, which is the conservative direction — cleanup
	// just happens a bit sooner. We never rely on the exact wall-clock value.
	constexpr std::uint64_t kTscPerMs          = 2'000'000ull;
	constexpr std::uint64_t kSweepIntervalTsc  = 500  * kTscPerMs; // ≈ 500 ms
	constexpr std::uint64_t kCr3TtlTsc         = 2000 * kTscPerMs; // ≈ 2 s

	std::uint64_t g_last_sweep_tsc = 0;

	// Walks cloak_list under cloak_mtx and removes any entry whose
	// installer_cr3 has not been touched in the TTL window. Flushes EPT
	// cache once at the end if anything was removed.
	void cloak_sweep(const std::uint64_t now_tsc) noexcept
	{
		std::size_t removed = 0;

		{
			cstd::lock_guard guard(slat::hook::cloak_mtx);

			slat::hook::cloak_list.remove_if(
				[now_tsc, &removed](const slat::hook::info& entry)
			{
				// Defensive: an entry without a recorded CR3 can't be judged
				// stale. Should not happen for cloak entries after this fix,
				// but if it does, leave it alone.
				if (entry.installer_cr3 == 0)
					return false;

				const auto cr3_tsc = cr3_map_get_tsc(entry.installer_cr3);
				const bool stale =
					(cr3_tsc == 0) ||                      // never seen / evicted
					(now_tsc - cr3_tsc > kCr3TtlTsc);      // too long since seen

				if (!stale)
					return false;

				// Same EPT restoration as cloak_remove: put the hyperv entry
				// back to original HPA + RWX, and drop shadow back to RW.
				if (auto* orig_pte = slat::cr3::find_split_leaf(slat::cr3::hyperv, entry.gpa))
				{
					orig_pte->page_frame_number = entry.original_hpa >> page_shift;
					arch::slat_set_perm(*orig_pte, page_perm::rwx);
				}
				if (auto* shadow_pte = slat::cr3::find_split_leaf(slat::cr3::shadow, entry.gpa))
				{
					arch::slat_set_perm(*shadow_pte, page_perm::rw);
				}

				++removed;
				return true;
			});
		}

		if (removed > 0)
			slat::cache::flush_all();
	}
}

bool slat::hook::cloak_add(const phys_addr gpa) noexcept
{
	if (!ensure_shadow_root())
		return false;

	const auto zero_hpa = ensure_zero_page_hpa();
	if (!zero_hpa)
		return false;

	{
		cstd::lock_guard guard(cloak_mtx);

		// Already cloaked? idempotent — treat as success.
		for (const auto& entry : cloak_list)
		{
			if (entry.gpa == gpa)
				return true;
		}

		// hyperv EPT: redirect to zero PFN with R-only. Reads see zeros,
		// writes/executes violate. Execute violation bounces to shadow via
		// the existing slat::violation::handle protocol (which also walks
		// cloak_list; see violation.cpp).
		auto* orig_pte = cr3::find_split_leaf(cr3::hyperv, gpa);
		if (!orig_pte)
			return false;

		const auto original_hpa = orig_pte->page_frame_number << page_shift;

		orig_pte->page_frame_number = zero_hpa >> page_shift;
		arch::slat_set_perm(*orig_pte, page_perm::read);

		// shadow EPT: original PFN (was already set by deep_copy, but the
		// deep_copy may have set the 2 MB large PDE that would get split
		// here for the first time — grab the leaf and make sure it points
		// at the ORIGINAL HPA, not whatever the shadow page frame happened
		// to be prior). Permission RWX so the owning code runs real bytes.
		auto* shadow_pte = cr3::find_split_leaf(cr3::shadow, gpa);
		if (!shadow_pte)
		{
			// Roll back the hyperv change to leave the EPT consistent.
			orig_pte->page_frame_number = original_hpa >> page_shift;
			arch::slat_set_perm(*orig_pte, page_perm::rwx);
			return false;
		}

		shadow_pte->page_frame_number = original_hpa >> page_shift;
		arch::slat_set_perm(*shadow_pte, page_perm::rwx);

		const auto installer_cr3 = arch::guest_cr3().flags & ~0xFFFull;
		cloak_list.push_front({ gpa, original_hpa, 0, installer_cr3, __rdtsc() });
	}

	cache::flush_all();
	return true;
}

// ----- Lifetime-tracking exports called from vmexit::detour ------------------

void slat::hook::cr3_map_touch(const std::uint64_t cr3, const std::uint64_t tsc) noexcept
{
	const auto cr3_pfn = cr3 & ~0xFFFull;
	if (cr3_pfn == 0) return;  // defensive — invalid/boot-time

	// Lock-free: direct-mapped store. Benign races (last writer wins) are OK:
	// the sweep only uses this as "proof of life", not for correctness.
	auto& slot = g_cr3_map[slot_index(cr3_pfn)];
	slot.cr3_pfn = cr3_pfn;
	slot.tsc = tsc;
}

void slat::hook::cloak_sweep_if_due(const std::uint64_t now_tsc) noexcept
{
	if (now_tsc - g_last_sweep_tsc < kSweepIntervalTsc)
		return;

	g_last_sweep_tsc = now_tsc;
	cloak_sweep(now_tsc);
}

bool slat::hook::cloak_remove(const phys_addr gpa) noexcept
{
	bool found = false;

	{
		cstd::lock_guard guard(cloak_mtx);

		cloak_list.remove_if([gpa, &found](const info& entry)
		{
			if (entry.gpa != gpa)
				return false;

			found = true;

			// hyperv EPT: restore original HPA and RWX. The PFN was pointing
			// to the shared zero page; flip it back and re-enable X.
			if (auto* orig_pte = cr3::find_split_leaf(cr3::hyperv, gpa))
			{
				orig_pte->page_frame_number = entry.original_hpa >> page_shift;
				arch::slat_set_perm(*orig_pte, page_perm::rwx);
			}

			// shadow EPT: drop X back to the post-deep_copy state (RW only
			// on non-hooked / non-cloaked pages). Original HPA was already
			// correct from the deep_copy — only the perm changed.
			if (auto* shadow_pte = cr3::find_split_leaf(cr3::shadow, gpa))
			{
				arch::slat_set_perm(*shadow_pte, page_perm::rw);
			}

			return true;
		});
	}

	if (found)
		cache::flush_all();

	return found;
}
