#include "cloak.hpp"
#include "hide.hpp"
#include "info.hpp"
#include "../cr3/cr3.hpp"
#include "../cr3/split.hpp"
#include "../../arch/current.hpp"
#include "cache.hpp"

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

		cloak_list.push_front({ gpa, original_hpa, 0 });
	}

	cache::flush_all();
	return true;
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
