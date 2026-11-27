#pragma once
#include "../../arch/defs.hpp"

namespace slat::hook
{
	// Make a guest page "invisible to readers but normally executable":
	//
	//   hyperv EPT (default, non-owning code runs here):
	//     gpa -> zero PFN,  perm = R    (reads return 0, no execute, no write)
	//
	//   shadow EPT (switched to on execute violation, owning code runs here):
	//     gpa -> original HPA,  perm = RWX  (owning code runs real bytes +
	//                                        reads/writes its real data)
	//
	// External scanners that walk memory via the default EPT see zeros for
	// the page, but the owning code (inside a module that runs on this page)
	// executes normally because every instruction fetch on a cloaked page
	// faults from hyperv EPT and the HV switches to shadow EPT where the
	// page is real and executable. The existing EPT-switching protocol
	// (slat::violation::handle + handle_page_split) handles the switch-back.
	//
	// Intended use: cloak every page of Core.dll's mapped image (manual-map
	// anonymous PE) from external memory scans while Core itself keeps
	// running normally. Wired into Core via hc::cloak_add / cloak_remove.
	//
	// Caveats:
	//   - Writes to a cloaked page from the default EPT violate — guests
	//     see an access violation similar to PAGE_NOACCESS. Expected for
	//     external code; do not cloak pages the OS writes to.
	//   - On first cloak_add, the shadow EPT is created on demand (same as
	//     hook_add). VMFUNC / EPT-switching overhead applies.
	//   - No merge: once a page is cloaked the 2 MB large page (if it was
	//     one) is split and stays split until all cloaks on it are removed.
	bool cloak_add(phys_addr gpa) noexcept;

	// Undo cloak_add: restore hyperv EPT entry to the original HPA + RWX,
	// and shadow EPT entry back to its post-deep_copy state (original HPA,
	// RW, no X). Returns true if the page was in the cloak list.
	bool cloak_remove(phys_addr gpa) noexcept;

	// ----- Lifetime tracking (NMI-race fix for stale cloaks) ----------------
	//
	// Problem: a cloak entry that outlives the process that installed it
	// becomes a time bomb — once Windows reassigns the GPA, HV's SLAT-sync
	// NMI path touches a stale guest context and bugchecks with #GP on a
	// non-canonical pointer (`-1`). See notes in cloak.cpp + the write-up.
	//
	// Fix: vmexit::detour calls cr3_map_touch on every VMEXIT to record "this
	// CR3 is still alive". cloak_sweep_if_due periodically walks cloak_list
	// and removes any entry whose installer_cr3 hasn't been touched in the
	// TTL window — i.e. the process is gone.
	//
	// Both calls are safe from VMEXIT root context. cr3_map_touch is lock-free
	// (direct-mapped array, benign races tolerated). cloak_sweep_if_due takes
	// cloak_mtx and flushes the cache once after any removals.
	void cr3_map_touch(std::uint64_t cr3, std::uint64_t tsc) noexcept;
	void cloak_sweep_if_due(std::uint64_t now_tsc) noexcept;
}
