#pragma once
#include "../../arch/defs.hpp"
#include <cstdint>
#include <list.hpp>
#include <mutex.hpp>

namespace slat::hook
{
	struct info
	{
		phys_addr gpa;
		phys_addr original_hpa;
		phys_addr shadow_hpa;    // 0 for cloak entries (unused)

		// Cloak-only lifetime tracking. For hook_add entries both stay 0 and
		// the sweeper in cloak.cpp doesn't walk `list`. installer_cr3 is the
		// guest CR3 (lower 12 bits masked off → PFN) recorded at cloak_add
		// time, and the cloak_sweep walker expires any cloak whose CR3 hasn't
		// appeared on any VCPU for longer than the TTL — proof the installing
		// process has terminated.
		std::uint64_t installer_cr3;
		std::uint64_t last_active_tsc;
	};

	// hook_add/remove entries — hyperv EPT: original/RW, shadow EPT: shadow_hpa/RWX
	inline cstd::single_linked_list<info> list;
	inline cstd::shared_mutex mtx;

	// cloak_add/remove entries — hyperv EPT: zero/R, shadow EPT: original/RWX
	// Kept separate from `list` because the EPT state (and therefore the
	// restore logic in remove) is inverted. shadow_hpa is unused for cloaks.
	inline cstd::single_linked_list<info> cloak_list;
	inline cstd::shared_mutex cloak_mtx;
}
