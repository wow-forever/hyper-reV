#pragma once
#include "../../arch/defs.hpp"
#include <list.hpp>
#include <mutex.hpp>

namespace slat::hook
{
	struct info
	{
		phys_addr gpa;
		phys_addr original_hpa;
		phys_addr shadow_hpa;    // 0 for cloak entries (unused)
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
