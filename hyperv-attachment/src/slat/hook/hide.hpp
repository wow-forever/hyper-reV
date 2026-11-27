#pragma once
#include "../../arch/defs.hpp"

#include <cstddef>

struct boot_info;

namespace slat::hook
{
	// takes the ranges that have to be kept out of the guest's sight
	void init_hide(const boot_info& bi) noexcept;

	// points a guest physical range at a zero page, in every root that exists
	bool hide(phys_addr gpa, std::size_t page_count = 1) noexcept;

	bool hide_heap() noexcept;

	// lazily allocates (first call) a single shared host page full of zeros
	// and returns its host physical address. Used by both hide() (for
	// hiding HV-internal pages) and cloak_add() (for Core cloak).
	phys_addr ensure_zero_page_hpa() noexcept;
}
