#pragma once
#include <cstdint>
#include <span>

namespace hook
{
	bool init() noexcept;

	bool install(std::uintptr_t target_va,
	             std::span<const std::uint8_t> pre_asm,
	             std::span<const std::uint8_t> post_asm,
	             bool monitor) noexcept;

	// user-mode-capable minimal hook: shadow page with one 0xCC byte at target_va,
	// reads through target_va return the original bytes (integrity scans safe),
	// executions hit INT3. target_cr3 maps the target va in a foreign process; a
	// VEH in that process is responsible for catching the #BP and resuming.
	bool install_int3(std::uintptr_t target_va, std::uint64_t target_cr3) noexcept;

	bool remove(std::uintptr_t target_va) noexcept;
}
