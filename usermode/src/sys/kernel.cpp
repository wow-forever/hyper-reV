#include "kernel.hpp"
#include "dump.hpp"
#include "../nt/kernel_module.hpp"
#include "../util/log.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <optional>
#include <string_view>
#include <thread>
#include <unordered_set>

namespace
{
	// Win11 24H2/25H2 EPROCESS.Pcb.DirectoryTableBase has been at this offset for
	// many generations; validated at probe time by requiring the resolved value
	// to be a sane cr3 (nonzero, below 48-bit phys).
	constexpr std::size_t KPROC_DIRBASE_OFF = 0x28;

	constexpr std::uintptr_t kernel_va_floor = 0xFFFF800000000000ULL;

	struct eproc_layout
	{
		std::size_t name_off  = 0;   // ImageFileName (15 bytes + null)
		std::size_t pid_off   = 0;   // UniqueProcessId (ULONG_PTR, holds HANDLE)
		std::size_t links_off = 0;   // ActiveProcessLinks (LIST_ENTRY)
	};

	// Probes the System EPROCESS to discover per-build EPROCESS field offsets.
	// Returns default-constructed layout on failure.
	eproc_layout probe_layout(const std::uintptr_t system_eproc) noexcept
	{
		eproc_layout l{};

		std::array<std::uint8_t, 0x1000> buf{};
		if (!sys::kern::read<std::uint8_t>(system_eproc, std::span(buf)))
			return {};

		// ImageFileName: "System" null-terminated. First match wins.
		constexpr char sys_name[] = "System";
		for (std::size_t i = 0x100; i + sizeof(sys_name) <= buf.size(); ++i)
		{
			if (std::memcmp(buf.data() + i, sys_name, sizeof(sys_name)) == 0)
			{
				l.name_off = i;
				break;
			}
		}
		if (!l.name_off)
			return {};

		// UniqueProcessId = 4 for System. Scan 8-aligned u64s in a plausible window.
		for (std::size_t i = 0x1C0; i + 8 <= 0x400; i += 8)
		{
			std::uint64_t v;
			std::memcpy(&v, buf.data() + i, 8);
			if (v == 4)
			{
				l.pid_off = i;
				break;
			}
		}
		if (!l.pid_off)
			return {};

		// ActiveProcessLinks: LIST_ENTRY whose Flink points to another EPROCESS's
		// ActiveProcessLinks. Try offsets immediately after UniqueProcessId.
		for (const std::size_t off : { l.pid_off + 8, l.pid_off + 0x10, l.pid_off + 0x18, l.pid_off + 0x20 })
		{
			if (off + 16 > buf.size())
				continue;

			std::uintptr_t flink, blink;
			std::memcpy(&flink, buf.data() + off, 8);
			std::memcpy(&blink, buf.data() + off + 8, 8);
			if (flink < kernel_va_floor || blink < kernel_va_floor)
				continue;

			// Peer validation: peer's Flink should be kernel VA too.
			const auto peer_flink = sys::kern::read<std::uintptr_t>(flink);
			if (peer_flink < kernel_va_floor)
				continue;

			l.links_off = off;
			break;
		}

		return l;
	}

	std::optional<eproc_layout> get_layout(std::uintptr_t& system_eproc) noexcept
	{
		static eproc_layout cached{};
		static std::uintptr_t cached_system = 0;

		// Fast path: once we've resolved the System EPROCESS and probed its
		// layout, both are effectively immutable for the lifetime of this
		// usermode.exe session. Re-reading PsInitialSystemProcess on every
		// call would turn any transient hc::virt_copy failure (e.g. the
		// kernel .data page getting briefly paged out) into a spurious
		// "eproc layout probe failed", even though the previously-probed
		// layout and system_eproc are still correct.
		if (cached_system != 0 && cached.links_off != 0)
		{
			system_eproc = cached_system;
			return cached;
		}

		const auto nt_it = sys::kern::nt();
		if (nt_it == sys::kern::modules_list.end())
			return std::nullopt;

		const auto exp_it = nt_it->second.exports.find("PsInitialSystemProcess");
		if (exp_it == nt_it->second.exports.end())
			return std::nullopt;

		// Retry a few times — a 0 return here can be either a stale swap or a
		// transient hypercall failure. Brief retries cover both.
		for (int tries = 0; tries < 4; ++tries)
		{
			system_eproc = sys::kern::read<std::uintptr_t>(exp_it->second);
			if (system_eproc >= kernel_va_floor)
				break;
			std::this_thread::sleep_for(std::chrono::milliseconds(2));
		}
		if (system_eproc < kernel_va_floor)
			return std::nullopt;

		cached = probe_layout(system_eproc);
		cached_system = system_eproc;

		if (cached.links_off == 0)
		{
			cached_system = 0;   // force re-probe on next call
			return std::nullopt;
		}

		return cached;
	}

	template <class F>
	void walk_eprocs(const std::uintptr_t system_eproc,
	                 const eproc_layout& l,
	                 F&& fn) noexcept
	{
		const auto head = system_eproc + l.links_off;
		auto curr = sys::kern::read<std::uintptr_t>(head);

		for (std::size_t i = 0; i < 4096; ++i)
		{
			if (curr == head || curr < kernel_va_floor)
				break;

			const auto eproc = curr - l.links_off;
			if (fn(eproc))
				return;

			curr = sys::kern::read<std::uintptr_t>(curr);
		}
	}
}

bool sys::kern::init() noexcept
{
	curr_cr3 = hc::curr_cr3();

	if (curr_cr3 == 0)
		return false;

	parse_modules();
	return true;
}

void sys::kern::parse_modules() noexcept
{
	const nt::kernel_modules current;

	if (!current)
		return;

	std::unordered_set<std::string> seen;

	for (const auto module : current)
	{
		if (!module)
			continue;

		std::string name{ module.name };

		seen.insert(name);

		if (const auto it = modules_list.find(name); it != modules_list.end())
		{
			if (it->second.base == module.base && it->second.size == module.size)
				continue;
		}

		const auto image = dump::run(module.base);

		if (!image)
			continue;

		kernel_module entry{ module.base, module.size, {} };

		for (const auto& exp : image->exports())
		{
			if (exp.forwarded)
				continue;

			entry.exports.emplace(std::string(exp.name), module.base + exp.loc.rva());
		}

		modules_list[std::move(name)] = std::move(entry);
	}

	for (auto it = modules_list.begin(); it != modules_list.end();)
	{
		if (!seen.contains(it->first))
			it = modules_list.erase(it);
		else
			++it;
	}
}

std::uint64_t sys::kern::cr3_for_pid(const std::uint32_t pid) noexcept
{
	std::uintptr_t system_eproc = 0;
	const auto l = get_layout(system_eproc);
	if (!l)
	{
		LOG_ERR("cr3_for_pid: eproc layout probe failed");
		return 0;
	}

	std::uint64_t result = 0;

	walk_eprocs(system_eproc, *l, [&](const std::uintptr_t eproc)
	{
		const auto id = read<std::uint64_t>(eproc + l->pid_off);
		if (static_cast<std::uint32_t>(id) != pid)
			return false;

		const auto dirbase = read<std::uint64_t>(eproc + KPROC_DIRBASE_OFF);
		if (dirbase == 0 || (dirbase & ~((1ULL << 52) - 1)) != 0)
			return false;

		result = dirbase;
		return true;
	});

	return result;
}

std::uint32_t sys::kern::pid_for_name(const std::string_view name) noexcept
{
	std::uintptr_t system_eproc = 0;
	const auto l = get_layout(system_eproc);
	if (!l)
	{
		LOG_ERR("pid_for_name: eproc layout probe failed");
		return 0;
	}

	std::uint32_t result = 0;
	const std::size_t name_cmp_len = std::min<std::size_t>(name.size(), 15);

	walk_eprocs(system_eproc, *l, [&](const std::uintptr_t eproc)
	{
		std::array<char, 16> img{};
		if (!read<char>(eproc + l->name_off, std::span(img)))
			return false;

		// ImageFileName is 15 bytes NUL-padded; compare case-insensitively.
		const auto ilen = std::char_traits<char>::length(img.data());
		if (ilen != name_cmp_len)
			return false;

		for (std::size_t i = 0; i < name_cmp_len; ++i)
		{
			const auto a = static_cast<unsigned char>(img[i]);
			const auto b = static_cast<unsigned char>(name[i]);
			if ((a | 0x20) != (b | 0x20))
				return false;
		}

		const auto id = read<std::uint64_t>(eproc + l->pid_off);
		result = static_cast<std::uint32_t>(id);
		return true;
	});

	return result;
}
