#include "cmd.hpp"
#include "alias.hpp"

#include "../arch/arch.hpp"
#include "../hook/hook.hpp"
#include "../hypercall/hypercall.hpp"
#include "../script/script.hpp"
#include "../sys/dump.hpp"
#include "../sys/kernel.hpp"
#include "../util/log.hpp"

#include <CLI/CLI.hpp>

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

//   SUB(name, desc)       declare a subcommand named `name` on `app`
//   OPT(cmd, opt)         positional option
//   REQ(cmd, opt)         required positional option
//   TREQ(cmd, opt)        required positional option transformed through `xf` (must be in scope)
//   LOPT(cmd, opt)        --long option
//   LFLAG(cmd, opt)       --long flag
//   VAR_LOPT(cmd, opt)    --long option, variadic (TakeAll)
//   GET(cmd, opt, T)      fetch option value as T
//   GET_U64(cmd, opt)     fetch option value as uint64_t
//   GET_STR(cmd, opt)     fetch option value as string

#define SUB(name, desc) \
	CLI::App* const name = app.add_subcommand(#name, desc)->ignore_case()

#define OPT(cmd, opt)        add_option(cmd, #opt)
#define REQ(cmd, opt)        add_option(cmd, #opt)->required()
#define TREQ(cmd, opt)       add_option(cmd, #opt)->required()->transform(xf)
#define LOPT(cmd, opt)       add_option(cmd, "--" #opt)
#define LFLAG(cmd, opt)      add_flag(cmd,   "--" #opt)
#define VAR_LOPT(cmd, opt)   add_option(cmd, "--" #opt)->multi_option_policy(CLI::MultiOptionPolicy::TakeAll)->expected(-1)

#define GET(cmd, opt, T)   get_opt<T>(cmd, #opt)
#define GET_U64(cmd, opt)  get_opt<std::uint64_t>(cmd, #opt)
#define GET_STR(cmd, opt)  get_opt<std::string>(cmd, #opt)
#define GET_FLAG(cmd, opt) get_flag(cmd, "--" #opt)

#define INVOKE_COMMAND_PROCESSOR(command) process_##command(command)
#define PROCESS_INITIAL_COMMAND(command) if (*command) INVOKE_COMMAND_PROCESSOR(command)
#define PROCESS_COMMAND(command) else if (*command) INVOKE_COMMAND_PROCESSOR(command)

namespace
{
	template <class T>
	T get_opt(const CLI::App* const app, const std::string& name)
	{
		const auto* const o = app->get_option(name);
		return !o->empty() ? o->as<T>() : T{};
	}

	std::uint8_t get_flag(const CLI::App* const app, const std::string& name)
	{
		return static_cast<std::uint8_t>(!app->get_option(name)->empty());
	}

	CLI::Option* add_option(CLI::App* const app, const std::string& name)
	{
		return app->add_option(name);
	}

	CLI::Option* add_flag(CLI::App* const app, const std::string& name)
	{
		return app->add_flag(name);
	}

	bool read_gpm(void* dest, std::uintptr_t src_pa, std::uint64_t size) noexcept
	{
		const auto dest_pa = hc::translate_va(hc::curr_cr3(), reinterpret_cast<std::uintptr_t>(dest));
		return dest_pa && hc::phys_copy(src_pa, dest_pa, size);
	}

	bool write_gpm(const void* src, std::uintptr_t dest_pa, std::uint64_t size) noexcept
	{
		const auto src_pa = hc::translate_va(hc::curr_cr3(), reinterpret_cast<std::uintptr_t>(src));
		return src_pa && hc::phys_copy(src_pa, dest_pa, size);
	}

	bool read_gvm(void* dest, std::uintptr_t src_va, std::uint64_t src_cr3, std::uint64_t size) noexcept
	{
		return hc::virt_copy(src_cr3, src_va, hc::curr_cr3(), reinterpret_cast<std::uintptr_t>(dest), size);
	}

	bool write_gvm(const void* src, std::uintptr_t dest_va, std::uint64_t dest_cr3, std::uint64_t size) noexcept
	{
		return hc::virt_copy(hc::curr_cr3(), reinterpret_cast<std::uintptr_t>(src), dest_cr3, dest_va, size);
	}

	CLI::App* init_rgpm(CLI::App& app, const CLI::Transformer& xf)
	{
		SUB(rgpm, "reads memory from a given guest physical address");
		TREQ(rgpm, physical_address);
		REQ(rgpm, size)->check(CLI::Range(0, 8));
		return rgpm;
	}

	void process_rgpm(const CLI::App* const rgpm)
	{
		const auto pa   = GET_U64(rgpm, physical_address);
		const auto size = GET_U64(rgpm, size);

		std::uint64_t value = 0;

		if (read_gpm(&value, pa, size))
			LOG_INFO("value: 0x{:x}", value);
		else
			LOG_ERR("failed to read");
	}

	CLI::App* init_wgpm(CLI::App& app, const CLI::Transformer& xf)
	{
		SUB(wgpm, "writes memory to a given guest physical address");
		TREQ(wgpm, physical_address);
		REQ(wgpm, value);
		REQ(wgpm, size)->check(CLI::Range(0, 8));
		return wgpm;
	}

	void process_wgpm(const CLI::App* const wgpm)
	{
		const auto pa    = GET_U64(wgpm, physical_address);
		const auto value = GET_U64(wgpm, value);
		const auto size  = GET_U64(wgpm, size);

		if (write_gpm(&value, pa, size))
			LOG_INFO("success in write");
		else
			LOG_ERR("failed to write");
	}

	CLI::App* init_cgpm(CLI::App& app, const CLI::Transformer& xf)
	{
		SUB(cgpm, "copies memory from a given source to a destination (guest physical addresses)");
		TREQ(cgpm, destination_physical_address);
		TREQ(cgpm, source_physical_address);
		REQ(cgpm, size);
		return cgpm;
	}

	void process_cgpm(const CLI::App* const cgpm)
	{
		const auto dst  = GET_U64(cgpm, destination_physical_address);
		const auto src  = GET_U64(cgpm, source_physical_address);
		const auto size = GET_U64(cgpm, size);

		if (hc::phys_copy(src, dst, size))
			LOG_INFO("success in copy");
		else
			LOG_ERR("failed to copy");
	}

	CLI::App* init_gvat(CLI::App& app, const CLI::Transformer& xf)
	{
		SUB(gvat, "translates a guest virtual address to its corresponding guest physical address, with the given guest cr3 value");
		TREQ(gvat, virtual_address);
		TREQ(gvat, cr3);
		return gvat;
	}

	void process_gvat(const CLI::App* const gvat)
	{
		const auto va  = GET_U64(gvat, virtual_address);
		const auto cr3 = GET_U64(gvat, cr3);

		LOG_INFO("physical address: 0x{:x}", hc::translate_va(cr3, va));
	}

	CLI::App* init_rgvm(CLI::App& app, const CLI::Transformer& xf)
	{
		SUB(rgvm, "reads memory from a given guest virtual address (when given the corresponding guest cr3 value)");
		TREQ(rgvm, virtual_address);
		TREQ(rgvm, cr3);
		REQ(rgvm, size)->check(CLI::Range(0, 8));
		return rgvm;
	}

	void process_rgvm(const CLI::App* const rgvm)
	{
		const auto va   = GET_U64(rgvm, virtual_address);
		const auto cr3  = GET_U64(rgvm, cr3);
		const auto size = GET_U64(rgvm, size);

		std::uint64_t value = 0;

		if (read_gvm(&value, va, cr3, size))
			LOG_INFO("value: 0x{:x}", value);
		else
			LOG_ERR("failed to read");
	}

	CLI::App* init_wgvm(CLI::App& app, const CLI::Transformer& xf)
	{
		SUB(wgvm, "writes memory from a given guest virtual address (when given the corresponding guest cr3 value)");
		TREQ(wgvm, virtual_address);
		TREQ(wgvm, cr3);
		REQ(wgvm, value);
		REQ(wgvm, size)->check(CLI::Range(0, 8));
		return wgvm;
	}

	void process_wgvm(const CLI::App* const wgvm)
	{
		const auto va    = GET_U64(wgvm, virtual_address);
		const auto cr3   = GET_U64(wgvm, cr3);
		const auto value = GET_U64(wgvm, value);
		const auto size  = GET_U64(wgvm, size);

		if (write_gvm(&value, va, cr3, size))
			LOG_INFO("success in write at given address");
		else
			LOG_ERR("failed to write at given address");
	}

	CLI::App* init_cgvm(CLI::App& app, const CLI::Transformer& xf)
	{
		SUB(cgvm, "copies memory from a given source to a destination (guest virtual addresses) (when given the corresponding guest cr3 values)");
		TREQ(cgvm, destination_virtual_address);
		TREQ(cgvm, destination_cr3);
		TREQ(cgvm, source_virtual_address);
		TREQ(cgvm, source_cr3);
		REQ(cgvm, size);
		return cgvm;
	}

	void process_cgvm(const CLI::App* const cgvm)
	{
		const auto dst_va  = GET_U64(cgvm, destination_virtual_address);
		const auto dst_cr3 = GET_U64(cgvm, destination_cr3);
		const auto src_va  = GET_U64(cgvm, source_virtual_address);
		const auto src_cr3 = GET_U64(cgvm, source_cr3);
		const auto size    = GET_U64(cgvm, size);

		if (hc::virt_copy(src_cr3, src_va, dst_cr3, dst_va, size))
			LOG_INFO("success in copy");
		else
			LOG_ERR("failed to copy");
	}

	CLI::App* init_akh(CLI::App& app, const CLI::Transformer& xf)
	{
		SUB(akh, "add a hook on specified kernel code (given the guest virtual address) (asmbytes in form: 0xE8 0x12 0x23 0x34 0x45)");
		TREQ(akh, virtual_address);
		VAR_LOPT(akh, script_text);
		VAR_LOPT(akh, script_file);
		VAR_LOPT(akh, asmbytes);
		VAR_LOPT(akh, post_original_asmbytes);
		LFLAG(akh, monitor);
		return akh;
	}

	void process_akh(const CLI::App* const akh)
	{
		const auto va          = GET_U64(akh, virtual_address);
		const auto post        = GET(akh, --post_original_asmbytes, std::vector<std::uint8_t>);
		const auto script_text = GET_STR(akh, --script_text);
		const auto script_file = GET_STR(akh, --script_file);
		const auto monitor     = GET_FLAG(akh, monitor);

		auto pre = GET(akh, --asmbytes, std::vector<std::uint8_t>);

		std::vector<std::uint8_t> script_bytes;

		if (!script_text.empty())
			script_bytes = script::compile(script_text, cmd::alias::compile());
		else if (!script_file.empty())
			script_bytes = script::compile_file(script_file, cmd::alias::compile());

		pre.insert(pre.end(), script_bytes.begin(), script_bytes.end());

		if (hook::install(va, pre, post, monitor != 0))
			LOG_INFO("success in hook");
		else
			LOG_ERR("failed to hook");
	}

	CLI::App* init_p2c(CLI::App& app, const CLI::Transformer& xf)
	{
		SUB(p2c, "resolve a process identifier to its cr3 (DirectoryTableBase). Give exactly one "
		         "of --pid / --name. Walks the EPROCESS ActiveProcessLinks chain via "
		         "PsInitialSystemProcess; no kernel driver needed.");
		LOPT(p2c, pid);
		LOPT(p2c, name);
		return p2c;
	}

	void process_p2c(const CLI::App* const p2c)
	{
		const auto pid  = GET_U64(p2c, --pid);
		const auto name = GET_STR(p2c, --name);

		if (pid)
		{
			const auto cr3 = sys::kern::cr3_for_pid(static_cast<std::uint32_t>(pid));
			if (cr3)
				LOG_INFO("pid {} -> cr3 {:#x}", pid, cr3);
			else
				LOG_ERR("pid {} not found", pid);
			return;
		}

		if (!name.empty())
		{
			const auto resolved_pid = sys::kern::pid_for_name(name);
			if (!resolved_pid)
			{
				LOG_ERR("name '{}' not found", name);
				return;
			}
			const auto cr3 = sys::kern::cr3_for_pid(resolved_pid);
			if (cr3)
				LOG_INFO("'{}' -> pid {} -> cr3 {:#x}", name, resolved_pid, cr3);
			else
				LOG_ERR("'{}' -> pid {} had null cr3", name, resolved_pid);
			return;
		}

		LOG_ERR("p2c: give --pid or --name");
	}

	CLI::App* init_aih(CLI::App& app, const CLI::Transformer& xf)
	{
		SUB(aih, "add an INT3 (0xCC) shadow-page hook on the given guest virtual address; reads through "
		         "the page return the original bytes (integrity scans safe), execution hits INT3. "
		         "Use exactly one of --cr3 / --pid / --name to pick the target process address space; "
		         "a VEH in that process must handle the #BP. Defaults to the kernel cr3 if all are omitted.");
		TREQ(aih, virtual_address);
		LOPT(aih, cr3);
		LOPT(aih, pid);
		LOPT(aih, name);
		return aih;
	}

	void process_aih(const CLI::App* const aih)
	{
		const auto va   = GET_U64(aih, virtual_address);
		const auto cr3  = GET_U64(aih, --cr3);
		const auto pid  = GET_U64(aih, --pid);
		const auto name = GET_STR(aih, --name);

		std::uint64_t effective_cr3 = cr3;

		if (!effective_cr3 && pid)
		{
			effective_cr3 = sys::kern::cr3_for_pid(static_cast<std::uint32_t>(pid));
			if (!effective_cr3)
			{
				LOG_ERR("aih: no running process with pid {}", pid);
				return;
			}
			LOG_INFO("aih: pid {} -> cr3 {:#x}", pid, effective_cr3);
		}

		if (!effective_cr3 && !name.empty())
		{
			const auto resolved_pid = sys::kern::pid_for_name(name);
			if (!resolved_pid)
			{
				LOG_ERR("aih: no running process named '{}'", name);
				return;
			}
			effective_cr3 = sys::kern::cr3_for_pid(resolved_pid);
			if (!effective_cr3)
			{
				LOG_ERR("aih: pid {} for name '{}' had null cr3", resolved_pid, name);
				return;
			}
			LOG_INFO("aih: '{}' -> pid {} -> cr3 {:#x}", name, resolved_pid, effective_cr3);
		}

		if (!effective_cr3)
			effective_cr3 = sys::kern::curr_cr3;

		if (hook::install_int3(va, effective_cr3))
			LOG_INFO("success in int3 hook");
		else
			LOG_ERR("failed to install int3 hook");
	}

	CLI::App* init_rkh(CLI::App& app, const CLI::Transformer& xf)
	{
		SUB(rkh, "remove a previously placed hook on specified kernel code (given the guest virtual address)");
		TREQ(rkh, virtual_address);
		return rkh;
	}

	void process_rkh(const CLI::App* const rkh)
	{
		const auto va = GET_U64(rkh, virtual_address);

		if (hook::remove(va))
			LOG_INFO("success in hook removal");
		else
			LOG_ERR("failed to remove hook");
	}

	CLI::App* init_hgpp(CLI::App& app, const CLI::Transformer& xf)
	{
		SUB(hgpp, "hide a physical page's real contents from the guest");
		TREQ(hgpp, physical_address);
		return hgpp;
	}

	void process_hgpp(const CLI::App* const hgpp)
	{
		const auto pa = GET_U64(hgpp, physical_address);

		if (hc::hide_page(pa))
			LOG_INFO("success in hiding page");
		else
			LOG_ERR("failed to hide page");
	}

	CLI::App* init_clk(CLI::App& app, const CLI::Transformer& xf)
	{
		SUB(clk, "cloak a page: external reads see zeros, owning code still executes + "
		         "reads its own data (hyperv EPT = zero/R, shadow EPT = original/RWX)");
		TREQ(clk, physical_address);
		return clk;
	}

	void process_clk(const CLI::App* const clk)
	{
		const auto pa = GET_U64(clk, physical_address);

		if (hc::cloak_add(pa))
			LOG_INFO("cloak_add OK for {:#x}", pa);
		else
			LOG_ERR("cloak_add failed for {:#x}", pa);
	}

	CLI::App* init_rck(CLI::App& app, const CLI::Transformer& xf)
	{
		SUB(rck, "remove cloak from a page previously cloaked with clk");
		TREQ(rck, physical_address);
		return rck;
	}

	void process_rck(const CLI::App* const rck)
	{
		const auto pa = GET_U64(rck, physical_address);

		if (hc::cloak_remove(pa))
			LOG_INFO("cloak_remove OK for {:#x}", pa);
		else
			LOG_ERR("cloak_remove failed for {:#x}", pa);
	}

	CLI::App* init_fl(CLI::App& app)
	{
		SUB(fl, "flush trap frame logs from hooks");
		return fl;
	}

	void process_fl(const CLI::App* const /*fl*/)
	{
		std::vector<logs::entry> buf(logs::ring_capacity);

		const auto n = hc::flush_logs(buf.data(),
			static_cast<std::uint16_t>(buf.size()));

		if (n == 0)
		{
			LOG_INFO("no logs");
			return;
		}

		LOG_INFO("flushed {} log(s)", n);
		for (std::size_t i = 0; i < n; i++)
		{
			auto e = buf[i];
			// stub pushed the caller's rcx before clobbering it; recover the real value
			e.regs.rcx = e.stack_data[0];

			const auto& r = e.regs;

			LOG_INFO("[{}] rip=0x{:016X} cr3=0x{:016X}", i, e.rip, e.cr3);
			LOG_INFO("  rax=0x{:016X}  rbx=0x{:016X}  rcx=0x{:016X}  rdx=0x{:016X}",
				r.rax, r.rbx, r.rcx, r.rdx);
			LOG_INFO("  rsi=0x{:016X}  rdi=0x{:016X}  rbp=0x{:016X}  rsp=0x{:016X}",
				r.rsi, r.rdi, r.rbp, r.rsp);
			LOG_INFO("  r8 =0x{:016X}  r9 =0x{:016X}  r10=0x{:016X}  r11=0x{:016X}",
				r.r8, r.r9, r.r10, r.r11);
			LOG_INFO("  r12=0x{:016X}  r13=0x{:016X}  r14=0x{:016X}  r15=0x{:016X}",
				r.r12, r.r13, r.r14, r.r15);
			LOG_INFO("  stack: 0x{:016X} 0x{:016X} 0x{:016X} 0x{:016X}",
				e.stack_data[1], e.stack_data[2], e.stack_data[3], e.stack_data[4]);
		}
	}

	CLI::App* init_hfpc(CLI::App& app)
	{
		SUB(hfpc, "get hyperv-attachment's heap free page count");
		return hfpc;
	}

	void process_hfpc(const CLI::App* const /*hfpc*/)
	{
		LOG_INFO("heap free page count: {}", hc::rem_heap_size() / arch::page_size);
	}

	CLI::App* init_lkm(CLI::App& app)
	{
		SUB(lkm, "print list of loaded kernel modules");
		return lkm;
	}

	void process_lkm(const CLI::App* const /*lkm*/)
	{
		for (const auto& [name, info] : sys::kern::modules_list)
			LOG_INFO("'{}' base=0x{:X} size=0x{:X}", name, info.base, info.size);
	}

	CLI::App* init_kme(CLI::App& app)
	{
		SUB(kme, "list the exports of a loaded kernel module (when given the name)");
		REQ(kme, module_name);
		return kme;
	}

	void process_kme(const CLI::App* const kme)
	{
		const auto name = GET_STR(kme, module_name);

		const auto it = sys::kern::modules_list.find(name);

		if (it == sys::kern::modules_list.end())
		{
			LOG_ERR("module not found");
			return;
		}

		for (const auto& [export_name, address] : it->second.exports)
			LOG_INFO("{} = 0x{:X}", export_name, address);
	}

	CLI::App* init_dkm(CLI::App& app)
	{
		SUB(dkm, "dump kernel module to a file on disk");
		REQ(dkm, module_name);
		REQ(dkm, output_directory);
		return dkm;
	}

	void process_dkm(const CLI::App* const dkm)
	{
		const auto name = GET_STR(dkm, module_name);
		const auto out_dir = GET_STR(dkm, output_directory);

		const auto it = sys::kern::modules_list.find(name);

		if (it == sys::kern::modules_list.end())
		{
			LOG_ERR("module not found");
			return;
		}

		const auto path = out_dir + "\\dump_" + name;

		if (sys::dump::to_disk(path, it->second.base))
			LOG_INFO("dumped to '{}'", path);
		else
			LOG_ERR("failed to dump to '{}'", path);
	}

	CLI::App* init_gva(CLI::App& app, const CLI::Transformer& xf)
	{
		SUB(gva, "get the numerical value of an alias");
		TREQ(gva, alias_name);
		return gva;
	}

	void process_gva(const CLI::App* const gva)
	{
		LOG_INFO("alias value: 0x{:X}", GET_U64(gva, alias_name));
	}

	void process(const std::string& command)
	{
		if (command.empty()) return;

		sys::kern::parse_modules();

		const auto aliases = cmd::alias::compile();
		const auto xf = CLI::Transformer(aliases, CLI::ignore_case);

		CLI::App app;
		app.require_subcommand();

		const CLI::App* const rgpm = init_rgpm(app, xf);
		const CLI::App* const wgpm = init_wgpm(app, xf);
		const CLI::App* const cgpm = init_cgpm(app, xf);
		const CLI::App* const gvat = init_gvat(app, xf);
		const CLI::App* const rgvm = init_rgvm(app, xf);
		const CLI::App* const wgvm = init_wgvm(app, xf);
		const CLI::App* const cgvm = init_cgvm(app, xf);
		const CLI::App* const akh  = init_akh(app, xf);
		const CLI::App* const aih  = init_aih(app, xf);
		const CLI::App* const p2c  = init_p2c(app, xf);
		const CLI::App* const rkh  = init_rkh(app, xf);
		const CLI::App* const gva  = init_gva(app, xf);
		const CLI::App* const hgpp = init_hgpp(app, xf);
		const CLI::App* const clk  = init_clk(app, xf);
		const CLI::App* const rck  = init_rck(app, xf);
		const CLI::App* const fl   = init_fl(app);
		const CLI::App* const hfpc = init_hfpc(app);
		const CLI::App* const lkm  = init_lkm(app);
		const CLI::App* const kme  = init_kme(app);
		const CLI::App* const dkm  = init_dkm(app);

		try
		{
			app.parse(command);

			PROCESS_INITIAL_COMMAND(rgpm);
			PROCESS_COMMAND(wgpm);
			PROCESS_COMMAND(cgpm);
			PROCESS_COMMAND(gvat);
			PROCESS_COMMAND(rgvm);
			PROCESS_COMMAND(wgvm);
			PROCESS_COMMAND(cgvm);
			PROCESS_COMMAND(akh);
			PROCESS_COMMAND(aih);
			PROCESS_COMMAND(p2c);
			PROCESS_COMMAND(rkh);
			PROCESS_COMMAND(gva);
			PROCESS_COMMAND(hgpp);
			PROCESS_COMMAND(clk);
			PROCESS_COMMAND(rck);
			PROCESS_COMMAND(fl);
			PROCESS_COMMAND(hfpc);
			PROCESS_COMMAND(lkm);
			PROCESS_COMMAND(kme);
			PROCESS_COMMAND(dkm);
		}
		catch (const CLI::ParseError& e)
		{
			app.exit(e);
		}
	}
}

void cmd::run() noexcept
{
	for (std::string line; ;)
	{
		std::printf("> ");

		if (!std::getline(std::cin, line))
			break;

		if (line == "exit")
			break;

		process(line);
	}
}
