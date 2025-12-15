#include "ldbg.h"

#include <format>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <unordered_map>

#include <lgc.h>
#include <lmem.h>
#include <lfunc.h>
#include <ldebug.h>
#include <lualib.h>
#include <Luau/Compiler.h>
#include <Luau/Bytecode.h>
#include <Luau/BytecodeUtils.h>

#include "style.h"
#include "disasm.h"

#define DLL_PROCESS_ATTACH	1
#define DLL_THREAD_ATTACH	2
#define DLL_THREAD_DETACH	3
#define DLL_PROCESS_DETACH	0

namespace nula {
	constexpr uint32_t signature = 0x616c756e;
}

namespace ldbg {

	static std::unordered_map<lua_State*, Debugger*> debuggers;

	static void debugstep(lua_State* L, lua_Debug* ar) {
		auto it = debuggers.find(L);
		if (it == debuggers.end())
			return;

		it->second->debugstep(L, ar);
	}

	static void debugbreak(lua_State* L, lua_Debug* ar) {
		auto it = debuggers.find(L);
		if (it == debuggers.end())
			return;

		it->second->debugbreak(L, ar);
	}

	static int onError(lua_State* L) {
		const Debugger::Options& options = ((Debugger*)L->global->ud)->options;

		fprintf(options.out, ANSI_RED "%s" ANSI_GREY "\nStack Begin\n", luaL_checkstring(L, 1));
		lua_getglobal(L, "debug");
		lua_getfield(L, -1, "traceback");
		lua_call(L, 0, 1);
		if (const char* traceback = lua_tostring(L, -1))
			fprintf(options.out, "%s", traceback);
		fprintf(options.out, "Stack End\n" ANSI_RESET);
		lua_pop(L, 2);
		return 0;
	}

	extern std::string lua_strprimitive(const TValue* o);

	template<typename T>
	static bool parseInt(const std::string& s, T& idx) {
		const char* end = s.data() + s.size();
		auto result = std::from_chars(s.data(), end, idx);
		return result.ec == std::errc() && result.ptr == end;
	}

	static bool isNumber(const std::string& s) {
		if (s.empty())
			return false;

		if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
			return std::all_of(s.begin() + 2, s.end(), [](uint8_t c) { return isxdigit(c); });

		return std::all_of(s.begin(), s.end(), [](uint8_t c) { return isdigit(c); });
	}

	static std::string getSource(Proto* p) {
		char ss[LUA_IDSIZE];
		return luaO_chunkid(ss, sizeof(ss), getstr(p->source), p->source->len);
	}

	static void* frealloc(void* ud, void* ptr, size_t osize, size_t nsize) {
		Debugger* dbg = (Debugger*)ud;
		if (!ptr)
			fprintf(dbg->options.out, "[gc trace] allocation with size " ANSI_YELLOW "%zu\n" ANSI_RESET, nsize);
		else if (!nsize)
			fprintf(dbg->options.out, "[gc trace] deallocation of ptr " ANSI_YELLOW "0x%llx\n" ANSI_RESET, (uintptr_t)ptr);
		else
			fprintf(dbg->options.out, "[gc trace] reallocation of ptr " ANSI_YELLOW "0x%llx" ANSI_RESET ": " ANSI_YELLOW "%zu" ANSI_RESET " -> " ANSI_YELLOW "%zu\n" ANSI_RESET, (uintptr_t)ptr, osize, nsize);

		return dbg->oldFrealloc(ud, ptr, osize, nsize);
	}

	static void ensureDebugInsn(lua_State* L, Proto* p) {
		if (p->debuginsn)
			return;

		p->debuginsn = luaM_newarray(L, p->sizecode, uint8_t, p->memcat);
		for (int j = 0; j < p->sizecode; j++)
			p->debuginsn[j] = LUAU_INSN_OP(p->code[j]);
	}

	Debugger::Debugger() {
		options.onError = onError;

		options.debugbreak = nullptr;

		options.in = stdin;
		options.out = stdout;
	}

	Debugger::~Debugger() {
		std::vector<lua_State*> states;
		for (const auto& [L, dbg] : debuggers) {
			if (L && dbg == this)
				states.emplace_back(L);
		}

		for (const auto& L : states)
			detach(L);
	}

	void Debugger::attach(lua_State* L) {
		debuggers[L] = this;

		L->global->cb.debugstep = ldbg::debugstep;
		L->global->cb.debugbreak = ldbg::debugbreak;

		L->singlestep = true;
	}

	void Debugger::detach(lua_State* L) {
		debuggers.erase(L);

		L->singlestep = false;

		L->global->cb.debugstep = nullptr;
		L->global->cb.debugbreak = nullptr;
	}

	size_t Debugger::setBreakpoint(lua_State* L, Proto* p, bool enable) {
		return setBreakpoint(L, p, 0, getSource(p), enable);
	}

	size_t Debugger::setBreakpoint(lua_State* L, const std::string& source, uint32_t line, bool enable) {
		int count = 0;
		size_t idx = 0;
		for (const auto& p : loadedProtos) {
			if (!p->lineinfo || source != getSource(p))
				continue;

			for (int i = 0; i < p->sizecode; i++) {
				if (LUAU_INSN_OP(p->code[i]) == LOP_PREPVARARGS)
					continue;

				if (luaG_getline(p, i) != line)
					continue;

				idx = setBreakpoint(L, p, i, source, line, enable);
				count++;
				break;
			}
		}

		if (count > 0)
			fprintf(options.out, "breakpoint %zu %s at %s:" ANSI_YELLOW "%d\n" ANSI_RESET, idx, enable ? "set" : "cleared", source.c_str(), line);
		else
			fprintf(options.out, "no functions found matching source '%s' or line number out of range\n", source.c_str());
		return idx;
	}

	size_t Debugger::setBreakpoint(lua_State* L, Proto* p, int pc, const std::string& source, uint32_t line, bool enable) {
		ensureDebugInsn(L, p);
		p->code[pc] &= ~0xFF;
		
		if (enable) {
			p->code[pc] |= LOP_BREAK;
			return pushBreakpoint(p, source, pc, line);
		} else {
			p->code[pc] |= LUAU_INSN_OP(p->debuginsn[pc]);
			removeBreakpoint(p, pc);
			return 0;
		}
	}

	bool Debugger::removeBreakpoint(Proto* p, int pc) {
		for (auto it = breakpoints.begin(); it != breakpoints.end(); ++it) {
			if (it->p == p && it->pc == pc) {
				breakpoints.erase(it);
				return true;
			}
		}
		return false;
	}

	void Debugger::toggleBreakpoint(lua_State* L, size_t num) {
		if (num < 1 || num > breakpoints.size()) {
			puts("invalid breakpoint number");
			return;
		}

		auto& bp = breakpoints[num - 1];
		if (bp.enabled) {
			bp.enabled = false;
			bp.p->code[bp.pc] = LUAU_INSN_OP(bp.p->debuginsn[bp.pc]);
		} else {
			bp.enabled = true;
			bp.p->code[bp.pc] = LOP_BREAK;
		}

		fprintf(options.out, "breakpoint %zu %s\n", num, bp.enabled ? "enabled" : "disabled");
	}

	void Debugger::collectProtos(Proto* p) {
		for (const auto& proto : loadedProtos) {
			if (proto == p)
				return;
		}

		loadedProtos.push_back(p);
		for (int i = 0; i < p->sizep; i++)
			collectProtos(p->p[i]);
	}

	void Debugger::dumpFunctionInfo(lua_State* L) {
		lua_Debug ar;
		if (lua_getinfo(L, 0, "sln", &ar)) {
			const Closure* cl = clvalue(L->ci->func);
			fprintf(options.out, ANSI_GREY "=> " ANSI_CYAN "%s" ANSI_RESET "() at %s:" ANSI_YELLOW "%d\n" ANSI_RESET, cl->l.p->debugname ? getstr(cl->l.p->debugname) : "??", ar.short_src, ar.currentline);
		}
	}

	size_t Debugger::pushBreakpoint(Proto* p, const std::string& source, int pc, uint32_t line) {
		size_t i = 0;
		for (auto& bp : breakpoints) {
			if (bp.p == p && bp.pc == pc) {
				bp.enabled = true;
				return i;
			}
			i++;
		}

		breakpoints.push_back({ p, source, pc, true, line });
		return breakpoints.size();
	}

	void Debugger::handleBreakByPc(lua_State* L, Proto* p, int pc) {
		if (pc >= p->sizecode) {
			puts("pc out of range");
			return;
		}

		if (Luau::getOpLength((LuauOpcode)LUAU_INSN_OP(p->code[pc - 1])) - 1)
			pc--;

		ensureDebugInsn(L, p);
		p->code[pc] = LOP_BREAK;

		uint32_t ln = luaG_getline(p, pc);
		fprintf(options.out, "breakpoint %zu set at %s:" ANSI_YELLOW "%d\n" ANSI_RESET, pushBreakpoint(p, getSource(p), pc, ln), getSource(p).c_str(), ln);
	}

	void Debugger::handleBreakByFunc(lua_State* L, const std::string& source, const std::string& func) {
		bool found = false;
		for (const auto& p : loadedProtos) {
			if (p->debugname && getstr(p->debugname) == func) {
				if (!source.empty() && source != getSource(p))
					continue;

				setBreakpoint(L, p, true);
				found = true;
				break;
			}
		}

		if (!found)
			puts("function not found");
	}

	void Debugger::repl(lua_State* L) {
		debugstepActive = true;

		std::string line;
		std::ifstream istream(options.in);

		while (true) {
			fputs(ANSI_RESET "(ldbg) ", options.out);
			if (!std::getline(istream, line))
				break;

			if (line.empty())
				continue;

			std::istringstream ss(line);
			std::string cmd;
			ss >> cmd;

			if (cmd == "continue" || cmd == "c") {
				state = State::None;
				debugstepActive = false;
				break;

			}
			else if (cmd == "bt" || cmd == "backtrace") {
				lua_Debug ar;
				int level = 0;
				fputs(ANSI_GREY "(current) " ANSI_RESET, options.out);
				while (lua_getinfo(L, level++, "sl", &ar))
					fprintf(options.out, ANSI_YELLOW "%d" ANSI_RESET " - %s:" ANSI_YELLOW "%d\n", level, ar.short_src, ar.currentline);
				fputs(ANSI_RESET "", options.out);
			}
			else if (cmd == "quit" || cmd == "q") {
				L->status = LUA_ERRRUN;
				break;

			}
			else if (cmd == "step" || cmd == "s") {
				state = State::None;
				break;

			}
			else if (cmd == "next" || cmd == "n") {
				state = State::StepOver;
				stateLevel = (uint32_t)(L->ci - L->base_ci);
				break;

			}
			else if (cmd == "finish") {
				state = State::Finish;
				stateLevel = (uint32_t)(L->ci - L->base_ci);
				break;

			}
			else if (cmd == "break" || cmd == "b") {
				std::string loc;
				ss >> std::ws;
				std::getline(ss, loc);

				if (loc.empty()) {
					puts("usage: break source:line/source:func/*func:pc/*pc/line/func");
					continue;
				}

				size_t colon = loc.find(':');
				if (colon != std::string::npos) {
					const std::string& lhs = loc.substr(0, colon);
					const std::string& rhs = loc.substr(colon + 1);

					if (!lhs.empty() && lhs[0] == '*') {
						if (!rhs.empty() && isNumber(rhs)) {
							int pc = std::stoi(rhs, nullptr, 0);
							const std::string& func = lhs.substr(1);

							for (const auto& p : loadedProtos) {
								if (p->debugname && getstr(p->debugname) == func) {
									handleBreakByPc(L, p, pc);
									break;
								}
							}
						} else
							puts("invalid *func:pc format");

					} else {
						if (isNumber(rhs))
							setBreakpoint(L, lhs, std::stoi(rhs, nullptr, 0), true);
						else
							handleBreakByFunc(L, lhs, rhs);
					}
				}
				else {
					if (!loc.empty() && loc[0] == '*') {
						if (isNumber(loc.substr(1))) {
							Proto* p = clvalue(L->ci->func)->l.p;
							handleBreakByPc(L, p, std::stoi(loc.substr(1), nullptr, 0));
						} else
							puts("invalid *pc format");

					} else if (isNumber(loc)) {
						lua_Debug ar;
						lua_getinfo(L, 0, "s", &ar);
						setBreakpoint(L, ar.short_src, std::stoi(loc, nullptr, 0), true);

					} else
						handleBreakByFunc(L, "", loc);
				}

			}
			else if (cmd == "delete" || cmd == "d") {
				size_t num = 0;
				if (ss >> num) {
					if (num < 1 || num > breakpoints.size()) {
						puts("invalid breakpoint number");
						continue;
					}

					const auto& bp = breakpoints[num - 1];
					if (bp.p->debuginsn) {
						bp.p->code[bp.pc] &= ~0xFF;
						bp.p->code[bp.pc] |= LUAU_INSN_OP(bp.p->debuginsn[bp.pc]);
					}

					fprintf(options.out, "deleted breakpoint %zu at %s:" ANSI_YELLOW "%d\n" ANSI_RESET, num, bp.source.c_str(), bp.line);
					breakpoints.erase(breakpoints.begin() + (num - 1));
				} else
					puts("usage: delete <breakpoint number>");

			}
			else if (cmd == "toggle") {
				size_t num;
				if (ss >> num) toggleBreakpoint(L, num);
				else puts("usage: toggle <breakpoint number>");

			}
			else if (cmd == "inspect" || cmd == "i") {
				std::string subcmd;
				ss >> std::ws;
				std::getline(ss, subcmd);

				if (subcmd.empty()) {
					dumpFunctionInfo(L);
					continue;
				}
				
				const Closure* cl = clvalue(L->ci->func);
				const Proto* p = cl->l.p;

				if (subcmd == "locals") {
					if (!p->sizelocvars) {
						puts("missing local info");
						continue;
					}

					for (int i = 0; i < p->sizelocvars; i++) {
						const LocVar* local = &p->locvars[i];

						const int pc = (int)((L->ci->savedpc - 1) - p->code);
						fprintf(options.out, ANSI_CYAN "  R%u" ANSI_RESET " = %s", local->reg, getstr(local->varname));
						if (pc > local->startpc && pc <= local->endpc)
							putchar('\n');
						else
							puts(ANSI_GREY " ; inactive" ANSI_RESET);
					}
				}
				else if (subcmd == "upvalues") {
					if (!p->sizeupvalues) {
						puts("missing upvalue info");
						continue;
					}

					for (int i = 0; i < p->sizeupvalues; i++)
						fprintf(options.out, ANSI_CYAN "  U%d" ANSI_RESET " = %s\n", i, getstr(p->upvalues[i]));
				}
				else if (subcmd == "stack") {
					const uint32_t end = p->maxstacksize;
					const uint32_t rows = (end + 3) / 4;

					for (uint32_t i = 0; i < rows; i++) {
						for (uint32_t j = 0; j < 4; j++) {
							uint32_t idx = i + j * rows;
							if (idx < end)
								fprintf(options.out, ANSI_CYAN "  R%-3d" ANSI_RESET " = %-15s", idx, lua_strprimitive(L->ci->base + idx).c_str());
						}
						putchar('\n');
					}
				}
				else if (subcmd == "breakpoints") {
					if (breakpoints.empty()) {
						puts("no breakpoints set");
						continue;
					}

					fprintf(options.out, 
						"%-4s %-8s %-30s %s\n"
						ANSI_GREY "---- -------- ------------------------------ ----------\n" ANSI_RESET,
						"n", "active", "location", "func");

					size_t i = 0;
					for (const auto& bp : breakpoints) {
						const char* funcName = bp.p->debugname ? getstr(bp.p->debugname) : "??";
						fprintf(options.out, "%-4zu %-8s %-35s " ANSI_CYAN "%s\n" ANSI_RESET,
							++i,
							bp.enabled ? "yes" : "no",
							(bp.source + ":" ANSI_YELLOW + std::to_string(bp.line)).c_str(), funcName
						);
					}
				}
				else if (subcmd == "funcs") {
					if (loadedProtos.empty()) {
						puts("no functions loaded");
						continue;
					}

					fprintf(options.out, 
						"%-4s %-30s %-8s %s\n"
						ANSI_GREY "---- ------------------------------ -------- --------------------\n" ANSI_RESET,
						"n", "func", "line", "source"
					);

					size_t i = 0;
					for (const auto& p : loadedProtos) {
						fprintf(options.out, "%-4zu " ANSI_CYAN "%-30s" ANSI_YELLOW " %-9d" ANSI_RESET  "%s\n",
							++i,
							p->debugname ? getstr(p->debugname) : "??", p->linedefined,
							getSource(p).c_str()
						);
					}
				}
				else if (subcmd == "insn") {
					const Instruction* pc = L->ci->savedpc - 1;
					ldbg::idisasm(options.out, pc, p);
					putchar('\n');
				}
				else if (subcmd[0] == 'R') {
					int idx = 0;
					if (!parseInt(subcmd.substr(1), idx)) {
						puts("index must be a number");
						continue;
					}

					if (idx < 0 || idx >= p->maxstacksize) puts("index out of range");
					else puts(lua_strprimitive(L->base + idx).c_str());
				}
				else if (subcmd[0] == 'K') {
					int idx = 0;
					if (!parseInt(subcmd.substr(1), idx)) {
						puts("index must be a number");
						continue;
					}

					if (idx < 0 || idx >= p->sizek) puts("index out of range");
					else puts(lua_strprimitive(&p->k[idx]).c_str());
				}
				else if (subcmd[0] == 'U') {
					int idx = 0;
					if (!parseInt(subcmd.substr(1), idx)) {
						puts("index must be a number");
						continue;
					}

					if (idx < 0 || idx >= p->nups) puts("index out of range");
					else puts(lua_strprimitive(&cl->l.uprefs[idx]).c_str());
				}
				else
					puts("unknown subcommand");

			}
			else if (cmd == "disasm") {
				std::string func;
				ss >> std::ws;
				std::getline(ss, func);

				const Proto* p = clvalue(L->ci->func)->l.p;
				if (!func.empty()) {
					bool found = false;
					for (const auto& lp : loadedProtos) {
						if (lp->debugname && getstr(lp->debugname) == func) {
							found = true;
							p = lp;
							break;
						}
					}
					
					if (!found) {
						puts("function not found");
						continue;
					}
				}

				const Instruction* pc = p->code;
				const Instruction* end = p->code + p->sizecode;

				while (pc < end) {
					fprintf(options.out, ANSI_GREY "  %04X  ", (uint32_t)(pc - p->code));
					ldbg::idisasm(options.out, pc, p);
					fputs(ANSI_RESET "\n", options.out);
					pc++;
				}

			}
			else if (cmd == "cls") system("cls");
			else if (cmd == "load") {
				std::string path;
				ss >> std::ws;
				ss >> path;

				std::ifstream file(path, std::ios::binary);
				if (!file.is_open()) {
					puts("unable to open file");
					continue;
				}

				uint32_t filesig = 0;
				file.read((char*)&filesig, sizeof(filesig));
				if (!file || filesig != nula::signature) {
					puts("not a nula library");
					file.close();
					continue;
				}

				file.seekg(0, std::ios::end);
				size_t size = (size_t)file.tellg() - 4;
				if (size <= 8) {
					puts("file too small");
					file.close();
					continue;
				}

				std::string btc;
				btc.resize(size);

				file.seekg(4, std::ios::beg);
				file.read(btc.data(), size);
				file.close();
		
				if (luau_load(L, std::format("@{}", path).c_str(), btc.data(), btc.size(), 0)) {
					puts("invalid or corrupted bytecode");
					file.close();
					continue;
				}

				file.close();

				int refDllMain = LUA_REFNIL;
				const Closure* DllMain = nullptr;
				const Closure* cl = (const Closure*)lua_topointer(L, -1);
				for (int i = 0; i < cl->l.p->sizep; i++) {
					Proto* p = cl->l.p->p[i];
					if (!p->debugname)
						continue;

					const Closure* ncl = luaF_newLclosure(L, p->nups, L->gt, p);
					setclvalue(L, L->top, ncl);
					incr_top(L);

					const char* debugname = getstr(p->debugname);
					if (strcmp(debugname, "DllMain")) {
						lua_setglobal(L, debugname);
						loadedProtos.push_back(p);
					} else {
						DllMain = ncl;
						lua_pop(L, 1);
						lua_ref(L, -1);
					}
				}

				if (DllMain) {
					setclvalue(L, L->top, DllMain);
					incr_top(L);

					lua_pushlightuserdata(L, nullptr);
					lua_pushinteger(L, DLL_PROCESS_ATTACH);
					lua_pushboolean(L, false);
					lua_call(L, 3, 1);

					if (L->status != LUA_OK || !lua_toboolean(L, -1)) {
						puts("DLL_PROCESS_ATTACH routine has failed");

						lua_unref(L, refDllMain);
						L->status = LUA_OK;
						continue;
					}
					lua_pop(L, 1);
					lua_unref(L, refDllMain);
				}

			}
			else if (cmd == "help") {
				fprintf(options.out, 
					"  c, continue           - continue execution\n"
					"  s, step               - step into next instruction\n"
					"  n, next               - step over function calls\n"
					"  finish                - step out of current function\n"
					"  bt, backtrace         - dump call stack\n"
					"  b, break <loc>        - set breakpoint at location\n"
					"  d, delete <num>       - delete breakpoint by number\n"
					"  toggle <num>          - enable/disable breakpoint by number\n"
					"  i, inspect [what]     - (no what) show function info\n"
					"    locals              - list all local variables\n"
					"    upvalues            - list upvalues\n"
					"    R<num>              - show value of register\n"
					"    U<num>              - show value of upvalue\n"
					"    K<num>              - show value of constant\n"
					"    stack               - dump stack\n"
					"    breakpoints         - list all breakpoints\n"
					"    funcs               - list loaded functions\n"
					"    insn				 - disassemble current instruction\n"
					"  disasm [func]         - disassemble the provided or the current function\n"
					"  cls                   - clear console\n"
					"  quit, q               - quit\n"
					"  load <filename>       - load a nula library\n"
					"  patch <op> <val>      - patch the current instruction\n"
					"  gc [subcmd]           - (no subcmd) show GC & memory usage info\n"
					"    step                - step the garbage collector\n"
					"    full                - perform a full GC cycle\n"
					"    threshold <val>     - set the GC threshold\n"
					"    pause               - pause the GC completly\n"
					"    resume              - resume the garbage collector\n"
					"    stats               - show statistics\n"
					"    trace               - toggle allocation, deallocation, and reallocation tracing\n"
					"    dump                - dump the entire heap to ./gcdump.json\n"
				);

			}
			else if (cmd == "patch") {
				char operand;
				ss >> std::ws;
				ss >> operand;

				int val = 0;
				if (!(ss >> val)) {
					puts("val must be an integer");
					continue;
				}

				uint8_t* pc = (uint8_t*)(L->ci->savedpc - 1);

				switch (tolower((unsigned char)operand)) {
				case 'a':
					if (val < 0 || val > 255) {
						puts("val must be 0–255 for this operand");
						continue;
					}
					pc[1] = (uint8_t)val;
					break;

				case 'b':
					if (val < 0 || val > 255) {
						puts("val must be 0–255 for this operand");
						continue;
					}
					pc[2] = (uint8_t)val;
					break;

				case 'c':
					if (val < 0 || val > 255) {
						puts("val must be 0–255 for this operand");
						continue;
					}
					pc[3] = (uint8_t)val;
					break;

				case 'd':
					if (val < -32768 || val > 32767) {
						puts("val must be -32768–32767 for this operand");
						continue;
					}
					
					*(int16_t*)(pc + 2) = (int16_t)val;
					break;

				case 'e':
					if (val < -8388608 || val > 8388607) {
						puts("val must be -8388608-8388607 for this operand");
						continue;
					}
					
					pc[1] = (uint8_t)(val & 0xFF);
					pc[2] = (uint8_t)((val >> 8) & 0xFF);
					pc[3] = (uint8_t)((val >> 16) & 0xFF);
					break;

				default:
					puts("invalid operand");
					continue;
				}

				ldbg::idisasm(options.out, (const Instruction*&)pc, clvalue(L->ci->func)->l.p);
				putchar('\n');
			}
			else if (cmd == "gc") {
				std::string subcmd;
				ss >> std::ws;
				ss >> subcmd;

				global_State* g = L->global;

				if (subcmd.empty()) {
					struct Context {
						global_State* g;
						uint32_t dead, total;
					};
					Context ctx = { 0 };
					ctx.g = g;

					luaM_visitgco(L, &ctx, [](void* _ctx, lua_Page* page, GCObject* gco) -> bool {
						if (!iscollectable(&gco->gch))
							return false;
						Context* ctx = (Context*)_ctx;
						ctx->total++;
						if (isdead(ctx->g, gco))
							ctx->dead++;
						return false;
						});
					if (g->GCthreshold == SIZE_MAX) {
						fprintf(options.out, "GC is unavailable\ntotal bytes allocated: " ANSI_YELLOW "%zu\n" ANSI_RESET, g->totalbytes);
					}
					else
						fprintf(options.out, "GC state: %s (threshold: " ANSI_YELLOW "%zu" ANSI_RESET " bytes)\ntotal bytes allocated: " ANSI_YELLOW "%zu\n" ANSI_RESET,
							luaC_statename(g->gcstate), g->GCthreshold, g->totalbytes);

					fprintf(options.out, "total GC objects allocated: " ANSI_YELLOW "%u" ANSI_GREY "\n  %u of them are dead\n" ANSI_GREY, ctx.total, ctx.dead);
					continue;
				}
				else if (subcmd == "step") {
					if (!luaC_needsGC(L)) {
						puts("can't step GC if totalbytes < GCthreshold; either change the threshold or run a full GC cycle");
						continue;
					}

					std::string countStr;
					ss >> std::ws;
					ss >> countStr;

					uint8_t count = 1;
					if (!countStr.empty() && !parseInt(countStr, count)) {
						puts("count must be an integer");
						continue;
					}
					for (uint8_t i = 0; i < count; i++) {
						luaC_step(L, true);
						if (!luaC_needsGC(L))
							break;
					}
				}
				else if (subcmd == "full") {
					if (g->GCthreshold != SIZE_MAX)
						luaC_fullgc(L);
				}
				else if (subcmd == "threshold") {
					std::string thresholdStr;
					ss >> std::ws;
					ss >> thresholdStr;

					size_t threshold = 0;
					if (!parseInt(thresholdStr, threshold)) {
						puts("threshold must be an integer");
						continue;
					}
					g->GCthreshold = threshold;
					if (oldGCThreshold)
						oldGCThreshold = 0;
				}
				else if (subcmd == "pause") {
					if (oldGCThreshold)
						puts("GC is already paused");
					else {
						oldGCThreshold = g->GCthreshold;
						g->GCthreshold = SIZE_MAX;
					}
				}
				else if (subcmd == "resume") {
					if (!oldGCThreshold)
						puts("GC is not paused");
					else {
						g->GCthreshold = oldGCThreshold;
						oldGCThreshold = 0;
					}
				}
				else if (subcmd == "stats") {
					struct Context {
						global_State* g;
						uint32_t dead, total, white, gray, black, fixed;
					};

					Context ctx = { 0 };
					ctx.g = g;

					luaM_visitgco(L, &ctx, [](void* _ctx, lua_Page* page, GCObject* gco) -> bool {
						if (!iscollectable(&gco->gch))
							return false;

						Context* ctx = (Context*)_ctx;
						ctx->total++;

						if (isdead(ctx->g, gco))
							ctx->dead++;
						if (iswhite(gco))
							ctx->white++;
						else if (isblack(gco))
							ctx->black++;
						else if (isgray(gco))
							ctx->gray++;
						if (isfixed(gco))
							ctx->fixed++;
						return false;
					});
	
					fprintf(options.out, 
						"total GC objects: " ANSI_YELLOW "%u\n" ANSI_GREY
						"  %u of them are dead\n"
						"  %u of them are white\n"
						"  %u of them are gray\n"
						"  %u of them are black\n"
						"  %u of them are fixed\n" ANSI_RESET,
						ctx.total, ctx.dead, ctx.white, ctx.gray, ctx.black, ctx.fixed
					);
					
					fprintf(options.out, "heap goal size: " ANSI_YELLOW "%zu" ANSI_RESET " bytes\n", g->gcstats.heapgoalsizebytes);
					fprintf(options.out, "atomic start total size: " ANSI_YELLOW "%zu" ANSI_RESET " bytes\n" ANSI_RESET, g->gcstats.atomicstarttotalsizebytes);
					fprintf(options.out, "end total size: " ANSI_YELLOW "%zu" ANSI_RESET " bytes\n" ANSI_RESET, g->gcstats.endtotalsizebytes);
					fprintf(options.out, "trigger integral: " ANSI_YELLOW "%d\n" ANSI_RESET, g->gcstats.triggerintegral);
					fprintf(options.out, "trigger term position: " ANSI_YELLOW "%u\n" ANSI_RESET, g->gcstats.triggertermpos);

					if (g->gcstats.starttimestamp > 0) {
						fprintf(options.out, "start timestamp: " ANSI_YELLOW "%.6f\n" ANSI_RESET, g->gcstats.starttimestamp);
						fprintf(options.out, "end timestamp: " ANSI_YELLOW "%.6f\n" ANSI_RESET, g->gcstats.endtimestamp);
						fprintf(options.out, "atomic start timestamp: " ANSI_YELLOW "%.6f\n" ANSI_RESET, g->gcstats.atomicstarttimestamp);

						if (g->gcstats.endtimestamp > g->gcstats.starttimestamp)
							fprintf(options.out, "total GC cycle time: " ANSI_YELLOW "%.6f seconds\n" ANSI_RESET, g->gcstats.endtimestamp - g->gcstats.starttimestamp);

						if (g->gcstats.atomicstarttimestamp > g->gcstats.starttimestamp)
							fprintf(options.out, "mark phase time: " ANSI_YELLOW "%.6f seconds\n" ANSI_RESET, g->gcstats.atomicstarttimestamp - g->gcstats.starttimestamp);
					}
				}
				else if (subcmd == "list") {
					std::string arg;

					uint8_t filterType = 255;
					uint8_t filterMarked = 255;
					uint8_t filterMemcat = 255;

					while (ss >> arg) {
						size_t eq = arg.find('=');
						if (eq != std::string::npos) {
							const std::string& key = arg.substr(0, eq);
							const std::string& value = arg.substr(eq + 1);
							if (key == "type") {
								int tt = LUA_TNONE;
								for (int i = 0; i < LUA_T_COUNT; i++) {
									if (value == luaT_typenames[i]) {
										tt = i;
										break;
									}
								}

								if (tt == LUA_TNONE) {
									puts("unknown type");
									goto badOption;
								}

								if (tt < LUA_TSTRING) {
									puts("type is not garbage collectable");
									goto badOption;
								}

								filterType = tt;

							}
							else if (key == "mark") {
								if (value == "white") filterMarked = 0;
								else if (value == "gray") filterMarked = 1;
								else if (value == "black") filterMarked = 2;
								else if (value == "fixed") filterMarked = 3;
								else {
									puts("invalid marked");
									goto badOption;
								}
							}
							else if (key == "memcat") {
								if (!parseInt(value, filterMemcat)) {
									puts("memcat must be an integer");
									goto badOption;
								}

								if (filterMemcat > LUA_MEMORY_CATEGORIES) {
									puts("memcat out of range");
									goto badOption;
								}
							}
							else {
								puts("unknown option");
								goto badOption;
							}
						}
					}

					// TODO: fuckass
					goto allGood;
				badOption:
					continue;
				allGood:;

					struct Context {
						global_State* g;
						FILE* out;

						uint32_t count;
						uint8_t filterType;
						uint8_t filterMarked;
						uint8_t filterMemcat;
					};
					Context ctx = { g, options.out, filterType, filterMarked, filterMemcat, 0 };

					luaM_visitgco(L, &ctx, [](void* _ctx, lua_Page* page, GCObject* gco) -> bool {
						if (!iscollectable(&gco->gch))
							return false;
						Context* ctx = (Context*)_ctx;

						if (ctx->filterType != 255 && gco->gch.tt != ctx->filterType)
							return false;

						if (ctx->filterMemcat != 255 && gco->gch.memcat != ctx->filterMemcat)
							return false;

						switch (ctx->filterMarked) {
						case 0:
							if (!iswhite(gco))
								return false;
							break;
						case 1:
							if (!isgray(gco))
								return false;
							break;
						case 2:
							if (!isblack(gco))
								return false;
							break;
						case 3:
							if (!isfixed(gco))
								return false;
							break;
						default:
							break;
						}
						
						TValue o;
						o.value.p = gco;
						o.tt = gco->gch.tt;
						const std::string& s = lua_strprimitive(&o);

						fprintf(ctx->out, "  %.*s (address = " ANSI_YELLOW "0x%llx" ANSI_RESET ", type=%s, marked=%s%s, memcat=" ANSI_YELLOW "%u" ANSI_RESET ")\n",
							(uint32_t)s.length(), s.c_str(),
							(uintptr_t)gco,
							luaT_typenames[gco->gch.tt],
							isfixed(gco) ? "fixed " : "", iswhite(gco) ? "white" : isblack(gco) ? "black" : isgray(gco) ? "gray" : "unknown",
							gco->gch.memcat
						);
						ctx->count++;
						return false;
					});
					fprintf(options.out, "\ntotal objects: " ANSI_YELLOW "%u\n" ANSI_RESET, ctx.count);
				}
				else if (subcmd == "trace") {
					if (oldFrealloc) {
						g->ud = nullptr;
						g->frealloc = oldFrealloc;
						oldFrealloc = nullptr;
						fprintf(options.out, "allocation tracing disabled\n");
					}
					else {
						oldFrealloc = g->frealloc;
						g->frealloc = frealloc;
						g->ud = this;
						fprintf(options.out, "allocation tracing enabled\n");
					}
				}
				else if (subcmd == "dump") {
					FILE* file = nullptr;
					if (!fopen_s(&file, "gcdump.json", "w") || !file) {
						puts("unable to open gcdump.json");
						continue;
					}

					luaC_dump(L, file, nullptr);
					fclose(file);
					puts("heap dump written to gcdump.json");
				}
				else puts("unknown subcommand");
			}
			else {
				const std::string& btc = Luau::compile(line, { 2, 2, 1 }, {}, nullptr);

				L->singlestep = false;
				lua_pushcfunction(L, options.onError, "");
				if (luau_load(L, "ldbg", btc.data(), btc.size(), 0)) puts(lua_tostring(L, -1));
				else lua_pcall(L, 0, 0, -2);
				lua_pop(L, 1);
				L->singlestep = true;
			}
		}
	}

	void Debugger::debugstep(lua_State* L, lua_Debug* ar) {
		if (!debugstepActive)
			return;

		const Closure* cl = clvalue(L->ci->func);
		if (cl->isC)
			return;

		const Instruction* pc = L->ci->savedpc - 1;
		uint32_t level = (uint32_t)(L->ci - L->base_ci);
		if (level != lastLevel) {
			if (state == State::None) {
				dumpFunctionInfo(L);
				putchar('\n');
			}
			lastLevel = level;
		}

		switch (state) {
		case State::StepOver: {
			if (level < stateLevel)
				state = State::None;
			else if (level > stateLevel)
				return;
		} break;

		case State::Finish: {
			uint32_t level = (uint32_t)(L->ci - L->base_ci);

			if (level < stateLevel) {
				state = State::None;

				const CallInfo* cip = L->ci + 1;
				const Instruction* pc = cip->savedpc;
				if (LUAU_INSN_OP(*pc) == LOP_RETURN) {
					dumpFunctionInfo(L);

					uint8_t ra = LUAU_INSN_A(*pc);
					uint8_t rb = LUAU_INSN_B(*pc);
		
					int count = 0;
					if (rb == 0)
						count = (int)(L->top - (cip->base + ra));
					else
						count = rb - 1;

					printf("returned " ANSI_YELLOW "%d" ANSI_RESET " value(s):\n", count);
					for (int i = 0; i < count; i++)
						printf(ANSI_GREY "  %d " ANSI_RESET "= %s\n", i + 1, lua_strprimitive(cip->base + ra + i).c_str());
				}
			} else
				return;
		} break;

		default:
			break;
		}

		ldbg::idisasm(stdout, pc, cl->l.p);
		putchar('\n');

		repl(L);
	}

	void Debugger::debugbreak(lua_State* L, lua_Debug* ar) {
		const Closure* cl = clvalue(L->ci->func);
		if (cl->isC)
			return;

		printf("breakpoint hit in function '%s' at %s:" ANSI_YELLOW "%d\n" ANSI_RESET,
			cl->l.p->debugname ? getstr(cl->l.p->debugname) : "??",
			getSource(cl->l.p).c_str(), ar->currentline
		);

		const Instruction* pc = L->ci->savedpc - 1;

		if (!ar->userdata) {
			ldbg::idisasm(stdout, pc, cl->l.p);
			putchar('\n');

			repl(L);
		} else
			debugstepActive = true;
	}

} // namespace ldbg
