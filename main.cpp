#include <string>
#include <vector>
#include <format>
#include <sstream>
#include <fstream>
#include <iostream>
#include <algorithm>

#include <lgc.h>
#include <lmem.h>
#include <lfunc.h>
#include <ldebug.h>
#include <lualib.h>
#include <Luau/Bytecode.h>

#include "disasm.h"

#define DLL_PROCESS_ATTACH	1
#define DLL_THREAD_ATTACH	2
#define DLL_THREAD_DETACH	3
#define DLL_PROCESS_DETACH	0

namespace nula {
	constexpr uint8_t utag = 45; // n + u + l + a
	constexpr uint32_t signature = 0x616c756e;
}

namespace ldbg {
	enum class State {
		None,
		Finish,
		StepOver
	};

	struct Breakpoint {
		Proto* p;
		std::string source;
		int pc;
		int enabled : 1;
		uint32_t line : 31;
	};

	std::vector<Proto*> loadedProtos;
	std::vector<Breakpoint> breakpoints;

	uint32_t lastLevel = 0;
	uint32_t stateLevel = 0;
	State state = State::None;
	bool debugstepActive = true;

	extern std::string lua_strprimitive(const TValue* o);

	static bool isNumber(const std::string& s) {
		if (s.empty())
			return false;

		if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
			return std::all_of(s.begin() + 2, s.end(), [](unsigned char c) { return isxdigit(c); });

		return std::all_of(s.begin(), s.end(), [](unsigned char c) { return isdigit(c); });
	}

	static std::string getSource(Proto* p) {
		char ss[LUA_IDSIZE];
		return luaO_chunkid(ss, sizeof(ss), getstr(p->source), p->source->len);
	}

	static void ensureDebugInsn(lua_State* L, Proto* p) {
		if (p->debuginsn)
			return;

		p->debuginsn = luaM_newarray(L, p->sizecode, uint8_t, p->memcat);
		for (int j = 0; j < p->sizecode; j++)
			p->debuginsn[j] = LUAU_INSN_OP(p->code[j]);
	}

	static size_t addBreakpoint(Proto* p, const std::string& source, int pc, uint32_t line) {
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

	static bool removeBreakpoint(Proto* p, int pc) {
		for (auto it = breakpoints.begin(); it != breakpoints.end(); ++it) {
			if (it->p == p && it->pc == pc) {
				breakpoints.erase(it);
				return true;
			}
		}
		return false;
	}

	static int _handler(lua_State* L) {
		printf("%s\nStack Begin\n", luaL_checkstring(L, 1));
		lua_getglobal(L, "debug");
		lua_getfield(L, -1, "traceback");
		lua_call(L, 0, 1);
		if (const char* traceback = lua_tostring(L, -1))
			printf("%s", traceback);
		printf("Stack End\n");
		lua_pop(L, 2);
		return 0;
	}

	void collectProtos(Proto* p) {
		for (const auto& proto : loadedProtos) {
			if (proto == p)
				return;
		}

		loadedProtos.push_back(p);
		for (int i = 0; i < p->sizep; i++)
			collectProtos(p->p[i]);
	}

	void dumpFunctionInfo(lua_State* L) {
		lua_Debug ar;
		if (lua_getinfo(L, 0, "sln", &ar)) {
			const Closure* cl = clvalue(L->ci->func);
			printf("=> %s() at %s:%d\n", cl->l.p->debugname ? getstr(cl->l.p->debugname) : "??", ar.short_src, ar.currentline);
		}
	}

	static void setBreakpointAtPc(lua_State* L, Proto* p, int pc, bool enable, const std::string& source, uint32_t line) {
		ensureDebugInsn(L, p);
		p->code[pc] &= ~0xFF;
		p->code[pc] |= enable ? LOP_BREAK : LUAU_INSN_OP(p->debuginsn[pc]);

		if (enable)
			addBreakpoint(p, source, pc, line);
		else
			removeBreakpoint(p, pc);
	}

	void setBreakpoint(lua_State* L, const std::string& source, uint32_t line, bool enable) {
		int count = 0;
		for (const auto& p : loadedProtos) {
			if (!p->lineinfo || source == getSource(p))
				continue;

			for (int i = 0; i < p->sizecode; i++) {
				if (LUAU_INSN_OP(p->code[i]) == LOP_PREPVARARGS)
					continue;

				if (luaG_getline(p, i) != line)
					continue;

				setBreakpointAtPc(L, p, i, enable, source, line);
				count++;
				break;
			}
		}

		if (count > 0)
			printf("breakpoint %zu %s at %s:%d\n", breakpoints.size(), enable ? "set" : "cleared", source.c_str(), line);
		else
			printf("no functions found matching source '%s' or line number out of range\n", source.c_str());
	}

	void setBreakpoint(lua_State* L, Proto* p, bool enable) {
		for (int i = 0; i < p->sizecode; i++) {
			if (LUAU_INSN_OP(p->code[i]) == LOP_PREPVARARGS)
				continue;

			setBreakpointAtPc(L, p, i, enable, getstr(p->source), (uint32_t)p->linedefined);
			break;
		}

		printf("breakpoint %zu %s at %s:%d\n", breakpoints.size(), enable ? "set" : "cleared", getstr(p->source), p->linedefined);
	}

	void toggleBreakpoint(lua_State* L, size_t num) {
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

		printf("breakpoint %zu %s\n", num, bp.enabled ? "enabled" : "disabled");
	}

	static void handleBreakByPc(lua_State* L, Proto* p, int pc) {
		if (pc >= p->sizecode) {
			puts("pc out of range");
			return;
		}

		ensureDebugInsn(L, p);
		p->code[pc] = LOP_BREAK;

		uint32_t ln = luaG_getline(p, pc);
		printf("breakpoint %zu set at %s:%d\n", addBreakpoint(p, getSource(p), pc, ln), getSource(p).c_str(), ln);
	}

	static void handleBreakByFunc(lua_State* L, const std::string& source, const std::string& func) {
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
	
	void repl(lua_State* L) {
		debugstepActive = true;

		std::string line;
		while (true) {
			fputs("(ldbg) ", stdout);
			if (!std::getline(std::cin, line))
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
				fputs("(current) ", stdout);
				while (lua_getinfo(L, level++, "sl", &ar))
					printf("%d - %s:%d\n", level, ar.short_src, ar.currentline);

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
						return;
					}

					const auto& bp = breakpoints[num - 1];
					if (bp.p->debuginsn) {
						bp.p->code[bp.pc] &= ~0xFF;
						bp.p->code[bp.pc] |= LUAU_INSN_OP(bp.p->debuginsn[bp.pc]);
					}

					printf("deleted breakpoint %zu at %s:%d\n", num, bp.source.c_str(), bp.line);
					breakpoints.erase(breakpoints.begin() + (num - 1));
				} else
					puts("usage: delete <breakpoint number>");

			}
			else if (cmd == "toggle") {
				size_t num;
				if (ss >> num)
					toggleBreakpoint(L, num);
				else
					puts("usage: toggle <breakpoint number>");

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
						return;
					}

					for (int i = 0; i < p->sizelocvars; i++) {
						const LocVar* local = &p->locvars[i];

						const int pc = (int)((L->ci->savedpc - 1) - p->code);
						printf("  R%u = %s", local->reg, getstr(local->varname));
						if (pc > local->startpc && pc <= local->endpc)
							putchar('\n');
						else
							puts(" ; inactive");
					}
				}
				else if (subcmd == "upvalues") {
					if (!p->sizeupvalues) {
						puts("missing upvalue info");
						return;
					}

					for (int i = 0; i < p->sizeupvalues; i++)
						printf("  U%d = %s\n", i, getstr(p->upvalues[i]));
				}
				else if (subcmd == "stack") {
					const uint32_t end = p->maxstacksize;
					const uint32_t rows = (end + 3) / 4;

					for (uint32_t i = 0; i < rows; i++) {
						for (uint32_t j = 0; j < 4; j++) {
							uint32_t idx = i + j * rows;
							if (idx < end)
								printf("R%-3d = %-15s", idx, lua_strprimitive(L->ci->base + idx).c_str());
						}
						putchar('\n');
					}
				}
				else if (subcmd == "breakpoints") {
					if (breakpoints.empty()) {
						puts("no breakpoints set");
						return;
					}

					printf(
						"%-4s %-8s %-30s %s\n"
						"---- -------- ------------------------------ ----------\n",
						"n", "active", "location", "func");

					size_t i = 0;
					for (const auto& bp : breakpoints) {
						const char* funcName = bp.p->debugname ? getstr(bp.p->debugname) : "??";
						printf("%-4zu %-8s %-30s %s\n",
							++i,
							bp.enabled ? "yes" : "no",
							(bp.source + ":" + std::to_string(bp.line)).c_str(), funcName
						);
					}
				}
				else if (subcmd == "funcs") {
					if (loadedProtos.empty()) {
						puts("no functions loaded");
						return;
					}

					printf(
						"%-4s %-30s %-8s %s\n"
						"---- ------------------------------ -------- --------------------\n",
						"n", "func", "line", "source"
					);

					size_t i = 0;
					for (const auto& p : loadedProtos) {
						printf("%-4zu %-30s %-8d %s\n",
							++i,
							p->debugname ? getstr(p->debugname) : "??", p->linedefined,
							getSource(p).c_str()
						);
					}
				}
				else if (subcmd == "insn") {
					const Instruction* pc = L->ci->savedpc - 1;
					ldbg::idisasm(stdout, pc, p);
					putchar('\n');
				}
				else if (subcmd[0] == 'R') {
					uint8_t idx = std::stoi(subcmd.substr(1));
					if (idx > p->maxstacksize)
						puts("index out of range");
					else
						puts(lua_strprimitive(L->ci->base + idx).c_str());
				}
				else if (subcmd[0] == 'K') {
					int idx = std::stoi(subcmd.substr(1));
					if (idx < 0 || idx > p->sizek)
						puts("index out of range");
					else
						puts(lua_strprimitive(&p->k[idx]).c_str());
				}
				else if (subcmd[0] == 'U') {
					uint8_t idx = std::stoi(subcmd.substr(1));
					if (idx > p->nups)
						puts("index out of range");
					else
						puts(lua_strprimitive(&cl->l.uprefs[idx]).c_str());
				}
				else if (subcmd == "mem") {
					global_State* g = L->global;

					printf("total memory usage: %zu bytes\n", g->totalbytes);
					if (g->GCthreshold == SIZE_MAX)
						puts("GC is unavailable");
					else {
						static const char* const gcStates[] = { "pause", "propagate", "propagateagain", "atomic", "sweep" };
						printf("GC state: %s (threshold: %zu)\n", gcStates[g->gcstate], g->GCthreshold);
					}

				} else
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
					printf("  %04X  ", (uint32_t)(pc - p->code));
					ldbg::idisasm(stdout, pc, p);
					putchar('\n');
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
				printf(
					"  c, continue           - continue execution\n"
					"  s, step               - step into next instruction\n"
					"  n, next               - step over function calls\n"
					"  finish                - step out of current function\n"
					"  bt, backtrace         - dump call stack\n"
					"  b, break <loc>        - set breakpoint at location\n"
					"  d, delete <num>       - delete breakpoint by number\n"
					"  toggle <num>          - enable/disable breakpoint by number\n"
					"  i, inspect [what]     - (no what) show function info\n"
					"    locals              - list active local variables\n"
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
					
					*(int16_t*)(pc + 1) = (int16_t)val;
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
			}
			else {
				const std::string& btc = Luau::compile(line, { 2, 2, 1 }, {}, nullptr);

				if (luau_load(L, "ldbg", btc.data(), btc.size(), 0))
					puts(lua_tostring(L, -1));
				else {
					lua_pushcfunction(L, _handler, "");
					lua_pcall(L, 0, 0, -2);
				}
				lua_pop(L, 1);
			}
		}
	}

	void debugstep(lua_State* L, lua_Debug* ar) {
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
		
					if (rb == 0) {
						int count = (int)(L->top - (cip->base + ra));
						printf("returned %d value(s):\n", count);
			
						for (int i = 0; i < count; i++)
							printf("  %d = %s\n", i + 1, lua_strprimitive(cip->base + ra + i).c_str());
					} else {
						int count = rb - 1;
						printf("returned %d value(s)\n", count);
			
						for (int i = 0; i < count; i++)
							printf("  %d = %s\n", i + 1, lua_strprimitive(cip->base + ra + i).c_str());
					}
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

	void debugbreak(lua_State* L, lua_Debug* ar) {
		const Closure* cl = clvalue(L->ci->func);
		if (cl->isC)
			return;

		printf("breakpoint hit in function '%s' at %s:%d\n",
			cl->l.p->debugname ? getstr(cl->l.p->debugname) : "??",
			getSource(cl->l.p).c_str(), ar->currentline
		);

		const Instruction* pc = L->ci->savedpc - 1;
		ldbg::idisasm(stdout, pc, cl->l.p);
		putchar('\n');

		repl(L);
	}
}

int main(int argc, char** argv) {
	if (argc < 2) {
		printf("usage: ldbg <filename>\n");
		return 1;
	}

	try {
		lua_State* L = luaL_newstate();
		luaL_openlibs(L);
		luaL_sandboxthread(L);

		L->global->cb.debugstep = ldbg::debugstep;
		L->global->cb.debugbreak = ldbg::debugbreak;
		L->singlestep = true;

		std::ifstream file(argv[1], std::ios::binary | std::ios::ate);
		if (!file.is_open()) {
			puts("unable to open file");
			return 1;
		}

		std::streamsize size = file.tellg();
		file.seekg(0, std::ios::beg);

		std::string src(size, '\0');
		if (!file.read(&src[0], size)) {
			puts("unable to read file");
			return 1;
		}

		if (isprint(src[0]) && isprint(src[1]))
			src = Luau::compile(src, {
				1, // O2 can harm debuggability
				2, // all debug info
				1,
				1, // verbose coverage is stupid
			}, {}, nullptr);

		if (!luau_load(L, std::format("@{}", argv[1]).c_str(), src.data(), src.size(), 0)) {
			const Closure* cl = clvalue(L->top - 1);
			ldbg::collectProtos(cl->l.p);
			lua_call(L, 0, 0);
		} else {
			puts(lua_tostring(L, -1));
			return 1;
		}

		return 0;
	} catch (const std::exception& e) {
		std::cout << e.what();
		return 1;
	}
}
