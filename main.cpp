#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <iostream>

#include <lmem.h>
#include <lfunc.h>
#include <ldebug.h>
#include <lualib.h>
#include <Luau/Bytecode.h>

#include "disasm.h"

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
		int line : 31;
		int enabled : 1;
	};

	std::vector<Proto*> loadedProtos;
	std::vector<Breakpoint> breakpoints;

	State state;
	uint32_t lastLevel = 0;
	uint32_t stateLevel = 0;
	bool debugstepActive = true;

	extern std::string lua_strprimitive(const TValue* o);

	void collectProtos(Proto* p) {
		if (!p)
			return;

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

	void setBreakpoint(lua_State* L, const std::string& source, int line, bool enable) {
		int count = 0;
		for (const auto& p : loadedProtos) {
			if (!p->lineinfo)
				continue;
			TString* protoSrc = p->source;

			bool matches = false;
			if (source == getstr(protoSrc))
				matches = true;
			else {
				char ss[LUA_IDSIZE];
				if (source == luaO_chunkid(ss, sizeof(ss), getstr(protoSrc), protoSrc->len))
					matches = true;
			}

			if (matches) {
				for (int i = 0; i < p->sizecode; i++) {
					if (LUAU_INSN_OP(p->code[i]) == LOP_PREPVARARGS)
						continue;

					if (luaG_getline(p, i) != line)
						continue;

					if (!p->debuginsn) {
						p->debuginsn = luaM_newarray(L, p->sizecode, uint8_t, p->memcat);
						for (int j = 0; j < p->sizecode; j++)
							p->debuginsn[j] = LUAU_INSN_OP(p->code[j]);
					}

					p->code[i] &= ~0xff;
					p->code[i] |= enable ? LOP_BREAK : LUAU_INSN_OP(p->debuginsn[i]);

					if (enable) {
						bool exists = false;
						for (auto& bp : breakpoints) {
							if (bp.p == p && bp.pc == i) {
								bp.enabled = true;
								exists = true;
								break;
							}
						}

						if (!exists)
							breakpoints.push_back({ p, source, i, line, true });
					} else {
						for (auto it = breakpoints.begin(); it != breakpoints.end(); it++) {
							if (it->p == p && it->pc == i) {
								breakpoints.erase(it);
								break;
							}
						}
					}

					count++;
					break;
				}
			}
		}

		if (count > 0)
			printf("breakpoint %zu %s at %s:%d\n", breakpoints.size(), enable ? "set" : "cleared", source.c_str(), line);
		else
			printf("no functions found matching source '%s' or line number out of range\n", source.c_str());
	}

	void setBreakpoint(lua_State* L, Proto* p, bool enable) {
		bool found = false;
		for (int i = 0; i < p->sizecode; i++) {
			if (LUAU_INSN_OP(p->code[i]) == LOP_PREPVARARGS)
				continue;

			if (!p->debuginsn) {
				p->debuginsn = luaM_newarray(L, p->sizecode, uint8_t, p->memcat);
				for (int j = 0; j < p->sizecode; j++)
					p->debuginsn[j] = LUAU_INSN_OP(p->code[j]);
			}

			p->code[i] &= ~0xff;
			p->code[i] |= enable ? LOP_BREAK : LUAU_INSN_OP(p->debuginsn[i]);

			if (enable) {
				bool exists = false;
				for (auto& bp : breakpoints) {
					if (bp.p == p && bp.pc == i) {
						bp.enabled = true;
						exists = true;
						break;
					}
				}

				if (!exists)
					breakpoints.push_back({ p, getstr(p->source), i, p->linedefined, true });
			} else {
				for (auto it = breakpoints.begin(); it != breakpoints.end(); ++it) {
					if (it->p == p && it->pc == i) {
						breakpoints.erase(it);
						break;
					}
				}
			}

			found = true;
			break;
		}

		if (found)
			printf("breakpoint %zu %s at %s:%d\n", breakpoints.size(), enable ? "set" : "cleared", getstr(p->source), p->linedefined);
		else
			printf("line number out of range\n");
	}

	void toggleBreakpoint(lua_State* L, size_t num) {
		if (num < 1 || num > breakpoints.size()) {
			puts("invalid breakpoint number");
			return;
		}

		auto& bp = breakpoints[num - 1];
		bp.enabled ^= true;

		bp.p->code[bp.pc] &= ~0xff;
		bp.p->code[bp.pc] |= bp.enabled ? LOP_BREAK : LUAU_INSN_OP(bp.p->debuginsn[bp.pc]);

		printf("breakpoint %zu %s\n", num, bp.enabled ? "enabled" : "disabled");
	}

	void repl(lua_State* L) {
		debugstepActive = true;

		std::string line;
		while (true) {
			fputs("\n(ldbg) ", stdout);
			if (!std::getline(std::cin, line))
				break;

			if (line.empty())
				continue;

			std::istringstream ss(line);
			std::string cmd;
			ss >> cmd;

			if (cmd == "c" || cmd == "continue") {
				state = State::None;
				debugstepActive = false;
				break;

			} else if (cmd == "bt" || cmd == "backtrace") {
				lua_Debug ar;
				int level = 0;
				fputs("(current) ", stdout);
				while (lua_getinfo(L, level++, "sl", &ar))
					printf("%d - %s:%d\n", level, ar.short_src, ar.currentline);

			} else if (cmd == "quit" || cmd == "q") {
				L->status = LUA_ERRRUN;
				break;

			} else if (cmd == "s" || cmd == "step") {
				state = State::None;
				break;

			} else if (cmd == "n" || cmd == "next") {
				state = State::StepOver;
				stateLevel = (uint32_t)(L->ci - L->base_ci);
				break;

			} else if (cmd == "finish") {
				state = State::Finish;
				stateLevel = (uint32_t)(L->ci - L->base_ci);
				break;

			} else if (cmd == "b" || cmd == "break") {
				std::string loc;
				ss >> std::ws;
				std::getline(ss, loc);

				if (loc.empty()) {
					puts("usage: break <file:line>, <line>, or <funcname>");
					continue;
				}

				size_t colon = loc.find(':');
				if (colon != std::string::npos) {
					std::string file = loc.substr(0, colon);
					uint32_t ln = std::stoi(loc.substr(colon + 1));
					setBreakpoint(L, file, ln, true);
				} else {
					bool isNumber = true;
					for (char c : loc)
						if (!isdigit(c)) {
							isNumber = false;
							break;
						}

					if (isNumber) {
						lua_Debug ar;
						if (lua_getinfo(L, 0, "s", &ar))
							setBreakpoint(L, ar.short_src, std::stoi(loc), true);
						else
							puts("cannot determine current source file");
					} else {
						bool found = false;
						for (const auto& p : loadedProtos) {
							if (p->debugname && getstr(p->debugname) == loc) {
								setBreakpoint(L, p, true);
								found = true;
								break;
							}
						}

						if (!found)
							puts("function not found");
					}
				}

			} else if (cmd == "d" || cmd == "delete") {
				size_t num = 0;
				if (ss >> num) {
					if (num < 1 || num > breakpoints.size()) {
						puts("invalid breakpoint number");
						return;
					}

					const auto& bp = breakpoints[num - 1];
					if (bp.p->debuginsn) {
						bp.p->code[bp.pc] &= ~0xff;
						bp.p->code[bp.pc] |= LUAU_INSN_OP(bp.p->debuginsn[bp.pc]);
					}

					printf("deleted breakpoint %zu at %s:%d\n", num, bp.source.c_str(), bp.line);
					breakpoints.erase(breakpoints.begin() + (num - 1));
				} else
					puts("usage: delete <breakpoint number>");

			} else if (cmd == "toggle") {
				size_t num;
				if (ss >> num)
					toggleBreakpoint(L, num);
				else
					puts("usage: toggle <breakpoint number>");

			} else if (cmd == "info") {
				std::string subcmd;
				ss >> std::ws;
				std::getline(ss, subcmd);

				if (subcmd.empty())
					dumpFunctionInfo(L);
				else {
					const Proto* p = clvalue(L->ci->func)->l.p;

					if (subcmd == "locals") {
						if (p->sizelocvars) {
							for (int i = 0; i < p->sizelocvars; i++) {
								const LocVar* local = &p->locvars[i];

								const int pc = (int)((L->ci->savedpc - 1) - p->code);
								if (pc >= local->startpc && pc < local->endpc)
									printf("  %s = R%u\n", getstr(local->varname), local->reg);
							}
						} else
							puts("missing local info; is debug level set to 2?");

					} else if (subcmd == "upvalues") {
						if (p->sizeupvalues) {
							for (int i = 0; i < p->sizeupvalues; i++)
								printf("  %s = U%d\n", getstr(p->upvalues[i]), i);
						} else
							puts("missing local info; is debug level set to 2?");

					} else if (subcmd[0] == 'R') {
						uint8_t idx = std::stoi(subcmd.substr(1));
						puts(lua_strprimitive(L->ci->base + idx).c_str());

					} else if (subcmd == "stack") {
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

					} else if (subcmd == "breakpoints") {
						if (breakpoints.empty()) {
							puts("no breakpoints set");
							continue;
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

					} else if (subcmd == "protos") {
						if (loadedProtos.empty()) {
							puts("no protos loaded");
							continue;
						}

						printf(
							"%-4s %-30s %-8s %s\n"
							"---- ------------------------------ -------- --------------------\n",
							"n", "func", "line", "source"
						);

						size_t i = 0;
						for (const auto& p : loadedProtos) {
							char ss[LUA_IDSIZE];
							printf("%-4zu %-30s %-8d %s\n",
								++i,
								p->debugname ? getstr(p->debugname) : "??", p->linedefined,
								luaO_chunkid(ss, sizeof(ss), getstr(p->source), p->source->len)
							);
						}

					} else
						puts("unknown subcommand");
				}

			} else if (cmd == "disasm") {
				const Closure* cl = clvalue(L->ci->func);
				const Instruction* pc = cl->l.p->code;
				const Instruction* end = cl->l.p->code + cl->l.p->sizecode;

				while (pc < end) {
					printf("%04X  ", (uint32_t)(pc - cl->l.p->code));
					ldbg::idisasm(stdout, pc, cl->l.p);
					putchar('\n');
					pc++;
				}

			} else if (cmd == "cls") {
				system("cls");

			} else if (cmd == "help") {
				printf(
					"  c, continue           - continue execution\n"
					"  s, step               - step into next instruction\n"
					"  n, next               - step over function calls\n"
					"  finish                - step out of current function\n"
					"  bt, backtrace         - dump call stack\n"
					"  b, break <loc>        - set breakpoint (source:line, line, or function)\n"
					"  d, delete <num>       - delete breakpoint by number\n"
					"  toggle <num>          - enable/disable breakpoint by number\n"
					"  info                  - show function info\n"
					"    locals              - show local variables\n"
					"    upvalues            - show upvalues\n"
					"    R<num>              - show value of register <num>\n"
					"    stack               - dump stack\n"
					"    breakpoints         - list all breakpoints\n"
					"    protos              - list loaded functions\n"
					"  disasm                - disassemble current function\n"
					"  cls                   - clear console\n"
					"  quit, q               - quit\n"
				);

			} else {
				const std::string& btc = Luau::compile(line, { 2, 2, 1 }, {}, nullptr);

				if (!luau_load(L, "=[string \"=\"]", btc.data(), btc.size(), 0)) {
					// TODO: maybe we should run this on a separate thread
					L->singlestep = false;
					lua_call(L, 0, 0);
					L->singlestep = true;
				} else
					puts(lua_tostring(L, -1));
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
						printf("returned %d values:\n", count);
			
						for (int i = 0; i < count; i++)
							printf("  R%d = %s\n", ra + i, lua_strprimitive(cip->base + ra + i).c_str());
					} else {
						int count = rb - 1;
						printf("returned %d values\n", count);
			
						for (int i = 0; i < count; i++)
							printf("  R%d = %s\n", ra + i, lua_strprimitive(cip->base + ra + i).c_str());
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
			luaO_chunkid(ar->ssbuf, sizeof(ar->ssbuf), getstr(cl->l.p->source), cl->l.p->source->len), ar->currentline
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
		luaL_sandbox(L);

		L->global->cb.debugstep = ldbg::debugstep;
		L->global->cb.debugbreak = ldbg::debugbreak;
		L->singlestep = true;

		std::ifstream file(argv[1], std::ios::binary | std::ios::ate);
		std::streamsize size = file.tellg();
		file.seekg(0, std::ios::beg);

		std::string src(size, '\0');
		if (!file.read(&src[0], size)) {
			puts("unable to read file");
			return 1;
		}

		if (isprint(src[0]) && isprint(src[1]))
			src = Luau::compile(src, {
				1,	// O2 can harm debuggability
				2,	// all debug info
				1,	// type info for all modules
				1,	// TODO: not sure if coverage is helpful
			}, {}, nullptr);

		if (!luau_load(L, "=[string \"=\"]", src.data(), src.size(), 0)) {
			const Closure* cl = clvalue(L->top - 1);
			ldbg::collectProtos(cl->l.p);

			lua_call(L, 0, 0);
		} else
			puts(lua_tostring(L, -1));

		return 0;
	} catch (const std::exception& e) {
		std::cout << e.what();
		return 1;
	}
}
