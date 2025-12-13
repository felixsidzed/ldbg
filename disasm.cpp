#include "disasm.h"

#include <format>
#include <sstream>
#include <iomanip>

#include <lua.h>
#include <lualib.h>
#include <ldebug.h>
#include <Luau/Compiler.h>
#include <Luau/Bytecode.h>
#include <Luau/BytecodeUtils.h>

namespace ldbg {
	static const char* luau_opcode[LOP__COUNT] = {
		"NOP", "BREAK",
		"LOADNIL", "LOADB", "LOADN", "LOADK",
		"MOVE",
		"GETGLOBAL", "SETGLOBAL",
		"GETUPVAL", "SETUPVAL", "CLOSEUPVALS",
		"GETIMPORT",
		"GETTABLE", "SETTABLE", "GETTABLEKS", "SETTABLEKS", "GETTABLEN", "SETTABLEN",
		"NEWCLOSURE",
		"NAMECALL", "CALL", "RETURN",
		"JUMP", "JUMPBACK", "JUMPIF", "JUMPIFNOT", "JUMPIFEQ", "JUMPIFLE", "JUMPIFLT", "JUMPIFNOTEQ", "JUMPIFNOTLE", "JUMPIFNOTLT",
		"ADD", "SUB", "MUL", "DIV", "MOD", "POW", "ADDK", "SUBK", "MULK", "DIVK", "MODK", "POWK", "AND", "OR", "ANDK", "ORK",
		"CONCAT", "NOT", "MINUS", "LENGTH",
		"NEWTABLE", "DUPTABLE", "SETLIST",
		"FORNPREP", "FORNLOOP", "FORGLOOP", "FORGPREP_INEXT",
		"FASTCALL3", "FORGPREP_NEXT", "NATIVECALL",
		"GETVARARGS", "DUPCLOSURE", "PREPVARARGS",
		"LOADKX", "JUMPX",
		"FASTCALL", "COVERAGE", "CAPTURE",
		"SUBRK", "DIVRK",
		"FASTCALL1", "FASTCALL2", "FASTCALL2K",
		"FORGPREP", "JUMPXEQKNIL", "JUMPXEQKB", "JUMPXEQKN", "JUMPXEQKS",
		"IDIV", "IDIVK",
	};

	std::string lua_strprimitive(const TValue* o) {
		switch (ttype(o)) {
		case LUA_TNIL:
			return "nil";
		case LUA_TBOOLEAN:
			return bvalue(o) ? "true" : "false";
		case LUA_TNUMBER: {
			char buf[32];
			snprintf(buf, sizeof(buf), "%.14g", nvalue(o));
			return buf;
		}
		case LUA_TSTRING:
			return '"' + std::string(svalue(o), tsvalue(o)->len) + '"';
		case LUA_TFUNCTION:
			if (Closure* cl = clvalue(o)) {
				if (cl->isC) {
					if (cl->c.debugname)
						return cl->c.debugname;
				} else {
					if (cl->l.p && cl->l.p->debugname)
						return std::string(getstr(cl->l.p->debugname), cl->l.p->debugname->len);
				}
			}
			[[fallthrough]];
		default:
			return "";
		}
	}
	
	void idisasm(FILE* f, const Instruction*& pc, const Proto* p) {
		const Instruction insn = *pc;
#ifdef LDBG_ROBLOX
		const uint8_t op = reverse(LUAU_INSN_OP(insn)) * 223;
#else
		const uint8_t op = LUAU_INSN_OP(insn);
#endif

		if (op >= LOP__COUNT) {
			fprintf(f, "INVALID %u", op);
			return;
		}
		fputs(luau_opcode[op], f); fputc(' ', f);

		uint32_t line = (uint32_t)(pc - p->code);
		switch (op) {
		case LOP_BREAK: {
			uint8_t realOp = p->debuginsn[line];
			if (Luau::getOpLength((LuauOpcode)realOp) - 1) {
				const Instruction copy[2] = { (insn & 0xFFFFFF00) | realOp, *++pc };
				const Instruction* pcCopy = copy;
				idisasm(f, pcCopy, p);
			} else {
				const Instruction copy = (insn & 0xFFFFFF00) | realOp;
				const Instruction* pcCopy = &copy;
				idisasm(f, pcCopy, p);
			}
		} break;
		case LOP_LOADNIL:
		case LOP_PREPVARARGS:
		case LOP_FORGPREP_INEXT:
		case LOP_CLOSEUPVALS:
			fprintf(f, "R%u", LUAU_INSN_A(insn));
			break;
		case LOP_LOADB:
			fprintf(f, "R%u %s", LUAU_INSN_A(insn), LUAU_INSN_B(insn) ? "true" : "false");
			pc += LUAU_INSN_C(insn);
			break;
		case LOP_LOADN:
			fprintf(f, "R%u %hd", LUAU_INSN_A(insn), LUAU_INSN_D(insn));
			break;
		case LOP_MOVE:
		case LOP_NOT:
		case LOP_MINUS:
		case LOP_LENGTH:
			fprintf(f, "R%u R%u", LUAU_INSN_A(insn), LUAU_INSN_D(insn));
			break;
		case LOP_LOADK:
		case LOP_DUPTABLE:
		case LOP_NEWCLOSURE:
		case LOP_DUPCLOSURE:
		case LOP_LOADKX: {
			uint32_t D = LUAU_INSN_D(insn);
			fprintf(f, "R%u K%u ; %s", LUAU_INSN_A(insn), D, lua_strprimitive(&p->k[D]).c_str());
		} break;
		case LOP_SETGLOBAL:
		case LOP_GETGLOBAL:
			fprintf(f, "R%u K%u", LUAU_INSN_A(insn), LUAU_INSN_B(insn));
			break;
		case LOP_SETUPVAL:
		case LOP_GETUPVAL:
			fprintf(f, "R%u U%u", LUAU_INSN_A(insn), LUAU_INSN_B(insn));
			if (p->upvalues)
				fprintf(f, " ; %s", getstr(p->upvalues[LUAU_INSN_B(insn)]));
			break;
		case LOP_GETIMPORT: {
			fprintf(f, "R%u K%u ; ", LUAU_INSN_A(insn), LUAU_INSN_D(insn));
			
			uint32_t aux = *++pc;
			int count = (uint8_t)(aux >> 30);

			if (count) {
				TString* v = tsvalue(&p->k[uint32_t(aux >> 20) & 0x3FF]);
				fprintf(f, "%.*s", v->len, getstr(v));

				if (count >= 2) {
					TString* v = tsvalue(&p->k[uint32_t(aux >> 10) & 0x3FF]);
					fprintf(f, ".%.*s", v->len, getstr(v));

					if (count == 3) {
						TString* v = tsvalue(&p->k[aux & 0x3FF]);
						fprintf(f, ".%.*s", v->len, getstr(v));
					}
				}
			}

		} break;
		case LOP_ADD:
		case LOP_SUB:
		case LOP_MUL:
		case LOP_DIV:
		case LOP_MOD:
		case LOP_POW:
		case LOP_AND:
		case LOP_OR:
		case LOP_IDIV:
		case LOP_CONCAT:
		case LOP_GETTABLE:
		case LOP_SETTABLE:
		case LOP_IDIVK:
		case LOP_ADDK:
		case LOP_SUBK:
		case LOP_MULK:
		case LOP_DIVK:
		case LOP_MODK:
		case LOP_POWK:
		case LOP_ANDK:
		case LOP_ORK:
		case LOP_SUBRK:
		case LOP_DIVRK:
			fprintf(f, "R%u R%u R%u", LUAU_INSN_A(insn), LUAU_INSN_B(insn), LUAU_INSN_C(insn));
			break;
		case LOP_GETTABLEKS:
		case LOP_SETTABLEKS:
		case LOP_NAMECALL: {
			uint32_t aux = *++pc;
			fprintf(f, "R%u R%u K%u ; %s", LUAU_INSN_A(insn), LUAU_INSN_B(insn), aux, lua_strprimitive(&p->k[aux]).c_str());
		} break;
		case LOP_GETTABLEN:
		case LOP_SETTABLEN:
			fprintf(f, "R%u R%u %u", LUAU_INSN_A(insn), LUAU_INSN_B(insn), LUAU_INSN_C(insn) + 1);
			break;
		case LOP_CALL:
			fprintf(f, "R%u %u %u", LUAU_INSN_A(insn), LUAU_INSN_B(insn) - 1, LUAU_INSN_C(insn) - 1);
			break;
		case LOP_RETURN:
		case LOP_GETVARARGS:
			fprintf(f, "R%u %u", LUAU_INSN_A(insn), LUAU_INSN_B(insn) - 1);
			break;
		case LOP_FORGLOOP:
		case LOP_FORNPREP:
		case LOP_JUMPIF:
		case LOP_JUMPIFNOT:
			fprintf(f, "R%u ", LUAU_INSN_A(insn));
			[[fallthrough]];
		case LOP_JUMPBACK:
		case LOP_JUMP:
			fprintf(f, "L%u", line + LUAU_INSN_D(insn));
			break;
		case LOP_JUMPIFEQ:
		case LOP_JUMPIFLE:
		case LOP_JUMPIFLT:
		case LOP_JUMPIFNOTEQ:
		case LOP_JUMPIFNOTLE:
		case LOP_JUMPIFNOTLT:
			fprintf(f, "R%u R%u L%u", LUAU_INSN_A(insn), *++pc, line + LUAU_INSN_D(insn) - 1);
			break;
		case LOP_NEWTABLE:
			fprintf(f, "R%u %u %u", LUAU_INSN_A(insn), LUAU_INSN_B(insn), *++pc);
			break;
		case LOP_SETLIST:
			fprintf(f, "R%u R%u %u %u", LUAU_INSN_A(insn), LUAU_INSN_B(insn), LUAU_INSN_C(insn) - 1, *++pc);
			break;
		case LOP_FORNLOOP:
			fprintf(f, "R%u L%u", LUAU_INSN_A(insn), line + LUAU_INSN_D(insn) + 2);
			break;
		case LOP_FASTCALL:
			fprintf(f, "%u L%u", LUAU_INSN_A(insn), line + LUAU_INSN_C(insn) + 1);
			break;
		case LOP_FASTCALL1:
			fprintf(f, "%u R%u L%u", LUAU_INSN_A(insn), LUAU_INSN_B(insn), line + LUAU_INSN_C(insn) + 1);
			break;
		case LOP_FASTCALL2:
			fprintf(f, "%u R%u R%u L%u", LUAU_INSN_A(insn), LUAU_INSN_B(insn), *++pc & 0xFF, line + LUAU_INSN_C(insn));
			break;
		case LOP_FASTCALL2K: {
			uint32_t aux = *++pc;
			fprintf(f, "%u R%u K%u L%u ; %s", LUAU_INSN_A(insn), LUAU_INSN_B(insn), aux, line + LUAU_INSN_C(insn), lua_strprimitive(&p->k[aux]).c_str());
		} break;
		case LOP_FASTCALL3:
			fprintf(f, "%u R%u R%u R%u L%u", LUAU_INSN_A(insn), LUAU_INSN_B(insn), *++pc & 0xFF, (*pc >> 8) & 0xFF, line + LUAU_INSN_C(insn));
			break;
		case LOP_JUMPX:
			fprintf(f, "L%u", line + LUAU_INSN_E(insn));
			break;
		case LOP_COVERAGE:
			fprintf(f, "%u", LUAU_INSN_E(insn));
			break;
		case LOP_CAPTURE:
			switch (LUAU_INSN_A(insn)) {
			case LCT_VAL:
				fprintf(f, "VAL R%u", LUAU_INSN_B(insn));
				break;
			case LCT_REF:
				fprintf(f, "REF R%u", LUAU_INSN_B(insn));
				break;
			case LCT_UPVAL:
				fprintf(f, "UPVAL U%u", LUAU_INSN_B(insn));
				if (p->upvalues)
					fprintf(f, " ; %s", getstr(p->upvalues[LUAU_INSN_B(insn)]));
				break;
			}
			break;
		case LOP_JUMPXEQKNIL:
		case LOP_JUMPXEQKB:
			// TODO: add note
			fprintf(f, "R%u L%u %u", LUAU_INSN_A(insn), line + LUAU_INSN_D(insn) - 1, *++pc);
			break;
		case LOP_JUMPXEQKN:
		case LOP_JUMPXEQKS: {
			uint32_t aux = *++pc & 0xFFFFFF;
			fprintf(f, "R%u K%u L%u ; %s", LUAU_INSN_A(insn), aux, line + LUAU_INSN_D(insn) - 1, lua_strprimitive(&p->k[aux]).c_str());
		} break;
		default:
			break;
		}
	}

	void fdisasm(FILE* f, const Proto* p) {
		const Instruction* pc = p->code;
		const Instruction* end = p->code + p->sizecode;
		while (pc < end) {
			idisasm(f, pc, p);
			pc++;
			fputc('\n', f);
		}
	}

	void disasm(const Proto* p) {
		fdisasm(stdout, p);
	}
}
