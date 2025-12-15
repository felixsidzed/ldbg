#pragma once

#include <vector>
#include <string>
#include <cstdint>

#include <lua.h>
#include <lstate.h>

// to enable ANSI highlighting - predefine LDBG_ENABLE_HIGHLIGHTING

struct Proto;

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
		bool enabled : 1;
		uint32_t line : 31;
	};

	class Debugger {
	public:
		struct Options {
			lua_CFunction onError;

			void (*debugbreak)(Debugger*, lua_State*, lua_Debug*);

			FILE* in;
			FILE* out;
		};

		Options options;

		Debugger();
		~Debugger();

		Debugger(const Debugger&) = delete;
		Debugger& operator=(const Debugger&) = delete;

		void attach(lua_State* L);
		void detach(lua_State* L);

		size_t setBreakpoint(lua_State* L, Proto* p, bool enable = true);
		size_t setBreakpoint(lua_State* L, const std::string& source, uint32_t line, bool enable = true);
		size_t setBreakpoint(lua_State* L, Proto* p, int pc, const std::string& source, uint32_t line, bool enable = true);

		bool removeBreakpoint(Proto* p, int pc);
		void toggleBreakpoint(lua_State* L, size_t index);

		const std::vector<Breakpoint>& getBreakpoints() const { return breakpoints; }

		void collect(Closure* cl) {
			LUAU_ASSERT(!cl->isC);
			collectProtos(cl->l.p);
		}

	private:
		friend void debugstep(lua_State* L, lua_Debug* ar);
		friend void debugbreak(lua_State* L, lua_Debug* ar);
		friend void* frealloc(void* ud, void* ptr, size_t osize, size_t nsize);

		std::vector<Proto*> loadedProtos;
		std::vector<Breakpoint> breakpoints;

		uint32_t lastLevel = 0;
		uint32_t stateLevel = 0;
		State state = State::None;

		bool debugstepActive = true;

		size_t oldGCThreshold = 0;
		lua_Alloc oldFrealloc = nullptr;

		void collectProtos(Proto* root);
		void dumpFunctionInfo(lua_State* L);

		void debugstep(lua_State* L, lua_Debug* ar);
		void debugbreak(lua_State* L, lua_Debug* ar);

		size_t pushBreakpoint(Proto* p, const std::string& source, int pc, uint32_t line);

		void handleBreakByPc(lua_State* L, Proto* p, int pc);
		void handleBreakByFunc(lua_State* L, const std::string& source, const std::string& func);

		void repl(lua_State* L);
	};

} // namespace ldbg
