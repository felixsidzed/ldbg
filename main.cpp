#include <format>
#include <fstream>
#include <iostream>

#include <lgc.h>
#include <lua.h>
#include <lualib.h>
#include <lstate.h>
#include <Luau/Compiler.h>

#include "ldbg.h"

int main(int argc, char** argv) {
	if (argc < 2) {
		printf("%s <file>", argv[0]);
		return 1;
	}

	std::string filename;
	for (int i = 1; i < argc; i++)
		filename += argv[i];

	try {
		lua_State* L = luaL_newstate();
		luaL_openlibs(L);
		luaL_sandboxthread(L);

		std::ifstream file(filename, std::ios::binary | std::ios::ate);
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

		ldbg::Debugger dbg;
		dbg.attach(L);

		lua_pushcfunction(L, dbg.options.onError, "");
		if (!luau_load(L, std::format("@{}", filename).c_str(), src.data(), src.size(), 0)) {
			dbg.collect(clvalue(L->top - 1));

			lua_pcall(L, 0, 0, -2);
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
