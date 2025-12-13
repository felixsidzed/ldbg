#pragma once

#include <lstate.h>
#include <Luau/Compiler.h>

namespace ldbg {
	/// <summary>
	/// Dumps the provided proto's bytecode to stdout
	/// </summary>
	/// <param name="p">Proto to dump</param>
	void disasm(const Proto* p);

	/// <summary>
	/// Dumps the provided proto's bytecode into the provided file stream
	/// </summary>
	/// <param name="f">File stream to dump into</param>
	/// <param name="p">Proto to dump</param>
	void fdisasm(FILE* f, const Proto* p);

	/// <summary>
	/// Dumps a single instruction into the provided file stream
	/// </summary>
	/// <param name="f">File stream to dump into</param>
	/// <param name="pc">Current program counter</param>
	/// <param name="p">Current proto</param>
	void idisasm(FILE* f, const Instruction*& pc, const Proto* p);
}
