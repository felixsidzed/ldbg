# ldbg
An embeddable GDB-like debugger for Luau  

## REPL Documentation
If input is not a recgonized command the loop treats it as a piece of Luau code and executes it within the current scope on the same thread.

### Flow Control
| Command | Alias | Description |
| --- | --- | --- |
| `continue` | `c` | Continue execution until a breakpoint is hit |
| `step` | `s` | Step into the next instruction, including calls |
| `next` | `n` | Step over the next instruction, skipping calls |
| `finish` |  | Continue until the end of the function (return) |
| `quit` | `q` | Terminates execution (sets status to `LUA_ERRRUN`) |

---

## Breakpoints
Breakpoints pause execution when they are hit. Once created they are referenced by 1-based index.  

### `break` / `b`
Creates a new breakpoint by patching an instruction with BREAK. Creates `p->debuginsn` if null.  

* `source:line` (e.g. `test.luau:10`): break at the first instruction of line in a source file (based on `p->lineinfo`)
* `source:func` (e.g. `test.luau:foo`): break at the start of a named function in a source file (based on `cl->c.debugname` / `p->debugname`)
* `*func:pc` (e.g. `*myfn:10`): break at a specific instruction offset in a named function
* `*pc` (e.g. `*0xa`): break at a specific instruction within the current function
* `line` (e.g. `10`): break at the first instruction of line in the current source file
* `func` (e.g. `foo`): break at the start of the first found named function

### `delete` / `d`
Self explanatory  
`delete <index>`

### `toggle`
Toggle a breakpoint (patch/unpatch opcode) without deleting it  
`toggle <index>`

---

## Inspection

### `backtrace` / `bt`
Dump the current call stack. Prints depth level, source file, and line number

### `inspect` / `i`
shi idk  
Running `inspect` with no subcommand will print information about the current function

| Subcommand | Description |
| --- | --- |
| `locals` | List all local variables and their registers (requires debuginfo, based on `p->locvars`) |
| `upvalues` | List all upvalues and their indicies (requires debuginfo, based on `p->upvalues`) |
| `stack` | Dumps registers from 0 to `p->maxstacksize` |
| `breakpoints` | List all breakpoints and their information |
| `funcs` | List all loaded functions and their information |
| `insn` | Disassemble the current instruction |
| `object <num>` | List members of a class instance. Index must be a register |
| `R<num>` | Dump the value in a register |
| `K<num>` | Dump the value in the constant table at index num |
| `U<num>` | Dump the value in an upvalue |

### `disasm`
Disassembles Luau bytecode into readable instructions.
Disassembles a function. If no function is provided the current one is used  
`disasm [fname]`

---

## GC Control
Running `gc` without arguments prints basic usage stats.

| Subcommand | Description |
| --- | --- |
| `step [count]` | Advances the GC by count steps (defaults to 1). Only works if memory usage exceeds threshold |
| `full` | Force a complete GC cycle. Deletes all dead objects |
| `threshold <val>` | Sets the GC threshold to val bytes |
| `pause` | Pauses the GC by setting threshold to `SIZE_MAX` |
| `resume` | Resets the GC threshold back after pausing |
| `stats` | Dumps amount of dead/white/gray/black/fixed objects, heap goals, and cycle timestamps |
| `trace` | Toggles logging of memory allocation, reallocation, and deallocation (based on `g->frealloc`) |
| `dump` | Dumps the entire heap to `gcdump.json` in the current working direction |

### `gc list`
Iterates the heap and prints objects matching specific criteria  
`gc list [type=...] [mark=...] [memcat=...]`

* `type`: Filter by type tag
* `mark`: Filter by GC color (`white`/`gray`/`black`/`fixed`)
* `memcat`: Filter by memory category

---

## Miscellaneous

### `patch`
Patches an operand of the current instruction  
`patch <operand> <value>`

* `a`: 8-bit unsigned integer
* `b`: 8-bit unsigned integer
* `c`: 8-bit unsigned integer
* `d`: 16-bit unsigned integer
* `e`: 24-bit unsigned integer

### `load`
Loads an executes a [nula](https://github.com/felixsidzed/nula) library  
`load <path>`

### `cls`
Clears the terminal screen.
