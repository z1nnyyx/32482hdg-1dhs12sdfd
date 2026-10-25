# VoidTrace

Windows C++ Roblox executor. The module is **packed inside `VoidTrace.exe`**.

Ship **`bin\x64\Release\VoidTrace.exe`** only. No friend folder, no loose DLL.

Open `VoidTrace executor roblox.slnx` in Visual Studio. **Release | x64**. Build.

Default inject is in-memory manual map. Data lives in a hidden `%LOCALAPPDATA%\VoidTrace\`.

`identifyexecutor()` is **VoidTrace**.

## Layout

| Piece | Role |
|---|---|
| `src/exe` | Dark Win32 host: attach, inject, editor, script list, console |
| `src/core` | Process finder, LoadLibrary inject, manual map, named pipe |
| `src/dll` | Module that runs inside `RobloxPlayerBeta.exe` |
| `src/lua` | Offset resolver, pattern scan, Luau C API facade, scheduler walk, execute queue, UNC-style env |
| `config/offsets.json` | **Version-dependent RVAs** — you must update these after every Roblox ship |
| `scripts/autoexec` | Ran automatically after inject |
| `scripts/hub` / `scripts/saved` | Double-click in the UI to load |
| `workspace` | `readfile` / `writefile` sandbox |

## How to test

1. Visual Studio → **Release \| x64** → Build Solution.
2. Use **`bin\x64\Release\VoidTrace.exe`** only.
3. They open Roblox, join a game, then run the exe **as Administrator**.
4. Attach (overlay only). Inject to run scripts. Wait for `READY`.
5. Execute:

```lua
print("hello", identifyexecutor())
```

If you see `Lua API incomplete` or `no lua_State`, offsets are stale. Dump `RobloxPlayerBeta.exe` and fill `config/offsets.json`.

## External mode (Xeno-style)

A second execution backend ported from
[`tyronetheqt/Xeno`](https://github.com/tyronetheqt/Xeno) now lives at
`src/xeno/`. It does **not** inject a DLL — it drives Roblox entirely
through cross-process memory writes against a `ModuleScript`'s bytecode
slot (the Incognito method). Full architecture, offsets, and the
one-time vcxproj + vcpkg wiring are documented in `src/xeno/README.md`.

Public API:

```cpp
#include "xeno/XenoMode.h"
vt::xeno::start();
vt::xeno::execute(source);     // broadcast
vt::xeno::clients();           // UI list
```

Toggle **External Mode** in the host to route Execute through this
backend instead of the manual-map DLL. Same detection posture as the
upstream — alt-only.

## Hyperion (Byfron)

LoadLibrary + `CreateRemoteThread` and a usermode manual map are **detected** on the live client. This base does not include a hypervisor, a vulnerable driver, or a signed mapper. Treat it as a development executor: it will work on unprotected/test setups and will get you banned on production if you inject blindly.

What actually moves on live clients (and why this repo does not ship it):

- Hypervisor / DMA-style external (no DLL in the Roblox process)
- Signed, frequently-rotated mappers (cat-and-mouse, account/HWID risk)
- Internal exploit primitives that die every patch

## Offsets you must keep current

`luau_load`, `lua_pcall`, the rest of the Lua C API, `TaskScheduler` singleton, job list, `ScriptContext`, `lua_State`, extra-space / identity. Patterns in `pat_*` are used when the RVA is `0`.

Execution never `lua_pcall`s from the pipe thread. Scripts go on a queue and run on the module pump with SEH.

## Environment (once the API is bound)

`getgenv` `getrenv` `getreg` `identifyexecutor` `checkcaller`  
`readfile` `writefile` `isfolder` `makefolder` `listfiles` `loadfile`  
`mouse1click` `keypress` `mousemoveabs` `isrbxactive`  
`request` / `httpget`  
`Drawing.new` (object model; hook Present/RenderJob to actually paint)  
`queue_on_teleport` `setclipboard`
