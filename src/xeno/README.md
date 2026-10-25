# VoidTrace — Xeno-style external backend

This folder is a ported, cleaned, VoidTrace-integrated copy of
[`tyronetheqt/Xeno`](https://github.com/tyronetheqt/Xeno) (MIT, included
in `LICENSE.Xeno`). It is **not** a replacement for VoidTrace's existing
internal manual-map backend — it sits alongside it as a second attack
surface. The user can pick one per attach.

Original method credit: [`Incognito-Roblox/Incognito`](https://github.com/Incognito-Roblox/Incognito).

## What it does

No DLL enters Roblox. The whole backend is cross-process RPM/WPM against
`RobloxPlayerBeta.exe` via `NtReadVirtualMemory` / `NtWriteVirtualMemory`.

### Pipeline

| Step | What | Where |
|---|---|---|
| 1 | Enumerate `RobloxPlayerBeta.exe` PIDs, spawn one `RBXClient` per | `Xeno.cpp` |
| 2 | Scan `%LOCALAPPDATA%\Roblox\logs\*.log` for `SurfaceController[_:1]::initialize view(0x…)` to recover the RenderView pointer | `worker.cpp::GetRV` |
| 3 | `RenderView + 0x118` → fake DataModel; `+ 0x190` → real DataModel | `worker.hpp::FetchDataModel` |
| 4 | Walk the Instance tree with hardcoded offsets to find a hijackable `ModuleScript` | `worker.hpp::Instance::*` |
| 5 | **Home page**: hijack `CoreGui.RobloxGui.Modules.Common.Url`. **In-game**: hijack `StarterPlayer.StarterPlayerScripts.PlayerModule.ControlModule.VRNavigation` and trigger it by remapping `PlayerListManager.This` + sending ESC | `worker.cpp::RBXClient()` |
| 6 | Compile `client.lua` to Luau bytecode with the vendored compiler, XOR each opcode (`op *= 227`), prepend `RSB1` + 8-byte size, zstd-compress, re-XOR with an `xxh32(…, 42)`-keyed stream | `worker.cpp::Compile / compress` |
| 7 | `VirtualAllocEx` a page in Roblox, write the blob, rewrite `embedded->Bytecode` + `BytecodeSize`. For `ModuleScript` also write `ModuleFlags = 0x100000000` and `IsCoreScript = 0x1` to lift the core-script lock | `worker.hpp::Instance::SetBytecode / UnlockModule` |
| 8 | `client.lua` creates `RobloxReplicatedStorage.Xeno.{Scripts, Instance Pointers}` and polls a localhost `httplib` server for scripts to execute | `client.lua`, `server.cpp` |
| 9 | `execute()` writes a fresh `return { ['x e n o'] = function(...) <source> end }` into the Xeno `ModuleScript` and `UnlockModule`s it — Roblox's loader picks it up | `worker.cpp::RBXClient::execute` |

### Offsets (upstream Xeno 1.0.8 — update when Roblox ships)

```
Instance.This        0x08
Instance.Name        0x50
Instance.Children    0x58
Instance.Parent      0x28
ClassDescriptor      0x18
ClassName            0x08
LocalPlayer          0x110
ObjectValue          0xc0

ModuleScript.Embedded    0x160
LocalScript.Embedded     0x1c0
Script.IsCoreScript      0x1a8
Script.ModuleFlags       0x1a4   // IsCoreScript - 0x4
Embedded.Bytecode        0x10
Embedded.BytecodeSize    0x20
RenderView.FakeDataModel 0x118
FakeDataModel.Real       0x190
```

Keep these mirrored in `src/lua/Offsets.cpp` + `config/offsets.json` if
you want the internal backend to resolve them without re-scanning.

## VoidTrace-facing API

```cpp
#include "xeno/XenoMode.h"

vt::xeno::start();                        // once, at app launch
auto rows = vt::xeno::clients();          // UI client list
vt::xeno::execute(source);                // broadcast
vt::xeno::execute(source, {"usernameA"}); // targeted
vt::xeno::compilable(source);             // syntax check
```

`App.cpp` adds a toolbar toggle **External Mode** that routes
Execute through `vt::xeno::execute` instead of the pipe to the injected
module. When the toggle is off, everything flows through the existing
manual-map DLL as before.

## Build glue (Visual Studio)

The vendored Luau compiler lives at `src/xeno/vendor/Luau/*.cpp` with
headers at `src/xeno/vendor/include/`. One-time edits in
`VoidTrace executor roblox.vcxproj`:

1. Add `src/xeno/**/*.cpp` and `src/xeno/vendor/Luau/*.cpp` to
   `<ClCompile>` items (or right-click → *Add → Existing Item* on the
   `src/xeno` folder in Solution Explorer).
2. Add `$(ProjectDir)..\src\xeno\vendor\include;$(ProjectDir)..\src`
   to **C/C++ → General → Additional Include Directories**.
3. Install the two native deps with vcpkg:
   ```
   vcpkg install xxhash zstd openssl
   ```
   The upstream `vcpkg.json` is reproduced at the repo root.
4. The `client.lua` resource is already wired into `src/exe/VoidTrace.rc`
   via `SCRIPT LUAFILE "../xeno/client.lua"` — no manual step.
5. `src/xeno/vendor/include/utils/ntdll.cpp` must be added to the build
   so `NtReadVirtualMemory` / `NtWriteVirtualMemory` resolve.

## Caveats

- **Detected.** Byfron flags the bytecode-slot overwrite. The upstream
  README says "most likely banned"; this port inherits that risk.
  Alt-only — same policy as the rest of VoidTrace.
- **Logs required.** `GetRV` deletes stale log files to force Roblox to
  print a fresh RenderView line. If the user has no write permission to
  `%LOCALAPPDATA%\Roblox\logs` the attach fails silently; run as admin.
- **~150 MB working-set gate.** `RBXClient()` blocks until the Roblox
  process's working set exceeds ~150 MB. On slow disks this adds a
  cold-start wait.
- **In-game attach cost.** Hijacking VRNavigation sends a synthetic ESC
  to foreground Roblox. Hyperion sees the input; it is the single
  loudest signal in the pipeline.
- **Shared globals** (`Xeno.SetGlobal` / `GetGlobal`) live in the
  external process's memory, not in Roblox — persistence survives the
  Roblox restart as long as `VoidTrace.exe` stays up.

## Attribution

- `tyronetheqt/Xeno` — ©2024–2026 tyronetheqt, MIT (`LICENSE.Xeno`)
- Luau — ©Roblox, MIT (`vendor/Luau/`)
- `Incognito-Roblox/Incognito` — the bytecode-slot method
- `plusgiant5/TaaprWareV2` — InitScript foundation that `client.lua` reuses
- `httplib`, `xxhash`, `zstd`, `openssl`, `nlohmann/json` — their own licenses apply

Do not strip these credits.
