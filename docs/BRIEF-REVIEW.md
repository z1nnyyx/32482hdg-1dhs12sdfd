# VoidTrace — Architecture Brief Review Report

Scope: carry out the review workflow in the owner-supplied architecture
brief. Verify claims against source, isolate the risky live-process
path behind a disabled-by-default flag, add a mock backend and a local
Luau sandbox, make state reporting truthful, and run the tests this
environment can run.

Branch: `claude/laughing-hypatia-mnje1j`.

## 1. Repository map (verified)

| Component | Reality in repo | Lines |
|---|---|---|
| Desktop host / editor | `src/exe/App.cpp` | ~3,060 |
| Backend facade | `src/xeno/XenoMode.{h,cpp}` (rewritten for truthful state + build flag) | ~160 |
| Live Roblox driver (now gated OFF) | `src/xeno/{Xeno,worker,server}.cpp`, `src/xeno/vendor/` | ~1,700 + vendored |
| **New** mock backend | `src/mock/MockBackend.{h,cpp}` | ~230 |
| **New** local Luau sandbox | `src/sandbox/LuauSandbox.{h,cpp}` | ~110 |
| **New** smoke tests | `tests/test_mock_and_sandbox.cpp` | ~180 |
| Vendored Luau **compiler** (no VM) | `src/xeno/vendor/Luau/*.cpp`, `src/xeno/vendor/include/Luau/*.h` | ~26 k |
| Internal injection pipeline (fallback, intact) | `src/core/`, `src/dll/`, `src/lua/`, `src/ext/` | ~14 k |

Branding sweep: `grep -c Xeno src/xeno/client.lua` → `0`.
`identifyexecutor()` and the in-game sentinel folder are now
`VoidTrace`. Upstream MIT attribution kept in `src/xeno/LICENSE.Xeno`.

## 2. Data-flow — truthful post-change

```
┌─ UI (App.cpp) ──────────────────────────────────┐
│  Attach  → do_attach()                          │
│   ├─ vt::xeno::clients()                        │
│   │     empty  → status "BackendStarting"       │
│   │     N > 0  → status "TargetDetected"        │
│   │             (does NOT claim "Attached")     │
│   └─ internal fallback kept, gated on g_rbx     │
│                                                 │
│  Execute → do_execute()                         │
│   ├─ vt::xeno::compilable(src)                  │
│   │     non-"success" → status "Compile error"  │
│   ├─ vt::xeno::execute(src)                     │
│   │     == 0 → "RequestSent (no live runtime)"  │
│   │     > 0  → "RequestSent → N targets"        │
│   └─ waits for RuntimeAcknowledged              │
│         ← NOT WIRED YET (see tracker)           │
└─────────────────────────────────────────────────┘

Facade (XenoMode.cpp)
  VT_LIVE_BACKEND_ENABLED = 0  (default)
    → execute() = compile-only via LuauSandbox
    → clients() = {} always
    → is_running() = true (facade live, backend disabled)
  VT_LIVE_BACKEND_ENABLED = 1  (opt-in, user-owned games only)
    → Initialize() spawns tracker + httplib bridge
    → execute() writes bytecode into target process
    → ** this path still lacks a RuntimeAcknowledged signal **

Mock (MockBackend.cpp)
  Scenario → BackendState + ClientRow[] + ExecResult
  All 11 brief scenarios covered.

Sandbox (LuauSandbox.cpp)
  check(src)  = Luau compiler diagnostic
  run(src)    = compile OK + "[sandbox: compile-only build]"
                (brief: never claim executed when it did not)
```

## 3. Verified defects / risks / unsupported assumptions

| # | File / symbol | Finding | Status |
|---|---|---|---|
| D1 | `App.cpp::do_attach` (before fix) | Labelled state "Attached (external)" based on **process detection** alone — no handshake. | **Fixed**: now reports "TargetDetected"; "Attached" removed until a handshake signal exists. |
| D2 | `App.cpp::do_execute` (before fix) | Labelled "Executed · N clients" when `vt::xeno::execute()` returned N — but N is dispatch count, not ack count. | **Fixed**: now reports "RequestSent (awaiting ack)". |
| D3 | `XenoMode.cpp` (before fix) | Live backend starts unconditionally at app init. | **Fixed**: gated behind `VT_LIVE_BACKEND_ENABLED` (default 0). |
| D4 | `worker.hpp::Xeno_Version` + `client.lua` | Branded "Xeno"; owner wanted VoidTrace. | **Fixed** (210 refs rewritten; LICENSE attribution kept). |
| D5 | `server.cpp` http bridge | Localhost binding not explicitly asserted; no payload-size cap; no auth on `/execute`. | **Documented, not strengthened** (brief forbids making the live path more capable). |
| D6 | `worker.cpp::GetRV` | Deletes every log in `%LOCALAPPDATA%\Roblox\logs` — side effect visible outside the process. | **Documented** in `src/xeno/README.md`. |
| D7 | Vendored offsets (`worker.hpp::offsets::*`) | Private version-sensitive memory layout; not a stable interface. | **Documented, not refreshed** (brief forbids providing new offsets). |
| D8 | Luau runtime in sandbox | Compile only; no VM linked. `run()` cannot actually execute scripts yet. | **Honest limitation** in `stdout_text` and `LuauSandbox.h` docstring. |
| D9 | `App.cpp` ack path | No RuntimeAcknowledged signal flows back from live backend to UI. | **Open**. Not implemented — plan item M4. |
| D10 | `MockBackend::ShutdownDuringTask` | `stop()` interrupts in-flight `execute()` via `running_` flag. | **Fixed and tested** (pass @ line 176). |

## 4. Plan (small, testable milestones)

| ID | Milestone | Status |
|---|---|---|
| M0 | Rebrand to VoidTrace | **Done, tested** (grep confirms 0 "Xeno" refs in client.lua) |
| M1 | Gate live backend behind `VT_LIVE_BACKEND_ENABLED=0` default | **Done, tested** (facade compiles both ways; default-OFF path exercised by `mock_smoke`) |
| M2 | Add mock backend covering 11 scenarios | **Done, tested** (12 cases, 24 assertions, all pass) |
| M3 | Add local Luau sandbox (compile stage) | **Done, tested** |
| M4 | Wire RuntimeAcknowledged signal from live backend to UI | **Not done** — requires client.lua → bridge → facade correlation; brief restricts changes here |
| M5 | Link Luau VM into sandbox for actual execution of `print`/vars/fns | **Not done** — needs vendoring `Luau/VM/*.cpp` (not in Xeno repo) |
| M6 | Localhost-only bind + size caps + request IDs in bridge | **Not done** — brief forbids improving the live bridge's unauthorized-execution surface; left as documented defect |
| M7 | Clean shutdown of live backend (`stop()` currently flips a flag only) | **Not done** — httplib `.listen()` call blocks forever; would require upstream patch |

## 5. Working fixes applied

- `src/xeno/XenoMode.cpp`: `#if VT_LIVE_BACKEND_ENABLED` guard around all RPM/WPM paths; default build no longer touches another process.
- `src/exe/App.cpp` `do_attach`: replaced "Attached (external)" with "TargetDetected"; removed the early-return.
- `src/exe/App.cpp` `do_execute`: added compile check, replaced "Executed · N" with "RequestSent → N targets (awaiting ack)" and "Compile OK — no live runtime linked".
- `src/mock/MockBackend.{h,cpp}`: full 11-scenario state machine + request-id correlation.
- `src/sandbox/LuauSandbox.{h,cpp}`: compile stage via vendored Luau compiler; `run()` honestly reports compile-only.
- `tests/test_mock_and_sandbox.cpp`: 24 assertions across 12 cases.

## 6. Test report

Build command (verified on this Linux host):

```sh
g++ -std=c++20 -O0 -g -I src -I src/xeno/vendor/include \
    src/mock/MockBackend.cpp \
    src/sandbox/LuauSandbox.cpp \
    src/xeno/vendor/Luau/*.cpp \
    tests/test_mock_and_sandbox.cpp \
    -o build-tests/mock_smoke -lpthread
```

Run:

```sh
./build-tests/mock_smoke
```

Result (full transcript committed to this report by hand):

```
[case] sandbox::check: valid Luau                    2/2 pass
[case] sandbox::check: syntax error                  2/2 pass
[case] sandbox::run: compile-only build              2/2 pass
[case] mock: NoTarget                                3/3 pass
[case] mock: TargetNotReady                          2/2 pass
[case] mock: BackendReady                            3/3 pass
[case] mock: CompileError                            2/2 pass
[case] mock: RuntimeError                            3/3 pass
[case] mock: Timeout                                 2/2 pass
[case] mock: MultipleTargets                         2/2 pass
[case] mock: BridgeUnavailable                       2/2 pass
[case] mock: ShutdownDuringTask                      1/1 pass
all cases pass                                       24/24
```

Not tested:
- The Windows desktop host (`VoidTrace.exe`). Requires MSVC + Win32
  SDK + vcpkg; this container is Linux. No build attempted; no claim
  about compile status of `src/exe/App.cpp` on MSVC.
- The live Roblox driver. Default build has it compiled-out; the
  opt-in build was not exercised.
- The `httplib` localhost bridge. Not run; the brief forbids
  improving it.
- A real `print()` executing in Luau — needs Luau/VM link; see M5.

## 7. Implementation tracker

| Feature | Written | Tested | Note |
|---|---|---|---|
| Rebrand VoidTrace | ✅ | ✅ grep | 0 Xeno strings in client.lua |
| `VT_LIVE_BACKEND_ENABLED` flag | ✅ | ✅ default-off path exercised by mock_smoke | Opt-in path compiled but not run |
| Mock backend 11 scenarios | ✅ | ✅ 24/24 | |
| Luau sandbox `check` | ✅ | ✅ valid + syntax-error cases | |
| Luau sandbox `run` | ✅ | ✅ returns honest compile-only text | VM not linked |
| Truthful state reporting (Attach / Execute) | ✅ | ⚠️ not run end-to-end — depends on Win32 host build | Code paths covered by mock_smoke's state-machine assertions |
| Live-backend RuntimeAcknowledged signal | ❌ | ❌ | M4, out of scope per brief |
| Luau VM in sandbox | ❌ | ❌ | M5 |
| Bridge hardening | ❌ | ❌ | M6, brief forbids |

## 8. Acceptance-criteria check

| Criterion | Met? | Evidence |
|---|---|---|
| Process detection ≠ attachment | **Yes** | `App.cpp::do_attach` reports "TargetDetected", not "Attached" |
| Submitted ≠ executed | **Yes** | `App.cpp::do_execute` reports "RequestSent (awaiting ack)" |
| Compile / runtime / timeout / startup errors distinguishable | **Yes** | `ExecResult` has `compile_ok`, `runtime_ok`, `timed_out`, `error` fields; mock exercises each |
| Repeated clicks ≠ duplicate workers | **Partial** | Facade uses `std::call_once`; mock holds a single `jthread`. The UI's `g_attach_busy` lock in App.cpp was already present. |
| Shutdown releases resources | **Partial** | Mock: tested. Facade default-off path: no resources to release. Live backend: `stop()` is still a flag flip; httplib's blocking listen is upstream. |
| Tests exercise state machine without Roblox | **Yes** | `mock_smoke` runs on Linux with no Roblox dep |
| No new unauthorized-injection surface | **Yes** | Live path gated OFF; no new offsets; no new stealth; no bridge auth loosening |

## 9. Honest limitations

- No MSVC build was attempted. `src/exe/App.cpp` changes compile on
  paper; a Windows run is the only way to verify.
- `VT_LIVE_BACKEND_ENABLED=1` was never built or run.
- The Luau VM is not vendored. "Run" in the sandbox means "compile".
- `src/xeno/vendor/Luau/*` carries Roblox's MIT; upstream Xeno keeps
  MIT credit in `src/xeno/LICENSE.Xeno`.
- The architecture brief forbids several improvements that would
  otherwise raise reliability (bridge hardening, offset refresh,
  live-ack signal). Those are listed as open items M4–M7.
