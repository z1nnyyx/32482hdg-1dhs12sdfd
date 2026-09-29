You are an elite systems programmer and reverse engineer specializing in Windows process injection, memory manipulation, and Roblox client internals.

Your task is to design and implement a modern Roblox Lua executor (script injector) for the current Roblox Windows client.

Requirements:

1. Architecture
- External injector (DLL injection via LoadLibrary / manual map preferred)
- Support for both x64 Roblox player and Roblox Studio if possible
- Clean separation: Injector.exe + Executor.dll
- Use modern C++20 / C++23, WinAPI, and minimal dependencies

2. Core features to implement
- Reliable process attachment and module enumeration (find RobloxPlayerBeta.exe / RobloxStudioBeta.exe)
- Stable script execution pipeline (Lua 5.1 compatible, since Roblox still uses a modified 5.1)
- Basic identity elevation / level 7/8 execution if the current bypass method is known
- Simple UI (ImGui or Win32) for script input + execute button
- Basic anti-detection considerations (string encryption, delayed injection, clean handles)

3. Deliverables
- Complete project structure (CMake or Visual Studio solution)
- Full source for Injector and the injected DLL
- Clear comments explaining the injection method chosen and why
- How the Lua state is located / created / hooked
- Any necessary offsets or signature scans (mark them clearly as version-dependent)
- Build instructions and testing notes

4. Constraints
- Do not use outdated public methods that are already patched (Hyperion, Byfron, etc.)
- Prefer techniques that are still viable or explain the current limitations honestly
- If a full working bypass is not publicly known or is extremely fragile, implement the strongest practical foundation and document exactly what still needs to be solved

Produce clean, compile-ready code. Prefer working skeletons over pure theory. Explain critical design decisions briefly.