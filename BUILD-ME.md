# Build VoidTrace — plain steps, Sir

Do these in order. If something stops working, come back and tell me
which step broke.

## One-time setup (do this once ever)

**1. Install Visual Studio 2022 Community** (free)
https://visualstudio.microsoft.com/vs/community/
During install, check the box: **"Desktop development with C++"**.

**2. Install vcpkg** (dependency manager)
Open PowerShell. Paste these one at a time:
```powershell
cd C:\
git clone https://github.com/microsoft/vcpkg
C:\vcpkg\bootstrap-vcpkg.bat
C:\vcpkg\vcpkg integrate install
```

**3. Install the three C++ libraries VoidTrace needs**
Still in PowerShell:
```powershell
C:\vcpkg\vcpkg install openssl:x64-windows zstd:x64-windows xxhash:x64-windows
```
This takes 5–10 minutes. Let it finish.

## Clone the repo (do this once)

In PowerShell:
```powershell
cd C:\
git clone https://github.com/z1nnyyx/roblox-executor
cd roblox-executor
git checkout claude/laughing-hypatia-mnje1j
```

## Build (do this every time you want a fresh exe)

**1.** In Visual Studio: **File → Open → Project/Solution**, pick
`C:\roblox-executor\VoidTrace executor roblox.slnx`.

**2.** In the top toolbar, change the dropdown from `Debug | x86` to
**`Release | x64`**.

**3.** In **Solution Explorer** (right side), right-click the project
→ **Add → Existing Item** → navigate to `src\xeno\` → select the
whole folder → OK. This adds all the new VoidTrace code to the build.

**4.** Right-click the project → **Properties** →
**C/C++ → General → Additional Include Directories** → click the
dropdown → **Edit** → add two lines:
```
$(ProjectDir)..\src\xeno\vendor\include
$(ProjectDir)..\src
```
Click **OK → Apply → OK**.

**5.** **Build → Build Solution** (or press `Ctrl+Shift+B`).

Wait 2–5 minutes. If it says **"Build: 1 succeeded"** at the bottom —
done. Your exe is at `C:\roblox-executor\bin\x64\Release\VoidTrace.exe`.

## Run it

1. Open Roblox and join any game.
2. **Right-click** `VoidTrace.exe` → **Run as administrator**.
3. Press **Attach** — status should flip to "Attached · YourName".
4. Paste a script, press **F5**. Should see "Executed · 1 client".
5. Open Roblox dev console (`F9`) to see output.

## Test script that proves it works

```lua
print("hello from", identifyexecutor())
```

Should print `hello from VoidTrace` in Roblox's dev console.

## If a step breaks

Tell me which one. Don't guess at fixes — the error message tells me
exactly what to do. Common ones:

- **"openssl.lib not found"** → step 3 of one-time setup didn't finish.
  Re-run the vcpkg install line.
- **"cannot open source file worker.hpp"** → step 4 of build (include
  directories) was skipped.
- **"identifier Luau::compile is undefined"** → step 3 of build
  (Add → Existing Item on src\xeno) was skipped.
- **Visual Studio crashes on Build** → run as admin, close other
  heavy apps.

## Important

- Use an **alt account**. This method is detected by Roblox's
  anti-cheat. Your real account can be banned.
- Keep `VoidTrace.exe` **running** while you play. Closing it closes
  the backend.
- If Roblox updates and attach stops working, the private offsets in
  `src\xeno\vendor\include\worker.hpp` need refreshing. Tell me and
  I'll walk you through it.
