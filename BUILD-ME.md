# VoidTrace — just download and run

**You do not build anything, Sir.** GitHub builds `VoidTrace.exe` for
you on every push. You download the pre-built exe.

## How to get the exe

1. Open: https://github.com/z1nnyyx/roblox-executor/releases
2. Click the **latest** release at the top.
3. Download **VoidTrace.exe** (under "Assets").

## How to run it

1. Open Roblox, join any game.
2. Right-click `VoidTrace.exe` → **Run as administrator**.
3. Click **Attach** → status flips to "Attached · YourName".
4. Paste a script, press **F5**.

## Test script

```lua
print("hello from", identifyexecutor())
```

Open Roblox dev console with `F9` to see it print `hello from VoidTrace`.

## Important

- **Use an alt account.** This method is detected by Roblox's anti-cheat.
- Keep `VoidTrace.exe` running while you play.
- If a Roblox update breaks it, tell me — the offsets need refreshing.

## If the release page is empty

Means the first automated build hasn't finished yet, or it failed. Open:

https://github.com/z1nnyyx/roblox-executor/actions

Click the latest workflow run. If it's green, the exe is in **Artifacts**
at the bottom (download **VoidTrace-x64**). If it's red, send me the
error from the failing step and I'll fix it.
