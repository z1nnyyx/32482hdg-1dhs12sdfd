#include "dll/Module.h"
#include "lua/JobHook.h"
#include "shared/OffBlob.h"

#include <Windows.h>

static HMODULE g_module = nullptr;

// Patched by the mapper with the host pipe path (\\.\pipe\...).
extern "C" __declspec(dllexport) volatile wchar_t VT_BOOT[80] = L"??VTBOOT??";
extern "C" __declspec(dllexport) volatile VTOffBlob VT_OFF = { {'V','T','_','O','F','F','S'} };

// Called from the USER32 IAT trampoline on every PeekMessage. No new thread.
extern "C" __declspec(dllexport) void VT_TICK() {
    vt::module_tick();
}

// KERNELBASE wait IAT — runs on the script job thread, not PeekMessage.
extern "C" __declspec(dllexport) void VT_PULSE() {
    vt::JobHook::pulse();
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_module = module;
        vt::module_main(module); // records HMODULE only — work runs on VT_TICK
    } else if (reason == DLL_PROCESS_DETACH) {
        vt::module_shutdown();
    }
    return TRUE;
}
