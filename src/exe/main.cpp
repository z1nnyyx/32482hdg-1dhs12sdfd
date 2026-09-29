#include "exe/App.h"

#include <Windows.h>

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, PWSTR, int) {
    return vt::App::run(inst);
}

#if defined(_MSC_VER) && defined(_CONSOLE)
int wmain() {
    return wWinMain(GetModuleHandleW(nullptr), nullptr, GetCommandLineW(), SW_SHOW);
}
#endif
