#pragma once

#include <Windows.h>

namespace vt {

void module_main(HMODULE self);
void module_tick();
void module_poll_pipe();
void module_note_ready();
void module_shutdown();

} // namespace vt
