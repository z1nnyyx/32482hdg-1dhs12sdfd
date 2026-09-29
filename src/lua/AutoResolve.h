#pragma once

#include "lua/Offsets.h"

namespace vt {

// Fills missing RVAs / pointers from the live Roblox image.
// Called after offsets.json is applied. Never invents "undetected".
void auto_resolve(Resolved& r);
// One pattern-group per call so we never stall PeekMessage on a 100MB scan.
// Returns true when every group has been attempted.
bool auto_resolve_tick(Resolved& r);

} // namespace vt
