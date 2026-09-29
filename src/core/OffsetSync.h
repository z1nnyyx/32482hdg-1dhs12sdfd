#pragma once

#include <filesystem>
#include <string>

namespace vt {

// Reads RobloxPlayerBeta.exe from disk (not Hyperion-paged memory),
// pattern-scans .text, scores pointer RVAs against a live process if present,
// writes the result into Config + offsets.json.
class OffsetSync {
public:
    static bool refresh();
    static std::filesystem::path find_roblox_exe();
};

} // namespace vt
