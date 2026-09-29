#include "exe/Payload.h"
#include "exe/resource.h"
#include "exe/Defaults.h"
#include "shared/Utils.h"
#include "shared/Log.h"

#include <Windows.h>

namespace vt {

std::vector<uint8_t> Payload::module_bytes() {
    HMODULE self = GetModuleHandleW(nullptr);
    HRSRC rc = FindResourceW(self, MAKEINTRESOURCEW(IDR_VT_MODULE), RT_RCDATA);
    if (!rc)
        return {};
    HGLOBAL mem = LoadResource(self, rc);
    if (!mem)
        return {};
    const auto n = SizeofResource(self, rc);
    const auto* p = (const uint8_t*)LockResource(mem);
    if (!p || !n)
        return {};
    return {p, p + n};
}

void Payload::seed() {
    const auto root = data_root();
    hide_path(root);
    app_dir(L"config");
    app_dir(L"scripts\\autoexec");
    app_dir(L"scripts\\hub");
    app_dir(L"scripts\\saved");
    app_dir(L"workspace");
    app_dir(L"tabs");
    hide_path(root / L"config");

    const auto cfg = root / L"config" / L"offsets.json";
    const auto welcome = root / L"scripts" / L"autoexec" / L"welcome.lua";
    const auto esp = root / L"scripts" / L"autoexec" / L"esp.lua";
    const auto hub = root / L"scripts" / L"hub" / L"example.lua";
    if (!file_exists(cfg))
        write_file_utf8(cfg, kDefaultOffsetsJson);
    if (!file_exists(welcome))
        write_file_utf8(welcome, kWelcomeLua);
    if (!file_exists(esp))
        write_file_utf8(esp, kEspLua);
    if (!file_exists(hub))
        write_file_utf8(hub, kHubExampleLua);
    hide_path(cfg);
}

std::filesystem::path Payload::unpack_hidden_module() {
    auto bytes = module_bytes();
    if (bytes.empty()) {
        VT_ERR(L"exe has no packed module — rebuild Release | x64");
        return {};
    }

    // Unique per-run name so a Defender-locked stale file from a previous
    // attempt never blocks the exclusive CreateFile.
    wchar_t uname[32];
    swprintf_s(uname, L"api-%08X.bin", GetTickCount());

    // Never drop the module into Roblox's Versions tree — Hyperion hashes that
    // directory. Stage next to our own data dir, then %TEMP%.
    std::vector<std::filesystem::path> dirs;
    seed();
    dirs.emplace_back(data_root() / L"cache");
    wchar_t tmp[MAX_PATH]{};
    if (GetTempPathW(MAX_PATH, tmp))
        dirs.emplace_back(std::filesystem::path(tmp));

    for (auto& dir : dirs) {
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        if (ec) continue;

        const auto file = dir / uname;
        DeleteFileW(file.c_str()); // remove any same-name leftover
        if (write_file_bytes(file, bytes.data(), bytes.size())) {
            hide_path(file);
            VT_LOG(L"staged module → " + file.wstring());
            return file;
        }
        VT_WARN(L"stage failed: " + file.wstring() +
                L"  err=" + std::to_wstring(GetLastError()));
    }

    VT_ERR(L"failed to stage module — all candidate paths rejected");
    return {};
}

} // namespace vt
