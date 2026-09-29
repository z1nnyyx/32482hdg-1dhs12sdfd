#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <filesystem>
#include <optional>
#include <cstdint>

namespace vt {

std::wstring utf8_to_wide(const std::string& s);
std::string  wide_to_utf8(const std::wstring& s);

std::filesystem::path exe_dir();
std::filesystem::path data_root(); // hidden %LOCALAPPDATA%\WinAppCache
std::filesystem::path app_dir(const wchar_t* sub);
void hide_path(const std::filesystem::path& p);

bool enable_debug_privilege();
bool file_exists(const std::filesystem::path& p);
std::string read_file_utf8(const std::filesystem::path& p);
bool write_file_utf8(const std::filesystem::path& p, const std::string& data);
bool write_file_bytes(const std::filesystem::path& p, const void* data, size_t n);

std::wstring format_hex(uintptr_t v);
std::wstring last_error_text(DWORD err = GetLastError());

struct ModuleInfo {
    uintptr_t base = 0;
    size_t    size = 0;
    std::wstring path;
};

std::optional<ModuleInfo> find_module(DWORD pid, const wchar_t* name);
std::optional<ModuleInfo> find_module_local(const wchar_t* name);

} // namespace vt
