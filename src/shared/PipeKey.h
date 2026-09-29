#pragma once

#include <string>
#include <Windows.h>

// Session-unique named pipe key shared between the host EXE and the
// injected DLL via a named shared-memory section.
//
// Flow:
//   Host (EXE):  PipeKey::create()  -> generates a random pipe name,
//                                       writes it to the section,
//                                       returns the pipe name to use.
//   Module (DLL): PipeKey::open()   -> opens the same section, reads
//                                       and returns the pipe name.
//
// The section name itself is obfuscated (derived at runtime from XOR'd
// bytes so it never appears as a plaintext string in the binary).

namespace vt {

class PipeKey {
public:
    // EXE side — call before starting the PipeServer.
    // Returns the pipe path to listen on (e.g. \\.\pipe\DevSKU_a3f9b2c1).
    // Returns empty string on failure (use the static kPipeName fallback).
    static std::wstring create();

    // Last name produced by create(), or empty if create() has not run.
    static std::wstring cached();

    // DLL side — call after DLL_PROCESS_ATTACH, before connect().
    // Blocks up to timeout_ms for the section to appear (EXE may still
    // be setting up when the DLL first runs).
    static std::wstring open(int timeout_ms = 10000);

private:
    static std::wstring section_name();   // obfuscated at runtime
    static std::wstring generate_name();  // random per session

    static constexpr size_t kBufLen = 80; // wchar_t slots in the section
};

} // namespace vt
