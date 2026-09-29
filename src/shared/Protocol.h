#pragma once

#include <string>
#include <cstdint>
#include <vector>

namespace vt {

// Length-prefixed messages over a duplex named pipe.
// Frame: uint32 le size | uint8 type | payload
enum class MsgType : uint8_t {
    Ping        = 1,
    Pong        = 2,
    Execute     = 3,
    ExecuteOk   = 4,
    ExecuteErr  = 5,
    Log         = 6,
    Status      = 7,
    AutoExec    = 8,
    Ready       = 9,
    Shutdown    = 10,
    DrawFrame   = 11,
    JobHint     = 12, // host RPM: "0xJOB TID" (WaitingHybridScriptsJob + lua thread)
    OffsetReport = 13, // dll→host: "0xPCALL 0xLOAD" resolved absolute VAs
    // External IAT patch — VirtualProtect from injected DLL is denied by
    // Hyperion (err=5). Exe patches game IAT from outside (VirtualProtectEx +
    // WriteProcessMemory succeeds because it comes from a different process).
    ExtHookReq     = 14, // dll→host: "module|func1,func2,...|0xSTUB_ADDR"
    ExtHookAck     = 15, // host→dll: "0xORIG" on success, "0" on fail
    ExtHookUnpatch = 16, // dll→host: restore the patched IAT slot now (pump ran)
    Park           = 17, // host→dll: stop ticking; host will restore USER32 IAT
};

struct Message {
    MsgType     type = MsgType::Ping;
    std::string payload;
};

std::vector<uint8_t> pack(const Message& m);
bool try_unpack(const uint8_t* data, size_t n, Message& out, size_t& consumed);

constexpr wchar_t kPipeName[] = L"\\\\.\\pipe\\crashpad_44182_dmp";
constexpr uint32_t kMaxPayload = 8 * 1024 * 1024;

} // namespace vt
