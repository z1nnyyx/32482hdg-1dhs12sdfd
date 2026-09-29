#include "shared/Protocol.h"

#include <cstring>

namespace vt {

std::vector<uint8_t> pack(const Message& m) {
    const uint32_t size = 1 + (uint32_t)m.payload.size();
    std::vector<uint8_t> buf(4 + size);
    std::memcpy(buf.data(), &size, 4);
    buf[4] = (uint8_t)m.type;
    if (!m.payload.empty())
        std::memcpy(buf.data() + 5, m.payload.data(), m.payload.size());
    return buf;
}

bool try_unpack(const uint8_t* data, size_t n, Message& out, size_t& consumed) {
    consumed = 0;
    if (n < 5)
        return false;
    uint32_t size = 0;
    std::memcpy(&size, data, 4);
    if (size == 0 || size > kMaxPayload)
        return false;
    if (n < 4 + size)
        return false;
    out.type = (MsgType)data[4];
    out.payload.assign((const char*)data + 5, size - 1);
    consumed = 4 + size;
    return true;
}

} // namespace vt
