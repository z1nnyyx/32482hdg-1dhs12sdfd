#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace vt {

enum DrawKind : uint8_t {
    DK_LINE = 1,
    DK_SQUARE = 2,
    DK_CIRCLE = 3,
    DK_TEXT = 4,
    DK_QUAD = 5,
    DK_TRIANGLE = 6,
};

enum DrawFlags : uint8_t {
    DF_VIS  = 1,
    DF_FILL = 2,
    DF_OUT  = 4,
};

#pragma pack(push, 1)
struct DrawPrim {
    uint8_t  kind = 0;
    uint8_t  flags = DF_VIS;
    uint8_t  r = 255, g = 255, b = 255, a = 255;
    uint8_t  or_ = 0, og = 0, ob = 0, oa = 255;
    float    thick = 1;
    float    size = 16;
    float    rad = 0;
    float    x1 = 0, y1 = 0, x2 = 0, y2 = 0, x3 = 0, y3 = 0, x4 = 0, y4 = 0;
    uint16_t ntext = 0;
};
#pragma pack(pop)

struct DrawItem {
    DrawPrim    p{};
    std::string text;
};

inline std::string pack_draws(const std::vector<DrawItem>& items) {
    const uint16_t n = (uint16_t)(items.size() > 512 ? 512 : items.size());
    std::string out;
    out.resize(2);
    std::memcpy(out.data(), &n, 2);
    for (uint16_t i = 0; i < n; ++i) {
        DrawPrim pr = items[i].p;
        const uint16_t tn = (uint16_t)(items[i].text.size() > 256 ? 256 : items[i].text.size());
        pr.ntext = tn;
        const size_t at = out.size();
        out.resize(at + sizeof(DrawPrim) + tn);
        std::memcpy(out.data() + at, &pr, sizeof(DrawPrim));
        if (tn)
            std::memcpy(out.data() + at + sizeof(DrawPrim), items[i].text.data(), tn);
    }
    return out;
}

inline std::vector<DrawItem> unpack_draws(const std::string& blob) {
    std::vector<DrawItem> out;
    if (blob.size() < 2)
        return out;
    uint16_t n = 0;
    std::memcpy(&n, blob.data(), 2);
    size_t off = 2;
    out.reserve(n);
    for (uint16_t i = 0; i < n; ++i) {
        if (off + sizeof(DrawPrim) > blob.size())
            break;
        DrawItem it;
        std::memcpy(&it.p, blob.data() + off, sizeof(DrawPrim));
        off += sizeof(DrawPrim);
        if (it.p.ntext) {
            if (off + it.p.ntext > blob.size())
                break;
            it.text.assign(blob.data() + off, it.p.ntext);
            off += it.p.ntext;
        }
        out.push_back(std::move(it));
    }
    return out;
}

} // namespace vt
