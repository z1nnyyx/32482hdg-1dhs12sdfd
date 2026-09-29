#include "ext/Overlay.h"

#include "shared/Log.h"

#include <dwmapi.h>
#include <algorithm>
#include <string>
#include <tuple>
#include <vector>

#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "msimg32.lib")

#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif

namespace vt::ext {
namespace {

constexpr wchar_t kCls[] = L"Windows.UI.Composition.Host";

} // namespace

Overlay& Overlay::instance() {
    static Overlay g;
    return g;
}

void Overlay::set_lua_draw(std::string blob) {
    auto items = unpack_draws(blob);
    std::lock_guard lock(lua_mtx_);
    lua_draw_ = std::move(items);
}

void Overlay::present(int W, int H) {
    if (!wnd_ || W < 8 || H < 8)
        return;

    const bool resized = !memdc_ || dib_w_ != W || dib_h_ != H || !dib_ || !bits_;
    if (resized) {
        if (dib_) {
            if (memdc_ && oldbmp_)
                SelectObject(memdc_, oldbmp_);
            DeleteObject(dib_);
            dib_ = nullptr;
            bits_ = nullptr;
            oldbmp_ = nullptr;
        }
        if (!memdc_)
            memdc_ = CreateCompatibleDC(nullptr);
        BITMAPINFO bi{};
        bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bi.bmiHeader.biWidth = W;
        bi.bmiHeader.biHeight = -H;
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 32;
        bi.bmiHeader.biCompression = BI_RGB;
        dib_ = CreateDIBSection(memdc_, &bi, DIB_RGB_COLORS, &bits_, nullptr, 0);
        if (!dib_ || !bits_)
            return;
        oldbmp_ = SelectObject(memdc_, dib_);
        dib_w_ = W;
        dib_h_ = H;
        dirty_any_ = false;
    }
    HDC dc = memdc_;
    void* bits = bits_;
    auto* px = static_cast<unsigned char*>(bits);

    auto clampi = [](int v, int lo, int hi) {
        return v < lo ? lo : (v > hi ? hi : v);
    };
    auto clear_rect = [&](int x0, int y0, int x1, int y1) {
        x0 = clampi(x0, 0, W);
        y0 = clampi(y0, 0, H);
        x1 = clampi(x1, 0, W);
        y1 = clampi(y1, 0, H);
        if (x1 <= x0 || y1 <= y0)
            return;
        const size_t row_bytes = (size_t)(x1 - x0) * 4;
        for (int y = y0; y < y1; ++y)
            memset(px + ((size_t)y * (size_t)W + (size_t)x0) * 4, 0, row_bytes);
    };
    if (resized || !dirty_any_)
        memset(bits, 0, (size_t)W * (size_t)H * 4);
    else
        clear_rect(dirty_x0_ - 2, dirty_y0_ - 2, dirty_x1_ + 2, dirty_y1_ + 2);

    int dx0 = W, dy0 = H, dx1 = 0, dy1 = 0;
    bool any = false;
    auto mark = [&](int x0, int y0, int x1, int y1) {
        if (x0 > x1) std::swap(x0, x1);
        if (y0 > y1) std::swap(y0, y1);
        x0 -= 2; y0 -= 2; x1 += 2; y1 += 2;
        if (!any) {
            dx0 = x0; dy0 = y0; dx1 = x1; dy1 = y1;
            any = true;
            return;
        }
        if (x0 < dx0) dx0 = x0;
        if (y0 < dy0) dy0 = y0;
        if (x1 > dx1) dx1 = x1;
        if (y1 > dy1) dy1 = y1;
    };

    std::vector<DrawItem> lua;
    {
        std::lock_guard lock(lua_mtx_);
        lua = lua_draw_;
    }

    const auto& ents = ents_;
    int sw = ent_sw_ > 0 ? ent_sw_ : W;
    int sh = ent_sh_ > 0 ? ent_sh_ : H;
    const float xs = W / (float)(sw > 0 ? sw : W);
    const float ys = H / (float)(sh > 0 ? sh : H);

    SetBkMode(dc, TRANSPARENT);
    auto of = SelectObject(dc, font_ ? font_ : GetStockObject(DEFAULT_GUI_FONT));

    auto stroke = [&](COLORREF c, int thick, bool fill) {
        HPEN pen = CreatePen(PS_SOLID, thick > 0 ? thick : 1, c);
        HBRUSH br = fill ? CreateSolidBrush(c) : (HBRUSH)GetStockObject(NULL_BRUSH);
        auto op = SelectObject(dc, pen);
        auto ob = SelectObject(dc, br);
        return std::tuple<HPEN, HBRUSH, HGDIOBJ, HGDIOBJ, bool>{pen, br, op, ob, fill};
    };
    auto unstroke = [&](auto t) {
        SelectObject(dc, std::get<2>(t));
        SelectObject(dc, std::get<3>(t));
        DeleteObject(std::get<0>(t));
        if (std::get<4>(t))
            DeleteObject(std::get<1>(t));
    };

    if (esp_) {
        HPEN pen = CreatePen(PS_SOLID, 2, RGB(90, 170, 255));
        auto op = SelectObject(dc, pen);
        SelectObject(dc, GetStockObject(NULL_BRUSH));
        SetTextColor(dc, RGB(230, 236, 255));

        int listed = 0;
        RECT header{14, 12, 360, 30};
        char hdr[96];
        const auto st = world_.stats();
        if (ents.empty())
            sprintf_s(hdr, "ESP  %ls", st.note);
        else
            sprintf_s(hdr, "ESP  %d players", (int)ents.size());
        DrawTextA(dc, hdr, -1, &header, DT_LEFT | DT_SINGLELINE);
        mark(header.left, header.top, header.right, header.bottom);

        for (const auto& e : ents) {
            if (e.local)
                continue;
            RECT lr{16, 32 + listed * 18, 340, 50 + listed * 18};
            char row[160];
            if (e.has_pos)
                sprintf_s(row, "%s", e.name.c_str());
            else
                sprintf_s(row, "%s  (no char)", e.name.c_str());
            DrawTextA(dc, row, -1, &lr, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
            mark(lr.left, lr.top, lr.right, lr.bottom);
            ++listed;
            if (listed > 28)
                break;

            if (!e.has_pos)
                continue;
            Vec2 s{};
            if (!world_.world_to_screen(e.pos, s))
                continue;
            const int nx = (int)(s.x * xs);
            const int ny = (int)(s.y * ys);
            const int box_h = 64, box_w = 28;
            const int x = nx - box_w / 2;
            const int y = ny - box_h;
            Rectangle(dc, x, y, x + box_w, y + box_h);
            MoveToEx(dc, W / 2, H, nullptr);
            LineTo(dc, nx, ny);
            RECT tr{x - 70, y - 18, x + box_w + 70, y};
            DrawTextA(dc, e.name.c_str(), -1, &tr, DT_CENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            mark(x, y, x + box_w, y + box_h);
            mark(W / 2, ny, nx, H);
            mark(tr.left, tr.top, tr.right, tr.bottom);
        }
        SelectObject(dc, op);
        DeleteObject(pen);
    }

    for (const auto& it : lua) {
        const auto& p = it.p;
        const COLORREF c = RGB(p.r, p.g, p.b);
        const int t = (int)(p.thick > 0 ? p.thick : 1);
        const bool fill = (p.flags & DF_FILL) != 0;
        auto st = stroke(c, t, fill);
        switch (p.kind) {
        case DK_LINE:
            MoveToEx(dc, (int)p.x1, (int)p.y1, nullptr);
            LineTo(dc, (int)p.x2, (int)p.y2);
            mark((int)p.x1, (int)p.y1, (int)p.x2, (int)p.y2);
            break;
        case DK_SQUARE: {
            const int x2 = (int)(p.x1 + p.x2);
            const int y2 = (int)(p.y1 + p.y2);
            Rectangle(dc, (int)p.x1, (int)p.y1, x2, y2);
            mark((int)p.x1, (int)p.y1, x2, y2);
            break;
        }
        case DK_CIRCLE: {
            const float rad = p.rad > 0 ? p.rad : p.size;
            Ellipse(dc, (int)(p.x1 - rad), (int)(p.y1 - rad),
                    (int)(p.x1 + rad), (int)(p.y1 + rad));
            mark((int)(p.x1 - rad), (int)(p.y1 - rad), (int)(p.x1 + rad), (int)(p.y1 + rad));
            break;
        }
        case DK_TEXT: {
            SetTextColor(dc, c);
            RECT tr{(int)p.x1, (int)p.y1, (int)p.x1 + 800, (int)p.y1 + (int)(p.size + 8)};
            DrawTextA(dc, it.text.c_str(), -1, &tr, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
            mark(tr.left, tr.top, tr.right, tr.bottom);
            break;
        }
        case DK_TRIANGLE: {
            POINT pts[3] = {
                {(int)p.x1, (int)p.y1}, {(int)p.x2, (int)p.y2}, {(int)p.x3, (int)p.y3}
            };
            Polygon(dc, pts, 3);
            mark((int)p.x1, (int)p.y1, (int)p.x2, (int)p.y2);
            mark((int)p.x1, (int)p.y1, (int)p.x3, (int)p.y3);
            break;
        }
        case DK_QUAD: {
            POINT pts[4] = {
                {(int)p.x1, (int)p.y1}, {(int)p.x2, (int)p.y2},
                {(int)p.x3, (int)p.y3}, {(int)p.x4, (int)p.y4}
            };
            Polygon(dc, pts, 4);
            mark((int)p.x1, (int)p.y1, (int)p.x3, (int)p.y3);
            mark((int)p.x2, (int)p.y2, (int)p.x4, (int)p.y4);
            break;
        }
        default:
            break;
        }
        unstroke(st);
    }

    SelectObject(dc, of);

    if (any) {
        dx0 = clampi(dx0, 0, W);
        dy0 = clampi(dy0, 0, H);
        dx1 = clampi(dx1, 0, W);
        dy1 = clampi(dy1, 0, H);
        for (int y = dy0; y < dy1; ++y) {
            unsigned char* row = px + ((size_t)y * (size_t)W) * 4;
            for (int x = dx0; x < dx1; ++x) {
                unsigned char* p = row + (size_t)x * 4;
                if (p[0] | p[1] | p[2])
                    p[3] = 255;
            }
        }
        dirty_x0_ = dx0;
        dirty_y0_ = dy0;
        dirty_x1_ = dx1;
        dirty_y1_ = dy1;
        dirty_any_ = true;
    } else {
        dirty_any_ = false;
    }

    POINT pt{};
    RECT wr{};
    GetWindowRect(wnd_, &wr);
    pt.x = wr.left;
    pt.y = wr.top;
    SIZE sz{W, H};
    POINT src{0, 0};
    BLENDFUNCTION bf{AC_SRC_OVER, 0, 255, AC_SRC_ALPHA};
    HDC screen = GetDC(nullptr);
    UpdateLayeredWindow(wnd_, screen, &pt, &sz, dc, &src, 0, &bf, ULW_ALPHA);
    ReleaseDC(nullptr, screen);
}

void Overlay::tick() {
    if (!wnd_)
        return;
    if (!game_ || !IsWindow(game_))
        return;

    bool lua_any = false;
    {
        std::lock_guard lock(lua_mtx_);
        lua_any = !lua_draw_.empty();
    }
    if (!esp_ && !lua_any) {
        if (shown_) {
            ShowWindow(wnd_, SW_HIDE);
            shown_ = false;
        }
        return;
    }

    RECT rc{};
    if (!GetClientRect(game_, &rc))
        return;
    POINT tl{rc.left, rc.top};
    POINT br{rc.right, rc.bottom};
    ClientToScreen(game_, &tl);
    ClientToScreen(game_, &br);
    const int w = br.x - tl.x, h = br.y - tl.y;
    if (w < 8 || h < 8)
        return;
    world_.set_fallback_size((float)w, (float)h);

    const DWORD now = GetTickCount();
    const DWORD gap = last_ents_ > 0 ? 50u : 1000u;
    if (esp_ && (now - last_poll_ >= gap || last_poll_ == 0)) {
        int sw = w, sh = h;
        world_.poll(ents_, &sw, &sh);
        ent_sw_ = sw;
        ent_sh_ = sh;
        last_ents_ = (int)ents_.size();
        last_poll_ = now;
    }

    if (!lua_any && last_ents_ <= 0) {
        if (shown_) {
            ShowWindow(wnd_, SW_HIDE);
            shown_ = false;
        }
        return;
    }

    if (!shown_) {
        ShowWindow(wnd_, SW_SHOWNOACTIVATE);
        shown_ = true;
    }
    if (tl.x != last_x_ || tl.y != last_y_ || w != last_w_ || h != last_h_) {
        SetWindowPos(wnd_, HWND_TOPMOST, tl.x, tl.y, w, h,
                     SWP_NOACTIVATE | SWP_SHOWWINDOW);
        last_x_ = tl.x;
        last_y_ = tl.y;
        last_w_ = w;
        last_h_ = h;
    } else
        SetWindowPos(wnd_, HWND_TOPMOST, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    present(w, h);
}

LRESULT CALLBACK Overlay::wndproc(HWND wnd, UINT msg, WPARAM wp, LPARAM lp) {
    auto* self = &instance();
    switch (msg) {
    case WM_CREATE:
        SetTimer(wnd, 1, 32, nullptr);
        return 0;
    case WM_TIMER:
        self->tick();
        return 0;
    case WM_ERASEBKGND:
        return 1;
    case WM_DESTROY:
        KillTimer(wnd, 1);
        return 0;
    }
    return DefWindowProcW(wnd, msg, wp, lp);
}

bool Overlay::start(DWORD pid, uintptr_t image_base, size_t image_size, HWND game) {
    if (on_ && wnd_ && attach_pid_ == pid && world_.ok()) {
        game_ = game;
        if (game)
            tick();
        return true;
    }
    stop();
    attach_pid_ = pid;
    last_poll_ = 0;
    last_ents_ = 0;
    if (!world_.attach(pid, image_base, image_size)) {
        VT_WARN(L"Attach failed — run as Administrator");
        return false;
    }
    if (!game) {
        VT_WARN(L"Roblox window not found — join a game, then Attach again");
        world_.detach();
        return false;
    }
    game_ = game;

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = wndproc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.lpszClassName = kCls;
    wc.hbrBackground = (HBRUSH)GetStockObject(NULL_BRUSH);
    RegisterClassExW(&wc);

    wnd_ = CreateWindowExW(
        WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_TOPMOST,
        kCls, L"",
        WS_POPUP,
        0, 0, 64, 64,
        nullptr, nullptr, wc.hInstance, nullptr);
    if (!wnd_) {
        world_.detach();
        return false;
    }
    SetWindowDisplayAffinity(wnd_, WDA_EXCLUDEFROMCAPTURE);
    font_ = CreateFontW(13, 0, 0, 0, FW_MEDIUM, 0, 0, 0, DEFAULT_CHARSET, 0, 0,
                        CLEARTYPE_QUALITY, 0, L"Segoe UI");
    ShowWindow(wnd_, SW_SHOWNOACTIVATE);
    shown_ = true;
    last_x_ = INT_MIN;
    tick();
    on_ = true;
    {
        const auto st = world_.stats();
        VT_LOG(std::wstring(L"ESP  ") + st.note);
        if (!st.datamodel)
            VT_WARN(L"Live RVAs are empty on this build. Attach overlay cannot see DataModel. Inject → wait READY for Highlight ESP.");
        else if (st.entities <= 0)
            VT_WARN(L"DataModel yes, no characters yet.");
        else
            VT_LOG(L"ESP players " + std::to_wstring(st.entities));
    }
    return true;
}

void Overlay::stop() {
    on_ = false;
    shown_ = false;
    last_x_ = INT_MIN;
    dirty_any_ = false;
    attach_pid_ = 0;
    last_poll_ = 0;
    last_ents_ = 0;
    ents_.clear();
    world_.detach();
    if (font_) {
        DeleteObject(font_);
        font_ = nullptr;
    }
    if (dib_) {
        if (memdc_ && oldbmp_)
            SelectObject(memdc_, oldbmp_);
        DeleteObject(dib_);
        dib_ = nullptr;
        bits_ = nullptr;
        oldbmp_ = nullptr;
        dib_w_ = dib_h_ = 0;
    }
    if (memdc_) {
        DeleteDC(memdc_);
        memdc_ = nullptr;
    }
    if (wnd_) {
        DestroyWindow(wnd_);
        wnd_ = nullptr;
    }
    game_ = nullptr;
}

} // namespace vt::ext
