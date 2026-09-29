#include "exe/App.h"

#include "core/Process.h"
#include "core/Injector.h"
#include "core/Pipe.h"
#include "core/Syscall.h"
#include "core/Byovd.h"
#include "core/CallSpoof.h"
#include "core/OffsetSync.h"
#include "shared/CfgProxy.h"
#include "exe/Payload.h"
#include "exe/resource.h"
#include "ext/World.h"
#include "ext/Overlay.h"
#include "shared/Config.h"
#include "shared/Log.h"
#include "shared/PipeKey.h"
#include "shared/Utils.h"

#include <CommDlg.h>
#include <psapi.h>
#include <dwmapi.h>
#include <uxtheme.h>
#include <shellapi.h>
#include <windowsx.h>
#include <wincodec.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <cwctype>
#include <filesystem>
#include <atomic>
#include <mutex>
#include <thread>
#include <optional>
#include <string>
#include <vector>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "msimg32.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "windowscodecs.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "psapi.lib")

#ifndef DWMWA_WINDOW_CORNER_PREFERENCE
#define DWMWA_WINDOW_CORNER_PREFERENCE 33
#endif
#ifndef DWMWCP_ROUND
#define DWMWCP_ROUND 2
#endif

namespace vt {

enum : int {
    ID_EXECUTE = 1003, ID_CLEAR, ID_OPEN, ID_SAVE, ID_SAVEAS,
    ID_NEWTAB, ID_CLOSETAB, ID_EDITOR,
};

HACCEL make_accels() {
    ACCEL acc[] = {
        {FVIRTKEY, VK_F5, ID_EXECUTE},
        {FVIRTKEY | FCONTROL, 'S', ID_SAVE},
        {FVIRTKEY | FCONTROL, 'T', ID_NEWTAB},
        {FVIRTKEY | FCONTROL, 'W', ID_CLOSETAB},
        {FVIRTKEY | FCONTROL, 'O', ID_OPEN},
    };
    return CreateAcceleratorTableW(acc, (int)std::size(acc));
}

namespace {

constexpr wchar_t kClass[] = L"VoidTrace.Shell.Window";
constexpr wchar_t kLogClass[] = L"VoidTrace.Shell.Window.Out";
constexpr UINT WM_TRAY = WM_APP + 7;
constexpr UINT WM_LOG_WAKE = WM_APP + 21;
constexpr UINT WM_JOB_HINT = WM_APP + 22;
constexpr UINT WM_PROG = WM_APP + 25;
constexpr UINT WM_ATTACH_CONT = WM_APP + 26;
constexpr UINT ID_HOT_TOGGLE = 0x71;

constexpr int kTitleH = 34;
constexpr int kTabH   = 28;
constexpr int kBarH   = 46;
constexpr int kGutter = 32;
constexpr int kLogLineH = 18;
constexpr int kEdge   = 6;
constexpr UINT kTipDelay = 380;

// Dark-navy palette — electric blue accent, deep navy base.
constexpr COLORREF kBg      = RGB(6,  10, 22);      // near-black navy
constexpr COLORREF kEditor  = RGB(3,   6, 14);      // deeper navy for code area
constexpr COLORREF kBar     = RGB(8,  13, 26);      // toolbar/status bar
constexpr COLORREF kChip    = RGB(14, 24, 52);      // chip button background
constexpr COLORREF kLine    = RGB(24, 44, 96);      // dividers
constexpr COLORREF kText    = RGB(215, 230, 255);   // blue-tinted white
constexpr COLORREF kMuted   = RGB(80, 115, 175);    // muted blue-grey
constexpr COLORREF kBlue    = RGB(65, 148, 255);    // electric blue accent
constexpr COLORREF kGlow    = RGB(22,  80, 200);    // deep blue glow / border
constexpr COLORREF kTabOn   = RGB(0,  200, 255);    // cyan active tab
constexpr COLORREF kHover   = RGB(14,  28, 64);     // hover highlight
constexpr COLORREF kTipBg   = RGB(10,  18, 40);
constexpr COLORREF kTipBd   = RGB(40,  80, 180);
constexpr COLORREF kOk      = RGB(0,  210, 140);    // connected/success green
constexpr COLORREF kWarn    = RGB(255, 180, 30);    // injected / attaching amber
constexpr COLORREF kExecBtn = RGB(22, 100, 220);    // execute button fill (blue)

struct ScriptTab {
    std::wstring name, path, text;
    bool dirty = false;
};
struct FileItem {
    std::wstring label, path;
};
struct Hit {
    RECT rc{};
    int id = 0;
};

enum HitId : int {
    H_NONE = 0, H_MIN, H_MAX, H_CLOSE,
    H_GEAR, H_OPEN, H_SAVE, H_CLEAR,
    H_ATTACH, H_INJECT, H_ESP, H_SCRIPTS, H_TOPMOST, H_EXECUTE, H_NEWTAB,
    H_SETLOG, H_SETHELP, H_SETINJ, H_SETESP, H_SETMAP, H_SETBACK, H_SETAUTO, H_SETSTARS,
    H_TAB0 = 200, H_TABX0 = 400, H_FILE0 = 600,
};

// ── Star-field animation ─────────────────────────────────────────────────────
struct Star { float x, y, vx, vy, phase, phase_rate, base_alpha; int sz; };
static constexpr int kStarCount = 90;
static Star  g_stars[kStarCount]{};
static bool  g_stars_inited  = false;
bool         g_stars_enabled = false;

// External hook auto-unpatch tracking. Set by ExtHookReq handler when a slot
// is patched; the WM_TIMER handler restores the original after ~5s so
// Hyperion's periodic IAT integrity scan (~10-15s interval) sees a clean
// pointer and doesn't kill the process.
static uintptr_t g_ext_patch_slot = 0;
static uintptr_t g_ext_patch_orig = 0;
static DWORD     g_ext_patch_time = 0;   // GetTickCount at patch time
static bool      g_ext_unpatched  = false;

static uintptr_t g_job_saved = 0;
static uintptr_t g_job_vptr_orig = 0;
static DWORD     g_job_hint_tick = 0;
static bool      g_job_vptr_restored = false;

static void init_stars(int W, int H) {
    // Deterministic seed so the field looks the same on every launch.
    srand(0xC0FFEE);
    for (auto& s : g_stars) {
        s.x          = (float)(rand() % W);
        s.y          = (float)(rand() % H);
        s.vx         = ((rand() % 200) - 100) * 0.0003f;   // ±0.03 px/tick drift
        s.vy         = ((rand() % 200) - 100) * 0.0003f;
        s.phase      = (float)(rand() % 628) * 0.01f;
        s.phase_rate = 0.015f + (rand() % 60) * 0.0005f;   // slow, varied flicker
        s.base_alpha = 0.30f + (rand() % 70) * 0.01f;
        s.sz         = (rand() % 5 == 0) ? 2 : 1;           // 1-in-5 are 2×2
    }
    g_stars_inited = true;
}

static void update_stars(int W, int H, int mx, int my) {
    constexpr float kRepelDist = 110.f;
    constexpr float kRepelStr  = 0.7f;
    constexpr float kDamp      = 0.93f;
    for (auto& s : g_stars) {
        s.phase += s.phase_rate;
        // Cursor repulsion
        const float dx = s.x - (float)mx;
        const float dy = s.y - (float)my;
        const float d2 = dx*dx + dy*dy;
        if (d2 < kRepelDist*kRepelDist && d2 > 0.5f) {
            const float d = sqrtf(d2);
            const float f = kRepelStr * (1.f - d / kRepelDist);
            s.vx += dx / d * f;
            s.vy += dy / d * f;
        }
        s.vx *= kDamp;
        s.vy *= kDamp;
        s.x  += s.vx;
        s.y  += s.vy;
        // Wrap edges
        if (s.x < -2)     s.x += (float)W + 4;
        if (s.x > W + 2)  s.x -= (float)W + 4;
        if (s.y < -2)     s.y += (float)H + 4;
        if (s.y > H + 2)  s.y -= (float)H + 4;
    }
}

static void draw_stars(HDC dc, int W, int H) {
    if (!g_stars_enabled) return;
    if (!g_stars_inited && W > 0 && H > 0) init_stars(W, H);
    if (!g_stars_inited) return;
    for (const auto& s : g_stars) {
        const float alpha = s.base_alpha * (0.5f + 0.5f * sinf(s.phase));
        if (alpha < 0.06f) continue;
        int v = (int)(alpha * 235);
        if (v < 0) v = 0; if (v > 235) v = 235;
        // Blue-white tint
        const COLORREF c = RGB(v, v + 12 > 255 ? 255 : v + 12,
                                  v + 35 > 255 ? 255 : v + 35);
        const int sx = (int)s.x, sy = (int)s.y;
        if (sx < 0 || sy < 0 || sx >= W || sy >= H) continue;
        SetPixel(dc, sx, sy, c);
        if (s.sz == 2) {
            if (sx + 1 < W) SetPixel(dc, sx + 1, sy, c);
            if (sy + 1 < H) SetPixel(dc, sx, sy + 1, c);
        }
    }
}
// ─────────────────────────────────────────────────────────────────────────────

ext::World g_rpm;

HWND g_wnd = nullptr;
HWND g_editor = nullptr;
HWND g_log_wnd = nullptr;
HWND g_log_edit = nullptr;
WNDPROC g_log_edit_prev = nullptr;
HBRUSH g_brLog = nullptr;
int g_log_shown = 0;
PipeServer g_pipe;
std::optional<RobloxProcess> g_rbx;
bool g_injected = false;
DWORD g_mapped_pid = 0;
DWORD g_map_tick = 0;
uintptr_t g_iat_slot = 0;
uintptr_t g_iat_stub = 0;
uintptr_t g_iat_orig = 0;
bool      g_iat_restored = false;
bool      g_wait_hooked = false;
bool g_pipe_warned = false;
bool g_auto_attach  = false;
bool g_auto_inject  = true;
bool g_stream_proof = false;
int  g_pipe_pct     = 0;
std::wstring g_pipe_note = L"Idle";
bool g_init_done    = false;
int  g_init_step    = -1;  // 0-5: do_deferred_init steps
int  g_attach_step  = -1;  // 0-N: do_attach / map_module steps
std::atomic<bool> g_attach_busy{false};
DWORD g_ui_tid = 0;
bool g_show_log = false;
int  g_log_hover = 0;
std::mutex g_log_mtx;
std::vector<std::pair<LogLevel, std::wstring>> g_log_lines;
std::atomic<int> g_log_wake{0};
bool g_autoexec_done = false;
bool g_mod_ready = false;

bool g_topmost = false;
bool g_scripts_open = false;
bool g_settings_open = false;
HFONT g_font = nullptr;
HFONT g_fontSm = nullptr;
HFONT g_fontBd = nullptr;
HFONT g_fontTitle = nullptr;
HFONT g_fontMono = nullptr;
HBRUSH g_brBg = nullptr;
HBRUSH g_brEdit = nullptr;
HBITMAP g_logo = nullptr;
int g_logo_w = 22;
int g_logo_h = 22;
std::vector<ScriptTab> g_docs;
std::vector<FileItem> g_files;
std::vector<Hit> g_hits;
std::wstring g_status = L"Idle";
std::wstring g_toast;
DWORD g_toast_until = 0;
std::string g_pending_exec;
int g_cur = 0;
int g_tab_serial = 1;
int g_hover = H_NONE;
DWORD g_hover_tick = 0;
bool g_tip_on = false;
POINT g_mouse{};
NOTIFYICONDATAW g_nid{};
bool g_visible = true;
WNDPROC g_edit_prev = nullptr;

HBITMAP load_png_resource(int id, int w, int h) {
    HMODULE self = GetModuleHandleW(nullptr);
    HRSRC rc = FindResourceW(self, MAKEINTRESOURCEW(id), RT_RCDATA);
    if (!rc)
        return nullptr;
    HGLOBAL mem = LoadResource(self, rc);
    if (!mem)
        return nullptr;
    const DWORD n = SizeofResource(self, rc);
    void* p = LockResource(mem);
    if (!p || !n)
        return nullptr;

    IWICImagingFactory* fac = nullptr;
    if (FAILED(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                                IID_PPV_ARGS(&fac))))
        return nullptr;

    IWICStream* stream = nullptr;
    IWICBitmapDecoder* dec = nullptr;
    IWICBitmapFrameDecode* frame = nullptr;
    IWICFormatConverter* conv = nullptr;
    IWICBitmapScaler* scaler = nullptr;
    HBITMAP bmp = nullptr;

    if (SUCCEEDED(fac->CreateStream(&stream)) &&
        SUCCEEDED(stream->InitializeFromMemory(static_cast<BYTE*>(p), n)) &&
        SUCCEEDED(fac->CreateDecoderFromStream(stream, nullptr, WICDecodeMetadataCacheOnLoad, &dec)) &&
        SUCCEEDED(dec->GetFrame(0, &frame)) &&
        SUCCEEDED(fac->CreateFormatConverter(&conv)) &&
        SUCCEEDED(conv->Initialize(frame, GUID_WICPixelFormat32bppPBGRA,
                                   WICBitmapDitherTypeNone, nullptr, 0.0,
                                   WICBitmapPaletteTypeCustom)) &&
        SUCCEEDED(fac->CreateBitmapScaler(&scaler)) &&
        SUCCEEDED(scaler->Initialize(conv, (UINT)w, (UINT)h, WICBitmapInterpolationModeFant))) {
        BITMAPINFO bi{};
        bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bi.bmiHeader.biWidth = w;
        bi.bmiHeader.biHeight = -h;
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 32;
        bi.bmiHeader.biCompression = BI_RGB;
        void* bits = nullptr;
        HDC screen = GetDC(nullptr);
        bmp = CreateDIBSection(screen, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
        ReleaseDC(nullptr, screen);
        if (bmp && bits)
            scaler->CopyPixels(nullptr, (UINT)(w * 4), (UINT)(w * h * 4), static_cast<BYTE*>(bits));
    }

    if (scaler) scaler->Release();
    if (conv) conv->Release();
    if (frame) frame->Release();
    if (dec) dec->Release();
    if (stream) stream->Release();
    fac->Release();
    return bmp;
}

void blit_logo(HDC dc, int x, int y) {
    if (!g_logo)
        return;
    HDC mem = CreateCompatibleDC(dc);
    auto old = SelectObject(mem, g_logo);
    BLENDFUNCTION bf{AC_SRC_OVER, 0, 255, AC_SRC_ALPHA};
    AlphaBlend(dc, x, y, g_logo_w, g_logo_h, mem, 0, 0, g_logo_w, g_logo_h, bf);
    SelectObject(mem, old);
    DeleteDC(mem);
}

void apply_capture(HWND wnd) {
    if (!wnd)
        return;
    SetWindowDisplayAffinity(wnd, g_stream_proof ? 0x00000011u : 0u);
}

void apply_stealth_window(HWND wnd) {
    apply_capture(wnd);
}

void apply_capture_all() {
    apply_capture(g_wnd);
    apply_capture(g_log_wnd);
}

void show_ui() {
    if (!g_wnd)
        return;
    LONG_PTR ex = GetWindowLongPtrW(g_wnd, GWL_EXSTYLE);
    ex &= ~WS_EX_TOOLWINDOW;
    ex |= WS_EX_APPWINDOW;
    SetWindowLongPtrW(g_wnd, GWL_EXSTYLE, ex);
    ShowWindow(g_wnd, SW_SHOW);
    SetForegroundWindow(g_wnd);
    g_visible = true;
    if (g_show_log && g_log_wnd)
        ShowWindow(g_log_wnd, SW_SHOWNOACTIVATE);
}

void hide_ui() {
    if (!g_wnd)
        return;
    ShowWindow(g_wnd, SW_HIDE);
    LONG_PTR ex = GetWindowLongPtrW(g_wnd, GWL_EXSTYLE);
    ex |= WS_EX_TOOLWINDOW;
    ex &= ~WS_EX_APPWINDOW;
    SetWindowLongPtrW(g_wnd, GWL_EXSTYLE, ex);
    g_visible = false;
    if (g_log_wnd)
        ShowWindow(g_log_wnd, SW_HIDE);
}

void tray_add(HWND wnd) {
    g_nid = {};
    g_nid.cbSize = sizeof(g_nid);
    g_nid.hWnd = wnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAY;
    g_nid.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wcsncpy_s(g_nid.szTip, L"Runtime", _TRUNCATE);
    Shell_NotifyIconW(NIM_ADD, &g_nid);
}

void tray_del() {
    if (g_nid.hWnd)
        Shell_NotifyIconW(NIM_DELETE, &g_nid);
    g_nid = {};
}

void request_exit() {
    if (!g_wnd)
        return;
    HWND wnd = g_wnd;
    HWND log = g_log_wnd;
    g_wnd = nullptr;
    g_log_wnd = nullptr;
    g_rpm.detach();
    tray_del();
    g_pipe.stop();
    if (log)
        DestroyWindow(log);
    DestroyWindow(wnd);
}

std::filesystem::path tabs_dir() { return app_dir(L"tabs"); }
std::filesystem::path saved_dir() { return app_dir(L"scripts") / L"saved"; }

void invalidate() {
    if (g_wnd)
        InvalidateRect(g_wnd, nullptr, FALSE);
}

void toast(const std::wstring& s, DWORD ms = 2400) {
    g_toast = s;
    g_toast_until = GetTickCount() + ms;
    invalidate();
}

void notify(const wchar_t* title, const std::wstring& body, DWORD ms = 4500) {
    toast(body, ms);
    if (!g_nid.hWnd)
        return;
    NOTIFYICONDATAW n = g_nid;
    n.cbSize = sizeof(n);
    n.uFlags = NIF_INFO | NIF_MESSAGE | NIF_ICON | NIF_TIP;
    n.dwInfoFlags = NIIF_INFO;
    n.uTimeout = ms;
    wcsncpy_s(n.szInfoTitle, title, _TRUNCATE);
    wcsncpy_s(n.szInfo, body.c_str(), _TRUNCATE);
    Shell_NotifyIconW(NIM_MODIFY, &n);
    MessageBeep(MB_OK);
}

RECT RR(int x, int y, int w, int h);
void fill_rect(HDC dc, RECT rc, COLORREF c);
void fill_round(HDC dc, RECT rc, COLORREF c, int rad);
void frame_rect(HDC dc, RECT rc, COLORREF c, int w);
void text_at(HDC dc, RECT rc, const wchar_t* s, COLORREF c, HFONT f, UINT fmt);
void line(HDC dc, int x1, int y1, int x2, int y2, COLORREF c, int w = 1);
void draw_win_close(HDC dc, RECT r, COLORREF c);
void draw_win_min(HDC dc, RECT r, COLORREF c);
void blit_logo(HDC dc, int x, int y);

void layout_edits(HWND wnd);
void show_tab(int i);
void new_tab(const std::wstring& name, const std::wstring& text, const std::wstring& path = {});

void layout_log_edit() {
    if (!g_log_wnd || !g_log_edit)
        return;
    RECT rc{};
    GetClientRect(g_log_wnd, &rc);
    const int x = 8, y = kTitleH + 4;
    const int w = rc.right - 16;
    const int h = rc.bottom - kTitleH - kBarH - 8;
    if (w > 8 && h > 8)
        MoveWindow(g_log_edit, x, y, w, h, TRUE);
}

LRESULT CALLBACK log_edit_proc(HWND h, UINT msg, WPARAM w, LPARAM l) {
    if (msg == WM_KEYDOWN && w == 'A' && (GetKeyState(VK_CONTROL) & 0x8000)) {
        SendMessageW(h, EM_SETSEL, 0, -1);
        return 0;
    }
    return CallWindowProcW(g_log_edit_prev, h, msg, w, l);
}

void log_set_text(const std::wstring& all) {
    if (!g_log_edit)
        return;
    SetWindowTextW(g_log_edit, all.c_str());
    const int len = GetWindowTextLengthW(g_log_edit);
    SendMessageW(g_log_edit, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessageW(g_log_edit, EM_SCROLLCARET, 0, 0);
}

void log_wake() {
    g_log_wake.store(0, std::memory_order_relaxed);
    if (!g_log_edit)
        return;

    std::wstring add;
    std::wstring rebuild;
    bool full = false;
    {
        std::lock_guard lock(g_log_mtx);
        if (g_log_lines.size() > 2200) {
            g_log_lines.erase(g_log_lines.begin(), g_log_lines.begin() + 400);
            g_log_shown = 0;
        }
        if (g_log_shown > (int)g_log_lines.size())
            g_log_shown = 0;
        if (g_log_shown == 0) {
            full = true;
            rebuild.reserve(g_log_lines.size() * 40);
            for (const auto& row : g_log_lines) {
                rebuild += row.second;
                rebuild += L"\r\n";
            }
            g_log_shown = (int)g_log_lines.size();
        } else {
            add.reserve(((int)g_log_lines.size() - g_log_shown) * 40);
            for (int i = g_log_shown; i < (int)g_log_lines.size(); ++i) {
                add += g_log_lines[i].second;
                add += L"\r\n";
            }
            g_log_shown = (int)g_log_lines.size();
        }
    }

    if (full) {
        log_set_text(rebuild);
        return;
    }
    if (add.empty())
        return;

    DWORD sel0 = 0, sel1 = 0;
    SendMessageW(g_log_edit, EM_GETSEL, (WPARAM)&sel0, (LPARAM)&sel1);
    const int len = GetWindowTextLengthW(g_log_edit);
    const bool selecting = sel0 != sel1;
    const int lines = (int)SendMessageW(g_log_edit, EM_GETLINECOUNT, 0, 0);
    const int first = (int)SendMessageW(g_log_edit, EM_GETFIRSTVISIBLELINE, 0, 0);
    RECT rc{};
    GetClientRect(g_log_edit, &rc);
    const int vis = rc.bottom > 16 ? rc.bottom / 16 : 1;
    const bool at_end = first + vis >= lines - 2;

    SendMessageW(g_log_edit, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessageW(g_log_edit, EM_REPLACESEL, FALSE, (LPARAM)add.c_str());
    if (selecting)
        SendMessageW(g_log_edit, EM_SETSEL, sel0, sel1);
    else if (at_end) {
        const int nlen = GetWindowTextLengthW(g_log_edit);
        SendMessageW(g_log_edit, EM_SETSEL, (WPARAM)nlen, (LPARAM)nlen);
        SendMessageW(g_log_edit, EM_SCROLLCARET, 0, 0);
    }
}

void log_sink(const LogLine& l) {
    const wchar_t* tag = L"  ";
    if (l.level == LogLevel::Warn) tag = L"! ";
    if (l.level == LogLevel::Error) tag = L"x ";
    {
        std::lock_guard lock(g_log_mtx);
        if (g_log_lines.size() < 4000)
            g_log_lines.push_back({l.level, std::wstring(tag) + l.text});
    }
    if (g_log_wnd && g_log_wake.exchange(1, std::memory_order_acq_rel) == 0)
        PostMessageW(g_log_wnd, WM_LOG_WAKE, 0, 0);
}

void seed_log_from_history() {
    std::lock_guard lock(g_log_mtx);
    if (!g_log_lines.empty())
        return;
    for (const auto& line : Logger::instance().snapshot()) {
        const wchar_t* tag = L"  ";
        if (line.level == LogLevel::Warn) tag = L"! ";
        if (line.level == LogLevel::Error) tag = L"x ";
        g_log_lines.push_back({line.level, std::wstring(tag) + line.text});
    }
}

void hide_log_window() {
    g_show_log = false;
    if (g_log_wnd)
        ShowWindow(g_log_wnd, SW_HIDE);
}

LRESULT CALLBACK log_wndproc(HWND wnd, UINT msg, WPARAM wp, LPARAM lp);

void place_log_window() {
    if (!g_log_wnd || !g_wnd)
        return;
    RECT wr{}, va{};
    GetWindowRect(g_wnd, &wr);
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &va, 0);
    const int h = wr.bottom - wr.top;
    const int w = 560;
    int x = wr.right + 12;
    int y = wr.top;
    if (x + w > va.right)
        x = wr.left - w - 12;
    if (x < va.left) {
        x = (std::max)(va.left + 8, wr.left);
        y = wr.bottom + 8;
        if (y + 360 > va.bottom)
            y = va.top + 48;
    }
    SetWindowPos(g_log_wnd, nullptr, x, y, w, h, SWP_NOACTIVATE | SWP_NOZORDER);
}

void ensure_log_window() {
    if (g_log_wnd)
        return;
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = log_wndproc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = g_brBg ? g_brBg : (HBRUSH)GetStockObject(BLACK_BRUSH);
    wc.lpszClassName = kLogClass;
    wc.style = CS_DBLCLKS;
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    RegisterClassExW(&wc);

    g_log_wnd = CreateWindowExW(
        WS_EX_APPWINDOW,
        kLogClass, L"Runtime Broker",
        WS_POPUP | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX,
        100, 100, 560, 580,
        nullptr, nullptr, wc.hInstance, nullptr);
    if (!g_log_wnd)
        return;
    apply_stealth_window(g_log_wnd);
    BOOL dark = TRUE;
    DwmSetWindowAttribute(g_log_wnd, 20, &dark, sizeof(dark));
    COLORREF cap = RGB(6, 10, 22);
    DwmSetWindowAttribute(g_log_wnd, 35, &cap, sizeof(cap));
    COLORREF brd = RGB(22, 80, 200);
    DwmSetWindowAttribute(g_log_wnd, 34, &brd, sizeof(brd));
    int corner = DWMWCP_ROUND;
    DwmSetWindowAttribute(g_log_wnd, DWMWA_WINDOW_CORNER_PREFERENCE, &corner, sizeof(corner));
    if (!g_brLog)
        g_brLog = CreateSolidBrush(RGB(3, 6, 14));
    g_log_edit = CreateWindowExW(
        0, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL |
        ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | ES_NOHIDESEL | ES_LEFT,
        8, kTitleH + 4, 200, 200,
        g_log_wnd, (HMENU)(INT_PTR)90, GetModuleHandleW(nullptr), nullptr);
    if (g_log_edit) {
        SendMessageW(g_log_edit, WM_SETFONT, (WPARAM)g_fontMono, TRUE);
        SendMessageW(g_log_edit, EM_LIMITTEXT, 0x7FFFFFFE, 0);
        SetWindowTheme(g_log_edit, L"", L"");
        g_log_edit_prev = (WNDPROC)SetWindowLongPtrW(g_log_edit, GWLP_WNDPROC, (LONG_PTR)log_edit_proc);
    }
    seed_log_from_history();
    g_log_shown = 0;
    layout_log_edit();
}

void show_log_window() {
    g_show_log = true;
    ensure_log_window();
    if (!g_log_wnd)
        return;
    place_log_window();
    ShowWindow(g_log_wnd, SW_SHOW);
    log_wake();
}

LRESULT CALLBACK log_wndproc(HWND wnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_LOG_WAKE:
        log_wake();
        return 0;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC odc = BeginPaint(wnd, &ps);
        RECT cr{};
        GetClientRect(wnd, &cr);
        const int W = cr.right, H = cr.bottom;
        HDC dc = CreateCompatibleDC(odc);
        HBITMAP bmp = CreateCompatibleBitmap(odc, (std::max)(W, 1), (std::max)(H, 1));
        auto oldb = SelectObject(dc, bmp);

        fill_rect(dc, cr, kBg);
        {
            TRIVERTEX tv[2]{};
            tv[0].x = 0; tv[0].y = 0;
            tv[0].Red = 0x1800; tv[0].Green = 0x1000; tv[0].Blue = 0x3000; tv[0].Alpha = 0xFF00;
            tv[1].x = W; tv[1].y = kTitleH;
            tv[1].Red = 0x0700; tv[1].Green = 0x0500; tv[1].Blue = 0x0E00; tv[1].Alpha = 0xFF00;
            GRADIENT_RECT gr{0, 1};
            GradientFill(dc, tv, 2, &gr, 1, GRADIENT_FILL_RECT_V);
        }
        frame_rect(dc, cr, kGlow, 2);
        frame_rect(dc, {1, 1, W - 1, H - 1}, kBlue, 1);
        blit_logo(dc, 12, (kTitleH - g_logo_h) / 2);
        text_at(dc, RR(12 + g_logo_w + 8, 0, 140, kTitleH), L"VoidTrace", kText, g_fontTitle,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        text_at(dc, RR(12 + g_logo_w + 100, 0, 160, kTitleH), L"Output", kMuted, g_fontSm,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        RECT minr = RR(W - 70, 4, 30, 26);
        RECT xr = RR(W - 38, 4, 30, 26);
        if (g_log_hover == 1)
            fill_round(dc, minr, kHover, 6);
        if (g_log_hover == 2)
            fill_round(dc, xr, RGB(140, 28, 36), 6);
        draw_win_min(dc, minr, kText);
        draw_win_close(dc, xr, kText);

        line(dc, 1, kTitleH, W - 1, kTitleH, kLine);

        fill_rect(dc, RR(2, H - kBarH, W - 4, kBarH - 2), kBar);
        line(dc, 2, H - kBarH, W - 2, H - kBarH, kLine);
        int total = 0;
        {
            std::lock_guard lock(g_log_mtx);
            total = (int)g_log_lines.size();
        }
        wchar_t foot[80];
        swprintf_s(foot, L"%d lines  ·  select text  ·  Ctrl+C / Ctrl+A", total);
        text_at(dc, RR(12, H - kBarH, W - 90, kBarH), foot, kMuted, g_fontSm,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        RECT clr = RR(W - 78, H - kBarH + 10, 64, 26);
        fill_round(dc, clr, g_log_hover == 3 ? kHover : kChip, 6);
        text_at(dc, clr, L"Clear", kText, g_fontSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

        BitBlt(odc, 0, 0, W, H, dc, 0, 0, SRCCOPY);
        SelectObject(dc, oldb);
        DeleteObject(bmp);
        DeleteDC(dc);
        EndPaint(wnd, &ps);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_SIZE:
        layout_log_edit();
        InvalidateRect(wnd, nullptr, FALSE);
        return 0;
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
        SetTextColor((HDC)wp, RGB(220, 210, 255));
        SetBkColor((HDC)wp, RGB(4, 2, 10));
        return (LRESULT)(g_brLog ? g_brLog : g_brEdit);
    case WM_LBUTTONUP: {
        const int x = GET_X_LPARAM(lp);
        const int y = GET_Y_LPARAM(lp);
        RECT rc{};
        GetClientRect(wnd, &rc);
        if (y < kTitleH && x >= rc.right - 38) {
            hide_log_window();
            return 0;
        }
        if (y < kTitleH && x >= rc.right - 70 && x < rc.right - 38) {
            ShowWindow(wnd, SW_MINIMIZE);
            return 0;
        }
        if (y >= rc.bottom - kBarH && x >= rc.right - 78) {
            {
                std::lock_guard lock(g_log_mtx);
                g_log_lines.clear();
            }
            g_log_shown = 0;
            if (g_log_edit)
                SetWindowTextW(g_log_edit, L"");
            InvalidateRect(wnd, nullptr, FALSE);
            return 0;
        }
        return 0;
    }
    case WM_MOUSEMOVE: {
        RECT rc{};
        GetClientRect(wnd, &rc);
        const int x = GET_X_LPARAM(lp);
        const int y = GET_Y_LPARAM(lp);
        int hov = 0;
        if (y < kTitleH && x >= rc.right - 38)
            hov = 2;
        else if (y < kTitleH && x >= rc.right - 70)
            hov = 1;
        else if (y >= rc.bottom - kBarH && x >= rc.right - 78)
            hov = 3;
        if (hov != g_log_hover) {
            g_log_hover = hov;
            InvalidateRect(wnd, nullptr, FALSE);
        }
        TRACKMOUSEEVENT tme{sizeof(tme), TME_LEAVE, wnd, 0};
        TrackMouseEvent(&tme);
        return 0;
    }
    case WM_MOUSELEAVE:
        if (g_log_hover) {
            g_log_hover = 0;
            InvalidateRect(wnd, nullptr, FALSE);
        }
        return 0;
    case WM_NCHITTEST: {
        POINT sp{GET_X_LPARAM(lp), GET_Y_LPARAM(lp)};
        RECT wr{};
        GetWindowRect(wnd, &wr);
        const bool left = sp.x < wr.left + kEdge;
        const bool right = sp.x >= wr.right - kEdge;
        const bool top = sp.y < wr.top + kEdge;
        const bool bottom = sp.y >= wr.bottom - kEdge;
        if (top && left) return HTTOPLEFT;
        if (top && right) return HTTOPRIGHT;
        if (bottom && left) return HTBOTTOMLEFT;
        if (bottom && right) return HTBOTTOMRIGHT;
        if (left) return HTLEFT;
        if (right) return HTRIGHT;
        if (top) return HTTOP;
        if (bottom) return HTBOTTOM;
        POINT p = sp;
        ScreenToClient(wnd, &p);
        RECT rc{};
        GetClientRect(wnd, &rc);
        if (p.y < kTitleH && p.x < rc.right - 70)
            return HTCAPTION;
        return HTCLIENT;
    }
    case WM_CLOSE:
        hide_log_window();
        return 0;
    case WM_DESTROY:
        g_log_edit = nullptr;
        g_log_edit_prev = nullptr;
        if (g_log_wnd == wnd)
            g_log_wnd = nullptr;
        return 0;
    }
    return DefWindowProcW(wnd, msg, wp, lp);
}


void set_status(const std::wstring& s) {
    g_status = s;
    invalidate();
}

void set_progress(int pct, const wchar_t* note) {
    if (pct < 0) pct = 0;
    if (pct > 100) pct = 100;
    if (g_wnd && g_ui_tid && GetCurrentThreadId() != g_ui_tid) {
        auto* s = new std::wstring(note ? note : L"");
        PostMessageW(g_wnd, WM_PROG, (WPARAM)pct, (LPARAM)s);
        return;
    }
    g_pipe_pct = pct;
    g_pipe_note = note ? note : L"";
    wchar_t buf[192];
    swprintf_s(buf, L"%d%%  %s", pct, note ? note : L"");
    g_status = buf;
    invalidate();
}

void fail_progress(const wchar_t* why) {
    wchar_t buf[256];
    swprintf_s(buf, L"Stopped at %d%% — %s", g_pipe_pct, why ? why : L"unknown");
    VT_WARN(buf);
    g_status = buf;
    notify(L"Runtime", buf, 7000);
    invalidate();
}

std::wstring editor_text() {
    const int n = GetWindowTextLengthW(g_editor);
    std::wstring s(n, 0);
    GetWindowTextW(g_editor, s.data(), n + 1);
    return s;
}

void set_editor(const std::wstring& s) {
    SetWindowTextW(g_editor, s.c_str());
}

void layout_edits(HWND wnd);
void run_autoexec();

static void do_deferred_init() {
    g_init_step = 0; enable_debug_privilege();
    g_init_step = 1; Syscalls::get().init();
    g_init_step = 2; Byovd::get().init();
    g_init_step = 3; CallSpoof::get().init();
    g_init_step = 4; scan_cfg_gadget();
    g_init_step = 5; Payload::seed();
    g_init_step = 6; Config::instance().load(data_root() / L"config" / L"offsets.json");
    auto& cfg = Config::instance().get();
    cfg.auto_attach = false;
    g_auto_attach = false;
    g_auto_inject = cfg.auto_inject;
    g_show_log = false;
    g_stream_proof = false;
    apply_capture_all();
    Config::instance().save(data_root() / L"config" / L"offsets.json");
    g_init_step = -1;
    g_init_done  = true;
}

void restore_peek_iat() {
    if (g_iat_restored || !g_iat_slot || !g_iat_orig || !g_rbx)
        return;
    HANDLE p = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                           FALSE, g_rbx->pid);
    if (!p)
        return;
    DWORD old = 0;
    const bool prot = SC_VirtualProtectEx(p, (void*)g_iat_slot, 8, PAGE_READWRITE, &old);
    SIZE_T wr = 0;
    const bool ok = SC_WriteProcessMemory(p, (void*)g_iat_slot, &g_iat_orig, 8, &wr) && wr == 8;
    if (prot) {
        DWORD dummy = 0;
        SC_VirtualProtectEx(p, (void*)g_iat_slot, 8, old, &dummy);
    }
    CloseHandle(p);
    if (ok) {
        g_iat_restored = true;
        VT_LOG(L"PeekMessage IAT restored orig=" + format_hex(g_iat_orig));
    } else
        VT_WARN(L"PeekMessage IAT restore failed");
}

void rearm_peek_iat() {
    if (!g_iat_slot || !g_iat_stub || !g_rbx)
        return;
    HANDLE p = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                           FALSE, g_rbx->pid);
    if (!p)
        return;
    uintptr_t cur = 0;
    SC_ReadProcessMemory(p, (void*)g_iat_slot, &cur, 8, nullptr);
    if (cur != g_iat_stub) {
        DWORD old = 0;
        if (SC_VirtualProtectEx(p, (void*)g_iat_slot, 8, PAGE_READWRITE, &old)) {
            SIZE_T wr = 0;
            SC_WriteProcessMemory(p, (void*)g_iat_slot, &g_iat_stub, 8, &wr);
            DWORD dummy = 0;
            SC_VirtualProtectEx(p, (void*)g_iat_slot, 8, old, &dummy);
            g_iat_restored = false;
            VT_LOG(L"IAT rearmed PeekMessage stub (was " + format_hex(cur) + L")");
        }
    }
    CloseHandle(p);
}

void send_job_hint() {
    if (!g_pipe.connected() || !g_injected || !g_rbx)
        return;
    // Once the module is READY the DLL has everything it needs. Continuing
    // to RPM-scan Roblox for job/state addresses just adds a constant stream
    // of external memory reads that Hyperion can pattern-detect.
    if (g_mod_ready)
        return;
    if (g_ui_tid && GetCurrentThreadId() == g_ui_tid) {
        static std::atomic<bool> busy{false};
        if (busy.exchange(true))
            return;
        std::thread([] {
            send_job_hint();
            busy = false;
        }).detach();
        return;
    }
    if (!g_rpm.ok())
        g_rpm.attach(g_rbx->pid, g_rbx->base, g_rbx->size);
    const uintptr_t job = g_rpm.find_script_job();
    if (!job)
        return;
    // DLL finds Lua TID internally via CaptureStackBackTrace — never enumerate threads
    // from the exe (CreateToolhelp32Snapshot from outside is detectable by Hyperion).
    constexpr DWORD lua_tid = 0;
    const uintptr_t L = g_rpm.find_lua_state(job);
    static uintptr_t last = 0;
    static uintptr_t last_L = 0;
    static DWORD sent = 0;
    const DWORD now = GetTickCount();
    const bool first = (last != job);
    const bool new_L = (L && L != last_L);
    if (!first && !new_L && now - sent < 800)
        return;
    last = job;
    if (L)
        last_L = L;
    sent = now;
    char pay[96]{};
    sprintf_s(pay, "0x%llX %u 0x%llX",
              (unsigned long long)job, 0u, (unsigned long long)L);
    g_pipe.send({MsgType::JobHint, pay});
    if (first || new_L)
        VT_LOG(L"job hint -> " + format_hex(job) +
               (L ? (L" L " + format_hex(L)) : L" (no L yet)"));
    if (first) {
        g_job_saved = job;
        g_job_vptr_orig = 0;
        HANDLE hp = OpenProcess(PROCESS_VM_READ, FALSE, g_rbx->pid);
        if (hp) {
            ReadProcessMemory(hp, (void*)job, &g_job_vptr_orig, 8, nullptr);
            CloseHandle(hp);
        }
        g_job_hint_tick = now;
        g_job_vptr_restored = false;
        if (g_job_vptr_orig)
            VT_LOG(L"saved job vptr " + format_hex(g_job_vptr_orig));
        // KERNEL32 NtWait IAT patches but never fires (forwarder). Restoring
        // PeekMessage dropped the pipe so Execute never reached the module.
        VT_LOG(L"PeekMessage kept — pipe only");
    }
    if (g_pipe_pct < 82)
        set_progress(82, L"script job found");
}

std::string http_get_body(const std::string& url8) {
    if (url8.size() < 8)
        return {};
    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256]{}, path[4096]{};
    uc.lpszHostName = host;
    uc.dwHostNameLength = 256;
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = 4096;
    const std::wstring url = utf8_to_wide(url8);
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &uc))
        return {};
    HINTERNET ses = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ses)
        return {};
    HINTERNET con = WinHttpConnect(ses, host, uc.nPort, 0);
    if (!con) {
        WinHttpCloseHandle(ses);
        return {};
    }
    const DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET req = WinHttpOpenRequest(con, L"GET", path, nullptr, WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!req) {
        WinHttpCloseHandle(con);
        WinHttpCloseHandle(ses);
        return {};
    }
    std::string out;
    if (WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, nullptr, 0, 0, 0) &&
        WinHttpReceiveResponse(req, nullptr)) {
        for (;;) {
            DWORD avail = 0, got = 0;
            if (!WinHttpQueryDataAvailable(req, &avail) || !avail)
                break;
            const size_t at = out.size();
            out.resize(at + avail);
            if (!WinHttpReadData(req, out.data() + at, avail, &got) || !got) {
                out.resize(at);
                break;
            }
            out.resize(at + got);
        }
    }
    WinHttpCloseHandle(req);
    WinHttpCloseHandle(con);
    WinHttpCloseHandle(ses);
    return out;
}

std::string expand_loadstring_http(std::string s) {
    for (int n = 0; n < 8; ++n) {
        const size_t p = s.find("loadstring(");
        if (p == std::string::npos)
            break;
        size_t hg = s.find("HttpGet", p);
        const size_t hg2 = s.find("httpget", p);
        if (hg == std::string::npos || (hg2 != std::string::npos && hg2 < hg))
            hg = hg2;
        if (hg == std::string::npos || hg > p + 96)
            break;
        const size_t q = s.find_first_of("\"'", hg);
        if (q == std::string::npos || q > hg + 48)
            break;
        const char quote = s[q];
        const size_t q2 = s.find(quote, q + 1);
        if (q2 == std::string::npos)
            break;
        const std::string url = s.substr(q + 1, q2 - q - 1);
        size_t end = s.find(")()", q2);
        size_t nch = 3;
        if (end == std::string::npos || end > q2 + 24) {
            end = s.find(')', q2);
            nch = 1;
        }
        if (end == std::string::npos)
            break;
        VT_LOG(L"host HttpGet " + utf8_to_wide(url.substr(0, 80)));
        std::string body = http_get_body(url);
        if (body.empty()) {
            VT_WARN(L"host HttpGet empty — " + utf8_to_wide(url.substr(0, 80)));
            break;
        }
        s.replace(p, end + nch - p, "\n(function()\n" + body + "\nend)()\n");
    }
    return s;
}

void start_ext_esp() {
    if (!g_rbx)
        return;
    auto& ov = ext::Overlay::instance();
    ov.set_host(g_wnd);
    ov.set_esp(true);
    if (!ov.start(g_rbx->pid, g_rbx->base, g_rbx->size, g_rbx->hwnd)) {
        VT_WARN(L"overlay start failed");
        notify(L"Runtime", L"Overlay failed — join a match, run as Admin");
        return;
    }
    const auto st = ov.stats();
    VT_LOG(L"overlay ESP on  " + std::wstring(st.note));
    notify(L"Runtime", L"ESP on the game window — not in F9. Lua hubs cannot run in-game.");
}

void try_corescript(const std::string& src, const std::wstring& nm) {
    // Preferred path: DLL is inside Roblox and pipe is up — ship the raw source
    // to the module. The DLL (Execution::run_now) compiles it to Luau bytecode
    // and runs it through luau_load + lua_pcall on the safe scheduler thread.
    if (g_pipe.connected() && g_mod_ready && !src.empty()) {
        g_pipe.send({MsgType::Execute, src});
        VT_LOG(L"Execute " + nm + L" → DLL (" +
               std::to_wstring(src.size()) + L" bytes)");
        return;
    }
    // Fallback: no DLL, no pipe — the exe has no way to reach the Luau VM.
    // Bring up the external overlay so at least ESP works, and tell the user
    // exactly why their script did not run.
    start_ext_esp();
    VT_LOG(L"Execute " + nm +
           L" → overlay only (DLL not injected — scripts cannot execute; "
           L"Rayfield / Drawing / hookmetamethod need in-process Luau)");
    notify(L"Runtime",
           L"Script cannot run — module is not inside Roblox. Overlay ESP is active.",
           4500);
}

void flush_pending_exec() {
    if (g_pending_exec.empty())
        return;
    const std::string src = std::move(g_pending_exec);
    g_pending_exec.clear();
    try_corescript(src, L"queued");
}

void on_pipe(const Message& m) {
    switch (m.type) {
    case MsgType::Log: {
        std::string p = m.payload;
        LogLevel lv = LogLevel::Info;
        if (!p.empty() && p[0] == 'W') lv = LogLevel::Warn;
        if (!p.empty() && p[0] == 'E') lv = LogLevel::Error;
        std::wstring w = utf8_to_wide(p.size() >= 2 && p[1] == '|' ? p.substr(2) : p);
        Logger::instance().write(lv, w);
        break;
    }
    case MsgType::Status:
        set_status(utf8_to_wide(m.payload));
        if (m.payload == "injected") {
            set_progress(60, L"module in — binding Lua");
            notify(L"Runtime", L"Module connected");
            if (g_wnd)
                PostMessageW(g_wnd, WM_JOB_HINT, 0, 0);
        }
        if (m.payload.find("scanning") != std::string::npos)
            set_progress(68, L"Lua API bind");
        if (m.payload.find("waiting_state") != std::string::npos)
            set_progress(75, L"waiting script job");
        if (m.payload == "arming")
            set_progress(85, L"arming pump");
        if (m.payload == "hooking")
            set_progress(92, L"pump live — almost READY");
        if (m.payload == "ready") {
            g_mod_ready = true;
            set_progress(100, L"READY");
            notify(L"Runtime", L"Attached  ·  READY");
            if (!g_autoexec_done) {
                g_autoexec_done = true;
                run_autoexec();
            }
            flush_pending_exec();
        }
        break;
    case MsgType::Ready:
        g_mod_ready = true;
        set_progress(100, L"READY");
        notify(L"Runtime", L"Attached  ·  READY");
        if (!g_autoexec_done) {
            g_autoexec_done = true;
            run_autoexec();
        }
        flush_pending_exec();
        break;
    case MsgType::ExecuteOk:
        notify(L"Runtime", L"Executed");
        break;
    case MsgType::ExecuteErr:
        VT_ERR(utf8_to_wide(m.payload));
        notify(L"Runtime", utf8_to_wide(m.payload), 5000);
        break;
    case MsgType::OffsetReport: {
        // DLL resolved lua_pcall/luau_load in-process. Update config for reference only.
        // Do NOT trigger find_lua_tid — the DLL detects the Lua thread itself via
        // CaptureStackBackTrace. Posting WM_JOB_HINT here caused g_rpm.find_lua_tid()
        // to enumerate Roblox's threads from the exe, which Hyperion detects and kills on.
        unsigned long long pcall_va = 0, load_va = 0;
        sscanf_s(m.payload.c_str(), "0x%llX 0x%llX", &pcall_va, &load_va);
        if (g_rbx && (pcall_va || load_va)) {
            auto& o = Config::instance().get().offsets;
            if (pcall_va && pcall_va > g_rbx->base)
                o.lua_pcall = pcall_va - g_rbx->base;
            if (load_va && load_va > g_rbx->base)
                o.luau_load = load_va - g_rbx->base;
            VT_LOG(L"DLL offsets: pcall " + format_hex(o.lua_pcall) +
                   L"  load " + format_hex(o.luau_load));
        }
        break;
    }
    case MsgType::DrawFrame:
        break;
    case MsgType::ExtHookUnpatch: {
        restore_peek_iat();
        if (!g_ext_patch_slot || g_ext_unpatched || !g_rbx) break;
        HANDLE hp = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                                FALSE, g_rbx->pid);
        if (!hp) break;
        DWORD old_p = 0;
        bool ok = false;
        SIZE_T wr = 0;
        if (WriteProcessMemory(hp, (void*)g_ext_patch_slot, &g_ext_patch_orig, 8, &wr) && wr == 8) {
            ok = true;
        } else if (VirtualProtectEx(hp, (void*)g_ext_patch_slot, 8, PAGE_READWRITE, &old_p)) {
            ok = WriteProcessMemory(hp, (void*)g_ext_patch_slot, &g_ext_patch_orig, 8, &wr) && wr == 8;
            DWORD junk = 0;
            VirtualProtectEx(hp, (void*)g_ext_patch_slot, 8, old_p, &junk);
        }
        CloseHandle(hp);
        if (ok) {
            g_ext_unpatched = true;
            VT_LOG(L"ExtHook unpatched (DLL request) — pump ran, scripts active");
        }
        break;
    }
    case MsgType::ExtHookReq: {
        // Format: "module|func1,func2,...|0xSTUB"
        // Externally patch a game IAT slot to point at the DLL's stub. Injected
        // VirtualProtect is denied by Hyperion; VirtualProtectEx from this
        // external process bypasses that (proven for USER32 hook).
        if (!g_rbx) { g_pipe.send({MsgType::ExtHookAck, "0"}); break; }
        // Skip if we already have a working patch (from an earlier request in
        // the same session). Only ONE slot should ever be hooked or the
        // unpatch step can't restore both.
        if (g_ext_patch_slot && !g_ext_unpatched) {
            g_pipe.send({MsgType::ExtHookAck, "0"});
            break;
        }
        auto reply_fail = []() { g_pipe.send({MsgType::ExtHookAck, "0"}); };

        // Parse
        std::string s = m.payload;
        auto p1 = s.find('|');
        auto p2 = s.find('|', p1 == std::string::npos ? 0 : p1 + 1);
        if (p1 == std::string::npos || p2 == std::string::npos) { reply_fail(); break; }
        std::string mod_name = s.substr(0, p1);
        std::string funcs_csv = s.substr(p1 + 1, p2 - p1 - 1);
        uintptr_t stub = (uintptr_t)strtoull(s.c_str() + p2 + 1, nullptr, 0);
        if (!stub) { reply_fail(); break; }
        // Allocator IAT redirects crash Roblox (CFG + recursive HeapAlloc).
        if (_stricmp(mod_name.c_str(), "ucrtbase.dll") == 0 ||
            funcs_csv.find("HeapAlloc") != std::string::npos ||
            funcs_csv.find("RtlAllocateHeap") != std::string::npos ||
            funcs_csv.find("HeapFree") != std::string::npos) {
            reply_fail();
            break;
        }

        // Open Roblox with full memory access
        HANDLE hp = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE |
                                PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
                                FALSE, g_rbx->pid);
        if (!hp) {
            VT_WARN(L"ExtHook: OpenProcess failed err=" + std::to_wstring(GetLastError()));
            reply_fail(); break;
        }
        VT_LOG(L"ExtHook: opened Roblox pid=" + std::to_wstring(g_rbx->pid) +
               L" mod=" + utf8_to_wide(mod_name) + L" stub=" + format_hex(stub));

        // Find target module base+size in Roblox
        HMODULE mods[512]; DWORD mods_needed = 0;
        auto find_mod = [&](const std::string& want, uintptr_t& base, size_t& size) -> bool {
            if (!EnumProcessModules(hp, mods, sizeof(mods), &mods_needed)) return false;
            const int n = (int)(mods_needed / sizeof(HMODULE));
            for (int i = 0; i < n; ++i) {
                wchar_t name[MAX_PATH]{};
                if (!GetModuleBaseNameW(hp, mods[i], name, MAX_PATH)) continue;
                if (_wcsicmp(name, utf8_to_wide(want).c_str()) == 0) {
                    MODULEINFO mi{};
                    if (GetModuleInformation(hp, mods[i], &mi, sizeof(mi))) {
                        base = (uintptr_t)mi.lpBaseOfDll;
                        size = (size_t)mi.SizeOfImage;
                        return true;
                    }
                }
            }
            return false;
        };
        uintptr_t mbase = 0; size_t msize = 0;
        if (!find_mod(mod_name, mbase, msize)) {
            VT_WARN(L"ExtHook: module " + utf8_to_wide(mod_name) + L" not found in Roblox");
            CloseHandle(hp); reply_fail(); break;
        }
        VT_LOG(L"ExtHook: found " + utf8_to_wide(mod_name) + L" @" + format_hex(mbase) +
               L" size " + format_hex(msize));

        // Read PE headers, walk import table, look for any funcs_csv name
        std::vector<char> hdrs(0x1000);
        if (!ReadProcessMemory(hp, (void*)mbase, hdrs.data(), hdrs.size(), nullptr)) {
            CloseHandle(hp); reply_fail(); break;
        }
        auto* dos = (IMAGE_DOS_HEADER*)hdrs.data();
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) { CloseHandle(hp); reply_fail(); break; }
        // Read a bigger range if headers spill past 4K
        if (dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > hdrs.size()) {
            hdrs.resize(dos->e_lfanew + 0x1000);
            ReadProcessMemory(hp, (void*)mbase, hdrs.data(), hdrs.size(), nullptr);
            dos = (IMAGE_DOS_HEADER*)hdrs.data();
        }
        auto* nt = (IMAGE_NT_HEADERS64*)(hdrs.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) { CloseHandle(hp); reply_fail(); break; }
        const auto imp_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!imp_dir.VirtualAddress) { CloseHandle(hp); reply_fail(); break; }

        // Split funcs_csv into set
        std::vector<std::string> wanted;
        {
            size_t start = 0;
            for (size_t i = 0; i <= funcs_csv.size(); ++i) {
                if (i == funcs_csv.size() || funcs_csv[i] == ',') {
                    if (i > start) wanted.push_back(funcs_csv.substr(start, i - start));
                    start = i + 1;
                }
            }
        }
        if (wanted.empty()) { CloseHandle(hp); reply_fail(); break; }

        // Walk import descriptors
        auto rpm_str = [&](uintptr_t addr, size_t max = 64) -> std::string {
            std::string buf(max, '\0');
            SIZE_T got = 0;
            if (!ReadProcessMemory(hp, (void*)addr, buf.data(), max, &got)) return {};
            buf.resize(strnlen(buf.c_str(), got));
            return buf;
        };
        auto rpm_u64 = [&](uintptr_t addr) -> uintptr_t {
            uintptr_t v = 0;
            ReadProcessMemory(hp, (void*)addr, &v, 8, nullptr);
            return v;
        };

        // Load descriptors range
        const uintptr_t desc_va = mbase + imp_dir.VirtualAddress;
        std::vector<IMAGE_IMPORT_DESCRIPTOR> descs;
        {
            IMAGE_IMPORT_DESCRIPTOR d{};
            for (uintptr_t off = 0; ; off += sizeof(d)) {
                SIZE_T got = 0;
                if (!ReadProcessMemory(hp, (void*)(desc_va + off), &d, sizeof(d), &got) ||
                    got != sizeof(d) || d.Name == 0) break;
                descs.push_back(d);
                if (descs.size() > 256) break;
            }
        }

        VT_LOG(L"ExtHook: walked " + std::to_wstring(descs.size()) + L" import descriptors");
        uintptr_t patched_orig = 0;
        int total_names = 0, matched_names = 0, write_attempts = 0;
        for (const auto& d : descs) {
            const uintptr_t ilt_va = mbase + (d.OriginalFirstThunk ? d.OriginalFirstThunk : d.FirstThunk);
            const uintptr_t iat_va = mbase + d.FirstThunk;
            for (int i = 0; i < 4096; ++i) {
                const uintptr_t name_thunk = rpm_u64(ilt_va + (uintptr_t)i * 8);
                if (!name_thunk) break;
                if (name_thunk & (1ULL << 63)) continue;  // ordinal import
                // IMAGE_IMPORT_BY_NAME: WORD hint + name
                const std::string import_name = rpm_str(mbase + name_thunk + 2, 96);
                if (import_name.empty()) continue;
                ++total_names;
                bool match = false;
                for (const auto& w : wanted) if (w == import_name) { match = true; break; }
                if (!match) continue;
                ++matched_names;

                const uintptr_t slot = iat_va + (uintptr_t)i * 8;
                const uintptr_t orig = rpm_u64(slot);
                if (!orig) {
                    VT_WARN(L"ExtHook: " + utf8_to_wide(import_name) + L" slot orig=0, skip");
                    continue;
                }
                ++write_attempts;

                // Try direct WriteProcessMemory first (some slots may already be writable).
                SIZE_T wr = 0;
                bool ok = WriteProcessMemory(hp, (void*)slot, &stub, 8, &wr) && wr == 8;
                if (!ok) {
                    DWORD old_p = 0;
                    if (VirtualProtectEx(hp, (void*)slot, 8, PAGE_READWRITE, &old_p)) {
                        ok = WriteProcessMemory(hp, (void*)slot, &stub, 8, &wr) && wr == 8;
                        DWORD junk = 0;
                        VirtualProtectEx(hp, (void*)slot, 8, old_p, &junk);
                    } else {
                        VT_WARN(L"ExtHook: VirtualProtectEx " + utf8_to_wide(import_name) +
                                L" err=" + std::to_wstring(GetLastError()));
                    }
                }
                if (ok) {
                    patched_orig = orig;
                    // Track for auto-unpatch — timer restores this slot ~5s
                    // later before Hyperion's IAT integrity scan fires.
                    g_ext_patch_slot = slot;
                    g_ext_patch_orig = orig;
                    g_ext_patch_time = GetTickCount();
                    g_ext_unpatched  = false;
                    VT_LOG(L"ExtHook patched " + utf8_to_wide(mod_name) + L"!" +
                           utf8_to_wide(import_name) + L" slot " + format_hex(slot) +
                           L" orig " + format_hex(orig));
                    break;
                } else {
                    VT_WARN(L"ExtHook: WriteProcessMemory " + utf8_to_wide(import_name) +
                            L" err=" + std::to_wstring(GetLastError()));
                }
            }
            if (patched_orig) break;
        }
        CloseHandle(hp);

        char reply[32]{};
        sprintf_s(reply, "0x%llX", (unsigned long long)patched_orig);
        g_pipe.send({MsgType::ExtHookAck, reply});
        VT_LOG(L"ExtHook summary: names=" + std::to_wstring(total_names) +
               L" matched=" + std::to_wstring(matched_names) +
               L" write_attempts=" + std::to_wstring(write_attempts) +
               L" patched=" + std::to_wstring(patched_orig ? 1 : 0));
        if (!patched_orig)
            VT_WARN(L"ExtHook: no writable IAT slot found in " + utf8_to_wide(mod_name));
        break;
    }
    default:
        break;
    }
}

void sync_editor_into_tab() {
    if (g_cur < 0 || g_cur >= (int)g_docs.size() || !g_editor)
        return;
    auto t = editor_text();
    if (t != g_docs[g_cur].text) {
        g_docs[g_cur].text = std::move(t);
        g_docs[g_cur].dirty = true;
    }
}

void show_tab(int i) {
    if (i < 0 || i >= (int)g_docs.size())
        return;
    sync_editor_into_tab();
    g_cur = i;
    set_editor(g_docs[i].text);
    invalidate();
}

void new_tab(const std::wstring& name, const std::wstring& text, const std::wstring& path) {
    sync_editor_into_tab();
    ScriptTab t;
    t.name = name.empty() ? (L"Tab " + std::to_wstring(g_tab_serial++)) : name;
    t.text = text;
    t.path = path;
    t.dirty = path.empty() && !text.empty();
    g_docs.push_back(std::move(t));
    show_tab((int)g_docs.size() - 1);
}

void close_tab() {
    if (g_docs.empty())
        return;
    sync_editor_into_tab();
    if (g_docs[g_cur].dirty) {
        if (MessageBoxW(g_wnd, L"Unsaved changes. Close this tab?", L"Runtime",
                        MB_YESNO | MB_ICONWARNING) != IDYES)
            return;
    }
    g_docs.erase(g_docs.begin() + g_cur);
    if (g_docs.empty()) {
        new_tab(L"Tab 1", L"");
        return;
    }
    if (g_cur >= (int)g_docs.size())
        g_cur = (int)g_docs.size() - 1;
    show_tab(g_cur);
}

void persist_tabs() {
    sync_editor_into_tab();
    const auto dir = tabs_dir();
    std::error_code ec;
    for (auto& e : std::filesystem::directory_iterator(dir, ec))
        if (e.path().extension() == L".lua" || e.path().extension() == L".txt")
            std::filesystem::remove(e.path(), ec);
    std::wstring idx;
    for (int i = 0; i < (int)g_docs.size(); ++i) {
        auto file = dir / (L"tab" + std::to_wstring(i) + L".lua");
        write_file_utf8(file, wide_to_utf8(g_docs[i].text));
        idx += g_docs[i].name + L"|" + file.wstring() + L"\r\n";
        if (!g_docs[i].path.empty())
            write_file_utf8(g_docs[i].path, wide_to_utf8(g_docs[i].text));
        g_docs[i].dirty = false;
    }
    write_file_utf8(dir / L"index.txt", wide_to_utf8(idx));
}

void restore_tabs() {
    const auto idx = tabs_dir() / L"index.txt";
    if (!file_exists(idx)) {
        new_tab(L"Tab 1", L"");
        return;
    }
    const auto raw = read_file_utf8(idx);
    bool any = false;
    size_t pos = 0;
    while (pos < raw.size()) {
        auto nl = raw.find('\n', pos);
        if (nl == std::string::npos)
            nl = raw.size();
        std::string line = raw.substr(pos, nl - pos);
        pos = nl + 1;
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        const auto bar = line.find('|');
        if (bar == std::string::npos)
            continue;
        auto name = utf8_to_wide(line.substr(0, bar));
        auto path = utf8_to_wide(line.substr(bar + 1));
        auto text = utf8_to_wide(read_file_utf8(path));
        if (text.empty() && !file_exists(path))
            continue;
        new_tab(name, text, L"");
        g_docs.back().dirty = false;
        any = true;
    }
    if (!any)
        new_tab(L"Tab 1", L"");
    else
        show_tab(0);
}

void refresh_scripts() {
    g_files.clear();
    const auto root = data_root() / "scripts";
    std::error_code ec;
    for (auto* sub : {L"saved", L"hub", L"autoexec"}) {
        const auto dir = root / sub;
        if (!std::filesystem::exists(dir, ec))
            continue;
        for (auto& e : std::filesystem::directory_iterator(dir, ec)) {
            if (!e.is_regular_file())
                continue;
            auto ext = e.path().extension().wstring();
            if (ext != L".lua" && ext != L".txt")
                continue;
            g_files.push_back({e.path().stem().wstring() + L"  ·  " + sub,
                               e.path().wstring()});
        }
    }
}

std::string rewrite_hub_source(std::string s) {
    auto repl = [&](const char* a, const char* b) {
        const size_t na = std::char_traits<char>::length(a);
        const size_t nb = std::char_traits<char>::length(b);
        size_t p = 0;
        while ((p = s.find(a, p)) != std::string::npos) {
            s.replace(p, na, b);
            p += nb;
        }
    };
    repl("game:HttpGetAsync", "httpget");
    repl("game:HttpGet", "httpget");
    repl("game.HttpGetAsync", "httpget");
    repl("game.HttpGet", "httpget");
    repl("game:GetObjects", "getobjects");
    repl("syn.request", "request");
    repl("fluxus.request", "request");
    repl("http.request", "request");
    repl("syn.crypt", "crypt");
    return s;
}

void run_autoexec() {
    // Corescript host is one LocalScript. Two autoexecs in a row restarted it
    // twice and closed Roblox. F5 one tab at a time.
    VT_LOG(L"autoexec skipped — F5 a single script");
}

bool map_module() {
    if (!g_rbx)
        return false;
    if (g_pipe.connected()) {
        g_injected = true;
        g_mapped_pid = g_rbx->pid;
        set_progress(60, L"pipe up — not READY yet");
        return true;
    }
    if (g_injected && g_mapped_pid == g_rbx->pid) {
        set_status(L"Attaching");
        return true;
    }
    {
        const auto& o = Config::instance().get().offsets;
        if (!o.luau_load || !o.lua_pcall)
            OffsetSync::refresh();
        const auto& o2 = Config::instance().get().offsets;
        if (!o2.luau_load || !o2.lua_pcall)
            VT_WARN(L"luau_load/lua_pcall still 0 — module will auto-scan in-process");
    }
    enable_debug_privilege();
    g_attach_step = 10;
    HANDLE proc = ProcessFinder::open(g_rbx->pid,
        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_SUSPEND_RESUME);
    if (!proc) {
        g_attach_step = -1;
        VT_ERR(L"OpenProcess failed — run as Administrator");
        notify(L"Runtime", L"Run as Administrator");
        return false;
    }
    g_attach_step = 11;
    auto result = Injector::inject_embedded(proc, InjectMethod::ManualMap);
    CloseHandle(proc);
    g_attach_step = -1;
    if (!result.ok) {
        VT_ERR(result.error);
        notify(L"Runtime", L"Inject failed");
        return false;
    }
    g_injected = true;
    g_mapped_pid = g_rbx->pid;
    g_map_tick = GetTickCount();
    g_pipe_warned = false;
    g_mod_ready = false;
    g_iat_slot = result.iat_slot;
    g_iat_stub = result.iat_stub;
    g_iat_orig = result.iat_orig;
    g_iat_restored = false;
    g_wait_hooked = result.wait_hooked;
    if (g_wait_hooked)
        VT_LOG(L"wait-IAT live — PeekMessage will restore after JobHint");
    set_progress(45, L"mapped — waiting pipe");
    VT_LOG(L"mapped " + format_hex(result.module_base));
    VT_LOG(L"DllMain ran — waiting for pipe (PeekMessage tick)");
    notify(L"Runtime", L"Attached — waiting READY");
    return true;
}

void attach_after_sync() {
    const auto& pname = Config::instance().get().process_name;
    g_attach_step = 2;
    g_rbx = ProcessFinder::find(pname);
    if (!g_rbx) {
        g_attach_step = -1;
        g_rpm.detach();
        g_attach_busy = false;
        set_progress(0, L"Idle");
        notify(L"VoidTrace", L"Roblox closed during attach — try again");
        return;
    }
    g_attach_step = 3;
    g_rpm.attach(g_rbx->pid, g_rbx->base, g_rbx->size);
    VT_LOG(L"Found Roblox  pid " + std::to_wstring(g_rbx->pid) +
           (g_rbx->path.empty() ? L"" : (L"  " + g_rbx->path)));
    g_attach_step = 4;
    // Do not map a module. PeekMessage IAT + KERNEL32 wait-IAT closed Roblox.
    // Execute is host-side corescript bytecode (Xeno-style). ManualMap stays compiled.
    g_injected = true;
    g_mapped_pid = g_rbx->pid;
    g_map_tick = 0;
    g_mod_ready = true;
    g_iat_slot = g_iat_stub = g_iat_orig = 0;
    g_iat_restored = true;
    g_wait_hooked = false;
    VT_LOG(L"external attach — no module map");
    set_progress(100, L"READY");
    notify(L"Runtime", L"Attached  ·  READY");
    std::vector<ext::Entity> ents;
    int sw = 0, sh = 0;
    g_rpm.poll(ents, &sw, &sh);
    if (g_rpm.stats().datamodel && g_rpm.stats().players_svc)
        VT_LOG(L"place DataModel live — F5 starts overlay ESP");
    else
        VT_WARN(L"place DataModel not found yet — join a match, then F5");
    start_ext_esp();
    if (!g_autoexec_done) {
        g_autoexec_done = true;
        run_autoexec();
    }
    flush_pending_exec();
    g_attach_step = -1;
    g_attach_busy = false;
    if (g_wnd)
        PostMessageW(g_wnd, WM_ATTACH_CONT, 0, 0);
}

void do_attach() {
    if (!g_init_done) {
        notify(L"VoidTrace", L"Still initialising — wait a moment and try again");
        return;
    }
    if (g_attach_busy.exchange(true)) {
        toast(L"Already attaching");
        return;
    }
    const auto& pname = Config::instance().get().process_name;
    if (!ProcessFinder::find(pname)) {
        g_attach_busy = false;
        set_progress(0, L"Idle");
        notify(L"VoidTrace", L"Roblox not found — open Roblox and join a game first");
        return;
    }
    set_progress(10, L"syncing offsets…");
    std::thread([] {
        OffsetSync::refresh();
        attach_after_sync();
    }).detach();
}

void do_execute() {
    sync_editor_into_tab();
    auto raw = wide_to_utf8(editor_text());
    if (raw.empty()) {
        notify(L"Runtime", L"This tab is empty");
        return;
    }
    const std::wstring nm = (g_cur >= 0 && g_cur < (int)g_docs.size()) ? g_docs[g_cur].name : L"script";
    if (!g_rbx || !g_injected || g_mapped_pid != (g_rbx ? g_rbx->pid : 0) || !g_mod_ready) {
        g_pending_exec = expand_loadstring_http(raw);
        notify(L"Runtime", L"Queued  " + nm + L" — attaching");
        VT_LOG(L"Execute queued " + nm);
        if (!g_attach_busy)
            do_attach();
        return;
    }
    try_corescript(expand_loadstring_http(raw), nm);
}

bool pick_file(wchar_t* path, bool save) {
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_wnd;
    ofn.lpstrFilter = L"Luau (*.lua)\0*.lua\0Text (*.txt)\0*.txt\0All\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrDefExt = L"lua";
    ofn.Flags = save ? OFN_OVERWRITEPROMPT : (OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST);
    return save ? GetSaveFileNameW(&ofn) : GetOpenFileNameW(&ofn);
}

void do_open() {
    wchar_t path[MAX_PATH]{};
    if (!pick_file(path, false))
        return;
    new_tab(std::filesystem::path(path).filename().wstring(),
            utf8_to_wide(read_file_utf8(path)), path);
    g_docs.back().dirty = false;
    toast(L"Opened  " + g_docs.back().name);
}

std::wstring safe_lua_name(std::wstring n) {
    for (auto& c : n) {
        if (wcschr(L"\\/:*?\"<>|", c))
            c = L'_';
    }
    if (n.size() >= 4) {
        auto ext = n.substr(n.size() - 4);
        for (auto& c : ext) c = (wchar_t)towlower(c);
        if (ext == L".lua" || ext == L".txt")
            return n;
    }
    return n + L".lua";
}

void do_save(bool save_as) {
    sync_editor_into_tab();
    if (g_docs.empty())
        return;
    auto& t = g_docs[g_cur];
    std::wstring dest = t.path;
    if (save_as) {
        wchar_t path[MAX_PATH]{};
        if (!t.path.empty())
            wcsncpy_s(path, t.path.c_str(), _TRUNCATE);
        else
            wcsncpy_s(path, (saved_dir() / safe_lua_name(t.name)).wstring().c_str(), _TRUNCATE);
        if (!pick_file(path, true))
            return;
        dest = path;
    } else if (dest.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(saved_dir(), ec);
        dest = (saved_dir() / safe_lua_name(t.name)).wstring();
    }
    write_file_utf8(dest, wide_to_utf8(t.text));
    t.path = dest;
    t.name = std::filesystem::path(dest).stem().wstring();
    t.dirty = false;
    persist_tabs();
    refresh_scripts();
    toast(L"Saved  " + t.name);
    VT_LOG(L"Saved  " + dest);
}

void set_topmost(bool on) {
    g_topmost = on;
    if (g_wnd)
        SetWindowPos(g_wnd, on ? HWND_TOPMOST : HWND_NOTOPMOST,
                     0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    toast(on ? L"Always on top" : L"Not always on top");
}

const wchar_t* hover_tip(int id) {
    if (id >= H_FILE0)
        return L"Load script";
    if (id >= H_TABX0)
        return L"Close tab";
    if (id >= H_TAB0)
        return L"Switch tab";
    switch (id) {
    case H_MIN:     return L"Minimize";
    case H_MAX:     return L"Maximize";
    case H_CLOSE:   return L"Exit";
    case H_GEAR:    return L"Settings";
    case H_OPEN:    return L"Open file";
    case H_SAVE:    return L"Save in app";
    case H_CLEAR:   return L"Clear editor";
    case H_ATTACH:  return L"Attach";
    case H_SCRIPTS: return L"Saved scripts";
    case H_TOPMOST: return L"Always on top";
    case H_EXECUTE: return L"Execute  (F5)";
    case H_NEWTAB:  return L"New tab";
    case H_SETLOG:  return L"Output window";
    case H_SETHELP: return L"How to use";
    case H_SETESP:  return L"Stream proof (hide from capture)";
    case H_SETBACK: return L"Back";
    default:        return nullptr;
    }
}

void show_help() {
    MessageBoxW(g_wnd,
        L"1. Join a Roblox game.\n"
        L"2. Type or paste a script.\n"
        L"3. Save — it stays in the app.\n"
        L"4. Attach (or just press Execute / F5).\n"
        L"5. Wait READY, then Execute.\n\n"
        L"Insert hides this window. X / taskbar close exits fully.\n"
        L"Settings → Stream Proof: hide UI from OBS (off = show on stream).\n"
        L"Right-click Save: Save As.",
        L"Runtime", MB_OK | MB_ICONINFORMATION);
}

LRESULT CALLBACK editor_proc(HWND h, UINT msg, WPARAM w, LPARAM l) {
    if (msg == WM_PASTE) {
        if (!IsClipboardFormatAvailable(CF_UNICODETEXT) && !IsClipboardFormatAvailable(CF_TEXT))
            return 0;
    }
    if (msg == WM_DROPFILES)
        return 0;
    if (msg == WM_MOUSEWHEEL) {
        const int delta = GET_WHEEL_DELTA_WPARAM(w);
        const int lines = delta > 0 ? -3 : 3;
        SendMessageW(h, EM_LINESCROLL, 0, lines);
        return 0;
    }
    return CallWindowProcW(g_edit_prev, h, msg, w, l);
}

void style_edit(HWND h, COLORREF) {
    SendMessageW(h, WM_SETFONT, (WPARAM)g_fontMono, TRUE);
    SendMessageW(h, EM_LIMITTEXT, 0x7FFFFFFE, 0);
}

RECT RR(int x, int y, int w, int h) { return {x, y, x + w, y + h}; }

void add_hit(const RECT& rc, int id) {
    g_hits.push_back({rc, id});
}

int hit_at(int x, int y) {
    POINT p{x, y};
    for (int i = (int)g_hits.size() - 1; i >= 0; --i)
        if (PtInRect(&g_hits[i].rc, p))
            return g_hits[i].id;
    return H_NONE;
}

void fill_round(HDC dc, RECT rc, COLORREF c, int rad) {
    HBRUSH br = CreateSolidBrush(c);
    HPEN pen = CreatePen(PS_SOLID, 1, c);
    auto ob = SelectObject(dc, br);
    auto op = SelectObject(dc, pen);
    RoundRect(dc, rc.left, rc.top, rc.right, rc.bottom, rad, rad);
    SelectObject(dc, ob);
    SelectObject(dc, op);
    DeleteObject(br);
    DeleteObject(pen);
}

void fill_rect(HDC dc, RECT rc, COLORREF c) {
    HBRUSH br = CreateSolidBrush(c);
    FillRect(dc, &rc, br);
    DeleteObject(br);
}

void frame_rect(HDC dc, RECT rc, COLORREF c, int w) {
    HPEN pen = CreatePen(PS_SOLID, w, c);
    auto old = SelectObject(dc, pen);
    auto oldb = SelectObject(dc, GetStockObject(NULL_BRUSH));
    Rectangle(dc, rc.left, rc.top, rc.right, rc.bottom);
    SelectObject(dc, old);
    SelectObject(dc, oldb);
    DeleteObject(pen);
}

void frame_round(HDC dc, RECT rc, COLORREF c, int w, int rad) {
    HPEN pen = CreatePen(PS_SOLID, w, c);
    auto old = SelectObject(dc, pen);
    auto oldb = SelectObject(dc, GetStockObject(NULL_BRUSH));
    RoundRect(dc, rc.left, rc.top, rc.right, rc.bottom, rad, rad);
    SelectObject(dc, old);
    SelectObject(dc, oldb);
    DeleteObject(pen);
}

void text_at(HDC dc, RECT rc, const wchar_t* s, COLORREF c, HFONT f, UINT fmt) {
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, c);
    auto old = SelectObject(dc, f);
    DrawTextW(dc, s, -1, &rc, fmt);
    SelectObject(dc, old);
}

void line(HDC dc, int x1, int y1, int x2, int y2, COLORREF c, int w) {
    HPEN pen = CreatePen(PS_SOLID, w, c);
    auto old = SelectObject(dc, pen);
    MoveToEx(dc, x1, y1, nullptr);
    LineTo(dc, x2, y2);
    SelectObject(dc, old);
    DeleteObject(pen);
}

HPEN stroke(HDC dc, COLORREF c, int w) {
    HPEN pen = CreatePen(PS_SOLID, w, c);
    SelectObject(dc, pen);
    SelectObject(dc, GetStockObject(NULL_BRUSH));
    return pen;
}

void end_stroke(HDC dc, HPEN pen) {
    SelectObject(dc, GetStockObject(BLACK_PEN));
    SelectObject(dc, GetStockObject(NULL_BRUSH));
    DeleteObject(pen);
}

void icon_gear(HDC dc, RECT r, COLORREF c) {
    const int cx = (r.left + r.right) / 2, cy = (r.top + r.bottom) / 2;
    HPEN pen = stroke(dc, c, 2);
    Ellipse(dc, cx - 5, cy - 5, cx + 6, cy + 6);
    HBRUSH br = CreateSolidBrush(c);
    auto ob = SelectObject(dc, br);
    for (int i = 0; i < 8; ++i) {
        const double a = i * 3.14159265 / 4.0;
        const int x = cx + (int)(std::cos(a) * 8);
        const int y = cy + (int)(std::sin(a) * 8);
        Ellipse(dc, x - 1, y - 1, x + 3, y + 3);
    }
    SelectObject(dc, ob);
    DeleteObject(br);
    end_stroke(dc, pen);
}

void icon_folder(HDC dc, RECT r, COLORREF c) {
    const int x = r.left + 8, y = r.top + 10;
    HPEN pen = stroke(dc, c, 1);
    RoundRect(dc, x, y + 4, x + 18, y + 16, 2, 2);
    MoveToEx(dc, x, y + 7, nullptr);
    LineTo(dc, x + 5, y + 7);
    LineTo(dc, x + 8, y + 3);
    LineTo(dc, x + 14, y + 3);
    LineTo(dc, x + 14, y + 7);
    end_stroke(dc, pen);
}

void icon_save(HDC dc, RECT r, COLORREF c) {
    const int x = r.left + 9, y = r.top + 9;
    HPEN pen = stroke(dc, c, 1);
    POINT p[] = {{x, y + 16}, {x, y}, {x + 12, y}, {x + 16, y + 4}, {x + 16, y + 16}};
    Polygon(dc, p, 5);
    Rectangle(dc, x + 4, y, x + 12, y + 6);
    Rectangle(dc, x + 3, y + 9, x + 13, y + 16);
    end_stroke(dc, pen);
}

void icon_eraser(HDC dc, RECT r, COLORREF c) {
    const int x = r.left + 8, y = r.top + 11;
    HPEN pen = stroke(dc, c, 1);
    POINT p[] = {{x, y + 8}, {x + 8, y}, {x + 16, y + 4}, {x + 8, y + 12}};
    Polygon(dc, p, 4);
    MoveToEx(dc, x + 2, y + 13, nullptr);
    LineTo(dc, x + 18, y + 13);
    end_stroke(dc, pen);
}

void icon_link(HDC dc, RECT r, COLORREF c) {
    const int cx = (r.left + r.right) / 2, cy = (r.top + r.bottom) / 2;
    HPEN pen = stroke(dc, c, 2);
    Ellipse(dc, cx - 9, cy - 5, cx + 1, cy + 6);
    Ellipse(dc, cx - 1, cy - 5, cx + 9, cy + 6);
    end_stroke(dc, pen);
}

void icon_doc(HDC dc, RECT r, COLORREF c) {
    const int x = r.left + 10, y = r.top + 8;
    HPEN pen = stroke(dc, c, 1);
    RoundRect(dc, x, y, x + 14, y + 18, 2, 2);
    line(dc, x + 3, y + 5, x + 11, y + 5, c);
    line(dc, x + 3, y + 9, x + 11, y + 9, c);
    line(dc, x + 3, y + 13, x + 9, y + 13, c);
    end_stroke(dc, pen);
}

void icon_grid(HDC dc, RECT r, COLORREF c) {
    const int cx = (r.left + r.right) / 2, cy = (r.top + r.bottom) / 2;
    HPEN pen = stroke(dc, c, 1);
    const int s = 5, g = 3;
    RoundRect(dc, cx - s - g, cy - s - g, cx - g + 1, cy - g + 1, 2, 2);
    RoundRect(dc, cx + g - 1, cy - s - g, cx + s + g, cy - g + 1, 2, 2);
    RoundRect(dc, cx - s - g, cy + g - 1, cx - g + 1, cy + s + g, 2, 2);
    RoundRect(dc, cx + g - 1, cy + g - 1, cx + s + g, cy + s + g, 2, 2);
    end_stroke(dc, pen);
}

void icon_inject(HDC dc, RECT r, COLORREF c) {
    const int cx = (r.left + r.right) / 2, cy = (r.top + r.bottom) / 2;
    HPEN pen = stroke(dc, c, 2);
    MoveToEx(dc, cx, cy - 8, nullptr);
    LineTo(dc, cx, cy + 4);
    MoveToEx(dc, cx - 5, cy - 1, nullptr);
    LineTo(dc, cx, cy + 4);
    LineTo(dc, cx + 5, cy - 1);
    MoveToEx(dc, cx - 7, cy + 8, nullptr);
    LineTo(dc, cx + 7, cy + 8);
    end_stroke(dc, pen);
}

void icon_play(HDC dc, RECT r, COLORREF c) {
    const int x = r.left + 12, y = r.top + 11;
    HPEN pen = stroke(dc, c, 2);
    POINT p[] = {{x, y}, {x + 12, y + 8}, {x, y + 16}};
    Polygon(dc, p, 3);
    end_stroke(dc, pen);
}

void icon_btn(HDC dc, RECT r, int id, void (*draw)(HDC, RECT, COLORREF)) {
    add_hit(r, id);
    if (g_hover == id)
        fill_round(dc, r, kHover, 6);
    draw(dc, r, kText);
}

void chip_btn(HDC dc, RECT r, int id, const wchar_t* label, bool primary, bool on) {
    add_hit(r, id);
    COLORREF bg = kChip;
    if (primary)
        bg = (g_hover == id) ? kGlow : kBlue;
    else if (on)
        bg = RGB(22, 56, 38);
    else if (g_hover == id)
        bg = kHover;
    fill_round(dc, r, bg, 8);
    if (on && !primary)
        frame_round(dc, r, kOk, 1, 8);
    text_at(dc, r, label, kText, g_fontBd, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

void draw_win_min(HDC dc, RECT r, COLORREF c) {
    const int cx = (r.left + r.right) / 2, cy = (r.top + r.bottom) / 2;
    line(dc, cx - 6, cy, cx + 6, cy, c, 2);
}

void draw_win_max(HDC dc, RECT r, COLORREF c) {
    const int cx = (r.left + r.right) / 2, cy = (r.top + r.bottom) / 2;
    auto corner = [&](int x, int y, int hx, int hy) {
        line(dc, x, y, x + hx, y, c, 1);
        line(dc, x, y, x, y + hy, c, 1);
    };
    corner(cx - 7, cy - 7, 5, 5);
    corner(cx + 7, cy - 7, -5, 5);
    corner(cx - 7, cy + 7, 5, -5);
    corner(cx + 7, cy + 7, -5, -5);
}

void draw_win_close(HDC dc, RECT r, COLORREF c) {
    const int cx = (r.left + r.right) / 2, cy = (r.top + r.bottom) / 2;
    line(dc, cx - 5, cy - 5, cx + 6, cy + 6, c, 1);
    line(dc, cx + 5, cy - 5, cx - 6, cy + 6, c, 1);
}

int line_count() {
    if (!g_editor)
        return 1;
    const int n = (int)SendMessageW(g_editor, EM_GETLINECOUNT, 0, 0);
    return n > 0 ? n : 1;
}

void layout_edits(HWND wnd) {
    RECT rc{};
    GetClientRect(wnd, &rc);
    const int W = rc.right, H = rc.bottom;
    const int yEd = kTitleH + kTabH;
    const int edH = H - yEd - kBarH - 2;
    const bool page = g_settings_open || g_scripts_open;
    if (g_editor) {
        if (page)
            ShowWindow(g_editor, SW_HIDE);
        else {
            ShowWindow(g_editor, SW_SHOW);
            MoveWindow(g_editor, kGutter + 6, yEd + 4, (W - kGutter - 14), edH > 40 ? edH : 40, TRUE);
            ShowScrollBar(g_editor, SB_BOTH, FALSE);
        }
    }
}

void paint_tooltip(HDC dc, int W, int H) {
    if (!g_tip_on)
        return;
    const wchar_t* tip = hover_tip(g_hover);
    if (!tip)
        return;
    SIZE sz{};
    auto old = SelectObject(dc, g_fontSm);
    GetTextExtentPoint32W(dc, tip, (int)wcslen(tip), &sz);
    SelectObject(dc, old);
    const int tw = sz.cx + 18;
    const int th = sz.cy + 10;
    int x = g_mouse.x + 16;
    int y = g_mouse.y + 20;
    if (x + tw > W - 8) x = g_mouse.x - tw - 10;
    if (y + th > H - 8) y = g_mouse.y - th - 10;
    if (x < 8) x = 8;
    if (y < 8) y = 8;
    RECT box = RR(x, y, tw, th);
    fill_round(dc, {box.left + 1, box.top + 2, box.right + 1, box.bottom + 2}, RGB(0, 0, 0), 8);
    fill_round(dc, box, kTipBg, 8);
    frame_round(dc, box, kTipBd, 1, 8);
    text_at(dc, box, tip, kText, g_fontSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

void paint(HWND wnd) {
    PAINTSTRUCT ps;
    HDC odc = BeginPaint(wnd, &ps);
    RECT cr{};
    GetClientRect(wnd, &cr);
    const int W = cr.right, H = cr.bottom;

    HDC dc = CreateCompatibleDC(odc);
    HBITMAP bmp = CreateCompatibleBitmap(odc, W, H);
    auto oldb = SelectObject(dc, bmp);

    fill_rect(dc, cr, kBg);
    draw_stars(dc, W, H);
    g_hits.clear();

    // Gradient title bar: dark navy-blue top → kBg at divider
    {
        TRIVERTEX tv[2]{};
        tv[0].x = 0; tv[0].y = 0;
        tv[0].Red = 0x0F00; tv[0].Green = 0x1A00; tv[0].Blue = 0x3C00; tv[0].Alpha = 0xFF00;
        tv[1].x = W; tv[1].y = kTitleH;
        tv[1].Red = 0x0600; tv[1].Green = 0x0A00; tv[1].Blue = 0x1600; tv[1].Alpha = 0xFF00;
        GRADIENT_RECT gr{0, 1};
        GradientFill(dc, tv, 2, &gr, 1, GRADIENT_FILL_RECT_V);
    }

    // Two-pixel blue glow border
    frame_rect(dc, cr, kGlow, 2);
    frame_rect(dc, {1, 1, W - 1, H - 1}, kBlue, 1);

    blit_logo(dc, 12, (kTitleH - g_logo_h) / 2);
    text_at(dc, RR(12 + g_logo_w + 8, 0, 160, kTitleH), L"VoidTrace", kText, g_fontTitle,
            DT_LEFT | DT_VCENTER | DT_SINGLELINE);

    auto winbtn = [&](int x, int id, void (*draw)(HDC, RECT, COLORREF)) {
        RECT r = RR(x, 4, 30, 26);
        add_hit(r, id);
        if (g_hover == id)
            fill_round(dc, r, id == H_CLOSE ? RGB(140, 28, 36) : kHover, 6);
        draw(dc, r, kText);
    };
    winbtn(W - 102, H_MIN, draw_win_min);
    winbtn(W - 70, H_MAX, draw_win_max);
    winbtn(W - 38, H_CLOSE, draw_win_close);

    line(dc, 1, kTitleH, W - 1, kTitleH, kLine);

    const int yTab = kTitleH;
    int tx = 10;
    for (int i = 0; i < (int)g_docs.size(); ++i) {
        std::wstring name = g_docs[i].name;
        if (g_docs[i].dirty)
            name += L" •";
        const bool on = i == g_cur;
        const bool hot = g_hover == H_TAB0 + i || g_hover == H_TABX0 + i;
        const int tw = 22 + (int)name.size() * 7 + (hot ? 14 : 0);
        RECT tr = RR(tx, yTab + 4, tw, 22);
        add_hit(tr, H_TAB0 + i);
        if (on)
            fill_round(dc, tr, kChip, 5);
        else if (hot)
            fill_round(dc, tr, kHover, 5);
        RECT nr = tr;
        if (hot)
            nr.right -= 14;
        text_at(dc, nr, name.c_str(), on ? kTabOn : kMuted, g_fontSm,
                DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        if (hot) {
            RECT xr = RR(tr.right - 16, tr.top, 14, 22);
            add_hit(xr, H_TABX0 + i);
            text_at(dc, xr, L"×", g_hover == H_TABX0 + i ? kText : kMuted, g_fontSm,
                    DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        }
        tx += tw + 2;
    }
    RECT plus = RR(tx + 2, yTab + 4, 22, 22);
    add_hit(plus, H_NEWTAB);
    text_at(dc, plus, L"+", g_hover == H_NEWTAB ? kText : kMuted, g_fontBd,
            DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    const int yEd = kTitleH + kTabH;
    fill_rect(dc, RR(1, yEd, W - 2, H - yEd - kBarH), kEditor);

    if (g_settings_open) {
        // ── Header ──────────────────────────────────────────────────────
        text_at(dc, RR(24, yEd + 14, 300, 26), L"Settings", kText, g_fontTitle,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        // Back button top-right
        {
            RECT br = RR(W - 110, yEd + 14, 86, 26);
            add_hit(br, H_SETBACK);
            fill_round(dc, br, g_hover == H_SETBACK ? kHover : kChip, 6);
            text_at(dc, br, L"← Back", kText, g_fontSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        }
        line(dc, 24, yEd + 46, W - 24, yEd + 46, kLine);

        // ── How to use ──────────────────────────────────────────────────
        text_at(dc, RR(24, yEd + 54, 200, 18), L"HOW TO USE", kMuted, g_fontSm,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        const wchar_t* steps[] = {
            L"1.  Open Roblox and join a game (not just the launcher)",
            L"2.  Click the ⊕ Attach button in the bottom toolbar",
            L"3.  Wait until the status dot turns green and shows READY",
            L"4.  Paste or type your script, then press F5 or click Execute",
        };
        for (int i = 0; i < 4; ++i)
            text_at(dc, RR(28, yEd + 74 + i * 20, W - 56, 18), steps[i],
                    kMuted, g_fontSm, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        line(dc, 24, yEd + 160, W - 24, yEd + 160, kLine);

        // ── Toggle rows ─────────────────────────────────────────────────
        // label on left, ON/OFF chip on right, description below label
        auto toggle_row = [&](int y, int id, const wchar_t* title, const wchar_t* desc, bool on) {
            const int rw = W - 48;
            RECT r = RR(24, yEd + y, rw, 44);
            add_hit(r, id);
            fill_round(dc, r, g_hover == id ? kHover : kChip, 8);
            if (on) frame_round(dc, r, kBlue, 1, 8);
            // Title
            text_at(dc, RR(36, yEd + y + 6, rw - 90, 18), title, kText, g_fontBd,
                    DT_LEFT | DT_VCENTER | DT_SINGLELINE);
            // Description
            text_at(dc, RR(36, yEd + y + 24, rw - 90, 16), desc, kMuted, g_fontSm,
                    DT_LEFT | DT_VCENTER | DT_SINGLELINE);
            // ON/OFF pill
            RECT pill = RR(24 + rw - 72, yEd + y + 12, 60, 22);
            fill_round(dc, pill, on ? kOk : RGB(50, 40, 80), 11);
            text_at(dc, pill, on ? L"ON" : L"OFF", on ? RGB(4,2,10) : kMuted,
                    g_fontBd, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        };

        toggle_row(168, H_SETAUTO, L"Auto-Attach",
                   L"Automatically attach when Roblox opens", g_auto_attach);
        toggle_row(220, H_SETLOG,  L"Output Log",
                   L"Open a second VoidTrace window for logs", g_show_log);
        toggle_row(272, H_SETESP,  L"Stream Proof",
                   L"Hide this UI from OBS / Discord. Off = show on stream",
                   g_stream_proof);
        toggle_row(324, H_SETSTARS, L"Star Field",
                   L"Animated starfield — stars drift and repel from cursor",
                   g_stars_enabled);
    } else if (g_scripts_open) {
        text_at(dc, RR(24, yEd + 16, 300, 24), L"Scripts", kText, g_fontTitle,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        RECT back = RR(W - 120, yEd + 14, 96, 28);
        add_hit(back, H_SETBACK);
        fill_round(dc, back, g_hover == H_SETBACK ? kHover : kChip, 6);
        text_at(dc, back, L"Back", kText, g_fontSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        int fy = yEd + 56;
        if (g_files.empty()) {
            text_at(dc, RR(24, fy, W - 48, 40), L"Save a script to keep it here.", kMuted, g_font,
                    DT_LEFT | DT_WORDBREAK);
        } else {
            for (int i = 0; i < (int)g_files.size(); ++i) {
                RECT fr = RR(24, fy, W - 48, 32);
                add_hit(fr, H_FILE0 + i);
                fill_round(dc, fr, g_hover == H_FILE0 + i ? kHover : kChip, 6);
                text_at(dc, fr, g_files[i].label.c_str(), kText, g_font,
                        DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
                fy += 38;
                if (fy + 32 > H - kBarH - 8)
                    break;
            }
        }
    } else {
        fill_rect(dc, RR(2, yEd, kGutter, H - yEd - kBarH), kEditor);
        const int lines = line_count();
        int first = 0;
        if (g_editor)
            first = (int)SendMessageW(g_editor, EM_GETFIRSTVISIBLELINE, 0, 0);
        int ly = yEd + 6;
        for (int i = first + 1; i <= lines && ly < H - kBarH - 4; ++i, ly += 16) {
            wchar_t buf[12];
            swprintf_s(buf, L"%d", i);
            text_at(dc, RR(2, ly, kGutter - 6, 16), buf, RGB(72, 58, 110), g_fontSm,
                    DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
        }
        line(dc, kGutter + 2, yEd + 8, kGutter + 2, H - kBarH - 8, RGB(36, 36, 40));
    }

    fill_rect(dc, RR(2, H - kBarH, W - 4, kBarH - 2), kBar);
    line(dc, 2, H - kBarH, W - 2, H - kBarH, kLine);

    const int by = H - kBarH;
    icon_btn(dc, RR(10, by + 7, 32, 32), H_GEAR, icon_gear);
    icon_btn(dc, RR(46, by + 7, 32, 32), H_OPEN, icon_folder);
    icon_btn(dc, RR(82, by + 7, 32, 32), H_SAVE, icon_save);
    icon_btn(dc, RR(118, by + 7, 32, 32), H_CLEAR, icon_eraser);

    icon_btn(dc, RR(W - 194, by + 7, 32, 32), H_ATTACH,  icon_link);
    icon_btn(dc, RR(W - 158, by + 7, 32, 32), H_SCRIPTS, icon_doc);
    icon_btn(dc, RR(W - 122, by + 7, 32, 32), H_TOPMOST, icon_grid);

    // Execute: wide coloured chip with label so it can't be missed
    {
        RECT exr = RR(W - 110, by + 8, 100, 30);
        add_hit(exr, H_EXECUTE);
        const COLORREF btn_bg = (g_hover == H_EXECUTE) ? kBlue : kExecBtn;
        fill_round(dc, exr, btn_bg, 8);
        // subtle inner highlight line at top
        HPEN hl = CreatePen(PS_SOLID, 1, RGB(180, 140, 255));
        auto op = SelectObject(dc, hl);
        MoveToEx(dc, exr.left + 4, exr.top + 1, nullptr);
        LineTo  (dc, exr.right - 4, exr.top + 1);
        SelectObject(dc, op);
        DeleteObject(hl);
        text_at(dc, exr, L"▶  Execute", kText, g_fontBd, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    }

    // Status dot + text centred in toolbar (left of toast area)
    {
        COLORREF dot = g_pipe.connected() ? kOk
                     : g_injected         ? kWarn
                                          : RGB(70, 60, 100);
        const int dot_cx = W / 2 - 54;
        const int dot_cy = by + 23;
        fill_round(dc, {dot_cx - 4, dot_cy - 4, dot_cx + 5, dot_cy + 5}, dot, 5);
        text_at(dc, RR(dot_cx + 8, by + 8, 280, 28), g_status.c_str(), kMuted, g_fontSm,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    }

    if (!g_toast.empty() && GetTickCount() < g_toast_until) {
        SIZE sz{};
        auto oldf = SelectObject(dc, g_fontSm);
        GetTextExtentPoint32W(dc, g_toast.c_str(), (int)g_toast.size(), &sz);
        SelectObject(dc, oldf);
        const int tw = sz.cx + 40;
        RECT tb = RR((W - tw) / 2, H - kBarH - 52, tw, 36);
        fill_round(dc, tb, RGB(12, 18, 36), 10);
        frame_round(dc, tb, kBlue, 2, 10);
        text_at(dc, tb, g_toast.c_str(), kText, g_fontBd, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    }

    paint_tooltip(dc, W, H);

    BitBlt(odc, 0, 0, W, H, dc, 0, 0, SRCCOPY);
    SelectObject(dc, oldb);
    DeleteObject(bmp);
    DeleteDC(dc);
    EndPaint(wnd, &ps);
}

void click(int id) {
    g_tip_on = false;
    if (id == H_MIN) { ShowWindow(g_wnd, SW_MINIMIZE); return; }
    if (id == H_MAX) {
        ShowWindow(g_wnd, IsZoomed(g_wnd) ? SW_RESTORE : SW_MAXIMIZE);
        return;
    }
    if (id == H_CLOSE) { request_exit(); return; }
    if (id == H_GEAR || id == H_SETBACK) {
        if (id == H_GEAR) {
            g_settings_open = !g_settings_open;
            g_scripts_open = false;
        } else {
            g_settings_open = false;
            g_scripts_open = false;
        }
        layout_edits(g_wnd);
        invalidate();
        return;
    }
    if (id == H_SETAUTO) {
        g_auto_attach = !g_auto_attach;
        if (g_init_done)
            Config::instance().get().auto_attach = g_auto_attach;
        Config::instance().save(data_root() / L"config" / L"offsets.json");
        toast(g_auto_attach ? L"Auto-attach ON" : L"Auto-attach OFF");
        invalidate();
        return;
    }
    if (id == H_SETLOG) {
        if (g_show_log && g_log_wnd && IsWindowVisible(g_log_wnd))
            hide_log_window();
        else
            show_log_window();
        invalidate();
        return;
    }
    if (id == H_SETESP) {
        g_stream_proof = !g_stream_proof;
        apply_capture_all();
        toast(g_stream_proof ? L"Stream proof ON — hidden from capture" : L"Stream proof OFF — visible on stream");
        invalidate();
        return;
    }
    if (id == H_SETSTARS) {
        g_stars_enabled = !g_stars_enabled;
        toast(g_stars_enabled ? L"Star field ON" : L"Star field OFF");
        invalidate();
        return;
    }
    if (id == H_SETHELP) {
        show_help();
        return;
    }
    if (id == H_ATTACH) { do_attach(); return; }
    if (id == H_EXECUTE) { do_execute(); return; }
    if (id == H_SCRIPTS) {
        g_scripts_open = !g_scripts_open;
        g_settings_open = false;
        refresh_scripts();
        layout_edits(g_wnd);
        invalidate();
        return;
    }
    if (id == H_TOPMOST) {
        set_topmost(!g_topmost);
        invalidate();
        return;
    }
    if (id == H_CLEAR) {
        set_editor(L"");
        if (g_cur < (int)g_docs.size()) {
            g_docs[g_cur].text.clear();
            g_docs[g_cur].dirty = true;
        }
        invalidate();
        return;
    }
    if (id == H_OPEN) { do_open(); return; }
    if (id == H_SAVE) { do_save(false); return; }
    if (id == H_NEWTAB) { new_tab({}, L""); return; }
    if (id >= H_TAB0 && id < H_TABX0) { show_tab(id - H_TAB0); return; }
    if (id >= H_TABX0 && id < H_FILE0) {
        g_cur = id - H_TABX0;
        close_tab();
        return;
    }
    if (id >= H_FILE0) {
        const int i = id - H_FILE0;
        if (i >= 0 && i < (int)g_files.size()) {
            auto name = std::filesystem::path(g_files[i].path).stem().wstring();
            new_tab(name, utf8_to_wide(read_file_utf8(g_files[i].path)), g_files[i].path);
            g_docs.back().dirty = false;
            g_scripts_open = false;
            layout_edits(g_wnd);
            toast(L"Loaded  " + name);
        }
        return;
    }
}

LRESULT CALLBACK wndproc(HWND wnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        g_wnd = wnd;
        g_ui_tid = GetCurrentThreadId();
        BOOL dark = TRUE;
        DwmSetWindowAttribute(wnd, 20, &dark, sizeof(dark));
        COLORREF cap = RGB(6, 10, 22);      // match kBg
        DwmSetWindowAttribute(wnd, 35, &cap, sizeof(cap));
        COLORREF brd = RGB(22, 80, 200);    // kGlow — blue DWM border
        DwmSetWindowAttribute(wnd, 34, &brd, sizeof(brd));
        int corner = DWMWCP_ROUND;
        DwmSetWindowAttribute(wnd, DWMWA_WINDOW_CORNER_PREFERENCE, &corner, sizeof(corner));

        g_brBg = CreateSolidBrush(kBg);
        g_brEdit = CreateSolidBrush(kEditor);
        g_font = CreateFontW(14, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
        g_fontSm = CreateFontW(12, 0, 0, 0, FW_MEDIUM, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
        g_fontBd = CreateFontW(14, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
        g_fontTitle = CreateFontW(16, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI Semibold");
        g_fontMono = CreateFontW(15, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, FIXED_PITCH, L"Cascadia Mono");
        g_logo = load_png_resource(IDR_VT_LOGO, g_logo_w, g_logo_h);

        g_editor = CreateWindowExW(0, L"EDIT", L"",
                                   WS_CHILD | WS_VISIBLE |
                                   ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN | ES_NOHIDESEL,
                                   0, 0, 100, 100, wnd, (HMENU)ID_EDITOR, GetModuleHandleW(nullptr), nullptr);
        SetWindowTheme(g_editor, L"", L"");
        style_edit(g_editor, kEditor);
        ShowScrollBar(g_editor, SB_BOTH, FALSE);
        g_edit_prev = (WNDPROC)SetWindowLongPtrW(g_editor, GWLP_WNDPROC, (LONG_PTR)editor_proc);
        DragAcceptFiles(g_editor, FALSE);

        restore_tabs();
        refresh_scripts();
        SetTimer(wnd, 1, 800, nullptr);
        SetTimer(wnd, 2, 8000, nullptr);
        SetTimer(wnd, 3, 50, nullptr);
        // Session-unique pipe name — written to shared memory for the DLL.
        {
            const auto pipe_name = PipeKey::create();
            g_pipe.start(pipe_name, on_pipe);
        }
        apply_stealth_window(wnd);
        tray_add(wnd);
        RegisterHotKey(wnd, ID_HOT_TOGGLE, 0, VK_INSERT);
        PostMessageW(wnd, WM_APP + 8, 0, 0); // deferred heavy init
        return 0;
    }
    case WM_APP + 8:
        do_deferred_init();
        return 0;
    case WM_APP + 9:
        return 0;
    case WM_JOB_HINT:
        send_job_hint();
        return 0;
    case WM_PROG: {
        auto* s = reinterpret_cast<std::wstring*>(lp);
        if (s) {
            set_progress((int)wp, s->c_str());
            delete s;
        }
        return 0;
    }
    case WM_ATTACH_CONT:
        invalidate();
        return 0;
    case WM_SIZE:
        layout_edits(wnd);
        invalidate();
        return 0;
    case WM_PAINT:
        paint(wnd);
        return 0;
    case WM_ERASEBKGND:
        return 1;
    case WM_MOUSEMOVE: {
        const int x = GET_X_LPARAM(lp);
        const int y = GET_Y_LPARAM(lp);
        g_mouse = {x, y};
        const int id = hit_at(x, y);
        if (id != g_hover) {
            g_hover = id;
            g_hover_tick = GetTickCount();
            g_tip_on = false;
            invalidate();
        } else if (g_tip_on) {
            invalidate();
        }
        TRACKMOUSEEVENT tme{sizeof(tme), TME_LEAVE, wnd, 0};
        TrackMouseEvent(&tme);
        return 0;
    }
    case WM_MOUSELEAVE:
        g_hover = H_NONE;
        g_tip_on = false;
        invalidate();
        return 0;
    case WM_LBUTTONUP:
        click(hit_at(GET_X_LPARAM(lp), GET_Y_LPARAM(lp)));
        return 0;
    case WM_RBUTTONUP: {
        const int id = hit_at(GET_X_LPARAM(lp), GET_Y_LPARAM(lp));
        if (id == H_SAVE) {
            do_save(true);
            return 0;
        }
        if (id == H_GEAR) {
            g_stream_proof = !g_stream_proof;
            apply_capture_all();
            toast(g_stream_proof ? L"Stream proof ON" : L"Stream proof OFF");
            return 0;
        }
        break;
    }
    case WM_NCHITTEST: {
        POINT sp{GET_X_LPARAM(lp), GET_Y_LPARAM(lp)};
        RECT wr{};
        GetWindowRect(wnd, &wr);
        const bool left = sp.x < wr.left + kEdge;
        const bool right = sp.x >= wr.right - kEdge;
        const bool top = sp.y < wr.top + kEdge;
        const bool bottom = sp.y >= wr.bottom - kEdge;
        if (top && left) return HTTOPLEFT;
        if (top && right) return HTTOPRIGHT;
        if (bottom && left) return HTBOTTOMLEFT;
        if (bottom && right) return HTBOTTOMRIGHT;
        if (left) return HTLEFT;
        if (right) return HTRIGHT;
        if (top) return HTTOP;
        if (bottom) return HTBOTTOM;
        POINT p = sp;
        ScreenToClient(wnd, &p);
        if (p.y < kTitleH && hit_at(p.x, p.y) == H_NONE)
            return HTCAPTION;
        return HTCLIENT;
    }
    case WM_TIMER:
        if (wp == 3) {
            POINT sp{};
            GetCursorPos(&sp);
            POINT cp = sp;
            ScreenToClient(wnd, &cp);
            RECT crc{};
            GetClientRect(wnd, &crc);
            const int id = PtInRect(&crc, cp) ? hit_at(cp.x, cp.y) : H_NONE;
            g_mouse = cp;
            if (id != g_hover) {
                g_hover = id;
                g_hover_tick = GetTickCount();
                g_tip_on = false;
                invalidate();
            } else if (g_hover != H_NONE && hover_tip(g_hover) && !g_tip_on &&
                       GetTickCount() - g_hover_tick >= kTipDelay) {
                g_tip_on = true;
                invalidate();
            } else if (g_tip_on) {
                static POINT last{};
                if (last.x != cp.x || last.y != cp.y) {
                    last = cp;
                    invalidate();
                }
            }
            if (!g_toast.empty() && GetTickCount() >= g_toast_until) {
                g_toast.clear();
                invalidate();
            }
            // Advance star-field physics every tick (50 ms → ~20 fps animation)
            if (g_stars_enabled && g_stars_inited) {
                RECT crc2{};
                GetClientRect(wnd, &crc2);
                update_stars(crc2.right, crc2.bottom, cp.x, cp.y);
                invalidate();
            }
            return 0;
        }
        if (wp == 2) {
            persist_tabs();
            return 0;
        }
        if (!g_init_done)
            return 0;
        if (g_pipe.connected() && g_injected)
            send_job_hint();
        // PeekMessage stub stays. A timed restore closed the pipe last run.
        if (!g_job_vptr_restored && g_job_hint_tick &&
            GetTickCount() - g_job_hint_tick > 2500)
            g_job_vptr_restored = true; // we never swapped vptr — do not WPM the job

        // Unpatch is now driven by the DLL sending ExtHookUnpatch after its
        // pump succeeded. No blind timer — that fired before the pump could
        // even run.
        if (g_injected && g_map_tick && !g_pipe.connected() && !g_pipe_warned &&
            GetTickCount() - g_map_tick > 10000) {
            g_pipe_warned = true;
            notify(L"Runtime", L"Module didn't connect — Hyperion likely blocked it");
            VT_ERR(L"no pipe after map — module never called back");
        }
        if (!g_rbx || !ProcessFinder::still_alive(g_rbx->pid)) {
            if (g_rbx) {
                if (g_pipe_pct > 0 && g_pipe_pct < 100) {
                    if (g_pipe_pct >= 80)
                        fail_progress(L"Roblox died while arming the lua pump. Rejoin and Attach again.");
                    else if (g_pipe_pct >= 45)
                        fail_progress(L"Roblox died after map, before READY. Hyperion likely killed the module.");
                    else
                        fail_progress(L"Roblox closed");
                } else {
                    VT_WARN(L"Roblox closed");
                }
                g_rpm.detach();
                g_rbx.reset();
                g_injected = false;
                g_mapped_pid = 0;
                g_map_tick = 0;
                g_pipe_warned = false;
                g_autoexec_done = false;
                g_mod_ready = false;
                g_iat_slot = 0;
                g_iat_stub = 0;
                g_iat_orig = 0;
                g_iat_restored = false;
                g_job_saved = 0;
                g_job_vptr_orig = 0;
                g_job_vptr_restored = false;
            }
            if (g_auto_attach) {
                if (ProcessFinder::find())
                    do_attach();
            }
        }
        return 0;
    case WM_HOTKEY:
        if (wp == ID_HOT_TOGGLE) {
            if (g_visible)
                hide_ui();
            else
                show_ui();
        }
        return 0;
    case WM_TRAY:
        if (lp == WM_LBUTTONUP) {
            if (g_visible)
                hide_ui();
            else
                show_ui();
        } else if (lp == WM_RBUTTONUP) {
            POINT pt{};
            GetCursorPos(&pt);
            HMENU m = CreatePopupMenu();
            AppendMenuW(m, MF_STRING, 1, L"Show");
            AppendMenuW(m, MF_STRING, 2, L"Hide");
            AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
            AppendMenuW(m, MF_STRING, 3, L"Exit");
            SetForegroundWindow(wnd);
            const int cmd = TrackPopupMenu(m, TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, wnd, nullptr);
            DestroyMenu(m);
            if (cmd == 1)
                show_ui();
            else if (cmd == 2)
                hide_ui();
            else if (cmd == 3)
                request_exit();
        }
        return 0;
    case WM_CLOSE:
        request_exit();
        return 0;
    case WM_SYSCOMMAND:
        if ((wp & 0xFFF0) == SC_CLOSE) {
            request_exit();
            return 0;
        }
        break;
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case ID_EXECUTE: do_execute(); break;
        case ID_CLEAR:
            click(H_CLEAR);
            break;
        case ID_OPEN: do_open(); break;
        case ID_SAVE: do_save(false); break;
        case ID_SAVEAS: do_save(true); break;
        case ID_NEWTAB: new_tab({}, L""); break;
        case ID_CLOSETAB: close_tab(); break;
        case ID_EDITOR:
            if (HIWORD(wp) == EN_CHANGE) {
                if (g_cur < (int)g_docs.size() && !g_docs[g_cur].dirty) {
                    g_docs[g_cur].dirty = true;
                }
                invalidate();
            }
            break;
        }
        return 0;
    case WM_CTLCOLOREDIT:
        SetTextColor((HDC)wp, kText);
        SetBkColor((HDC)wp, kEditor);
        return (LRESULT)g_brEdit;
    case WM_DESTROY:
        persist_tabs();
        g_rpm.detach();
        UnregisterHotKey(wnd, ID_HOT_TOGGLE);
        tray_del();
        g_pipe.stop();
        g_wnd = nullptr;
        KillTimer(wnd, 1);
        KillTimer(wnd, 2);
        KillTimer(wnd, 3);
        if (g_font) DeleteObject(g_font);
        if (g_fontSm) DeleteObject(g_fontSm);
        if (g_fontBd) DeleteObject(g_fontBd);
        if (g_fontTitle) DeleteObject(g_fontTitle);
        if (g_fontMono) DeleteObject(g_fontMono);
        if (g_brBg) DeleteObject(g_brBg);
        if (g_brEdit) DeleteObject(g_brEdit);
        if (g_brLog) DeleteObject(g_brLog);
        if (g_logo) DeleteObject(g_logo);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(wnd, msg, wp, lp);
}

} // namespace

static void vt_write_crash_file(const wchar_t* step, EXCEPTION_POINTERS* ep) {
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    wcscat_s(tmp, L"VoidTrace_crash.txt");
    HANDLE f = CreateFileW(tmp, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE)
        return;
    const DWORD code = ep->ExceptionRecord->ExceptionCode;
    const ULONG_PTR access_type = (ep->ExceptionRecord->NumberParameters >= 1)
        ? ep->ExceptionRecord->ExceptionInformation[0] : (ULONG_PTR)-1;
    const ULONG_PTR fault_addr  = (ep->ExceptionRecord->NumberParameters >= 2)
        ? ep->ExceptionRecord->ExceptionInformation[1] : (ULONG_PTR)-1;
    static const wchar_t* kAccess[] = {L"READ", L"WRITE", L"DEPEXEC"};
    const wchar_t* access_str = (access_type < 3) ? kAccess[access_type] : L"?";

    // Identify module containing the faulting instruction.
    HMODULE crash_mod = nullptr;
    wchar_t mod_path[MAX_PATH] = L"<unknown>";
    ULONG_PTR mod_base = 0;
    if (GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCWSTR)ep->ExceptionRecord->ExceptionAddress, &crash_mod) && crash_mod) {
        GetModuleFileNameW(crash_mod, mod_path, MAX_PATH);
        mod_base = (ULONG_PTR)crash_mod;
    }
    const ULONG_PTR rva = (ULONG_PTR)ep->ExceptionRecord->ExceptionAddress - mod_base;

    const CONTEXT* ctx = ep->ContextRecord;
    wchar_t line[1200];
    int n = swprintf_s(line,
        L"Step        : %s\r\n"
        L"Exception   : 0x%08X\r\n"
        L"Module      : %s\r\n"
        L"ModBase     : 0x%p\r\n"
        L"RVA         : 0x%llX\r\n"
        L"Instr Addr  : 0x%p\r\n"
        L"Access      : %s at 0x%p\r\n"
        L"RCX         : 0x%llX\r\n"
        L"RDX         : 0x%llX\r\n"
        L"R8          : 0x%llX\r\n"
        L"R9          : 0x%llX\r\n"
        L"RSP         : 0x%llX\r\n"
        L"InitStep    : %d\r\n"
        L"AttachStep  : %d\r\n",
        step, code,
        mod_path, (void*)mod_base, (ULONGLONG)rva,
        ep->ExceptionRecord->ExceptionAddress,
        access_str, (void*)fault_addr,
        ctx->Rcx, ctx->Rdx, ctx->R8, ctx->R9, ctx->Rsp,
        g_init_step, g_attach_step);
    DWORD written = 0;
    WriteFile(f, line, (DWORD)(n * sizeof(wchar_t)), &written, nullptr);
    CloseHandle(f);
}

static const wchar_t* vt_step_name() {
    static const wchar_t* kInitSteps[] = {
        L"enable_debug_privilege", L"Syscalls::init", L"Byovd::init",
        L"CallSpoof::init", L"Payload::seed", L"Config::load",
    };
    static const wchar_t* kAttachSteps[] = {
        L"ProcessFinder::find (pre-sync)", L"OffsetSync::refresh",
        L"ProcessFinder::find (post-sync)", L"World::attach",
        L"map_module (setup)",
        L"(unknown)", L"(unknown)", L"(unknown)", L"(unknown)", L"(unknown)",
        L"ProcessFinder::open", L"Injector::inject_embedded",
    };
    if (g_init_step >= 0 && g_init_step < 6)   return kInitSteps[g_init_step];
    if (g_attach_step >= 0 && g_attach_step < 12) return kAttachSteps[g_attach_step];
    return L"(unknown)";
}

static LONG WINAPI vt_veh_filter(EXCEPTION_POINTERS* ep) {
    const DWORD code = ep->ExceptionRecord->ExceptionCode;
    // Ignore first-chance debug / single-step / breakpoint exceptions
    if (code == EXCEPTION_BREAKPOINT || code == STATUS_SINGLE_STEP ||
        code == DBG_PRINTEXCEPTION_C || code == 0x406D1388u)
        return EXCEPTION_CONTINUE_SEARCH;
    static bool once = false;
    if (once) return EXCEPTION_CONTINUE_SEARCH;
    once = true;
    const wchar_t* step = vt_step_name();
    vt_write_crash_file(step, ep);
    wchar_t buf[512];
    swprintf_s(buf,
        L"VoidTrace crashed (VEH).\n\n"
        L"Step      : %s\n"
        L"Exception : 0x%08X\n"
        L"Address   : 0x%p\n\n"
        L"Crash log: %%TEMP%%\\VoidTrace_crash.txt",
        step,
        code,
        ep->ExceptionRecord->ExceptionAddress);
    MessageBoxW(nullptr, buf, L"VoidTrace — Fatal Error", MB_OK | MB_ICONSTOP | MB_SYSTEMMODAL);
    return EXCEPTION_CONTINUE_SEARCH;
}

static LONG WINAPI vt_crash_filter(EXCEPTION_POINTERS* ep) {
    const wchar_t* step = vt_step_name();
    vt_write_crash_file(step, ep);
    wchar_t buf[512];
    swprintf_s(buf,
        L"VoidTrace crashed.\n\n"
        L"Step      : %s\n"
        L"Exception : 0x%08X\n"
        L"Address   : 0x%p\n\n"
        L"Crash log: %%TEMP%%\\VoidTrace_crash.txt",
        step,
        ep->ExceptionRecord->ExceptionCode,
        ep->ExceptionRecord->ExceptionAddress);
    MessageBoxW(nullptr, buf, L"VoidTrace — Fatal Error", MB_OK | MB_ICONSTOP | MB_SYSTEMMODAL);
    return EXCEPTION_CONTINUE_SEARCH;
}

int App::run(HINSTANCE inst) {
    AddVectoredExceptionHandler(1, vt_veh_filter);
    SetUnhandledExceptionFilter(vt_crash_filter);
    HANDLE mtx = CreateMutexW(nullptr, TRUE, L"Local\\VoidTrace_4a9f2c7e");
    if (mtx && GetLastError() == ERROR_ALREADY_EXISTS) {
        HWND old = FindWindowW(kClass, L"Runtime Broker");
        if (old) {
            LONG_PTR ex = GetWindowLongPtrW(old, GWL_EXSTYLE);
            ex |= WS_EX_APPWINDOW;
            ex &= ~WS_EX_TOOLWINDOW;
            SetWindowLongPtrW(old, GWL_EXSTYLE, ex);
            ShowWindow(old, SW_RESTORE);
            SetForegroundWindow(old);
        }
        if (mtx)
            CloseHandle(mtx);
        return 0;
    }
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    Logger::instance().set_sink(log_sink);

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = wndproc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(RGB(7, 5, 14));
    wc.lpszClassName = kClass;
    wc.style = CS_DBLCLKS;
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    RegisterClassExW(&wc);

    HACCEL hacc = make_accels();
    const int sw = GetSystemMetrics(SM_CXSCREEN);
    const int sh = GetSystemMetrics(SM_CYSCREEN);
    const int ww = 960, wh = 580;
    HWND wnd = CreateWindowExW(WS_EX_APPWINDOW, kClass, L"Runtime Broker",
                               WS_POPUP | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_VISIBLE,
                               (sw - ww) / 2, (sh - wh) / 2, ww, wh,
                               nullptr, nullptr, inst, nullptr);
    if (!wnd) {
        MessageBoxW(nullptr, L"Window creation failed. Check that you are running as Administrator.",
                    L"VoidTrace", MB_OK | MB_ICONERROR);
        CoUninitialize();
        return 1;
    }
    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (hacc && TranslateAcceleratorW(wnd, hacc, &msg))
            continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    if (hacc)
        DestroyAcceleratorTable(hacc);
    CoUninitialize();
    return (int)msg.wParam;
}

} // namespace vt
