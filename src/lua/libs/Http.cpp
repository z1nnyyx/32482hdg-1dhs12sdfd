#include "lua/libs/Http.h"
#include "shared/Utils.h"

#include <Windows.h>
#include <winhttp.h>
#include <string>
#include <vector>

#pragma comment(lib, "winhttp.lib")

namespace vt::libs {
namespace {

void append_header(std::wstring& out, lua_State* L, int table, const char* key) {
    auto& a = LuaApi::instance();
    a.pushstring(L, key);
    a.gettable(L, table);
    if (a.type(L, -1) == LUA_TSTRING) {
        const char* v = a.tostring(L, -1);
        if (v && v[0]) {
            out += utf8_to_wide(key);
            out += L": ";
            out += utf8_to_wide(v);
            out += L"\r\n";
        }
    }
    a.pop(L, 1);
}

std::string field_string(lua_State* L, int table, const char* a, const char* b = nullptr) {
    auto& api = LuaApi::instance();
    api.pushstring(L, a);
    api.gettable(L, table);
    if (api.type(L, -1) != LUA_TSTRING && b) {
        api.pop(L, 1);
        api.pushstring(L, b);
        api.gettable(L, table);
    }
    std::string s;
    if (api.type(L, -1) == LUA_TSTRING)
        s = api.tostring(L, -1);
    api.pop(L, 1);
    return s;
}

bool http_exchange(const std::wstring& method,
                   const std::wstring& url,
                   const std::wstring& headers,
                   const std::string& body,
                   std::string& out,
                   DWORD& status) {
    status = 0;
    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256]{}, path[4096]{};
    uc.lpszHostName = host;
    uc.dwHostNameLength = 256;
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = 4096;
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &uc))
        return false;

    HINTERNET ses = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                                WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ses)
        return false;
    HINTERNET con = WinHttpConnect(ses, host, uc.nPort, 0);
    if (!con) {
        WinHttpCloseHandle(ses);
        return false;
    }
    DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET req = WinHttpOpenRequest(con, method.c_str(), path, nullptr,
                                       WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!req) {
        WinHttpCloseHandle(con);
        WinHttpCloseHandle(ses);
        return false;
    }

    LPCWSTR hdr = headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str();
    LPVOID data = body.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)body.data();
    DWORD dlen = (DWORD)body.size();
    BOOL ok = WinHttpSendRequest(req, hdr, headers.empty() ? 0 : (DWORD)-1L, data, dlen, dlen, 0) &&
              WinHttpReceiveResponse(req, nullptr);
    DWORD sz = sizeof(status);
    WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);
    if (ok) {
        for (;;) {
            DWORD avail = 0;
            if (!WinHttpQueryDataAvailable(req, &avail) || avail == 0)
                break;
            std::string chunk(avail, '\0');
            DWORD read = 0;
            if (!WinHttpReadData(req, chunk.data(), avail, &read))
                break;
            chunk.resize(read);
            out += chunk;
        }
    }
    WinHttpCloseHandle(req);
    WinHttpCloseHandle(con);
    WinHttpCloseHandle(ses);
    return ok;
}

int l_httpget(lua_State* L) {
    auto& a = LuaApi::instance();
    int idx = 1;
    if (a.type(L, 1) != LUA_TSTRING && a.gettop(L) >= 2 && a.type(L, 2) == LUA_TSTRING)
        idx = 2;
    const std::string url8 = a.tostring(L, idx);
    std::string body;
    DWORD status = 0;
    if (!http_exchange(L"GET", utf8_to_wide(url8), {}, {}, body, status)) {
        a.pushnil(L);
        a.pushstring(L, "request failed");
        return 2;
    }
    a.pushlstring(L, body.data(), body.size());
    return 1;
}

int l_request(lua_State* L) {
    auto& a = LuaApi::instance();
    if (a.type(L, 1) != LUA_TTABLE) {
        a.pushnil(L);
        a.pushstring(L, "request expects a table");
        return 2;
    }

    const std::string url8 = field_string(L, 1, "Url", "url");
    std::string method8 = field_string(L, 1, "Method", "method");
    if (method8.empty())
        method8 = "GET";
    for (char& c : method8)
        if (c >= 'a' && c <= 'z')
            c = (char)(c - 32);

    size_t blen = 0;
    std::string body;
    a.pushstring(L, "Body");
    a.gettable(L, 1);
    if (a.type(L, -1) != LUA_TSTRING) {
        a.pop(L, 1);
        a.pushstring(L, "body");
        a.gettable(L, 1);
    }
    if (a.type(L, -1) == LUA_TSTRING) {
        const char* p = a.tolstring(L, -1, &blen);
        body.assign(p ? p : "", blen);
    }
    a.pop(L, 1);

    std::wstring headers;
    a.pushstring(L, "Headers");
    a.gettable(L, 1);
    if (a.type(L, -1) != LUA_TTABLE) {
        a.pop(L, 1);
        a.pushstring(L, "headers");
        a.gettable(L, 1);
    }
    const int hdr = a.gettop(L);
    if (a.type(L, hdr) == LUA_TTABLE) {
        static const char* keys[] = {
            "Content-Type", "content-type", "Authorization", "authorization",
            "User-Agent", "user-agent", "Accept", "accept", "Cookie", "cookie",
            "X-Requested-With", "Referer", "referer"
        };
        for (auto* k : keys)
            append_header(headers, L, hdr, k);
    }
    a.pop(L, 1);

    std::string out;
    DWORD status = 0;
    http_exchange(utf8_to_wide(method8), utf8_to_wide(url8), headers, body, out, status);

    a.newtable(L);
    a.pushstring(L, "Body");
    a.pushlstring(L, out.data(), out.size());
    a.settable(L, -3);
    a.pushstring(L, "StatusCode");
    a.pushnumber(L, (lua_Number)status);
    a.settable(L, -3);
    a.pushstring(L, "StatusMessage");
    a.pushstring(L, status >= 200 && status < 300 ? "OK" : "HTTP");
    a.settable(L, -3);
    a.pushstring(L, "Success");
    a.pushboolean(L, status >= 200 && status < 300 ? 1 : 0);
    a.settable(L, -3);
    a.pushstring(L, "Headers");
    a.newtable(L);
    a.settable(L, -3);
    return 1;
}

} // namespace

void register_http(lua_State* L) {
    auto& a = LuaApi::instance();
    a.pushcfunction(L, l_httpget, "httpget");
    a.setglobal(L, "httpget");
    a.pushcfunction(L, l_httpget, "httpgetasync");
    a.setglobal(L, "httpgetasync");
    a.pushcfunction(L, l_httpget, "gamehttpget");
    a.setglobal(L, "gamehttpget");
    a.pushcfunction(L, l_request, "request");
    a.setglobal(L, "request");
    a.pushcfunction(L, l_request, "http_request");
    a.setglobal(L, "http_request");
}

} // namespace vt::libs
