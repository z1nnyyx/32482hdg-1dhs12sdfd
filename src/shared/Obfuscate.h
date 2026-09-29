#pragma once

#include <string>
#include <cstdint>

// Compile-time XOR string obfuscation.
// String literals encrypted in the binary; decoded only when str() is called.
// Requires C++17 or later (constexpr ctor with loops).
//
// Usage:
//   auto name = OBF("NtCreateThreadEx");    // std::string
//   auto path = WOBF(L"ntdll.dll");         // std::wstring

namespace vt::obf {

constexpr uint8_t kKey = 0xB3;

template<size_t N>
struct XorStr {
    char data[N]{};
    constexpr XorStr(const char (&s)[N]) noexcept {
        for (size_t i = 0; i < N; ++i)
            data[i] = static_cast<char>(static_cast<uint8_t>(s[i]) ^ kKey);
    }
    std::string str() const {
        std::string out(N - 1, '\0');
        for (size_t i = 0; i < N - 1; ++i)
            out[i] = static_cast<char>(static_cast<uint8_t>(data[i]) ^ kKey);
        return out;
    }
    // Convenience: call into APIs that take const char*
    // Use str().c_str() — never store the raw pointer.
};

template<size_t N>
struct XorWStr {
    wchar_t data[N]{};
    constexpr XorWStr(const wchar_t (&s)[N]) noexcept {
        for (size_t i = 0; i < N; ++i)
            data[i] = static_cast<wchar_t>(static_cast<uint16_t>(s[i]) ^ kKey);
    }
    std::wstring str() const {
        std::wstring out(N - 1, L'\0');
        for (size_t i = 0; i < N - 1; ++i)
            out[i] = static_cast<wchar_t>(static_cast<uint16_t>(data[i]) ^ kKey);
        return out;
    }
};

} // namespace vt::obf

#define OBF(s)  (::vt::obf::XorStr<sizeof(s)>(s).str())
#define WOBF(s) (::vt::obf::XorWStr<sizeof(s)/sizeof(wchar_t)>(s).str())
