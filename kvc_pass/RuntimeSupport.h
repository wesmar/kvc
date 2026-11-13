#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>
#include <cstdint>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

namespace kvc
{
    namespace text
    {
        std::string WideToUtf8(std::wstring_view value);
        std::wstring Utf8ToWide(std::string_view value);

        bool ParseUnsigned(std::string_view value, unsigned base, std::uint64_t& result) noexcept;
        bool ParseInt(std::string_view value, int& result) noexcept;

        void AppendUnsigned(std::string& output, std::uint64_t value, unsigned base = 10,
                            unsigned minDigits = 0, bool lowercase = true);
        void AppendSigned(std::string& output, std::int64_t value);
        void AppendHex(std::string& output, std::uint64_t value, bool prefix = false,
                       unsigned minDigits = 0, bool lowercase = true);

        bool IEqualsAscii(std::string_view left, std::string_view right) noexcept;
        bool IEqualsWide(std::wstring_view left, std::wstring_view right) noexcept;
        bool Contains(std::wstring_view value, std::wstring_view needle) noexcept;
        bool StartsWith(std::string_view value, std::string_view prefix) noexcept;
        void LowerAsciiInPlace(std::string& value) noexcept;
        void LowerWideInPlace(std::wstring& value) noexcept;
        std::string TrimNulTerminator(std::string value);
    }

    namespace paths
    {
        std::wstring Join(std::wstring_view left, std::wstring_view right);
        std::wstring FileName(std::wstring_view path);
        std::wstring Parent(std::wstring_view path);
        std::wstring CurrentDirectory();
        std::wstring Absolute(std::wstring_view path);

        bool Exists(std::wstring_view path) noexcept;
        bool FileExists(std::wstring_view path) noexcept;
        bool DirectoryExists(std::wstring_view path) noexcept;
        bool EnsureDirectory(std::wstring_view path) noexcept;
        std::vector<std::wstring> EnumerateDirectories(std::wstring_view path);
    }

    namespace io
    {
        bool ReadAllBytes(std::wstring_view path, std::vector<std::uint8_t>& data) noexcept;
        bool ReadAllText(std::wstring_view path, std::string& text) noexcept;
        bool WriteAllBytes(std::wstring_view path, const void* data, std::size_t size) noexcept;
        bool WriteAllText(std::wstring_view path, std::string_view text) noexcept;
        bool WriteAllText(std::wstring_view path, std::wstring_view text) noexcept;
    }

    namespace console
    {
        void WriteUtf8(std::string_view text) noexcept;
        void WriteWide(std::wstring_view text) noexcept;
        void WriteUtf8(HANDLE handle, std::string_view text) noexcept;
        void WriteWide(HANDLE handle, std::wstring_view text) noexcept;
        void WriteRepeatedWide(HANDLE handle, wchar_t value, std::size_t count) noexcept;
    }
}
