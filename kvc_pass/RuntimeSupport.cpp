#include "RuntimeSupport.h"

#include <intrin.h>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <exception>
#include <iterator>

#pragma function(memchr, memcmp, memcpy, memmove, memset, strlen, strcmp, strncmp, wcslen, wcscmp)

extern "C"
{
    int __isa_available = 1;

    int __cdecl __isa_available_init()
    {
        // The project is built for baseline SSE2. Keep the compiler's dispatch value deterministic.
        __isa_available = 1;
        return 1;
    }

    int __cdecl memcmp(const void* left, const void* right, std::size_t count)
    {
        const auto* a = static_cast<const unsigned char*>(left);
        const auto* b = static_cast<const unsigned char*>(right);
        for (std::size_t i = 0; i < count; ++i)
        {
            if (a[i] != b[i])
                return (a[i] < b[i]) ? -1 : 1;
        }
        return 0;
    }

    const void* __cdecl memchr(const void* memory, int value, std::size_t count)
    {
        const auto* bytes = static_cast<const unsigned char*>(memory);
        const auto wanted = static_cast<unsigned char>(value);
        for (std::size_t i = 0; i < count; ++i)
        {
            if (bytes[i] == wanted)
                return bytes + i;
        }
        return nullptr;
    }

    void* __cdecl memcpy(void* destination, const void* source, std::size_t count)
    {
        __movsb(static_cast<unsigned char*>(destination),
                static_cast<const unsigned char*>(source), count);
        return destination;
    }

    void* __cdecl memmove(void* destination, const void* source, std::size_t count)
    {
        auto* destinationBytes = static_cast<unsigned char*>(destination);
        const auto* sourceBytes = static_cast<const unsigned char*>(source);
        if (destinationBytes <= sourceBytes || destinationBytes >= sourceBytes + count)
        {
            __movsb(destinationBytes, sourceBytes, count);
            return destination;
        }

        for (std::size_t i = count; i > 0; --i)
            destinationBytes[i - 1] = sourceBytes[i - 1];
        return destination;
    }

    void* __cdecl memset(void* destination, int value, std::size_t count)
    {
        __stosb(static_cast<unsigned char*>(destination),
                static_cast<unsigned char>(value), count);
        return destination;
    }

    std::size_t __cdecl strlen(const char* value)
    {
        const char* cursor = value;
        while (*cursor)
            ++cursor;
        return static_cast<std::size_t>(cursor - value);
    }

    int __cdecl strcmp(const char* left, const char* right)
    {
        while (*left && *left == *right)
        {
            ++left;
            ++right;
        }
        return static_cast<unsigned char>(*left) - static_cast<unsigned char>(*right);
    }

    int __cdecl strncmp(const char* left, const char* right, std::size_t count)
    {
        for (std::size_t i = 0; i < count; ++i)
        {
            const auto a = static_cast<unsigned char>(left[i]);
            const auto b = static_cast<unsigned char>(right[i]);
            if (a != b || a == 0)
                return static_cast<int>(a) - static_cast<int>(b);
        }
        return 0;
    }

    std::size_t __cdecl wcslen(const wchar_t* value)
    {
        const wchar_t* cursor = value;
        while (*cursor)
            ++cursor;
        return static_cast<std::size_t>(cursor - value);
    }

    int __cdecl wcscmp(const wchar_t* left, const wchar_t* right)
    {
        while (*left && *left == *right)
        {
            ++left;
            ++right;
        }
        return (*left < *right) ? -1 : ((*left > *right) ? 1 : 0);
    }

    void __cdecl _invalid_parameter_noinfo()
    {
        TerminateProcess(GetCurrentProcess(), static_cast<UINT>(STATUS_INVALID_PARAMETER));
        __fastfail(FAST_FAIL_INVALID_ARG);
    }

    __declspec(noreturn) void __cdecl _invalid_parameter_noinfo_noreturn()
    {
        TerminateProcess(GetCurrentProcess(), static_cast<UINT>(STATUS_INVALID_PARAMETER));
        __fastfail(FAST_FAIL_INVALID_ARG);
    }

    __declspec(noreturn) void __cdecl _invalid_parameter(const wchar_t*, const wchar_t*,
                                                         const wchar_t*, unsigned int,
                                                         std::uintptr_t)
    {
        _invalid_parameter_noinfo_noreturn();
    }

    __declspec(noreturn) void __cdecl abort()
    {
        TerminateProcess(GetCurrentProcess(), static_cast<UINT>(STATUS_FATAL_APP_EXIT));
        __fastfail(FAST_FAIL_FATAL_APP_EXIT);
    }

    [[noreturn]] void __cdecl __std_terminate()
    {
        abort();
    }

    __declspec(noreturn) void __stdcall _CxxThrowException(void*, _ThrowInfo*) noexcept(false)
    {
        abort();
    }
}

namespace std
{
    _Prhand _Raise_handler = nullptr;

    [[noreturn]] void __cdecl _Xlength_error(const char*)
    {
        abort();
    }

    [[noreturn]] void __cdecl _Xout_of_range(const char*)
    {
        abort();
    }
}

namespace
{
    [[noreturn]] void OutOfMemory()
    {
        TerminateProcess(GetCurrentProcess(), static_cast<UINT>(STATUS_NO_MEMORY));
        __fastfail(FAST_FAIL_FATAL_APP_EXIT);
    }
}

void* operator new(std::size_t size)
{
    if (size == 0)
        size = 1;
    if (void* memory = HeapAlloc(GetProcessHeap(), 0, size))
        return memory;
    OutOfMemory();
}

void* operator new[](std::size_t size)
{
    return ::operator new(size);
}

void* operator new(std::size_t size, const std::nothrow_t&) noexcept
{
    if (size == 0)
        size = 1;
    return HeapAlloc(GetProcessHeap(), 0, size);
}

void* operator new[](std::size_t size, const std::nothrow_t&) noexcept
{
    return ::operator new(size, std::nothrow);
}

void operator delete(void* memory) noexcept
{
    if (memory)
        HeapFree(GetProcessHeap(), 0, memory);
}

void operator delete[](void* memory) noexcept
{
    ::operator delete(memory);
}

void operator delete(void* memory, std::size_t) noexcept
{
    ::operator delete(memory);
}

void operator delete[](void* memory, std::size_t) noexcept
{
    ::operator delete(memory);
}

namespace kvc::text
{
    std::string WideToUtf8(std::wstring_view value)
    {
        if (value.empty())
            return {};

        const int required = WideCharToMultiByte(CP_UTF8, 0, value.data(),
                                                 static_cast<int>(value.size()),
                                                 nullptr, 0, nullptr, nullptr);
        if (required <= 0)
            return {};

        std::string result(static_cast<std::size_t>(required), '\0');
        WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                            result.data(), required, nullptr, nullptr);
        return result;
    }

    std::wstring Utf8ToWide(std::string_view value)
    {
        if (value.empty())
            return {};

        const int required = MultiByteToWideChar(CP_UTF8, 0, value.data(),
                                                 static_cast<int>(value.size()),
                                                 nullptr, 0);
        if (required <= 0)
            return {};

        std::wstring result(static_cast<std::size_t>(required), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                            result.data(), required);
        return result;
    }

    bool ParseUnsigned(std::string_view value, unsigned base, std::uint64_t& result) noexcept
    {
        if (value.empty() || base < 2 || base > 36)
            return false;

        std::uint64_t accumulator = 0;
        for (char character : value)
        {
            unsigned digit = 0;
            if (character >= '0' && character <= '9')
                digit = static_cast<unsigned>(character - '0');
            else if (character >= 'a' && character <= 'z')
                digit = static_cast<unsigned>(character - 'a') + 10U;
            else if (character >= 'A' && character <= 'Z')
                digit = static_cast<unsigned>(character - 'A') + 10U;
            else
                return false;

            if (digit >= base || accumulator > (UINT64_MAX - digit) / base)
                return false;
            accumulator = accumulator * base + digit;
        }

        result = accumulator;
        return true;
    }

    bool ParseInt(std::string_view value, int& result) noexcept
    {
        if (value.empty())
            return false;

        bool negative = false;
        if (value.front() == '-' || value.front() == '+')
        {
            negative = value.front() == '-';
            value.remove_prefix(1);
        }

        std::uint64_t magnitude = 0;
        if (!ParseUnsigned(value, 10, magnitude))
            return false;
        if (negative ? magnitude > 2147483648ULL : magnitude > 2147483647ULL)
            return false;

        result = negative ? -static_cast<int>(magnitude) : static_cast<int>(magnitude);
        return true;
    }

    void AppendUnsigned(std::string& output, std::uint64_t value, unsigned base,
                        unsigned minDigits, bool lowercase)
    {
        char buffer[65];
        const char* alphabet = lowercase ? "0123456789abcdefghijklmnopqrstuvwxyz"
                                         : "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        std::size_t count = 0;
        do
        {
            buffer[count++] = alphabet[value % base];
            value /= base;
        } while (value != 0);

        while (count < minDigits)
            buffer[count++] = '0';

        while (count > 0)
            output.push_back(buffer[--count]);
    }

    void AppendSigned(std::string& output, std::int64_t value)
    {
        if (value < 0)
        {
            output.push_back('-');
            const auto magnitude = static_cast<std::uint64_t>(-(value + 1)) + 1;
            AppendUnsigned(output, magnitude);
        }
        else
        {
            AppendUnsigned(output, static_cast<std::uint64_t>(value));
        }
    }

    void AppendHex(std::string& output, std::uint64_t value, bool prefix,
                   unsigned minDigits, bool lowercase)
    {
        if (prefix)
            output.append("0x");
        AppendUnsigned(output, value, 16, minDigits, lowercase);
    }

    bool IEqualsAscii(std::string_view left, std::string_view right) noexcept
    {
        if (left.size() != right.size())
            return false;
        for (std::size_t i = 0; i < left.size(); ++i)
        {
            char a = left[i];
            char b = right[i];
            if (a >= 'A' && a <= 'Z')
                a = static_cast<char>(a + ('a' - 'A'));
            if (b >= 'A' && b <= 'Z')
                b = static_cast<char>(b + ('a' - 'A'));
            if (a != b)
                return false;
        }
        return true;
    }

    bool IEqualsWide(std::wstring_view left, std::wstring_view right) noexcept
    {
        if (left.size() != right.size())
            return false;
        for (std::size_t i = 0; i < left.size(); ++i)
        {
            wchar_t a = left[i];
            wchar_t b = right[i];
            if (a >= L'A' && a <= L'Z')
                a = static_cast<wchar_t>(a + (L'a' - L'A'));
            if (b >= L'A' && b <= L'Z')
                b = static_cast<wchar_t>(b + (L'a' - L'A'));
            if (a != b)
                return false;
        }
        return true;
    }

    bool Contains(std::wstring_view value, std::wstring_view needle) noexcept
    {
        if (needle.empty())
            return true;
        if (needle.size() > value.size())
            return false;
        for (std::size_t i = 0; i <= value.size() - needle.size(); ++i)
        {
            if (value.substr(i, needle.size()) == needle)
                return true;
        }
        return false;
    }

    bool StartsWith(std::string_view value, std::string_view prefix) noexcept
    {
        return value.size() >= prefix.size() && value.substr(0, prefix.size()) == prefix;
    }

    void LowerAsciiInPlace(std::string& value) noexcept
    {
        for (char& character : value)
        {
            if (character >= 'A' && character <= 'Z')
                character = static_cast<char>(character + ('a' - 'A'));
        }
    }

    void LowerWideInPlace(std::wstring& value) noexcept
    {
        for (wchar_t& character : value)
        {
            if (character >= L'A' && character <= L'Z')
                character = static_cast<wchar_t>(character + (L'a' - L'A'));
        }
    }

    std::string TrimNulTerminator(std::string value)
    {
        if (!value.empty() && value.back() == '\0')
            value.pop_back();
        return value;
    }
}

namespace kvc::paths
{
    namespace
    {
        bool IsSeparator(wchar_t character) noexcept
        {
            return character == L'\\' || character == L'/';
        }

        bool IsAbsolute(std::wstring_view path) noexcept
        {
            if (path.size() >= 2 && IsSeparator(path[0]) && IsSeparator(path[1]))
                return true;
            return path.size() >= 3 && ((path[0] >= L'A' && path[0] <= L'Z') ||
                                        (path[0] >= L'a' && path[0] <= L'z')) &&
                   path[1] == L':' && IsSeparator(path[2]);
        }
    }

    std::wstring Join(std::wstring_view left, std::wstring_view right)
    {
        if (left.empty() || IsAbsolute(right))
            return std::wstring(right);
        if (right.empty())
            return std::wstring(left);

        std::wstring result(left);
        if (!IsSeparator(result.back()) && !IsSeparator(right.front()))
            result.push_back(L'\\');
        result.append(right);
        return result;
    }

    std::wstring FileName(std::wstring_view path)
    {
        while (!path.empty() && IsSeparator(path.back()))
            path.remove_suffix(1);
        if (path.empty())
            return {};

        std::size_t separator = path.size();
        while (separator > 0 && !IsSeparator(path[separator - 1]))
            --separator;
        return std::wstring(path.substr(separator));
    }

    std::wstring Parent(std::wstring_view path)
    {
        while (!path.empty() && IsSeparator(path.back()))
            path.remove_suffix(1);
        if (path.empty())
            return {};

        std::size_t separator = path.size();
        while (separator > 0 && !IsSeparator(path[separator - 1]))
            --separator;
        if (separator == 0)
            return {};
        if (separator == 1)
            return std::wstring(path.substr(0, 1));
        if (separator == 3 && path[1] == L':')
            return std::wstring(path.substr(0, 3));
        return std::wstring(path.substr(0, separator - 1));
    }

    std::wstring CurrentDirectory()
    {
        const DWORD required = GetCurrentDirectoryW(0, nullptr);
        if (required == 0)
            return {};
        std::wstring result(required, L'\0');
        const DWORD written = GetCurrentDirectoryW(required, result.data());
        if (written == 0 || written >= required)
            return {};
        result.resize(written);
        return result;
    }

    std::wstring Absolute(std::wstring_view path)
    {
        if (path.empty())
            return CurrentDirectory();

        const DWORD required = GetFullPathNameW(std::wstring(path).c_str(), 0, nullptr, nullptr);
        if (required == 0)
            return std::wstring(path);

        std::wstring result(required, L'\0');
        const DWORD written = GetFullPathNameW(std::wstring(path).c_str(), required,
                                               result.data(), nullptr);
        if (written == 0 || written >= required)
            return std::wstring(path);
        result.resize(written);
        return result;
    }

    bool Exists(std::wstring_view path) noexcept
    {
        return !path.empty() && GetFileAttributesW(std::wstring(path).c_str()) != INVALID_FILE_ATTRIBUTES;
    }

    bool FileExists(std::wstring_view path) noexcept
    {
        const DWORD attributes = path.empty() ? INVALID_FILE_ATTRIBUTES
                                              : GetFileAttributesW(std::wstring(path).c_str());
        return attributes != INVALID_FILE_ATTRIBUTES &&
               (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
    }

    bool DirectoryExists(std::wstring_view path) noexcept
    {
        const DWORD attributes = path.empty() ? INVALID_FILE_ATTRIBUTES
                                              : GetFileAttributesW(std::wstring(path).c_str());
        return attributes != INVALID_FILE_ATTRIBUTES &&
               (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    }

    bool EnsureDirectory(std::wstring_view path) noexcept
    {
        if (path.empty())
            return false;
        if (DirectoryExists(path))
            return true;

        std::wstring normalized(path);
        for (wchar_t& character : normalized)
        {
            if (character == L'/')
                character = L'\\';
        }
        while (!normalized.empty() && normalized.back() == L'\\')
            normalized.pop_back();

        for (std::size_t i = 0; i < normalized.size(); ++i)
        {
            if (normalized[i] != L'\\')
                continue;
            if (i == 2 && normalized[1] == L':')
                continue;

            const std::wstring prefix = normalized.substr(0, i);
            if (!prefix.empty() && !DirectoryExists(prefix))
            {
                if (!CreateDirectoryW(prefix.c_str(), nullptr) &&
                    GetLastError() != ERROR_ALREADY_EXISTS)
                    return false;
            }
        }

        if (!CreateDirectoryW(normalized.c_str(), nullptr) &&
            GetLastError() != ERROR_ALREADY_EXISTS)
            return false;
        return DirectoryExists(normalized);
    }

    std::vector<std::wstring> EnumerateDirectories(std::wstring_view path)
    {
        std::vector<std::wstring> result;
        if (!DirectoryExists(path))
            return result;

        const std::wstring searchPath = Join(path, L"*");
        WIN32_FIND_DATAW entry{};
        HANDLE find = FindFirstFileExW(searchPath.c_str(), FindExInfoBasic, &entry,
                                       FindExSearchLimitToDirectories, nullptr,
                                       FIND_FIRST_EX_LARGE_FETCH);
        if (find == INVALID_HANDLE_VALUE)
            return result;

        do
        {
            if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
                continue;
            if (entry.cFileName[0] == L'.' &&
                (entry.cFileName[1] == L'\0' ||
                 (entry.cFileName[1] == L'.' && entry.cFileName[2] == L'\0')))
                continue;
            result.push_back(Join(path, entry.cFileName));
        } while (FindNextFileW(find, &entry));

        FindClose(find);
        return result;
    }
}

namespace kvc::io
{
    namespace
    {
        class FileHandle
        {
        public:
            explicit FileHandle(HANDLE handle = INVALID_HANDLE_VALUE) noexcept : m_handle(handle) {}
            ~FileHandle() noexcept
            {
                if (m_handle != INVALID_HANDLE_VALUE)
                    CloseHandle(m_handle);
            }

            FileHandle(const FileHandle&) = delete;
            FileHandle& operator=(const FileHandle&) = delete;

            HANDLE Get() const noexcept { return m_handle; }
            bool IsValid() const noexcept { return m_handle != INVALID_HANDLE_VALUE; }

        private:
            HANDLE m_handle;
        };
    }

    bool ReadAllBytes(std::wstring_view path, std::vector<std::uint8_t>& data) noexcept
    {
        const std::wstring nativePath(path);
        FileHandle file(CreateFileW(nativePath.c_str(), GENERIC_READ,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (!file.IsValid())
            return false;

        LARGE_INTEGER size{};
        if (!GetFileSizeEx(file.Get(), &size) || size.QuadPart < 0 ||
            static_cast<std::uint64_t>(size.QuadPart) > SIZE_MAX)
            return false;

        data.resize(static_cast<std::size_t>(size.QuadPart));
        std::size_t offset = 0;
        while (offset < data.size())
        {
            const DWORD chunk = static_cast<DWORD>(
                (data.size() - offset > MAXDWORD) ? MAXDWORD : data.size() - offset);
            DWORD read = 0;
            if (!ReadFile(file.Get(), data.data() + offset, chunk, &read, nullptr) || read == 0)
                return false;
            offset += read;
        }
        return true;
    }

    bool ReadAllText(std::wstring_view path, std::string& text) noexcept
    {
        std::vector<std::uint8_t> bytes;
        if (!ReadAllBytes(path, bytes))
            return false;
        text.assign(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        return true;
    }

    bool WriteAllBytes(std::wstring_view path, const void* data, std::size_t size) noexcept
    {
        const std::wstring nativePath(path);
        FileHandle file(CreateFileW(nativePath.c_str(), GENERIC_WRITE, 0, nullptr,
                                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (!file.IsValid())
            return false;

        const auto* bytes = static_cast<const std::uint8_t*>(data);
        std::size_t offset = 0;
        while (offset < size)
        {
            const DWORD chunk = static_cast<DWORD>(
                (size - offset > MAXDWORD) ? MAXDWORD : size - offset);
            DWORD written = 0;
            if (!WriteFile(file.Get(), bytes + offset, chunk, &written, nullptr) ||
                written == 0)
                return false;
            offset += written;
        }
        return true;
    }

    bool WriteAllText(std::wstring_view path, std::string_view text) noexcept
    {
        return WriteAllBytes(path, text.data(), text.size());
    }

    bool WriteAllText(std::wstring_view path, std::wstring_view text) noexcept
    {
        const std::string utf8 = text::WideToUtf8(text);
        return WriteAllBytes(path, utf8.data(), utf8.size());
    }
}

namespace kvc::console
{
    void WriteUtf8(HANDLE handle, std::string_view text) noexcept
    {
        WriteWide(handle, text::Utf8ToWide(text));
    }

    void WriteWide(HANDLE handle, std::wstring_view text) noexcept
    {
        if (handle == nullptr || handle == INVALID_HANDLE_VALUE || text.empty())
            return;

        DWORD mode = 0;
        if (GetConsoleMode(handle, &mode))
        {
            std::size_t offset = 0;
            while (offset < text.size())
            {
                const DWORD chunk = static_cast<DWORD>(
                    (text.size() - offset > 32767) ? 32767 : text.size() - offset);
                DWORD written = 0;
                if (!WriteConsoleW(handle, text.data() + offset, chunk, &written, nullptr) ||
                    written == 0)
                    return;
                offset += written;
            }
            return;
        }

        const std::string utf8 = text::WideToUtf8(text);
        std::size_t offset = 0;
        while (offset < utf8.size())
        {
            const DWORD chunk = static_cast<DWORD>(
                (utf8.size() - offset > MAXDWORD) ? MAXDWORD : utf8.size() - offset);
            DWORD written = 0;
            if (!WriteFile(handle, utf8.data() + offset, chunk, &written, nullptr) ||
                written == 0)
                return;
            offset += written;
        }
    }

    void WriteUtf8(std::string_view text) noexcept
    {
        WriteUtf8(GetStdHandle(STD_OUTPUT_HANDLE), text);
    }

    void WriteWide(std::wstring_view text) noexcept
    {
        WriteWide(GetStdHandle(STD_OUTPUT_HANDLE), text);
    }

    void WriteRepeatedWide(HANDLE handle, wchar_t value, std::size_t count) noexcept
    {
        wchar_t block[64];
        for (wchar_t& character : block)
            character = value;

        while (count > 0)
        {
            const std::size_t chunk = count < std::size(block) ? count : std::size(block);
            WriteWide(handle, std::wstring_view(block, chunk));
            count -= chunk;
        }
    }
}
