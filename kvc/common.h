// common.h
// Common definitions, utilities and includes for KVC Framework

#pragma once

#include <Windows.h>
#include <winternl.h>
#include <DbgHelp.h>
#include <Shellapi.h>
#include <Shlobj.h>
#include <accctrl.h>
#include <aclapi.h>
#include <wincrypt.h>
#include <iostream>
#include <string>
#include <optional>
#include <sstream>
#include <array>
#include <chrono>
#include <memory>
#include <vector>
#include <algorithm>
#include <iomanip>
#include <filesystem>

#pragma comment(lib, "crypt32.lib")

// Session management constants
inline constexpr int MAX_SESSIONS = 16;

#ifdef BUILD_DATE
    #define __DATE__ BUILD_DATE
#endif

#ifdef BUILD_TIME  
    #define __TIME__ BUILD_TIME
#endif

#define kvc_DEBUG_ENABLED 0

#ifdef ERROR
#undef ERROR
#endif

#ifndef SHTDN_REASON_MAJOR_SOFTWARE
#define SHTDN_REASON_MAJOR_SOFTWARE 0x00030000
#endif

#ifndef SHTDN_REASON_MINOR_RECONFIGURE  
#define SHTDN_REASON_MINOR_RECONFIGURE 0x00000004
#endif

// Smart module handle management

// Custom deleter for HMODULE with FreeLibrary
struct ModuleDeleter {
    void operator()(HMODULE mod) const noexcept {
        if (mod) {
            FreeLibrary(mod);
        }
    }
};

// Custom deleter for system modules (no cleanup needed)
struct SystemModuleDeleter {
    void operator()(HMODULE) const noexcept {
        // System modules obtained via GetModuleHandle don't need to be freed
    }
};

using ModuleHandle = std::unique_ptr<std::remove_pointer_t<HMODULE>, ModuleDeleter>;
using SystemModuleHandle = std::unique_ptr<std::remove_pointer_t<HMODULE>, SystemModuleDeleter>;

// ============================================================================
// RAII GUARDS FOR WINDOWS RESOURCES
//
// All guards are aliases of a single policy-based template WinHandle<Policy>.
//
// Why Policy structs instead of NTTP NullValue?
//   INVALID_HANDLE_VALUE is (HANDLE)(LONG_PTR)(-1) — a reinterpret_cast —
//   which the C++ standard forbids as a non-type template argument for pointer
//   types. A Policy struct sidesteps this entirely: null sentinel, validity
//   check, and close function are bundled in one type, resolved at compile
//   time with zero runtime cost.
//
// Each Policy must provide:
//   handle_type              — the Win32 handle typedef
//   static handle_type null_value() noexcept   — the "empty" sentinel
//   static bool        is_null(handle_type)    — true when no resource held
//   static void        close(handle_type)      — release the resource
// ============================================================================

// ---------------------------------------------------------------------------
// Policy definitions
// ---------------------------------------------------------------------------

// Generic kernel-object HANDLE (OpenProcess, OpenThread, CreateEvent, ...).
// Treats both nullptr AND INVALID_HANDLE_VALUE as null — because some APIs
// return nullptr on failure and others return INVALID_HANDLE_VALUE, and
// CloseHandle on either form is undefined on some Windows builds.
struct HandlePolicy {
    using handle_type = HANDLE;
    // null_value() is constexpr (returns nullptr literal).
    // is_null() is NOT constexpr: INVALID_HANDLE_VALUE is (void*)(LONG_PTR)(-1),
    // a reinterpret_cast, which the standard forbids in constant expressions.
    static constexpr HANDLE null_value() noexcept { return nullptr; }
    static bool is_null(HANDLE h) noexcept {
        return h == nullptr || h == INVALID_HANDLE_VALUE;
    }
    static void close(HANDLE h) noexcept { CloseHandle(h); }
};

// CreateFile / CreateToolhelp32Snapshot.
// These APIs never return nullptr — only INVALID_HANDLE_VALUE on failure.
// CloseHandle(nullptr) is UB; using INVALID_HANDLE_VALUE as the sole sentinel
// keeps the guard honest about what it actually protects.
// Neither null_value() nor is_null() can be constexpr (reinterpret_cast).
struct FilePolicy {
    using handle_type = HANDLE;
    static HANDLE null_value() noexcept { return INVALID_HANDLE_VALUE; }
    static bool   is_null(HANDLE h) noexcept { return h == INVALID_HANDLE_VALUE; }
    static void   close(HANDLE h)   noexcept { CloseHandle(h); }
};

// HKEY from RegOpenKeyEx / RegCreateKeyEx.
struct RegKeyPolicy {
    using handle_type = HKEY;
    static constexpr HKEY null_value() noexcept { return nullptr; }
    static constexpr bool is_null(HKEY h) noexcept { return h == nullptr; }
    static void close(HKEY h) noexcept { RegCloseKey(h); }
};

// SC_HANDLE from OpenSCManager / OpenService / CreateService.
struct SCHandlePolicy {
    using handle_type = SC_HANDLE;
    static constexpr SC_HANDLE null_value() noexcept { return nullptr; }
    static constexpr bool      is_null(SC_HANDLE h) noexcept { return h == nullptr; }
    static void                close(SC_HANDLE h)   noexcept { CloseServiceHandle(h); }
};

// ---------------------------------------------------------------------------
// WinHandle<Policy> — single template, all guards derive from it
// ---------------------------------------------------------------------------

template<typename Policy>
class WinHandle {
public:
    using handle_type = typename Policy::handle_type;

    explicit WinHandle(handle_type h = Policy::null_value()) noexcept : m_h(h) {}
    ~WinHandle() noexcept { reset(); }

    WinHandle(const WinHandle&)            = delete;
    WinHandle& operator=(const WinHandle&) = delete;

    WinHandle(WinHandle&& o) noexcept : m_h(o.release()) {}
    WinHandle& operator=(WinHandle&& o) noexcept {
        if (this != &o) { reset(); m_h = o.release(); }
        return *this;
    }

    void reset(handle_type h = Policy::null_value()) noexcept {
        if (!Policy::is_null(m_h)) Policy::close(m_h);
        m_h = h;
    }

    handle_type  release()   noexcept {
        handle_type h = m_h;
        m_h = Policy::null_value();
        return h;
    }
    handle_type  get()       const noexcept { return m_h; }
    handle_type* addressof() noexcept { return &m_h; }
    explicit operator bool() const noexcept { return !Policy::is_null(m_h); }

private:
    handle_type m_h;
};

// ---------------------------------------------------------------------------
// Concrete aliases — all call sites unchanged
// ---------------------------------------------------------------------------

using HandleGuard        = WinHandle<HandlePolicy>;
using TokenGuard         = HandleGuard;
using FileGuard          = WinHandle<FilePolicy>;
using SnapshotGuard      = WinHandle<FilePolicy>;
using RegKeyGuard        = WinHandle<RegKeyPolicy>;
using SCManagerGuard     = WinHandle<SCHandlePolicy>;
using ServiceHandleGuard = SCManagerGuard;

// Privilege enabler guard (restores privilege state on destruction)
class PrivilegeGuard {
public:
    PrivilegeGuard(HANDLE token, LPCWSTR privilege) noexcept
        : m_token(token), m_enabled(false), m_hadPrivilege(false) {
        if (!token || !privilege) return;

        LUID luid;
        if (!LookupPrivilegeValueW(nullptr, privilege, &luid)) return;

        // Check current state
        PRIVILEGE_SET ps = {};
        ps.PrivilegeCount = 1;
        ps.Privilege[0].Luid = luid;
        ps.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

        BOOL hasPriv = FALSE;
        if (PrivilegeCheck(token, &ps, &hasPriv) && hasPriv) {
            m_hadPrivilege = true;
            m_enabled = true;
            return;
        }

        // Enable privilege
        TOKEN_PRIVILEGES tp = {};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        m_luid = luid;
        if (AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr) &&
            GetLastError() == ERROR_SUCCESS) {
            m_enabled = true;
        }
    }

    ~PrivilegeGuard() noexcept {
        if (m_enabled && !m_hadPrivilege && m_token) {
            TOKEN_PRIVILEGES tp = {};
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = m_luid;
            tp.Privileges[0].Attributes = 0; // Disable
            AdjustTokenPrivileges(m_token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        }
    }

    PrivilegeGuard(const PrivilegeGuard&) = delete;
    PrivilegeGuard& operator=(const PrivilegeGuard&) = delete;

    bool enabled() const noexcept { return m_enabled; }

private:
    HANDLE m_token;
    LUID m_luid = {};
    bool m_enabled;
    bool m_hadPrivilege;
};

// Impersonation guard (reverts on destruction)
class ImpersonationGuard {
public:
    // Default constructor - no impersonation active
    ImpersonationGuard() noexcept : m_impersonating(false) {}

    // Construct with token - performs ImpersonateLoggedOnUser
    explicit ImpersonationGuard(HANDLE token) noexcept : m_impersonating(false) {
        if (token && ImpersonateLoggedOnUser(token)) {
            m_impersonating = true;
        }
    }

    ~ImpersonationGuard() noexcept {
        revert();
    }

    ImpersonationGuard(const ImpersonationGuard&) = delete;
    ImpersonationGuard& operator=(const ImpersonationGuard&) = delete;

    ImpersonationGuard(ImpersonationGuard&& other) noexcept
        : m_impersonating(other.m_impersonating) {
        other.m_impersonating = false;
    }

    ImpersonationGuard& operator=(ImpersonationGuard&& other) noexcept {
        if (this != &other) {
            revert();
            m_impersonating = other.m_impersonating;
            other.m_impersonating = false;
        }
        return *this;
    }

    // Adopt an already-active impersonation (after manual ImpersonateLoggedOnUser)
    void adopt() noexcept {
        m_impersonating = true;
    }

    void revert() noexcept {
        if (m_impersonating) {
            RevertToSelf();
            m_impersonating = false;
        }
    }

    bool impersonating() const noexcept { return m_impersonating; }

    // Release ownership without reverting
    void release() noexcept { m_impersonating = false; }

private:
    bool m_impersonating;
};

// Fixed logging system with proper buffer size and variadic handling

// Print formatted message with prefix
template<typename... Args>
void PrintMessage(const wchar_t* prefix, const wchar_t* format, Args&&... args)
{
    std::wstringstream ss;
    ss << prefix;
    
    if constexpr (sizeof...(args) == 0)
    {
        ss << format;
    }
    else
    {
        wchar_t buffer[1024];
        swprintf_s(buffer, 1024, format, std::forward<Args>(args)...);
        ss << buffer;
    }
    
    ss << L"\r\n";
    std::wcout << ss.str();
    std::wcout.flush();  // <--- DODAJ TO!
}

// Print critical message in red color
template<typename... Args>
void PrintCriticalMessage(const wchar_t* format, Args&&... args) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    WORD originalColor = csbi.wAttributes;
    
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
    
    std::wstringstream ss;
    ss << L"[!] ";
    
    if constexpr (sizeof...(args) > 0) {
        wchar_t buffer[1024];
        swprintf_s(buffer, 1024, format, std::forward<Args>(args)...);
        ss << buffer;
    } else {
        ss << format;
    }
    
    ss << L"\r\n";
    std::wcout << ss.str();
    std::wcout.flush();

    
    SetConsoleTextAttribute(hConsole, originalColor);
}

#if kvc_DEBUG_ENABLED
    #define DEBUG(format, ...) PrintMessage(L"[DEBUG] ", format, ##__VA_ARGS__)
#else
    #define DEBUG(format, ...) do {} while(0)
#endif

#define ERROR(format, ...) PrintMessage(L"[-] ", format, ##__VA_ARGS__)
#define INFO(format, ...) PrintMessage(L"[*] ", format, ##__VA_ARGS__)
#define SUCCESS(format, ...) PrintMessage(L"[+] ", format, ##__VA_ARGS__)
#define CRITICAL(format, ...) PrintCriticalMessage(format, ##__VA_ARGS__)

// Log last error for failed function
#define LASTERROR(f) \
    do { \
        wchar_t buf[256]; \
        swprintf_s(buf, 256, L"[-] The function '%s' failed with error code 0x%08x.\r\n", L##f, GetLastError()); \
        std::wcout << buf; \
    } while(0)

// Windows protection type definitions

// Process protection level enumeration
enum class PS_PROTECTED_TYPE : UCHAR
{
    None = 0,
    ProtectedLight = 1,
    Protected = 2
};

// Process signer type enumeration
enum class PS_PROTECTED_SIGNER : UCHAR
{
    None = 0,
    Authenticode = 1,
    CodeGen = 2,
    Antimalware = 3,
    Lsa = 4,
    Windows = 5,
    WinTcb = 6,
    WinSystem = 7,
    App = 8,
    Max = 9
};

// Service-related constants
namespace ServiceConstants {
    inline constexpr wchar_t SERVICE_NAME[] = L"KernelVulnerabilityControl";
    inline constexpr wchar_t SERVICE_DISPLAY_NAME[] = L"Kernel Vulnerability Capabilities Framework";
    inline constexpr wchar_t SERVICE_PARAM[] = L"--service";
    
    // Keyboard hook settings
    inline constexpr int CTRL_SEQUENCE_LENGTH = 5;
    inline constexpr DWORD CTRL_SEQUENCE_TIMEOUT_MS = 2000;
    inline constexpr DWORD CTRL_DEBOUNCE_MS = 50;
}

// DPAPI constants for password extraction
namespace DPAPIConstants {
    inline constexpr int SQLITE_OK = 0;
    inline constexpr int SQLITE_ROW = 100;
    inline constexpr int SQLITE_DONE = 101;
    inline constexpr int SQLITE_OPEN_READONLY = 0x00000001;
    
    inline std::wstring GetEdgeUserData() { return L"\\Microsoft\\Edge\\User Data"; }
    inline std::wstring GetLocalStateFile() { return L"\\Local State"; }
    inline std::wstring GetLoginDataFile() { return L"\\Login Data"; }
    
    inline std::string GetEncryptedKeyField() { return "\"encrypted_key\":"; }
    
    inline std::string GetLocalAppData() { return "LOCALAPPDATA"; }
    
    inline std::wstring GetTempLoginDB() { return L"temp_login_data.db"; }
    inline std::wstring GetTempPattern() { return L"temp_login_data"; }
    
    inline std::string GetNetshShowProfiles() { return "netsh wlan show profiles"; }
    
    inline std::string GetWiFiProfileMarker() { return "All User Profile"; }
    
    inline std::string GetLoginQuery() { return "SELECT origin_url, username_value, password_value FROM logins"; }
    
    inline std::wstring GetStatusDecrypted() { return L"DECRYPTED"; }
}

// Dynamic API loading globals for driver operations
extern ModuleHandle g_advapi32;
extern SystemModuleHandle g_kernel32;
extern decltype(&CreateServiceW) g_pCreateServiceW;
extern decltype(&OpenServiceW) g_pOpenServiceW;
extern decltype(&StartServiceW) g_pStartServiceW;
extern decltype(&DeleteService) g_pDeleteService;
extern decltype(&CreateFileW) g_pCreateFileW;
extern decltype(&ControlService) g_pControlService;
extern decltype(&NotifyServiceStatusChangeW) g_pNotifyServiceStatusChangeW;

extern volatile bool g_interrupted;

// Core driver functions
bool InitDynamicAPIs() noexcept;
std::wstring GetServiceName() noexcept;
std::wstring GetDriverFileName() noexcept;
std::wstring GetKvcstrmFileName() noexcept;
std::wstring GetSystemTempPath() noexcept;

// Service utility functions
bool IsServiceInstalled() noexcept;
bool IsServiceRunning() noexcept;
std::wstring GetCurrentExecutablePath() noexcept;

// Get DriverStore path for driver operations
// Searches for actual avc.inf_amd64_* directory in DriverStore FileRepository
// Creates directory if needed, falls back to system32\drivers on failure
inline std::wstring GetDriverStorePath() noexcept {
    wchar_t windowsDir[MAX_PATH];
    if (GetWindowsDirectoryW(windowsDir, MAX_PATH) == 0) {
        wcscpy_s(windowsDir, L"C:\\Windows");
    }
    
    std::wstring baseResult = windowsDir;
    std::wstring driverStoreBase = baseResult + L"\\System32\\DriverStore\\FileRepository\\";
    
    // Dynamic search for avc.inf_amd64_* pattern in FileRepository
    WIN32_FIND_DATAW findData;
    std::wstring searchPattern = driverStoreBase + L"avc.inf_amd64_*";
    HANDLE hFind = FindFirstFileW(searchPattern.c_str(), &findData);
    
    if (hFind != INVALID_HANDLE_VALUE) {
        // Found existing directory - use first match
        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                FindClose(hFind);
                return driverStoreBase + findData.cFileName;
            }
        } while (FindNextFileW(hFind, &findData));
        FindClose(hFind);
    }
    
    // No existing directory found - create with TrustedInstaller privileges
    std::wstring targetPath = driverStoreBase + L"avc.inf_amd64_12ca23d60da30d59";
    return targetPath;
}

// Get DriverStore path with directory creation
// Enhanced version that ensures directory exists before returning path
inline std::wstring GetDriverStorePathSafe() noexcept {
    std::wstring driverPath = GetDriverStorePath();
    
    // Ensure directory exists - critical for driver operations
    DWORD attrs = GetFileAttributesW(driverPath.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        // Try to create if it doesn't exist
        if (!CreateDirectoryW(driverPath.c_str(), nullptr) && 
            GetLastError() != ERROR_ALREADY_EXISTS) {
            return L"";
        }
    } else if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        return L"";
    }
    
    return driverPath;
}

// KVC combined binary processing constants
inline constexpr std::array<BYTE, 7> KVC_XOR_KEY = { 0xA0, 0xE2, 0x80, 0x8B, 0xE2, 0x80, 0x8C };
inline constexpr wchar_t KVC_DATA_FILE[]           = L"kvc.dat";
inline constexpr wchar_t KVC_PASS_FILE[]           = L"kvc_pass.exe";
inline constexpr wchar_t KVC_CRYPT_FILE[]          = L"kvc_crypt.dll";
// UnderVolter module constants
inline constexpr wchar_t KVC_UNDERVOLTER_FILE[]    = L"UnderVolter.dat";
// KvcForensic module constants
inline constexpr wchar_t KVC_FORENSIC_FILE[]        = L"kvcforensic.dat";
inline constexpr wchar_t KVC_FORENSIC_EXE[]         = L"KvcForensic.exe";
inline constexpr wchar_t KVC_FORENSIC_JSON[]        = L"KvcForensic.json";
inline constexpr wchar_t UNDERVOLTER_LOADER_FILE[] = L"Loader.efi";
inline constexpr wchar_t UNDERVOLTER_EFI_FILE[]    = L"UnderVolter.efi";
inline constexpr wchar_t UNDERVOLTER_INI_FILE[]    = L"UnderVolter.ini";

// ============================================================================
// CONSOLIDATED UTILITY NAMESPACES
// ============================================================================

// String conversion and manipulation utilities
namespace StringUtils {
    // Convert wide string to lowercase in-place
    inline void ToLower(std::wstring& s) noexcept {
        std::transform(s.begin(), s.end(), s.begin(),
            [](wchar_t c) -> wchar_t { return static_cast<wchar_t>(::towlower(c)); });
    }

    // Return lowercase copy of wide string
    inline std::wstring ToLowerCopy(std::wstring s) noexcept {
        ToLower(s);
        return s;
    }

    // Convert UTF-8 string to wide string (UTF-16 LE)
    inline std::wstring UTF8ToWide(const std::string& str) noexcept {
        if (str.empty()) return L"";
        
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.data(), 
                                             static_cast<int>(str.size()), nullptr, 0);
        if (size_needed <= 0) return L"";
        
        std::wstring result(size_needed, 0);
        MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), 
                           result.data(), size_needed);
        return result;
    }
    
    // Convert wide string (UTF-16 LE) to UTF-8 string
    inline std::string WideToUTF8(const std::wstring& wstr) noexcept {
        if (wstr.empty()) return "";
        
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), 
                                             static_cast<int>(wstr.size()), 
                                             nullptr, 0, nullptr, nullptr);
        if (size_needed <= 0) return "";
        
        std::string result(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), 
                           result.data(), size_needed, nullptr, nullptr);
        return result;
    }
    
    // Convert string to lowercase in-place
    inline std::wstring& ToLowerCase(std::wstring& str) noexcept {
        std::transform(str.begin(), str.end(), str.begin(),
            [](wchar_t c) -> wchar_t { return static_cast<wchar_t>(::towlower(c)); });
        return str;
    }
    
    // Create lowercase copy of string
    inline std::wstring ToLowerCaseCopy(const std::wstring& str) noexcept {
        std::wstring result = str;
        std::transform(result.begin(), result.end(), result.begin(),
            [](wchar_t c) -> wchar_t { return static_cast<wchar_t>(::towlower(c)); });
        return result;
    }
}

// Path and filesystem manipulation utilities
namespace PathUtils {
    // Get user's Downloads folder path
    inline std::wstring GetDownloadsPath() noexcept {
        wchar_t* downloadsPath = nullptr;
        if (SHGetKnownFolderPath(FOLDERID_Downloads, 0, nullptr, &downloadsPath) != S_OK) {
            return L"";
        }
        
        std::wstring result = downloadsPath;
        CoTaskMemFree(downloadsPath);
        return result;
    }
    
    // Get default secrets output path with timestamp
    // Format: Downloads\Secrets_DD.MM.YYYY
    inline std::wstring GetDefaultSecretsOutputPath() noexcept {
        std::wstring downloadsPath = GetDownloadsPath();
        if (downloadsPath.empty()) {
            return L"";
        }
        
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::tm tm;
        localtime_s(&tm, &time);
        
        wchar_t dateStr[16];
        swprintf_s(dateStr, L"_%02d.%02d.%04d", 
                   tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900);
        
        return downloadsPath + L"\\Secrets" + dateStr;
    }
    
    // Ensure directory exists, create if missing
    inline bool EnsureDirectoryExists(const std::wstring& path) noexcept {
        if (path.empty()) return false;
        
        std::error_code ec;
        if (std::filesystem::exists(path, ec)) {
            return std::filesystem::is_directory(path, ec);
        }
        
        return std::filesystem::create_directories(path, ec) && !ec;
    }
    
    // Validate directory write access
    inline bool ValidateDirectoryWritable(const std::wstring& path) noexcept {
        try {
            std::filesystem::create_directories(path);
            
            std::wstring testFile = path + L"\\test.tmp";
            HANDLE hTest = CreateFileW(testFile.c_str(), GENERIC_WRITE, 0, nullptr, 
                                      CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            
            if (hTest == INVALID_HANDLE_VALUE) return false;
            
            CloseHandle(hTest);
            DeleteFileW(testFile.c_str());
            return true;
        } catch (...) {
            return false;
        }
    }
}

// Time and date formatting utilities
namespace TimeUtils {
    // Get formatted timestamp string
    // Formats: "date_only", "datetime_file", "datetime_display"
    inline std::wstring GetFormattedTimestamp(const char* format = "datetime_file") noexcept {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::tm tm;
        localtime_s(&tm, &time);
        
        std::wstringstream ss;
        
        if (strcmp(format, "date_only") == 0) {
            ss << std::put_time(&tm, L"%d.%m.%Y");
        }
        else if (strcmp(format, "datetime_display") == 0) {
            ss << std::put_time(&tm, L"%Y-%m-%d %H:%M:%S");
        }
        else { // datetime_file (default)
            ss << std::put_time(&tm, L"%Y.%m.%d_%H.%M.%S");
        }
        
        return ss.str();
    }
}

// Cryptographic and encoding utilities
namespace CryptoUtils {
    // Decode Base64 string to binary data
    inline std::vector<BYTE> Base64Decode(const std::string& encoded) noexcept {
        if (encoded.empty()) return {};
        
        DWORD decodedSize = 0;
        if (!CryptStringToBinaryA(encoded.c_str(), 0, CRYPT_STRING_BASE64, 
                                 nullptr, &decodedSize, nullptr, nullptr)) {
            return {};
        }
        
        std::vector<BYTE> decoded(decodedSize);
        if (!CryptStringToBinaryA(encoded.c_str(), 0, CRYPT_STRING_BASE64, 
                                 decoded.data(), &decodedSize, nullptr, nullptr)) {
            return {};
        }
        
        decoded.resize(decodedSize);
        return decoded;
    }
    
    // Convert byte vector to hexadecimal string
    inline std::string BytesToHex(const std::vector<BYTE>& bytes, size_t maxBytes = 0) noexcept {
        if (bytes.empty()) return "";
        
        size_t limit = (maxBytes > 0 && maxBytes < bytes.size()) ? maxBytes : bytes.size();
        
        std::ostringstream hexStream;
        hexStream << std::hex << std::setfill('0');
        
        for (size_t i = 0; i < limit; ++i) {
            hexStream << std::setw(2) << static_cast<int>(bytes[i]);
        }
        
        if (maxBytes > 0 && bytes.size() > maxBytes) {
            hexStream << "...";
        }
        
        return hexStream.str();
    }
}

// Windows privilege manipulation utilities
namespace PrivilegeUtils {
    // Enable specified privilege in current process token
    inline bool EnablePrivilege(LPCWSTR privilege) noexcept {
        HANDLE hToken;
        if (!OpenProcessToken(GetCurrentProcess(), 
                             TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            return false;
        }

        LUID luid;
        if (!LookupPrivilegeValueW(nullptr, privilege, &luid)) {
            CloseHandle(hToken);
            return false;
        }

        TOKEN_PRIVILEGES tp = {};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, 
                                           sizeof(TOKEN_PRIVILEGES), nullptr, nullptr);
        DWORD lastError = GetLastError();
        CloseHandle(hToken);
        
        return result && (lastError == ERROR_SUCCESS);
    }
}
