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
// ============================================================================

// Generic HANDLE guard (CloseHandle)
class HandleGuard {
public:
    explicit HandleGuard(HANDLE h = nullptr) noexcept : m_handle(h) {}
    ~HandleGuard() noexcept { reset(); }

    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;

    HandleGuard(HandleGuard&& other) noexcept : m_handle(other.release()) {}
    HandleGuard& operator=(HandleGuard&& other) noexcept {
        if (this != &other) {
            reset();
            m_handle = other.release();
        }
        return *this;
    }

    void reset(HANDLE h = nullptr) noexcept {
        if (m_handle && m_handle != INVALID_HANDLE_VALUE) {
            CloseHandle(m_handle);
        }
        m_handle = h;
    }

    HANDLE release() noexcept {
        HANDLE h = m_handle;
        m_handle = nullptr;
        return h;
    }

    HANDLE get() const noexcept { return m_handle; }
    explicit operator bool() const noexcept { return m_handle && m_handle != INVALID_HANDLE_VALUE; }
    HANDLE* addressof() noexcept { return &m_handle; }

private:
    HANDLE m_handle;
};

// Token HANDLE guard (specialized for process tokens)
using TokenGuard = HandleGuard;

// Service Control Manager guard
class SCManagerGuard {
public:
    explicit SCManagerGuard(SC_HANDLE h = nullptr) noexcept : m_handle(h) {}
    ~SCManagerGuard() noexcept { reset(); }

    SCManagerGuard(const SCManagerGuard&) = delete;
    SCManagerGuard& operator=(const SCManagerGuard&) = delete;

    SCManagerGuard(SCManagerGuard&& other) noexcept : m_handle(other.release()) {}
    SCManagerGuard& operator=(SCManagerGuard&& other) noexcept {
        if (this != &other) {
            reset();
            m_handle = other.release();
        }
        return *this;
    }

    void reset(SC_HANDLE h = nullptr) noexcept {
        if (m_handle) {
            CloseServiceHandle(m_handle);
        }
        m_handle = h;
    }

    SC_HANDLE release() noexcept {
        SC_HANDLE h = m_handle;
        m_handle = nullptr;
        return h;
    }

    SC_HANDLE get() const noexcept { return m_handle; }
    explicit operator bool() const noexcept { return m_handle != nullptr; }

private:
    SC_HANDLE m_handle;
};

// Service handle guard (same behavior as SCManagerGuard)
using ServiceHandleGuard = SCManagerGuard;

// Registry key guard
class RegKeyGuard {
public:
    explicit RegKeyGuard(HKEY h = nullptr) noexcept : m_key(h) {}
    ~RegKeyGuard() noexcept { reset(); }

    RegKeyGuard(const RegKeyGuard&) = delete;
    RegKeyGuard& operator=(const RegKeyGuard&) = delete;

    RegKeyGuard(RegKeyGuard&& other) noexcept : m_key(other.release()) {}
    RegKeyGuard& operator=(RegKeyGuard&& other) noexcept {
        if (this != &other) {
            reset();
            m_key = other.release();
        }
        return *this;
    }

    void reset(HKEY h = nullptr) noexcept {
        if (m_key) {
            RegCloseKey(m_key);
        }
        m_key = h;
    }

    HKEY release() noexcept {
        HKEY h = m_key;
        m_key = nullptr;
        return h;
    }

    HKEY get() const noexcept { return m_key; }
    explicit operator bool() const noexcept { return m_key != nullptr; }
    HKEY* addressof() noexcept { return &m_key; }

private:
    HKEY m_key;
};

// File handle guard (specialized for CreateFile handles)
class FileGuard {
public:
    explicit FileGuard(HANDLE h = INVALID_HANDLE_VALUE) noexcept : m_handle(h) {}
    ~FileGuard() noexcept { reset(); }

    FileGuard(const FileGuard&) = delete;
    FileGuard& operator=(const FileGuard&) = delete;

    FileGuard(FileGuard&& other) noexcept : m_handle(other.release()) {}
    FileGuard& operator=(FileGuard&& other) noexcept {
        if (this != &other) {
            reset();
            m_handle = other.release();
        }
        return *this;
    }

    void reset(HANDLE h = INVALID_HANDLE_VALUE) noexcept {
        if (m_handle != INVALID_HANDLE_VALUE) {
            CloseHandle(m_handle);
        }
        m_handle = h;
    }

    HANDLE release() noexcept {
        HANDLE h = m_handle;
        m_handle = INVALID_HANDLE_VALUE;
        return h;
    }

    HANDLE get() const noexcept { return m_handle; }
    explicit operator bool() const noexcept { return m_handle != INVALID_HANDLE_VALUE; }

private:
    HANDLE m_handle;
};

// Snapshot guard (CreateToolhelp32Snapshot)
class SnapshotGuard {
public:
    explicit SnapshotGuard(HANDLE h = INVALID_HANDLE_VALUE) noexcept : m_handle(h) {}
    ~SnapshotGuard() noexcept { reset(); }

    SnapshotGuard(const SnapshotGuard&) = delete;
    SnapshotGuard& operator=(const SnapshotGuard&) = delete;

    SnapshotGuard(SnapshotGuard&& other) noexcept : m_handle(other.release()) {}
    SnapshotGuard& operator=(SnapshotGuard&& other) noexcept {
        if (this != &other) {
            reset();
            m_handle = other.release();
        }
        return *this;
    }

    void reset(HANDLE h = INVALID_HANDLE_VALUE) noexcept {
        if (m_handle != INVALID_HANDLE_VALUE) {
            CloseHandle(m_handle);
        }
        m_handle = h;
    }

    HANDLE release() noexcept {
        HANDLE h = m_handle;
        m_handle = INVALID_HANDLE_VALUE;
        return h;
    }

    HANDLE get() const noexcept { return m_handle; }
    explicit operator bool() const noexcept { return m_handle != INVALID_HANDLE_VALUE; }

private:
    HANDLE m_handle;
};

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
    
    inline std::string GetChromeV10Prefix() { return "v10"; }
    inline std::string GetChromeDPAPIPrefix() { return "DPAPI"; }
    
    inline std::wstring GetSecurityPolicySecrets() { return L"SECURITY\\Policy\\Secrets"; }
    inline std::wstring GetDPAPISystemKey() { return L"DPAPI_SYSTEM"; }
    inline std::wstring GetNLKMKey() { return L"NL$KM"; }
    inline std::wstring GetDefaultPasswordKey() { return L"DefaultPassword"; }
    
    inline std::wstring GetCurrVal() { return L"CurrVal"; }
    inline std::wstring GetOldVal() { return L"OldVal"; }
    
    inline std::wstring GetChromeUserData() { return L"\\Google\\Chrome\\User Data"; }
    inline std::wstring GetEdgeUserData() { return L"\\Microsoft\\Edge\\User Data"; }
    inline std::wstring GetLocalStateFile() { return L"\\Local State"; }
    inline std::wstring GetLoginDataFile() { return L"\\Login Data"; }
    
    inline std::string GetEncryptedKeyField() { return "\"encrypted_key\":"; }
    
    inline std::string GetLocalAppData() { return "LOCALAPPDATA"; }
    
    inline std::wstring GetHTMLExt() { return L".html"; }
    inline std::wstring GetTXTExt() { return L".txt"; }
    inline std::wstring GetDBExt() { return L".db"; }
    
    inline std::wstring GetTempLoginDB() { return L"temp_login_data.db"; }
    inline std::wstring GetTempPattern() { return L"temp_login_data"; }
    
    inline std::string GetNetshShowProfiles() { return "netsh wlan show profiles"; }
    inline std::string GetNetshShowProfileKey() { return "netsh wlan show profile name=\""; }
    inline std::string GetNetshKeyClear() { return "\" key=clear"; }
    
    inline std::string GetWiFiProfileMarker() { return "All User Profile"; }
    inline std::string GetWiFiKeyContent() { return "Key Content"; }
    
    inline std::string GetLoginQuery() { return "SELECT origin_url, username_value, password_value FROM logins"; }
    
    inline std::wstring GetStatusDecrypted() { return L"DECRYPTED"; }
    inline std::wstring GetStatusClearText() { return L"CLEAR_TEXT"; }
    inline std::wstring GetStatusEncrypted() { return L"ENCRYPTED"; }
    inline std::wstring GetStatusFailed() { return L"FAILED"; }
    inline std::wstring GetStatusExtracted() { return L"EXTRACTED"; }
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

// Service mode detection
extern bool g_serviceMode;
extern volatile bool g_interrupted;

// Core driver functions
bool InitDynamicAPIs() noexcept;
extern "C" const wchar_t* GetServiceNameRaw();
std::wstring GetServiceName() noexcept;
std::wstring GetDriverFileName() noexcept;
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
inline constexpr wchar_t KVC_DATA_FILE[]  = L"kvc.dat";
inline constexpr wchar_t KVC_PASS_FILE[]  = L"kvc_pass.exe";
inline constexpr wchar_t KVC_CRYPT_FILE[] = L"kvc_crypt.dll";

// ============================================================================
// CONSOLIDATED UTILITY NAMESPACES
// ============================================================================

// String conversion and manipulation utilities
namespace StringUtils {
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
        std::transform(str.begin(), str.end(), str.begin(), ::towlower);
        return str;
    }
    
    // Create lowercase copy of string
    inline std::wstring ToLowerCaseCopy(const std::wstring& str) noexcept {
        std::wstring result = str;
        std::transform(result.begin(), result.end(), result.begin(), ::towlower);
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