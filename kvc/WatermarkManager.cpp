// WatermarkManager.cpp
// Implementation of watermark removal via DLL hijacking

#include "WatermarkManager.h"
#include "Utils.h"
#include <tlhelp32.h>
#include <iostream>

// Constructor
WatermarkManager::WatermarkManager(TrustedInstallerIntegrator& trustedInstaller)
    : m_trustedInstaller(trustedInstaller)
{
}

// Main removal operation
bool WatermarkManager::RemoveWatermark() noexcept
{
    INFO(L"[WATERMARK] Starting watermark removal process");
    
    // Extract ExplorerFrame\u200B.dll from resource
    std::vector<BYTE> dllData;
    if (!ExtractWatermarkDLL(dllData)) {
        ERROR(L"[WATERMARK] Failed to extract DLL from resource");
        return false;
    }
    
    INFO(L"[WATERMARK] Successfully extracted ExplorerFrame\u200B.dll (%zu bytes)", dllData.size());
    
    // Get System32 path
    std::wstring system32Path = GetSystem32Path();
    if (system32Path.empty()) {
        ERROR(L"[WATERMARK] Failed to locate System32 directory");
        return false;
    }
    
    std::wstring dllPath = system32Path + L"\\ExplorerFrame\u200B.dll";
    
    // Write DLL using TrustedInstaller
    if (!m_trustedInstaller.WriteFileAsTrustedInstaller(dllPath, dllData)) {
        ERROR(L"[WATERMARK] Failed to deploy DLL to System32");
        return false;
    }
    
    INFO(L"[WATERMARK] DLL deployed to: %s", dllPath.c_str());
    
    // Hijack registry entry
    if (!m_trustedInstaller.WriteRegistryValueAsTrustedInstaller(
        HKEY_CLASSES_ROOT, CLSID_KEY, L"", HIJACKED_DLL)) {
        ERROR(L"[WATERMARK] Failed to hijack registry entry");
        return false;
    }
    
    INFO(L"[WATERMARK] Registry hijacked successfully");
    
    // Restart Explorer to apply changes
    if (!RestartExplorer()) {
        ERROR(L"[WATERMARK] Failed to restart Explorer");
        return false;
    }
    
    SUCCESS(L"[WATERMARK] Watermark removed successfully");
    return true;
}

// Restore original watermark
bool WatermarkManager::RestoreWatermark() noexcept
{
    INFO(L"[WATERMARK] Starting watermark restoration process");
    
    // Step 1: Restore registry to original value
    if (!m_trustedInstaller.WriteRegistryValueAsTrustedInstaller(
        HKEY_CLASSES_ROOT, CLSID_KEY, L"", ORIGINAL_DLL)) {
        ERROR(L"[WATERMARK] Failed to restore registry entry");
        return false;
    }

    INFO(L"[WATERMARK] Registry restored to original value");

    // Step 2: Restart Explorer to release handle to DLL
    if (!RestartExplorer()) {
        ERROR(L"[WATERMARK] Failed to restart Explorer");
        return false;
    }

    // Step 3: Delete the DLL now that the handle is released
    std::wstring system32Path = GetSystem32Path();
    if (!system32Path.empty()) {
        std::wstring dllPath = system32Path + L"\\ExplorerFrame\u200B.dll";

        // Brief delay to ensure Explorer has fully released the DLL
        Sleep(1000);

        if (!m_trustedInstaller.DeleteFileAsTrustedInstaller(dllPath)) {
            // Not a critical error - DLL may still be in use by another process
            INFO(L"[WATERMARK] DLL might still be in use, will be removed on next restart: %s",
                 dllPath.c_str());
        } else {
            INFO(L"[WATERMARK] Hijacked DLL deleted successfully");
        }
    }
    
    SUCCESS(L"[WATERMARK] Watermark restored successfully");
    return true;
}

// Check current status
std::wstring WatermarkManager::GetWatermarkStatus() noexcept
{
    std::wstring currentValue = ReadRegistryValue(HKEY_CLASSES_ROOT, CLSID_KEY, L"");
    
    if (currentValue == HIJACKED_DLL) {
        return L"REMOVED";
    } else if (currentValue == ORIGINAL_DLL) {
        return L"ACTIVE";
    }
    
    return L"UNKNOWN";
}

bool WatermarkManager::IsWatermarkRemoved() noexcept
{
    return GetWatermarkStatus() == L"REMOVED";
}

// Extract DLL from resource - Complete pipeline
bool WatermarkManager::ExtractWatermarkDLL(std::vector<BYTE>& outDllData) noexcept
{
    std::vector<BYTE> kvcSysData;
    
    if (!Utils::ExtractResourceComponents(RESOURCE_ID, kvcSysData, outDllData)) {
        ERROR(L"[WATERMARK] Failed to extract DLL from resource");
        return false;
    }
    
    DEBUG(L"[WATERMARK] ExplorerFrame\u200B.dll extracted: %zu bytes", outDllData.size());
    return !outDllData.empty();
}

// Restart Explorer process
bool WatermarkManager::RestartExplorer() noexcept
{
    INFO(L"[WATERMARK] Restarting Explorer...");
    
    // Find all explorer.exe processes
    std::vector<DWORD> explorerPids;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        
        if (Process32FirstW(hSnapshot, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0) {
                    explorerPids.push_back(pe.th32ProcessID);
                }
            } while (Process32NextW(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    
    // Terminate all Explorer instances
    std::vector<HANDLE> processHandles;
    for (DWORD pid : explorerPids) {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
        if (hProcess) {
            TerminateProcess(hProcess, 0);
            processHandles.push_back(hProcess);
        }
    }
    
    // Wait for termination
    if (!processHandles.empty()) {
        WaitForMultipleObjects(
            static_cast<DWORD>(processHandles.size()),
            processHandles.data(),
            TRUE,
            5000
        );
        
        for (HANDLE h : processHandles) {
            CloseHandle(h);
        }
    }
    
	// Start new Explorer instance
	SHELLEXECUTEINFOW sei = { sizeof(sei) };
	sei.fMask = SEE_MASK_FLAG_NO_UI;
	sei.lpFile = L"explorer.exe";
	sei.lpParameters = L"/e,";  // ← Prevents opening folder window
	sei.nShow = SW_HIDE;        // ← ! Hide the window
    
    if (!ShellExecuteExW(&sei)) {
        ERROR(L"[WATERMARK] Failed to restart Explorer");
        return false;
    }
    
    Sleep(1000);  // Give Explorer time to start
    return true;
}

// Get System32 path
std::wstring WatermarkManager::GetSystem32Path() noexcept
{
    wchar_t systemDir[MAX_PATH];
    if (GetSystemDirectoryW(systemDir, MAX_PATH) == 0) {
        return L"";
    }
    return std::wstring(systemDir);
}

// Read registry value
std::wstring WatermarkManager::ReadRegistryValue(HKEY hKey, const std::wstring& subKey, 
                                                 const std::wstring& valueName) noexcept
{
    HKEY hOpenKey;
    if (RegOpenKeyExW(hKey, subKey.c_str(), 0, KEY_READ, &hOpenKey) != ERROR_SUCCESS) {
        return L"";
    }
    
    wchar_t value[1024];
    DWORD dataSize = sizeof(value);
    DWORD type;
    
    if (RegQueryValueExW(hOpenKey, valueName.empty() ? nullptr : valueName.c_str(), 
                         NULL, &type, (LPBYTE)value, &dataSize) == ERROR_SUCCESS) {
        RegCloseKey(hOpenKey);
        if (type == REG_SZ || type == REG_EXPAND_SZ) {
            return std::wstring(value);
        }
    }
    
    RegCloseKey(hOpenKey);
    return L"";
}