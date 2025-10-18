#pragma once

#include "kvcDrv.h"
#include <memory>
#include <optional>
#include <utility>

// Forward declaration - MUSI BYĆ PRZED class DSEBypass
class TrustedInstallerIntegrator;

class DSEBypass {
private:
    std::unique_ptr<kvc>& m_rtc;
    TrustedInstallerIntegrator* m_trustedInstaller;
    ULONG_PTR m_ciOptionsAddr = 0;
    DWORD m_originalValue = 0;

public:
    explicit DSEBypass(std::unique_ptr<kvc>& rtc, TrustedInstallerIntegrator* ti);
    
    // Main DSE control functions
    bool DisableDSE() noexcept;
    bool RestoreDSE() noexcept;
    
    // Getters for debugging and status checks
    ULONG_PTR GetCiOptionsAddress() const noexcept { return m_ciOptionsAddr; }
    DWORD GetOriginalValue() const noexcept { return m_originalValue; }
    
    // Helper functions (needed for status check from kvc.cpp)
    std::optional<ULONG_PTR> GetKernelModuleBase(const char* moduleName) noexcept;
    ULONG_PTR FindCiOptions(ULONG_PTR ciBase) noexcept;

    // HVCI bypass workflow
    bool DisableDSEAfterReboot() noexcept;

private:
    // Internal PE parsing helpers
    std::optional<std::pair<ULONG_PTR, SIZE_T>> GetDataSection(ULONG_PTR moduleBase) noexcept;
    
    // HVCI bypass helpers
    bool RenameSkciLibrary() noexcept;
    bool RestoreSkciLibrary() noexcept;
    bool CreateRunOnceEntry() noexcept;
    bool SaveDSEState(DWORD originalValue) noexcept;
    bool LoadDSEState(std::wstring& outState, DWORD& outOriginalValue) noexcept;
    bool ClearDSEState() noexcept;
    
    // HVCI/VBS detection
    bool IsHVCIEnabled(DWORD ciOptionsValue) const noexcept {
        return (ciOptionsValue & 0x0001C000) != 0;
    }
};