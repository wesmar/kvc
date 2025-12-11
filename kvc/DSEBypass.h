// DSEBypass.h
// Unified DSE Bypass Manager - combines Standard and Safe (PDB-based) methods
// Handles g_CiOptions patching and SeCiCallbacks manipulation in single class

#pragma once

#include "kvcDrv.h"
#include "SymbolEngine.h"
#include "SessionManager.h"
#include <memory>
#include <optional>
#include <utility>
#include <string>

// Forward declaration
class TrustedInstallerIntegrator;

class DSEBypass {
public:
    // Bypass method selection
    enum class Method {
        Standard,   // g_CiOptions modification + HVCI bypass via skci.dll rename
        Safe        // PDB-based SeCiCallbacks patching (preserves VBS)
    };

    // DSE state for Safe method
    enum class DSEState {
        UNKNOWN,
        NORMAL,      // DSE enabled, original callback active
        PATCHED,     // DSE disabled, ZwFlush callback active
        CORRUPTED    // Unknown callback value
    };

    // Status information structure
    struct Status {
        ULONG_PTR CiOptionsAddress;
        DWORD CiOptionsValue;
        bool DSEEnabled;
        bool HVCIEnabled;
        DWORD64 SavedCallback;      // For Safe method state tracking
    };

    DSEBypass(std::unique_ptr<kvc>& driver, TrustedInstallerIntegrator* ti);
    ~DSEBypass() = default;

    // ========================================================================
    // MAIN OPERATIONS
    // ========================================================================
    
    // Disable DSE using specified method
    bool Disable(Method method) noexcept;
    
    // Restore DSE using specified method
    bool Restore(Method method) noexcept;

    // ========================================================================
    // STATUS AND DIAGNOSTICS
    // ========================================================================
    
    // Get comprehensive DSE status
    bool GetStatus(Status& outStatus) noexcept;
    
    // Check DSE state for Safe method
    DSEState CheckSafeMethodState() noexcept;
    static std::wstring GetDSEStateString(DSEState state);
    
    // Get g_CiOptions address (after status check)
    ULONG_PTR GetCiOptionsAddress() const noexcept { return m_ciOptionsAddr; }
    DWORD GetOriginalValue() const noexcept { return m_originalCiOptions; }

    // ========================================================================
    // KERNEL MODULE HELPERS (public for Controller status checks)
    // ========================================================================
    
    std::optional<ULONG_PTR> GetKernelModuleBase(const char* moduleName) noexcept;
    ULONG_PTR FindCiOptions(ULONG_PTR ciBase) noexcept;

    // ========================================================================
    // HVCI DETECTION
    // ========================================================================
    
    // Check if HVCI/Memory Integrity is enabled (0x0001C006 pattern)
    static bool IsHVCIEnabled(DWORD ciOptionsValue) noexcept {
        return (ciOptionsValue & 0x0001C000) == 0x0001C000;
    }

    // ========================================================================
    // HVCI BYPASS (public for Controller to call after user confirmation)
    // ========================================================================
    
    bool RenameSkciLibrary() noexcept;
    bool CreatePendingFileRename() noexcept;

private:
    std::unique_ptr<kvc>& m_driver;
    TrustedInstallerIntegrator* m_trustedInstaller;
    SymbolEngine m_symbolEngine;  // Lazy-initialized for Safe method
    
    // Cached state
    ULONG_PTR m_ciOptionsAddr = 0;
    DWORD m_originalCiOptions = 0;

    // ========================================================================
    // STANDARD METHOD IMPLEMENTATION (g_CiOptions patching)
    // ========================================================================
    
    bool DisableStandard() noexcept;
    bool RestoreStandard() noexcept;
    
    // HVCI bypass helper (internal)
    bool RestoreSkciLibrary() noexcept;

    // ========================================================================
    // SAFE METHOD IMPLEMENTATION (SeCiCallbacks patching)
    // ========================================================================
    
    bool DisableSafe() noexcept;
    bool RestoreSafe() noexcept;
    
    // Kernel information for Safe method
    std::optional<std::pair<DWORD64, std::wstring>> GetKernelInfo() noexcept;
    std::wstring GetCurrentLCUVersion() noexcept;
    
    // Patch operations
    bool ApplyCallbackPatch(DWORD64 targetAddress, DWORD64 safeFunction, DWORD64 originalCallback) noexcept;
    bool RestoreCallbackPatch(DWORD64 targetAddress, DWORD64 originalCallback) noexcept;
    bool ValidateOffsets(DWORD64 offSeCi, DWORD64 offZwFlush, DWORD64 kernelBase) noexcept;

    // ========================================================================
    // PE PARSING HELPERS
    // ========================================================================
    
    std::optional<std::pair<ULONG_PTR, SIZE_T>> GetDataSection(ULONG_PTR moduleBase) noexcept;
};
