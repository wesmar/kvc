// DSEBypassNG.h
// Next-Generation DSE Bypass using SeCiCallbacks manipulation
// Memory-only symbol resolution with LCUVer tracking and state management
// Author: Marek Wesolowski, 2025

#pragma once

#include "kvcDrv.h"
#include "SymbolEngine.h"
#include "SessionManager.h"
#include <memory>
#include <optional>
#include <string>

class DSEBypassNG {
public:
    // DSE state enumeration
    enum class DSEState {
        UNKNOWN,
        NORMAL,      // DSE enabled, original callback active
        PATCHED,     // DSE disabled, ZwFlush callback active
        CORRUPTED    // Unknown callback value
    };

    DSEBypassNG(std::unique_ptr<kvc>& driver);
    ~DSEBypassNG() = default;

    // Main operations with LCUVer-aware caching
    bool DisableDSE() noexcept;
    bool RestoreDSE() noexcept;
    
    // Cache management
    bool ClearSymbolCache() noexcept;
    std::wstring GetCacheStatus() noexcept;
    
    // State checking
    DSEState CheckDSEState() noexcept;
    static std::wstring GetDSEStateString(DSEState state);

private:
    std::unique_ptr<kvc>& m_driver; // Reference to KVC driver wrapper
    SymbolEngine m_symbolEngine;

    // Kernel information
    std::optional<std::pair<DWORD64, std::wstring>> GetKernelInfo() noexcept;
    
    // LCUVer tracking
    std::wstring GetCurrentLCUVersion() noexcept;
    bool IsLCUVersionChanged(const std::wstring& currentLCUVer) noexcept;
    
    // Offset calculation with caching
    std::optional<std::tuple<DWORD64, DWORD64, DWORD64>> GetCachedOffsets() noexcept;
    std::optional<std::tuple<DWORD64, DWORD64, DWORD64>> CalculateNewOffsets() noexcept;
    
    // Patch operations
    bool ApplyPatch(DWORD64 targetAddress, DWORD64 safeFunction, DWORD64 originalCallback) noexcept;
    bool RestorePatch(DWORD64 targetAddress, DWORD64 originalCallback) noexcept;
    
    // Validation
    bool ValidateOffsets(DWORD64 offSeCi, DWORD64 offZwFlush, DWORD64 kernelBase) noexcept;
};