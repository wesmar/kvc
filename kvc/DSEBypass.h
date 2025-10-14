#pragma once

#include "kvcDrv.h"
#include <memory>
#include <optional>
#include <utility>

class DSEBypass {
private:
    std::unique_ptr<kvc>& m_rtc;
    ULONG_PTR m_ciOptionsAddr = 0;
    DWORD m_originalValue = 0;

public:
    explicit DSEBypass(std::unique_ptr<kvc>& rtc);
    
    // Main DSE control functions
    bool DisableDSE() noexcept;
    bool RestoreDSE() noexcept;
    
    // Getters for debugging and status checks
    ULONG_PTR GetCiOptionsAddress() const noexcept { return m_ciOptionsAddr; }
    DWORD GetOriginalValue() const noexcept { return m_originalValue; }
    
    // Helper functions (needed for status check from kvc.cpp)
    std::optional<ULONG_PTR> GetKernelModuleBase(const char* moduleName) noexcept;
    ULONG_PTR FindCiOptions(ULONG_PTR ciBase) noexcept;

private:
    // Internal PE parsing helpers
    std::optional<std::pair<ULONG_PTR, SIZE_T>> GetTextSection(ULONG_PTR moduleBase) noexcept;
    std::optional<std::pair<ULONG_PTR, SIZE_T>> GetDataSection(ULONG_PTR moduleBase) noexcept;
    bool IsValidDataPointer(ULONG_PTR moduleBase, ULONG_PTR addr) noexcept;
    DWORD GetWindowsBuild() noexcept;
};