// DSEBypassNG.h
// Next-Generation DSE Bypass using SeCiCallbacks manipulation and PDB symbols
// Safe against PatchGuard/HVCI (in most scenarios)

#pragma once

#include "kvcDrv.h"
#include "SymbolEngine.h"
#include <memory>

class DSEBypassNG {
public:
    DSEBypassNG(std::unique_ptr<kvc>& driver);
    ~DSEBypassNG() = default;

    // Main operations
    bool DisableDSE() noexcept;
    bool RestoreDSE() noexcept;

private:
    std::unique_ptr<kvc>& m_driver; // Reference to existing KVC driver wrapper
    SymbolEngine m_symbolEngine;

    // Helper: Gets kernel base and builds path to ntoskrnl.exe
    std::optional<std::pair<DWORD64, std::wstring>> GetKernelInfo() noexcept;
    
    // Constants
    static constexpr DWORD64 INVALID_OFFSET = 0xFFFFFFFFFFFFFFFF;
};