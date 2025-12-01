// SymbolEngine.h
// Next-Gen symbol engine for KVC Framework - memory-only PDB processing
// Author: Marek Wesolowski, 2025

#pragma once

#include "common.h"
#include <dbghelp.h>
#include <winhttp.h>
#include <utility>
#include <vector>
#include <optional>

class SymbolEngine {
public:
    SymbolEngine();
    ~SymbolEngine();

    // Main entry point: get symbol offsets for kernel without disk storage
    // Returns pair: (SeCiCallbacks_offset, ZwFlushInstructionCache_offset)
    std::optional<std::pair<DWORD64, DWORD64>> GetKernelSymbolOffsets() noexcept;
    
    // Direct offset calculation from kernel path (for debugging/flexibility)
    std::optional<std::pair<DWORD64, DWORD64>> GetSymbolOffsets(const std::wstring& kernelPath) noexcept;

private:
    std::wstring m_symbolServer;
    bool m_initialized = false;

    // Core initialization
    bool Initialize() noexcept;
    
    // Kernel module resolution
    std::optional<std::pair<DWORD64, std::wstring>> GetKernelInfo() noexcept;
    
    // PDB extraction from PE file
    std::optional<std::pair<std::wstring, std::wstring>> GetPdbInfoFromPe(const std::wstring& pePath) noexcept;
    
    // Memory-only PDB processing
    std::optional<std::vector<BYTE>> DownloadPdbToMemory(const std::wstring& pdbName, const std::wstring& guid) noexcept;
    
    // Calculate offsets from PDB data in memory (NO temporary files)
    std::optional<std::pair<DWORD64, DWORD64>> CalculateOffsetsFromMemory(
        const std::vector<BYTE>& pdbData, 
        const std::wstring& pdbName) noexcept;
    
    // HTTP download helper
    bool DownloadFileToMemory(const std::wstring& url, std::vector<BYTE>& output) noexcept;
    
    // DbgHelp symbol callback for virtual module loading
    static BOOL CALLBACK SymbolCallback(
        HANDLE hProcess,
        ULONG ActionCode,
        ULONG64 CallbackData,
        ULONG64 UserContext);
};