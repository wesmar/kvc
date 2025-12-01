// SymbolEngine.h
// Symbol resolution with local PDB priority and automatic download fallback

#pragma once

#include "common.h"
#include <dbghelp.h>
#include <winhttp.h>
#include <vector>
#include <string>
#include <optional>

class SymbolEngine {
public:
    SymbolEngine();
    ~SymbolEngine();

    // Get kernel symbol offsets using local PDB or download
    std::optional<std::pair<DWORD64, DWORD64>> GetKernelSymbolOffsets() noexcept;
    
    // Get offsets for specific kernel path
    std::optional<std::pair<DWORD64, DWORD64>> GetSymbolOffsets(const std::wstring& kernelPath) noexcept;

private:
    bool m_initialized = false;
    std::wstring m_symbolServer;

    // Initialization
    bool Initialize() noexcept;

    // Kernel information
    std::optional<std::pair<DWORD64, std::wstring>> GetKernelInfo() noexcept;

    // Local PDB resolution
    std::wstring GetLocalPdbPath(const std::wstring& pdbName, const std::wstring& guid) noexcept;

    // PDB extraction from PE
    std::optional<std::pair<std::wstring, std::wstring>> GetPdbInfoFromPe(const std::wstring& pePath) noexcept;

    // PDB download - directly to target location (no temp)
    bool DownloadPdbToDisk(const std::wstring& pdbName, const std::wstring& guid, 
                           const std::wstring& targetPath) noexcept;
    bool HttpDownload(const std::wstring& url, std::vector<BYTE>& output) noexcept;
    bool CreateDirectoryTree(const std::wstring& path) noexcept;

    // Offset calculation from disk
    std::optional<std::pair<DWORD64, DWORD64>> CalculateOffsetsFromDisk(
        const std::wstring& pdbPath,
        const std::wstring& pdbName) noexcept;

    // Callback for symbol loading
    static BOOL CALLBACK SymbolCallback(HANDLE, ULONG, ULONG64, ULONG64);
};
