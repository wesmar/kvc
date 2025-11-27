// SymbolEngine.h
// Handles PDB downloading and symbol resolution for kernel modules
// Adapted for KVC Framework

#pragma once

#include "common.h"
#include <dbghelp.h>
#include <winhttp.h>
#include <utility>

class SymbolEngine {
public:
    SymbolEngine();
    ~SymbolEngine();

    // Initializes the symbol engine and sets up the local cache
    bool Initialize() noexcept;

    // Downloads PDB for a specific module if not present in cache
    bool EnsureSymbolsForModule(const std::wstring& modulePath) noexcept;

    // Resolves a symbol name to an RVA (Relative Virtual Address)
    std::optional<DWORD64> GetSymbolOffset(const std::wstring& modulePath, const std::wstring& symbolName) noexcept;

private:
    std::wstring m_symbolCachePath;
    std::wstring m_symbolServer;
    bool m_initialized = false;

    // Internal helpers
    bool EnsureCacheDirectory() noexcept;
    std::pair<std::wstring, std::wstring> GetPdbInfoFromPe(const std::wstring& pePath) noexcept;
    bool DownloadPdb(const std::wstring& modulePath, const std::wstring& pdbName, const std::wstring& guid) noexcept;
    bool DownloadFile(const std::wstring& url, const std::wstring& outputPath) noexcept;
};