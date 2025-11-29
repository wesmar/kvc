// ModuleManager.h
// Module enumeration and memory inspection for target processes
// Author: Marek Wesolowski, 2025

#pragma once

#include "common.h"
#include <vector>
#include <string>

// Module information structure for enumeration results
struct ModuleInfo
{
    std::wstring name;
    std::wstring path;
    ULONG_PTR baseAddress;
    DWORD size;
};

// Static module manager - no instantiation needed
class ModuleManager
{
public:
    ModuleManager() = delete;
    ~ModuleManager() = delete;

    // Enumerate all loaded modules in target process
    static std::vector<ModuleInfo> EnumerateModules(DWORD pid) noexcept;
    
    // Find specific module by name in target process
    static std::optional<ModuleInfo> FindModule(DWORD pid, const std::wstring& moduleName) noexcept;
    
    // Display formatted module list with base addresses
    static void PrintModuleList(const std::vector<ModuleInfo>& modules) noexcept;
    
    // Display hex dump of module memory region
    static void PrintHexDump(const unsigned char* buffer, size_t size, ULONG_PTR baseAddress) noexcept;
    
    // Validate PE signature in buffer
    static bool ValidatePESignature(const unsigned char* buffer, size_t size) noexcept;

private:
    // Format size for human-readable display
    static std::wstring FormatSize(DWORD size) noexcept;
};
