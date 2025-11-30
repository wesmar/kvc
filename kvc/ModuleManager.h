// ModuleManager.h
// Module enumeration and memory inspection for target processes
// Provides Toolhelp32 snapshot access with kernel driver support for protected processes

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <optional>

// Module information structure with base address, size, and path
struct ModuleInfo {
    std::wstring name;
    std::wstring path;
    ULONG_PTR baseAddress;
    DWORD size;
};

// Table formatting constants for module list display
namespace ModuleTable {
    struct Columns {
        static constexpr size_t NAME = 36;
        static constexpr size_t ADDR = 18;
        static constexpr size_t SIZE = 14;
        static constexpr size_t TOTAL = NAME + ADDR + SIZE;
    };
}

class ModuleManager
{
public:
    // Enumerate all loaded modules in target process
    static std::vector<ModuleInfo> EnumerateModules(DWORD pid) noexcept;
    
    // Find specific module by name with partial matching support
    static std::optional<ModuleInfo> FindModule(DWORD pid, const std::wstring& moduleName) noexcept;
    
    // Display formatted module list with color-coded output
    static void PrintModuleList(const std::vector<ModuleInfo>& modules) noexcept;
    
    // Display hex dump with address offsets and ASCII representation
    static void PrintHexDump(const unsigned char* buffer, size_t size, ULONG_PTR baseAddress) noexcept;
    
    // Validate PE signature at buffer start
    static bool ValidatePESignature(const unsigned char* buffer, size_t size) noexcept;
    
private:
    // Format byte size to human-readable string
    static std::wstring FormatSize(DWORD size) noexcept;
};
