#pragma once

#include "common.h"
#include <string>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace Utils
{
    // String and numeric parsing utilities
    std::optional<DWORD> ParsePid(const std::wstring& pidStr) noexcept;
    bool IsNumeric(const std::wstring& str) noexcept;
    
    // Resource and file operations
    std::vector<BYTE> ReadFile(const std::wstring& path);
    std::vector<BYTE> ReadResource(int resourceId, const wchar_t* resourceType);
    bool WriteFile(const std::wstring& path, const std::vector<BYTE>& data);
    
    // Advanced process name resolution
    std::wstring ResolveUnknownProcessLocal(DWORD pid, ULONG_PTR kernelAddress, UCHAR protectionLevel, UCHAR signerType) noexcept;

    // Kernel operations with inline optimizations
    std::optional<ULONG_PTR> GetKernelBaseAddress() noexcept;
    
    constexpr ULONG_PTR GetKernelAddress(ULONG_PTR base, DWORD offset) noexcept
    {
        return base + offset;
    }
    
    constexpr UCHAR GetProtectionLevel(UCHAR protection) noexcept
    {
        return protection & 0x07;
    }
    
    constexpr UCHAR GetSignerType(UCHAR protection) noexcept
    {
        return (protection & 0xf0) >> 4;
    }
    
    constexpr UCHAR GetProtection(UCHAR protectionLevel, UCHAR signerType) noexcept
    {
        return (signerType << 4) | protectionLevel;
    }
    
    constexpr UCHAR GetSignatureLevelValue(UCHAR signatureLevel) noexcept
    {
        return signatureLevel & 0x0F; 
    }
    
    constexpr UCHAR GetSectionSignatureLevelValue(UCHAR sectionSignatureLevel) noexcept
    {
        return sectionSignatureLevel & 0x0F;
    }
    
    // String conversion functions with static caching for performance
    const wchar_t* GetProtectionLevelAsString(UCHAR protectionLevel) noexcept;
    const wchar_t* GetSignerTypeAsString(UCHAR signerType) noexcept;
    const wchar_t* GetSignatureLevelAsString(UCHAR signatureLevel) noexcept;
    
    // Parsing functions for command-line input
    std::optional<UCHAR> GetProtectionLevelFromString(const std::wstring& protectionLevel) noexcept;
    std::optional<UCHAR> GetSignerTypeFromString(const std::wstring& signerType) noexcept;
    std::optional<UCHAR> GetSignatureLevel(UCHAR signerType) noexcept;
    std::optional<UCHAR> GetSectionSignatureLevel(UCHAR signerType) noexcept;
    
    // Process operations with comprehensive dumpability analysis
    std::wstring GetProcessName(DWORD pid) noexcept;
    
    struct ProcessDumpability
    {
        bool CanDump;
        std::wstring Reason;
    };
    
    ProcessDumpability CanDumpProcess(DWORD pid, const std::wstring& processName, 
                                      UCHAR protectionLevel, UCHAR signerType) noexcept;
    
    // Hex string processing utilities for kernel tools
    bool HexStringToBytes(const std::wstring& hexString, std::vector<BYTE>& bytes) noexcept;
    bool IsValidHexString(const std::wstring& hexString) noexcept;

    // PE parsing and binary manipulation utilities
    std::optional<size_t> GetPEFileLength(const std::vector<BYTE>& data, size_t offset = 0) noexcept;
    bool SplitCombinedPE(const std::vector<BYTE>& combined, 
                         std::vector<BYTE>& first, 
                         std::vector<BYTE>& second) noexcept;
    std::vector<BYTE> DecryptXOR(const std::vector<BYTE>& encryptedData, 
                                const std::array<BYTE, 7>& key) noexcept;

    // Console coloring utilities for process display
    struct ProcessColors {
        static constexpr const wchar_t* GREEN = L"\033[92m";
        static constexpr const wchar_t* YELLOW = L"\033[93m"; 
        static constexpr const wchar_t* BLUE = L"\033[94m";
        static constexpr const wchar_t* HEADER = L"\033[97;44m";
        static constexpr const wchar_t* RESET = L"\033[0m";
    };

    bool EnableConsoleVirtualTerminal() noexcept;
    const wchar_t* GetProcessDisplayColor(UCHAR signerType, UCHAR signatureLevel, UCHAR sectionSignatureLevel) noexcept;
}