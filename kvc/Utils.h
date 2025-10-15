// Utils.h
// Core utility functions for KVC Framework
// Author: Marek Wesolowski, 2025

#pragma once

#include "common.h"
#include <string>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <array>

namespace Utils
{
    // ============================================================================
    // STRING AND NUMERIC PARSING
    // ============================================================================
    
    std::optional<DWORD> ParsePid(const std::wstring& pidStr) noexcept;
    bool IsNumeric(const std::wstring& str) noexcept;
    
    // ============================================================================
    // FILE AND RESOURCE OPERATIONS
    // ============================================================================
    
    // Read file into byte vector
    std::vector<BYTE> ReadFile(const std::wstring& path) noexcept;
    
    // Read embedded resource from executable
    std::vector<BYTE> ReadResource(int resourceId, const wchar_t* resourceType);
    
    // Write byte vector to file
    bool WriteFile(const std::wstring& path, const std::vector<BYTE>& data) noexcept;
    
    // Force delete file with attribute removal
    bool ForceDeleteFile(const std::wstring& path) noexcept;
    
    // ============================================================================
    // PROCESS NAME RESOLUTION
    // ============================================================================
    
    std::wstring GetProcessName(DWORD pid) noexcept;
    
    std::wstring ResolveUnknownProcessLocal(DWORD pid, ULONG_PTR kernelAddress, 
                                           UCHAR protectionLevel, UCHAR signerType) noexcept;

    // ============================================================================
    // KERNEL OPERATIONS
    // ============================================================================
    
    std::optional<ULONG_PTR> GetKernelBaseAddress() noexcept;
    
    constexpr ULONG_PTR GetKernelAddress(ULONG_PTR base, DWORD offset) noexcept
    {
        return base + offset;
    }
    
    // ============================================================================
    // PROTECTION LEVEL BIT MANIPULATION
    // ============================================================================
    
    // Extract protection level from combined byte (lower 3 bits)
    constexpr UCHAR GetProtectionLevel(UCHAR protection) noexcept
    {
        return protection & 0x07;
    }
    
    // Extract signer type from combined byte (upper 4 bits)
    constexpr UCHAR GetSignerType(UCHAR protection) noexcept
    {
        return (protection & 0xF0) >> 4;
    }
    
    // Combine protection level and signer into single byte
    constexpr UCHAR GetProtection(UCHAR protectionLevel, UCHAR signerType) noexcept
    {
        return (signerType << 4) | protectionLevel;
    }
    
    // Extract signature level value (lower 4 bits)
    constexpr UCHAR GetSignatureLevelValue(UCHAR signatureLevel) noexcept
    {
        return signatureLevel & 0x0F; 
    }
    
    // Extract section signature level value (lower 4 bits)
    constexpr UCHAR GetSectionSignatureLevelValue(UCHAR sectionSignatureLevel) noexcept
    {
        return sectionSignatureLevel & 0x0F;
    }
    
    // ============================================================================
    // PROTECTION LEVEL STRING CONVERSIONS
    // ============================================================================
    
    const wchar_t* GetProtectionLevelAsString(UCHAR protectionLevel) noexcept;
    const wchar_t* GetSignerTypeAsString(UCHAR signerType) noexcept;
    const wchar_t* GetSignatureLevelAsString(UCHAR signatureLevel) noexcept;
    const wchar_t* GetSectionSignatureLevelAsString(UCHAR sectionSignatureLevel) noexcept;
    
    // ============================================================================
    // STRING TO ENUM PARSING
    // ============================================================================
    
    std::optional<UCHAR> GetProtectionLevelFromString(const std::wstring& protectionLevel) noexcept;
    std::optional<UCHAR> GetSignerTypeFromString(const std::wstring& signerType) noexcept;
    std::optional<UCHAR> GetSignatureLevel(UCHAR signerType) noexcept;
    std::optional<UCHAR> GetSectionSignatureLevel(UCHAR signerType) noexcept;
    
    // ============================================================================
    // PROCESS DUMPABILITY ANALYSIS
    // ============================================================================
    
    struct ProcessDumpability
    {
        bool CanDump;
        std::wstring Reason;
    };
    
    ProcessDumpability CanDumpProcess(DWORD pid, const std::wstring& processName, 
                                     UCHAR protectionLevel, UCHAR signerType) noexcept;
    
    // ============================================================================
    // HEX STRING UTILITIES
    // ============================================================================
    
    bool HexStringToBytes(const std::wstring& hexString, std::vector<BYTE>& bytes) noexcept;
    bool IsValidHexString(const std::wstring& hexString) noexcept;

    // ============================================================================
    // PE BINARY MANIPULATION
    // ============================================================================
    
    // Get PE file length from binary data
    std::optional<size_t> GetPEFileLength(const std::vector<BYTE>& data, size_t offset = 0) noexcept;
    
    // Split combined PE binary (used for kvc.dat extraction)
    bool SplitCombinedPE(const std::vector<BYTE>& combined, 
                         std::vector<BYTE>& first, 
                         std::vector<BYTE>& second) noexcept;
    
    // XOR decryption with 7-byte key
    std::vector<BYTE> DecryptXOR(const std::vector<BYTE>& encryptedData, 
                                const std::array<BYTE, 7>& key) noexcept;

    // ============================================================================
    // CAB DECOMPRESSION AND WATERMARK EXTRACTION
    // ============================================================================
    
    // Decompress CAB archive from memory and extract kvc.evtx
    std::vector<BYTE> DecompressCABFromMemory(const BYTE* cabData, size_t cabSize) noexcept;
    
    // Split kvc.evtx into kvc.sys (driver) and ExpIorerFrame.dll
    bool SplitKvcEvtx(const std::vector<BYTE>& kvcData, 
                      std::vector<BYTE>& outKvcSys, 
                      std::vector<BYTE>& outDll) noexcept;

	// Extract components from resource 102 (CAB containing kvc.sys + ExpIorerFrame.dll)
	bool ExtractResourceComponents(int resourceId, 
                                std::vector<BYTE>& outKvcSys, 
                                std::vector<BYTE>& outDll) noexcept;

    // ============================================================================
    // CONSOLE COLORING
    // ============================================================================
    
    struct ProcessColors {
        static constexpr const wchar_t* GREEN = L"\033[92m";
        static constexpr const wchar_t* RED = L"\033[91m";
        static constexpr const wchar_t* YELLOW = L"\033[93m";
        static constexpr const wchar_t* BLUE = L"\033[94m";
        static constexpr const wchar_t* PURPLE = L"\033[95m";
        static constexpr const wchar_t* CYAN = L"\033[96m";
        static constexpr const wchar_t* HEADER = L"\033[97;44m";
        static constexpr const wchar_t* RESET = L"\033[0m";
    };

    bool EnableConsoleVirtualTerminal() noexcept;
    
    const wchar_t* GetProcessDisplayColor(UCHAR signerType, UCHAR signatureLevel, 
                                         UCHAR sectionSignatureLevel) noexcept;
}