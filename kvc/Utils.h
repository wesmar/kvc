/**
 * @file Utils.h
 * @brief Core utility functions declarations for KVC Framework
 * @author Marek Wesolowski
 * @date 2025
 * @copyright KVC Framework
 * 
 * Header file containing declarations for process management, memory operations,
 * protection level handling, and various system utilities.
 */

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
    // STRING AND NUMERIC PARSING UTILITIES
    // ============================================================================
    
    /**
     * @brief Parses PID from string with validation
     * @param pidStr String containing PID value
     * @return std::optional<DWORD> Parsed PID or nullopt on invalid input
     */
    std::optional<DWORD> ParsePid(const std::wstring& pidStr) noexcept;
    
    /**
     * @brief Checks if string contains only numeric characters
     * @param str String to validate
     * @return bool true if string is numeric
     */
    bool IsNumeric(const std::wstring& str) noexcept;
    
    // ============================================================================
    // FILE AND RESOURCE OPERATIONS (RENAMED TO AVOID WINAPI CONFLICTS)
    // ============================================================================
    
    /**
     * @brief Reads file contents into byte vector
     * @param path File path to read
     * @return std::vector<BYTE> File contents or empty on failure
     * @note Renamed from ReadFile to avoid conflict with Windows API
     */
    std::vector<BYTE> ReadFile(const std::wstring& path) noexcept;
    
    /**
     * @brief Reads embedded resource from executable
     * @param resourceId Resource identifier
     * @param resourceType Resource type (e.g., RT_RCDATA)
     * @return std::vector<BYTE> Resource data or empty on failure
     */
    std::vector<BYTE> ReadResource(int resourceId, const wchar_t* resourceType);
    
    /**
     * @brief Writes byte vector to file with error handling
     * @param path File path to write
     * @param data Data to write
     * @return bool true on successful write
     * @note Renamed from WriteFile to avoid conflict with Windows API
     */
    bool WriteFile(const std::wstring& path, const std::vector<BYTE>& data) noexcept;
    
    /**
     * @brief Force deletes file by removing attributes and using fallback methods
     * @param path File path to delete
     * @return bool true if file deleted successfully
     */
    bool ForceDeleteFile(const std::wstring& path) noexcept;
    
    // ============================================================================
    // PROCESS NAME RESOLUTION
    // ============================================================================
    
    /**
     * @brief Resolves process name from PID using multiple methods
     * @param pid Process ID to resolve
     * @return std::wstring Process name or "[Unknown]"
     */
    std::wstring GetProcessName(DWORD pid) noexcept;
    
    /**
     * @brief Creates descriptive identifier for unknown protected processes
     * @param pid Process ID
     * @param kernelAddress Kernel EPROCESS address
     * @param protectionLevel Protection level byte
     * @param signerType Signer type byte
     * @return std::wstring Descriptive process identifier
     */
    std::wstring ResolveUnknownProcessLocal(DWORD pid, ULONG_PTR kernelAddress, 
                                           UCHAR protectionLevel, UCHAR signerType) noexcept;

    // ============================================================================
    // KERNEL OPERATIONS (INLINE OPTIMIZED)
    // ============================================================================
    
    /**
     * @brief Resolves kernel base address with caching
     * @return std::optional<ULONG_PTR> Kernel base or nullopt on failure
     */
    std::optional<ULONG_PTR> GetKernelBaseAddress() noexcept;
    
    /**
     * @brief Calculates kernel address from base and offset
     * @param base Kernel base address
     * @param offset Offset from base
     * @return ULONG_PTR Calculated kernel address
     */
    constexpr ULONG_PTR GetKernelAddress(ULONG_PTR base, DWORD offset) noexcept
    {
        return base + offset;
    }
    
    // ============================================================================
    // PROTECTION LEVEL BIT MANIPULATION (INLINE FOR PERFORMANCE)
    // ============================================================================
    
    /**
     * @brief Extracts protection level from combined byte
     * @param protection Combined protection byte
     * @return UCHAR Protection level (lower 3 bits)
     */
    constexpr UCHAR GetProtectionLevel(UCHAR protection) noexcept
    {
        return protection & 0x07;
    }
    
    /**
     * @brief Extracts signer type from combined byte
     * @param protection Combined protection byte
     * @return UCHAR Signer type (upper 4 bits)
     */
    constexpr UCHAR GetSignerType(UCHAR protection) noexcept
    {
        return (protection & 0xF0) >> 4;
    }
    
    /**
     * @brief Combines protection level and signer into single byte
     * @param protectionLevel Protection level (0-7)
     * @param signerType Signer type (0-15)
     * @return UCHAR Combined protection byte
     */
    constexpr UCHAR GetProtection(UCHAR protectionLevel, UCHAR signerType) noexcept
    {
        return (signerType << 4) | protectionLevel;
    }
    
    /**
     * @brief Extracts signature level value
     * @param signatureLevel Raw signature level byte
     * @return UCHAR Signature level value
     */
    constexpr UCHAR GetSignatureLevelValue(UCHAR signatureLevel) noexcept
    {
        return signatureLevel & 0x0F; 
    }
    
    /**
     * @brief Extracts section signature level value
     * @param sectionSignatureLevel Raw section signature level byte
     * @return UCHAR Section signature level value
     */
    constexpr UCHAR GetSectionSignatureLevelValue(UCHAR sectionSignatureLevel) noexcept
    {
        return sectionSignatureLevel & 0x0F;
    }
    
    // ============================================================================
    // PROTECTION LEVEL STRING CONVERSIONS
    // ============================================================================
    
    /**
     * @brief Converts protection level to human-readable string
     * @param protectionLevel Protection level byte
     * @return const wchar_t* String representation ("None", "PPL", "PP")
     */
    const wchar_t* GetProtectionLevelAsString(UCHAR protectionLevel) noexcept;
    
    /**
     * @brief Converts signer type to human-readable string
     * @param signerType Signer type byte
     * @return const wchar_t* String representation (e.g., "Windows", "Antimalware")
     */
    const wchar_t* GetSignerTypeAsString(UCHAR signerType) noexcept;
    
    /**
     * @brief Converts signature level to human-readable string
     * @param signatureLevel Signature level byte
     * @return const wchar_t* String representation
     */
    const wchar_t* GetSignatureLevelAsString(UCHAR signatureLevel) noexcept;
    
    /**
     * @brief Converts section signature level to human-readable string
     * @param sectionSignatureLevel Section signature level byte
     * @return const wchar_t* String representation
     */
    const wchar_t* GetSectionSignatureLevelAsString(UCHAR sectionSignatureLevel) noexcept;
    
    // ============================================================================
    // STRING TO ENUM PARSING
    // ============================================================================
    
    /**
     * @brief Parses protection level string to enum value
     * @param protectionLevel String like "PP", "PPL", "None"
     * @return std::optional<UCHAR> Protection level value or nullopt
     */
    std::optional<UCHAR> GetProtectionLevelFromString(const std::wstring& protectionLevel) noexcept;
    
    /**
     * @brief Parses signer type string to enum value
     * @param signerType String like "Windows", "Antimalware"
     * @return std::optional<UCHAR> Signer type value or nullopt
     */
    std::optional<UCHAR> GetSignerTypeFromString(const std::wstring& signerType) noexcept;
    
    /**
     * @brief Gets recommended signature level for signer type
     * @param signerType Signer type enumeration value
     * @return std::optional<UCHAR> Signature level or nullopt
     */
    std::optional<UCHAR> GetSignatureLevel(UCHAR signerType) noexcept;
    
    /**
     * @brief Gets recommended section signature level for signer type
     * @param signerType Signer type enumeration value
     * @return std::optional<UCHAR> Section signature level or nullopt
     */
    std::optional<UCHAR> GetSectionSignatureLevel(UCHAR signerType) noexcept;
    
    // ============================================================================
    // PROCESS DUMPABILITY ANALYSIS
    // ============================================================================
    
    /**
     * @brief Result structure for process dumpability analysis
     */
    struct ProcessDumpability
    {
        bool CanDump;           ///< Whether process can be dumped
        std::wstring Reason;    ///< Detailed reason for dumpability status
    };
    
    /**
     * @brief Analyzes whether process can be memory dumped
     * @param pid Process ID
     * @param processName Process executable name
     * @param protectionLevel Current protection level
     * @param signerType Digital signature authority
     * @return ProcessDumpability Analysis result with reason
     */
    ProcessDumpability CanDumpProcess(DWORD pid, const std::wstring& processName, 
                                     UCHAR protectionLevel, UCHAR signerType) noexcept;
    
    // ============================================================================
    // HEX STRING UTILITIES
    // ============================================================================
    
    /**
     * @brief Converts hex string to byte array
     * @param hexString Hex string (supports 0x prefix, spaces, commas)
     * @param bytes Output byte vector
     * @return bool true if conversion successful
     */
    bool HexStringToBytes(const std::wstring& hexString, std::vector<BYTE>& bytes) noexcept;
    
    /**
     * @brief Validates hex string format
     * @param hexString String to validate
     * @return bool true if valid hex string
     */
    bool IsValidHexString(const std::wstring& hexString) noexcept;

    // ============================================================================
    // PE BINARY MANIPULATION
    // ============================================================================
    
    /**
     * @brief Gets length of PE file from binary data
     * @param data Binary data containing PE file
     * @param offset Starting offset in data
     * @return std::optional<size_t> PE file length or nullopt on invalid PE
     */
    std::optional<size_t> GetPEFileLength(const std::vector<BYTE>& data, size_t offset = 0) noexcept;
    
    /**
     * @brief Splits combined PE binary into separate components
     * @param combined Combined PE data
     * @param first Output for first PE component
     * @param second Output for second PE component
     * @return bool true if splitting successful
     */
    bool SplitCombinedPE(const std::vector<BYTE>& combined, 
                         std::vector<BYTE>& first, 
                         std::vector<BYTE>& second) noexcept;
    
    /**
     * @brief Decrypts data using XOR cipher
     * @param encryptedData Data to decrypt
     * @param key XOR key (7 bytes)
     * @return std::vector<BYTE> Decrypted data or empty on failure
     */
    std::vector<BYTE> DecryptXOR(const std::vector<BYTE>& encryptedData, 
                                const std::array<BYTE, 7>& key) noexcept;

    // ============================================================================
    // CONSOLE COLORING UTILITIES
    // ============================================================================
    
    /**
     * @brief ANSI color codes for process display
     */
	struct ProcessColors {
		static constexpr const wchar_t* GREEN = L"\033[92m";   ///< System processes (WinTcb, WinSystem, Windows)
		static constexpr const wchar_t* RED = L"\033[91m";     ///< LSA processes (critical security)
		static constexpr const wchar_t* YELLOW = L"\033[93m";  ///< User/Antimalware processes
		static constexpr const wchar_t* BLUE = L"\033[94m";    ///< Unchecked signatures
		static constexpr const wchar_t* HEADER = L"\033[97;44m"; ///< Table headers
		static constexpr const wchar_t* RESET = L"\033[0m";    ///< Reset color
	};

    /**
     * @brief Enables ANSI virtual terminal processing for colored output
     * @return bool true if enabled successfully
     */
    bool EnableConsoleVirtualTerminal() noexcept;
    
    /**
     * @brief Gets appropriate display color for process based on trust level
     * @param signerType Process signer type
     * @param signatureLevel Executable signature level
     * @param sectionSignatureLevel DLL signature level
     * @return const wchar_t* ANSI color code
     */
    const wchar_t* GetProcessDisplayColor(UCHAR signerType, UCHAR signatureLevel, 
                                         UCHAR sectionSignatureLevel) noexcept;
}