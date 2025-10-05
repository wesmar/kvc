/**
 * @file Utils.h
 * @brief Core utility functions declarations for KVC Framework
 * @author Marek Wesolowski
 * @date 2025
 * @copyright KVC Framework
 * 
 * Header file containing declarations for process management, memory operations,
 * protection level handling, and various system utilities.
 * Centralized utilities used throughout the KVC Framework.
 */

#pragma once

#include "common.h"
#include <string>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <array>

/**
 * @namespace Utils
 * @brief Core utility functions namespace for KVC Framework
 * 
 * Provides essential utilities for:
 * - String and numeric parsing
 * - File and resource operations  
 * - Process name resolution
 * - Kernel address operations
 * - Protection level bit manipulation
 * - String conversion utilities
 * - Process dumpability analysis
 * - Hex string utilities
 * - PE binary manipulation
 * - Console coloring utilities
 */
namespace Utils
{
    // ============================================================================
    // STRING AND NUMERIC PARSING UTILITIES
    // ============================================================================
    
    /**
     * @brief Parses PID from string with validation
     * @param pidStr String containing PID value
     * @return std::optional<DWORD> Parsed PID or nullopt on invalid input
     * @note Validates numeric range and format
     * @note Returns nullopt for non-numeric strings or invalid PIDs
     */
    std::optional<DWORD> ParsePid(const std::wstring& pidStr) noexcept;
    
    /**
     * @brief Checks if string contains only numeric characters
     * @param str String to validate
     * @return bool true if string is numeric
     * @note Empty string returns false
     * @note Handles Unicode numeric characters
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
     * @note Maximum file size: 256MB for safety
     * @note Uses memory-mapped files for large files
     */
    std::vector<BYTE> ReadFile(const std::wstring& path) noexcept;
    
    /**
     * @brief Reads embedded resource from executable
     * @param resourceId Resource identifier
     * @param resourceType Resource type (e.g., RT_RCDATA)
     * @return std::vector<BYTE> Resource data or empty on failure
     * @note Uses FindResource/LoadResource Windows API
     * @note Returns empty vector if resource not found
     */
    std::vector<BYTE> ReadResource(int resourceId, const wchar_t* resourceType);
    
    /**
     * @brief Writes byte vector to file with error handling
     * @param path File path to write
     * @param data Data to write
     * @return bool true on successful write
     * @note Renamed from WriteFile to avoid conflict with Windows API
     * @note Handles large files with chunked writing
     * @note Creates directory structure if needed
     */
    bool WriteFile(const std::wstring& path, const std::vector<BYTE>& data) noexcept;
    
    /**
     * @brief Force deletes file by removing attributes and using fallback methods
     * @param path File path to delete
     * @return bool true if file deleted successfully
     * @note Removes read-only, system, and hidden attributes
     * @note Uses multiple deletion strategies for stubborn files
     * @note Handles file locking and sharing violations
     */
    bool ForceDeleteFile(const std::wstring& path) noexcept;
    
    // ============================================================================
    // PROCESS NAME RESOLUTION
    // ============================================================================
    
    /**
     * @brief Resolves process name from PID using multiple methods
     * @param pid Process ID to resolve
     * @return std::wstring Process name or "[Unknown]"
     * @note Attempts: Toolhelp32, OpenProcess+GetModuleFileName, NtQuerySystemInformation
     * @note Returns "[Unknown]" if all methods fail
     * @note Caches results for performance
     */
    std::wstring GetProcessName(DWORD pid) noexcept;
    
    /**
     * @brief Creates descriptive identifier for unknown protected processes
     * @param pid Process ID
     * @param kernelAddress Kernel EPROCESS address
     * @param protectionLevel Protection level byte
     * @param signerType Signer type byte
     * @return std::wstring Descriptive process identifier
     * @note Format: "Protected_Process_[PID]_[Address]_[ProtectionLevel]"
     * @note Used when process name cannot be resolved normally
     */
    std::wstring ResolveUnknownProcessLocal(DWORD pid, ULONG_PTR kernelAddress, 
                                           UCHAR protectionLevel, UCHAR signerType) noexcept;

    // ============================================================================
    // KERNEL OPERATIONS (INLINE OPTIMIZED)
    // ============================================================================
    
    /**
     * @brief Resolves kernel base address with caching
     * @return std::optional<ULONG_PTR> Kernel base or nullopt on failure
     * @note Uses NtQuerySystemInformation with SystemModuleInformation
     * @note Caches result for 5000ms for performance
     * @note Returns ntoskrnl.exe base address
     */
    std::optional<ULONG_PTR> GetKernelBaseAddress() noexcept;
    
    /**
     * @brief Calculates kernel address from base and offset
     * @param base Kernel base address
     * @param offset Offset from base
     * @return ULONG_PTR Calculated kernel address
     * @note Simple addition operation, marked constexpr for compile-time evaluation
     * @note Used for calculating EPROCESS field addresses
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
     * @note Values: 0=None, 1=ProtectedLight, 2=Protected
     * @note Uses bitmask 0x07 to extract lower 3 bits
     */
    constexpr UCHAR GetProtectionLevel(UCHAR protection) noexcept
    {
        return protection & 0x07;
    }
    
    /**
     * @brief Extracts signer type from combined byte
     * @param protection Combined protection byte
     * @return UCHAR Signer type (upper 4 bits)
     * @note Values: 0=None, 1=Authenticode, 3=Antimalware, 6=WinTcb, etc.
     * @note Uses bitmask 0xF0 and right shift to extract upper 4 bits
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
     * @note Format: [SignerType:4 bits][ProtectionLevel:3 bits][0:1 bit]
     * @note Used for writing protection values to kernel memory
     */
    constexpr UCHAR GetProtection(UCHAR protectionLevel, UCHAR signerType) noexcept
    {
        return (signerType << 4) | protectionLevel;
    }
    
    /**
     * @brief Extracts signature level value
     * @param signatureLevel Raw signature level byte
     * @return UCHAR Signature level value
     * @note Uses bitmask 0x0F to extract lower 4 bits
     * @note Signature level indicates code signing verification level
     */
    constexpr UCHAR GetSignatureLevelValue(UCHAR signatureLevel) noexcept
    {
        return signatureLevel & 0x0F; 
    }
    
    /**
     * @brief Extracts section signature level value
     * @param sectionSignatureLevel Raw section signature level byte
     * @return UCHAR Section signature level value
     * @note Uses bitmask 0x0F to extract lower 4 bits
     * @note Section signature level indicates DLL signature verification level
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
     * @note Returns "Unknown" for invalid protection levels
     * @note Used for display and logging purposes
     */
    const wchar_t* GetProtectionLevelAsString(UCHAR protectionLevel) noexcept;
    
    /**
     * @brief Converts signer type to human-readable string
     * @param signerType Signer type byte
     * @return const wchar_t* String representation (e.g., "Windows", "Antimalware")
     * @note Returns "Unknown" for invalid signer types
     * @note Maps PS_PROTECTED_SIGNER enum values to strings
     */
    const wchar_t* GetSignerTypeAsString(UCHAR signerType) noexcept;
    
    /**
     * @brief Converts signature level to human-readable string
     * @param signatureLevel Signature level byte
     * @return const wchar_t* String representation
     * @note Returns numeric value as string for unknown levels
     * @note Used for displaying code signing information
     */
    const wchar_t* GetSignatureLevelAsString(UCHAR signatureLevel) noexcept;
    
    /**
     * @brief Converts section signature level to human-readable string
     * @param sectionSignatureLevel Section signature level byte
     * @return const wchar_t* String representation
     * @note Returns numeric value as string for unknown levels
     * @note Used for displaying DLL signing information
     */
    const wchar_t* GetSectionSignatureLevelAsString(UCHAR sectionSignatureLevel) noexcept;
    
    // ============================================================================
    // STRING TO ENUM PARSING
    // ============================================================================
    
    /**
     * @brief Parses protection level string to enum value
     * @param protectionLevel String like "PP", "PPL", "None"
     * @return std::optional<UCHAR> Protection level value or nullopt
     * @note Case-insensitive matching
     * @note Supports "PP", "PPL", "None", "0", "1", "2" formats
     */
    std::optional<UCHAR> GetProtectionLevelFromString(const std::wstring& protectionLevel) noexcept;
    
    /**
     * @brief Parses signer type string to enum value
     * @param signerType String like "Windows", "Antimalware"
     * @return std::optional<UCHAR> Signer type value or nullopt
     * @note Case-insensitive matching
     * @note Supports: WinTcb, Windows, Antimalware, Lsa, WinSystem, etc.
     */
    std::optional<UCHAR> GetSignerTypeFromString(const std::wstring& signerType) noexcept;
    
    /**
     * @brief Gets recommended signature level for signer type
     * @param signerType Signer type enumeration value
     * @return std::optional<UCHAR> Signature level or nullopt
     * @note Provides reasonable defaults for different signer types
     * @note Used when setting new protection levels
     */
    std::optional<UCHAR> GetSignatureLevel(UCHAR signerType) noexcept;
    
    /**
     * @brief Gets recommended section signature level for signer type
     * @param signerType Signer type enumeration value
     * @return std::optional<UCHAR> Section signature level or nullopt
     * @note Provides reasonable defaults for different signer types
     * @note Used when setting new protection levels
     */
    std::optional<UCHAR> GetSectionSignatureLevel(UCHAR signerType) noexcept;
    
    // ============================================================================
    // PROCESS DUMPABILITY ANALYSIS
    // ============================================================================
    
    /**
     * @brief Result structure for process dumpability analysis
     * 
     * Contains analysis result indicating whether a process can be memory dumped
     * and the detailed reason for the decision.
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
     * @note Considers protection level, signer type, and process name
     * @note Some protected processes cannot be dumped for security reasons
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
     * @note Handles both uppercase and lowercase hex
     * @note Skips whitespace and common separators
     * @note Returns false for invalid hex characters
     */
    bool HexStringToBytes(const std::wstring& hexString, std::vector<BYTE>& bytes) noexcept;
    
    /**
     * @brief Validates hex string format
     * @param hexString String to validate
     * @return bool true if valid hex string
     * @note Allows 0x prefix, spaces, commas as separators
     * @note Requires even number of hex digits after cleaning
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
     * @note Validates DOS and NT headers
     * @note Calculates length from section table
     * @note Returns nullopt for invalid PE headers
     */
    std::optional<size_t> GetPEFileLength(const std::vector<BYTE>& data, size_t offset = 0) noexcept;
    
    /**
     * @brief Splits combined PE binary into separate components
     * @param combined Combined PE data
     * @param first Output for first PE component
     * @param second Output for second PE component
     * @return bool true if splitting successful
     * @note Validates both PE structures before splitting
     * @note Used for extracting kvc_pass.exe and kvc_crypt.dll from kvc.dat
     */
    bool SplitCombinedPE(const std::vector<BYTE>& combined, 
                         std::vector<BYTE>& first, 
                         std::vector<BYTE>& second) noexcept;
    
    /**
     * @brief Decrypts data using XOR cipher
     * @param encryptedData Data to decrypt
     * @param key XOR key (7 bytes)
     * @return std::vector<BYTE> Decrypted data or empty on failure
     * @note Uses repeating key pattern for decryption
     * @note Used for decrypting embedded driver and binaries
     */
    std::vector<BYTE> DecryptXOR(const std::vector<BYTE>& encryptedData, 
                                const std::array<BYTE, 7>& key) noexcept;

    // ============================================================================
    // CONSOLE COLORING UTILITIES
    // ============================================================================
    
    /**
     * @brief ANSI color codes for process display
     * 
     * Provides color coding for different process trust levels and types
     * in console output. Uses ANSI escape sequences.
     */
	struct ProcessColors {
		static constexpr const wchar_t* GREEN = L"\033[92m";   ///< System processes (WinTcb, WinSystem)
		static constexpr const wchar_t* RED = L"\033[91m";     ///< LSA processes (critical security)
		static constexpr const wchar_t* YELLOW = L"\033[93m";  ///< User/Antimalware processes
		static constexpr const wchar_t* BLUE = L"\033[94m";    ///< Unchecked signatures
		static constexpr const wchar_t* PURPLE = L"\033[95m"; 	///< SYSTEM ONLY!(always 4)
		static constexpr const wchar_t* CYAN = L"\033[96m";		///< Windows Signer
		static constexpr const wchar_t* HEADER = L"\033[97;44m"; ///< Table headers (white on blue)
		static constexpr const wchar_t* RESET = L"\033[0m";    ///< Reset color to default
	};

    /**
     * @brief Enables ANSI virtual terminal processing for colored output
     * @return bool true if enabled successfully
     * @note Required for ANSI color codes to work on Windows 10+
     * @note Uses SetConsoleMode with ENABLE_VIRTUAL_TERMINAL_PROCESSING
     */
    bool EnableConsoleVirtualTerminal() noexcept;
    
    /**
     * @brief Gets appropriate display color for process based on trust level
     * @param signerType Process signer type
     * @param signatureLevel Executable signature level
     * @param sectionSignatureLevel DLL signature level
     * @return const wchar_t* ANSI color code
     * @note Color coding: Green=System, Red=LSA, Yellow=User, Blue=Unchecked
     * @note Used in process listing and information display
     */
    const wchar_t* GetProcessDisplayColor(UCHAR signerType, UCHAR signatureLevel, 
                                         UCHAR sectionSignatureLevel) noexcept;
}