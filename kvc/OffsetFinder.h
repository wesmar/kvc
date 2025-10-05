/**
 * @file OffsetFinder.h
 * @brief Kernel structure offset discovery for EPROCESS manipulation
 * @author Marek Wesolowski
 * @date 2025  
 * @copyright KVC Framework
 * 
 * Dynamically discovers kernel offsets by pattern matching in ntoskrnl.exe,
 * supporting multiple Windows versions without hardcoded offsets.
 * Enables reliable EPROCESS structure manipulation across Windows versions.
 */

#pragma once

#include "common.h"
#include <unordered_map>
#include <memory>
#include <optional>

/**
 * @brief Windows kernel structure offset identifiers
 * 
 * Enumeration of all kernel structure offsets required for
 * EPROCESS manipulation and process protection operations.
 */
enum class Offset
{
    KernelPsInitialSystemProcess,   ///< PsInitialSystemProcess global pointer offset
    ProcessActiveProcessLinks,      ///< EPROCESS.ActiveProcessLinks list entry offset
    ProcessUniqueProcessId,         ///< EPROCESS.UniqueProcessId (PID) offset
    ProcessProtection,              ///< EPROCESS.Protection protection level offset
    ProcessSignatureLevel,          ///< EPROCESS.SignatureLevel code signing level offset
    ProcessSectionSignatureLevel    ///< EPROCESS.SectionSignatureLevel DLL signing level offset
};

/**
 * @class OffsetFinder
 * @brief Kernel structure offset discovery and caching
 * 
 * Discovers kernel offsets by:
 * 1. Loading ntoskrnl.exe from System32
 * 2. Pattern matching for specific structures and functions
 * 3. Calculating offsets from known patterns and signatures
 * 4. Caching results for performance across multiple operations
 * 
 * Supports Windows 7 through Windows 11 with automatic version detection.
 * No hardcoded offsets - all discovered dynamically at runtime.
 * 
 * @note Must call FindAllOffsets() before using GetOffset()
 */
class OffsetFinder
{
public:
    /**
     * @brief Construct offset finder and load kernel module
     * 
     * Loads ntoskrnl.exe from System32 directory for analysis.
     * Does not automatically find offsets - call FindAllOffsets().
     */
    OffsetFinder();
    
    /**
     * @brief Cleanup and free kernel module
     * 
     * Releases loaded ntoskrnl.exe module if still loaded.
     */
    ~OffsetFinder();
    
    OffsetFinder(const OffsetFinder&) = delete;                    ///< Copy constructor deleted
    OffsetFinder& operator=(const OffsetFinder&) = delete;        ///< Copy assignment deleted
    OffsetFinder(OffsetFinder&&) noexcept = default;              ///< Move constructor
    OffsetFinder& operator=(OffsetFinder&&) noexcept = default;   ///< Move assignment

    /**
     * @brief Get cached offset value
     * @param name Offset identifier to retrieve
     * @return Offset value in bytes, or nullopt if not found
     * @note Returns cached value - call FindAllOffsets() first to populate cache
     */
    std::optional<DWORD> GetOffset(Offset name) const noexcept;
    
    /**
     * @brief Discover all kernel offsets via pattern matching
     * @return true if all required offsets found successfully
     * @note Must be called after construction before using GetOffset()
     * @note Results are cached in m_offsetMap for subsequent calls
     * @note Failure indicates incompatible Windows version or corrupted system file
     */
    bool FindAllOffsets() noexcept;

private:
    /**
     * @brief Smart pointer deleter for HMODULE with FreeLibrary
     * 
     * Ensures proper cleanup of loaded kernel module.
     */
    struct ModuleDeleter
    {
        /**
         * @brief Free library module
         * @param module Module handle to free
         */
        void operator()(HMODULE module) const noexcept
        {
            if (module) {
                FreeLibrary(module);
            }
        }
    };

    using ModuleHandle = std::unique_ptr<std::remove_pointer_t<HMODULE>, ModuleDeleter>;  ///< Smart module handle type
    
    ModuleHandle m_kernelModule;                        ///< ntoskrnl.exe module handle
    std::unordered_map<Offset, DWORD> m_offsetMap;      ///< Cached offset values

    // Offset discovery methods
    
    /**
     * @brief Find PsInitialSystemProcess global pointer offset
     * @return true if offset discovered successfully
     * @note Uses PsGetCurrentProcess pattern matching technique
     */
    bool FindKernelPsInitialSystemProcessOffset() noexcept;
    
    /**
     * @brief Find EPROCESS.ActiveProcessLinks offset
     * @return true if offset discovered successfully
     * @note Uses PsGetNextProcess pattern matching technique
     */
    bool FindProcessActiveProcessLinksOffset() noexcept;
    
    /**
     * @brief Find EPROCESS.UniqueProcessId offset
     * @return true if offset discovered successfully
     * @note Uses PsGetProcessId pattern matching technique
     */
    bool FindProcessUniqueProcessIdOffset() noexcept;
    
    /**
     * @brief Find EPROCESS.Protection offset
     * @return true if offset discovered successfully
     * @note Pattern varies by Windows version, uses multiple techniques
     */
    bool FindProcessProtectionOffset() noexcept;
    
    /**
     * @brief Find EPROCESS.SignatureLevel offset
     * @return true if offset discovered successfully
     * @note Used for code signing level manipulation
     */
    bool FindProcessSignatureLevelOffset() noexcept;
    
    /**
     * @brief Find EPROCESS.SectionSignatureLevel offset
     * @return true if offset discovered successfully
     * @note Used for DLL signature level manipulation
     */
    bool FindProcessSectionSignatureLevelOffset() noexcept;
};