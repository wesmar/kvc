// OffsetFinder.h - Kernel offset discovery for EPROCESS manipulation (dynamic pattern matching)

#pragma once

#include "common.h"
#include <unordered_map>
#include <memory>
#include <optional>

// Kernel structure offset identifiers for EPROCESS and protection fields
enum class Offset
{
    KernelPsInitialSystemProcess,   // PsInitialSystemProcess global pointer
    ProcessActiveProcessLinks,      // EPROCESS.ActiveProcessLinks list entry
    ProcessUniqueProcessId,         // EPROCESS.UniqueProcessId (PID)
    ProcessProtection,              // EPROCESS.Protection level
    ProcessSignatureLevel,          // EPROCESS.SignatureLevel
    ProcessSectionSignatureLevel    // EPROCESS.SectionSignatureLevel
};

// Discover and cache kernel offsets by pattern matching ntoskrnl.exe
class OffsetFinder
{
public:
    // Load ntoskrnl.exe for analysis (does not auto-discover offsets)
    OffsetFinder();
    
    // Unload module and cleanup
    ~OffsetFinder();
    
    OffsetFinder(const OffsetFinder&) = delete;
    OffsetFinder& operator=(const OffsetFinder&) = delete;
    OffsetFinder(OffsetFinder&&) noexcept = default;
    OffsetFinder& operator=(OffsetFinder&&) noexcept = default;

    // Return cached offset value or nullopt if missing (call FindAllOffsets first)
    std::optional<DWORD> GetOffset(Offset name) const noexcept;
    
    // Discover all required offsets via pattern matching and cache results
    bool FindAllOffsets() noexcept;

private:
    // Smart deleter for HMODULE using FreeLibrary
    struct ModuleDeleter
    {
        void operator()(HMODULE module) const noexcept
        {
            if (module) {
                FreeLibrary(module);
            }
        }
    };

    using ModuleHandle = std::unique_ptr<std::remove_pointer_t<HMODULE>, ModuleDeleter>;
    
    ModuleHandle m_kernelModule;                        // ntoskrnl.exe handle
    std::unordered_map<Offset, DWORD> m_offsetMap;      // Cached offsets

    // Individual offset discovery routines
    bool FindKernelPsInitialSystemProcessOffset() noexcept;
    bool FindProcessActiveProcessLinksOffset() noexcept;
    bool FindProcessUniqueProcessIdOffset() noexcept;
    bool FindProcessProtectionOffset() noexcept;
    bool FindProcessSignatureLevelOffset() noexcept;
    bool FindProcessSectionSignatureLevelOffset() noexcept;
};
