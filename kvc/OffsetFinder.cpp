// OffsetFinder.cpp
#include "OffsetFinder.h"
#include "Utils.h"
#include "common.h"
#include <cstring>

namespace {
    // Safe offset extraction with validation to prevent crashes
    std::optional<WORD> SafeExtractWord(const void* base, size_t byteOffset) noexcept 
    {
        if (!base) return std::nullopt;

        WORD value = 0;
        __try {
            std::memcpy(&value, reinterpret_cast<const BYTE*>(base) + byteOffset, sizeof(value));
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return std::nullopt;
        }

        // Sanity check - offsets should be reasonable for EPROCESS structure
        if (value == 0 || value > 0x3000) {
            return std::nullopt;
        }

        return value;
    }
}

// Initialize offset finder with kernel image analysis
OffsetFinder::OffsetFinder()
{
    HMODULE rawModule = LoadLibraryW(L"ntoskrnl.exe");
    m_kernelModule = ModuleHandle(rawModule);
    
    if (!m_kernelModule) {
        ERROR(L"OffsetFinder: Failed to load kernel image (error: %d) - verify administrator privileges", GetLastError());
    }
}

OffsetFinder::~OffsetFinder() = default;

std::optional<DWORD> OffsetFinder::GetOffset(Offset name) const noexcept
{
    if (auto it = m_offsetMap.find(name); it != m_offsetMap.end())
        return it->second;
    return std::nullopt;
}

// Master offset discovery in dependency order
bool OffsetFinder::FindAllOffsets() noexcept
{
    return FindKernelPsInitialSystemProcessOffset() &&
           FindProcessUniqueProcessIdOffset() &&
           FindProcessProtectionOffset() &&
           FindProcessActiveProcessLinksOffset() &&
           FindProcessSignatureLevelOffset() &&
           FindProcessSectionSignatureLevelOffset();
}

// PsInitialSystemProcess export location discovery
bool OffsetFinder::FindKernelPsInitialSystemProcessOffset() noexcept
{
    if (m_offsetMap.contains(Offset::KernelPsInitialSystemProcess))
        return true;

    if (!m_kernelModule) {
        ERROR(L"Cannot find PsInitialSystemProcess - kernel image not loaded");
        return false;
    }

    auto pPsInitialSystemProcess = reinterpret_cast<ULONG_PTR>(
        GetProcAddress(m_kernelModule.get(), "PsInitialSystemProcess"));
    
    if (!pPsInitialSystemProcess) {
        ERROR(L"PsInitialSystemProcess export not found (error: %d)", GetLastError());
        
        // Test if other exports are accessible
        if (GetProcAddress(m_kernelModule.get(), "PsGetProcessId")) {
            ERROR(L"Other kernel exports accessible - partial export table issue");
        } else {
            ERROR(L"No kernel exports accessible - incompatible kernel image");
        }
        return false;
    }

    DWORD offset = static_cast<DWORD>(pPsInitialSystemProcess - reinterpret_cast<ULONG_PTR>(m_kernelModule.get()));
    
    // Sanity check for reasonable offset range
    if (offset < 0x1000 || offset > 0x2000000) { 
        ERROR(L"PsInitialSystemProcess offset 0x%x outside reasonable range", offset);
        return false;
    }
    
    m_offsetMap[Offset::KernelPsInitialSystemProcess] = offset;
    SUCCESS(L"Found PsInitialSystemProcess offset: 0x%x", offset);
    return true;
}

// ActiveProcessLinks follows UniqueProcessId in EPROCESS structure
bool OffsetFinder::FindProcessActiveProcessLinksOffset() noexcept
{
    if (m_offsetMap.contains(Offset::ProcessActiveProcessLinks))
        return true;
    
    if (!m_offsetMap.contains(Offset::ProcessUniqueProcessId))
        return false;

    // ActiveProcessLinks is always sizeof(HANDLE) bytes after UniqueProcessId
    WORD offset = static_cast<WORD>(m_offsetMap[Offset::ProcessUniqueProcessId] + sizeof(HANDLE));
    m_offsetMap[Offset::ProcessActiveProcessLinks] = offset;
    return true;
}

// UniqueProcessId offset extraction from PsGetProcessId function
bool OffsetFinder::FindProcessUniqueProcessIdOffset() noexcept
{
    if (m_offsetMap.contains(Offset::ProcessUniqueProcessId))
        return true;

    if (!m_kernelModule)
        return false;

    FARPROC pPsGetProcessId = GetProcAddress(m_kernelModule.get(), "PsGetProcessId");
    if (!pPsGetProcessId) {
        ERROR(L"PsGetProcessId export not found (error: %d)", GetLastError());
        return false;
    }

    // Extract offset from function disassembly
    std::optional<WORD> offset;
#ifdef _WIN64
    // mov rax, [rcx+offset] - offset at bytes 3-4
    offset = SafeExtractWord(pPsGetProcessId, 3);
#else
    // mov eax, [ecx+offset] - offset at bytes 2-3
    offset = SafeExtractWord(pPsGetProcessId, 2);
#endif

    if (!offset) {
        ERROR(L"Failed to extract UniqueProcessId offset from PsGetProcessId function");
        return false;
    }

    // Sanity check for EPROCESS structure size
    if (offset.value() > 0x1500) { 
        ERROR(L"UniqueProcessId offset 0x%x appears too large for EPROCESS", offset.value());
        return false;
    }

    m_offsetMap[Offset::ProcessUniqueProcessId] = offset.value();
    SUCCESS(L"Found UniqueProcessId offset: 0x%x", offset.value());
    return true;
}

// Process protection offset validation using dual function analysis
bool OffsetFinder::FindProcessProtectionOffset() noexcept
{
    if (m_offsetMap.contains(Offset::ProcessProtection))
        return true;

    if (!m_kernelModule)
        return false;

    FARPROC pPsIsProtectedProcess = GetProcAddress(m_kernelModule.get(), "PsIsProtectedProcess");
    FARPROC pPsIsProtectedProcessLight = GetProcAddress(m_kernelModule.get(), "PsIsProtectedProcessLight");
    
    if (!pPsIsProtectedProcess || !pPsIsProtectedProcessLight) {
        ERROR(L"Protection function exports not found in kernel image");
        return false;
    }

    // Both functions should reference the same offset
    auto offsetA = SafeExtractWord(pPsIsProtectedProcess, 2);
    auto offsetB = SafeExtractWord(pPsIsProtectedProcessLight, 2);

    if (!offsetA || !offsetB) {
        ERROR(L"Failed to extract offsets from protection validation functions");
        return false;
    }

    // Cross-validation - both functions must agree
    if (offsetA.value() != offsetB.value() || offsetA.value() > 0x1500) { 
        ERROR(L"Protection offset validation failed: A=0x%x, B=0x%x", offsetA.value(), offsetB.value());
        return false;
    }

    m_offsetMap[Offset::ProcessProtection] = offsetA.value();
    SUCCESS(L"Found ProcessProtection offset: 0x%x", offsetA.value());
    return true;
}

// SignatureLevel precedes Protection field by 2 bytes
bool OffsetFinder::FindProcessSignatureLevelOffset() noexcept
{
    if (m_offsetMap.contains(Offset::ProcessSignatureLevel))
        return true;

    if (!m_offsetMap.contains(Offset::ProcessProtection))
        return false;

    WORD offset = static_cast<WORD>(m_offsetMap[Offset::ProcessProtection] - (2 * sizeof(UCHAR)));
    m_offsetMap[Offset::ProcessSignatureLevel] = offset;
    return true;
}

// SectionSignatureLevel precedes Protection field by 1 byte
bool OffsetFinder::FindProcessSectionSignatureLevelOffset() noexcept
{
    if (m_offsetMap.contains(Offset::ProcessSectionSignatureLevel))
        return true;

    if (!m_offsetMap.contains(Offset::ProcessProtection))
        return false;

    WORD offset = static_cast<WORD>(m_offsetMap[Offset::ProcessProtection] - sizeof(UCHAR));
    m_offsetMap[Offset::ProcessSectionSignatureLevel] = offset;
    return true;
}