// ControllerCore.cpp
#include "Controller.h"
#include "common.h"
#include "resource.h"
#include <algorithm>
#include <chrono>

extern volatile bool g_interrupted;

Controller::Controller() : m_rtc(std::make_unique<kvc>()), m_of(std::make_unique<OffsetFinder>()) {
    if (!m_of->FindAllOffsets()) {
        ERROR(L"Failed to find required kernel structure offsets");
    }
}

Controller::~Controller() {
}

// Atomic operation cleanup - critical for BSOD prevention
bool Controller::PerformAtomicCleanup() noexcept {
    DEBUG(L"Starting atomic cleanup procedure...");
    
    // 1. First, close the connection to the driver
    if (m_rtc && m_rtc->IsConnected()) {
        DEBUG(L"Force-closing driver connection...");
        m_rtc->Cleanup();
    }
    
    // 2. Wait for resources to be released
    // Only for USB Debug Sleep(200);
	
	// CHECK IF THE SERVICE IS A ZOMBIE
    if (IsServiceZombie()) {
        DEBUG(L"Service in zombie state - skipping aggressive cleanup to avoid BSOD");
        return true;
    }
    
    // 3. Stop the service (if it exists)
    DEBUG(L"Stopping driver service...");
    if (!StopDriverService()) {
        ERROR(L"Failed to stop driver service during cleanup");
        // Continue on error - the service may already be stopped
    }
    
    // 4. Verify that the service has stopped
    DEBUG(L"Verifying service stopped...");
    bool serviceVerified = false;
    if (InitDynamicAPIs()) {
        for(int attempt = 0; attempt < 10; attempt++) {
            SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
            if (hSCM) {
                SC_HANDLE hService = g_pOpenServiceW(hSCM, GetServiceName().c_str(), SERVICE_QUERY_STATUS);
                if (hService) {
                    SERVICE_STATUS status;
                    if (QueryServiceStatus(hService, &status)) {
                        if (status.dwCurrentState == SERVICE_STOPPED) {
                            serviceVerified = true;
                            CloseServiceHandle(hService);
                            CloseServiceHandle(hSCM);
                            break;
                        }
                    }
                    CloseServiceHandle(hService);
                } else {
                    // Service does not exist - consider it stopped
                    serviceVerified = true;
                    CloseServiceHandle(hSCM);
                    break;
                }
                CloseServiceHandle(hSCM);
            }
            // Only for USB Debug Sleep(100);
        }
    }
    
    // 5. Wait again for safety
    // Only for USB Debug Sleep(100);
    
    // 6. Only uninstall if the service is confirmed to be stopped
    if (serviceVerified) {
        DEBUG(L"Service verified stopped, uninstalling...");
        UninstallDriver();
    } else {
        ERROR(L"Service still running, skipping uninstall to avoid BSOD");
    }
    
    // 7. Reinitialize for subsequent operations
    // Only for USB Debug Sleep(100);
    m_rtc = std::make_unique<kvc>();
    
    DEBUG(L"Atomic cleanup completed successfully");
    return true;
}

bool Controller::PerformAtomicInit() noexcept {
    if (!EnsureDriverAvailable()) {
        ERROR(L"Failed to load driver for atomic operation");
        return false;
    }
    return true;
}

bool Controller::PerformAtomicInitWithErrorCleanup() noexcept {
    if (!PerformAtomicInit()) {
        PerformAtomicCleanup();
        return false;
    }
    return true;
}

// Core driver availability check with fallback mechanisms
bool Controller::EnsureDriverAvailable() noexcept {
    if (IsServiceZombie()) {
        DEBUG(L"Service zombie detected - cannot reload driver safely");
        return false; // AVOID BSOD - do not reload the driver
    }
	// Phase 1: Check if the driver is already available (without testing)
	ForceRemoveService();
	// Only for USB Debug Sleep(100);
    if (IsDriverCurrentlyLoaded()) {
        return true;
    }

    // Phase 2: Try to start the existing service
    if (!InitDynamicAPIs()) return false;
    
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (hSCM) {
        SC_HANDLE hService = g_pOpenServiceW(hSCM, GetServiceName().c_str(), SERVICE_QUERY_STATUS | SERVICE_START);
        if (hService) {
            SERVICE_STATUS status;
            if (QueryServiceStatus(hService, &status)) {
                if (status.dwCurrentState == SERVICE_STOPPED) {
                    g_pStartServiceW(hService, 0, nullptr);
                }
            }
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hSCM);
        
        // Give it time to start
        // Only for USB Debug Sleep(100);
        
        // Check if it's running now (without a test read)
        if (m_rtc->Initialize() && m_rtc->IsConnected()) {
            return true;
        }
    }

    // Phase 3: Install a new driver (ONLY if necessary)
    DEBUG(L"Initializing kernel driver component...");
    
    if (!InstallDriverSilently()) {
        ERROR(L"Failed to install kernel driver component");
        return false;
    }

    if (!StartDriverServiceSilent()) {
        ERROR(L"Failed to start kernel driver service");
        return false;
    }

    // Phase 4: Final check
    if (!m_rtc->Initialize()) {
        ERROR(L"Failed to initialize kernel driver communication");
        return false;
    }

    DEBUG(L"Kernel driver component initialized successfully");
    return true;
}

bool Controller::IsDriverCurrentlyLoaded() noexcept {
    if (!m_rtc) return false;
    return m_rtc->IsConnected(); // Just check if the device is open
}
