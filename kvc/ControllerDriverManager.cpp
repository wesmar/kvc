// ControllerDriverManager.cpp
// Driver lifecycle management: installation, service control, extraction
// Author: Marek Wesolowski, 2025

#include "Controller.h"
#include "common.h"
#include "Utils.h"
#include "resource.h"
#include <filesystem>

namespace fs = std::filesystem;

// ============================================================================
// SERVICE CLEANUP AND MANAGEMENT
// ============================================================================

// Forcefully remove driver service, ignoring most errors
bool Controller::ForceRemoveService() noexcept {
    if (!InitDynamicAPIs()) {
        return false;
    }

    StopDriverService();
    	
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        return false;
    }

    SC_HANDLE hService = g_pOpenServiceW(hSCM, GetServiceName().c_str(), DELETE);
    if (!hService) {
        DWORD err = GetLastError();
        CloseServiceHandle(hSCM);
        return (err == ERROR_SERVICE_DOES_NOT_EXIST); 
    }

    BOOL success = g_pDeleteService(hService);
    DWORD err = GetLastError();
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    return success || (err == ERROR_SERVICE_MARKED_FOR_DELETE);
}

// Detect zombie service state (marked for deletion but not removed)
bool Controller::IsServiceZombie() noexcept {
    if (!InitDynamicAPIs()) return false;
    
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return false;
    
    SC_HANDLE hService = g_pOpenServiceW(hSCM, GetServiceName().c_str(), DELETE);
    if (!hService) {
        DWORD err = GetLastError();
        CloseServiceHandle(hSCM);
        return false;
    }
    
    BOOL delResult = g_pDeleteService(hService);
    DWORD err = GetLastError();
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    
    return (!delResult && err == ERROR_SERVICE_MARKED_FOR_DELETE);
}

// ============================================================================
// SERVICE LIFECYCLE MANAGEMENT
// ============================================================================

bool Controller::StopDriverService() noexcept {
    DEBUG(L"StopDriverService called");
    
    if (!InitDynamicAPIs()) {
        DEBUG(L"InitDynamicAPIs failed in StopDriverService");
        return false;
    }
    
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) {
        DEBUG(L"OpenSCManagerW failed: %d", GetLastError());
        return false;
    }

    SC_HANDLE hService = g_pOpenServiceW(hSCM, GetServiceName().c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hService) {
        DWORD err = GetLastError();
        CloseServiceHandle(hSCM);
        
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            DEBUG(L"Service does not exist - considered stopped");
            return true;
        }
        
        DEBUG(L"Failed to open service: %d", err);
        return false;
    }

    SERVICE_STATUS status;
    if (!QueryServiceStatus(hService, &status)) {
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return false;
    }

    if (status.dwCurrentState == SERVICE_STOPPED) {
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        DEBUG(L"Service already stopped");
        return true;
    }

    if (status.dwCurrentState == SERVICE_RUNNING) {
        if (!g_pControlService(hService, SERVICE_CONTROL_STOP, &status)) {
            DWORD err = GetLastError();
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            DEBUG(L"ControlService failed: %d", err);
            return false;
        }

        // Wait for service to stop (up to 5 seconds)
        for (int i = 0; i < 50; i++) {
            Sleep(100);
            if (QueryServiceStatus(hService, &status)) {
                if (status.dwCurrentState == SERVICE_STOPPED) {
                    break;
                }
            }
        }
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    
    DEBUG(L"Service stop completed");
    return true;
}

bool Controller::StartDriverService() noexcept {
    if (!InitDynamicAPIs()) return false;
    GenerateFakeActivity();
    
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        ERROR(L"Failed to open service control manager: %d", GetLastError());
        return false;
    }

    SC_HANDLE hService = g_pOpenServiceW(hSCM, GetServiceName().c_str(), SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(hSCM);
        ERROR(L"Failed to open kernel driver service: %d", GetLastError());
        return false;
    }

    SERVICE_STATUS status;
    if (QueryServiceStatus(hService, &status)) {
        if (status.dwCurrentState == SERVICE_RUNNING) {
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            INFO(L"Kernel driver service already running");
            return true;
        }
    }

    BOOL success = g_pStartServiceW(hService, 0, nullptr);
    DWORD err = GetLastError();

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    if (!success && err != ERROR_SERVICE_ALREADY_RUNNING) {
        ERROR(L"Failed to start kernel driver service: %d", err);
        return false;
    }

    SUCCESS(L"Kernel driver service started successfully");
    return true;
}

bool Controller::StartDriverServiceSilent() noexcept {
    if (!InitDynamicAPIs()) return false;
    GenerateFakeActivity();
    
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return false;

    SC_HANDLE hService = g_pOpenServiceW(hSCM, GetServiceName().c_str(), SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(hSCM);
        return false;
    }

    SERVICE_STATUS status;
    bool success = true;
    
    if (QueryServiceStatus(hService, &status)) {
        if (status.dwCurrentState != SERVICE_RUNNING) {
            success = g_pStartServiceW(hService, 0, nullptr) || (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING);
        }
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return success;
}

// ============================================================================
// DRIVER INSTALLATION
// ============================================================================

bool Controller::InstallDriver() noexcept {
    ForceRemoveService();
    
    // Check for zombie service state
    if (IsServiceZombie()) {
        CRITICAL(L"");
        CRITICAL(L"===============================================================");
        CRITICAL(L"  DRIVER SERVICE IN ZOMBIE STATE - SYSTEM RESTART REQUIRED");
        CRITICAL(L"===============================================================");
        CRITICAL(L"");
        CRITICAL(L"The kernel driver service is marked for deletion but cannot be");
        CRITICAL(L"removed until the system is restarted. This typically occurs");
        CRITICAL(L"when driver loading is interrupted during initialization.");
        CRITICAL(L"");
        INFO(L"Required action: Restart your computer to clear the zombie state");
        INFO(L"After restart, the driver will load normally");
        CRITICAL(L"");
        CRITICAL(L"===============================================================");
        CRITICAL(L"");
        return false;
    }
    
    // Extract driver (already decrypted by Utils::ExtractResourceComponents)
    auto driverData = ExtractDriver();
    if (driverData.empty()) {
        ERROR(L"Failed to extract driver from resource");
        return false;
    }

    // Get target paths
    fs::path driverDir = GetDriverStorePath();
    fs::path driverPath = driverDir / fs::path(GetDriverFileName());

    INFO(L"Target driver path: %s", driverPath.c_str());

    // Ensure directory exists with TrustedInstaller privileges
    INFO(L"Creating driver directory with TrustedInstaller privileges...");
    if (!m_trustedInstaller.CreateDirectoryAsTrustedInstaller(driverDir.wstring())) {
        ERROR(L"Failed to create driver directory: %s", driverDir.c_str());
        return false;
    }
    DEBUG(L"Driver directory ready: %s", driverDir.c_str());

    // Write driver file directly with TrustedInstaller privileges
    INFO(L"Writing driver file with TrustedInstaller privileges...");
    if (!m_trustedInstaller.WriteFileAsTrustedInstaller(driverPath.wstring(), driverData)) {
        ERROR(L"Failed to write driver file to system location");
        return false;
    }

    // Verify file was written successfully
    DWORD fileAttrs = GetFileAttributesW(driverPath.c_str());
    if (fileAttrs == INVALID_FILE_ATTRIBUTES) {
        ERROR(L"Driver file verification failed: %s", driverPath.c_str());
        return false;
    }

    DEBUG(L"Driver file written successfully: %s (%zu bytes)", driverPath.c_str(), driverData.size());

    // Register service
    if (!InitDynamicAPIs()) return false;
    GenerateFakeActivity();
    
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        ERROR(L"Failed to open service control manager: %d", GetLastError());
        return false;
    }

    SC_HANDLE hService = g_pCreateServiceW(
        hSCM, 
        GetServiceName().c_str(), 
        L"KVC",
        SERVICE_ALL_ACCESS, 
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL, 
        driverPath.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr
    );

    if (!hService) {
        DWORD err = GetLastError();
        CloseServiceHandle(hSCM);
        
        if (err != ERROR_SERVICE_EXISTS) {
            ERROR(L"Failed to create driver service: %d", err);
            return false;
        }
        
        INFO(L"Driver service already exists, proceeding");
    } else {
        CloseServiceHandle(hService);
        SUCCESS(L"Driver service created successfully");
    }

    CloseServiceHandle(hSCM);
    SUCCESS(L"Driver installed and registered as Windows service");
    return true;
}

// ============================================================================
// SILENT INSTALLATION
// ============================================================================

bool Controller::InstallDriverSilently() noexcept {
    if (IsServiceZombie()) {
        return false;
    }
    
    // Extract driver (already decrypted)
    auto driverData = ExtractDriver();
    if (driverData.empty()) return false;

    // Get target paths
    fs::path driverDir = GetDriverStorePath();
    fs::path driverPath = driverDir / fs::path(GetDriverFileName());

    // Ensure directory exists with TrustedInstaller privileges
    if (!m_trustedInstaller.CreateDirectoryAsTrustedInstaller(driverDir.wstring())) {
        return false;
    }

    // Write driver directly with TrustedInstaller privileges
    if (!m_trustedInstaller.WriteFileAsTrustedInstaller(driverPath.wstring(), driverData)) {
        return false;
    }

    // Verify file
    DWORD fileAttrs = GetFileAttributesW(driverPath.c_str());
    if (fileAttrs == INVALID_FILE_ATTRIBUTES) {
        return false;
    }

    // Register service
    return RegisterDriverServiceSilent(driverPath.wstring());
}

bool Controller::RegisterDriverServiceSilent(const std::wstring& driverPath) noexcept {
    if (!InitDynamicAPIs()) return false;
    
    if (IsServiceZombie()) {
        DEBUG(L"Zombie service detected - restart required");
        return false;
    }
    
    GenerateFakeActivity();
    
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return false;

    SC_HANDLE hService = g_pCreateServiceW(
        hSCM, 
        GetServiceName().c_str(), 
        L"KVC",
        SERVICE_ALL_ACCESS, 
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL, 
        driverPath.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr
    );

    bool success = (hService != nullptr) || (GetLastError() == ERROR_SERVICE_EXISTS);
    
    if (hService) CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return success;
}

// ============================================================================
// DRIVER UNINSTALLATION
// ============================================================================

bool Controller::UninstallDriver() noexcept {
    StopDriverService();

    if (!InitDynamicAPIs()) return true;

    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        return true;
    }

    std::wstring serviceName = GetServiceName();
    SC_HANDLE hService = g_pOpenServiceW(hSCM, serviceName.c_str(), DELETE);
    if (!hService) {
        CloseServiceHandle(hSCM);
        return true;
    }

    BOOL success = g_pDeleteService(hService);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    if (!success) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_MARKED_FOR_DELETE) {
            ERROR(L"Failed to delete driver service: %d", err);
            return false;
        }
    }

    // Clean up driver file with TrustedInstaller privileges
    fs::path driverDir = GetDriverStorePath();
    fs::path driverPath = driverDir / fs::path(GetDriverFileName());
    
    std::error_code ec;
    if (!fs::remove(driverPath, ec)) {
        if (ec.value() != ERROR_FILE_NOT_FOUND) {
            m_trustedInstaller.DeleteFileAsTrustedInstaller(driverPath.wstring());
        }
    }

    return true;
}

// ============================================================================
// DRIVER EXTRACTION
// ============================================================================

// Extract driver from resource (already decrypted by Utils::ExtractResourceComponents)
std::vector<BYTE> Controller::ExtractDriver() noexcept {
    std::vector<BYTE> kvcSysData, dllData;
    
    if (!Utils::ExtractResourceComponents(IDR_MAINICON, kvcSysData, dllData)) {
        ERROR(L"Failed to extract kvc.sys from resource");
        return {};
    }
    
    DEBUG(L"Driver extracted: %zu bytes", kvcSysData.size());
    return kvcSysData;
}