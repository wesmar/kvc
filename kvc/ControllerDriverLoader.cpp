// ControllerDriverLoader.cpp
// External driver loading with DSE bypass (Safe method) - automatic restore

#include "Controller.h"
#include "common.h"
#include <algorithm>

// Check if HVCI is enabled and handle it (returns true if safe to proceed)
bool Controller::CheckAndHandleHVCI(const std::wstring& operation, const std::wstring& targetPath) noexcept {
    PerformAtomicCleanup();
    if (!BeginDriverSession()) {
        ERROR(L"Failed to start driver session for HVCI check");
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
    
    // Get DSE status to check HVCI
    DSEBypass::Status status;
    if (!m_dseBypass->GetStatus(status)) {
        ERROR(L"Failed to get DSE status");
        EndDriverSession(true);
        return false;
    }
    
    EndDriverSession(true);
    
    if (!status.HVCIEnabled) {
        SUCCESS(L"Memory Integrity is disabled - safe to proceed");
        return true;
    }
    
    // HVCI is enabled - same handling as DisableDSESafe()
    INFO(L"Memory Integrity is enabled (g_CiOptions = 0x%08X)", status.CiOptionsValue);
    INFO(L"A reboot is required to disable Memory Integrity before driver %s", operation.c_str());
    std::wcout << L"\n";
    std::wcout << L"Disable Memory Integrity and reboot now? [Y/N]: ";
    wchar_t choice;
    std::wcin >> choice;
    if (choice != L'Y' && choice != L'y') {
        INFO(L"Operation cancelled by user");
        return false;
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
        return false;
    }
    INFO(L"Initiating system reboot...");
    INFO(L"After reboot, run 'kvc driver %s %s' again to complete the operation", 
         operation.c_str(), targetPath.c_str());
    // Enable shutdown privilege and reboot
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
    }
    return false; // Don't proceed - reboot required
}

std::wstring Controller::NormalizeDriverPath(const std::wstring& input) noexcept {
    if (input.find(L'\\') != std::wstring::npos || input.find(L':') != std::wstring::npos) {
        std::wstring path = input;
        if (path.length() < 4 || StringUtils::ToLowerCaseCopy(path.substr(path.length() - 4)) != L".sys") {
            path += L".sys";
        }
        return path;
    }
    std::wstring filename = input;
    if (filename.length() < 4 || StringUtils::ToLowerCaseCopy(filename.substr(filename.length() - 4)) != L".sys") {
        filename += L".sys";
    }
    wchar_t sysDir[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);
    return std::wstring(sysDir) + L"\\drivers\\" + filename;
}

std::wstring Controller::ExtractServiceName(const std::wstring& driverPath) noexcept {
    size_t lastSlash = driverPath.find_last_of(L"\\/");
    std::wstring filename = (lastSlash != std::wstring::npos) 
        ? driverPath.substr(lastSlash + 1) 
        : driverPath;
    if (filename.length() >= 4) {
        std::wstring ext = StringUtils::ToLowerCaseCopy(filename.substr(filename.length() - 4));
        if (ext == L".sys") {
            filename = filename.substr(0, filename.length() - 4);
        }
    }
    return filename;
}

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
    
    // CHECK AND HANDLE HVCI
    if (!CheckAndHandleHVCI(L"load", normalizedPath)) {
        return false;
    }
    
    bool dseDisabled = false;
    bool driverLoaded = false;
    
    // STEP 1: ACTIVATE DSE BYPASS (Safe Mode)
    {
        INFO(L"Activating DSE bypass (Safe Mode)...");
        PerformAtomicCleanup();
        
        if (!BeginDriverSession()) {
            ERROR(L"Failed to start driver session for DSE bypass");
            return false;
        }
        
        if (!m_rtc->Initialize()) {
            ERROR(L"Failed to initialize handle kvc (kvc.sys)");
            EndDriverSession(true);
            return false;
        }
        
        if (!m_dseBypass) {
            m_dseBypass = std::make_unique<DSEBypass>(m_rtc, &m_trustedInstaller);
        }
        
        if (!m_dseBypass->Disable(DSEBypass::Method::Safe)) {
            ERROR(L"Failed to disable DSE");
            EndDriverSession(true);
            return false;
        }
        
        dseDisabled = true;
        SUCCESS(L"DSE bypass activated successfully");
        EndDriverSession(true); // Close session to avoid conflicts with SCM
    }
    
    // STEP 2: LOAD THE DRIVER (with guaranteed DSE restore on exit)
    {
        bool serviceSuccess = false;
        bool apiInitialized = false;
        
        // RAII-style DSE restore guarantee
        auto dseRestoreGuard = [&]() {
            if (dseDisabled) {
                INFO(L"Auto-restoring DSE protection...");
                
                if (!BeginDriverSession()) {
                    ERROR(L"Failed to start driver session for DSE restore");
                    ERROR(L"DSE remains disabled - run 'kvc dse on --safe' manually");
                    return;
                }
                
                if (!m_rtc->Initialize()) {
                    ERROR(L"Failed to initialize driver handle for DSE restore");
                    ERROR(L"DSE remains disabled - run 'kvc dse on --safe' manually");
                    EndDriverSession(true);
                    return;
                }
                
                if (!m_dseBypass) {
                    m_dseBypass = std::make_unique<DSEBypass>(m_rtc, &m_trustedInstaller);
                }
                
                if (m_dseBypass->Restore(DSEBypass::Method::Safe)) {
                    SUCCESS(L"DSE protection restored successfully");
                } else {
                    ERROR(L"Failed to restore DSE protection");
                    ERROR(L"Run 'kvc dse on --safe' to manually restore kernel protection");
                }
                
                EndDriverSession(true);
            }
        };
        
        if (!InitDynamicAPIs()) {
            ERROR(L"Failed to initialize service APIs");
            dseRestoreGuard();
            return false;
        }
        apiInitialized = true;
        
        // Try to create and start the service
        SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
        if (!hSCM) {
            ERROR(L"Failed to open Service Control Manager: %d", GetLastError());
            dseRestoreGuard();
            return false;
        }
        
        // Check if service already exists
        SC_HANDLE hService = g_pOpenServiceW(hSCM, serviceName.c_str(), SERVICE_ALL_ACCESS);
        if (hService) {
            INFO(L"Service already exists - attempting to start...");
            
            // Query current status
            SERVICE_STATUS status;
            if (QueryServiceStatus(hService, &status)) {
                if (status.dwCurrentState == SERVICE_RUNNING) {
                    SUCCESS(L"Driver service is already running");
                    CloseServiceHandle(hService);
                    CloseServiceHandle(hSCM);
                    driverLoaded = true;
                    dseRestoreGuard();
                    return true;
                }
            }
            
            // Try to start
            if (g_pStartServiceW(hService, 0, nullptr)) {
                SUCCESS(L"Driver service started successfully");
                driverLoaded = true;
            } else {
                DWORD err = GetLastError();
                if (err == ERROR_SERVICE_ALREADY_RUNNING) {
                    SUCCESS(L"Driver service is already running");
                    driverLoaded = true;
                } else {
                    ERROR(L"Failed to start existing service: %d", err);
                }
            }
            CloseServiceHandle(hService);
        } else {
            // Create new service
            INFO(L"Creating new driver service...");
            hService = g_pCreateServiceW(
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
            
            if (!hService) {
                ERROR(L"Failed to create service: %d", GetLastError());
                CloseServiceHandle(hSCM);
                dseRestoreGuard();
                return false;
            }
            
            SUCCESS(L"Driver service created successfully");
            
            // Start the service
            if (g_pStartServiceW(hService, 0, nullptr)) {
                SUCCESS(L"Driver service started successfully");
                driverLoaded = true;
            } else {
                DWORD err = GetLastError();
                if (err == ERROR_SERVICE_ALREADY_RUNNING) {
                    SUCCESS(L"Driver service is already running");
                    driverLoaded = true;
                } else {
                    ERROR(L"Failed to start service: %d", err);
                }
            }
            CloseServiceHandle(hService);
        }
        
        CloseServiceHandle(hSCM);
        
        // STEP 3: AUTO-RESTORE DSE AFTER LOAD (always called)
        dseRestoreGuard();
    }
    
    return driverLoaded;
}

bool Controller::ReloadExternalDriver(const std::wstring& driverNameOrPath) noexcept {
    std::wstring normalizedPath = NormalizeDriverPath(driverNameOrPath);
    std::wstring serviceName = ExtractServiceName(normalizedPath);
    INFO(L"Reloading driver: %s", serviceName.c_str());
    
    // CHECK AND HANDLE HVCI
    if (!CheckAndHandleHVCI(L"reload", normalizedPath)) {
        return false;
    }
    
    bool dseDisabled = false;
    bool driverReloaded = false;
    
    // STEP 1: ACTIVATE DSE BYPASS (Safe Mode)
    {
        INFO(L"Activating DSE bypass (Safe Mode)...");
        PerformAtomicCleanup();
        
        if (!BeginDriverSession()) {
            ERROR(L"Failed to start driver session");
            return false;
        }
        
        if (!m_rtc->Initialize()) {
            ERROR(L"Failed to initialize handle kvc (kvc.sys)");
            EndDriverSession(true);
            return false;
        }
        
        if (!m_dseBypass) {
            m_dseBypass = std::make_unique<DSEBypass>(m_rtc, &m_trustedInstaller);
        }
        
        if (!m_dseBypass->Disable(DSEBypass::Method::Safe)) {
            ERROR(L"Failed to disable DSE");
            EndDriverSession(true);
            return false;
        }
        
        dseDisabled = true;
        SUCCESS(L"DSE bypass activated successfully");
        EndDriverSession(true);
    }
    
    // STEP 2: RELOAD THE DRIVER (with guaranteed DSE restore)
    {
        // RAII-style DSE restore guarantee
        auto dseRestoreGuard = [&]() {
            if (dseDisabled) {
                INFO(L"Auto-restoring DSE protection...");
                
                if (!BeginDriverSession()) {
                    ERROR(L"Failed to start driver session for DSE restore");
                    ERROR(L"DSE remains disabled - run 'kvc dse on --safe' manually");
                    return;
                }
                
                if (!m_rtc->Initialize()) {
                    ERROR(L"Failed to initialize driver handle for DSE restore");
                    ERROR(L"DSE remains disabled - run 'kvc dse on --safe' manually");
                    EndDriverSession(true);
                    return;
                }
                
                if (!m_dseBypass) {
                    m_dseBypass = std::make_unique<DSEBypass>(m_rtc, &m_trustedInstaller);
                }
                
                if (m_dseBypass->Restore(DSEBypass::Method::Safe)) {
                    SUCCESS(L"DSE protection restored successfully");
                } else {
                    ERROR(L"Failed to restore DSE protection");
                    ERROR(L"Run 'kvc dse on --safe' to manually restore kernel protection");
                }
                
                EndDriverSession(true);
            }
        };
        
        if (!InitDynamicAPIs()) {
            ERROR(L"Failed to initialize service APIs");
            dseRestoreGuard();
            return false;
        }
        
        // Stop existing service if running
        SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (hSCM) {
            SC_HANDLE hService = g_pOpenServiceW(hSCM, serviceName.c_str(), SERVICE_ALL_ACCESS);
            if (hService) {
                SERVICE_STATUS status;
                if (g_pControlService(hService, SERVICE_CONTROL_STOP, &status)) {
                    INFO(L"Service stopped successfully");
                }
                CloseServiceHandle(hService);
            }
            CloseServiceHandle(hSCM);
        }
        
        // Start service
        bool startSuccess = false;
        hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (hSCM) {
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
                    driverReloaded = true;
                } else {
                    ERROR(L"Failed to start service: %d", GetLastError());
                }
                CloseServiceHandle(hService);
            }
            CloseServiceHandle(hSCM);
        }
        
        // STEP 3: AUTO-RESTORE DSE AFTER RELOAD (always called)
        dseRestoreGuard();
    }
    
    return driverReloaded;
}

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
    SERVICE_STATUS status;
    if (QueryServiceStatus(hService, &status)) {
        if (status.dwCurrentState == SERVICE_STOPPED) {
            INFO(L"Service is already stopped");
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return true;
        }
    }
    if (!g_pControlService(hService, SERVICE_CONTROL_STOP, &status)) {
        ERROR(L"Failed to stop service: %d", GetLastError());
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return false;
    }
    SUCCESS(L"Driver service stopped: %s", serviceName.c_str());
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return true;
}

bool Controller::RemoveExternalDriver(const std::wstring& driverNameOrPath) noexcept {
    std::wstring serviceName = ExtractServiceName(driverNameOrPath);
    INFO(L"Removing driver service: %s", serviceName.c_str());
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
