// ControllerDriverLoader.cpp
// External driver loading with DSE bypass (NG method) - HVCI detection added
// Author: Marek Wesolowski, 2025

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
    // Check g_CiOptions to determine if Memory Integrity is enabled
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
    bool hvciEnabled = (currentValue & 0x0001C000) == 0x0001C000;
    EndDriverSession(true);
    if (!hvciEnabled) {
        SUCCESS(L"Memory Integrity is disabled - safe to proceed");
        return true;
    }
    // HVCI is enabled - same handling as DisableDSESafe()
    INFO(L"Memory Integrity is enabled (g_CiOptions = 0x%08X)", currentValue);
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
    // If contains \ or : -> treat as full path
    if (input.find(L'\\') != std::wstring::npos || input.find(L':') != std::wstring::npos) {
        std::wstring path = input;
        // Ensure .sys extension
        if (path.length() < 4 || StringUtils::ToLowerCaseCopy(path.substr(path.length() - 4)) != L".sys") {
            path += L".sys";
        }
        return path;
    }
    // Otherwise -> System32\drivers\<name>.sys
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
    // === CHECK AND HANDLE HVCI (same logic as DisableDSESafe) ===
    if (!CheckAndHandleHVCI(L"load", normalizedPath)) {
        return false; // Either HVCI enabled and user cancelled, or reboot initiated
    }
    
    // === ALWAYS ENSURE DSE-NG IS ACTIVE (Safe Mode) ===
    // We removed the registry check to force verification against kernel memory
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
    if (!m_dseBypassNG) {
        m_dseBypassNG = std::make_unique<DSEBypassNG>(m_rtc);
    }
    if (!m_dseBypassNG->DisableDSE()) {
        ERROR(L"Failed to disable DSE");
        EndDriverSession(true);
        return false;
    }
    EndDriverSession(true);
    SUCCESS(L"DSE bypass activated successfully");

    // === LOAD THE DRIVER ===
    bool serviceSuccess = false;
    if (!InitDynamicAPIs()) {
        ERROR(L"Failed to initialize service APIs");
        return false;
    }
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        ERROR(L"Failed to open Service Control Manager: %d", GetLastError());
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
    if (serviceSuccess) {
        SUCCESS(L"External driver loaded successfully: %s", serviceName.c_str());
    }
    return serviceSuccess;
}

bool Controller::ReloadExternalDriver(const std::wstring& driverNameOrPath) noexcept {
    std::wstring normalizedPath = NormalizeDriverPath(driverNameOrPath);
    std::wstring serviceName = ExtractServiceName(normalizedPath);
    INFO(L"Reloading driver: %s", serviceName.c_str());
    // === CHECK AND HANDLE HVCI (same logic as DisableDSESafe) ===
    if (!CheckAndHandleHVCI(L"reload", serviceName)) {
        return false; // Either HVCI enabled and user cancelled, or reboot initiated
    }
    
    // === ALWAYS ENSURE DSE-NG IS ACTIVE (Safe Mode) ===
    // We removed the registry check to force verification against kernel memory
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
    if (!m_dseBypassNG) {
        m_dseBypassNG = std::make_unique<DSEBypassNG>(m_rtc);
    }
    if (!m_dseBypassNG->DisableDSE()) {
        ERROR(L"Failed to disable DSE");
        EndDriverSession(true);
        return false;
    }
    EndDriverSession(true);
    SUCCESS(L"DSE bypass activated successfully");

    // === RELOAD THE DRIVER ===
    if (!InitDynamicAPIs()) {
        ERROR(L"Failed to initialize service APIs");
        return false;
    }
    // Stop existing service if running (kernel drivers stop synchronously)
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
    return startSuccess;
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
    // Send stop command (kernel drivers stop synchronously)
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