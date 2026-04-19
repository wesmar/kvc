// ControllerDriverManager.cpp
// Driver lifecycle management: installation, service control, extraction
// Author: Marek Wesolowski, 2025

#include "Controller.h"
#include "common.h"
#include "Utils.h"
#include "HelpSystem.h"
#include "resource.h"
#include <filesystem>
#include <tlhelp32.h>

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
// NON-COMPLIANT HOST PROCESS HANDLING
// ============================================================================
// Some tools (e.g. MSI Afterburner) load a non-compliant kernel driver and keep
// it alive as long as their host process runs.  Stopping the service via SCM
// leaves the driver in STOP_PENDING as long as the host holds it open.
// The reliable fix: terminate the host — it cleans up the driver on exit.
// Registry key: HKLM\SOFTWARE\WOW6432Node\MSI\Afterburner -> InstallPath
// The host is not restarted — it will relaunch itself if configured to do so.
// ============================================================================

bool Controller::CheckAndTerminateNonCompliantHost() noexcept
{
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\WOW6432Node\\MSI\\Afterburner",
                      0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return false;

    WCHAR pathBuf[MAX_PATH + 1]{};
    DWORD bufSize = sizeof(pathBuf);
    DWORD type = 0;
    LSTATUS ls = RegQueryValueExW(hKey, L"InstallPath", nullptr, &type,
                                  reinterpret_cast<LPBYTE>(pathBuf), &bufSize);
    RegCloseKey(hKey);

    if (ls != ERROR_SUCCESS || type != REG_SZ || pathBuf[0] == L'\0')
        return false;

    std::wstring exePath = pathBuf;
    std::wstring exeName = fs::path(exePath).filename().wstring();
    std::wstring exeNameLow = StringUtils::ToLowerCaseCopy(exeName);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    bool closed = false;

    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (StringUtils::ToLowerCaseCopy(pe.szExeFile) == exeNameLow) {
                HANDLE hProc = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pe.th32ProcessID);
                if (hProc) {
                    TerminateProcess(hProc, 0);
                    WaitForSingleObject(hProc, 5000);
                    CloseHandle(hProc);
                    closed = true;
                    INFO(L"[non-compliant host] Terminated: %s (PID %u)", exeName.c_str(), pe.th32ProcessID);
                }
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);

    if (closed) {
        // Poll service state until fully stopped — no Sleep, tight loop.
        // After host exits the driver unloads; this should break within microseconds.
        if (InitDynamicAPIs()) {
            SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
            if (hSCM) {
                SC_HANDLE hSvc = g_pOpenServiceW(hSCM, GetServiceName().c_str(), SERVICE_QUERY_STATUS);
                if (hSvc) {
                    SERVICE_STATUS st{};
                    for (int i = 0; i < 5000 &&
                         QueryServiceStatus(hSvc, &st) &&
                         st.dwCurrentState != SERVICE_STOPPED; ++i) {}
                    CloseServiceHandle(hSvc);
                }
                CloseServiceHandle(hSCM);
            }
        }
    }

    return closed;
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

    SC_HANDLE hService = g_pOpenServiceW(hSCM, GetServiceName().c_str(), 
                                         SERVICE_STOP | SERVICE_QUERY_STATUS);
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

    // Kernel drivers stop synchronously - no waiting required
    if (status.dwCurrentState == SERVICE_RUNNING) {
        if (!g_pControlService(hService, SERVICE_CONTROL_STOP, &status)) {
            DWORD err = GetLastError();
            if (err != ERROR_SERVICE_NOT_ACTIVE) {
                DEBUG(L"ControlService failed: %d", err);
                CloseServiceHandle(hService);
                CloseServiceHandle(hSCM);
                return false;
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
        CRITICAL(HelpLayout::MakeBorder(L'=', 63).c_str());
        CRITICAL(L"  DRIVER SERVICE IN ZOMBIE STATE - SYSTEM RESTART REQUIRED");
        CRITICAL(HelpLayout::MakeBorder(L'=', 63).c_str());
        CRITICAL(L"");
        CRITICAL(L"The kernel driver service is marked for deletion but cannot be");
        CRITICAL(L"removed until the system is restarted. This typically occurs");
        CRITICAL(L"when driver loading is interrupted during initialization.");
        CRITICAL(L"");
        INFO(L"Required action: Restart your computer to clear the zombie state");
        INFO(L"After restart, the driver will load normally");
        CRITICAL(L"");
        CRITICAL(HelpLayout::MakeBorder(L'=', 63).c_str());
        CRITICAL(L"");
        return false;
    }
    
    // Extract drivers from resource
    std::vector<BYTE> kvcstrmData;
    auto driverData = ExtractDriver(kvcstrmData);
    if (driverData.empty()) {
        ERROR(L"Failed to extract kvc.sys from resource");
        return false;
    }
    if (kvcstrmData.empty()) {
        ERROR(L"Failed to extract kvcstrm.sys from resource");
        return false;
    }

    // Get target paths (both drivers land in the same DriverStore directory)
    fs::path driverDir = GetDriverStorePath();
    fs::path driverPath     = driverDir / fs::path(GetDriverFileName());
    fs::path kvcstrmPath = driverDir / fs::path(GetKvcstrmFileName());

    INFO(L"Target driver path: %s", driverPath.c_str());
    INFO(L"Target kvcstrm path: %s", kvcstrmPath.c_str());

    // Ensure directory exists with TrustedInstaller privileges
    INFO(L"Creating driver directory with TrustedInstaller privileges...");
    if (!m_trustedInstaller.CreateDirectoryAsTrustedInstaller(driverDir.wstring())) {
        ERROR(L"Failed to create driver directory: %s", driverDir.c_str());
        return false;
    }
    DEBUG(L"Driver directory ready: %s", driverDir.c_str());

    // Write kvc.sys
    INFO(L"Writing kvc.sys with TrustedInstaller privileges...");
    if (!m_trustedInstaller.WriteFileAsTrustedInstaller(driverPath.wstring(), driverData)) {
        ERROR(L"Failed to write kvc.sys to system location");
        return false;
    }
    DWORD fileAttrs = GetFileAttributesW(driverPath.c_str());
    if (fileAttrs == INVALID_FILE_ATTRIBUTES) {
        ERROR(L"kvc.sys verification failed: %s", driverPath.c_str());
        return false;
    }
    DEBUG(L"kvc.sys written successfully: %s (%zu bytes)", driverPath.c_str(), driverData.size());

    // Write kvcstrm.sys
    INFO(L"Writing kvcstrm.sys with TrustedInstaller privileges...");
    if (!m_trustedInstaller.WriteFileAsTrustedInstaller(kvcstrmPath.wstring(), kvcstrmData)) {
        ERROR(L"Failed to write kvcstrm.sys to system location");
        return false;
    }
    DWORD omniAttrs = GetFileAttributesW(kvcstrmPath.c_str());
    if (omniAttrs == INVALID_FILE_ATTRIBUTES) {
        ERROR(L"kvcstrm.sys verification failed: %s", kvcstrmPath.c_str());
        return false;
    }
    DEBUG(L"kvcstrm.sys written successfully: %s (%zu bytes)", kvcstrmPath.c_str(), kvcstrmData.size());

    // Register service
    if (!InitDynamicAPIs()) return false;
        
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
    
    // Extract drivers from resource
    std::vector<BYTE> kvcstrmData;
    auto driverData = ExtractDriver(kvcstrmData);
    if (driverData.empty() || kvcstrmData.empty()) return false;

    // Get target paths (both drivers land in the same DriverStore directory)
    fs::path driverDir      = GetDriverStorePath();
    fs::path driverPath     = driverDir / fs::path(GetDriverFileName());
    fs::path kvcstrmPath = driverDir / fs::path(GetKvcstrmFileName());

    // Ensure directory exists with TrustedInstaller privileges
    if (!m_trustedInstaller.CreateDirectoryAsTrustedInstaller(driverDir.wstring())) {
        return false;
    }

    // Write kvc.sys
    if (!m_trustedInstaller.WriteFileAsTrustedInstaller(driverPath.wstring(), driverData)) {
        return false;
    }
    if (GetFileAttributesW(driverPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        return false;
    }

    // Write kvcstrm.sys
    // If the write fails (e.g. ERROR_SHARING_VIOLATION / error 32 because
    // kvcstrm.sys is currently loaded as an external driver), treat it as
    // non-fatal provided the file already exists on disk. kvc.sys is the only
    // component that must be freshly written; kvcstrm.sys being present and
    // locked means it is already the correct binary from a previous extract.
    if (!m_trustedInstaller.WriteFileAsTrustedInstaller(kvcstrmPath.wstring(), kvcstrmData)) {
        if (GetFileAttributesW(kvcstrmPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            // File does not exist at all - genuine failure.
            return false;
        }
        // File exists but is locked - acceptable, continue.
        DEBUG(L"kvcstrm.sys write skipped (file locked by running driver) - using existing copy");
    } else if (GetFileAttributesW(kvcstrmPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
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

    // File cleanup is always attempted regardless of SCM state
    DeleteDriverFiles();

    return true;
}

// Removes kvc.sys and kvcstrm.sys from DriverStore using TrustedInstaller privileges.
// Called from both UninstallDriver() and HandleUninstall() to ensure cleanup
// even when the SCM entry is already gone.
void Controller::DeleteDriverFiles() noexcept
{
    fs::path driverDir   = GetDriverStorePath();
    fs::path driverPath  = driverDir / fs::path(GetDriverFileName());
    fs::path kvcstrmPath = driverDir / fs::path(GetKvcstrmFileName());

    // Before deleting kvcstrm.sys, stop and remove the kvcstrm service if it
    // is currently running as an externally loaded driver. Without this step
    // the kernel holds the file open, DeleteFileAsTrustedInstaller() fails
    // silently, and the stale locked file remains on disk. Subsequent kvc
    // operations then fail because InstallDriverSilently() cannot overwrite it.
    if (InitDynamicAPIs()) {
        std::wstring kvcstrmSvc = GetKvcstrmFileName(); // "kvcstrm.sys"
        if (kvcstrmSvc.size() >= 4)
            kvcstrmSvc = kvcstrmSvc.substr(0, kvcstrmSvc.size() - 4); // "kvcstrm"

        SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (hSCM) {
            SC_HANDLE hSvc = g_pOpenServiceW(hSCM, kvcstrmSvc.c_str(),
                                             SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
            if (hSvc) {
                SERVICE_STATUS svcStatus{};
                if (QueryServiceStatus(hSvc, &svcStatus) &&
                    svcStatus.dwCurrentState != SERVICE_STOPPED) {
                    INFO(L"Stopping external kvcstrm driver before file removal...");
                    g_pControlService(hSvc, SERVICE_CONTROL_STOP, &svcStatus);
                }
                if (!g_pDeleteService(hSvc)) {
                    DWORD err = GetLastError();
                    if (err != ERROR_SERVICE_DOES_NOT_EXIST &&
                        err != ERROR_SERVICE_MARKED_FOR_DELETE) {
                        DEBUG(L"kvcstrm service delete returned: %d", err);
                    }
                } else {
                    DEBUG(L"kvcstrm external service entry removed");
                }
                CloseServiceHandle(hSvc);
            }
            CloseServiceHandle(hSCM);
        }
    }

    auto removeOne = [this](const fs::path& p) {
        std::error_code ec;
        if (fs::remove(p, ec)) {
            DEBUG(L"Removed: %s", p.c_str());
            return;
        }
        // fs::remove returns false both for "not found" (ec==0 on MSVC) and
        // access errors - call TI unconditionally and let it handle both cases.
        m_trustedInstaller.DeleteFileAsTrustedInstaller(p.wstring());
    };

    removeOne(driverPath);
    removeOne(kvcstrmPath);
}

// ============================================================================
// DRIVER EXTRACTION
// ============================================================================

// Extract drivers from resource (already decrypted by Utils::ExtractResourceComponents)
// Returns kvc.sys data; also populates outKvcstrm with kvcstrm.sys data
std::vector<BYTE> Controller::ExtractDriver(std::vector<BYTE>& outKvcstrm) noexcept {
    std::vector<BYTE> kvcSysData, dllData, smssData;

    if (!Utils::ExtractResourceComponents(IDR_MAINICON, kvcSysData, outKvcstrm, dllData, smssData)) {
        ERROR(L"Failed to extract drivers from resource");
        return {};
    }

    DEBUG(L"kvc.sys extracted: %zu bytes, kvcstrm.sys: %zu bytes",
          kvcSysData.size(), outKvcstrm.size());
    return kvcSysData;
}