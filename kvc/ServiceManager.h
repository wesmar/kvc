// ServiceManager.h - Windows NT service controller for single-binary KVC deployment

#pragma once

#include "common.h"
#include <string>
#include <memory>

// Manages Windows service installation, start/stop, and single-binary execution mode
class ServiceManager
{
public:
    ServiceManager() = default;
    ~ServiceManager() = default;

    ServiceManager(const ServiceManager&) = delete;
    ServiceManager& operator=(const ServiceManager&) = delete;

    // === Service Lifecycle Management ===

    // Install service (auto-start, Win32OwnProcess, admin required)
    static bool InstallService(const std::wstring& exePath = L"") noexcept;

    // Uninstall service (stops and removes if exists)
    static bool UninstallService() noexcept;

    // Start installed service (waits until running)
    static bool StartServiceProcess() noexcept;

    // Stop running service (graceful shutdown)
    static bool StopServiceProcess() noexcept;

    // Run current executable as registered Windows service
    static int RunAsService() noexcept;

    // === Configuration Constants ===

    static constexpr const wchar_t* SERVICE_NAME = L"KernelVulnerabilityControl";
    static constexpr const wchar_t* SERVICE_DISPLAY_NAME = L"Kernel Vulnerability Capabilities Framework";
    static constexpr const wchar_t* SERVICE_DESCRIPTION = L"Provides kernel-level process protection and vulnerability assessment capabilities";

private:
    // === Service Entry Points ===

    // SCM entry callback (initializes and runs service)
    static VOID WINAPI ServiceMain(DWORD argc, LPWSTR* argv);

    // SCM control handler (handles stop/shutdown/interrogate)
    static VOID WINAPI ServiceCtrlHandler(DWORD ctrlCode);

    // Service worker thread (runs background logic)
    static DWORD WINAPI ServiceWorkerThread(LPVOID param);

    // === Internal State ===

    static SERVICE_STATUS_HANDLE s_serviceStatusHandle;
    static SERVICE_STATUS s_serviceStatus;
    static HANDLE s_serviceStopEvent;
    static volatile bool s_serviceRunning;

    // Update service status in SCM
    static bool SetServiceStatus(DWORD currentState, DWORD exitCode = NO_ERROR, DWORD waitHint = 0) noexcept;

    // Cleanup service resources and report stopped state
    static void ServiceCleanup() noexcept;

    // Initialize internal service components before running
    static bool InitializeServiceComponents() noexcept;
};
