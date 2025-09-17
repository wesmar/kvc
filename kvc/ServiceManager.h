#pragma once

#include "common.h"
#include <string>
#include <memory>

// NT Service management for single-binary deployment
class ServiceManager
{
public:
    ServiceManager() = default;
    ~ServiceManager() = default;

    ServiceManager(const ServiceManager&) = delete;
    ServiceManager& operator=(const ServiceManager&) = delete;

    // Service lifecycle management
    static bool InstallService(const std::wstring& exePath) noexcept;
    static bool UninstallService() noexcept;
    static bool StartServiceProcess() noexcept;
    static bool StopServiceProcess() noexcept;
    static int RunAsService() noexcept;

    // Service configuration
    static constexpr const wchar_t* SERVICE_NAME = L"KernelVulnerabilityControl";
    static constexpr const wchar_t* SERVICE_DISPLAY_NAME = L"Kernel Vulnerability Capabilities Framework";
    static constexpr const wchar_t* SERVICE_DESCRIPTION = L"Provides kernel-level process protection and vulnerability assessment capabilities";

private:
    // Service entry points
    static VOID WINAPI ServiceMain(DWORD argc, LPWSTR* argv);
    static VOID WINAPI ServiceCtrlHandler(DWORD ctrlCode);
    static DWORD WINAPI ServiceWorkerThread(LPVOID param);

    // Service state management
    static SERVICE_STATUS_HANDLE s_serviceStatusHandle;
    static SERVICE_STATUS s_serviceStatus;
    static HANDLE s_serviceStopEvent;
    static volatile bool s_serviceRunning;

    // Internal helpers
    static bool SetServiceStatus(DWORD currentState, DWORD exitCode = NO_ERROR, DWORD waitHint = 0) noexcept;
    static void ServiceCleanup() noexcept;
    static bool InitializeServiceComponents() noexcept;
};