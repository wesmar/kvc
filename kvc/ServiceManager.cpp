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

#include "ServiceManager.h"
#include "Controller.h"
#include "KeyboardHook.h"
#include "common.h"
#include <memory>

// Service static members
SERVICE_STATUS_HANDLE ServiceManager::s_serviceStatusHandle = nullptr;
SERVICE_STATUS ServiceManager::s_serviceStatus = {};
HANDLE ServiceManager::s_serviceStopEvent = nullptr;
volatile bool ServiceManager::s_serviceRunning = false;

// Global service components
static std::unique_ptr<Controller> g_serviceController = nullptr;
static std::unique_ptr<KeyboardHook> g_keyboardHook = nullptr;

bool ServiceManager::InstallService(const std::wstring& exePath) noexcept
{
    if (!InitDynamicAPIs()) {
        ERROR(L"Failed to initialize service APIs");
        return false;
    }

    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) {
        ERROR(L"Failed to open Service Control Manager: %d", GetLastError());
        return false;
    }

    // Build service command line with --service parameter
    std::wstring servicePath = L"\"" + exePath + L"\" --service";

    SC_HANDLE hService = g_pCreateServiceW(
        hSCM,
        SERVICE_NAME,
        SERVICE_DISPLAY_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        servicePath.c_str(),
        nullptr,    // No load ordering group
        nullptr,    // No tag identifier
        nullptr,    // No dependencies
        nullptr,    // LocalSystem account
        nullptr     // No password
    );

    if (!hService) {
        DWORD error = GetLastError();
        CloseServiceHandle(hSCM);
        
        if (error == ERROR_SERVICE_EXISTS) {
            INFO(L"Service already exists, attempting to update configuration");
            
            hService = g_pOpenServiceW(hSCM, SERVICE_NAME, SERVICE_CHANGE_CONFIG);
            if (hService) {
                BOOL success = ChangeServiceConfigW(
                    hService,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL,
                    servicePath.c_str(),
                    nullptr, nullptr, nullptr, nullptr, nullptr, SERVICE_DISPLAY_NAME
                );
                CloseServiceHandle(hService);
                CloseServiceHandle(hSCM);
                
                if (success) {
                    SUCCESS(L"Service configuration updated successfully");
                    return true;
                } else {
                    ERROR(L"Failed to update service configuration: %d", GetLastError());
                    return false;
                }
            }
            return false;
        }
        
        ERROR(L"Failed to create service: %d", error);
        return false;
    }

    // Set service description
    SERVICE_DESCRIPTIONW serviceDesc = {};
    serviceDesc.lpDescription = const_cast<wchar_t*>(SERVICE_DESCRIPTION);
    ChangeServiceConfig2W(hService, SERVICE_CONFIG_DESCRIPTION, &serviceDesc);

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    SUCCESS(L"Service '%s' installed successfully", SERVICE_DISPLAY_NAME);
    
    // Attempt to start the service
    if (StartServiceProcess()) {
        SUCCESS(L"Service started successfully");
    } else {
        INFO(L"Service installed but failed to start automatically");
    }

    return true;
}

bool ServiceManager::UninstallService() noexcept
{
    if (!InitDynamicAPIs()) {
        ERROR(L"Failed to initialize service APIs");
        return false;
    }

    // First try to stop the service
    StopServiceProcess();

    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) {
        ERROR(L"Failed to open Service Control Manager: %d", GetLastError());
        return false;
    }

    SC_HANDLE hService = g_pOpenServiceW(hSCM, SERVICE_NAME, DELETE);
    if (!hService) {
        DWORD error = GetLastError();
        CloseServiceHandle(hSCM);
        
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
            INFO(L"Service does not exist");
            return true;
        }
        
        ERROR(L"Failed to open service for deletion: %d", error);
        return false;
    }

    BOOL success = g_pDeleteService(hService);
    DWORD error = GetLastError();

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    if (!success) {
        if (error == ERROR_SERVICE_MARKED_FOR_DELETE) {
            SUCCESS(L"Service marked for deletion (will be removed after next reboot)");
            return true;
        }
        ERROR(L"Failed to delete service: %d", error);
        return false;
    }

    SUCCESS(L"Service '%s' uninstalled successfully", SERVICE_DISPLAY_NAME);
    return true;
}

bool ServiceManager::StartServiceProcess() noexcept
{
    if (!InitDynamicAPIs()) return false;

    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return false;

    SC_HANDLE hService = g_pOpenServiceW(hSCM, SERVICE_NAME, SERVICE_START);
    if (!hService) {
        CloseServiceHandle(hSCM);
        return false;
    }

    BOOL success = g_pStartServiceW(hService, 0, nullptr);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    return success || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
}

bool ServiceManager::StopServiceProcess() noexcept
{
    if (!InitDynamicAPIs()) return false;

    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return false;

    SC_HANDLE hService = g_pOpenServiceW(hSCM, SERVICE_NAME, SERVICE_STOP);
    if (!hService) {
        CloseServiceHandle(hSCM);
        return false;
    }

    SERVICE_STATUS status;
    BOOL success = g_pControlService(hService, SERVICE_CONTROL_STOP, &status);
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    return success || GetLastError() == ERROR_SERVICE_NOT_ACTIVE;
}

int ServiceManager::RunAsService() noexcept
{
    // Enable debug output to Event Log for service debugging
    AllocConsole();
    freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
    freopen_s((FILE**)stderr, "CONOUT$", "w", stderr);
    
    INFO(L"SERVICE MODE: Starting service dispatcher...");

    // Service table for dispatcher
    SERVICE_TABLE_ENTRYW serviceTable[] = {
        { const_cast<wchar_t*>(SERVICE_NAME), ServiceMain },
        { nullptr, nullptr }
    };

    // Start service control dispatcher
    if (!StartServiceCtrlDispatcherW(serviceTable)) {
        ERROR(L"SERVICE MODE: StartServiceCtrlDispatcher failed: %d", GetLastError());
        return 1;
    }

    INFO(L"SERVICE MODE: Service dispatcher completed");
    return 0;
}

VOID WINAPI ServiceManager::ServiceMain(DWORD argc, LPWSTR* argv)
{
    INFO(L"SERVICE: ServiceMain entry point reached");

    // Register service control handler
    s_serviceStatusHandle = RegisterServiceCtrlHandlerW(SERVICE_NAME, ServiceCtrlHandler);
    if (!s_serviceStatusHandle) {
        ERROR(L"SERVICE: RegisterServiceCtrlHandler failed: %d", GetLastError());
        return;
    }

    INFO(L"SERVICE: Control handler registered successfully");

    // Initialize service status
    s_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    s_serviceStatus.dwCurrentState = SERVICE_START_PENDING;
    s_serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    s_serviceStatus.dwWin32ExitCode = NO_ERROR;
    s_serviceStatus.dwServiceSpecificExitCode = 0;
    s_serviceStatus.dwCheckPoint = 0;
    s_serviceStatus.dwWaitHint = 5000;

    SetServiceStatus(SERVICE_START_PENDING, NO_ERROR, 5000);
    INFO(L"SERVICE: Status set to START_PENDING");

    // Create stop event
    s_serviceStopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (!s_serviceStopEvent) {
        ERROR(L"SERVICE: Failed to create service stop event: %d", GetLastError());
        SetServiceStatus(SERVICE_STOPPED, GetLastError());
        return;
    }

    INFO(L"SERVICE: Stop event created successfully");

    // SET RUNNING FLAG BEFORE INITIALIZING COMPONENTS
    s_serviceRunning = true;
    INFO(L"SERVICE: Service running flag set to TRUE");

    // Initialize service components
    if (!InitializeServiceComponents()) {
        ERROR(L"SERVICE: Failed to initialize service components");
        SetServiceStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR);
        ServiceCleanup();
        return;
    }

    INFO(L"SERVICE: Components initialized successfully");

    // Create worker thread
    HANDLE hWorkerThread = CreateThread(nullptr, 0, ServiceWorkerThread, nullptr, 0, nullptr);
    if (!hWorkerThread) {
        ERROR(L"SERVICE: Failed to create worker thread: %d", GetLastError());
        SetServiceStatus(SERVICE_STOPPED, GetLastError());
        ServiceCleanup();
        return;
    }

    INFO(L"SERVICE: Worker thread created successfully");

    // Service is now running
    SetServiceStatus(SERVICE_RUNNING);
    SUCCESS(L"SERVICE: Kernel Vulnerability Capabilities Framework service started successfully");

    // Wait for stop signal
    INFO(L"SERVICE: Waiting for worker thread completion...");
    WaitForSingleObject(hWorkerThread, INFINITE);
    CloseHandle(hWorkerThread);

    INFO(L"SERVICE: Worker thread completed, performing cleanup...");

    // Cleanup and exit
    ServiceCleanup();
    SetServiceStatus(SERVICE_STOPPED);
    
    INFO(L"SERVICE: ServiceMain exiting");
}

VOID WINAPI ServiceManager::ServiceCtrlHandler(DWORD ctrlCode)
{
    switch (ctrlCode) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            INFO(L"SERVICE: Stop/shutdown requested");
            SetServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 5000);
            s_serviceRunning = false;
            if (s_serviceStopEvent) {
                SetEvent(s_serviceStopEvent);
            }
            break;

        case SERVICE_CONTROL_INTERROGATE:
            SetServiceStatus(s_serviceStatus.dwCurrentState);
            break;

        default:
            INFO(L"SERVICE: Unknown control code received: %d", ctrlCode);
            break;
    }
}

DWORD WINAPI ServiceManager::ServiceWorkerThread(LPVOID param)
{
    INFO(L"SERVICE WORKER: Thread started, running flag = %s", s_serviceRunning ? L"TRUE" : L"FALSE");

    DWORD loopCount = 0;

    // Main service loop
    while (s_serviceRunning) {
        loopCount++;
        
        if (loopCount % 12 == 0) { // Every minute (12 * 5 seconds)
            INFO(L"SERVICE WORKER: Heartbeat - loop iteration %d", loopCount);
        }

        // Wait for stop event with timeout for periodic tasks
        DWORD waitResult = WaitForSingleObject(s_serviceStopEvent, 100);
        
        if (waitResult == WAIT_OBJECT_0) {
            INFO(L"SERVICE WORKER: Stop event signaled");
            break;
        }
        
        if (waitResult == WAIT_TIMEOUT) {
            // Normal timeout, continue loop
            continue;
        }
        
        if (waitResult == WAIT_FAILED) {
            ERROR(L"SERVICE WORKER: WaitForSingleObject failed: %d", GetLastError());
            break;
        }
    }

    INFO(L"SERVICE WORKER: Thread exiting after %d iterations", loopCount);
    return 0;
}

bool ServiceManager::SetServiceStatus(DWORD currentState, DWORD exitCode, DWORD waitHint) noexcept
{
    static DWORD checkPoint = 1;

    s_serviceStatus.dwCurrentState = currentState;
    s_serviceStatus.dwWin32ExitCode = exitCode;
    s_serviceStatus.dwWaitHint = waitHint;

    if (currentState == SERVICE_START_PENDING || currentState == SERVICE_STOP_PENDING) {
        s_serviceStatus.dwCheckPoint = checkPoint++;
    } else {
        s_serviceStatus.dwCheckPoint = 0;
    }

    BOOL result = ::SetServiceStatus(s_serviceStatusHandle, &s_serviceStatus);
    
    const wchar_t* stateName = L"UNKNOWN";
    switch (currentState) {
        case SERVICE_START_PENDING: stateName = L"START_PENDING"; break;
        case SERVICE_RUNNING: stateName = L"RUNNING"; break;
        case SERVICE_STOP_PENDING: stateName = L"STOP_PENDING"; break;
        case SERVICE_STOPPED: stateName = L"STOPPED"; break;
    }
    
    INFO(L"SERVICE: Status set to %s, result = %s", stateName, result ? L"SUCCESS" : L"FAILED");
    
    return result != FALSE;
}

bool ServiceManager::InitializeServiceComponents() noexcept
{
    INFO(L"SERVICE INIT: Starting component initialization...");

    try {
        // Initialize controller with atomic operations
        INFO(L"SERVICE INIT: Creating Controller instance...");
        g_serviceController = std::make_unique<Controller>();
        INFO(L"SERVICE INIT: Controller created successfully");
        
        // Self-protect the service with PP-WinTcb
        INFO(L"SERVICE INIT: Attempting self-protection with PP-WinTcb...");
        if (!g_serviceController->SelfProtect(L"PP", L"WinTcb")) {
            ERROR(L"SERVICE INIT: Failed to set service self-protection to PP-WinTcb");
            // Continue anyway - protection failure is not critical for basic operation
        } else {
            SUCCESS(L"SERVICE INIT: Service protected with PP-WinTcb");
        }

        // Initialize keyboard hook for 5x Left Ctrl - THIS IS OPTIONAL
        INFO(L"SERVICE INIT: Attempting to install keyboard hook...");
        g_keyboardHook = std::make_unique<KeyboardHook>();
        if (!g_keyboardHook->Install()) {
            ERROR(L"SERVICE INIT: Failed to install keyboard hook - continuing without it");
            // Don't fail the service if keyboard hook fails
            // Services often can't access interactive desktop
            g_keyboardHook.reset();
        } else {
            SUCCESS(L"SERVICE INIT: Keyboard hook installed (5x Left Ctrl → TrustedInstaller CMD)");
        }
        
        INFO(L"SERVICE INIT: Component initialization completed successfully");
        return true;

    } catch (const std::exception& e) {
        std::string msg = e.what();
        std::wstring wmsg(msg.begin(), msg.end());
        ERROR(L"SERVICE INIT: Exception during initialization: %s", wmsg.c_str());
        return false;
    } catch (...) {
        ERROR(L"SERVICE INIT: Unknown exception during initialization");
        return false;
    }
}

void ServiceManager::ServiceCleanup() noexcept
{
    INFO(L"SERVICE CLEANUP: Starting cleanup process...");

    // Cleanup keyboard hook
    if (g_keyboardHook) {
        INFO(L"SERVICE CLEANUP: Uninstalling keyboard hook...");
        g_keyboardHook->Uninstall();
        g_keyboardHook.reset();
        INFO(L"SERVICE CLEANUP: Keyboard hook cleanup completed");
    }

    // Cleanup controller (automatic driver cleanup)
    if (g_serviceController) {
        INFO(L"SERVICE CLEANUP: Cleaning up controller...");
        g_serviceController.reset();
        INFO(L"SERVICE CLEANUP: Controller cleanup completed");
    }

    // Close stop event
    if (s_serviceStopEvent) {
        INFO(L"SERVICE CLEANUP: Closing stop event...");
        CloseHandle(s_serviceStopEvent);
        s_serviceStopEvent = nullptr;
        INFO(L"SERVICE CLEANUP: Stop event closed");
    }

    SUCCESS(L"SERVICE CLEANUP: All cleanup completed");
}