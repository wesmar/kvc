/**
 * @file ServiceManager.h
 * @brief NT Service management for single-binary deployment
 * @author Marek Wesolowski
 * @date 2025
 * @copyright KVC Framework
 * 
 * Provides Windows Service integration for KVC framework, enabling
 * background operation and automatic startup.
 * Supports single-binary operation (same executable runs as service or console).
 */

#pragma once

#include "common.h"
#include <string>
#include <memory>

/**
 * @class ServiceManager
 * @brief NT Service management for single-binary deployment
 * 
 * Features:
 * - Service installation with automatic start type
 * - Service lifecycle management (start/stop/uninstall)
 * - Single-binary operation (same executable runs as service or console)
 * - Background worker thread for service operations
 * - Automatic cleanup on service stop
 * 
 * Service Details:
 * - Name: KernelVulnerabilityControl
 * - Display: Kernel Vulnerability Capabilities Framework
 * - Type: Win32OwnProcess
 * - Start: Automatic (optional)
 * 
 * @note Requires administrative privileges for service operations
 * @warning Service operations affect system configuration
 */
class ServiceManager
{
public:
    ServiceManager() = default;          ///< Default constructor
    ~ServiceManager() = default;         ///< Default destructor

    // Disable copy semantics
    ServiceManager(const ServiceManager&) = delete;                    ///< Copy constructor deleted
    ServiceManager& operator=(const ServiceManager&) = delete;        ///< Copy assignment deleted

    // === Service Lifecycle Management ===
    
    /**
     * @brief Install service with automatic start
     * @param exePath Path to executable (empty = current executable)
     * @return true if installation successful
     * 
     * Creates Windows service with the following configuration:
     * - Service name: KernelVulnerabilityControl
     * - Display name: Kernel Vulnerability Capabilities Framework
     * - Description: Provides kernel-level process protection and vulnerability assessment capabilities
     * - Start type: SERVICE_AUTO_START (automatic startup)
     * - Service type: SERVICE_WIN32_OWN_PROCESS
     * 
     * @note Requires administrative privileges
     * @note Uses current executable path if exePath is empty
     * @note Adds --service parameter for service mode detection
     */
    static bool InstallService(const std::wstring& exePath = L"") noexcept;
    
    /**
     * @brief Uninstall service from system
     * @return true if uninstallation successful
     * 
     * Stops service if running before uninstall. Removes service
     * from Service Control Manager database.
     * 
     * @note Requires administrative privileges
     * @note Stops service gracefully before removal
     * @note Returns true if service was not installed
     */
    static bool UninstallService() noexcept;
    
    /**
     * @brief Start service process
     * @return true if service started successfully
     * 
     * Starts the installed service via Service Control Manager.
     * Waits for service to enter running state.
     * 
     * @note Returns true if service is already running
     * @note Uses StartServiceW with 30 second timeout
     */
    static bool StartServiceProcess() noexcept;
    
    /**
     * @brief Stop service process
     * @return true if service stopped successfully
     * 
     * Stops the running service via Service Control Manager.
     * Waits for service to enter stopped state.
     * 
     * @note Returns true if service is already stopped
     * @note Uses ControlService with SERVICE_CONTROL_STOP
     */
    static bool StopServiceProcess() noexcept;
    
    /**
     * @brief Run as Windows Service (service entry point)
     * @return Exit code (0 = success)
     * 
     * Main service entry point called when started as service.
     * Registers service control handler and starts worker thread.
     * 
     * Service workflow:
     * 1. Register ServiceMain with SCM
     * 2. Set service status to SERVICE_RUNNING
     * 3. Start worker thread for background operations
     * 4. Wait for stop signal from SCM
     * 5. Perform graceful shutdown
     * 
     * @note Called automatically when started as service
     * @note Registers service control handler for stop/shutdown events
     */
    static int RunAsService() noexcept;

    // === Service Configuration ===
    
    static constexpr const wchar_t* SERVICE_NAME = L"KernelVulnerabilityControl";                          ///< Service internal name
    static constexpr const wchar_t* SERVICE_DISPLAY_NAME = L"Kernel Vulnerability Capabilities Framework"; ///< Service display name
    static constexpr const wchar_t* SERVICE_DESCRIPTION = L"Provides kernel-level process protection and vulnerability assessment capabilities";  ///< Service description

private:
    // === Service Entry Points ===
    
    /**
     * @brief Service main entry point (SCM callback)
     * @param argc Argument count from SCM
     * @param argv Argument vector from SCM
     * 
     * Called by Service Control Manager when service is started.
     * Initializes service state and reports status to SCM.
     * 
     * @note Static callback function for SCM
     * @note Must call SetServiceStatus to report state changes
     */
    static VOID WINAPI ServiceMain(DWORD argc, LPWSTR* argv);
    
    /**
     * @brief Service control handler (SCM callback)
     * @param ctrlCode Control code from SCM
     * 
     * Handles control requests from Service Control Manager:
     * - SERVICE_CONTROL_STOP: Graceful shutdown
     * - SERVICE_CONTROL_SHUTDOWN: System shutdown
     * - SERVICE_CONTROL_INTERROGATE: Status query
     * 
     * @note Static callback function for SCM
     * @note Sets stop event for SERVICE_CONTROL_STOP and SERVICE_CONTROL_SHUTDOWN
     */
    static VOID WINAPI ServiceCtrlHandler(DWORD ctrlCode);
    
    /**
     * @brief Service worker thread
     * @param param Thread parameter (unused)
     * @return Thread exit code
     * 
     * Runs service logic in background. Monitors stop event
     * for graceful shutdown. Performs main service operations.
     * 
     * @note Runs in separate thread from service main
     * @note Monitors s_serviceStopEvent for shutdown signals
     */
    static DWORD WINAPI ServiceWorkerThread(LPVOID param);

    // === Service State Management ===
    
    static SERVICE_STATUS_HANDLE s_serviceStatusHandle;  ///< SCM status handle for service
    static SERVICE_STATUS s_serviceStatus;               ///< Current service status structure
    static HANDLE s_serviceStopEvent;                    ///< Stop event handle for graceful shutdown
    static volatile bool s_serviceRunning;               ///< Service running flag

    /**
     * @brief Update service status in SCM
     * @param currentState New service state
     * @param exitCode Exit code (default: NO_ERROR)
     * @param waitHint Wait hint in milliseconds (default: 0)
     * @return true if status updated successfully
     * 
     * Reports current service state to Service Control Manager.
     * Used to inform SCM about service state changes.
     * 
     * @note Must be called for all service state transitions
     * @note Sets SERVICE_STATUS structure and calls SetServiceStatus
     */
    static bool SetServiceStatus(DWORD currentState, DWORD exitCode = NO_ERROR, DWORD waitHint = 0) noexcept;
    
    /**
     * @brief Cleanup service resources
     * 
     * Performs graceful cleanup when service is stopping:
     * - Closes stop event handle
     * - Reports stopped state to SCM
     * - Cleans up any allocated resources
     * 
     * @note Called on service stop and shutdown
     */
    static void ServiceCleanup() noexcept;
    
    /**
     * @brief Initialize service components
     * @return true if initialization successful
     * 
     * Initializes service-specific components and resources.
     * Called at service start before entering running state.
     * 
     * @note Called from ServiceMain after SCM registration
     */
    static bool InitializeServiceComponents() noexcept;
};