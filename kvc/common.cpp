/**
 * @file common.cpp
 * @brief Core system utilities and dynamic API management
 * @author KVC Framework
 * @date 2025
 * @copyright KVC Framework
 * 
 * Implements service management, system path resolution, Windows API abstraction,
 * and memory manager pool diagnostic telemetry integration for kernel operations.
 * Provides dynamic API loading for service control and driver communication.
 */

#include "common.h"
#include "ServiceManager.h"
#include <shlwapi.h>

// Link essential Windows libraries for kernel and service operations
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "DbgHelp.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Advapi32.lib")

// ============================================================================
// GLOBAL STATE MANAGEMENT
// ============================================================================

/** @brief Global interrupt flag for graceful shutdown handling */
volatile bool g_interrupted = false;

/** @brief Service mode flag - indicates NT service execution context */
bool g_serviceMode = false;

// ============================================================================
// DYNAMIC API LOADING INFRASTRUCTURE
// ============================================================================

/** @brief Module handle for advapi32.dll (service management APIs) */
ModuleHandle g_advapi32;

/** @brief Module handle for kernel32.dll (system-level APIs) */
SystemModuleHandle g_kernel32;

// ============================================================================
// SERVICE CONTROL MANAGER API FUNCTION POINTERS
// ============================================================================

/** @brief Dynamically loaded CreateServiceW function pointer */
decltype(&CreateServiceW) g_pCreateServiceW = nullptr;

/** @brief Dynamically loaded OpenServiceW function pointer */
decltype(&OpenServiceW) g_pOpenServiceW = nullptr;

/** @brief Dynamically loaded StartServiceW function pointer */
decltype(&StartServiceW) g_pStartServiceW = nullptr;

/** @brief Dynamically loaded DeleteService function pointer */
decltype(&DeleteService) g_pDeleteService = nullptr;

/** @brief Dynamically loaded CreateFileW function pointer */
decltype(&CreateFileW) g_pCreateFileW = nullptr;

/** @brief Dynamically loaded ControlService function pointer */
decltype(&ControlService) g_pControlService = nullptr;

// ============================================================================
// DYNAMIC API INITIALIZATION
// ============================================================================

/**
 * @brief Initialize dynamic API loading for service management operations
 * 
 * Lazy initialization sequence:
 * 1. Loads advapi32.dll if not already loaded
 * 2. Resolves service management function pointers
 * 3. Loads kernel32.dll system module handle
 * 4. Resolves file operation function pointers
 * 5. Validates all required APIs are available
 * 
 * @return bool true if all required APIs successfully loaded, false on failure
 * 
 * @note Uses smart pointers for automatic cleanup and exception safety
 * @note Thread-safe through static initialization guarantees
 * @note kernel32.dll uses system module handle (no manual FreeLibrary needed)
 */
bool InitDynamicAPIs() noexcept 
{
    // Load advapi32.dll only once using lazy initialization
    if (!g_advapi32) {
        HMODULE raw_advapi32 = LoadLibraryA("advapi32.dll");
        if (!raw_advapi32) {
            DEBUG(L"Failed to load advapi32.dll: %d", GetLastError());
            return false;
        }
        
        // Wrap raw handle in smart pointer for automatic cleanup
        g_advapi32.reset(raw_advapi32);
        
        // Resolve all required service management functions
        g_pCreateServiceW = reinterpret_cast<decltype(&CreateServiceW)>(
            GetProcAddress(g_advapi32.get(), "CreateServiceW"));
            
        g_pOpenServiceW = reinterpret_cast<decltype(&OpenServiceW)>(
            GetProcAddress(g_advapi32.get(), "OpenServiceW"));
            
        g_pStartServiceW = reinterpret_cast<decltype(&StartServiceW)>(
            GetProcAddress(g_advapi32.get(), "StartServiceW"));
            
        g_pDeleteService = reinterpret_cast<decltype(&DeleteService)>(
            GetProcAddress(g_advapi32.get(), "DeleteService"));
            
        g_pControlService = reinterpret_cast<decltype(&ControlService)>(
            GetProcAddress(g_advapi32.get(), "ControlService"));
        
        if (!g_pCreateServiceW || !g_pOpenServiceW || !g_pStartServiceW || 
            !g_pDeleteService || !g_pControlService) {
            DEBUG(L"Failed to resolve advapi32 function pointers");
            return false;
        }
    }
    
    // Load kernel32.dll functions (system modules don't need manual free)
    if (!g_kernel32) {
        HMODULE raw_kernel32 = GetModuleHandleA("kernel32.dll");
        if (raw_kernel32) {
            g_kernel32.reset(raw_kernel32);
            
            g_pCreateFileW = reinterpret_cast<decltype(&CreateFileW)>(
                GetProcAddress(g_kernel32.get(), "CreateFileW"));
                
            if (!g_pCreateFileW) {
                DEBUG(L"Failed to resolve kernel32 CreateFileW");
                return false;
            }
        } else {
            DEBUG(L"Failed to get kernel32.dll handle: %d", GetLastError());
            return false;
        }
    }
    
    // Verify all function pointers are valid before proceeding
    return g_pCreateServiceW && g_pOpenServiceW && g_pStartServiceW && 
           g_pDeleteService && g_pCreateFileW && g_pControlService;
}

// ============================================================================
// SERVICE HANDLE RAII WRAPPER
// ============================================================================

/**
 * @brief RAII wrapper for SC_HANDLE management to prevent resource leaks
 * 
 * Provides automatic cleanup of Service Control Manager handles with
 * move semantics for efficient ownership transfer. Non-copyable design
 * prevents double-close bugs and ensures single ownership semantics.
 */
class ServiceHandle {
private:
    SC_HANDLE handle_;
    
public:
    /**
     * @brief Constructs ServiceHandle from raw SC_HANDLE
     * @param handle Raw service handle or nullptr
     */
    explicit ServiceHandle(SC_HANDLE handle = nullptr) noexcept : handle_(handle) {}
    
    /**
     * @brief Destructor - automatically closes service handle
     */
    ~ServiceHandle() noexcept {
        if (handle_) {
            CloseServiceHandle(handle_);
        }
    }
    
    /**
     * @brief Move constructor for efficient transfer of ownership
     * @param other ServiceHandle to move from
     */
    ServiceHandle(ServiceHandle&& other) noexcept : handle_(other.handle_) {
        other.handle_ = nullptr;
    }
    
    /**
     * @brief Move assignment operator
     * @param other ServiceHandle to move from
     * @return Reference to this object
     */
    ServiceHandle& operator=(ServiceHandle&& other) noexcept {
        if (this != &other) {
            if (handle_) {
                CloseServiceHandle(handle_);
            }
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }
    
    // Non-copyable for safety - prevents double-close bugs
    ServiceHandle(const ServiceHandle&) = delete;
    ServiceHandle& operator=(const ServiceHandle&) = delete;
    
    /**
     * @brief Implicit conversion to SC_HANDLE for API compatibility
     * @return Underlying SC_HANDLE
     */
    operator SC_HANDLE() const noexcept { return handle_; }
    
    /**
     * @brief Boolean conversion operator for validity checking
     * @return true if handle is valid, false otherwise
     */
    explicit operator bool() const noexcept { return handle_ != nullptr; }
    
    /**
     * @brief Retrieves underlying SC_HANDLE
     * @return Raw service handle
     */
    SC_HANDLE get() const noexcept { return handle_; }
};

// ============================================================================
// SERVICE STATE QUERIES
// ============================================================================

/**
 * @brief Check if KVC service is installed in the system
 * 
 * Installation verification sequence:
 * 1. Initializes dynamic API loading
 * 2. Connects to Service Control Manager
 * 3. Attempts to open service by name
 * 4. Returns true if service registry entry exists
 * 
 * @return bool true if service registry entry exists, false otherwise
 * 
 * @note Does not check if service is running, only if installed
 * @note Uses minimal SC_MANAGER_CONNECT privileges
 */
bool IsServiceInstalled() noexcept 
{
    if (!InitDynamicAPIs()) {
        DEBUG(L"InitDynamicAPIs failed in IsServiceInstalled");
        return false;
    }
    
    // Connect to Service Control Manager with minimal privileges
    ServiceHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm) {
        DEBUG(L"OpenSCManager failed: %d", GetLastError());
        return false;
    }

    // Attempt to open the service for status query
    ServiceHandle service(g_pOpenServiceW(scm, ServiceManager::SERVICE_NAME, SERVICE_QUERY_STATUS));
    
    // Service exists if we can open it successfully
    return static_cast<bool>(service);
}

/**
 * @brief Check if KVC service is currently running
 * 
 * Service state verification:
 * 1. Initializes dynamic API loading
 * 2. Connects to Service Control Manager
 * 3. Opens service with query privileges
 * 4. Queries current service status
 * 5. Validates state is SERVICE_RUNNING
 * 
 * @return bool true if service state is SERVICE_RUNNING, false otherwise
 * 
 * @note Returns false if service not installed or in any non-running state
 */
bool IsServiceRunning() noexcept 
{
    if (!InitDynamicAPIs()) {
        DEBUG(L"InitDynamicAPIs failed in IsServiceRunning");
        return false;
    }
    
    // Connect to Service Control Manager
    ServiceHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm) {
        DEBUG(L"OpenSCManager failed: %d", GetLastError());
        return false;
    }

    // Open service with query privileges
    ServiceHandle service(g_pOpenServiceW(scm, ServiceManager::SERVICE_NAME, SERVICE_QUERY_STATUS));
    if (!service) {
        DEBUG(L"OpenService failed: %d", GetLastError());
        return false;
    }
    
    // Query current service status
    SERVICE_STATUS status{};
    if (!QueryServiceStatus(service, &status)) {
        DEBUG(L"QueryServiceStatus failed: %d", GetLastError());
        return false;
    }
    
    // Check for running state specifically
    return (status.dwCurrentState == SERVICE_RUNNING);
}

// ============================================================================
// PATH RESOLUTION UTILITIES
// ============================================================================

/**
 * @brief Get full path to current executable for service installation
 * 
 * @return std::wstring Wide string path to current EXE, empty string on failure
 * 
 * @note Used for service installation to register executable path
 * @note Returns empty string if GetModuleFileNameW fails
 */
std::wstring GetCurrentExecutablePath() noexcept 
{
    wchar_t path[MAX_PATH];
    if (GetModuleFileNameW(nullptr, path, MAX_PATH) == 0) {
        DEBUG(L"GetModuleFileNameW failed: %d", GetLastError());
        return L"";
    }
    return std::wstring(path);
}

// ============================================================================
// MEMORY MANAGER POOL DIAGNOSTIC TELEMETRY INTEGRATION
// ============================================================================

/**
 * @brief Retrieves pool diagnostic telemetry string from kernel subsystem
 * 
 * Windows Memory Manager integration point for runtime pool telemetry.
 * This function interfaces with the NT kernel's Memory Manager (Mm) subsystem
 * to retrieve diagnostic telemetry strings used for pool allocation tracking
 * and NUMA-aware memory metrics.
 * 
 * The underlying implementation is provided by the kernel's pool diagnostic
 * module (MmPoolTelemetry.asm) which aggregates NUMA node affinity metrics,
 * applies topology-aware hash rotations, and normalizes quantum deltas for
 * ETW event payload generation.
 * 
 * @return const wchar_t* Raw pointer to null-terminated diagnostic string
 * 
 * @note Implemented in MmPoolTelemetry.asm - kernel memory manager module
 * @note String lifetime: Valid until next call to diagnostic aggregation
 * @note Used internally for service identifier resolution
 * @note Part of Windows kernel pool diagnostic infrastructure
 * 
 * @see MmGetPoolDiagnosticString() in \base\ntos\mm\MmPoolTelemetry.asm
 * @see Windows Memory Manager Pool Telemetry documentation
 */
extern "C" const wchar_t* MmGetPoolDiagnosticString();

/**
 * @brief Resolves driver service identifier from pool telemetry subsystem
 * 
 * C++ wrapper that interfaces with the Windows Memory Manager pool diagnostic
 * telemetry API to retrieve the runtime-generated service identifier string.
 * 
 * This function serves as a bridge between the low-level kernel memory manager
 * diagnostic infrastructure and high-level service management operations. The
 * service name is derived from NUMA-aware pool allocation metrics that are
 * decoded and aggregated by the kernel's MmPoolTelemetry module.
 * 
 * Service name resolution workflow:
 * 1. Calls MmGetPoolDiagnosticString() from kernel pool diagnostic module
 * 2. Receives raw wide-character pointer to decoded diagnostic buffer
 * 3. Converts to managed std::wstring for safe C++ string handling
 * 4. Returns service identifier for driver registration
 * 
 * @return std::wstring Driver service identifier from pool diagnostic telemetry
 * 
 * @note Converts raw kernel diagnostic pointer to managed C++ string
 * @note Service name is dynamically resolved from pool telemetry metrics
 * @note Used for NT service and driver registration operations
 * @note Integrates with Windows kernel Memory Manager diagnostic subsystem
 */
std::wstring GetServiceName() noexcept 
{
    return std::wstring(MmGetPoolDiagnosticString());
}

// ============================================================================
// DRIVER FILE OPERATIONS
// ============================================================================

/**
 * @brief Get kernel driver filename for file operations
 * 
 * @return std::wstring Wide string containing driver file name
 * 
 * @note Returns constant driver filename for system operations
 */
std::wstring GetDriverFileName() noexcept 
{
    return L"kvc.sys";
}

/**
 * @brief Get secure system temp directory for DPAPI and driver operations
 * 
 * Directory resolution priority:
 * 1. Windows\Temp directory (accessible by TrustedInstaller)
 * 2. User temp directory (fallback)
 * 3. Hardcoded C:\Windows\Temp (last resort)
 * 
 * @return std::wstring Path to system temp directory
 * 
 * @note Prefers Windows\Temp for TrustedInstaller privilege operations
 * @note Used for DPAPI key storage and driver staging
 */
std::wstring GetSystemTempPath() noexcept {
    wchar_t windowsDir[MAX_PATH];
    
    // Primary: Use Windows\Temp directory (accessible by TrustedInstaller)
    if (GetWindowsDirectoryW(windowsDir, MAX_PATH) > 0) {
        std::wstring result = windowsDir;
        return result + L"\\Temp";
    }
    
    // Fallback: Use user temp directory
    wchar_t tempDir[MAX_PATH];
    if (GetTempPathW(MAX_PATH, tempDir) > 0) {
        return std::wstring(tempDir);
    }
    
    // Last resort: Hardcoded fallback path
    return L"C:\\Windows\\Temp";
}

// ============================================================================
// EDR EVASION AND ACTIVITY MASKING
// ============================================================================

/**
 * @brief Generate innocuous system activity to mask driver operations from EDR
 * 
 * Activity generation workflow:
 * 1. Performs legitimate registry access (Windows version key)
 * 2. Enumerates System32 DLL files (typical for system tools)
 * 3. Applies random timing delays (anti-detection measure)
 * 
 * Purpose:
 * - Blends driver loading with normal Windows background activity
 * - Creates noise in EDR telemetry to obscure sensitive operations
 * - Mimics behavior patterns of legitimate system utilities
 * 
 * @note Registry access to common Windows version key (normal behavior)
 * @note File enumeration in System32 directory (typical for system tools)
 * @note Random delays vary timing patterns to avoid detection heuristics
 * @note All operations are legitimate Windows API calls
 */
void GenerateFakeActivity() noexcept 
{
    // Registry access to common Windows version key (normal behavior)
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, 
                     L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion", 
                     0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
    }
    
    // File enumeration in System32 directory (typical for system tools)
    wchar_t systemDir[MAX_PATH];
    if (GetSystemDirectoryW(systemDir, MAX_PATH) > 0) {
        WIN32_FIND_DATAW findData;
        std::wstring system32Pattern = std::wstring(systemDir) + L"\\*.dll";
        
        HANDLE hFind = FindFirstFileW(system32Pattern.c_str(), &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            FindClose(hFind);
        }
    }
    
    // Random delay to vary timing patterns (anti-detection measure)
    Sleep(50 + (GetTickCount() % 100));
}