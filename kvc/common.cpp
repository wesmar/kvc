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

// common.cpp - Core system utilities and dynamic API management
// Implements service management, system path resolution, and Windows API abstraction

#include "common.h"
#include "ServiceManager.h"
#include <shlwapi.h>

// Link essential Windows libraries for kernel and service operations
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "DbgHelp.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Advapi32.lib")

// Global interrupt flag for graceful shutdown handling
volatile bool g_interrupted = false;

// Service mode flag - indicates NT service execution context
bool g_serviceMode = false;

// Dynamic API loading globals for service and driver management
// Using smart pointers for automatic cleanup and exception safety
ModuleHandle g_advapi32;
SystemModuleHandle g_kernel32;

// Function pointers for Windows Service Control Manager APIs
decltype(&CreateServiceW) g_pCreateServiceW = nullptr;
decltype(&OpenServiceW) g_pOpenServiceW = nullptr;
decltype(&StartServiceW) g_pStartServiceW = nullptr;
decltype(&DeleteService) g_pDeleteService = nullptr;
decltype(&CreateFileW) g_pCreateFileW = nullptr;
decltype(&ControlService) g_pControlService = nullptr;

// Initialize dynamic API loading for service management operations
// Returns: true if all required APIs successfully loaded, false on failure
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

// RAII wrapper for SC_HANDLE management to prevent resource leaks
class ServiceHandle {
private:
    SC_HANDLE handle_;
    
public:
    explicit ServiceHandle(SC_HANDLE handle = nullptr) noexcept : handle_(handle) {}
    
    ~ServiceHandle() noexcept {
        if (handle_) {
            CloseServiceHandle(handle_);
        }
    }
    
    // Move semantics for efficient transfer of ownership
    ServiceHandle(ServiceHandle&& other) noexcept : handle_(other.handle_) {
        other.handle_ = nullptr;
    }
    
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
    
    // Access operators for SC_HANDLE compatibility
    operator SC_HANDLE() const noexcept { return handle_; }
    explicit operator bool() const noexcept { return handle_ != nullptr; }
    SC_HANDLE get() const noexcept { return handle_; }
};

// Check if KVC service is installed in the system
// Returns: true if service registry entry exists, false otherwise
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

// Check if KVC service is currently running
// Returns: true if service state is SERVICE_RUNNING, false otherwise  
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

// Get full path to current executable for service installation
// Returns: Wide string path to current EXE, empty string on failure
std::wstring GetCurrentExecutablePath() noexcept 
{
    wchar_t path[MAX_PATH];
    if (GetModuleFileNameW(nullptr, path, MAX_PATH) == 0) {
        DEBUG(L"GetModuleFileNameW failed: %d", GetLastError());
        return L"";
    }
    return std::wstring(path);
}

// External assembly function that returns raw pointer to service name
extern "C" const wchar_t* GetServiceNameRaw();

// C++ wrapper converting ASM raw pointer to std::wstring
// Returns: Wide string containing driver service identifier
std::wstring GetServiceName() noexcept 
{
    return std::wstring(GetServiceNameRaw());
}
// Get kernel driver filename for file operations
// Returns: Wide string containing driver file name
std::wstring GetDriverFileName() noexcept 
{
    return L"kvc.sys";
}

// Get secure system temp directory for DPAPI and driver operations
// Uses Windows temp directory with TrustedInstaller privileges
// Returns: Wide string path to system temp directory
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

// Generate innocuous system activity to mask driver operations from EDR
// Creates legitimate registry access and file enumeration patterns
// Purpose: Blend driver loading with normal Windows background activity
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