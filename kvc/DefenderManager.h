// DefenderManager.h
// Windows Defender security engine control via registry operations (privileged, restart required)

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <memory>

// Manage Windows Defender by swapping service dependencies in the registry (requires privileges, restart)
class DefenderManager {
public:
    // Security engine state based on WinDefend service dependency
    enum class SecurityState {
        ENABLED,    // Defender engine active (RpcSs)
        DISABLED,   // Defender engine inactive (RpcSt)
        UNKNOWN     // State could not be determined
    };

    // Disable Windows Defender by changing service dependency to RpcSt (requires admin + restart)
    static bool DisableSecurityEngine() noexcept;
    
    // Enable Windows Defender by restoring service dependency to RpcSs (requires admin + restart)
    static bool EnableSecurityEngine() noexcept;
    
    // Query current Defender state by reading service dependency (read-only, safe)
    static SecurityState GetSecurityEngineStatus() noexcept;

private:
    // Temporary registry snapshot context for atomic service-hive modifications
    struct RegistryContext {
        std::wstring tempPath;      // Temp directory for hive files
        std::wstring hiveFile;      // Saved Services hive path
        
        RegistryContext() = default;
        ~RegistryContext() { Cleanup(); } // Auto-cleanup of temp files
        
        RegistryContext(const RegistryContext&) = delete;
        RegistryContext& operator=(const RegistryContext&) = delete;
        RegistryContext(RegistryContext&&) = default;
        RegistryContext& operator=(RegistryContext&&) = default;
        
        // Remove temporary hive and transaction files (idempotent, handles locks)
        void Cleanup() noexcept;
    };

    // Core modify workflow (enable==true to enable engine, false to disable) using snapshot/restore
    static bool ModifySecurityEngine(bool enable) noexcept;
    
    // Enable required privileges: SE_BACKUP_NAME, SE_RESTORE_NAME, SE_LOAD_DRIVER_NAME
    static bool EnableRequiredPrivileges() noexcept;
    
    // Create temporary Services hive snapshot and load it under HKLM\Temp
    static bool CreateRegistrySnapshot(RegistryContext& ctx) noexcept;
    
    // Switch WinDefend DependOnService between RpcSt and RpcSs inside temp hive
    static bool ModifyDefenderDependencies(const RegistryContext& ctx, bool enable) noexcept;
    
    // Unload temp hive and restore modified snapshot to live Services key (critical operation)
    static bool RestoreRegistrySnapshot(const RegistryContext& ctx) noexcept;
    
    // Read REG_MULTI_SZ into vector; returns empty vector on error or missing value
    static std::vector<std::wstring> ReadMultiString(HKEY key, const std::wstring& valueName) noexcept;
    
    // Write vector as REG_MULTI_SZ (handles empty/single entries and double-null terminator)
    static bool WriteMultiString(HKEY key, const std::wstring& valueName, const std::vector<std::wstring>& values) noexcept;
    
    // Registry constants
    static constexpr const wchar_t* WINDEFEND_KEY = L"SYSTEM\\CurrentControlSet\\Services\\WinDefend";
    static constexpr const wchar_t* SERVICES_KEY = L"SYSTEM\\CurrentControlSet\\Services";
    static constexpr const wchar_t* DEPEND_VALUE = L"DependOnService";
    static constexpr const wchar_t* RPC_SERVICE_ACTIVE = L"RpcSs";
    static constexpr const wchar_t* RPC_SERVICE_INACTIVE = L"RpcSt";
};
