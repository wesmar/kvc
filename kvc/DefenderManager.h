#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <memory>

class DefenderManager {
public:
    enum class SecurityState {
        ENABLED,
        DISABLED,
        UNKNOWN
    };

    // Primary interface - matches KVC command pattern
    static bool DisableSecurityEngine() noexcept;
    static bool EnableSecurityEngine() noexcept;
    static SecurityState GetSecurityEngineStatus() noexcept;

private:
    struct RegistryContext {
        std::wstring tempPath;
        std::wstring hiveFile;
        
        RegistryContext() = default;
        ~RegistryContext() { Cleanup(); }
        
        // Non-copyable, movable
        RegistryContext(const RegistryContext&) = delete;
        RegistryContext& operator=(const RegistryContext&) = delete;
        RegistryContext(RegistryContext&&) = default;
        RegistryContext& operator=(RegistryContext&&) = default;
        
        void Cleanup() noexcept;
    };

    // Core engine manipulation
    static bool ModifySecurityEngine(bool enable) noexcept;
    
    // Registry operations - critical path functions
    static bool EnableRequiredPrivileges() noexcept;
    static bool CreateRegistrySnapshot(RegistryContext& ctx) noexcept;
    static bool ModifyDefenderDependencies(const RegistryContext& ctx, bool enable) noexcept;
    static bool RestoreRegistrySnapshot(const RegistryContext& ctx) noexcept;
    
    // Helper utilities
    static std::vector<std::wstring> ReadMultiString(HKEY key, const std::wstring& valueName) noexcept;
    static bool WriteMultiString(HKEY key, const std::wstring& valueName, const std::vector<std::wstring>& values) noexcept;
    static std::wstring GetSystemTempPath() noexcept;
    static bool ValidateWriteAccess(const std::wstring& path) noexcept;
    
    // Privilege management
    static bool EnablePrivilege(const wchar_t* privilege) noexcept;
    
    // Constants
    static constexpr const wchar_t* WINDEFEND_KEY = L"SYSTEM\\CurrentControlSet\\Services\\WinDefend";
    static constexpr const wchar_t* SERVICES_KEY = L"SYSTEM\\CurrentControlSet\\Services";
    static constexpr const wchar_t* DEPEND_VALUE = L"DependOnService";
    static constexpr const wchar_t* RPC_SERVICE_ACTIVE = L"RpcSs";
    static constexpr const wchar_t* RPC_SERVICE_INACTIVE = L"RpcSt";
};