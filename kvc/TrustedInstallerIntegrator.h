#pragma once

#include <windows.h>
#include <string>
#include <vector>

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
    bool WriteFileAsTrustedInstaller(const std::wstring& filePath, 
                                      const std::vector<BYTE>& data) noexcept;
    bool DeleteFileAsTrustedInstaller(const std::wstring& filePath) noexcept;
	
	bool RenameFileAsTrustedInstaller(const std::wstring& srcPath, 
                                   const std::wstring& dstPath) noexcept;
	
	// Creates a directory with TrustedInstaller privileges
	bool CreateDirectoryAsTrustedInstaller(const std::wstring& directoryPath) noexcept;
    
    // Registry operations (NEW - direct registry access with TrustedInstaller)
    bool CreateRegistryKeyAsTrustedInstaller(HKEY hRootKey, 
                                              const std::wstring& subKey) noexcept;
    bool WriteRegistryValueAsTrustedInstaller(HKEY hRootKey,
                                               const std::wstring& subKey,
                                               const std::wstring& valueName,
                                               const std::wstring& value) noexcept;
    bool WriteRegistryDwordAsTrustedInstaller(HKEY hRootKey,
                                               const std::wstring& subKey,
                                               const std::wstring& valueName,
                                               DWORD value) noexcept;
    bool WriteRegistryBinaryAsTrustedInstaller(HKEY hRootKey,
                                                const std::wstring& subKey,
                                                const std::wstring& valueName,
                                                const std::vector<BYTE>& data) noexcept;
    bool ReadRegistryValueAsTrustedInstaller(HKEY hRootKey,
                                              const std::wstring& subKey,
                                              const std::wstring& valueName,
                                              std::wstring& outValue) noexcept;
    bool DeleteRegistryKeyAsTrustedInstaller(HKEY hRootKey,
                                              const std::wstring& subKey) noexcept;
    
    // Defender exclusions
    bool AddDefenderExclusion(ExclusionType type, const std::wstring& value);
    bool RemoveDefenderExclusion(ExclusionType type, const std::wstring& value);
    bool AddToDefenderExclusions(const std::wstring& customPath = L"");
    bool RemoveFromDefenderExclusions(const std::wstring& customPath = L"");
    
    bool AddPathExclusion(const std::wstring& path);
    bool RemovePathExclusion(const std::wstring& path);
    bool AddProcessExclusion(const std::wstring& processName);
    bool RemoveProcessExclusion(const std::wstring& processName);
    bool AddExtensionExclusion(const std::wstring& extension);
    bool RemoveExtensionExclusion(const std::wstring& extension);
    bool AddIpAddressExclusion(const std::wstring& ipAddress);
    bool RemoveIpAddressExclusion(const std::wstring& ipAddress);
    
    bool AddProcessToDefenderExclusions(const std::wstring& processName);
    bool RemoveProcessFromDefenderExclusions(const std::wstring& processName);
    
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

    BOOL EnablePrivilegeInternal(LPCWSTR privilegeName);
    BOOL ImpersonateSystem();
    BOOL CreateProcessAsTrustedInstaller(DWORD pid, LPCWSTR commandLine);
    BOOL CreateProcessAsTrustedInstallerSilent(DWORD pid, LPCWSTR commandLine);
    
    DWORD GetProcessIdByName(LPCWSTR processName);
    bool IsLnkFile(LPCWSTR path);
    std::wstring ResolveLnk(LPCWSTR lnkPath);
    
    bool ValidateExtension(const std::wstring& extension) noexcept;
    bool ValidateIpAddress(const std::wstring& ipAddress) noexcept;
    std::wstring NormalizeExtension(const std::wstring& extension) noexcept;
    std::wstring ExtractProcessName(const std::wstring& fullPath) noexcept;
};