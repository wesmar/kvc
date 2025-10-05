/**
 * @file TrustedInstallerIntegrator.h
 * @brief TrustedInstaller privilege escalation and system-level operations
 * @author Marek Wesolowski
 * @date 2025
 * @copyright KVC Framework
 * 
 * Provides maximum privilege access through TrustedInstaller token impersonation,
 * enabling registry manipulation, Defender exclusions, and protected system operations.
 * Bypasses UAC and achieves SYSTEM + TrustedInstaller privileges for maximum access.
 */

#pragma once

#include <windows.h>
#include <string>
#include <vector>

/**
 * @class TrustedInstallerIntegrator
 * @brief Manages TrustedInstaller privilege escalation for maximum system access
 * 
 * This class handles:
 * - Token acquisition and caching from TrustedInstaller service
 * - Elevated command execution with SYSTEM + TrustedInstaller privileges
 * - Windows Defender exclusion management (paths, processes, extensions, IPs)
 * - Sticky keys backdoor installation/removal
 * - Context menu registry integration
 * - Comprehensive privilege enablement for maximum system access
 * 
 * @note Requires administrative privileges for initial token acquisition
 * @warning TrustedInstaller access provides complete system control
 */
class TrustedInstallerIntegrator
{
public:
    /**
     * @brief Construct TrustedInstaller integrator
     * 
     * Initializes internal state but does not acquire tokens immediately.
     * Token acquisition happens on first privileged operation.
     */
    TrustedInstallerIntegrator();
    
    /**
     * @brief Destructor with token cleanup
     * 
     * Releases any acquired tokens and reverts impersonation if active.
     */
    ~TrustedInstallerIntegrator();

    /**
     * @brief Types of Windows Defender exclusions
     * 
     * Categorizes different exclusion types for precise Defender management.
     */
    enum class ExclusionType {
        Paths,       ///< File/folder path exclusions (e.g., "C:\Windows\Temp")
        Processes,   ///< Process name exclusions (e.g., "notepad.exe")
        Extensions,  ///< File extension exclusions (e.g., ".exe", ".dll")
        IpAddresses  ///< IP address exclusions (e.g., "192.168.1.1", "10.0.0.0/24")
    };

    /**
     * @brief Execute command with TrustedInstaller privileges (visible window)
     * @param commandLine Command to execute
     * @return true if execution successful
     * @note Shows command window during execution
     * @note Uses CreateProcessAsTrustedInstaller internally
     */
    bool RunAsTrustedInstaller(const std::wstring& commandLine);
    
    /**
     * @brief Execute command with TrustedInstaller privileges (hidden window)
     * @param commandLine Command to execute
     * @return true if execution successful and exit code 0
     * @note Waits up to 3 seconds for process completion
     * @note Uses CreateProcessAsTrustedInstallerSilent internally
     */
    bool RunAsTrustedInstallerSilent(const std::wstring& commandLine);
    
    /**
     * @brief Add file/process to Windows Defender exclusions (legacy method)
     * @param customPath Path to exclude (empty = current executable)
     * @return true if exclusion added successfully
     * @note For executables, adds both path and process exclusions
     * @note Uses PowerShell Add-MpPreference cmdlet
     */
    bool AddToDefenderExclusions(const std::wstring& customPath = L"");
    
    /**
     * @brief Remove file/process from Windows Defender exclusions (legacy method)
     * @param customPath Path to remove (empty = current executable)
     * @return true if exclusion removed successfully
     * @note Uses PowerShell Remove-MpPreference cmdlet
     */
    bool RemoveFromDefenderExclusions(const std::wstring& customPath = L"");
    
    /**
     * @brief Add Windows Explorer context menu entries
     * @return true if registry keys created successfully
     * @note Adds "Run as TrustedInstaller" to right-click menu
     * @note Requires TrustedInstaller privileges for HKLM registry access
     */
    bool AddContextMenuEntries();
    
    /**
     * @brief Add exclusion to Windows Defender by type
     * @param type Exclusion type (Paths/Processes/Extensions/IpAddresses)
     * @param value Value to exclude
     * @return true if exclusion added successfully
     * @note Uses PowerShell Add-MpPreference cmdlet
     * @note Validates input based on exclusion type
     */
    bool AddDefenderExclusion(ExclusionType type, const std::wstring& value);
    
    /**
     * @brief Remove exclusion from Windows Defender by type
     * @param type Exclusion type (Paths/Processes/Extensions/IpAddresses)
     * @param value Value to remove
     * @return true if exclusion removed successfully
     * @note Uses PowerShell Remove-MpPreference cmdlet
     */
    bool RemoveDefenderExclusion(ExclusionType type, const std::wstring& value);
    
    /**
     * @brief Add file extension exclusion
     * @param extension Extension to exclude (e.g., ".exe", ".dll")
     * @return true if exclusion added successfully
     * @note Automatically adds leading dot if missing
     * @note Validates extension format
     */
    bool AddExtensionExclusion(const std::wstring& extension);
    
    /**
     * @brief Remove file extension exclusion
     * @param extension Extension to remove
     * @return true if exclusion removed successfully
     */
    bool RemoveExtensionExclusion(const std::wstring& extension);
    
    /**
     * @brief Add IP address exclusion
     * @param ipAddress IP address or CIDR notation (e.g., "192.168.1.1", "10.0.0.0/24")
     * @return true if exclusion added successfully
     * @note Validates IP address format
     */
    bool AddIpAddressExclusion(const std::wstring& ipAddress);
    
    /**
     * @brief Remove IP address exclusion
     * @param ipAddress IP address or CIDR notation to remove
     * @return true if exclusion removed successfully
     */
    bool RemoveIpAddressExclusion(const std::wstring& ipAddress);
    
    /**
     * @brief Install sticky keys backdoor (sethc.exe -> cmd.exe)
     * @return true if backdoor installed successfully
     * @note Requires system restart, adds cmd.exe to Defender exclusions
     * @warning Security risk - only for authorized testing
     * @note Uses Image File Execution Options registry key
     */
    bool InstallStickyKeysBackdoor() noexcept;
    
    /**
     * @brief Remove sticky keys backdoor and restore original behavior
     * @return true if backdoor removed successfully
     * @note Removes IFEO registry key and Defender exclusions
     */
    bool RemoveStickyKeysBackdoor() noexcept;
    
    /**
     * @brief Add process to Windows Defender exclusions
     * @param processName Process name (e.g., "notepad.exe")
     * @return true if exclusion added successfully
     * @note Validates process name format
     */
    bool AddProcessToDefenderExclusions(const std::wstring& processName);
    
    /**
     * @brief Remove process from Windows Defender exclusions
     * @param processName Process name to remove
     * @return true if exclusion removed successfully
     */
    bool RemoveProcessFromDefenderExclusions(const std::wstring& processName);
    
    /**
     * @brief Get array of all privilege names
     * @return Pointer to array of privilege name strings
     * @note Used for enabling comprehensive privileges on TrustedInstaller token
     */
    static const LPCWSTR* GetAllPrivileges() { return ALL_PRIVILEGES; }
    
    /**
     * @brief Get count of privileges in ALL_PRIVILEGES array
     * @return Number of privilege names
     */
    static int GetPrivilegeCount() { return PRIVILEGE_COUNT; }
    
    /**
     * @brief Impersonate SYSTEM account
     * @return true if impersonation successful
     * @note Required step before acquiring TrustedInstaller token
     * @note Uses SeDebugPrivilege to access SYSTEM processes
     */
    bool PublicImpersonateSystem() { return ImpersonateSystem(); }
    
    /**
     * @brief Get cached TrustedInstaller token or acquire new one
     * @return Handle to TrustedInstaller token, or nullptr on failure
     * @note Token cached for 30 seconds, automatically enables all privileges
     * @note Acquires token from TrustedInstaller service process
     */
    HANDLE GetCachedTrustedInstallerToken();
    
    /**
     * @brief Start TrustedInstaller service and get its PID
     * @return Process ID of TrustedInstaller service, or 0 on failure
     * @note Waits up to 30 seconds for service to start
     * @note Requires SC_MANAGER_ALL_ACCESS privileges
     */
    DWORD StartTrustedInstallerService();

private:
    /**
     * @brief Complete Windows privilege set for maximum access
     * 
     * Array containing all Windows privilege names for comprehensive enablement
     * on TrustedInstaller token. Includes backup, restore, debug, and security privileges.
     */
    static const LPCWSTR ALL_PRIVILEGES[];
    
    /**
     * @brief Number of privileges in ALL_PRIVILEGES array
     */
    static const int PRIVILEGE_COUNT;

    /**
     * @brief Impersonate SYSTEM account using SeDebugPrivilege
     * @return true if impersonation successful
     * @note Internal implementation used by PublicImpersonateSystem()
     */
    BOOL ImpersonateSystem();
    
    /**
     * @brief Create process with TrustedInstaller token (visible window)
     * @param pid TrustedInstaller process ID
     * @param commandLine Command to execute
     * @return true if process creation successful
     */
    BOOL CreateProcessAsTrustedInstaller(DWORD pid, LPCWSTR commandLine);
    
    /**
     * @brief Create process with TrustedInstaller token (hidden window)
     * @param pid TrustedInstaller process ID
     * @param commandLine Command to execute
     * @return true if process creation successful
     */
    BOOL CreateProcessAsTrustedInstallerSilent(DWORD pid, LPCWSTR commandLine);
    
    /**
     * @brief Enable specific privilege in current token
     * @param privilegeName Privilege name to enable
     * @return true if privilege enabled successfully
     */
    BOOL EnablePrivilegeInternal(LPCWSTR privilegeName);
    
    /**
     * @brief Add path exclusion to Windows Defender
     * @param path Path to exclude
     * @return true if exclusion added successfully
     */
    bool AddPathExclusion(const std::wstring& path);
    
    /**
     * @brief Get process ID by process name
     * @param processName Process name to find
     * @return Process ID if found, 0 if not found
     */
    DWORD GetProcessIdByName(LPCWSTR processName);
    
    /**
     * @brief Check if file is a Windows shortcut (.lnk)
     * @param filePath File path to check
     * @return true if file is a .lnk shortcut
     */
    BOOL IsLnkFile(LPCWSTR filePath);
    
    /**
     * @brief Resolve .lnk shortcut to target path
     * @param lnkPath Path to .lnk file
     * @return Resolved target path, empty on failure
     */
    std::wstring ResolveLnk(LPCWSTR lnkPath);
    
    /**
     * @brief Validate file extension format
     * @param extension Extension to validate
     * @return true if extension format is valid
     */
    bool ValidateExtension(const std::wstring& extension) noexcept;
    
    /**
     * @brief Validate IP address format
     * @param ipAddress IP address to validate
     * @return true if IP address format is valid
     */
    bool ValidateIpAddress(const std::wstring& ipAddress) noexcept;
    
    /**
     * @brief Normalize extension format (ensure leading dot)
     * @param extension Extension to normalize
     * @return Normalized extension with leading dot
     */
    std::wstring NormalizeExtension(const std::wstring& extension) noexcept;
    
    /**
     * @brief Get string representation of exclusion type
     * @param type Exclusion type
     * @return String representation for PowerShell commands
     */
    std::wstring GetExclusionTypeString(ExclusionType type) noexcept;
};