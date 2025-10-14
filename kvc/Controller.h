/**
 * @file Controller.h  
 * @brief Main orchestration class for KVC Framework operations
 * @author Marek Wesolowski
 * @date 2025
 * @copyright KVC Framework
 * 
 * Central controller managing kernel driver communication, process protection,
 * DPAPI password extraction, and system-level operations.
 * Integrates all framework components and provides unified interface.
 */

#pragma once

#include "SessionManager.h"
#include "kvcDrv.h"
#include "DSEBypass.h"
#include "OffsetFinder.h"
#include "TrustedInstallerIntegrator.h"
#include "Utils.h"
#include <vector>
#include <memory>
#include <optional>
#include <chrono>
#include <unordered_map>

// Forward declarations
class ReportExporter;

/**
 * @struct ProcessEntry
 * @brief Kernel process structure representation for EPROCESS manipulation
 * 
 * Contains complete process information obtained from kernel space
 * including protection levels, signature information, and kernel addresses.
 */
struct ProcessEntry
{
    ULONG_PTR KernelAddress;        ///< EPROCESS structure address in kernel space
    DWORD Pid;                      ///< Process identifier
    UCHAR ProtectionLevel;          ///< PP/PPL/None protection level (combined byte)
    UCHAR SignerType;               ///< Digital signature authority
    UCHAR SignatureLevel;           ///< Executable signature verification level
    UCHAR SectionSignatureLevel;    ///< DLL signature verification level
    std::wstring ProcessName;       ///< Process executable name
};

/**
 * @struct ProcessMatch
 * @brief Process search result with kernel information
 * 
 * Used for process resolution operations when driver may not be available.
 */
struct ProcessMatch
{
    DWORD Pid = 0;                  ///< Process ID
    std::wstring ProcessName;       ///< Process name
    ULONG_PTR KernelAddress = 0;    ///< Kernel EPROCESS address
};

/**
 * @struct SQLiteAPI
 * @brief WinSQLite dynamic loading structure for browser database operations
 * 
 * Function pointers for SQLite3 operations used in browser password extraction.
 * Loaded dynamically to avoid static linking dependencies.
 */
struct SQLiteAPI
{
    HMODULE hModule = nullptr;                                  ///< SQLite3 module handle
    int (*open_v2)(const char*, void**, int, const char*) = nullptr;      ///< sqlite3_open_v2
    int (*prepare_v2)(void*, const char*, int, void**, const char**) = nullptr;  ///< sqlite3_prepare_v2
    int (*step)(void*) = nullptr;                               ///< sqlite3_step
    const unsigned char* (*column_text)(void*, int) = nullptr;  ///< sqlite3_column_text
    const void* (*column_blob)(void*, int) = nullptr;           ///< sqlite3_column_blob
    int (*column_bytes)(void*, int) = nullptr;                  ///< sqlite3_column_bytes
    int (*finalize)(void*) = nullptr;                           ///< sqlite3_finalize
    int (*close_v2)(void*) = nullptr;                           ///< sqlite3_close_v2
};

/**
 * @struct PasswordResult
 * @brief Password extraction result structure for DPAPI operations
 * 
 * Stores decrypted credentials from browsers and WiFi with metadata.
 */
struct PasswordResult
{
    std::wstring type;              ///< Chrome, Edge, WiFi credential type
    std::wstring profile;           ///< Browser/WiFi profile name
    std::wstring url;               ///< URL for browser logins
    std::wstring username;          ///< Login username
    std::wstring password;          ///< Decrypted password
    std::wstring file;              ///< Source file path
    std::wstring data;              ///< Additional data
    std::wstring status;            ///< DECRYPTED, ENCRYPTED, FAILED
    uintmax_t size = 0;             ///< Data size in bytes
};

/**
 * @struct RegistryMasterKey
 * @brief Registry master key for DPAPI decryption operations
 * 
 * Represents encrypted master keys extracted from registry for DPAPI operations.
 */
struct RegistryMasterKey
{
    std::wstring keyName;           ///< Registry key path (DPAPI_SYSTEM, NL$KM, etc.)
    std::vector<BYTE> encryptedData; ///< Raw encrypted key data from registry
    std::vector<BYTE> decryptedData; ///< Decrypted master key data
    bool isDecrypted = false;       ///< Decryption success flag
};

/**
 * @class Controller
 * @brief Main orchestration class for all KVC Framework operations
 * 
 * Manages:
 * - Kernel driver lifecycle and communication
 * - Process protection manipulation (PP/PPL)
 * - Memory dumping operations with protection handling
 * - DPAPI password extraction (Chrome, Edge, WiFi)
 * - Windows Defender exclusion management
 * - TrustedInstaller privilege escalation
 * - Registry operations and hive management
 * - Session state tracking and restoration
 * 
 * @note Central hub integrating all framework components
 * @warning Requires appropriate privileges for different operations
 */
class Controller
{
public:
    /**
     * @brief Construct controller and initialize core components
     * 
     * Initializes TrustedInstaller integration, offset finder, and SQLite.
     * Does not automatically load driver - call driver methods as needed.
     */
    Controller();
    
    /**
     * @brief Destructor with comprehensive cleanup
     * 
     * Ends driver session, unloads SQLite, and cleans up resources.
     */
    ~Controller();

    // Disable copy semantics
    Controller(const Controller&) = delete;                    ///< Copy constructor deleted
    Controller& operator=(const Controller&) = delete;        ///< Copy assignment deleted
    
    // Enable move semantics
    Controller(Controller&&) noexcept = default;              ///< Move constructor
    Controller& operator=(Controller&&) noexcept = default;   ///< Move assignment

	// DSE Bypass methods

	/**
	 * @brief Disables Driver Signature Enforcement (DSE) on the system
	 * 
	 * This method bypasses kernel-mode code signing protection by:
	 * - Locating the CiEnabled/CI!g_CiOptions global variable in kernel memory
	 * - Modifying its value to disable signature enforcement checks
	 * - Bypassing PatchGuard protection mechanisms
	 * 
	 * @return true if DSE was successfully disabled, false otherwise
	 * @note Requires kernel driver to be loaded and elevated privileges
	 * @warning This exposes the system to unsigned driver loading - use with caution
	 * @note Automatically handles CiEnabled (Win7) and g_CiOptions (Win8+) variants
	 */
	bool DisableDSE() noexcept;

	/**
	 * @brief Restores Driver Signature Enforcement to its original state
	 * 
	 * Reverts the changes made by DisableDSE() by:
	 * - Restoring the original value of CiOptions/CiEnabled
	 * - Re-enforcing kernel-mode code signing requirements
	 * - Ensuring system integrity is maintained
	 * 
	 * @return true if DSE was successfully restored, false otherwise
	 * @note Should be called before driver unload to maintain system security
	 * @warning Failure to restore DSE may leave the system in an insecure state
	 */
	bool RestoreDSE() noexcept;

	/**
	 * @brief Retrieves the kernel address of CI!g_CiOptions or CiEnabled variable
	 * 
	 * Locates the critical kernel structure that controls DSE by:
	 * - Scanning kernel memory for known patterns
	 * - Using exported kernel symbols when available
	 * - Employing heuristic search methods as fallback
	 * 
	 * @return ULONG_PTR Virtual address of CiOptions in kernel space, 0 if not found
	 * @note The address is used for direct memory modification to bypass DSE
	 * @note Returns different addresses based on Windows version (Win7 vs Win8+)
	 */
	ULONG_PTR GetCiOptionsAddress() const noexcept;

	/**
	 * @brief Retrieves current DSE status including g_CiOptions address and value
	 * 
	 * Queries the kernel for current Driver Signature Enforcement state by:
	 * - Locating ci.dll module in kernel space
	 * - Finding g_CiOptions variable address
	 * - Reading current enforcement flags
	 * 
	 * @param outAddress Reference to store g_CiOptions kernel address
	 * @param outValue Reference to store current g_CiOptions value
	 * @return true if status retrieved successfully, false otherwise
	 * @note Requires driver session with kernel memory access
	 * @note outValue bits 1-2 indicate DSE state (set = enabled)
	 */
	bool GetDSEStatus(ULONG_PTR& outAddress, DWORD& outValue) noexcept;

    // === Memory Dumping Operations ===
    
    /**
     * @brief Dump process memory to file with driver support
     * @param pid Process ID to dump
     * @param outputPath Output file path
     * @return true if dump successful
     * @note Handles protected processes and undumpable flags
     * @note Uses kernel driver for memory access
     */
    bool DumpProcess(DWORD pid, const std::wstring& outputPath) noexcept;
    
    /**
     * @brief Dump process by name with pattern matching
     * @param processName Process name or pattern
     * @param outputPath Output file path
     * @return true if dump successful
     * @note Supports partial name matching and wildcards
     */
    bool DumpProcessByName(const std::wstring& processName, const std::wstring& outputPath) noexcept;
    
    // === Binary Management ===
    
    /**
     * @brief Load and split kvc.dat into components
     * @return true if components extracted successfully
     * @note Deploys kvc_pass.exe and kvc_crypt.dll to System32
     * @note Uses XOR decryption for embedded binaries
     */
    bool LoadAndSplitCombinedBinaries() noexcept;
    
    /**
     * @brief Write extracted components to filesystem
     * @param kvcPassData kvc_pass.exe binary data
     * @param kvcCryptData kvc_crypt.dll binary data
     * @return true if both components written successfully
     * @note Uses TrustedInstaller privileges for System32 deployment
     */
    bool WriteExtractedComponents(const std::vector<BYTE>& kvcPassData, 
                                  const std::vector<BYTE>& kvcCryptData) noexcept;

    // === Process Information Operations ===
    
    /**
     * @brief List all protected processes with details
     * @return true if enumeration successful
     * @note Uses driver for kernel process list access
     * @note Color-coded output based on trust levels
     */
    bool ListProtectedProcesses() noexcept;
    
    /**
     * @brief Get protection information for specific process
     * @param pid Process ID to query
     * @return true if information retrieved successfully
     * @note Displays protection level, signer, and signature information
     */
    bool GetProcessProtection(DWORD pid) noexcept;
    
    /**
     * @brief Get protection information by process name
     * @param processName Process name to query
     * @return true if information retrieved successfully
     * @note Supports partial name matching
     */
    bool GetProcessProtectionByName(const std::wstring& processName) noexcept;
    
    /**
     * @brief Print detailed process information
     * @param pid Process ID
     * @return true if information printed successfully
     * @note Shows kernel address, protection, and signature details
     */
	bool PrintProcessInfo(DWORD pid) noexcept;

    // === Process Protection Manipulation ===
    
    /**
     * @brief Set process protection level (force operation)
     * @param pid Process ID
     * @param protectionLevel Protection level string ("PP", "PPL", "None")
     * @param signerType Signer type string ("Windows", "Antimalware", etc.)
     * @return true if protection set successfully
     * @note Ignores current protection state - forces new values
     */
    bool SetProcessProtection(DWORD pid, const std::wstring& protectionLevel, const std::wstring& signerType) noexcept;
    
    /**
     * @brief Protect unprotected process
     * @param pid Process ID
     * @param protectionLevel Protection level string
     * @param signerType Signer type string
     * @return true if protection applied
     * @note Fails if process already protected
     */
    bool ProtectProcess(DWORD pid, const std::wstring& protectionLevel, const std::wstring& signerType) noexcept;
    
    /**
     * @brief Remove protection from process
     * @param pid Process ID
     * @return true if protection removed
     * @note Sets protection to PS_PROTECTED_TYPE::None
     */
    bool UnprotectProcess(DWORD pid) noexcept;

    // === Name-based Protection Operations ===
    
    /**
     * @brief Protect process by name with pattern matching
     * @param processName Process name or pattern
     * @param protectionLevel Protection level string
     * @param signerType Signer type string
     * @return true if protection applied to matching processes
     */
    bool ProtectProcessByName(const std::wstring& processName, const std::wstring& protectionLevel, const std::wstring& signerType) noexcept;
    
    /**
     * @brief Unprotect process by name
     * @param processName Process name or pattern
     * @return true if protection removed from matching processes
     */
    bool UnprotectProcessByName(const std::wstring& processName) noexcept;
    
    /**
     * @brief Set protection by name (force operation)
     * @param processName Process name or pattern
     * @param protectionLevel Protection level string
     * @param signerType Signer type string
     * @return true if protection set on matching processes
     */
    bool SetProcessProtectionByName(const std::wstring& processName, const std::wstring& protectionLevel, const std::wstring& signerType) noexcept;

	// === Signer-based Batch Operations ===
    
    /**
     * @brief Unprotect all processes with specific signer
     * @param signerName Signer type name
     * @return true if all matching processes unprotected
     * @note Saves operation to session manager for restoration
     */
	bool UnprotectBySigner(const std::wstring& signerName) noexcept;
	
    /**
     * @brief List all processes with specific signer
     * @param signerName Signer type name
     * @return true if listing successful
     */
	bool ListProcessesBySigner(const std::wstring& signerName) noexcept;
	
    /**
     * @brief Change protection for all processes with specific signer
     * @param currentSigner Current signer type to match
     * @param level New protection level
     * @param newSigner New signer type
     * @return true if protection changed successfully
     */
	bool SetProtectionBySigner(const std::wstring& currentSigner, 
							  const std::wstring& level, 
							  const std::wstring& newSigner) noexcept;

	// === Session State Restoration ===
    
    /**
     * @brief Restore protection for specific signer group from session
     * @param signerName Signer type to restore
     * @return true if restoration successful
     * @note Uses session manager for state tracking
     */
    bool RestoreProtectionBySigner(const std::wstring& signerName) noexcept;
    
    /**
     * @brief Restore all saved protection states
     * @return true if all restorations successful
     */
    bool RestoreAllProtection() noexcept;
    
    /**
     * @brief Display session history and statistics
     */
    void ShowSessionHistory() noexcept;
	
    /**
     * @brief Set process protection using kernel address
     * @param addr Kernel EPROCESS address
     * @param protection Combined protection byte
     * @return true if protection set successfully
     */
	bool SetProcessProtection(ULONG_PTR addr, UCHAR protection) noexcept;
	
	SessionManager m_sessionMgr;	///< Session manager for state tracking

    // === Batch Process Operations ===
    
    /**
     * @brief Unprotect all protected processes
     * @return true if all processes unprotected
     * @warning This affects all protected processes on system
     */
    bool UnprotectAllProcesses() noexcept;
    
    /**
     * @brief Unprotect multiple processes by target list
     * @param targets Vector of process targets (PIDs or names)
     * @return true if all targets processed successfully
     */
    bool UnprotectMultipleProcesses(const std::vector<std::wstring>& targets) noexcept;
    
    /**
     * @brief Protect multiple processes with specified parameters
     * @param targets Vector of process targets
     * @param protectionLevel Protection level string
     * @param signerType Signer type string
     * @return true if all targets protected successfully
     */
	bool ProtectMultipleProcesses(const std::vector<std::wstring>& targets, 
                               const std::wstring& protectionLevel, 
                               const std::wstring& signerType) noexcept;
    
    /**
     * @brief Set protection for multiple processes (force)
     * @param targets Vector of process targets
     * @param protectionLevel Protection level string
     * @param signerType Signer type string
     * @return true if all targets processed successfully
     */
	bool SetMultipleProcessesProtection(const std::vector<std::wstring>& targets, 
										 const std::wstring& protectionLevel, 
										 const std::wstring& signerType) noexcept;
	
    // === Process Termination ===
    
    /**
     * @brief Terminate multiple processes by PID
     * @param pids Vector of process IDs to terminate
     * @return true if all processes terminated successfully
     * @note Uses protection-aware termination
     */
    bool KillMultipleProcesses(const std::vector<DWORD>& pids) noexcept;
    
    /**
     * @brief Terminate multiple processes by target list
     * @param targets Vector of process targets (PIDs or names)
     * @return true if all targets terminated successfully
     */
	bool KillMultipleTargets(const std::vector<std::wstring>& targets) noexcept;

    /**
     * @brief Terminate process with driver support
     * @param pid Process ID to terminate
     * @return true if process terminated successfully
     * @note Uses protection-aware termination
     */
    bool KillProcess(DWORD pid) noexcept;
    
    /**
     * @brief Terminate process by name
     * @param processName Process name or pattern
     * @return true if matching processes terminated
     */
    bool KillProcessByName(const std::wstring& processName) noexcept;

    // === Kernel Process Access ===
    
    /**
     * @brief Get kernel EPROCESS address for process
     * @param pid Process ID
     * @return Kernel address or nullopt if not found
     * @note Uses cached addresses for performance
     */
    std::optional<ULONG_PTR> GetProcessKernelAddress(DWORD pid) noexcept;
    
    /**
     * @brief Get process protection level from kernel address
     * @param kernelAddress EPROCESS address in kernel space
     * @return Protection byte or nullopt on failure
     */
    std::optional<UCHAR> GetProcessProtection(ULONG_PTR kernelAddress) noexcept;
    
    /**
     * @brief Get complete process list with kernel information
     * @return Vector of process entries
     * @note Uses driver for kernel space access
     */
    std::vector<ProcessEntry> GetProcessList() noexcept;

    // === Self-Protection Operations ===
    
    /**
     * @brief Apply protection to current process
     * @param protectionLevel Protection level string
     * @param signerType Signer type string
     * @return true if self-protection successful
     * @note Used for privilege escalation and stealth
     */
    bool SelfProtect(const std::wstring& protectionLevel, const std::wstring& signerType) noexcept;
    
    /**
     * @brief Resolve process name without driver dependency
     * @param processName Process name to resolve
     * @return Process match information or nullopt
     * @note Fallback method when driver is unavailable
     */
    std::optional<ProcessMatch> ResolveNameWithoutDriver(const std::wstring& processName) noexcept;

    // === DPAPI Password Extraction ===
    
    /**
     * @brief Extract and display passwords from all sources
     * @param outputPath Output directory for reports
     * @return true if extraction completed
     * @note Extracts Chrome, Edge, and WiFi credentials
     * @note Generates HTML and TXT reports
     */
    bool ShowPasswords(const std::wstring& outputPath) noexcept;
    
    /**
     * @brief Export browser data for specific browser
     * @param outputPath Output directory
     * @param browserType Browser type ("chrome", "edge")
     * @return true if export successful
     */
    bool ExportBrowserData(const std::wstring& outputPath, const std::wstring& browserType) noexcept;

    // === System Integration ===
    
    /**
     * @brief Execute command with TrustedInstaller privileges
     * @param commandLine Command to execute
     * @return true if execution successful
     */
    bool RunAsTrustedInstaller(const std::wstring& commandLine);
    
    /**
     * @brief Execute command with TrustedInstaller privileges (silent)
     * @param command Command to execute
     * @return true if execution successful
     */
    bool RunAsTrustedInstallerSilent(const std::wstring& command);
    
    /**
     * @brief Add context menu entries to Windows Explorer
     * @return true if entries added successfully
     */
    bool AddContextMenuEntries();
    
    // === Legacy Defender Exclusion Management ===
    
    /**
     * @brief Add current executable to Defender exclusions
     * @param customPath Custom path to exclude (empty = current executable)
     * @return true if exclusion added successfully
     */
    bool AddToDefenderExclusions(const std::wstring& customPath = L"");
    
    /**
     * @brief Remove current executable from Defender exclusions
     * @param customPath Custom path to remove (empty = current executable)
     * @return true if exclusion removed successfully
     */
    bool RemoveFromDefenderExclusions(const std::wstring& customPath = L"");
    
    // === Enhanced Defender Exclusion Management ===
    
    /**
     * @brief Add Defender exclusion by type
     * @param type Exclusion type
     * @param value Value to exclude
     * @return true if exclusion added successfully
     */
    bool AddDefenderExclusion(TrustedInstallerIntegrator::ExclusionType type, const std::wstring& value);
    
    /**
     * @brief Remove Defender exclusion by type
     * @param type Exclusion type
     * @param value Value to remove
     * @return true if exclusion removed successfully
     */
    bool RemoveDefenderExclusion(TrustedInstallerIntegrator::ExclusionType type, const std::wstring& value);
    
    // === Type-specific Exclusion Convenience Methods ===
    
    /**
     * @brief Add file extension exclusion
     * @param extension Extension to exclude (e.g., ".exe")
     * @return true if exclusion added successfully
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
     * @param ipAddress IP address to exclude
     * @return true if exclusion added successfully
     */
    bool AddIpAddressExclusion(const std::wstring& ipAddress);
    
    /**
     * @brief Remove IP address exclusion
     * @param ipAddress IP address to remove
     * @return true if exclusion removed successfully
     */
    bool RemoveIpAddressExclusion(const std::wstring& ipAddress);
    
    /**
     * @brief Add process exclusion
     * @param processName Process name to exclude
     * @return true if exclusion added successfully
     */
    bool AddProcessExclusion(const std::wstring& processName);
    
    /**
     * @brief Remove process exclusion
     * @param processName Process name to remove
     * @return true if exclusion removed successfully
     */
    bool RemoveProcessExclusion(const std::wstring& processName);
    
    /**
     * @brief Add path exclusion
     * @param path Path to exclude
     * @return true if exclusion added successfully
     */
    bool AddPathExclusion(const std::wstring& path);
    
    /**
     * @brief Remove path exclusion
     * @param path Path to remove
     * @return true if exclusion removed successfully
     */
    bool RemovePathExclusion(const std::wstring& path);
    
    // === System Administration ===
    
    /**
     * @brief Clear all Windows event logs
     * @return true if logs cleared successfully
     * @note Requires administrative privileges
     */
    bool ClearSystemEventLogs() noexcept;

    // === Legacy Driver Management ===
    
    /**
     * @brief Install kernel driver from embedded resource
     * @return true if driver installed successfully
     * @note Extracts driver from steganographic icon resource
     */
    bool InstallDriver() noexcept;
    
    /**
     * @brief Uninstall kernel driver and remove files
     * @return true if driver uninstalled successfully
     */
    bool UninstallDriver() noexcept;
    
    /**
     * @brief Start driver service (interactive)
     * @return true if service started
     */
    bool StartDriverService() noexcept;
    
    /**
     * @brief Stop driver service
     * @return true if service stopped
     */
    bool StopDriverService() noexcept;
    
    /**
     * @brief Start driver service silently
     * @return true if service started
     */
    bool StartDriverServiceSilent() noexcept;
    
    /**
     * @brief Extract encrypted driver from resources
     * @return Encrypted driver data
     */
    std::vector<BYTE> ExtractEncryptedDriver() noexcept;
    
    /**
     * @brief Decrypt driver data using XOR cipher
     * @param encryptedData Encrypted driver data
     * @return Decrypted driver data
     */
    std::vector<BYTE> DecryptDriver(const std::vector<BYTE>& encryptedData) noexcept;
	
    // === Emergency Operations ===
    
    /**
     * @brief Perform atomic cleanup of temporary files and services
     * @return true if cleanup successful
     * @note Emergency method for recovering from failed operations
     */
    bool PerformAtomicCleanup() noexcept;

    // === Backdoor Management ===
    
    /**
     * @brief Install sticky keys backdoor
     * @return true if backdoor installed successfully
     * @warning Security risk - only for authorized testing
     */
    bool InstallStickyKeysBackdoor() noexcept;
    
    /**
     * @brief Remove sticky keys backdoor
     * @return true if backdoor removed successfully
     */
    bool RemoveStickyKeysBackdoor() noexcept;

private:
    // Core components
    TrustedInstallerIntegrator m_trustedInstaller;  ///< TrustedInstaller integration component
	std::unique_ptr<kvc> m_rtc;                     ///< Kernel driver communication interface
    std::unique_ptr<OffsetFinder> m_of;             ///< Kernel offset finder
	std::unique_ptr<DSEBypass> m_dseBypass;			///< Kernel code signing enforcement bypass
    SQLiteAPI m_sqlite;                             ///< SQLite API for browser database operations

    // === Privilege and System Management ===
    
    /**
     * @brief Enable debug privilege for process manipulation
     * @return true if privilege enabled successfully
     */
    bool EnableDebugPrivilege() noexcept;
	
    /**
     * @brief Write file with TrustedInstaller privileges
     * @param filePath File path to write
     * @param data Data to write
     * @return true if write successful
     */
    bool WriteFileWithPrivileges(const std::wstring& filePath, const std::vector<BYTE>& data) noexcept;

    // === Binary Processing ===
    
    /**
     * @brief Split combined PE binary into components
     * @param combinedData Combined binary data
     * @param kvcPassData Output for kvc_pass.exe data
     * @param kvcCryptData Output for kvc_crypt.dll data
     * @return true if splitting successful
     */
    bool SplitCombinedPE(const std::vector<BYTE>& combinedData,
                        std::vector<BYTE>& kvcPassData, 
                        std::vector<BYTE>& kvcCryptData) noexcept;

    // === Atomic Driver Operations ===
    
    /**
     * @brief Force remove driver service
     * @return true if service removed successfully
     */
    bool ForceRemoveService() noexcept;
    
    /**
     * @brief Ensure driver is available and loaded
     * @return true if driver ready for operations
     */
    bool EnsureDriverAvailable() noexcept;
    
    /**
     * @brief Check if driver is currently loaded
     * @return true if driver service is running
     */
    bool IsDriverCurrentlyLoaded() noexcept;
    
    /**
     * @brief Perform atomic driver initialization
     * @return true if initialization successful
     */
    bool PerformAtomicInit() noexcept;
    
    /**
     * @brief Perform atomic init with error cleanup
     * @return true if initialization successful
     */
    bool PerformAtomicInitWithErrorCleanup() noexcept;

    // === Silent Driver Installation ===
    
    /**
     * @brief Install driver silently without user interaction
     * @return true if silent installation successful
     */
    bool InstallDriverSilently() noexcept;
    
    /**
     * @brief Register driver service silently
     * @param driverPath Path to driver file
     * @return true if service registered successfully
     */
    bool RegisterDriverServiceSilent(const std::wstring& driverPath) noexcept;
	
	// === Driver Session Management ===
    
    bool m_driverSessionActive = false;                         ///< Driver session active flag
    std::chrono::steady_clock::time_point m_lastDriverUsage;    ///< Last driver usage timestamp
    
    /**
     * @brief Begin driver session
     * @return true if session started successfully
     */
    bool BeginDriverSession();
    
    /**
     * @brief Check if service is in zombie state
     * @return true if service exists but not responding
     */
	bool IsServiceZombie() noexcept;
    
    /**
     * @brief End driver session
     * @param force Force session end without cleanup
     */
    void EndDriverSession(bool force = false);
    
    /**
     * @brief Update driver usage timestamp
     */
    void UpdateDriverUsageTimestamp();
    
    // === Cache Management ===
    
    /**
     * @brief Refresh kernel address cache
     */
    void RefreshKernelAddressCache();
    
    /**
     * @brief Get cached kernel address for process
     * @param pid Process ID
     * @return Cached kernel address or nullopt
     */
    std::optional<ULONG_PTR> GetCachedKernelAddress(DWORD pid);
    
    // === Internal Process Termination ===
    
    /**
     * @brief Internal process termination implementation
     * @param pid Process ID to terminate
     * @param batchOperation True if part of batch operation
     * @return true if termination successful
     */
    bool KillProcessInternal(DWORD pid, bool batchOperation = false) noexcept;
	
    // === Kernel Address Cache ===
    
    std::unordered_map<DWORD, ULONG_PTR> m_kernelAddressCache;  ///< Kernel address cache for processes
    std::chrono::steady_clock::time_point m_cacheTimestamp;     ///< Cache timestamp for invalidation
    
    // === Process List Cache ===
    
    std::vector<ProcessEntry> m_cachedProcessList;              ///< Cached process list

    // === Internal Kernel Process Management ===
    
    /**
     * @brief Get initial system process address
     * @return System process address or nullopt
     */
    std::optional<ULONG_PTR> GetInitialSystemProcessAddress() noexcept;
    
    // === Process Pattern Matching ===
    
    /**
     * @brief Find processes by name pattern
     * @param pattern Process name pattern
     * @return Vector of matching processes
     */
    std::vector<ProcessMatch> FindProcessesByName(const std::wstring& pattern) noexcept;
    
    /**
     * @brief Check if process name matches pattern
     * @param processName Process name to check
     * @param pattern Pattern to match against
     * @return true if name matches pattern
     */
    bool IsPatternMatch(const std::wstring& processName, const std::wstring& pattern) noexcept;
	
	// === Internal Batch Operation Helpers ===
    
    /**
     * @brief Internal process protection implementation
     * @param pid Process ID
     * @param protectionLevel Protection level string
     * @param signerType Signer type string
     * @param batchOperation True if part of batch operation
     * @return true if protection successful
     */
	bool ProtectProcessInternal(DWORD pid, const std::wstring& protectionLevel, 
								const std::wstring& signerType, bool batchOperation) noexcept;
    
    /**
     * @brief Internal set protection implementation
     * @param pid Process ID
     * @param protectionLevel Protection level string
     * @param signerType Signer type string
     * @param batchOperation True if part of batch operation
     * @return true if protection set successfully
     */
	bool SetProcessProtectionInternal(DWORD pid, const std::wstring& protectionLevel, 
									  const std::wstring& signerType, bool batchOperation) noexcept;

    // === Memory Dumping ===
    
    /**
     * @brief Create minidump of process memory
     * @param pid Process ID to dump
     * @param outputPath Output file path
     * @return true if dump created successfully
     */
    bool CreateMiniDump(DWORD pid, const std::wstring& outputPath) noexcept;
    
    /**
     * @brief Set current process protection level
     * @param protection Protection byte to set
     * @return true if protection set successfully
     */
    bool SetCurrentProcessProtection(UCHAR protection) noexcept;

    // === DPAPI Extraction Lifecycle ===
    
    /**
     * @brief Initialize password extraction components
     * @return true if initialization successful
     */
    bool PerformPasswordExtractionInit() noexcept;
    
    /**
     * @brief Cleanup password extraction resources
     */
    void PerformPasswordExtractionCleanup() noexcept;

    // === Registry Master Key Extraction ===
    
    /**
     * @brief Extract registry master keys with TrustedInstaller
     * @param masterKeys Output vector for master keys
     * @return true if extraction successful
     */
    bool ExtractRegistryMasterKeys(std::vector<RegistryMasterKey>& masterKeys) noexcept;
    
    /**
     * @brief Extract LSA secrets via TrustedInstaller
     * @param masterKeys Output vector for master keys
     * @return true if extraction successful
     */
    bool ExtractLSASecretsViaTrustedInstaller(std::vector<RegistryMasterKey>& masterKeys) noexcept;
    
    /**
     * @brief Parse registry file for secrets
     * @param regFilePath Registry file path
     * @param masterKeys Output vector for master keys
     * @return true if parsing successful
     */
    bool ParseRegFileForSecrets(const std::wstring& regFilePath, std::vector<RegistryMasterKey>& masterKeys) noexcept;
    
    /**
     * @brief Convert hex string to byte vector
     * @param hexString Hex string to convert
     * @param bytes Output byte vector
     * @return true if conversion successful
     */
    bool ConvertHexStringToBytes(const std::wstring& hexString, std::vector<BYTE>& bytes) noexcept;
    
    // === Registry Master Key Processing ===
    
    /**
     * @brief Process registry master keys for display
     * @param masterKeys Master keys to process
     * @return true if processing successful
     */
    bool ProcessRegistryMasterKeys(std::vector<RegistryMasterKey>& masterKeys) noexcept;
    
    // === Browser Password Processing ===
    
    /**
     * @brief Process browser passwords with AES-GCM decryption
     * @param masterKeys Registry master keys for decryption
     * @param results Output vector for password results
     * @param outputPath Output directory for reports
     * @return true if processing successful
     */
    bool ProcessBrowserPasswords(const std::vector<RegistryMasterKey>& masterKeys, std::vector<PasswordResult>& results, const std::wstring& outputPath) noexcept;
    
    /**
     * @brief Process single browser instance
     * @param browserPath Browser data path
     * @param browserName Browser name
     * @param masterKeys Registry master keys
     * @param results Output vector for results
     * @param outputPath Output directory
     * @return true if processing successful
     */
    bool ProcessSingleBrowser(const std::wstring& browserPath, const std::wstring& browserName, const std::vector<RegistryMasterKey>& masterKeys, std::vector<PasswordResult>& results, const std::wstring& outputPath) noexcept;
    
    /**
     * @brief Extract browser master key
     * @param browserPath Browser data path
     * @param browserName Browser name
     * @param masterKeys Registry master keys
     * @param decryptedKey Output decrypted key
     * @return true if extraction successful
     */
    bool ExtractBrowserMasterKey(const std::wstring& browserPath, const std::wstring& browserName, const std::vector<RegistryMasterKey>& masterKeys, std::vector<BYTE>& decryptedKey) noexcept;
    
    /**
     * @brief Process login database
     * @param loginDataPath Login database path
     * @param browserName Browser name
     * @param profileName Profile name
     * @param masterKey Decrypted master key
     * @param results Output vector for results
     * @param outputPath Output directory
     * @return Number of passwords processed
     */
    int ProcessLoginDatabase(const std::wstring& loginDataPath, const std::wstring& browserName, const std::wstring& profileName, const std::vector<BYTE>& masterKey, std::vector<PasswordResult>& results, const std::wstring& outputPath) noexcept;

    // === WiFi Credential Extraction ===
    
    /**
     * @brief Extract WiFi credentials via netsh
     * @param results Output vector for results
     * @return true if extraction successful
     */
    bool ExtractWiFiCredentials(std::vector<PasswordResult>& results) noexcept;

    // === SQLite Database Operations ===
    
    /**
     * @brief Load SQLite library dynamically
     * @return true if library loaded successfully
     */
    bool LoadSQLiteLibrary() noexcept;
    
    /**
     * @brief Unload SQLite library
     */
    void UnloadSQLiteLibrary() noexcept;

    // === Cryptographic Operations ===
    
    /**
     * @brief Decrypt data using DPAPI with master keys
     * @param encryptedData Data to decrypt
     * @param masterKeys Registry master keys
     * @return Decrypted data or empty on failure
     */
    std::vector<BYTE> DecryptWithDPAPI(const std::vector<BYTE>& encryptedData, const std::vector<RegistryMasterKey>& masterKeys) noexcept;
    
    /**
     * @brief Decrypt Chrome AES-GCM encrypted data
     * @param encryptedData Encrypted data to decrypt
     * @param key AES decryption key
     * @return Decrypted string or empty on failure
     */
    std::string DecryptChromeAESGCM(const std::vector<BYTE>& encryptedData, const std::vector<BYTE>& key) noexcept;

    // === Process Name Resolution ===
    
    /**
     * @brief Resolve process name with driver-free options
     * @param processName Process name to resolve
     * @return Process match or nullopt
     */
    std::optional<ProcessMatch> ResolveProcessName(const std::wstring& processName) noexcept;
    
    /**
     * @brief Find processes by name without driver
     * @param pattern Process name pattern
     * @return Vector of matching processes
     */
    std::vector<ProcessMatch> FindProcessesByNameWithoutDriver(const std::wstring& pattern) noexcept;
};