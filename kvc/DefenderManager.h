/**
 * @file DefenderManager.h
 * @brief Windows Defender Security Engine manipulation through registry-level operations
 * @author Marek Wesolowski
 * @date 2025
 * @copyright KVC Framework
 * 
 * Provides registry-level manipulation of Windows Defender service dependencies
 * to enable/disable the security engine, bypassing tamper protection mechanisms.
 * Requires administrator privileges and system restart for changes to take effect.
 */

#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <memory>

/**
 * @brief Windows Defender Security Engine management through registry manipulation
 * 
 * This class provides low-level control over Windows Defender by modifying
 * service dependencies in the registry. Works by changing RPC service dependencies
 * (RpcSs <-> RpcSt) to enable or disable the security engine.
 * 
 * @warning Requires SE_BACKUP_NAME, SE_RESTORE_NAME, and SE_LOAD_DRIVER_NAME privileges
 * @warning System restart required for changes to take effect
 * @warning Bypasses Windows Defender tamper protection
 */
class DefenderManager {
public:
    /**
     * @brief Security engine state enumeration
     */
    enum class SecurityState {
        ENABLED,    ///< Windows Defender security engine is active (RpcSs dependency)
        DISABLED,   ///< Windows Defender security engine is inactive (RpcSt dependency)
        UNKNOWN     ///< Unable to determine security engine state
    };

    /**
     * @brief Disables Windows Defender security engine
     * 
     * Modifies Windows Defender service dependencies to prevent engine startup.
     * Changes RpcSs (active) dependency to RpcSt (inactive stub service).
     * 
     * @return bool true if operation successful, false on failure
     * 
     * @note Requires administrator privileges
     * @note System restart required for changes to take effect
     * @warning This bypasses Windows Defender tamper protection
     */
    static bool DisableSecurityEngine() noexcept;
    
    /**
     * @brief Enables Windows Defender security engine
     * 
     * Restores Windows Defender service dependencies to normal operation.
     * Changes RpcSt (inactive) dependency back to RpcSs (active service).
     * 
     * @return bool true if operation successful, false on failure
     * 
     * @note Requires administrator privileges
     * @note System restart required for changes to take effect
     */
    static bool EnableSecurityEngine() noexcept;
    
    /**
     * @brief Queries current Windows Defender security engine state
     * 
     * Reads Windows Defender service dependencies from registry to determine
     * if the security engine is enabled (RpcSs), disabled (RpcSt), or unknown.
     * 
     * @return SecurityState Current state of Windows Defender security engine
     * 
     * @note Does not require elevated privileges for read-only query
     */
    static SecurityState GetSecurityEngineStatus() noexcept;

private:
    /**
     * @brief Registry snapshot context for atomic operations
     * 
     * Holds temporary registry hive files and paths for atomic
     * modification of Windows Defender service configuration.
     */
    struct RegistryContext {
        std::wstring tempPath;      ///< Temporary working directory path
        std::wstring hiveFile;      ///< Saved registry hive file path
        
        RegistryContext() = default;
        
        /**
         * @brief Destructor - automatically cleans up temporary files
         */
        ~RegistryContext() { Cleanup(); }
        
        // Non-copyable, movable
        RegistryContext(const RegistryContext&) = delete;
        RegistryContext& operator=(const RegistryContext&) = delete;
        RegistryContext(RegistryContext&&) = default;
        RegistryContext& operator=(RegistryContext&&) = default;
        
        /**
         * @brief Cleans up temporary registry files and transaction logs
         * 
         * Removes:
         * - Main hive file
         * - Transaction logs (.LOG1, .LOG2)
         * - Binary log files (.blf)
         * - Registry transaction files (.regtrans-ms)
         * 
         * @note Safe to call multiple times (idempotent operation)
         */
        void Cleanup() noexcept;
    };

    /**
     * @brief Core registry manipulation logic for enable/disable operations
     * 
     * Workflow:
     * 1. Enables required privileges (SE_BACKUP_NAME, SE_RESTORE_NAME, SE_LOAD_DRIVER_NAME)
     * 2. Creates registry snapshot of Services hive
     * 3. Modifies Windows Defender service dependencies
     * 4. Restores modified registry snapshot to live registry
     * 
     * @param enable true to enable Defender, false to disable
     * @return bool true if all operations successful, false on any failure
     * 
     * @note Atomic operation - changes are rolled back on failure
     */
    static bool ModifySecurityEngine(bool enable) noexcept;
    
    /**
     * @brief Enables all required privileges for registry operations
     * 
     * Required privileges:
     * - SE_BACKUP_NAME: Read registry hives
     * - SE_RESTORE_NAME: Write registry hives
     * - SE_LOAD_DRIVER_NAME: Load/unload registry hives
     * 
     * @return bool true if all privileges enabled, false on any failure
     */
    static bool EnableRequiredPrivileges() noexcept;
    
    /**
     * @brief Creates temporary registry snapshot for atomic modifications
     * 
     * Process:
     * 1. Determines system temp path (Windows\temp)
     * 2. Validates write access to temp directory
     * 3. Saves Services registry hive to temporary file
     * 4. Loads saved hive as HKLM\Temp for modification
     * 
     * @param ctx [out] Registry context with temp paths and hive file location
     * @return bool true if snapshot created successfully, false on failure
     * 
     * @note Creates Services.hiv file in Windows\temp directory
     */
    static bool CreateRegistrySnapshot(RegistryContext& ctx) noexcept;
    
    /**
     * @brief Modifies Windows Defender service dependencies in temp registry
     * 
     * Changes RPC service dependency:
     * - Enable: RpcSt (inactive) → RpcSs (active)
     * - Disable: RpcSs (active) → RpcSt (inactive)
     * 
     * @param ctx Registry context with loaded temp hive
     * @param enable true to enable Defender, false to disable
     * @return bool true if dependency modification successful, false on failure
     * 
     * @note Operates on HKLM\Temp\WinDefend key, not live registry
     */
    static bool ModifyDefenderDependencies(const RegistryContext& ctx, bool enable) noexcept;
    
    /**
     * @brief Restores modified registry snapshot to live system registry
     * 
     * Process:
     * 1. Unloads temporary HKLM\Temp registry hive
     * 2. Restores modified hive to HKLM\SYSTEM\CurrentControlSet\Services
     * 3. Commits changes to live registry
     * 
     * @param ctx Registry context with modified hive file
     * @return bool true if restore successful, false on failure
     * 
     * @warning This operation modifies the live system registry
     * @note Uses REG_FORCE_RESTORE to overwrite existing registry data
     */
    static bool RestoreRegistrySnapshot(const RegistryContext& ctx) noexcept;
    
    /**
     * @brief Reads REG_MULTI_SZ registry value as string vector
     * 
     * @param key Open registry key handle
     * @param valueName Name of REG_MULTI_SZ value to read
     * @return std::vector<std::wstring> Vector of strings or empty on failure
     * 
     * @note Returns empty vector if value doesn't exist or wrong type
     */
    static std::vector<std::wstring> ReadMultiString(HKEY key, const std::wstring& valueName) noexcept;
    
    /**
     * @brief Writes string vector to REG_MULTI_SZ registry value
     * 
     * @param key Open registry key handle
     * @param valueName Name of REG_MULTI_SZ value to write
     * @param values Vector of strings to write
     * @return bool true if write successful, false on failure
     * 
     * @note Properly formats with double null terminator
     */
    static bool WriteMultiString(HKEY key, const std::wstring& valueName, const std::vector<std::wstring>& values) noexcept;
    
    // Registry constants
    static constexpr const wchar_t* WINDEFEND_KEY = L"SYSTEM\\CurrentControlSet\\Services\\WinDefend";  ///< Windows Defender service key
    static constexpr const wchar_t* SERVICES_KEY = L"SYSTEM\\CurrentControlSet\\Services";              ///< Windows Services root key
    static constexpr const wchar_t* DEPEND_VALUE = L"DependOnService";                                  ///< Service dependency value name
    static constexpr const wchar_t* RPC_SERVICE_ACTIVE = L"RpcSs";                                      ///< Active RPC service (enables Defender)
    static constexpr const wchar_t* RPC_SERVICE_INACTIVE = L"RpcSt";                                    ///< Inactive RPC stub (disables Defender)
};