/**
 * @file DefenderManager.cpp
 * @brief Implementation of Windows Defender Security Engine management
 * @author Marek Wesolowski
 * @date 2025
 * @copyright KVC Framework
 * 
 * Implements registry-level manipulation of Windows Defender service dependencies.
 * Provides atomic operations for enabling/disabling the security engine by modifying
 * RPC service dependencies in the Windows registry.
 */

#include "DefenderManager.h"
#include "common.h"
#include <filesystem>
#include <algorithm>
#include <iostream>

using namespace std;
namespace fs = std::filesystem;

// Console color helper (using existing SetColor function from main application)
extern void SetColor(int color);

// ============================================================================
// PUBLIC INTERFACE IMPLEMENTATION
// ============================================================================

/**
 * @brief Disables Windows Defender security engine
 * 
 * Implementation details:
 * 1. Calls ModifySecurityEngine(false) to perform registry manipulation
 * 2. Provides user feedback through console output
 * 
 * @return bool true if Defender successfully disabled, false on failure
 */
bool DefenderManager::DisableSecurityEngine() noexcept 
{
    std::wcout << L"Disabling Windows Security Engine...\n";
    return ModifySecurityEngine(false);
}

/**
 * @brief Enables Windows Defender security engine
 * 
 * Implementation details:
 * 1. Calls ModifySecurityEngine(true) to perform registry manipulation
 * 2. Provides user feedback through console output
 * 
 * @return bool true if Defender successfully enabled, false on failure
 */
bool DefenderManager::EnableSecurityEngine() noexcept 
{
    std::wcout << L"Enabling Windows Security Engine...\n";
    return ModifySecurityEngine(true);
}

/**
 * @brief Queries current Windows Defender security engine state
 * 
 * Detection logic:
 * 1. Opens Windows Defender service registry key (read-only)
 * 2. Reads DependOnService REG_MULTI_SZ value
 * 3. Searches for RpcSs (enabled) or RpcSt (disabled) in dependencies
 * 4. Returns ENABLED if RpcSs found, DISABLED if RpcSt found, UNKNOWN otherwise
 * 
 * @return SecurityState Current state of Windows Defender security engine
 */
DefenderManager::SecurityState DefenderManager::GetSecurityEngineStatus() noexcept 
{
    try {
        HKEY key;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, WINDEFEND_KEY, 0, KEY_READ, &key) != ERROR_SUCCESS) {
            return SecurityState::UNKNOWN;
        }
        
        auto values = ReadMultiString(key, DEPEND_VALUE);
        RegCloseKey(key);
        
        if (values.empty()) return SecurityState::UNKNOWN;
        
        // Check if RpcSs (active) or RpcSt (inactive) is present
        bool hasActive = find(values.begin(), values.end(), RPC_SERVICE_ACTIVE) != values.end();
        bool hasInactive = find(values.begin(), values.end(), RPC_SERVICE_INACTIVE) != values.end();
        
        if (hasActive) return SecurityState::ENABLED;
        if (hasInactive) return SecurityState::DISABLED;
        
        return SecurityState::UNKNOWN;
    }
    catch (...) {
        return SecurityState::UNKNOWN;
    }
}

// ============================================================================
// CORE OPERATIONS IMPLEMENTATION
// ============================================================================

/**
 * @brief Core registry manipulation logic for enable/disable operations
 * 
 * Atomic operation sequence:
 * 1. Enable required privileges (SE_BACKUP_NAME, SE_RESTORE_NAME, SE_LOAD_DRIVER_NAME)
 * 2. Create registry snapshot of Services hive to temp file
 * 3. Modify Windows Defender dependencies in temp registry
 * 4. Restore modified registry snapshot to live system
 * 
 * @param enable true to enable Defender (RpcSt→RpcSs), false to disable (RpcSs→RpcSt)
 * @return bool true if all operations successful, false on any failure
 * 
 * @note All operations are atomic - partial failure results in rollback
 * @note Provides detailed console feedback for each step
 */
bool DefenderManager::ModifySecurityEngine(bool enable) noexcept 
{
    try {
        // Enable required privileges first
        if (!EnableRequiredPrivileges()) {
            std::wcout << L"Failed to enable required privileges - run as administrator\n";
            return false;
        }
        
        // Create registry working context
        RegistryContext ctx;
        if (!CreateRegistrySnapshot(ctx)) {
            std::wcout << L"Failed to create registry snapshot\n";
            return false;
        }
        
        // Modify defender dependencies
        if (!ModifyDefenderDependencies(ctx, enable)) {
            std::wcout << L"Failed to modify Defender dependencies\n";
            return false;
        }
        
        // Restore modified registry
        if (!RestoreRegistrySnapshot(ctx)) {
            std::wcout << L"Failed to restore registry snapshot\n";
            return false;
        }
        
        std::wcout << L"Security engine " << (enable ? L"enabled" : L"disabled") << L" successfully\n";
        std::wcout << L"System restart required to apply changes\n";
        return true;
    }
    catch (...) {
        std::wcout << L"Exception in ModifySecurityEngine\n";
        return false;
    }
}

/**
 * @brief Creates temporary registry snapshot for atomic modifications
 * 
 * Process:
 * 1. Get system temp path (Windows\temp)
 * 2. Validate write access to temp directory
 * 3. Clean up any existing Services.hiv file
 * 4. Unload any existing HKLM\Temp registry hive
 * 5. Save HKLM\SYSTEM\CurrentControlSet\Services to Services.hiv
 * 6. Load Services.hiv as HKLM\Temp for modification
 * 
 * @param ctx [out] Registry context populated with temp paths and hive file
 * @return bool true if snapshot created successfully, false on failure
 * 
 * @note Uses REG_LATEST_FORMAT for maximum compatibility
 * @note Cleans up existing temp hives to prevent conflicts
 */
bool DefenderManager::CreateRegistrySnapshot(RegistryContext& ctx) noexcept 
{
    ctx.tempPath = ::GetSystemTempPath();
    if (ctx.tempPath.empty()) {
        std::wcout << L"Failed to get system temp path\n";
        return false;
    }
    
    // Ensure temp directory exists and is writable
    if (!PathUtils::ValidateDirectoryWritable(ctx.tempPath)) {
        std::wcout << L"Cannot write to temp directory: " << ctx.tempPath << L"\n";
        return false;
    }
    
    ctx.hiveFile = ctx.tempPath + L"Services.hiv";
    
    // Clean up any existing hive file
    if (fs::exists(ctx.hiveFile) && !DeleteFileW(ctx.hiveFile.c_str())) {
        std::wcout << L"Failed to delete existing hive file\n";
        return false;
    }
    
    // Unload any existing temp registry hive
    HKEY tempCheck;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Temp", 0, KEY_READ, &tempCheck) == ERROR_SUCCESS) {
        RegCloseKey(tempCheck);
        RegUnLoadKeyW(HKEY_LOCAL_MACHINE, L"Temp");
    }
    
    // Save current services registry hive
    HKEY servicesKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, SERVICES_KEY, 0, KEY_READ, &servicesKey) != ERROR_SUCCESS) {
        std::wcout << L"Failed to open Services registry key\n";
        return false;
    }
    
    LONG result = RegSaveKeyExW(servicesKey, ctx.hiveFile.c_str(), nullptr, REG_LATEST_FORMAT);
    RegCloseKey(servicesKey);
    
    if (result != ERROR_SUCCESS) {
        std::wcout << L"Failed to save registry hive: " << result << L"\n";
        return false;
    }
    
    // Load saved hive as temporary key
    if (RegLoadKeyW(HKEY_LOCAL_MACHINE, L"Temp", ctx.hiveFile.c_str()) != ERROR_SUCCESS) {
        std::wcout << L"Failed to load registry hive as temp key\n";
        return false;
    }
    
    return true;
}

/**
 * @brief Modifies Windows Defender service dependencies in temp registry
 * 
 * Modification logic:
 * 1. Opens HKLM\Temp\WinDefend key (loaded from snapshot)
 * 2. Reads DependOnService REG_MULTI_SZ value
 * 3. Transforms RPC service dependency:
 *    - Enable: RpcSt (inactive stub) → RpcSs (active service)
 *    - Disable: RpcSs (active service) → RpcSt (inactive stub)
 * 4. Writes modified dependencies back to temp registry
 * 
 * @param ctx Registry context with loaded temp hive
 * @param enable true to enable Defender, false to disable
 * @return bool true if dependency modification successful, false on failure
 * 
 * @note Operates only on temp registry (HKLM\Temp), not live system
 * @note Automatically closes registry key handle on exit
 */
bool DefenderManager::ModifyDefenderDependencies(const RegistryContext& ctx, bool enable) noexcept 
{
    HKEY tempKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Temp\\WinDefend", 0, KEY_READ | KEY_WRITE, &tempKey) != ERROR_SUCCESS) {
        std::wcout << L"Failed to open temporary WinDefend key\n";
        return false;
    }
    
    auto values = ReadMultiString(tempKey, DEPEND_VALUE);
    if (values.empty()) {
        std::wcout << L"No DependOnService values found\n";
        RegCloseKey(tempKey);
        return false;
    }
    
    // Transform RPC service dependency
    for (auto& value : values) {
        if (enable && value == RPC_SERVICE_INACTIVE) {
            value = RPC_SERVICE_ACTIVE;  // RpcSt -> RpcSs (enable)
        }
        else if (!enable && value == RPC_SERVICE_ACTIVE) {
            value = RPC_SERVICE_INACTIVE; // RpcSs -> RpcSt (disable)
        }
    }
    
    bool success = WriteMultiString(tempKey, DEPEND_VALUE, values);
    RegCloseKey(tempKey);
    
    if (!success) {
        std::wcout << L"Failed to write modified dependency values\n";
        return false;
    }
    
    return true;
}

/**
 * @brief Restores modified registry snapshot to live system registry
 * 
 * Restoration process:
 * 1. Unload temporary HKLM\Temp registry hive (modified snapshot)
 * 2. Open HKLM\SYSTEM\CurrentControlSet\Services key with write access
 * 3. Restore modified hive file using RegRestoreKeyW with force flag
 * 4. Close registry key handle
 * 
 * @param ctx Registry context with modified hive file path
 * @return bool true if restore successful, false on failure
 * 
 * @warning This operation permanently modifies the live system registry
 * @note Uses REG_FORCE_RESTORE to overwrite existing registry data
 * @note Warnings about failed unload are informational only (non-critical)
 */
bool DefenderManager::RestoreRegistrySnapshot(const RegistryContext& ctx) noexcept 
{
    // Unload temporary registry hive
    if (RegUnLoadKeyW(HKEY_LOCAL_MACHINE, L"Temp") != ERROR_SUCCESS) {
        std::wcout << L"Warning: Failed to unload temporary registry hive\n";
    }
    
    // Restore modified hive to live registry
    HKEY servicesKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, SERVICES_KEY, 0, KEY_WRITE, &servicesKey) != ERROR_SUCCESS) {
        std::wcout << L"Failed to open Services key for restore\n";
        return false;
    }
    
    LONG result = RegRestoreKeyW(servicesKey, ctx.hiveFile.c_str(), REG_FORCE_RESTORE);
    RegCloseKey(servicesKey);
    
    if (result != ERROR_SUCCESS) {
        std::wcout << L"Failed to restore modified registry hive: " << result << L"\n";
        return false;
    }
    
    return true;
}

// ============================================================================
// PRIVILEGE MANAGEMENT IMPLEMENTATION
// ============================================================================

/**
 * @brief Enables all required privileges for registry operations
 * 
 * Required privileges:
 * - SE_BACKUP_NAME: Allows reading registry hives (RegSaveKeyExW)
 * - SE_RESTORE_NAME: Allows writing registry hives (RegRestoreKeyW)
 * - SE_LOAD_DRIVER_NAME: Allows loading/unloading registry hives (RegLoadKeyW/RegUnLoadKeyW)
 * 
 * @return bool true if all three privileges enabled successfully, false if any fails
 * 
 * @note All three privileges must be enabled for registry snapshot operations
 * @note Failure of any single privilege causes entire operation to fail
 */
bool DefenderManager::EnableRequiredPrivileges() noexcept 
{
	return PrivilegeUtils::EnablePrivilege(SE_BACKUP_NAME) &&
		   PrivilegeUtils::EnablePrivilege(SE_RESTORE_NAME) &&
		   PrivilegeUtils::EnablePrivilege(SE_LOAD_DRIVER_NAME);
}

// ============================================================================
// HELPER UTILITIES IMPLEMENTATION
// ============================================================================

/**
 * @brief Reads REG_MULTI_SZ registry value as string vector
 * 
 * Reading process:
 * 1. Query value type and size using RegQueryValueExW (initial call)
 * 2. Validate value is REG_MULTI_SZ type
 * 3. Allocate buffer for value data
 * 4. Read value data into buffer
 * 5. Parse null-terminated strings from buffer
 * 6. Return vector of strings (empty vector on failure)
 * 
 * @param key Open registry key handle with KEY_READ access
 * @param valueName Name of REG_MULTI_SZ value to read
 * @return std::vector<std::wstring> Vector of strings, empty if value doesn't exist or wrong type
 * 
 * @note Returns empty vector if value is wrong type or doesn't exist
 * @note Properly handles null-terminated string array format
 * @note Does not close registry key handle (caller's responsibility)
 */
vector<wstring> DefenderManager::ReadMultiString(HKEY key, const wstring& valueName) noexcept 
{
    DWORD type, size;
    if (RegQueryValueExW(key, valueName.c_str(), nullptr, &type, nullptr, &size) != ERROR_SUCCESS || 
        type != REG_MULTI_SZ) {
        return {};
    }
    
    vector<wchar_t> buffer(size / sizeof(wchar_t));
    if (RegQueryValueExW(key, valueName.c_str(), nullptr, &type, 
                        reinterpret_cast<BYTE*>(buffer.data()), &size) != ERROR_SUCCESS) {
        return {};
    }
    
    vector<wstring> result;
    const wchar_t* current = buffer.data();
    
    while (*current != L'\0') {
        result.emplace_back(current);
        current += result.back().size() + 1;
    }
    
    return result;
}

/**
 * @brief Writes string vector to REG_MULTI_SZ registry value
 * 
 * Writing process:
 * 1. Create buffer for null-terminated string array
 * 2. Copy each string to buffer with null terminator
 * 3. Add final double null terminator
 * 4. Write buffer to registry using RegSetValueExW
 * 
 * @param key Open registry key handle with KEY_WRITE access
 * @param valueName Name of REG_MULTI_SZ value to write
 * @param values Vector of strings to write
 * @return bool true if write successful, false on failure
 * 
 * @note Properly formats with double null terminator (REG_MULTI_SZ requirement)
 * @note Does not close registry key handle (caller's responsibility)
 */
bool DefenderManager::WriteMultiString(HKEY key, const wstring& valueName, 
                                      const vector<wstring>& values) noexcept 
{
    vector<wchar_t> buffer;
    
    for (const auto& str : values) {
        buffer.insert(buffer.end(), str.begin(), str.end());
        buffer.push_back(L'\0');
    }
    buffer.push_back(L'\0'); // Double null terminator
    
    return RegSetValueExW(key, valueName.c_str(), 0, REG_MULTI_SZ,
                         reinterpret_cast<const BYTE*>(buffer.data()),
                         static_cast<DWORD>(buffer.size() * sizeof(wchar_t))) == ERROR_SUCCESS;
}

// ============================================================================
// REGISTRY CONTEXT CLEANUP IMPLEMENTATION
// ============================================================================

/**
 * @brief Cleans up temporary registry files and transaction logs
 * 
 * Cleanup targets:
 * 1. Main hive file (Services.hiv)
 * 2. Transaction logs (Services.hiv.LOG1, Services.hiv.LOG2)
 * 3. Binary log file (Services.hiv.blf)
 * 4. Registry transaction files (*.regtrans-ms in temp directory)
 * 
 * @note Safe to call multiple times (idempotent operation)
 * @note Ignores errors during cleanup (best-effort cleanup)
 * @note Called automatically by RegistryContext destructor
 */
void DefenderManager::RegistryContext::Cleanup() noexcept 
{
    if (hiveFile.empty()) return;
    
    // Standard cleanup patterns
    vector<wstring> patterns = {
        hiveFile,
        hiveFile + L".LOG1",
        hiveFile + L".LOG2", 
        hiveFile + L".blf"
    };
    
    for (const auto& file : patterns) {
        DeleteFileW(file.c_str());
    }
    
    // Clean transaction files
    try {
        for (const auto& entry : fs::directory_iterator(tempPath)) {
            if (entry.path().extension() == L".regtrans-ms") {
                DeleteFileW(entry.path().c_str());
            }
        }
    }
    catch (...) {
        // Ignore cleanup errors
    }
}