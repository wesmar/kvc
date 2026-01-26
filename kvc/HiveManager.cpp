// HiveManager.cpp
#include "HiveManager.h"
#include "common.h"
#include "TrustedInstallerIntegrator.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <shlobj.h>
#include <sddl.h>
#include <lmcons.h>

#pragma comment(lib, "advapi32.lib")

HiveManager::HiveManager()
    : m_tiToken(nullptr)
    , m_tiIntegrator(nullptr)
{
    m_currentUserSid = GetCurrentUserSid();
    m_currentUsername = GetCurrentUsername();
    InitializeHiveLists();
    ResetStats();
}

HiveManager::~HiveManager()
{
    if (m_tiToken) {
        RevertToSelf();
        m_tiToken = nullptr;
    }
    
    if (m_tiIntegrator) {
        delete m_tiIntegrator;
        m_tiIntegrator = nullptr;
    }
}

std::wstring HiveManager::GetCurrentUserSid()
{
    TokenGuard token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, token.addressof())) {
        return L"";
    }

    DWORD dwSize = 0;
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &dwSize);

    std::vector<BYTE> buffer(dwSize);
    TOKEN_USER* pTokenUser = reinterpret_cast<TOKEN_USER*>(buffer.data());

    std::wstring sidString;
    if (GetTokenInformation(token.get(), TokenUser, pTokenUser, dwSize, &dwSize)) {
        LPWSTR stringSid;
        if (ConvertSidToStringSidW(pTokenUser->User.Sid, &stringSid)) {
            sidString = stringSid;
            LocalFree(stringSid);
        }
    }

    return sidString;
}

std::wstring HiveManager::GetCurrentUsername()
{
    wchar_t username[UNLEN + 1];
    DWORD size = UNLEN + 1;
    
    if (GetUserNameW(username, &size)) {
        return std::wstring(username);
    }
    
    return L"";
}

// HiveManager.cpp - poprawiona funkcja GetHivePhysicalPath

fs::path HiveManager::GetHivePhysicalPath(const std::wstring& hiveName)
{
    wchar_t winDir[MAX_PATH];
    wchar_t sysDir[MAX_PATH];
    
    GetWindowsDirectoryW(winDir, MAX_PATH);
    GetSystemDirectoryW(sysDir, MAX_PATH);
    
    fs::path windowsPath(winDir);
    fs::path systemPath(sysDir);
    
    if (hiveName == L"DEFAULT") {
        return systemPath / L"config" / L"DEFAULT";
    }
    else if (hiveName == L"SAM") {
        return systemPath / L"config" / L"SAM";
    }
    else if (hiveName == L"SECURITY") {
        return systemPath / L"config" / L"SECURITY";
    }
    else if (hiveName == L"SOFTWARE") {
        return systemPath / L"config" / L"SOFTWARE";
    }
    else if (hiveName == L"SYSTEM") {
        return systemPath / L"config" / L"SYSTEM";
    }
    else if (hiveName == L"NTUSER" && !m_currentUsername.empty()) {
        // Get user profile directory dynamically
        wchar_t profileDir[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PROFILE, nullptr, 0, profileDir))) {
            return fs::path(profileDir) / L"NTUSER.DAT";
        }
    }
    else if (hiveName == L"UsrClass" && !m_currentUsername.empty()) {
        // Get user AppData\Local dynamically
        wchar_t localAppData[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localAppData))) {
            return fs::path(localAppData) / L"Microsoft" / L"Windows" / L"UsrClass.dat";
        }
    }
    
    return L"";
}

void HiveManager::InitializeHiveLists()
{
    // Build user-specific paths
    std::wstring userHivePath = L"HKU\\" + m_currentUserSid;
    std::wstring userClassPath = userHivePath + L"_Classes";
    
    // Critical registry hives (all operations require TrustedInstaller elevation)
    m_registryHives = {
        { L"BCD", L"HKLM\\BCD00000000", false },           // Bootloader, cannot restore
        { L"DEFAULT", L"HKU\\.DEFAULT", true },
        { L"NTUSER", userHivePath, true },                 // User hive with real SID
        { L"SAM", L"HKLM\\SAM", true },
        { L"SECURITY", L"HKLM\\SECURITY", true },
        { L"SOFTWARE", L"HKLM\\SOFTWARE", true },
        { L"SYSTEM", L"HKLM\\SYSTEM", true },
        { L"UsrClass", userClassPath, true }               // User classes with real SID
    };
}

void HiveManager::ResetStats()
{
    m_lastStats = BackupStats{};
}

fs::path HiveManager::GenerateDefaultBackupPath()
{
    wchar_t downloadsPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PROFILE, nullptr, 0, downloadsPath))) {
        fs::path basePath = fs::path(downloadsPath) / L"Downloads";
        std::wstring folderName = L"Registry_Backup_" + TimeUtils::GetFormattedTimestamp("datetime_file");
        return basePath / folderName;
    }
    
    // Fallback to temp if Downloads not found
    return fs::temp_directory_path() / (L"Registry_Backup_" + TimeUtils::GetFormattedTimestamp("datetime_file"));
}

bool HiveManager::ValidateBackupDirectory(const fs::path& path)
{
    std::error_code ec;
    
    // Normalize path
    fs::path normalizedPath = fs::absolute(path, ec);
    if (ec) {
        ERROR(L"Failed to normalize path: %s", path.c_str());
        return false;
    }
    
    // Create directory if it doesn't exist
    if (!fs::exists(normalizedPath, ec)) {
        if (!fs::create_directories(normalizedPath, ec)) {
            ERROR(L"Failed to create backup directory: %s", normalizedPath.c_str());
            return false;
        }
        INFO(L"Created backup directory: %s", normalizedPath.c_str());
    }
    
    // Verify it's a directory
    if (!fs::is_directory(normalizedPath, ec)) {
        ERROR(L"Path is not a directory: %s", normalizedPath.c_str());
        return false;
    }
    
    return true;
}

bool HiveManager::ValidateRestoreDirectory(const fs::path& path)
{
    std::error_code ec;
    
    fs::path normalizedPath = fs::absolute(path, ec);
    if (ec) {
        ERROR(L"Failed to normalize path: %s", path.c_str());
        return false;
    }
    
    if (!fs::exists(normalizedPath, ec) || !fs::is_directory(normalizedPath, ec)) {
        ERROR(L"Restore directory does not exist: %s", normalizedPath.c_str());
        return false;
    }
    
    return true;
}

bool HiveManager::ElevateToTrustedInstaller()
{
    if (m_tiToken) {
        return true; // Already elevated
    }
    
    if (!m_tiIntegrator) {
        m_tiIntegrator = new TrustedInstallerIntegrator();
    }
    
    INFO(L"Acquiring TrustedInstaller token...");
    m_tiToken = m_tiIntegrator->GetCachedTrustedInstallerToken();
    
    if (!m_tiToken) {
        ERROR(L"Failed to acquire TrustedInstaller token - ensure running as Administrator");
        return false;
    }
    
    // Impersonate using TrustedInstaller token
    if (!ImpersonateLoggedOnUser(m_tiToken)) {
        ERROR(L"Failed to impersonate TrustedInstaller: %d", GetLastError());
        m_tiToken = nullptr;
        return false;
    }
    
    SUCCESS(L"Elevated to TrustedInstaller");
    return true;
}

bool HiveManager::PromptYesNo(const wchar_t* question)
{
    std::wcout << L"\n" << question << L" ";
    std::wstring response;
    std::getline(std::wcin, response);
    
    if (response.empty()) {
        return false;
    }
    
    wchar_t first = towlower(response[0]);
    return (first == L'y' || first == L't'); // Y/y or T/t (Polish "tak")
}

bool HiveManager::SaveRegistryHive(const std::wstring& registryPath, const fs::path& destFile)
{
    // Parse registry path to get root key
    HKEY hRootKey = nullptr;
    std::wstring subKey;

    if (registryPath.starts_with(L"HKLM\\") || registryPath.starts_with(L"HKEY_LOCAL_MACHINE\\")) {
        hRootKey = HKEY_LOCAL_MACHINE;
        size_t pos = registryPath.find(L'\\');
        subKey = registryPath.substr(pos + 1);
    }
    else if (registryPath.starts_with(L"HKU\\") || registryPath.starts_with(L"HKEY_USERS\\")) {
        hRootKey = HKEY_USERS;
        size_t pos = registryPath.find(L'\\');
        subKey = registryPath.substr(pos + 1);
    }
    else if (registryPath.starts_with(L"HKCU") || registryPath.starts_with(L"HKEY_CURRENT_USER")) {
        hRootKey = HKEY_CURRENT_USER;
        size_t pos = registryPath.find(L'\\');
        if (pos != std::wstring::npos) {
            subKey = registryPath.substr(pos + 1);
        }
    }
    else {
        ERROR(L"Invalid registry path format: %s", registryPath.c_str());
        return false;
    }

    // Open registry key with backup privilege
    RegKeyGuard key;
    LONG result = RegOpenKeyExW(hRootKey, subKey.empty() ? nullptr : subKey.c_str(),
                                0, KEY_READ, key.addressof());

    if (result != ERROR_SUCCESS) {
        ERROR(L"Failed to open registry key %s: %d", registryPath.c_str(), result);
        return false;
    }

    // Save the hive using latest format (compresses and defragments)
    result = RegSaveKeyExW(key.get(), destFile.c_str(), nullptr, REG_LATEST_FORMAT);

    if (result != ERROR_SUCCESS) {
        ERROR(L"RegSaveKeyEx failed for %s: %d", registryPath.c_str(), result);
        return false;
    }

    return true;
}

bool HiveManager::BackupRegistryHives(const fs::path& targetDir)
{
    INFO(L"Backing up registry hives...");
    
    for (const auto& hive : m_registryHives) {
        m_lastStats.totalHives++;
        
        fs::path destFile = targetDir / hive.name;
        
        INFO(L"  Saving %s -> %s", hive.name.c_str(), destFile.filename().c_str());
        
        if (SaveRegistryHive(hive.registryPath, destFile)) {
            m_lastStats.successfulHives++;
            
            // Get file size
            std::error_code ec;
            auto size = fs::file_size(destFile, ec);
            if (!ec) {
                m_lastStats.totalBytes += size;
            }
            
            SUCCESS(L"  Saved %s (%llu bytes)", hive.name.c_str(), size);
        }
        else {
            m_lastStats.failedHives++;
            ERROR(L"  Failed to save %s", hive.name.c_str());
        }
    }
    
    return m_lastStats.successfulHives > 0;
}

void HiveManager::PrintStats(const std::wstring& operation)
{
    std::wcout << L"\n";
    INFO(L"=== %s Statistics ===", operation.c_str());
    INFO(L"Registry Hives: %zu/%zu successful", m_lastStats.successfulHives, m_lastStats.totalHives);
    INFO(L"Total Size: %.2f MB", static_cast<double>(m_lastStats.totalBytes) / (1024.0 * 1024.0));
    
    if (m_lastStats.failedHives > 0) {
        ERROR(L"Failed: %zu hives", m_lastStats.failedHives);
    }
}

bool HiveManager::Backup(const std::wstring& targetPath)
{
    ResetStats();
    
    // Determine target directory BEFORE elevation (to get real user profile)
    fs::path backupDir;
    if (targetPath.empty()) {
        backupDir = GenerateDefaultBackupPath();
        INFO(L"Using default backup path: %s", backupDir.c_str());
    }
    else {
        backupDir = targetPath;
    }
    
    // Validate and create directory (before elevation)
    if (!ValidateBackupDirectory(backupDir)) {
        return false;
    }
    
    // NOW elevate to TrustedInstaller for unrestricted registry access
    if (!ElevateToTrustedInstaller()) {
        return false;
    }
    
    INFO(L"Starting registry backup to: %s", backupDir.c_str());
    
    // Backup registry hives
    bool success = BackupRegistryHives(backupDir);
    
    // Print summary
    PrintStats(L"Backup");
    
    if (success) {
        SUCCESS(L"Backup completed: %s", backupDir.c_str());
        return true;
    }
    
    ERROR(L"Backup failed");
    return false;
}

bool HiveManager::RestoreRegistryHives(const fs::path& sourceDir)
{
    INFO(L"Validating backup files...");
    
    for (const auto& hive : m_registryHives) {
        fs::path sourceFile = sourceDir / hive.name;
        
        std::error_code ec;
        if (fs::exists(sourceFile, ec)) {
            INFO(L"  Found: %s", hive.name.c_str());
            m_lastStats.successfulHives++;
            
            auto size = fs::file_size(sourceFile, ec);
            if (!ec) {
                m_lastStats.totalBytes += size;
            }
        }
        else {
            ERROR(L"  Missing: %s", hive.name.c_str());
            m_lastStats.failedHives++;
        }
    }
    
    return m_lastStats.failedHives == 0;
}

bool HiveManager::ApplyRestoreAndReboot(const fs::path& sourceDir)
{
    // Enable restore privileges BEFORE attempting any restore operations
    {
        TokenGuard token;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, token.addressof())) {
            TOKEN_PRIVILEGES tp;
            LUID luid;

            // SE_RESTORE_NAME - critical for RegRestoreKeyW
            if (LookupPrivilegeValueW(nullptr, SE_RESTORE_NAME, &luid)) {
                tp.PrivilegeCount = 1;
                tp.Privileges[0].Luid = luid;
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                AdjustTokenPrivileges(token.get(), FALSE, &tp, 0, nullptr, nullptr);
            }

            // SE_BACKUP_NAME - for good measure
            if (LookupPrivilegeValueW(nullptr, SE_BACKUP_NAME, &luid)) {
                tp.PrivilegeCount = 1;
                tp.Privileges[0].Luid = luid;
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                AdjustTokenPrivileges(token.get(), FALSE, &tp, 0, nullptr, nullptr);
            }
        }
    }

    INFO(L"Applying registry restore using RegRestoreKeyW...");

    size_t restoredLive = 0;
    size_t restoredPending = 0;

    for (const auto& hive : m_registryHives) {
        // Skip non-restorable hives
        if (!hive.canRestore) {
            INFO(L"  Skipping %s (cannot restore)", hive.name.c_str());
            continue;
        }

        fs::path sourceFile = sourceDir / hive.name;

        std::error_code ec;
        if (!fs::exists(sourceFile, ec)) {
            ERROR(L"  Missing backup file: %s", hive.name.c_str());
            continue;
        }

        // Parse registry path to get root key and subkey
        HKEY hRootKey = nullptr;
        std::wstring subKey;

        if (hive.registryPath.starts_with(L"HKLM\\")) {
            hRootKey = HKEY_LOCAL_MACHINE;
            size_t pos = hive.registryPath.find(L'\\');
            subKey = hive.registryPath.substr(pos + 1);
        }
        else if (hive.registryPath.starts_with(L"HKU\\")) {
            hRootKey = HKEY_USERS;
            size_t pos = hive.registryPath.find(L'\\');
            subKey = hive.registryPath.substr(pos + 1);
        }
        else {
            ERROR(L"  Invalid path format for %s", hive.name.c_str());
            continue;
        }

        // Open the target key
        RegKeyGuard key;
        LONG result = RegOpenKeyExW(hRootKey, subKey.c_str(), 0, KEY_WRITE, key.addressof());

        if (result != ERROR_SUCCESS) {
            ERROR(L"  Failed to open key %s: %d", hive.name.c_str(), result);
            continue;
        }

        INFO(L"  Restoring %s...", hive.name.c_str());

        // Try live restore using REG_FORCE_RESTORE
        result = RegRestoreKeyW(key.get(), sourceFile.c_str(), REG_FORCE_RESTORE);

        // Close key before checking result
        key.reset();

        if (result == ERROR_SUCCESS) {
            SUCCESS(L"  Restored %s (live)", hive.name.c_str());
            restoredLive++;
        }
        else if (result == ERROR_ACCESS_DENIED) {
            // Live restore failed - schedule for next boot
            INFO(L"  Live restore failed (error 5) - scheduling for next boot...");

            fs::path physicalPath = GetHivePhysicalPath(hive.name);
            if (physicalPath.empty()) {
                ERROR(L"  Cannot determine physical path for %s", hive.name.c_str());
                continue;
            }

            // Schedule file replacement on next boot
            if (MoveFileExW(sourceFile.c_str(), physicalPath.c_str(),
                            MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_REPLACE_EXISTING)) {
                SUCCESS(L"  Scheduled %s for next boot", hive.name.c_str());
                restoredPending++;
            }
            else {
                ERROR(L"  Failed to schedule %s: %d", hive.name.c_str(), GetLastError());
            }
        }
        else {
            ERROR(L"  Failed to restore %s: %d", hive.name.c_str(), result);
        }
    }

    if (restoredLive == 0 && restoredPending == 0) {
        ERROR(L"No hives were restored successfully");
        return false;
    }

    SUCCESS(L"Successfully restored %zu hives (live: %zu, pending: %zu)",
            restoredLive + restoredPending, restoredLive, restoredPending);

    if (restoredPending > 0) {
        INFO(L"Note: %zu hives scheduled for next boot (will replace on-disk files)", restoredPending);
    }

    INFO(L"System restart required for changes to take effect");
    INFO(L"Initiating system reboot in 10 seconds...");

    // Enable shutdown privilege
    {
        TokenGuard token;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, token.addressof())) {
            TOKEN_PRIVILEGES tp;
            LUID luid;

            if (LookupPrivilegeValueW(nullptr, SE_SHUTDOWN_NAME, &luid)) {
                tp.PrivilegeCount = 1;
                tp.Privileges[0].Luid = luid;
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                AdjustTokenPrivileges(token.get(), FALSE, &tp, 0, nullptr, nullptr);
            }
        }
    }
    
    // Initiate system shutdown
    if (!InitiateSystemShutdownExW(
        nullptr,
        const_cast<LPWSTR>(L"Registry restore complete - system restart required"),
        10,
        TRUE,  // Force apps closed
        TRUE,  // Reboot after shutdown
        SHTDN_REASON_MAJOR_OPERATINGSYSTEM | SHTDN_REASON_MINOR_RECONFIG | SHTDN_REASON_FLAG_PLANNED
    )) {
        ERROR(L"Failed to initiate shutdown: %d", GetLastError());
        INFO(L"Please restart the system manually");
        return false;
    }
    
    SUCCESS(L"System reboot initiated");
    return true;
}

bool HiveManager::Restore(const std::wstring& sourcePath)
{
    ResetStats();
    
    fs::path restoreDir = sourcePath;
    
    // Validate source directory BEFORE elevation
    if (!ValidateRestoreDirectory(restoreDir)) {
        return false;
    }
    
    // NOW elevate to TrustedInstaller
    if (!ElevateToTrustedInstaller()) {
        return false;
    }
    
    INFO(L"Starting registry restore from: %s", restoreDir.c_str());
    
    // Validate backup files
    bool validated = RestoreRegistryHives(restoreDir);
    
    // Print summary
    PrintStats(L"Restore Validation");
    
    if (!validated) {
        ERROR(L"Restore validation failed - missing backup files");
        return false;
    }
    
    INFO(L"All backup files validated successfully");
    INFO(L"WARNING: Registry restore will modify system hives and requires restart");
    
    // Prompt user
    if (PromptYesNo(L"Apply restore and reboot now? (Y/N):")) {
        return ApplyRestoreAndReboot(restoreDir);
    }
    
    INFO(L"Restore cancelled by user");
    return false;
}

bool HiveManager::Defrag(const std::wstring& tempPath)
{
    INFO(L"Starting registry defragmentation (backup with compression)");
    
    // Generate temp backup path BEFORE any elevation (to get real user temp)
    fs::path defragPath;
    if (tempPath.empty()) {
        defragPath = fs::temp_directory_path() / (L"Registry_Defrag_" + TimeUtils::GetFormattedTimestamp("datetime_file"));
    }
    else {
        defragPath = tempPath;
    }
    
    INFO(L"Using temporary path: %s", defragPath.c_str());
    
    // Backup automatically elevates to TrustedInstaller and uses REG_LATEST_FORMAT
    // which provides compression and defragmentation
    if (!Backup(defragPath.wstring())) {
        ERROR(L"Defrag failed at backup stage");
        return false;
    }
    
    INFO(L"Defragmented backup created successfully");
    INFO(L"Backup location: %s", defragPath.c_str());
    INFO(L"To complete defragmentation, defragmented hives must be restored");
    INFO(L"WARNING: This will modify system hives and requires restart");
    
    // Prompt user
    if (PromptYesNo(L"Apply defragmented hives and reboot now? (Y/N):")) {
        return ApplyRestoreAndReboot(defragPath);
    }
    
    SUCCESS(L"Defragmentation backup completed");
    INFO(L"You can manually restore from: %s", defragPath.c_str());
    return true;
}