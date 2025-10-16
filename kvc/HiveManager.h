// HiveManager.h
// Registry hive backup, restore and defragmentation manager (TrustedInstaller, destructive ops)

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <filesystem>

namespace fs = std::filesystem;

// Forward declaration of TrustedInstallerIntegrator class
class TrustedInstallerIntegrator;
// Manage registry hives: backup, restore and defragment (supports system and user hives; TI required)
class HiveManager
{
public:
    // Acquire TrustedInstaller, gather user info and initialize internal state
    HiveManager();
    
    // Release TrustedInstaller token and clean up on destruction
    ~HiveManager();

    // === Main Operations ===
    
    // Backup all supported registry hives to target directory (TrustedInstaller required)
    bool Backup(const std::wstring& targetPath = L"");
    
    // Restore registry hives from backup directory and schedule reboot (validates files, destructive)
    bool Restore(const std::wstring& sourcePath);
    
    // Defragment registry hives via export/import cycle to reduce fragmentation
    bool Defrag(const std::wstring& tempPath = L"");

    // Operation statistics for backup/restore runs
    struct BackupStats {
        size_t totalHives = 0;      // Hives processed
        size_t successfulHives = 0; // Successful operations
        size_t failedHives = 0;     // Failed operations
        uint64_t totalBytes = 0;    // Total bytes processed
    };

    // Return stats from last operation (reset at start of each op)
    const BackupStats& GetLastStats() const { return m_lastStats; }

private:
    // Registry hive metadata for processing
    struct RegistryHive {
        std::wstring name;          // Hive name (e.g., "SYSTEM")
        std::wstring registryPath;  // Registry path (e.g., "HKLM\\SYSTEM")
        bool canRestore;            // Restorable with RegRestoreKeyW
    };

    // === Internal Operations ===
    
    // Save all configured registry hives to target directory (calls SaveRegistryHive)
    bool BackupRegistryHives(const fs::path& targetDir);
    
    // Validate and prepare restore from backup directory (calls ApplyRestoreAndReboot)
    bool RestoreRegistryHives(const fs::path& sourceDir);
    
    // Apply restore and initiate system reboot (uses InitiateSystemShutdownExW)
    bool ApplyRestoreAndReboot(const fs::path& sourceDir);
    
    // Save a single registry hive to disk using RegSaveKeyW (requires SE_BACKUP_NAME)
    bool SaveRegistryHive(const std::wstring& registryPath, const fs::path& destFile);
    
    // Elevate process to TrustedInstaller and enable required privileges
    bool ElevateToTrustedInstaller();
    
    // Ask user Yes/No confirmation for destructive operations
    bool PromptYesNo(const wchar_t* question);
    
    // Generate default backup path using username and timestamp
    fs::path GenerateDefaultBackupPath();
    
    // Retrieve current user SID string (cached)
    std::wstring GetCurrentUserSid();
    
    // Retrieve current username (cached)
    std::wstring GetCurrentUsername();
    
    // Resolve hive name to physical file path on disk (handles user/system special cases)
    fs::path GetHivePhysicalPath(const std::wstring& hiveName);
    
    // Validate backup directory exists, is writable and has sufficient space
    bool ValidateBackupDirectory(const fs::path& path);
    
    // Validate restore directory contains expected .hiv files and readable sizes
    bool ValidateRestoreDirectory(const fs::path& path);
    
    // Populate m_registryHives with supported hives and metadata (called in ctor)
    void InitializeHiveLists();
    
    // Reset statistics counters to zero at operation start
    void ResetStats();
    
    // Print operation statistics to console in formatted form
    void PrintStats(const std::wstring& operation);

    // === Data Members ===
    
    std::vector<RegistryHive> m_registryHives;      // Hives to process
    BackupStats m_lastStats;                        // Last operation stats
    
    HANDLE m_tiToken;                               // TrustedInstaller token handle
    TrustedInstallerIntegrator* m_tiIntegrator;     // TrustedInstaller integration helper
    std::wstring m_currentUserSid;                  // Cached current user SID
    std::wstring m_currentUsername;                 // Cached current username
};
