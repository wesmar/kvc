// HiveManager.h
#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <filesystem>

namespace fs = std::filesystem;

// Forward declaration
class TrustedInstallerIntegrator;

// Registry hive backup, restore and defragmentation manager
class HiveManager
{
public:
    HiveManager();
    ~HiveManager();

    // Main operations
    bool Backup(const std::wstring& targetPath = L"");
    bool Restore(const std::wstring& sourcePath);
    bool Defrag(const std::wstring& tempPath = L"");

    // Statistics
    struct BackupStats {
        size_t totalHives = 0;
        size_t successfulHives = 0;
        size_t failedHives = 0;
        uint64_t totalBytes = 0;
    };

    const BackupStats& GetLastStats() const { return m_lastStats; }

private:
    // Hive definitions
    struct RegistryHive {
        std::wstring name;
        std::wstring registryPath;
        bool canRestore;  // Can be restored with RegRestoreKeyW
    };

    // Internal operations
    bool BackupRegistryHives(const fs::path& targetDir);
    bool RestoreRegistryHives(const fs::path& sourceDir);
    bool ApplyRestoreAndReboot(const fs::path& sourceDir);
    
    bool SaveRegistryHive(const std::wstring& registryPath, const fs::path& destFile);
    bool ElevateToTrustedInstaller();
    bool PromptYesNo(const wchar_t* question);
    
    fs::path GenerateDefaultBackupPath();
    std::wstring GetCurrentUserSid();
    std::wstring GetCurrentUsername();
    fs::path GetHivePhysicalPath(const std::wstring& hiveName);
    bool ValidateBackupDirectory(const fs::path& path);
    bool ValidateRestoreDirectory(const fs::path& path);
    
    void InitializeHiveLists();
    void ResetStats();
    void PrintStats(const std::wstring& operation);

    // Data members
    std::vector<RegistryHive> m_registryHives;
    BackupStats m_lastStats;
    
    HANDLE m_tiToken;
    TrustedInstallerIntegrator* m_tiIntegrator;
    std::wstring m_currentUserSid;
    std::wstring m_currentUsername;
};