/**
 * @file HiveManager.h
 * @brief Registry hive backup, restore and defragmentation manager
 * @author Marek Wesolowski
 * @date 2025
 * @copyright KVC Framework
 * 
 * Provides atomic registry operations with TrustedInstaller privileges,
 * supporting full system registry backup and point-in-time restoration.
 * Handles locked system hives and provides defragmentation capabilities.
 */

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <filesystem>

namespace fs = std::filesystem;

// Forward declaration
class TrustedInstallerIntegrator;

/**
 * @class HiveManager
 * @brief Registry hive backup, restore and defragmentation manager
 * 
 * Features:
 * - Full registry backup with TrustedInstaller access
 * - Atomic hive restoration with automatic reboot
 * - Registry defragmentation via export/import cycle
 * - Handles locked system hives (SAM, SECURITY, SYSTEM)
 * - Automatic temp file cleanup
 * - Statistics tracking for operations
 * 
 * Supported Hives:
 * - SYSTEM, SOFTWARE, SAM, SECURITY
 * - DEFAULT, NTUSER.DAT, UsrClass.dat
 * - User-specific hives with SID resolution
 * 
 * @note Requires TrustedInstaller privileges for full functionality
 * @warning Registry operations can affect system stability
 */
class HiveManager
{
public:
    /**
     * @brief Construct hive manager and initialize TrustedInstaller
     * 
     * Initializes internal state, acquires TrustedInstaller token,
     * and gathers current user information (SID, username).
     * 
     * @note Automatically gets current user SID and username
     */
    HiveManager();
    
    /**
     * @brief Destructor with token cleanup
     * 
     * Releases TrustedInstaller token and reverts any active
     * impersonation. Ensures clean state on destruction.
     */
    ~HiveManager();

    // === Main Operations ===
    
    /**
     * @brief Backup all registry hives to directory
     * @param targetPath Backup directory (empty = auto-generate)
     * @return true if backup successful
     * 
     * Performs complete registry backup including:
     * - System hives (SYSTEM, SOFTWARE, SAM, SECURITY)
     * - User hives (DEFAULT, NTUSER.DAT, UsrClass.dat)
     * - Registry statistics collection
     * - Automatic directory creation
     * 
     * Auto-generates path format: C:\RegistryBackup_{User}_{Timestamp}
     * 
     * @note Requires TrustedInstaller privileges
     * @note Uses RegSaveKeyW for atomic hive saving
     */
    bool Backup(const std::wstring& targetPath = L"");
    
    /**
     * @brief Restore registry hives from backup directory
     * @param sourcePath Backup directory path
     * @return true if restoration successful
     * 
     * Validates and restores registry hives from backup:
     * - Verifies backup file integrity
     * - Prompts for user confirmation
     * - Initiates system reboot for changes
     * - Uses RegRestoreKeyW for atomic restoration
     * 
     * @note Validates backup files before restoration
     * @note Prompts for confirmation before reboot
     * @note System restart required for changes to take effect
     */
    bool Restore(const std::wstring& sourcePath);
    
    /**
     * @brief Defragment registry hives
     * @param tempPath Temporary directory (empty = auto-generate)
     * @return true if defragmentation successful
     * 
     * Performs registry defragmentation by:
     * - Exporting hives to temporary files
     * - Re-importing hives to compact storage
     * - Reducing registry file fragmentation
     * - Improving registry performance
     * 
     * @note Exports hives to temp, then re-imports
     * @note Reduces registry file size and improves performance
     */
    bool Defrag(const std::wstring& tempPath = L"");

    /**
     * @struct BackupStats
     * @brief Statistics for backup/restore operations
     * 
     * Tracks operation metrics for reporting and validation.
     */
    struct BackupStats {
        size_t totalHives = 0;      ///< Number of hives processed
        size_t successfulHives = 0; ///< Successfully backed up/restored hives
        size_t failedHives = 0;     ///< Failed hive operations
        uint64_t totalBytes = 0;    ///< Total bytes processed across all hives
    };

    /**
     * @brief Get statistics from last operation
     * @return const BackupStats& Reference to backup statistics
     * 
     * Provides access to operation statistics for display
     * and logging purposes.
     * 
     * @note Statistics are reset at the start of each operation
     */
    const BackupStats& GetLastStats() const { return m_lastStats; }

private:
    /**
     * @struct RegistryHive
     * @brief Registry hive definition and metadata
     * 
     * Contains hive identification and operational information
     * for registry hive processing.
     */
    struct RegistryHive {
        std::wstring name;          ///< Hive name (e.g., "SYSTEM")
        std::wstring registryPath;  ///< Registry path (e.g., "HKLM\\SYSTEM")
        bool canRestore;            ///< Can be restored with RegRestoreKeyW
    };

    // === Internal Operations ===
    
    /**
     * @brief Backup all registry hives to target directory
     * @param targetDir Destination directory for backup files
     * @return true if all hives backed up successfully
     * 
     * Iterates through all defined registry hives and saves
     * each to individual .hiv files in target directory.
     * 
     * @note Uses SaveRegistryHive for individual hive operations
     */
    bool BackupRegistryHives(const fs::path& targetDir);
    
    /**
     * @brief Restore registry hives from backup directory
     * @param sourceDir Source directory with backup files
     * @return true if restoration validation successful
     * 
     * Validates backup files and prepares for restoration.
     * Calls ApplyRestoreAndReboot for actual restoration.
     * 
     * @note Validation step before destructive operation
     */
    bool RestoreRegistryHives(const fs::path& sourceDir);
    
    /**
     * @brief Apply restore and initiate system reboot
     * @param sourceDir Source directory with backup files
     * @return true if restore applied and reboot initiated
     * 
     * Performs actual registry restoration and initiates
     * system reboot for changes to take effect.
     * 
     * @note Uses InitiateSystemShutdownExW with 10 second delay
     * @note Destructive operation - cannot be undone
     */
    bool ApplyRestoreAndReboot(const fs::path& sourceDir);
    
    /**
     * @brief Save registry hive to file using RegSaveKeyW
     * @param registryPath Registry path (e.g., "HKLM\\SYSTEM")
     * @param destFile Destination file path
     * @return true if hive saved successfully
     * 
     * Uses Windows API RegSaveKeyW to save registry hive
     * to disk file. Handles privilege requirements and
     * error conditions.
     * 
     * @note Requires SE_BACKUP_NAME privilege
     * @note Atomic operation - all or nothing
     */
    bool SaveRegistryHive(const std::wstring& registryPath, const fs::path& destFile);
    
    /**
     * @brief Elevate to TrustedInstaller privileges
     * @return true if elevation successful
     * 
     * Acquires TrustedInstaller token and enables required
     * privileges for registry operations.
     * 
     * Required privileges:
     * - SE_BACKUP_NAME: For registry backup
     * - SE_RESTORE_NAME: For registry restoration
     * - SE_LOAD_DRIVER_NAME: For hive loading
     * 
     * @note Essential for system hive access
     */
    bool ElevateToTrustedInstaller();
    
    /**
     * @brief Prompt user for Yes/No confirmation
     * @param question Question to display to user
     * @return true if user answered Yes
     * 
     * Displays confirmation prompt and waits for user input.
     * Used for dangerous operations like registry restoration.
     * 
     * @note Safety measure for destructive operations
     */
    bool PromptYesNo(const wchar_t* question);
    
    /**
     * @brief Generate default backup path with timestamp
     * @return fs::path Generated backup directory path
     * 
     * Creates backup directory path in format:
     * C:\RegistryBackup_{Username}_{YYYY.MM.DD_HH.MM.SS}
     * 
     * @note Uses current user and system time for uniqueness
     */
    fs::path GenerateDefaultBackupPath();
    
    /**
     * @brief Get current user SID string
     * @return std::wstring User SID string (e.g., "S-1-5-21-...")
     * 
     * Retrieves current user's Security Identifier as string.
     * Used for user-specific hive operations and path generation.
     * 
     * @note Cached for performance during same session
     */
    std::wstring GetCurrentUserSid();
    
    /**
     * @brief Get current username
     * @return std::wstring Current username
     * 
     * Retrieves current user's account name for path generation
     * and display purposes.
     * 
     * @note Cached for performance during same session
     */
    std::wstring GetCurrentUsername();
    
    /**
     * @brief Get physical file path for registry hive
     * @param hiveName Hive name (e.g., "SYSTEM")
     * @return fs::path Physical file path on disk
     * 
     * Resolves registry hive name to physical file path
     * in Windows system directories.
     * 
     * Handles special cases:
     * - NTUSER.DAT in user profile directories
     * - UsrClass.dat in user appdata directories
     * - System hives in System32\config
     * 
     * @note Essential for hive file operations
     */
    fs::path GetHivePhysicalPath(const std::wstring& hiveName);
    
    /**
     * @brief Validate backup directory exists and is writable
     * @param path Directory path to validate
     * @return bool true if directory valid
     * 
     * Per comprehensive directory validation:
     * - Existence check
     * - Directory type verification
     * - Write access testing
     * - Sufficient space check
     * 
     * @note Critical for successful backup operations
     */
    bool ValidateBackupDirectory(const fs::path& path);
    
    /**
     * @brief Validate restore directory contains required files
     * @param path Directory path to validate
     * @return bool true if all required hive files exist
     * 
     * Verifies that restore directory contains:
     * - All expected .hiv files
     * - Valid file sizes
     * - Read access to files
     * - Matching hive set
     * 
     * @note Safety check before destructive restoration
     */
    bool ValidateRestoreDirectory(const fs::path& path);
    
    /**
     * @brief Initialize registry hive list with paths
     * 
     * Populates m_registryHives with all supported registry hives
     * and their operational metadata.
     * 
     * @note Called during construction
     */
    void InitializeHiveLists();
    
    /**
     * @brief Reset statistics counters
     * 
     * Resets operation statistics to zero values.
     * Called at the start of each new operation.
     */
    void ResetStats();
    
    /**
     * @brief Print operation statistics
     * @param operation Operation name for display
     * 
     * Displays operation statistics to console with
     * formatted output showing success/failure counts
     * and total bytes processed.
     */
    void PrintStats(const std::wstring& operation);

    // === Data Members ===
    
    std::vector<RegistryHive> m_registryHives;      ///< List of registry hives to process
    BackupStats m_lastStats;                        ///< Statistics from last operation
    
    HANDLE m_tiToken;                               ///< TrustedInstaller token handle
    TrustedInstallerIntegrator* m_tiIntegrator;     ///< TrustedInstaller integration component
    std::wstring m_currentUserSid;                  ///< Cached current user SID
    std::wstring m_currentUsername;                 ///< Cached current username
};