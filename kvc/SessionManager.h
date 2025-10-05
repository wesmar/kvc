/**
 * @file SessionManager.h
 * @brief Process protection state management across boot sessions
 * @author Marek Wesolowski
 * @date 2025
 * @copyright KVC Framework
 * 
 * Tracks protection state changes and enables restoration after system reboots,
 * maintaining up to 16 boot sessions with automatic cleanup.
 * Uses registry-based persistence for cross-boot state tracking.
 */

#pragma once

#include "common.h"
#include <string>
#include <vector>
#include <optional>

// Forward declarations
struct ProcessEntry;
class Controller;

/**
 * @struct SessionEntry
 * @brief Single process protection state entry for restoration
 * 
 * Stores complete protection state of a process at the time of unprotect
 * operation, enabling precise restoration after system reboot.
 */
struct SessionEntry
{
    DWORD Pid;                          ///< Process ID at time of unprotect operation
    std::wstring ProcessName;           ///< Process executable name for identification
    UCHAR OriginalProtection;           ///< Combined protection level + signer before unprotect
    UCHAR SignatureLevel;               ///< Executable signature level before unprotect
    UCHAR SectionSignatureLevel;        ///< DLL section signature level before unprotect
    std::wstring Status;                ///< Current status: "UNPROTECTED" or "RESTORED"
};

/**
 * @class SessionManager
 * @brief Manages process protection state across boot sessions
 * 
 * Features:
 * - Automatic boot session detection via boot ID + tick count
 * - Registry-based state persistence in HKLM
 * - Maximum 16 session history with automatic cleanup
 * - Restoration by signer type or all processes
 * - Stale session cleanup on reboot detection
 * - Status tracking (UNPROTECTED/RESTORED)
 * 
 * Registry Structure:
 * HKLM\SOFTWARE\KVC\Sessions\{BootID}_{TickCount}\{SignerName}\{Index}
 * 
 * @note Uses boot ID from registry and tick count for unique session identification
 * @warning Requires administrative privileges for HKLM registry access
 */
class SessionManager
{
public:
    /**
     * @brief Construct session manager
     * 
     * Initializes internal state but does not automatically detect reboot.
     * Call DetectAndHandleReboot() manually for reboot detection.
     */
    SessionManager() = default;
    
    /**
     * @brief Destructor
     * 
     * No special cleanup needed - registry operations are atomic.
     */
    ~SessionManager() = default;

    // === Session Lifecycle Management ===
    
    /**
     * @brief Remove sessions that no longer exist (old boot IDs)
     * 
     * Scans registry for session entries and removes those from previous
     * boot sessions. Called automatically on initialization.
     * 
     * @note Called automatically by DetectAndHandleReboot()
     */
    void CleanupStaleSessions() noexcept;
    
    /**
     * @brief Delete all sessions except current boot session
     * 
     * Manual cleanup method for removing historical session data.
     * Useful when session limit is reached or for privacy reasons.
     * 
     * @note Used for manual cleanup via 'cleanup-sessions' command
     */
    void CleanupAllSessionsExceptCurrent() noexcept;
    
    /**
     * @brief Detect system reboot and cleanup old sessions
     * 
     * Compares current boot ID with registry-stored value to detect
     * system reboot. Automatically cleans up stale sessions on reboot.
     * 
     * @note Should be called at application startup
     */
    void DetectAndHandleReboot() noexcept;
    
    /**
     * @brief Enforce maximum session limit (default: 16)
     * @param maxSessions Maximum number of sessions to keep
     * 
     * Deletes oldest sessions when limit exceeded. Sessions are sorted
     * by creation time (boot ID + tick count).
     * 
     * @note Called automatically when saving new sessions
     */
    void EnforceSessionLimit(int maxSessions) noexcept;

    // === State Tracking Operations ===
    
    /**
     * @brief Save unprotect operation for future restoration
     * @param signerName Signer type name (e.g., "Antimalware", "WinTcb")
     * @param affectedProcesses Vector of processes that were unprotected
     * @return true if state saved to registry successfully
     * 
     * Creates new session entry with current boot ID and saves complete
     * protection state of all affected processes for later restoration.
     * 
     * @note Each signer type gets separate registry key for organization
     */
    bool SaveUnprotectOperation(const std::wstring& signerName, 
                               const std::vector<ProcessEntry>& affectedProcesses) noexcept;

    // === Restoration Operations ===
    
    /**
     * @brief Restore protection for specific signer group
     * @param signerName Signer type to restore (e.g., "Antimalware")
     * @param controller Controller instance for protection operations
     * @return true if restoration successful for all processes
     * 
     * Loads session entries for specified signer and restores original
     * protection levels. Only processes with "UNPROTECTED" status are
     * processed. Updates status to "RESTORED" after successful restoration.
     * 
     * @note Uses Controller for actual protection manipulation
     */
    bool RestoreBySigner(const std::wstring& signerName, Controller* controller) noexcept;
    
    /**
     * @brief Restore all saved protection states
     * @param controller Controller instance for protection operations
     * @return true if all restorations successful
     * 
     * Iterates through all signers in current session and restores
     * protection for all "UNPROTECTED" processes.
     * 
     * @note Comprehensive restoration across all signer types
     */
    bool RestoreAll(Controller* controller) noexcept;

    // === Query Operations ===
    
    /**
     * @brief Display session history with statistics
     * 
     * Shows all stored sessions with process counts, timestamps, and
     * restoration status. Highlights current boot session.
     * 
     * @note Useful for debugging and session management
     */
    void ShowHistory() noexcept;

private:
    /**
     * @brief Get current boot session identifier
     * @return Session ID string: "{BootID}_{TickCount}"
     * 
     * Combines boot ID from registry with current tick count for
     * unique session identification across reboots.
     * 
     * @note Cached for performance during same execution
     */
    std::wstring GetCurrentBootSession() noexcept;
    
    /**
     * @brief Calculate boot time from tick count
     * @return Formatted boot time string
     * 
     * Converts system tick count to human-readable boot time
     * for display in session history.
     */
    std::wstring CalculateBootTime() noexcept;
    
    /**
     * @brief Get last boot ID from registry
     * @return Boot ID from last session, or 0 if not found
     * 
     * Reads stored boot ID from registry to detect system reboots.
     */
    ULONGLONG GetLastBootIdFromRegistry() noexcept;
    
    /**
     * @brief Save current boot ID to registry
     * @param bootId Boot ID to save
     * 
     * Stores current boot ID in registry for reboot detection
     * in subsequent executions.
     */
    void SaveLastBootId(ULONGLONG bootId) noexcept;
    
    /**
     * @brief Get last tick count from registry
     * @return Tick count from last session
     * 
     * Reads stored tick count for session continuity tracking.
     */
	ULONGLONG GetLastTickCountFromRegistry() noexcept;
	
    /**
     * @brief Save current tick count to registry
     * @param tickCount Tick count to save
     * 
     * Stores current tick count for precise session identification.
     */
	void SaveLastTickCount(ULONGLONG tickCount) noexcept;
    
    /**
     * @brief Get base registry path for sessions
     * @return "SOFTWARE\\KVC\\Sessions"
     * 
     * Base registry path where all session data is stored.
     */
    std::wstring GetRegistryBasePath() noexcept;
    
    /**
     * @brief Get registry path for specific session
     * @param sessionId Session identifier
     * @return Full registry path to session
     * 
     * Constructs complete registry path for a specific session.
     */
    std::wstring GetSessionPath(const std::wstring& sessionId) noexcept;
    
    /**
     * @brief Load session entries for specific signer
     * @param signerName Signer type name
     * @return Vector of session entries
     * 
     * Reads all session entries for a specific signer from registry.
     */
    std::vector<SessionEntry> LoadSessionEntries(const std::wstring& signerName) noexcept;
    
    /**
     * @brief Load session entries from specific registry path
     * @param sessionPath Registry path to session
     * @param signerName Signer type name
     * @return Vector of session entries
     * 
     * Internal method for reading session entries from arbitrary paths.
     */
    std::vector<SessionEntry> LoadSessionEntriesFromPath(const std::wstring& sessionPath, 
                                                         const std::wstring& signerName) noexcept;
    
    /**
     * @brief Write session entry to registry
     * @param signerName Signer type name
     * @param index Entry index within signer group
     * @param entry Session entry data to write
     * @return true if write successful
     * 
     * Stores individual session entry in registry with proper value types.
     */
    bool WriteSessionEntry(const std::wstring& signerName, DWORD index, const SessionEntry& entry) noexcept;
    
    /**
     * @brief Update entry status in registry
     * @param signerName Signer type name
     * @param index Entry index to update
     * @param newStatus New status string ("UNPROTECTED" or "RESTORED")
     * @return true if update successful
     * 
     * Updates status field of existing session entry after restoration.
     */
    bool UpdateEntryStatus(const std::wstring& signerName, DWORD index, const std::wstring& newStatus) noexcept;
    
    /**
     * @brief Get all session IDs from registry
     * @return Vector of session ID strings
     * 
     * Enumerates all existing session IDs in registry for cleanup operations.
     */
    std::vector<std::wstring> GetAllSessionIds() noexcept;
    
    /**
     * @brief Open or create registry key
     * @param path Registry path
     * @return Registry key handle or nullptr on failure
     * 
     * Helper method for registry operations that creates keys if missing.
     */
    HKEY OpenOrCreateKey(const std::wstring& path) noexcept;
    
    /**
     * @brief Recursively delete registry key and all subkeys
     * @param hKeyParent Parent key handle
     * @param subKey Subkey name to delete
     * @return true if deletion successful
     * 
     * Comprehensive registry key deletion for session cleanup.
     */
    bool DeleteKeyRecursive(HKEY hKeyParent, const std::wstring& subKey) noexcept;
};