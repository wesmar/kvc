// SessionManager.h - Manages process protection state and DSE-NG symbol cache with LCUVer tracking
#pragma once

#include "common.h"
#include <string>
#include <vector>
#include <optional>
#include <tuple>

// Forward declarations
struct ProcessEntry;
class Controller;

// Single process protection state entry for restoration
struct SessionEntry
{
    DWORD Pid;                          // Process ID at unprotect time
    std::wstring ProcessName;           // Executable name
    UCHAR OriginalProtection;           // Original protection level
    UCHAR SignatureLevel;               // Executable signature level
    UCHAR SectionSignatureLevel;        // DLL section signature level
    std::wstring Status;                // "UNPROTECTED" or "RESTORED"
};

// Manages protection state tracking, restoration, and DSE-NG symbol cache
class SessionManager
{
public:
    // Construct session manager (no automatic reboot detection)
    SessionManager() = default;
    
    // Default destructor (no cleanup needed)
    ~SessionManager() = default;

    // === Session Lifecycle Management ===
    
    // Remove outdated session entries from registry
    void CleanupStaleSessions() noexcept;
    
    // Delete all sessions except current boot session
    void CleanupAllSessionsExceptCurrent() noexcept;
    
    // Detect reboot by comparing boot ID and cleanup old sessions
    void DetectAndHandleReboot() noexcept;
    
    // Enforce maximum number of stored sessions (default 16)
    void EnforceSessionLimit(int maxSessions) noexcept;

    // === State Tracking Operations ===
    
    // Save unprotect state for given signer group to registry
    bool SaveUnprotectOperation(const std::wstring& signerName, 
                               const std::vector<ProcessEntry>& affectedProcesses) noexcept;

    // === Restoration Operations ===
    
    // Restore protection for all entries under specified signer
    bool RestoreBySigner(const std::wstring& signerName, Controller* controller) noexcept;
    
    // Restore all saved protections across all signer groups
    bool RestoreAll(Controller* controller) noexcept;

    // === Query Operations ===
    
    // Display session history and statistics
    void ShowHistory() noexcept;
    
    // === DSE-NG Symbol Cache Management (with LCUVer tracking) ===
    
    // Save/load original CiCallback for DSE-NG restoration
    static void SaveOriginalCiCallback(DWORD64 address) noexcept;
    static DWORD64 GetOriginalCiCallback() noexcept;
    static void ClearOriginalCiCallback() noexcept;
    
    // Save symbol offsets with LCUVersion marker
    static void SaveDSENGOffsets(DWORD64 offSeCi, DWORD64 offZwFlush, 
                                 DWORD64 kernelBase, const std::wstring& lcuVer) noexcept;
    
    // Get cached offsets if LCUVersion matches current system
    static std::optional<std::tuple<DWORD64, DWORD64, DWORD64>> 
        GetDSENGOffsets(const std::wstring& currentLCUVer) noexcept;
    
    // Clear all DSE-NG symbol cache (offsets and LCUVersion)
    static void ClearDSENGOffsets() noexcept;
    
    // Utility: Get current LCUVersion from system registry
    static std::wstring GetCurrentLCUVersion() noexcept;
    
    // Check if cached LCUVersion differs from current
    static bool HasLCUVersionChanged(const std::wstring& currentLCUVer) noexcept;

private:
    // Get current boot session ID: "{BootID}_{TickCount}"
    std::wstring GetCurrentBootSession() noexcept;
    
    // Convert tick count to human-readable boot time
    std::wstring CalculateBootTime() noexcept;
    
    // Read last boot ID from registry
    ULONGLONG GetLastBootIdFromRegistry() noexcept;
    
    // Save current boot ID to registry
    void SaveLastBootId(ULONGLONG bootId) noexcept;
    
    // Read last tick count from registry
    ULONGLONG GetLastTickCountFromRegistry() noexcept;
    
    // Save current tick count to registry
    void SaveLastTickCount(ULONGLONG tickCount) noexcept;
    
    // Return base registry path for sessions
    std::wstring GetRegistryBasePath() noexcept;
    
    // Build full registry path for given session ID
    std::wstring GetSessionPath(const std::wstring& sessionId) noexcept;
    
    // Load all session entries for given signer
    std::vector<SessionEntry> LoadSessionEntries(const std::wstring& signerName) noexcept;
    
    // Load session entries from given registry path
    std::vector<SessionEntry> LoadSessionEntriesFromPath(const std::wstring& sessionPath, 
                                                         const std::wstring& signerName) noexcept;
    
    // Write single session entry to registry
    bool WriteSessionEntry(const std::wstring& signerName, DWORD index, const SessionEntry& entry) noexcept;
    
    // Update status ("UNPROTECTED"/"RESTORED") for specific entry
    bool UpdateEntryStatus(const std::wstring& signerName, DWORD index, const std::wstring& newStatus) noexcept;
    
    // Enumerate all stored session IDs in registry
    std::vector<std::wstring> GetAllSessionIds() noexcept;
    
    // Open or create registry key by path
    HKEY OpenOrCreateKey(const std::wstring& path) noexcept;
    
    // Recursively delete registry key and all its subkeys
    bool DeleteKeyRecursive(HKEY hKeyParent, const std::wstring& subKey) noexcept;
};