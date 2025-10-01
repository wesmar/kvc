// SessionManager.h
#pragma once

#include "common.h"
#include <string>
#include <vector>
#include <optional>

struct ProcessEntry;

// Session state entry for restoration tracking
struct SessionEntry
{
    DWORD Pid;
    std::wstring ProcessName;
    UCHAR OriginalProtection;      // Combined level + signer
    UCHAR SignatureLevel;
    UCHAR SectionSignatureLevel;
    std::wstring Status;            // "UNPROTECTED" or "RESTORED"
};

// Manages process protection state across boot sessions
class SessionManager
{
public:
    SessionManager() = default;
    ~SessionManager() = default;

    // Session lifecycle management
    void CleanupStaleSessions() noexcept;
    void CleanupAllSessionsExceptCurrent() noexcept;
    void DetectAndHandleReboot() noexcept;
    void EnforceSessionLimit(int maxSessions) noexcept;
    
    // State tracking operations
    bool SaveUnprotectOperation(const std::wstring& signerName, 
                               const std::vector<ProcessEntry>& affectedProcesses) noexcept;
    
    // Restoration operations
    bool RestoreBySigner(const std::wstring& signerName, class Controller* controller) noexcept;
    bool RestoreAll(class Controller* controller) noexcept;
    
    // Query operations
    void ShowHistory() noexcept;

private:
    std::wstring GetCurrentBootSession() noexcept;
    std::wstring CalculateBootTime() noexcept;
    ULONGLONG GetLastBootIdFromRegistry() noexcept;
    void SaveLastBootId(ULONGLONG bootId) noexcept;

	ULONGLONG GetLastTickCountFromRegistry() noexcept;
	void SaveLastTickCount(ULONGLONG tickCount) noexcept;
    
    std::wstring GetRegistryBasePath() noexcept;
    std::wstring GetSessionPath(const std::wstring& sessionId) noexcept;
    
    std::vector<SessionEntry> LoadSessionEntries(const std::wstring& signerName) noexcept;
    std::vector<SessionEntry> LoadSessionEntriesFromPath(const std::wstring& sessionPath, const std::wstring& signerName) noexcept;
    bool WriteSessionEntry(const std::wstring& signerName, DWORD index, const SessionEntry& entry) noexcept;
    bool UpdateEntryStatus(const std::wstring& signerName, DWORD index, const std::wstring& newStatus) noexcept;
    
    std::vector<std::wstring> GetAllSessionIds() noexcept;
    
    // Registry helpers
    HKEY OpenOrCreateKey(const std::wstring& path) noexcept;
    bool DeleteKeyRecursive(HKEY hKeyParent, const std::wstring& subKey) noexcept;
};