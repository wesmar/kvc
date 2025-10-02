// SessionManager.cpp
#include "SessionManager.h"
#include "Controller.h"
#include "Utils.h"
#include <algorithm>
#include <sstream>
#include <iomanip>

// Static cache cleared on reboot detection
static std::wstring g_cachedBootSession;

// Calculate current boot time as unique session ID
std::wstring SessionManager::CalculateBootTime() noexcept
{
    FILETIME ftNow;
    GetSystemTimeAsFileTime(&ftNow);
    ULONGLONG currentTime = (static_cast<ULONGLONG>(ftNow.dwHighDateTime) << 32) | ftNow.dwLowDateTime;
    ULONGLONG tickCount = GetTickCount64();
    ULONGLONG bootTime = currentTime - (tickCount * 10000ULL);
    
    std::wostringstream oss;
    oss << bootTime;
    return oss.str();
}

ULONGLONG SessionManager::GetLastBootIdFromRegistry() noexcept
{
    std::wstring basePath = GetRegistryBasePath();
    HKEY hKey;
    
    if (RegOpenKeyExW(HKEY_CURRENT_USER, basePath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return 0;
    
    ULONGLONG lastBootId = 0;
    DWORD dataSize = sizeof(ULONGLONG);
    RegQueryValueExW(hKey, L"LastBootId", nullptr, nullptr, reinterpret_cast<BYTE*>(&lastBootId), &dataSize);
    
    RegCloseKey(hKey);
    return lastBootId;
}

void SessionManager::SaveLastBootId(ULONGLONG bootId) noexcept
{
    std::wstring basePath = GetRegistryBasePath();
    HKEY hKey = OpenOrCreateKey(basePath);
    
    if (hKey)
    {
        RegSetValueExW(hKey, L"LastBootId", 0, REG_QWORD, reinterpret_cast<const BYTE*>(&bootId), sizeof(ULONGLONG));
        RegCloseKey(hKey);
    }
}

ULONGLONG SessionManager::GetLastTickCountFromRegistry() noexcept
{
    std::wstring basePath = GetRegistryBasePath();
    HKEY hKey;
    
    if (RegOpenKeyExW(HKEY_CURRENT_USER, basePath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return 0;
    
    ULONGLONG lastTickCount = 0;
    DWORD dataSize = sizeof(ULONGLONG);
    RegQueryValueExW(hKey, L"LastTickCount", nullptr, nullptr, reinterpret_cast<BYTE*>(&lastTickCount), &dataSize);
    
    RegCloseKey(hKey);
    return lastTickCount;
}

void SessionManager::SaveLastTickCount(ULONGLONG tickCount) noexcept
{
    std::wstring basePath = GetRegistryBasePath();
    HKEY hKey = OpenOrCreateKey(basePath);
    
    if (hKey)
    {
        RegSetValueExW(hKey, L"LastTickCount", 0, REG_QWORD, reinterpret_cast<const BYTE*>(&tickCount), sizeof(ULONGLONG));
        RegCloseKey(hKey);
    }
}

std::wstring SessionManager::GetCurrentBootSession() noexcept
{
    if (!g_cachedBootSession.empty())
        return g_cachedBootSession;
    
    ULONGLONG lastBootId = GetLastBootIdFromRegistry();
    
    if (lastBootId == 0)
    {
        // First run ever - calculate and save
        std::wstring calculatedSession = CalculateBootTime();
        ULONGLONG calculatedBootId = std::stoull(calculatedSession);
        SaveLastBootId(calculatedBootId);
        g_cachedBootSession = calculatedSession;
        return g_cachedBootSession;
    }
    
    // Use LastBootId from registry as session ID
    std::wostringstream oss;
    oss << lastBootId;
    g_cachedBootSession = oss.str();
    
    return g_cachedBootSession;
}

void SessionManager::DetectAndHandleReboot() noexcept
{
    ULONGLONG currentTick = GetTickCount64();
    ULONGLONG lastTick = GetLastTickCountFromRegistry();
    ULONGLONG lastBootId = GetLastBootIdFromRegistry();
    
    if (lastBootId == 0)
    {
        // First run ever
        std::wstring calculatedSession = CalculateBootTime();
        ULONGLONG calculatedBootId = std::stoull(calculatedSession);
        SaveLastBootId(calculatedBootId);
        SaveLastTickCount(currentTick);
        g_cachedBootSession = calculatedSession;
        return;
    }
    
    // Detect reboot: tickCount decreased
    if (currentTick < lastTick)
    {
        // New boot detected
        std::wstring calculatedSession = CalculateBootTime();
        ULONGLONG calculatedBootId = std::stoull(calculatedSession);
        SaveLastBootId(calculatedBootId);
        SaveLastTickCount(currentTick);
        g_cachedBootSession = calculatedSession;
        
        // Enforce session limit
        EnforceSessionLimit(MAX_SESSIONS);
    }
    else
    {
        // Same boot - use LastBootId as session ID
        SaveLastTickCount(currentTick);
        std::wostringstream oss;
        oss << lastBootId;
        g_cachedBootSession = oss.str();
    }
}

std::vector<std::wstring> SessionManager::GetAllSessionIds() noexcept
{
    std::vector<std::wstring> sessionIds;
    std::wstring basePath = GetRegistryBasePath() + L"\\Sessions";
    
    HKEY hSessions;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, basePath.c_str(), 0, KEY_READ, &hSessions) != ERROR_SUCCESS)
        return sessionIds;
    
    DWORD index = 0;
    wchar_t sessionName[256];
    DWORD sessionNameSize;
    
    while (true)
    {
        sessionNameSize = 256;
        if (RegEnumKeyExW(hSessions, index, sessionName, &sessionNameSize, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;
        
        sessionIds.push_back(sessionName);
        index++;
    }
    
    RegCloseKey(hSessions);
    return sessionIds;
}

void SessionManager::EnforceSessionLimit(int maxSessions) noexcept
{
    auto sessions = GetAllSessionIds();
    
    if (static_cast<int>(sessions.size()) <= maxSessions)
        return;
    
    // Sort sessions by ID (oldest first)
    std::sort(sessions.begin(), sessions.end(), [](const std::wstring& a, const std::wstring& b) {
        try {
            return std::stoull(a) < std::stoull(b);
        } catch (...) {
            return a < b;
        }
    });
    
    std::wstring currentSession = GetCurrentBootSession();
    std::wstring basePath = GetRegistryBasePath() + L"\\Sessions";
    
    HKEY hSessions;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, basePath.c_str(), 0, KEY_WRITE, &hSessions) != ERROR_SUCCESS)
        return;
    
    int toDelete = static_cast<int>(sessions.size()) - maxSessions;
    int deleted = 0;
    
    for (const auto& sessionId : sessions)
    {
        if (deleted >= toDelete)
            break;
        
        if (sessionId != currentSession)
        {
            DeleteKeyRecursive(hSessions, sessionId);
            DEBUG(L"Deleted old session: %s", sessionId.c_str());
            deleted++;
        }
    }
    
    RegCloseKey(hSessions);
    
    if (deleted > 0)
    {
        INFO(L"Enforced session limit: deleted %d old sessions", deleted);
    }
}

void SessionManager::CleanupAllSessionsExceptCurrent() noexcept
{
    std::wstring currentSession = GetCurrentBootSession();
    std::wstring basePath = GetRegistryBasePath() + L"\\Sessions";
    
    HKEY hSessions;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, basePath.c_str(), 0, KEY_READ | KEY_WRITE, &hSessions) != ERROR_SUCCESS)
    {
        INFO(L"No sessions to cleanup");
        return;
    }
    
    DWORD index = 0;
    wchar_t subKeyName[256];
    DWORD subKeyNameSize;
    std::vector<std::wstring> keysToDelete;
    
    while (true)
    {
        subKeyNameSize = 256;
        if (RegEnumKeyExW(hSessions, index, subKeyName, &subKeyNameSize, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;
        
        std::wstring keyName = subKeyName;
        if (keyName != currentSession)
            keysToDelete.push_back(keyName);
        
        index++;
    }
    
    for (const auto& key : keysToDelete)
    {
        DeleteKeyRecursive(hSessions, key);
    }
    
    RegCloseKey(hSessions);
    
    if (!keysToDelete.empty())
    {
        SUCCESS(L"Cleaned up %zu old sessions (kept current session)", keysToDelete.size());
    }
    else
    {
        INFO(L"No old sessions to cleanup");
    }
}

std::wstring SessionManager::GetRegistryBasePath() noexcept
{
    return L"Software\\kvc";
}

std::wstring SessionManager::GetSessionPath(const std::wstring& sessionId) noexcept
{
    return GetRegistryBasePath() + L"\\Sessions\\" + sessionId;
}

// Remove all session keys except current boot session
void SessionManager::CleanupStaleSessions() noexcept
{
    std::wstring currentSession = GetCurrentBootSession();
    std::wstring basePath = GetRegistryBasePath() + L"\\Sessions";
    
    HKEY hSessions;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, basePath.c_str(), 0, KEY_READ | KEY_WRITE, &hSessions) != ERROR_SUCCESS)
        return;
    
    DWORD index = 0;
    wchar_t subKeyName[256];
    DWORD subKeyNameSize;
    
    std::vector<std::wstring> keysToDelete;
    
    while (true)
    {
        subKeyNameSize = 256;
        if (RegEnumKeyExW(hSessions, index, subKeyName, &subKeyNameSize, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;
        
        std::wstring keyName = subKeyName;
        if (keyName != currentSession)
            keysToDelete.push_back(keyName);
        
        index++;
    }
    
    // Delete stale sessions
    for (const auto& key : keysToDelete)
    {
        DeleteKeyRecursive(hSessions, key);
    }
    
    RegCloseKey(hSessions);
}

// Save process state before unprotect operation
bool SessionManager::SaveUnprotectOperation(const std::wstring& signerName, 
                                           const std::vector<ProcessEntry>& affectedProcesses) noexcept
{
    if (affectedProcesses.empty())
        return true;
    
    // Use original signer name (no normalization)
    std::wstring sessionPath = GetSessionPath(GetCurrentBootSession());
    std::wstring signerPath = sessionPath + L"\\" + signerName;
    
    HKEY hKey = OpenOrCreateKey(signerPath);
    if (!hKey)
    {
        ERROR(L"Failed to create registry key for session state");
        return false;
    }
    
    DWORD index = 0;
    for (const auto& proc : affectedProcesses)
    {
        SessionEntry entry;
        entry.Pid = proc.Pid;
        entry.ProcessName = proc.ProcessName;
        entry.OriginalProtection = Utils::GetProtection(proc.ProtectionLevel, proc.SignerType);
        entry.SignatureLevel = proc.SignatureLevel;
        entry.SectionSignatureLevel = proc.SectionSignatureLevel;
        entry.Status = L"UNPROTECTED";
        
        if (!WriteSessionEntry(signerName, index, entry))
        {
            RegCloseKey(hKey);
            return false;
        }
        
        index++;
    }
    
    // Write count
    DWORD count = static_cast<DWORD>(affectedProcesses.size());
    RegSetValueExW(hKey, L"Count", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&count), sizeof(DWORD));
    
    RegCloseKey(hKey);
    
    SUCCESS(L"Session state saved to registry (%d processes tracked)", count);
    return true;
}

bool SessionManager::WriteSessionEntry(const std::wstring& signerName, DWORD index, const SessionEntry& entry) noexcept
{
    std::wstring sessionPath = GetSessionPath(GetCurrentBootSession());
    std::wstring signerPath = sessionPath + L"\\" + signerName;
    
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, signerPath.c_str(), 0, KEY_WRITE, &hKey) != ERROR_SUCCESS)
        return false;
    
    // Format: "PID|ProcessName|Protection|SigLevel|SecSigLevel|Status"
    std::wostringstream oss;
    oss << entry.Pid << L"|"
        << entry.ProcessName << L"|"
        << static_cast<int>(entry.OriginalProtection) << L"|"
        << static_cast<int>(entry.SignatureLevel) << L"|"
        << static_cast<int>(entry.SectionSignatureLevel) << L"|"
        << entry.Status;
    
    std::wstring valueName = L"Proc_" + std::to_wstring(index);
    std::wstring valueData = oss.str();
    
    LONG result = RegSetValueExW(hKey, valueName.c_str(), 0, REG_SZ, 
                                  reinterpret_cast<const BYTE*>(valueData.c_str()),
                                  static_cast<DWORD>((valueData.length() + 1) * sizeof(wchar_t)));
    
    RegCloseKey(hKey);
    return result == ERROR_SUCCESS;
}

bool SessionManager::UpdateEntryStatus(const std::wstring& signerName, DWORD index, const std::wstring& newStatus) noexcept
{
    std::wstring sessionPath = GetSessionPath(GetCurrentBootSession());
    std::wstring signerPath = sessionPath + L"\\" + signerName;
    
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, signerPath.c_str(), 0, KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS)
        return false;
    
    std::wstring valueName = L"Proc_" + std::to_wstring(index);
    wchar_t valueData[512];
    DWORD valueSize = sizeof(valueData);
    
    if (RegQueryValueExW(hKey, valueName.c_str(), nullptr, nullptr, 
                        reinterpret_cast<BYTE*>(valueData), &valueSize) != ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return false;
    }
    
    // Parse existing entry
    std::wstring data = valueData;
    std::vector<std::wstring> parts;
    std::wstring current;
    
    for (wchar_t ch : data)
    {
        if (ch == L'|')
        {
            parts.push_back(current);
            current.clear();
        }
        else
        {
            current += ch;
        }
    }
    if (!current.empty())
        parts.push_back(current);
    
    if (parts.size() < 5)
    {
        RegCloseKey(hKey);
        return false;
    }
    
    // Rebuild with new status
    std::wostringstream oss;
    oss << parts[0] << L"|" << parts[1] << L"|" << parts[2] << L"|" 
        << parts[3] << L"|" << parts[4] << L"|" << newStatus;
    
    std::wstring newValueData = oss.str();
    
    LONG result = RegSetValueExW(hKey, valueName.c_str(), 0, REG_SZ, 
                                  reinterpret_cast<const BYTE*>(newValueData.c_str()),
                                  static_cast<DWORD>((newValueData.length() + 1) * sizeof(wchar_t)));
    
    RegCloseKey(hKey);
    return result == ERROR_SUCCESS;
}

std::vector<SessionEntry> SessionManager::LoadSessionEntries(const std::wstring& signerName) noexcept
{
    std::vector<SessionEntry> entries;
    
    // Normalize signer name for case-insensitive comparison
    std::wstring normalizedSigner = signerName;
    std::transform(normalizedSigner.begin(), normalizedSigner.end(), 
                   normalizedSigner.begin(), ::towlower);
    
    std::wstring sessionPath = GetSessionPath(GetCurrentBootSession());
    
    HKEY hSession;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, sessionPath.c_str(), 0, KEY_READ, &hSession) != ERROR_SUCCESS)
        return entries;
    
    // Search all subkeys for matching signer (case-insensitive)
    DWORD index = 0;
    wchar_t subKeyName[256];
    DWORD subKeyNameSize;
    std::wstring foundSignerKey;
    
    while (true)
    {
        subKeyNameSize = 256;
        LONG result = RegEnumKeyExW(hSession, index, subKeyName, &subKeyNameSize, nullptr, nullptr, nullptr, nullptr);
        if (result != ERROR_SUCCESS)
            break;
        
        std::wstring candidate = subKeyName;
        std::wstring normalizedCandidate = candidate;
        std::transform(normalizedCandidate.begin(), normalizedCandidate.end(), 
                       normalizedCandidate.begin(), ::towlower);
        
        if (normalizedCandidate == normalizedSigner) {
            foundSignerKey = candidate;
            break;
        }
        
        index++;
    }
    
    if (foundSignerKey.empty()) {
        RegCloseKey(hSession);
        DEBUG(L"No signer key found for: %s (normalized: %s)", signerName.c_str(), normalizedSigner.c_str());
        return entries;
    }
    
    // Use found key name
    entries = LoadSessionEntriesFromPath(sessionPath, foundSignerKey);
    RegCloseKey(hSession);
    
    DEBUG(L"Loaded %zu entries for signer: %s (key: %s)", entries.size(), signerName.c_str(), foundSignerKey.c_str());
    return entries;
}

std::vector<SessionEntry> SessionManager::LoadSessionEntriesFromPath(const std::wstring& sessionPath, const std::wstring& signerName) noexcept
{
    std::vector<SessionEntry> entries;
    
    std::wstring signerPath = sessionPath + L"\\" + signerName;
    
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, signerPath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return entries;
    
    DWORD count = 0;
    DWORD dataSize = sizeof(DWORD);
    if (RegQueryValueExW(hKey, L"Count", nullptr, nullptr, reinterpret_cast<BYTE*>(&count), &dataSize) != ERROR_SUCCESS) {
        count = 0;
    }
    
    for (DWORD i = 0; i < count; i++)
    {
        std::wstring valueName = L"Proc_" + std::to_wstring(i);
        wchar_t valueData[512];
        DWORD valueSize = sizeof(valueData);
        
        if (RegQueryValueExW(hKey, valueName.c_str(), nullptr, nullptr, 
                            reinterpret_cast<BYTE*>(valueData), &valueSize) == ERROR_SUCCESS)
        {
            // Parse: "PID|ProcessName|Protection|SigLevel|SecSigLevel|Status"
            std::wstring data = valueData;
            std::vector<std::wstring> parts;
            std::wstring current;
            
            for (wchar_t ch : data)
            {
                if (ch == L'|')
                {
                    parts.push_back(current);
                    current.clear();
                }
                else
                {
                    current += ch;
                }
            }
            if (!current.empty())
                parts.push_back(current);
            
            if (parts.size() >= 5)
            {
                SessionEntry entry;
                entry.Pid = static_cast<DWORD>(std::stoul(parts[0]));
                entry.ProcessName = parts[1];
                entry.OriginalProtection = static_cast<UCHAR>(std::stoi(parts[2]));
                entry.SignatureLevel = static_cast<UCHAR>(std::stoi(parts[3]));
                entry.SectionSignatureLevel = static_cast<UCHAR>(std::stoi(parts[4]));
                entry.Status = (parts.size() >= 6) ? parts[5] : L"UNPROTECTED";
                
                entries.push_back(entry);
            }
        }
    }
    
    RegCloseKey(hKey);
    return entries;
}

// Restore protection for specific signer group
bool SessionManager::RestoreBySigner(const std::wstring& signerName, Controller* controller) noexcept
{
    if (!controller)
    {
        ERROR(L"Controller not available for restoration");
        return false;
    }
    
    // Find actual signer key name in registry (case-insensitive search)
    std::wstring normalizedSigner = signerName;
    std::transform(normalizedSigner.begin(), normalizedSigner.end(), 
                   normalizedSigner.begin(), ::towlower);
    
    std::wstring sessionPath = GetSessionPath(GetCurrentBootSession());
    
    HKEY hSession;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, sessionPath.c_str(), 0, KEY_READ, &hSession) != ERROR_SUCCESS)
    {
        INFO(L"No saved state found for signer: %s", signerName.c_str());
        return false;
    }
    
    // Find actual key name in registry
    DWORD index = 0;
    wchar_t subKeyName[256];
    DWORD subKeyNameSize;
    std::wstring foundSignerKey;
    
    while (true)
    {
        subKeyNameSize = 256;
        LONG result = RegEnumKeyExW(hSession, index, subKeyName, &subKeyNameSize, nullptr, nullptr, nullptr, nullptr);
        if (result != ERROR_SUCCESS)
            break;
        
        std::wstring candidate = subKeyName;
        std::wstring normalizedCandidate = candidate;
        std::transform(normalizedCandidate.begin(), normalizedCandidate.end(), 
                       normalizedCandidate.begin(), ::towlower);
        
        if (normalizedCandidate == normalizedSigner) {
            foundSignerKey = candidate;
            break;
        }
        
        index++;
    }
    
    RegCloseKey(hSession);
    
    if (foundSignerKey.empty())
    {
        INFO(L"No saved state found for signer: %s", signerName.c_str());
        return false;
    }
    
    // Load entries using actual key name
    auto entries = LoadSessionEntriesFromPath(sessionPath, foundSignerKey);
    
    if (entries.empty())
    {
        INFO(L"No saved state found for signer: %s", signerName.c_str());
        return false;
    }
    
    INFO(L"Restoring protection for %s (%zu processes)", signerName.c_str(), entries.size());
    
    DWORD successCount = 0;
    DWORD skipCount = 0;
    DWORD entryIndex = 0;
    
    for (const auto& entry : entries)
    {
        // Skip if already restored
        if (entry.Status == L"RESTORED")
        {
            skipCount++;
            entryIndex++;
            continue;
        }
        
        // Check if process still exists
        auto kernelAddr = controller->GetProcessKernelAddress(entry.Pid);
        if (!kernelAddr)
        {
            INFO(L"Skipping PID %d (%s) - process no longer exists", entry.Pid, entry.ProcessName.c_str());
            skipCount++;
            entryIndex++;
            continue;
        }
        
        // Restore original protection
        if (controller->SetProcessProtection(kernelAddr.value(), entry.OriginalProtection))
        {
            UpdateEntryStatus(foundSignerKey, entryIndex, L"RESTORED");
            SUCCESS(L"Restored protection for PID %d (%s)", entry.Pid, entry.ProcessName.c_str());
            successCount++;
        }
        else
        {
            ERROR(L"Failed to restore protection for PID %d (%s)", entry.Pid, entry.ProcessName.c_str());
        }
        
        entryIndex++;
    }
    
    INFO(L"Restoration completed: %d restored, %d skipped", successCount, skipCount);
    return successCount > 0;
}

// Restore all saved protection states
bool SessionManager::RestoreAll(Controller* controller) noexcept
{
    if (!controller)
    {
        ERROR(L"Controller not available for restoration");
        return false;
    }
    
    std::wstring sessionPath = GetSessionPath(GetCurrentBootSession());
    
    HKEY hSession;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, sessionPath.c_str(), 0, KEY_READ, &hSession) != ERROR_SUCCESS)
    {
        INFO(L"No saved session state found");
        return false;
    }
    
    // Enumerate all signer subkeys
    DWORD index = 0;
    wchar_t subKeyName[256];
    DWORD subKeyNameSize;
    std::vector<std::wstring> signers;
    
    while (true)
    {
        subKeyNameSize = 256;
        if (RegEnumKeyExW(hSession, index, subKeyName, &subKeyNameSize, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;
        
        signers.push_back(subKeyName);
        index++;
    }
    
    RegCloseKey(hSession);
    
    if (signers.empty())
    {
        INFO(L"No saved state found in current session");
        return false;
    }
    
    INFO(L"Restoring all protection states (%zu groups)", signers.size());
    
    bool anySuccess = false;
    for (const auto& signer : signers)
    {
        if (RestoreBySigner(signer, controller))
            anySuccess = true;
    }
    
    return anySuccess;
}

// Display saved session history
void SessionManager::ShowHistory() noexcept
{
    std::wstring basePath = GetRegistryBasePath() + L"\\Sessions";
    
    HKEY hSessions;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, basePath.c_str(), 0, KEY_READ, &hSessions) != ERROR_SUCCESS)
    {
        INFO(L"No saved session state found (cannot open sessions key)");
        return;
    }

    // Show current calculated boot session ID
    std::wstring currentSession = GetCurrentBootSession();
    INFO(L"Current boot session ID: %s", currentSession.c_str());
    INFO(L"All sessions found in registry:");
    
    DWORD index = 0;
    wchar_t subKeyName[256];
    DWORD subKeyNameSize;
    bool foundSessions = false;

    while (true)
    {
        subKeyNameSize = 256;
        if (RegEnumKeyExW(hSessions, index, subKeyName, &subKeyNameSize, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;

        std::wstring sessionId = subKeyName;
        std::wcout << L"\nSession: " << sessionId;
        if (sessionId == currentSession) {
            std::wcout << L" [CURRENT]";
        }
        std::wcout << L"\n";
        
        std::wstring sessionPath = basePath + L"\\" + sessionId;
        HKEY hSession;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, sessionPath.c_str(), 0, KEY_READ, &hSession) == ERROR_SUCCESS)
        {
            DWORD signerIndex = 0;
            wchar_t signerName[256];
            DWORD signerNameSize;

            while (true)
            {
                signerNameSize = 256;
                if (RegEnumKeyExW(hSession, signerIndex, signerName, &signerNameSize, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                    break;

                std::wstring signer = signerName;
                auto entries = LoadSessionEntriesFromPath(sessionPath, signer);
                std::wcout << L"  [" << signer << L"] - " << entries.size() << L" processes\n";

                for (const auto& entry : entries)
                {
                    std::wcout << L"    PID " << entry.Pid << L": " << entry.ProcessName 
                               << L" (protection: 0x" << std::hex << static_cast<int>(entry.OriginalProtection) 
                               << std::dec << L", status: " << entry.Status << L")\n";
                }

                signerIndex++;
                foundSessions = true;
            }
            RegCloseKey(hSession);
        }
        index++;
    }

    RegCloseKey(hSessions);
    
    if (!foundSessions) {
        INFO(L"No session data found in registry");
    }
}

HKEY SessionManager::OpenOrCreateKey(const std::wstring& path) noexcept
{
    HKEY hKey;
    DWORD disposition;
    
    if (RegCreateKeyExW(HKEY_CURRENT_USER, path.c_str(), 0, nullptr, 
                       REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, 
                       &hKey, &disposition) != ERROR_SUCCESS)
    {
        return nullptr;
    }
    
    return hKey;
}

bool SessionManager::DeleteKeyRecursive(HKEY hKeyParent, const std::wstring& subKey) noexcept
{
    HKEY hKey;
    if (RegOpenKeyExW(hKeyParent, subKey.c_str(), 0, KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS)
        return false;
    
    // Delete all subkeys first
    wchar_t childName[256];
    DWORD childNameSize;
    
    while (true)
    {
        childNameSize = 256;
        if (RegEnumKeyExW(hKey, 0, childName, &childNameSize, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;
        
        DeleteKeyRecursive(hKey, childName);
    }
    
    RegCloseKey(hKey);
    RegDeleteKeyW(hKeyParent, subKey.c_str());
    
    return true;
}