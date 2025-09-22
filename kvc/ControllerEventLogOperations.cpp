#include "Controller.h"
#include "common.h"

// Fast admin privilege check using SID comparison - standalone function
static bool IsElevated() noexcept 
{
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    
    return isAdmin == TRUE;
}

// Core event log clearing function - optimized for speed and reliability
bool Controller::ClearSystemEventLogs() noexcept 
{
    if (!IsElevated()) {
        ERROR(L"Administrator privileges required for event log clearing");
        return false;
    }

    // Primary system logs - order matters for dependency clearing
    constexpr const wchar_t* logs[] = {
        L"Application", L"Security", L"Setup", L"System"
    };
    
    int cleared = 0;
    constexpr int total = sizeof(logs) / sizeof(logs[0]);

    INFO(L"Clearing system event logs...");

    for (const auto& logName : logs) {
        HANDLE hLog = OpenEventLogW(nullptr, logName);
        if (hLog) {
            // Clear with nullptr backup (fastest method)
            if (ClearEventLogW(hLog, nullptr)) {
                SUCCESS(L"Cleared: %s", logName);
                ++cleared;
            } else {
                ERROR(L"Failed to clear: %s (Error: %d)", logName, GetLastError());
            }
            CloseEventLog(hLog);
        } else {
            ERROR(L"Access denied: %s", logName);
        }
    }

    INFO(L"Summary: %d/%d logs cleared", cleared, total);
    return cleared == total;
}