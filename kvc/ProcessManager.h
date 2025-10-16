// ProcessManager.h - Process management with protection-aware termination (PID/name targeting)

#pragma once

#include "common.h"
#include <vector>
#include <string>

// Forward declaration to avoid circular includes
class Controller;

// ProcessManager: static utilities for protection-aware process operations
class ProcessManager
{
public:
    ProcessManager() = delete;           // Static class - no instances
    ~ProcessManager() = delete;

    // Handle 'kill' command: parse args and terminate targets with protection matching
    static void HandleKillCommand(int argc, wchar_t* argv[], Controller* controller) noexcept;

private:
    // Parse comma-separated PID list into vector (skips invalid entries)
    static bool ParseProcessIds(std::wstring_view pidList, std::vector<DWORD>& pids) noexcept;
    
    // Print usage information for kill command
    static void PrintKillUsage() noexcept;
    
    // Terminate process by PID, attempting protection elevation via Controller
    static bool TerminateProcessWithProtection(DWORD processId, Controller* controller) noexcept;
    
    // Return true if input is numeric PID string
    static bool IsNumericPid(std::wstring_view input) noexcept;
    
    // Find all PIDs whose process name matches the given (partial, case-insensitive)
    static std::vector<DWORD> FindProcessIdsByName(const std::wstring& processName) noexcept;
};
