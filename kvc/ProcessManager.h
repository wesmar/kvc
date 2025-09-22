// ProcessManager.h
#pragma once

#include "common.h"
#include <vector>
#include <string>

// Forward declaration to avoid circular includes
class Controller;

// Process management operations with self-protection capabilities
class ProcessManager
{
public:
    ProcessManager() = delete;
    ~ProcessManager() = delete;

    // Command line interface for process termination with Controller integration
    static void HandleKillCommand(int argc, wchar_t* argv[], Controller* controller) noexcept;

private:
    // Command parsing and validation helpers
    static bool ParseProcessIds(std::wstring_view pidList, std::vector<DWORD>& pids) noexcept;
    static void PrintKillUsage() noexcept;
    static bool TerminateProcessWithProtection(DWORD processId, Controller* controller) noexcept;
    static bool IsNumericPid(std::wstring_view input) noexcept;
    static std::vector<DWORD> FindProcessIdsByName(const std::wstring& processName) noexcept;
};