/**
 * @file ProcessManager.h
 * @brief Process management operations with protection-aware termination
 * @author Marek Wesolowski
 * @date 2025
 * @copyright KVC Framework
 * 
 * Handles process termination with automatic protection level matching,
 * supporting both PID and name-based targeting.
 * Integrates with Controller for protection manipulation during termination.
 */

#pragma once

#include "common.h"
#include <vector>
#include <string>

// Forward declaration to avoid circular includes
class Controller;

/**
 * @class ProcessManager
 * @brief Process management operations with self-protection capabilities
 * 
 * Features:
 * - Protection-aware termination (automatically elevates to target protection)
 * - Multi-target support (comma-separated PIDs/names)
 * - Name-based process resolution with partial matching
 * - Case-insensitive process name matching
 * - Integration with Controller for protection manipulation
 * 
 * Examples:
 * - kill 1234              -> Terminate process by PID
 * - kill notepad           -> Terminate all notepad.exe processes
 * - kill 1234,5678,chrome  -> Terminate multiple targets
 * 
 * @note Static class - no instantiation required
 * @warning Process termination can cause system instability
 */
class ProcessManager
{
public:
    ProcessManager() = delete;           ///< Constructor deleted - static class
    ~ProcessManager() = delete;          ///< Destructor deleted - static class

    /**
     * @brief Handle 'kill' command from command line
     * @param argc Argument count from command line
     * @param argv Argument vector from command line
     * @param controller Controller instance for protection operations
     * 
     * Parses command line and terminates specified processes with
     * automatic protection level matching. Supports both single and
     * multiple target specification.
     * 
     * Command format:
     * - kill <PID|name>              -> Single target
     * - kill <PID1,PID2,name3>       -> Multiple targets (comma-separated)
     * 
     * Features:
     * - Automatic protection elevation to match target
     * - Partial name matching (e.g., "note" matches "notepad.exe")
     * - Case-insensitive matching
     * - Batch operation with progress reporting
     * 
     * @note Integrates with Controller for protection manipulation
     * @warning Terminating system processes can cause system instability
     */
    static void HandleKillCommand(int argc, wchar_t* argv[], Controller* controller) noexcept;

private:
    // === Command Parsing and Validation ===
    
    /**
     * @brief Parse comma-separated list of PIDs
     * @param pidList Comma-separated PID string
     * @param pids Output vector of parsed PIDs
     * @return true if parsing successful
     * @note Handles whitespace and validates numeric values
     * @note Skips invalid entries and continues parsing
     */
    static bool ParseProcessIds(std::wstring_view pidList, std::vector<DWORD>& pids) noexcept;
    
    /**
     * @brief Print kill command usage information
     * 
     * Displays command syntax, examples, and available options
     * for the kill command.
     */
    static void PrintKillUsage() noexcept;
    
    /**
     * @brief Terminate process with automatic protection elevation
     * @param processId Target process ID
     * @param controller Controller instance for protection operations
     * @return true if termination successful
     * 
     * Automatically matches target's protection level before termination
     * to ensure successful process termination. This is necessary because
     * protected processes can only be terminated by processes with equal
     * or higher protection levels.
     * 
     * @note Uses Controller::SelfProtect for protection elevation
     * @note Falls back to standard termination if protection matching fails
     */
    static bool TerminateProcessWithProtection(DWORD processId, Controller* controller) noexcept;
    
    /**
     * @brief Check if input string is a numeric PID
     * @param input String to validate
     * @return true if string contains only digits
     * @note Used to distinguish between PID and process name targets
     */
    static bool IsNumericPid(std::wstring_view input) noexcept;
    
    /**
     * @brief Find all process IDs matching name pattern
     * @param processName Process name or partial name
     * @return Vector of matching PIDs
     * 
     * Performs case-insensitive partial matching against running processes.
     * Example: "note" matches "notepad.exe", "Notepad.exe", "notes.exe"
     * 
     * @note Uses Toolhelp32 snapshot for process enumeration
     * @note Returns empty vector if no matches found
     */
    static std::vector<DWORD> FindProcessIdsByName(const std::wstring& processName) noexcept;
};