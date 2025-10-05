/**
 * @file HelpSystem.h
 * @brief Comprehensive help system with modular command documentation
 * @author Marek Wesolowski
 * @date 2025
 * @copyright KVC Framework
 * 
 * Provides formatted help output with color-coded sections, usage examples,
 * and detailed command explanations.
 * Modular design allows displaying specific help sections as needed.
 */

#pragma once

#include "common.h"
#include <string_view>

/**
 * @class HelpSystem
 * @brief Comprehensive help system for KVC with modular command documentation
 * 
 * Features:
 * - Color-coded section headers for readability
 * - Categorized command listings by functionality
 * - Detailed parameter explanations
 * - Usage examples with real scenarios
 * - Technical feature documentation
 * - Security notices and warnings
 * 
 * Help Categories:
 * - Basic commands (help, list, info)
 * - Process protection (protect, unprotect, set)
 * - Process termination (kill)
 * - Windows Defender management
 * - DPAPI password extraction
 * - Browser credential extraction
 * - Service management
 * - Registry operations
 * - Security engine control
 * 
 * @note Static class - no instantiation required
 * @note Uses ANSI color codes for enhanced readability
 */
class HelpSystem
{
public:
    HelpSystem() = delete;           ///< Constructor deleted - static class
    ~HelpSystem() = delete;          ///< Destructor deleted - static class

    // === Main Help Interface ===
    
    /**
     * @brief Print complete usage information
     * @param programName Program name for display in examples
     * 
     * Displays all help sections in organized format:
     * 1. Program header with version and author
     * 2. Basic command documentation
     * 3. Process protection commands
     * 4. System commands
     * 5. Process termination commands
     * 6. Windows Defender commands
     * 7. DPAPI extraction commands
     * 8. Browser extraction commands
     * 9. Service management commands
     * 10. Protection type explanations
     * 11. Usage examples
     * 12. Security notice and footer
     * 
     * @note Comprehensive help covering all framework features
     */
    static void PrintUsage(std::wstring_view programName) noexcept;
    
    /**
     * @brief Print header with version and author info
     * 
     * Displays KVC banner with ASCII art, version information,
     * author credits, and copyright notice.
     * 
     * @note Uses color coding for visual appeal
     */
    static void PrintHeader() noexcept;
    
    /**
     * @brief Print basic command documentation
     * 
     * Commands covered:
     * - help: Display help information
     * - list: List protected processes
     * - info: Show process protection information
     * 
     * @note Basic commands available without special privileges
     */
    static void PrintBasicCommands() noexcept;
    
    /**
     * @brief Print process protection command documentation
     * 
     * Commands covered:
     * - protect: Add protection to unprotected process
     * - unprotect: Remove protection from process
     * - set: Force set protection level (overwrite)
     * - set-signer: Change protection for specific signer
     * - restore: Restore protection from session
     * 
     * @note Requires driver and appropriate privileges
     */
    static void PrintProtectionCommands() noexcept;
    
    /**
     * @brief Print system command documentation
     * 
     * Commands covered:
     * - dump: Dump process memory to file
     * - elevate: Elevate current process protection
     * - clear-logs: Clear Windows event logs
     * 
     * @note Advanced operations requiring high privileges
     */
    static void PrintSystemCommands() noexcept;
    
    /**
     * @brief Print process termination command documentation
     * 
     * Commands covered:
     * - kill: Terminate process with protection matching
     * - kill multiple: Terminate multiple processes
     * 
     * @note Supports both PID and name-based targeting
     */
    static void PrintProcessTerminationCommands() noexcept;
    
    /**
     * @brief Print Windows Defender command documentation
     * 
     * Commands covered:
     * - defender-enable: Enable Windows Defender exclusions
     * - defender-disable: Disable Windows Defender exclusions
     * - defender-add: Add specific exclusion
     * - defender-remove: Remove specific exclusion
     * 
     * @note Requires TrustedInstaller privileges for some operations
     */
    static void PrintDefenderCommands() noexcept;
    
    /**
     * @brief Print DPAPI extraction command documentation
     * 
     * Commands covered:
     * - extract-passwords: Extract passwords from Chrome/Edge/WiFi
     * - master-keys: Display extracted master keys
     * - decrypt: Decrypt specific DPAPI blob
     * 
     * @note Requires TrustedInstaller privileges for registry access
     */
    static void PrintDPAPICommands() noexcept;
    
    /**
     * @brief Print browser credential extraction documentation
     * 
     * Commands covered:
     * - chrome-passwords: Extract Chrome passwords only
     * - edge-passwords: Extract Edge passwords only
     * - browser-all: Extract from all supported browsers
     * 
     * @note Uses SQLite and AES-GCM decryption for browser data
     */
    static void PrintBrowserCommands() noexcept;
    
    /**
     * @brief Print service management command documentation
     * 
     * Commands covered:
     * - service-install: Install as Windows Service
     * - service-start: Start service
     * - service-stop: Stop service
     * - service-uninstall: Uninstall service
     * 
     * @note Requires administrative privileges
     */
    static void PrintServiceCommands() noexcept;
    
    /**
     * @brief Print protection type documentation
     * 
     * Explains PP (Protected Process) and PPL (Protected Process Light)
     * concepts, including:
     * - Protection level differences
     * - Signer type authorities
     * - Signature verification levels
     * - Practical implications
     * 
     * @note Technical background for protection operations
     */
    static void PrintProtectionTypes() noexcept;
    
    /**
     * @brief Print Defender exclusion type documentation
     * 
     * Explains different exclusion types:
     * - Paths: File and folder exclusions
     * - Processes: Process name exclusions
     * - Extensions: File extension exclusions
     * - IPs: IP address exclusions
     * 
     * @note Used with defender-add and defender-remove commands
     */
    static void PrintExclusionTypes() noexcept;
    
    /**
     * @brief Print pattern matching documentation
     * 
     * Explains wildcard and regex support in process targeting:
     * - Partial name matching
     * - Case-insensitive matching
     * - Multiple target specification
     * - Comma-separated lists
     * 
     * @note Used in process targeting commands
     */
    static void PrintPatternMatching() noexcept;
    
    /**
     * @brief Print technical features documentation
     * 
     * Explains advanced technical features:
     * - Kernel offset discovery
     * - EPROCESS structure manipulation
     * - Driver communication
     * - TrustedInstaller integration
     * - Session state tracking
     * 
     * @note For advanced users and developers
     */
    static void PrintTechnicalFeatures() noexcept;
    
    /**
     * @brief Print unknown command message
     * @param command Unknown command that was entered
     * 
     * Displays friendly error message when unknown command is entered.
     * Suggests using 'help' command for available options.
     * 
     * @note User-friendly error handling
     */
    static void PrintUnknownCommandMessage(std::wstring_view command) noexcept;
    
    /**
     * @brief Print Defender-specific notes and warnings
     * 
     * Important information about Defender exclusion management:
     * - Real-time protection implications
     * - Exclusion persistence across reboots
     * - Security considerations
     * - Best practices
     * 
     * @note Security-focused guidance
     */
    static void PrintDefenderNotes() noexcept;
    
    /**
     * @brief Print registry operation command documentation
     * 
     * Commands covered:
     * - registry-backup: Backup registry hives
     * - registry-restore: Restore registry hives
     * - registry-defrag: Defragment registry
     * 
     * @note Requires TrustedInstaller privileges
     */
    static void PrintRegistryCommands() noexcept;
    
    /**
     * @brief Print security engine command documentation
     * 
     * Commands covered:
     * - security-disable: Disable Windows Defender engine
     * - security-enable: Enable Windows Defender engine
     * - security-status: Check security engine status
     * 
     * @note Advanced system modification - use with caution
     */
    static void PrintSecurityEngineCommands() noexcept;
    
    /**
     * @brief Print session management documentation
     * 
     * Explains boot session tracking and restoration:
     * - Session state persistence
     * - Automatic reboot detection
     * - Protection state restoration
     * - Session cleanup operations
     * 
     * @note Cross-boot state tracking feature
     */
    static void PrintSessionManagement() noexcept;
    
    /**
     * @brief Print sticky keys backdoor documentation
     * 
     * Installation, removal, and security warnings for:
     * - Sticky keys backdoor mechanism
     * - Security implications
     * - Installation procedure
     * - Removal procedure
     * 
     * @warning Security risk - authorized use only
     */
    static void PrintStickyKeysInfo() noexcept;
    
    /**
     * @brief Print undumpable process documentation
     * 
     * Lists processes with anti-dump protection:
     * - LSA protected processes
     - System critical processes
     * - Anti-malware protected processes
     * - Dumpability analysis results
     * 
     * @note Processes that cannot be memory dumped
     */
    static void PrintUndumpableProcesses() noexcept;
    
    /**
     * @brief Print usage examples with real scenarios
     * @param programName Program name for display in examples
     * 
     * Shows practical command combinations for common tasks:
     * - Process protection manipulation
     * - Password extraction
     * - System maintenance
     * - Debugging and analysis
     * 
     * @note Real-world usage scenarios
     */
    static void PrintUsageExamples(std::wstring_view programName) noexcept;
    
    /**
     * @brief Print security notice and disclaimer
     * 
     * Legal and ethical use warnings:
     * - Authorized testing only
     * - Legal compliance requirements
     * - Responsible disclosure
     * - Educational purposes
     * 
     * @note Important legal and ethical considerations
     */
    static void PrintSecurityNotice() noexcept;
    
    /**
     * @brief Print footer with donation links
     * 
     * Support information and donation links:
     * - PayPal donation link
     * - Revolut donation link
     * - Contact information
     * - Support acknowledgments
     * 
     * @note Optional support for project development
     */
    static void PrintFooter() noexcept;

private:
    // === Helper Methods for Consistent Formatting ===
    
    /**
     * @brief Print color-coded section header
     * @param title Section title to display
     * 
     * Formats section headers with yellow color for visibility
     * and consistent spacing.
     * 
     * @note Internal formatting helper
     */
    static void PrintSectionHeader(const wchar_t* title) noexcept;
    
    /**
     * @brief Print formatted command line with description
     * @param command Command syntax
     * @param description Command description
     * 
     * Displays command and description in aligned columns
     * for readability.
     * 
     * @note Internal formatting helper
     */
    static void PrintCommandLine(const wchar_t* command, const wchar_t* description) noexcept;
    
    /**
     * @brief Print informational note
     * @param note Note text to display
     * 
     * Formats informational notes with indentation and
     * "Note:" prefix.
     * 
     * @note Internal formatting helper
     */
    static void PrintNote(const wchar_t* note) noexcept;
    
    /**
     * @brief Print warning message
     * @param warning Warning text to display
     * 
     * Formats warning messages with red color, indentation,
     * and "WARNING:" prefix.
     * 
     * @note Internal formatting helper
     */
    static void PrintWarning(const wchar_t* warning) noexcept;
};