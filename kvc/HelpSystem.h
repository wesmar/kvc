#pragma once

#include "common.h"
#include <string_view>

// Comprehensive help system for kvc with modular command documentation
class HelpSystem
{
public:
    HelpSystem() = delete;
    ~HelpSystem() = delete;

    // Main help interface
    static void PrintUsage(std::wstring_view programName) noexcept;
    
    // Specific help sections
    static void PrintHeader() noexcept;
    static void PrintBasicCommands() noexcept;
    static void PrintProtectionCommands() noexcept;
    static void PrintSystemCommands() noexcept;
	static void PrintProcessTerminationCommands() noexcept;
    static void PrintDefenderCommands() noexcept;
    static void PrintDPAPICommands() noexcept;
	static void PrintBrowserCommands() noexcept;
    static void PrintServiceCommands() noexcept;
    static void PrintProtectionTypes() noexcept;
    static void PrintExclusionTypes() noexcept;
    static void PrintPatternMatching() noexcept;
    static void PrintTechnicalFeatures() noexcept;
    static void PrintDefenderNotes() noexcept;
	static void PrintSecurityEngineCommands() noexcept;
    static void PrintSessionManagement() noexcept;
	static void PrintStickyKeysInfo() noexcept;
    static void PrintUndumpableProcesses() noexcept;
    static void PrintUsageExamples(std::wstring_view programName) noexcept;
    static void PrintSecurityNotice() noexcept;
    static void PrintFooter() noexcept;

private:
    // Helper methods for consistent formatting
    static void PrintSectionHeader(const wchar_t* title) noexcept;
    static void PrintCommandLine(const wchar_t* command, const wchar_t* description) noexcept;
    static void PrintNote(const wchar_t* note) noexcept;
    static void PrintWarning(const wchar_t* warning) noexcept;
};