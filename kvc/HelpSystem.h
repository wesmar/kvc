// HelpSystem.h
// Comprehensive help system with modular command documentation
// Author: Marek Wesolowski, 2025

#pragma once

#include "common.h"
#include <string_view>

// Static help system - no instantiation needed
class HelpSystem
{
public:
    HelpSystem() = delete;
    ~HelpSystem() = delete;

    // Main help interface
    static void PrintUsage(std::wstring_view programName) noexcept;
    static void PrintHeader() noexcept;
    static void PrintUnknownCommandMessage(std::wstring_view command) noexcept;
    
    // Command category sections
    static void PrintServiceCommands() noexcept;
    static void PrintDSECommands() noexcept;
    static void PrintDriverCommands() noexcept;
    static void PrintBasicCommands() noexcept;
    static void PrintModuleCommands() noexcept;
    static void PrintProcessTerminationCommands() noexcept;
    static void PrintProtectionCommands() noexcept;
    static void PrintSessionManagement() noexcept;
    static void PrintSystemCommands() noexcept;
    static void PrintRegistryCommands() noexcept;
    static void PrintBrowserCommands() noexcept;
    static void PrintDefenderCommands() noexcept;
    static void PrintSecurityEngineCommands() noexcept;
    static void PrintDPAPICommands() noexcept;
    static void PrintWatermarkCommands() noexcept;
    
    // Documentation sections
    static void PrintProtectionTypes() noexcept;
    static void PrintExclusionTypes() noexcept;
    static void PrintPatternMatching() noexcept;
    static void PrintTechnicalFeatures() noexcept;
    static void PrintDefenderNotes() noexcept;
    static void PrintStickyKeysInfo() noexcept;
    static void PrintUndumpableProcesses() noexcept;
    static void PrintUsageExamples(std::wstring_view programName) noexcept;
    static void PrintSecurityNotice() noexcept;
    static void PrintFooter() noexcept;

private:
    // Formatting helpers
    static void PrintSectionHeader(const wchar_t* title) noexcept;
    static void PrintCommandLine(const wchar_t* command, const wchar_t* description) noexcept;
    static void PrintNote(const wchar_t* note) noexcept;
    static void PrintWarning(const wchar_t* warning) noexcept;
};