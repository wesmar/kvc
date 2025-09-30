// BrowserHelp.h - Comprehensive help and usage information for PassExtractor
#ifndef BROWSER_HELP_H
#define BROWSER_HELP_H

#include <string>

namespace BrowserHelp
{
    // Print complete usage information with formatting and colors
    void PrintUsage(std::wstring_view programName) noexcept;

    // Section printing helpers
    void PrintHeader() noexcept;
    void PrintBasicUsage(std::wstring_view programName) noexcept;
    void PrintBrowserTargets() noexcept;
    void PrintCommandLineOptions() noexcept;
    void PrintOutputFormat() noexcept;
    void PrintTechnicalFeatures() noexcept;
    void PrintUsageExamples(std::wstring_view programName) noexcept;
    void PrintRequirements() noexcept;
    void PrintBrowserSpecificNotes() noexcept;
    void PrintSecurityNotice() noexcept;
    void PrintFooter() noexcept;

    // Formatting helpers
    void PrintSectionHeader(const wchar_t* title) noexcept;
    void PrintCommandLine(const wchar_t* command, const wchar_t* description) noexcept;
    void PrintNote(const wchar_t* note) noexcept;
    void PrintWarning(const wchar_t* warning) noexcept;
}

#endif // BROWSER_HELP_H