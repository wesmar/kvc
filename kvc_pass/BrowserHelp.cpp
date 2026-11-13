// BrowserHelp.cpp - Comprehensive help system for PassExtractor
#include <windows.h>
#include "BrowserHelp.h"
#include "HelpSystem.h"
#include "RuntimeSupport.h"

namespace
{
    void WriteLine(const std::wstring& text)
    {
        kvc::console::WriteWide(text);
        kvc::console::WriteWide(L"\n");
    }

    void WritePadded(std::wstring_view text, std::size_t width)
    {
        kvc::console::WriteWide(text);
        if (text.size() < width)
            kvc::console::WriteRepeatedWide(GetStdHandle(STD_OUTPUT_HANDLE), L' ', width - text.size());
    }
}

namespace BrowserHelp
{
    void PrintUsage(std::wstring_view programName) noexcept
    {
        PrintBasicUsage(programName);
        PrintBrowserTargets();
        PrintCommandLineOptions();
        PrintOutputFormat();
        PrintTechnicalFeatures();
        PrintUsageExamples(programName);
        PrintRequirements();
        PrintBrowserSpecificNotes();
        PrintSecurityNotice();
        PrintFooter();
    }

    void PrintHeader() noexcept
    {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hConsole, &csbi);
        WORD originalColor = csbi.wAttributes;

        const int width = 80;

        // Blue header border
        SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        kvc::console::WriteWide(hConsole, L"\n");
        kvc::console::WriteWide(hConsole, HelpLayout::MakeBorder());
        kvc::console::WriteWide(hConsole, L"\n");

        // Centered text printing
        auto printCentered = [&](const std::wstring& text) {
            int textLen = static_cast<int>(text.length());
            int padding = (width - textLen) / 2;
            if (padding < 0) padding = 0;
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            kvc::console::WriteRepeatedWide(hConsole, L' ', static_cast<std::size_t>(padding));
            kvc::console::WriteWide(hConsole, text);
            kvc::console::WriteWide(hConsole, L"\n");
        };

        printCentered(L"PassExtractor - Advanced Browser Credential Extraction Framework");
        printCentered(L"Multi-Browser Password, Cookie & Payment Data Recovery Tool");
        printCentered(L"Chrome, Brave, Edge Support via COM Elevation & DPAPI Techniques");

        SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        kvc::console::WriteWide(hConsole, HelpLayout::MakeBorder());
        kvc::console::WriteWide(hConsole, L"\n\n");

        SetConsoleTextAttribute(hConsole, originalColor);
    }

    void PrintBasicUsage(std::wstring_view programName) noexcept
    {
        PrintSectionHeader(L"USAGE");
        kvc::console::WriteWide(L"  ");
        kvc::console::WriteWide(programName);
        kvc::console::WriteWide(L" <browser_target> [options]\n");
        kvc::console::WriteWide(L"  ");
        kvc::console::WriteWide(programName);
        kvc::console::WriteWide(L" --help\n\n");
    }

    void PrintBrowserTargets() noexcept
    {
        PrintSectionHeader(L"BROWSER TARGETS");
        PrintCommandLine(L"chrome", L"Google Chrome (COM Elevation + AES-GCM)");
        PrintCommandLine(L"brave", L"Brave Browser (COM Elevation + AES-GCM)");
        PrintCommandLine(L"edge", L"Microsoft Edge (Split-Key Strategy: COM + DPAPI)");
        PrintCommandLine(L"all", L"All installed browsers (automatic detection)");
        kvc::console::WriteWide(L"\n");
    }

    void PrintCommandLineOptions() noexcept
    {
        PrintSectionHeader(L"OPTIONS");
        PrintCommandLine(L"-o, --output-path <path>", L"Output directory (default: .\\output\\)");
        PrintCommandLine(L"-v, --verbose", L"Enable detailed debug output");
        PrintCommandLine(L"--json-only", L"Extract only JSON files (skip reports)");
        PrintCommandLine(L"--quiet", L"Minimal output (errors only)");
        PrintCommandLine(L"--profile <name>", L"Extract specific browser profile only");
        PrintCommandLine(L"-h, --help", L"Show this help message");
        kvc::console::WriteWide(L"\n");
    }

    void PrintOutputFormat() noexcept
    {
        PrintSectionHeader(L"OUTPUT FORMAT");
        kvc::console::WriteWide(L"  JSON Files (all browsers):\n");
        kvc::console::WriteWide(L"    passwords.json    - Decrypted login credentials\n");
        kvc::console::WriteWide(L"    cookies.json      - Session cookies with tokens\n");
        kvc::console::WriteWide(L"    payments.json     - Credit card data with CVCs\n\n");
    }

    void PrintTechnicalFeatures() noexcept
    {
        PrintSectionHeader(L"TECHNICAL FEATURES");
        kvc::console::WriteWide(L"  - COM elevation service exploitation (Chrome/Brave/Edge cookies+payments)\n");
        kvc::console::WriteWide(L"  - DPAPI extraction for Edge passwords (orchestrator-side)\n");
        kvc::console::WriteWide(L"  - Split-key strategy for Edge (different keys per data type)\n");
        kvc::console::WriteWide(L"  - Direct syscall invocation for stealth operations\n");
        kvc::console::WriteWide(L"  - Process injection with custom PE loader\n");
        kvc::console::WriteWide(L"  - AES-GCM decryption with v10/v20 scheme support\n");
        kvc::console::WriteWide(L"  - Automatic profile discovery and enumeration\n");
        kvc::console::WriteWide(L"  - Multi-threaded extraction pipeline\n\n");
    }

    void PrintUsageExamples(std::wstring_view programName) noexcept
    {
        PrintSectionHeader(L"USAGE EXAMPLES");
        const int commandWidth = 50;

        auto printLine = [&](const std::wstring& command, const std::wstring& description) {
            kvc::console::WriteWide(L"  ");
            const std::wstring fullCommand = std::wstring(programName) + L" " + command;
            WritePadded(fullCommand, static_cast<std::size_t>(commandWidth));
            kvc::console::WriteWide(L"# ");
            kvc::console::WriteWide(description);
            kvc::console::WriteWide(L"\n");
        };

        printLine(L"chrome", L"Extract Chrome to .\\output\\");
        printLine(L"edge -o C:\\reports", L"Edge to custom directory");
        printLine(L"brave --verbose", L"Brave with debug output");
        printLine(L"all", L"All browsers to .\\output\\");
        printLine(L"chrome -o D:\\data -v", L"Combined options");
        printLine(L"edge --json-only", L"Edge JSON files only");
        printLine(L"chrome --profile Default", L"Extract specific profile");
        printLine(L"all --quiet -o C:\\dumps", L"Silent extraction to custom path");

        kvc::console::WriteWide(L"\n");
    }

    void PrintRequirements() noexcept
    {
        PrintSectionHeader(L"REQUIREMENTS");
        kvc::console::WriteWide(L"  - Windows 10/11 (x64 architecture)\n");
        kvc::console::WriteWide(L"  - Administrator privileges required\n");
        kvc::console::WriteWide(L"  - kvc_crypt.dll (security module)\n");
        kvc::console::WriteWide(L"  - Target browser must be installed\n\n");
    }

    void PrintBrowserSpecificNotes() noexcept
    {
        PrintSectionHeader(L"BROWSER-SPECIFIC BEHAVIOR");
        
        kvc::console::WriteWide(L"  Chrome/Brave:\n");
        kvc::console::WriteWide(L"    - Single COM-elevated key for all data types\n");
        kvc::console::WriteWide(L"    - Requires browser process for COM elevation\n");
        kvc::console::WriteWide(L"    - Extracts passwords, cookies, payment cards\n\n");
        
        kvc::console::WriteWide(L"  Edge:\n");
        kvc::console::WriteWide(L"    - Split-key strategy (COM + DPAPI)\n");
        kvc::console::WriteWide(L"    - COM key: cookies and payment data\n");
        kvc::console::WriteWide(L"    - DPAPI key: passwords (no browser process needed)\n\n");
    }

    void PrintSecurityNotice() noexcept
    {
        PrintSectionHeader(L"SECURITY & LEGAL NOTICE");

        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hConsole, &csbi);
        WORD originalColor = csbi.wAttributes;

        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
        kvc::console::WriteWide(hConsole, L"  WARNING: ADVANCED CREDENTIAL EXTRACTION TOOL\n\n");
        SetConsoleTextAttribute(hConsole, originalColor);

        kvc::console::WriteWide(hConsole, L"  CAPABILITIES:\n");
        kvc::console::WriteWide(hConsole, L"  - Extracts encrypted browser credentials (passwords, cookies, payments)\n");
        kvc::console::WriteWide(hConsole, L"  - Uses COM elevation bypass and DPAPI extraction techniques\n");
        kvc::console::WriteWide(hConsole, L"  - Direct syscall invocation for stealth operations\n");
        kvc::console::WriteWide(hConsole, L"  - Process injection and memory manipulation\n\n");

        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        kvc::console::WriteWide(hConsole, L"  LEGAL & ETHICAL RESPONSIBILITY:\n");
        SetConsoleTextAttribute(hConsole, originalColor);
        kvc::console::WriteWide(hConsole, L"  - Intended for authorized penetration testing and security research only\n");
        kvc::console::WriteWide(hConsole, L"  - User assumes full legal responsibility for all actions performed\n");
        kvc::console::WriteWide(hConsole, L"  - Ensure proper authorization before using on any system\n");
        kvc::console::WriteWide(hConsole, L"  - Misuse may violate computer crime laws in your jurisdiction\n\n");

        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
        kvc::console::WriteWide(hConsole, L"  By using this tool, you acknowledge understanding and accept full responsibility.\n\n");
        SetConsoleTextAttribute(hConsole, originalColor);
    }

    void PrintFooter() noexcept
    {
    }

    void PrintSectionHeader(const wchar_t* title) noexcept
    {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hConsole, &csbi);
        WORD originalColor = csbi.wAttributes;

        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        kvc::console::WriteWide(hConsole, L"=== ");
        kvc::console::WriteWide(hConsole, title);
        kvc::console::WriteWide(hConsole, L" ===\n");

        SetConsoleTextAttribute(hConsole, originalColor);
    }

    void PrintCommandLine(const wchar_t* command, const wchar_t* description) noexcept
    {
        const int commandWidth = 50;
        kvc::console::WriteWide(L"  ");
        WritePadded(command, static_cast<std::size_t>(commandWidth));
        kvc::console::WriteWide(L"- ");
        kvc::console::WriteWide(description);
        kvc::console::WriteWide(L"\n");
    }

    void PrintNote(const wchar_t* note) noexcept
    {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hConsole, &csbi);
        WORD originalColor = csbi.wAttributes;

        SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY);
        kvc::console::WriteWide(hConsole, L"  ");
        kvc::console::WriteWide(hConsole, note);
        kvc::console::WriteWide(hConsole, L"\n");

        SetConsoleTextAttribute(hConsole, originalColor);
    }

    void PrintWarning(const wchar_t* warning) noexcept
    {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hConsole, &csbi);
        WORD originalColor = csbi.wAttributes;

        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
        kvc::console::WriteWide(hConsole, L"  ");
        kvc::console::WriteWide(hConsole, warning);
        kvc::console::WriteWide(hConsole, L"\n");

        SetConsoleTextAttribute(hConsole, originalColor);
    }
}
