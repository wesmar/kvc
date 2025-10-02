// BrowserHelp.cpp - Comprehensive help system for PassExtractor
#include <windows.h>
#include "BrowserHelp.h"
#include <iostream>
#include <iomanip>

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
        std::wcout << L"\n";
        std::wcout << L"================================================================================\n";

        // Centered text printing
        auto printCentered = [&](const std::wstring& text) {
            int textLen = static_cast<int>(text.length());
            int padding = (width - textLen) / 2;
            if (padding < 0) padding = 0;
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            std::wcout << std::wstring(padding, L' ') << text << L"\n";
        };

        printCentered(L"PassExtractor - Advanced Browser Credential Extraction Framework");
        printCentered(L"Multi-Browser Password, Cookie & Payment Data Recovery Tool");
        printCentered(L"Chrome, Brave, Edge Support via COM Elevation & DPAPI Techniques");

        SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        std::wcout << L"================================================================================\n\n";

        SetConsoleTextAttribute(hConsole, originalColor);
    }

    void PrintBasicUsage(std::wstring_view programName) noexcept
    {
        PrintSectionHeader(L"USAGE");
        std::wcout << L"  " << programName << L" <browser_target> [options]\n";
        std::wcout << L"  " << programName << L" --help\n\n";
    }

    void PrintBrowserTargets() noexcept
    {
        PrintSectionHeader(L"BROWSER TARGETS");
        PrintCommandLine(L"chrome", L"Google Chrome (COM Elevation + AES-GCM)");
        PrintCommandLine(L"brave", L"Brave Browser (COM Elevation + AES-GCM)");
        PrintCommandLine(L"edge", L"Microsoft Edge (Split-Key Strategy: COM + DPAPI)");
        PrintCommandLine(L"all", L"All installed browsers (automatic detection)");
        std::wcout << L"\n";
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
        std::wcout << L"\n";
    }

    void PrintOutputFormat() noexcept
    {
        PrintSectionHeader(L"OUTPUT FORMAT");
        std::wcout << L"  JSON Files (all browsers):\n";
        std::wcout << L"    passwords.json    - Decrypted login credentials\n";
        std::wcout << L"    cookies.json      - Session cookies with tokens\n";
        std::wcout << L"    payments.json     - Credit card data with CVCs\n\n";
    }

    void PrintTechnicalFeatures() noexcept
    {
        PrintSectionHeader(L"TECHNICAL FEATURES");
        std::wcout << L"  - COM elevation service exploitation (Chrome/Brave/Edge cookies+payments)\n";
        std::wcout << L"  - DPAPI extraction for Edge passwords (orchestrator-side)\n";
        std::wcout << L"  - Split-key strategy for Edge (different keys per data type)\n";
        std::wcout << L"  - Direct syscall invocation for stealth operations\n";
        std::wcout << L"  - Process injection with custom PE loader\n";
        std::wcout << L"  - AES-GCM decryption with v10/v20 scheme support\n";
        std::wcout << L"  - Automatic profile discovery and enumeration\n";
        std::wcout << L"  - Multi-threaded extraction pipeline\n\n";
    }

    void PrintUsageExamples(std::wstring_view programName) noexcept
    {
        PrintSectionHeader(L"USAGE EXAMPLES");
        const int commandWidth = 50;

        auto printLine = [&](const std::wstring& command, const std::wstring& description) {
            std::wcout << L"  " << std::left << std::setw(commandWidth)
                       << (std::wstring(programName) + L" " + command)
                       << L"# " << description << L"\n";
        };

        printLine(L"chrome", L"Extract Chrome to .\\output\\");
        printLine(L"edge -o C:\\reports", L"Edge to custom directory");
        printLine(L"brave --verbose", L"Brave with debug output");
        printLine(L"all", L"All browsers to .\\output\\");
        printLine(L"chrome -o D:\\data -v", L"Combined options");
        printLine(L"edge --json-only", L"Edge JSON files only");
        printLine(L"chrome --profile Default", L"Extract specific profile");
        printLine(L"all --quiet -o C:\\dumps", L"Silent extraction to custom path");

        std::wcout << L"\n";
    }

    void PrintRequirements() noexcept
    {
        PrintSectionHeader(L"REQUIREMENTS");
        std::wcout << L"  - Windows 10/11 (x64 architecture)\n";
        std::wcout << L"  - Administrator privileges required\n";
        std::wcout << L"  - kvc_crypt.dll (security module)\n";
        std::wcout << L"  - Target browser must be installed\n\n";
    }

    void PrintBrowserSpecificNotes() noexcept
    {
        PrintSectionHeader(L"BROWSER-SPECIFIC BEHAVIOR");
        
        std::wcout << L"  Chrome/Brave:\n";
        std::wcout << L"    - Single COM-elevated key for all data types\n";
        std::wcout << L"    - Requires browser process for COM elevation\n";
        std::wcout << L"    - Extracts passwords, cookies, payment cards\n\n";
        
        std::wcout << L"  Edge:\n";
        std::wcout << L"    - Split-key strategy (COM + DPAPI)\n";
        std::wcout << L"    - COM key: cookies and payment data\n";
        std::wcout << L"    - DPAPI key: passwords (no browser process needed)\n\n";
    }

    void PrintSecurityNotice() noexcept
    {
        PrintSectionHeader(L"SECURITY & LEGAL NOTICE");

        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hConsole, &csbi);
        WORD originalColor = csbi.wAttributes;

        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::wcout << L"  WARNING: ADVANCED CREDENTIAL EXTRACTION TOOL\n\n";
        SetConsoleTextAttribute(hConsole, originalColor);

        std::wcout << L"  CAPABILITIES:\n";
        std::wcout << L"  - Extracts encrypted browser credentials (passwords, cookies, payments)\n";
        std::wcout << L"  - Uses COM elevation bypass and DPAPI extraction techniques\n";
        std::wcout << L"  - Direct syscall invocation for stealth operations\n";
        std::wcout << L"  - Process injection and memory manipulation\n\n";

        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::wcout << L"  LEGAL & ETHICAL RESPONSIBILITY:\n";
        SetConsoleTextAttribute(hConsole, originalColor);
        std::wcout << L"  - Intended for authorized penetration testing and security research only\n";
        std::wcout << L"  - User assumes full legal responsibility for all actions performed\n";
        std::wcout << L"  - Ensure proper authorization before using on any system\n";
        std::wcout << L"  - Misuse may violate computer crime laws in your jurisdiction\n\n";

        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::wcout << L"  By using this tool, you acknowledge understanding and accept full responsibility.\n\n";
        SetConsoleTextAttribute(hConsole, originalColor);
    }

    void PrintFooter() noexcept
    {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hConsole, &csbi);
        WORD originalColor = csbi.wAttributes;

        const int width = 80;

        SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        std::wcout << L"+" << std::wstring(width-2, L'-') << L"+\n";

        auto printCenteredFooter = [&](const std::wstring& text) {
            int textLen = static_cast<int>(text.length());
            int padding = (width - 2 - textLen) / 2;
            if (padding < 0) padding = 0;

            SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            std::wcout << L"|";

            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            std::wcout << std::wstring(padding, L' ') << text
                       << std::wstring(width - 2 - padding - textLen, L' ');

            SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            std::wcout << L"|\n";
        };

        printCenteredFooter(L"Support this project - a small donation is greatly appreciated");
        printCenteredFooter(L"and helps sustain private research builds.");
        printCenteredFooter(L"GitHub source code: https://github.com/wesmar/kvc/");
        printCenteredFooter(L"Professional services: marek@wesolowski.eu.org");

        SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        std::wcout << L"|";

        std::wstring paypal = L"PayPal: ";
        std::wstring paypalLink = L"paypal.me/ext1";
        std::wstring middle = L"        ";
        std::wstring revolut = L"Revolut: ";
        std::wstring revolutLink = L"revolut.me/marekb92";

        int totalLen = static_cast<int>(paypal.length() + paypalLink.length() +
                                       middle.length() + revolut.length() + revolutLink.length());
        int padding = (width - totalLen - 2) / 2;
        if (padding < 0) padding = 0;

        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        std::wcout << std::wstring(padding, L' ') << paypal;
        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::wcout << paypalLink;
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        std::wcout << middle << revolut;
        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::wcout << revolutLink;
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        std::wcout << std::wstring(width - totalLen - padding - 2, L' ');

        SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        std::wcout << L"|\n";

        std::wcout << L"+" << std::wstring(width-2, L'-') << L"+\n\n";

        SetConsoleTextAttribute(hConsole, originalColor);
    }

    void PrintSectionHeader(const wchar_t* title) noexcept
    {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hConsole, &csbi);
        WORD originalColor = csbi.wAttributes;

        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::wcout << L"=== " << title << L" ===\n";

        SetConsoleTextAttribute(hConsole, originalColor);
    }

    void PrintCommandLine(const wchar_t* command, const wchar_t* description) noexcept
    {
        const int commandWidth = 50;
        std::wcout << L"  " << std::left << std::setw(commandWidth)
                   << command << L"- " << description << L"\n";
    }

    void PrintNote(const wchar_t* note) noexcept
    {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hConsole, &csbi);
        WORD originalColor = csbi.wAttributes;

        SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY);
        std::wcout << L"  " << note << L"\n";

        SetConsoleTextAttribute(hConsole, originalColor);
    }

    void PrintWarning(const wchar_t* warning) noexcept
    {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hConsole, &csbi);
        WORD originalColor = csbi.wAttributes;

        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::wcout << L"  " << warning << L"\n";

        SetConsoleTextAttribute(hConsole, originalColor);
    }
}