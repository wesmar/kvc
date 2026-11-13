// Add these functions to CommunicationLayer.cpp or create separate BannerSystem.cpp

#include <Windows.h>
#include <string>
#include "HelpSystem.h"
#include "RuntimeSupport.h"

namespace Banner
{
    // Print centered text with specified color
    void PrintCentered(HANDLE hConsole, const std::wstring& text, WORD color, int width = 80)
    {
        int textLen = static_cast<int>(text.length());
        int padding = (width - textLen) / 2;
        if (padding < 0) padding = 0;
        
        SetConsoleTextAttribute(hConsole, color);
        kvc::console::WriteRepeatedWide(hConsole, L' ', static_cast<std::size_t>(padding));
        kvc::console::WriteWide(hConsole, text);
        kvc::console::WriteWide(hConsole, L"\n");
    }

    // Print application banner with blue frame
    void PrintHeader()
    {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hConsole, &csbi);
        WORD originalColor = csbi.wAttributes;

        const int width = 80;
        const WORD frameColor = FOREGROUND_BLUE | FOREGROUND_INTENSITY;
        const WORD textColor = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;

        // Top border
        SetConsoleTextAttribute(hConsole, frameColor);
        kvc::console::WriteWide(hConsole, L"\n");
        kvc::console::WriteWide(hConsole, HelpLayout::MakeBorder());
        kvc::console::WriteWide(hConsole, L"\n");

        // Banner content - centered white text
        PrintCentered(hConsole, L"Marek Wesolowski - WESMAR - \u00A9 2026", textColor, width);
        PrintCentered(hConsole, L"PassExtractor v1.0.5 https://kvc.pl", textColor, width);
        PrintCentered(hConsole, L"+48 607-440-283, marek@wesolowski.eu.org", textColor, width);
        PrintCentered(hConsole, L"PassExtractor - Advanced Browser Credential Extraction Framework", textColor, width);
        PrintCentered(hConsole, L"Multi-Browser Password, Cookie & Payment Data Recovery Tool", textColor, width);
        PrintCentered(hConsole, L"Chrome, Brave, Edge Support via COM Elevation & DPAPI Techniques", textColor, width);

        // Bottom border
        SetConsoleTextAttribute(hConsole, frameColor);
        kvc::console::WriteWide(hConsole, HelpLayout::MakeBorder());
        kvc::console::WriteWide(hConsole, L"\n\n");

        // Restore original color
        SetConsoleTextAttribute(hConsole, originalColor);
    }

    // Print footer - empty (donation section removed)
    void PrintFooter()
    {
    }
}
