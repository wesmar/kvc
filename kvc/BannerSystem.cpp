/*******************************************************************************
  _  ____     ______ 
 | |/ /\ \   / / ___|
 | ' /  \ \ / / |    
 | . \   \ V /| |___ 
 |_|\_\   \_/  \____|

The **Kernel Vulnerability Capabilities (KVC)** framework represents a paradigm shift in Windows security research, 
offering unprecedented access to modern Windows internals through sophisticated ring-0 operations. Originally conceived 
as "Kernel Process Control," the framework has evolved to emphasize not just control, but the complete **exploitation 
of kernel-level primitives** for legitimate security research and penetration testing.

KVC addresses the critical gap left by traditional forensic tools that have become obsolete in the face of modern Windows 
security hardening. Where tools like ProcDump and Process Explorer fail against Protected Process Light (PPL) and Antimalware 
Protected Interface (AMSI) boundaries, KVC succeeds by operating at the kernel level, manipulating the very structures 
that define these protections.

  -----------------------------------------------------------------------------
  Author : Marek Wesołowski
  Email  : marek@wesolowski.eu.org
  Phone  : +48 607 440 283 (Tel/WhatsApp)
  Date   : 04-09-2025

*******************************************************************************/

// Add these functions to CommunicationLayer.cpp or create separate BannerSystem.cpp

#include <Windows.h>
#include <iostream>
#include <string>

namespace Banner
{
    // Print centered text with specified color
    void PrintCentered(HANDLE hConsole, const std::wstring& text, WORD color, int width = 80)
    {
        int textLen = static_cast<int>(text.length());
        int padding = (width - textLen) / 2;
        if (padding < 0) padding = 0;
        
        SetConsoleTextAttribute(hConsole, color);
        std::wcout << std::wstring(padding, L' ') << text << L"\n";
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
        std::wcout << L"\n";
        std::wcout << L"================================================================================\n";

        // Banner content - centered white text
        PrintCentered(hConsole, L"Marek Wesolowski - WESMAR - 2025", textColor, width);
        PrintCentered(hConsole, L"PassExtractor v1.0.1 https://kvc.pl", textColor, width);
        PrintCentered(hConsole, L"+48 607-440-283, marek@wesolowski.eu.org", textColor, width);
        PrintCentered(hConsole, L"PassExtractor - Advanced Browser Credential Extraction Framework", textColor, width);
        PrintCentered(hConsole, L"Multi-Browser Password, Cookie & Payment Data Recovery Tool", textColor, width);
        PrintCentered(hConsole, L"Chrome, Brave, Edge Support via COM Elevation & DPAPI Techniques", textColor, width);

        // Bottom border
        SetConsoleTextAttribute(hConsole, frameColor);
        std::wcout << L"================================================================================\n\n";

        // Restore original color
        SetConsoleTextAttribute(hConsole, originalColor);
    }

    // Print footer with donation information
    void PrintFooter()
    {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hConsole, &csbi);
        WORD originalColor = csbi.wAttributes;
        
        const int width = 80;
        const WORD frameColor = FOREGROUND_BLUE | FOREGROUND_INTENSITY;
        const WORD textColor = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
        const WORD linkColor = FOREGROUND_GREEN | FOREGROUND_INTENSITY;

        // Helper lambda for centered text in frame
        auto printCenteredInFrame = [&](const std::wstring& text) {
            int textLen = static_cast<int>(text.length());
            int padding = (width - 2 - textLen) / 2;
            if (padding < 0) padding = 0;

            SetConsoleTextAttribute(hConsole, frameColor);
            std::wcout << L"|";

            SetConsoleTextAttribute(hConsole, textColor);
            std::wcout << std::wstring(padding, L' ') << text
                       << std::wstring(width - 2 - padding - textLen, L' ');

            SetConsoleTextAttribute(hConsole, frameColor);
            std::wcout << L"|\n";
        };

        // Top border
        SetConsoleTextAttribute(hConsole, frameColor);
        std::wcout << L"+" << std::wstring(width-2, L'-') << L"+\n";

        // Footer content
        printCenteredInFrame(L"Support this project - a small donation is greatly appreciated");
        printCenteredInFrame(L"and helps sustain private research builds.");
        printCenteredInFrame(L"GitHub source code: https://github.com/wesmar/kvc/");
        printCenteredInFrame(L"Professional services: marek@wesolowski.eu.org");

        // Donation line with colored links
        SetConsoleTextAttribute(hConsole, frameColor);
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
        
        SetConsoleTextAttribute(hConsole, textColor);
        std::wcout << std::wstring(padding, L' ') << paypal;
        SetConsoleTextAttribute(hConsole, linkColor);
        std::wcout << paypalLink;
        SetConsoleTextAttribute(hConsole, textColor);
        std::wcout << middle << revolut;
        SetConsoleTextAttribute(hConsole, linkColor);
        std::wcout << revolutLink;
        SetConsoleTextAttribute(hConsole, textColor);
        std::wcout << std::wstring(width - totalLen - padding - 2, L' ');
        
        SetConsoleTextAttribute(hConsole, frameColor);
        std::wcout << L"|\n";

        // Bottom border
        std::wcout << L"+" << std::wstring(width-2, L'-') << L"+\n\n";

        // Restore original color
        SetConsoleTextAttribute(hConsole, originalColor);
    }
}
