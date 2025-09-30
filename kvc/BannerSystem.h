// BannerSystem.h - Application banner and footer management
#ifndef BANNER_SYSTEM_H
#define BANNER_SYSTEM_H

#include <Windows.h>
#include <string>

namespace Banner
{
    // Print centered text with specified color
    void PrintCentered(HANDLE hConsole, const std::wstring& text, WORD color, int width = 80);

    // Print application banner with blue frame
    void PrintHeader();

    // Print footer with donation information
    void PrintFooter();
}

#endif // BANNER_SYSTEM_H