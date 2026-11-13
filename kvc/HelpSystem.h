#pragma once

#include <string>
#include <string_view>

namespace HelpLayout {
    inline constexpr int WIDTH = 80;
    inline constexpr int COMMAND_WIDTH = 50;
    inline constexpr int EXAMPLE_CMD_WIDTH = 60;

    inline std::wstring MakeBorder(wchar_t ch = L'=', int count = WIDTH) {
        return std::wstring(count, ch);
    }

    inline std::string MakeBorderA(char ch = '=', int count = WIDTH) {
        return std::string(count, ch);
    }
}

class HelpSystem {
public:
    static void PrintUsage(std::wstring_view programName) noexcept;
    static void PrintUnknownCommandMessage(std::wstring_view command) noexcept;
    static void PrintBrowserCommands() noexcept;
    static void PrintBlockerCommands() noexcept;
    static void PrintForceIOCommands() noexcept;

private:
    static void PrintSection(
        std::wstring_view programName,
        const wchar_t* sectionTitle
    ) noexcept;
};
