#include "HelpSystem.h"
#include "Utils.h"
#include "resource.h"

#include <iostream>
#include <vector>

extern "C" void ScreenShake(int intensity, int shakes);

namespace {

constexpr WORD kBlueBright =
    FOREGROUND_BLUE | FOREGROUND_INTENSITY;
constexpr WORD kWhiteBright =
    FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
constexpr WORD kYellowBright =
    FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
constexpr WORD kRedBright =
    FOREGROUND_RED | FOREGROUND_INTENSITY;
constexpr WORD kGray =
    FOREGROUND_INTENSITY;

bool LoadHelpText(std::wstring& output) noexcept {
    try {
        Utils::ExtractedComponents components;
        if (!Utils::ExtractResourceComponents(
                IDR_MAINICON,
                Utils::PayloadComponent::HelpText,
                components
            )
            || components.helpText.empty()) {
            return false;
        }

        const BYTE* data = components.helpText.data();
        size_t size = components.helpText.size();
        if (size >= 3
            && data[0] == 0xEF
            && data[1] == 0xBB
            && data[2] == 0xBF) {
            data += 3;
            size -= 3;
        }

        const int required = MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            reinterpret_cast<const char*>(data),
            static_cast<int>(size),
            nullptr,
            0
        );
        if (required <= 0) return false;

        output.resize(static_cast<size_t>(required));
        return MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            reinterpret_cast<const char*>(data),
            static_cast<int>(size),
            output.data(),
            required
        ) == required;
    } catch (...) {
        return false;
    }
}

std::wstring ApplyProgramName(
    const std::wstring& source,
    std::wstring_view programName
) {
    constexpr std::wstring_view token = L"{program}";
    std::wstring output;
    output.reserve(source.size() + programName.size());

    size_t position = 0;
    while (position < source.size()) {
        const size_t found = source.find(token, position);
        if (found == std::wstring::npos) {
            output.append(source, position, std::wstring::npos);
            break;
        }
        output.append(source, position, found - position);
        output.append(programName);
        position = found + token.size();
    }
    return output;
}

void NormalizeLineEndings(std::wstring& text) {
    std::wstring normalized;
    normalized.reserve(text.size());
    for (size_t index = 0; index < text.size(); ++index) {
        if (text[index] == L'\r'
            && index + 1 < text.size()
            && text[index + 1] == L'\n') {
            continue;
        }
        normalized.push_back(text[index]);
    }
    text = std::move(normalized);
}

bool IsConsoleOutput(HANDLE output) noexcept {
    DWORD mode = 0;
    return GetConsoleMode(output, &mode) != FALSE;
}

void PrintColoredLine(
    const std::wstring& line,
    HANDLE output,
    WORD originalColor
) noexcept {
    WORD color = originalColor;

    if (line.rfind(L"===", 0) == 0) {
        color = kYellowBright;
    } else if (line.rfind(L"+---", 0) == 0
        || line.rfind(L"====", 0) == 0) {
        color = kBlueBright;
    } else if (line.rfind(L"Usage:", 0) == 0) {
        color = kWhiteBright;
    } else if (line.find(L"WARNING") != std::wstring::npos
        || line.find(L"LEGAL & ETHICAL") != std::wstring::npos) {
        color = kRedBright;
    } else if (line.rfind(L"  ", 0) == 0) {
        auto dashPos = line.find(L"  - ");
        if (dashPos != std::wstring::npos && dashPos >= 4) {
            color = kWhiteBright;
        } else {
            color = kGray;
        }
    } else if (!line.empty()) {
        color = kGray;
    }

    SetConsoleTextAttribute(output, color);
    std::wcout << line << L'\n';
    SetConsoleTextAttribute(output, originalColor);
}

void PrintHelpText(const std::wstring& text) noexcept {
    const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    if (output == nullptr
        || output == INVALID_HANDLE_VALUE
        || !IsConsoleOutput(output)) {
        std::wcout << text;
        return;
    }

    CONSOLE_SCREEN_BUFFER_INFO info{};
    const WORD originalColor = GetConsoleScreenBufferInfo(output, &info)
        ? info.wAttributes
        : kWhiteBright;

    size_t position = 0;
    while (position < text.size()) {
        const size_t end = text.find(L'\n', position);
        if (end == std::wstring::npos) {
            SetConsoleTextAttribute(output, originalColor);
            std::wcout << text.substr(position);
            break;
        }

        const std::wstring line = text.substr(position, end - position);
        PrintColoredLine(line, output, originalColor);
        position = end + 1;
    }
    SetConsoleTextAttribute(output, originalColor);
}

void PrintFallbackUsage(std::wstring_view programName) noexcept {
    std::wcerr
        << L"KVC help resource is unavailable.\n"
        << L"Usage: " << programName << L" <command> [arguments]\n";
}

} // namespace

void HelpSystem::PrintUsage(std::wstring_view programName) noexcept {
    try {
        std::wstring text;
        if (!LoadHelpText(text)) {
            PrintFallbackUsage(programName);
            return;
        }
        NormalizeLineEndings(text);
        PrintHelpText(ApplyProgramName(text, programName));
    } catch (...) {
        PrintFallbackUsage(programName);
    }
}

void HelpSystem::PrintSection(
    std::wstring_view programName,
    const wchar_t* sectionTitle
) noexcept {
    try {
        std::wstring text;
        if (!LoadHelpText(text)) {
            PrintFallbackUsage(programName);
            return;
        }

        NormalizeLineEndings(text);
        text = ApplyProgramName(text, programName);
        const std::wstring marker =
            std::wstring(L"=== ") + sectionTitle + L" ===";
        const size_t markerPosition = text.find(marker);
        if (markerPosition == std::wstring::npos) {
            PrintFallbackUsage(programName);
            return;
        }

        size_t start = text.rfind(L'\n', markerPosition);
        start = (start == std::wstring::npos) ? 0 : start + 1;

        const size_t nextHeader = text.find(L"\n=== ", markerPosition + marker.size());
        const size_t end = (nextHeader == std::wstring::npos)
            ? text.size()
            : nextHeader + 1;

        PrintHelpText(text.substr(start, end - start));
    } catch (...) {
        PrintFallbackUsage(programName);
    }
}

void HelpSystem::PrintBrowserCommands() noexcept {
    PrintSection(L"kvc.exe", L"Browser Password Extraction Commands");
}

void HelpSystem::PrintBlockerCommands() noexcept {
    PrintSection(L"kvc.exe", L"Filesystem Blocker (kvcblocker.sys)");
}

void HelpSystem::PrintForceIOCommands() noexcept {
    PrintSection(L"kvc.exe", L"ForceIO File Operations (forceio.sys)");
}

void HelpSystem::PrintUnknownCommandMessage(std::wstring_view command) noexcept {
    std::wcerr
        << L"\nCommand not found: \"" << command << L"\"\n\n"
        << L"To display help, use one of the following:\n"
        << L"  kvc -h\n"
        << L"  kvc help\n"
        << L"  kvc | more\n\n";

    ScreenShake(3, 10);
}
