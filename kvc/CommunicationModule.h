// CommunicationModule.h - Inter-process communication and utilities
#ifndef COMMUNICATION_MODULE_H
#define COMMUNICATION_MODULE_H

#include <Windows.h>
#include <string>
#include <vector>
#include <optional>
#include <filesystem>
#include <sstream>
#include <iomanip>

namespace fs = std::filesystem;

// String utility functions for internal module use
namespace StringUtils
{
    inline std::string path_to_string(const fs::path& path)
    {
        return path.string();
    }
}

namespace SecurityComponents
{
    // Utility functions for encoding and formatting
    namespace Utils
    {
        // Retrieves Local AppData directory path
        fs::path GetLocalAppDataPath();

        // Decodes Base64 encoded string
        std::optional<std::vector<uint8_t>> Base64Decode(const std::string& input);

        // Converts bytes to hexadecimal string
        std::string BytesToHexString(const std::vector<uint8_t>& bytes);

        // Escapes special characters for JSON serialization
        std::string EscapeJson(const std::string& s);
    }

    // Manages named pipe communication with orchestrator
    class PipeLogger
    {
    public:
        explicit PipeLogger(LPCWSTR pipeName);
        ~PipeLogger();

        bool isValid() const noexcept { return m_pipe != INVALID_HANDLE_VALUE; }
        void Log(const std::string& message);
        HANDLE getHandle() const noexcept { return m_pipe; }

    private:
        HANDLE m_pipe = INVALID_HANDLE_VALUE;
    };
}

#endif // COMMUNICATION_MODULE_H