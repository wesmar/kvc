// CommunicationModule.cpp - Pipe communication and utility functions
#include "CommunicationModule.h"
#include <ShlObj.h>
#include <Wincrypt.h>

#pragma comment(lib, "Crypt32.lib")

namespace SecurityComponents
{
    namespace Utils
    {
        // Retrieves Local AppData path
        fs::path GetLocalAppDataPath()
        {
            PWSTR path = nullptr;
            if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &path)))
            {
                fs::path result = path;
                CoTaskMemFree(path);
                return result;
            }
            throw std::runtime_error("Failed to get Local AppData path.");
        }

        // Decodes Base64 string into byte vector
        std::optional<std::vector<uint8_t>> Base64Decode(const std::string& input)
        {
            DWORD size = 0;
            if (!CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &size, nullptr, nullptr))
                return std::nullopt;
            
            std::vector<uint8_t> data(size);
            if (!CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, data.data(), &size, nullptr, nullptr))
                return std::nullopt;
            
            return data;
        }

        // Converts byte array to hex string
        std::string BytesToHexString(const std::vector<uint8_t>& bytes)
        {
            std::ostringstream oss;
            oss << std::hex << std::setfill('0');
            for (uint8_t byte : bytes)
                oss << std::setw(2) << static_cast<int>(byte);
            return oss.str();
        }

        // Escapes JSON special characters
        std::string EscapeJson(const std::string& s)
        {
            std::ostringstream o;
            for (char c : s)
            {
                switch (c)
                {
                case '"':  o << "\\\""; break;
                case '\\': o << "\\\\"; break;
                case '\b': o << "\\b"; break;
                case '\f': o << "\\f"; break;
                case '\n': o << "\\n"; break;
                case '\r': o << "\\r"; break;
                case '\t': o << "\\t"; break;
                default:
                    if ('\x00' <= c && c <= '\x1f')
                    {
                        o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
                    }
                    else
                    {
                        o << c;
                    }
                }
            }
            return o.str();
        }
    }

    // PipeLogger implementation
    PipeLogger::PipeLogger(LPCWSTR pipeName)
    {
        m_pipe = CreateFileW(pipeName, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    }

    PipeLogger::~PipeLogger()
    {
        if (m_pipe != INVALID_HANDLE_VALUE)
        {
            Log("__DLL_PIPE_COMPLETION_SIGNAL__");
            FlushFileBuffers(m_pipe);
            CloseHandle(m_pipe);
        }
    }

    void PipeLogger::Log(const std::string& message)
    {
        if (isValid())
        {
            DWORD bytesWritten = 0;
            WriteFile(m_pipe, message.c_str(), static_cast<DWORD>(message.length() + 1), &bytesWritten, nullptr);
        }
    }
}