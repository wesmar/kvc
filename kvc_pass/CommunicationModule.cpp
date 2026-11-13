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
        std::wstring GetLocalAppDataPath()
        {
            PWSTR path = nullptr;
            if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &path)))
            {
                std::wstring result = path;
                CoTaskMemFree(path);
                return result;
            }
            return {};
        }

        // Decodes Base64 string into byte vector
        std::optional<std::vector<uint8_t>> Base64Decode(std::string_view input)
        {
            const std::string inputCopy(input);
            DWORD size = 0;
            if (!CryptStringToBinaryA(inputCopy.c_str(), 0, CRYPT_STRING_BASE64,
                                      nullptr, &size, nullptr, nullptr))
                return std::nullopt;
            
            std::vector<uint8_t> data(size);
            if (!CryptStringToBinaryA(inputCopy.c_str(), 0, CRYPT_STRING_BASE64,
                                      data.data(), &size, nullptr, nullptr))
                return std::nullopt;
            
            data.resize(size);
            return data;
        }

        // Converts byte array to hex string
        std::string BytesToHexString(const std::vector<uint8_t>& bytes)
        {
            std::string result;
            result.reserve(bytes.size() * 2);
            for (uint8_t byte : bytes)
                kvc::text::AppendUnsigned(result, byte, 16, 2);
            return result;
        }

        // Escapes JSON special characters
        std::string EscapeJson(std::string_view s)
        {
            std::string result;
            result.reserve(s.size());
            for (char c : s)
            {
                switch (c)
                {
                case '"':  result.append("\\\""); break;
                case '\\': result.append("\\\\"); break;
                case '\b': result.append("\\b"); break;
                case '\f': result.append("\\f"); break;
                case '\n': result.append("\\n"); break;
                case '\r': result.append("\\r"); break;
                case '\t': result.append("\\t"); break;
                default:
                    if ('\x00' <= c && c <= '\x1f')
                    {
                        result.append("\\u");
                        kvc::text::AppendUnsigned(result, static_cast<unsigned char>(c), 16, 4);
                    }
                    else
                    {
                        result.push_back(c);
                    }
                }
            }
            return result;
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

    void PipeLogger::Log(std::string_view message)
    {
        if (isValid())
        {
            std::string terminated(message);
            terminated.push_back('\0');
            DWORD bytesWritten = 0;
            WriteFile(m_pipe, terminated.data(), static_cast<DWORD>(terminated.size()),
                      &bytesWritten, nullptr);
        }
    }

    bool PipeLogger::WaitForMessage(std::string_view expected, DWORD timeoutMs,
                                    std::string& error)
    {
        const DWORD startTime = GetTickCount();
        char buffer[256] = {};

        for (;;)
        {
            DWORD bytesAvailable = 0;
            if (!PeekNamedPipe(m_pipe, nullptr, 0, nullptr,
                               &bytesAvailable, nullptr))
            {
                error = "PeekNamedPipe failed while waiting for acknowledgment. Error: ";
                kvc::text::AppendUnsigned(error, GetLastError());
                return false;
            }

            if (bytesAvailable > 0)
            {
                if (bytesAvailable > sizeof(buffer))
                {
                    error = "Named-pipe acknowledgment is too large.";
                    return false;
                }

                DWORD bytesRead = 0;
                if (!ReadFile(m_pipe, buffer, sizeof(buffer), &bytesRead, nullptr) ||
                    bytesRead == 0)
                {
                    error = "ReadFile failed while waiting for acknowledgment. Error: ";
                    kvc::text::AppendUnsigned(error, GetLastError());
                    return false;
                }

                std::string message(buffer, bytesRead);
                if (!message.empty() && message.back() == '\0')
                    message.pop_back();
                if (message == expected)
                    return true;

                error = "Unexpected named-pipe acknowledgment: ";
                error.append(message);
                return false;
            }

            if (GetTickCount() - startTime >= timeoutMs)
            {
                error = "Timed out waiting for database-ready acknowledgment.";
                return false;
            }

            Sleep(10);
        }
    }
}
