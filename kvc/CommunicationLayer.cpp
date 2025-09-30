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

// CommunicationLayer.cpp - Console and pipe communication implementation
#include "CommunicationLayer.h"
#include "syscalls.h"
#include <ShlObj.h>
#include <Rpc.h>
#include <iostream>
#include <algorithm>

#pragma comment(lib, "Rpcrt4.lib")

constexpr DWORD MODULE_COMPLETION_TIMEOUT_MS = 60000;

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Utility function implementations
namespace Utils
{
    std::string u8string_to_string(const std::u8string& u8str) noexcept
    {
        return {reinterpret_cast<const char*>(u8str.c_str()), u8str.size()};
    }

    std::string path_to_api_string(const fs::path& path)
    {
        return u8string_to_string(path.u8string());
    }
    
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

    std::string WStringToUtf8(std::wstring_view w_sv)
    {
        if (w_sv.empty()) return {};

        int size_needed = WideCharToMultiByte(CP_UTF8, 0, w_sv.data(), static_cast<int>(w_sv.length()),
                                            nullptr, 0, nullptr, nullptr);
        std::string utf8_str(size_needed, '\0');
        WideCharToMultiByte(CP_UTF8, 0, w_sv.data(), static_cast<int>(w_sv.length()),
                          &utf8_str[0], size_needed, nullptr, nullptr);
        return utf8_str;
    }

    std::string PtrToHexStr(const void* ptr) noexcept
    {
        std::ostringstream oss;
        oss << "0x" << std::hex << reinterpret_cast<uintptr_t>(ptr);
        return oss.str();
    }

    std::string NtStatusToString(NTSTATUS status) noexcept
    {
        std::ostringstream oss;
        oss << "0x" << std::hex << status;
        return oss.str();
    }

    std::wstring GenerateUniquePipeName()
    {
        UUID uuid;
        UuidCreate(&uuid);
        wchar_t* uuidStrRaw = nullptr;
        UuidToStringW(&uuid, (RPC_WSTR*)&uuidStrRaw);
        std::wstring pipeName = L"\\\\.\\pipe\\" + std::wstring(uuidStrRaw);
        RpcStringFreeW((RPC_WSTR*)&uuidStrRaw);
        return pipeName;
    }

    std::string Capitalize(const std::string& str)
    {
        if (str.empty()) return str;
        std::string result = str;
        result[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(result[0])));
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

void Console::displayBanner() const
{
    SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
    std::cout << "PassExtractor x64 | 1.0.1 by WESMAR\n\n";
    ResetColor();
}

void Console::printUsage() const
{
    SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::wcout << L"Usage:\n"
               << L"  kvc_pass.exe [options] <chrome|brave|edge|all>\n\n"
               << L"Options:\n"
               << L"  --output-path|-o <path>  Directory for output files (default: .\\output\\)\n"
               << L"  --verbose|-v             Enable verbose debug output from the orchestrator\n"
               << L"  --help|-h                Show this help message\n\n"
               << L"Browser targets:\n"
               << L"  chrome  - Extract from Google Chrome\n"
               << L"  brave   - Extract from Brave Browser\n"
               << L"  edge    - Extract from Microsoft Edge\n"
               << L"  all     - Extract from all installed browsers\n\n"
               << L"Required files:\n"
               << L"  kvc_crypt.dll - Security module (same directory)\n"
               << L"  winsqlite3.dll - SQLite library (system32) or sqlite3.dll fallback\n";
    ResetColor();
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
        std::cout << message.substr(0, tagStart);
        std::string tag = message.substr(tagStart, tagEnd - tagStart + 1);

        WORD color = m_originalAttributes;
        if (tag == "[+]") color = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        else if (tag == "[-]") color = FOREGROUND_RED | FOREGROUND_INTENSITY;
        else if (tag == "[*]") color = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        else if (tag == "[!]") color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;

        SetColor(color);
        std::cout << tag;
        ResetColor();
        std::cout << message.substr(tagEnd + 1) << std::endl;
    }
    else
    {
        std::cout << message << std::endl;
    }
}

void Console::print(const std::string& tag, const std::string& msg, WORD color) const
{
    SetColor(color);
    std::cout << tag;
    ResetColor();
    std::cout << " " << msg << std::endl;
}

void Console::SetColor(WORD attributes) const noexcept { SetConsoleTextAttribute(m_hConsole, attributes); }
void Console::ResetColor() const noexcept { SetConsoleTextAttribute(m_hConsole, m_originalAttributes); }

// PipeCommunicator implementation
PipeCommunicator::PipeCommunicator(const std::wstring& pipeName, const Console& console) 
    : m_pipeName(pipeName), m_console(console) {}

void PipeCommunicator::create()
{
    m_pipeHandle.reset(CreateNamedPipeW(m_pipeName.c_str(), PIPE_ACCESS_DUPLEX,
                                      PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                                      1, 4096, 4096, 0, nullptr));
    if (!m_pipeHandle)
        throw std::runtime_error("CreateNamedPipeW failed. Error: " + std::to_string(GetLastError()));

    m_console.Debug("Named pipe server created: " + Utils::WStringToUtf8(m_pipeName));
}

void PipeCommunicator::waitForClient()
{
    m_console.Debug("Waiting for security module to connect to named pipe.");
    if (!ConnectNamedPipe(m_pipeHandle.get(), nullptr) && GetLastError() != ERROR_PIPE_CONNECTED)
        throw std::runtime_error("ConnectNamedPipe failed. Error: " + std::to_string(GetLastError()));

    m_console.Debug("Security module connected to named pipe.");
}

void PipeCommunicator::sendInitialData(bool isVerbose, const fs::path& outputPath, const std::vector<uint8_t>& edgeDpapiKey)
{
    writeMessage(isVerbose ? "VERBOSE_TRUE" : "VERBOSE_FALSE");
    writeMessage(Utils::path_to_api_string(outputPath));
    
    // Send DPAPI key as hex string (or "NONE" if empty)
    if (!edgeDpapiKey.empty())
    {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (uint8_t byte : edgeDpapiKey)
            oss << std::setw(2) << static_cast<int>(byte);
        writeMessage("DPAPI_KEY:" + oss.str());
    }
    else
    {
        writeMessage("DPAPI_KEY:NONE");
    }
}

void PipeCommunicator::relayMessages()
{
    m_console.Debug("Waiting for security module execution. (Pipe: " + Utils::WStringToUtf8(m_pipeName) + ")");

    if (m_console.m_verbose)
        std::cout << std::endl;

    const std::string moduleCompletionSignal = "__DLL_PIPE_COMPLETION_SIGNAL__";
    DWORD startTime = GetTickCount();
    std::string accumulatedData;
    char buffer[4096];
    bool completed = false;

    while (!completed && (GetTickCount() - startTime < MODULE_COMPLETION_TIMEOUT_MS))
    {
        DWORD bytesAvailable = 0;
        if (!PeekNamedPipe(m_pipeHandle.get(), nullptr, 0, nullptr, &bytesAvailable, nullptr))
        {
            if (GetLastError() == ERROR_BROKEN_PIPE)
                break;
            m_console.Error("PeekNamedPipe failed. Error: " + std::to_string(GetLastError()));
            break;
        }

        if (bytesAvailable == 0)
        {
            Sleep(100);
            continue;
        }

        DWORD bytesRead = 0;
        if (!ReadFile(m_pipeHandle.get(), buffer, sizeof(buffer) - 1, &bytesRead, nullptr) || bytesRead == 0)
        {
            if (GetLastError() == ERROR_BROKEN_PIPE)
                break;
            continue;
        }

        accumulatedData.append(buffer, bytesRead);

        size_t messageStart = 0;
        size_t nullPos;
        while ((nullPos = accumulatedData.find('\0', messageStart)) != std::string::npos)
        {
            std::string message = accumulatedData.substr(messageStart, nullPos - messageStart);
            messageStart = nullPos + 1;

            if (message == moduleCompletionSignal)
            {
                m_console.Debug("Security module completion signal received.");
                completed = true;
                break;
            }

            parseExtractionMessage(message);

            if (!message.empty() && m_console.m_verbose)
                m_console.Relay(message);
        }
        
        if (completed)
            break;
            
        accumulatedData.erase(0, messageStart);
    }

    if (m_console.m_verbose)
        std::cout << std::endl;

    m_console.Debug("Security module signaled completion or pipe interaction ended.");
}

void PipeCommunicator::writeMessage(const std::string& msg)
{
    DWORD bytesWritten = 0;
    if (!WriteFile(m_pipeHandle.get(), msg.c_str(), static_cast<DWORD>(msg.length() + 1), &bytesWritten, nullptr) ||
        bytesWritten != (msg.length() + 1))
        throw std::runtime_error("WriteFile to pipe failed for message: " + msg);

    m_console.Debug("Sent message to pipe: " + msg);
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
        
        try {
            return std::stoi(message.substr(start, end - start));
        }
        catch (...) {
            return 0;
        }
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
        if (!path.empty() && fs::exists(path))
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
        m_console.Warn("No supported browsers found installed on this system");
    else
        m_console.Debug("Found " + std::to_string(installedBrowsers.size()) + " browser(s) to process");

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