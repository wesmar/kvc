// BrowserProcessManager.cpp - Browser process management and cleanup operations
#include "BrowserProcessManager.h"
#include "RuntimeSupport.h"
#include "syscalls.h"
#include <utility>

#ifndef IMAGE_FILE_MACHINE_AMD64
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#endif

#ifndef IMAGE_FILE_MACHINE_I386
#define IMAGE_FILE_MACHINE_I386 0x014c
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Handle cleanup using direct syscall
void HandleDeleter::operator()(HANDLE h) const noexcept
{
    if (h && h != INVALID_HANDLE_VALUE)
        NtClose_syscall(h);
}

// Constructor initializes target process context
TargetProcess::TargetProcess(const Configuration& config, const Console& console) 
    : m_config(config), m_console(console) {}

// Creates suspended browser process for safe injection
bool TargetProcess::createSuspended(std::string& error)
{
    m_console.Debug("Creating suspended " + m_config.browserDisplayName + " process.");
    m_console.Debug("Target executable path: " + Utils::WStringToUtf8(m_config.browserDefaultExePath));

    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);

    if (!CreateProcessW(m_config.browserDefaultExePath.c_str(), nullptr, nullptr, nullptr,
                       FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
    {
        error = "CreateProcessW failed. Error: ";
        kvc::text::AppendUnsigned(error, GetLastError());
        return false;
    }

    m_hProcess.reset(pi.hProcess);
    m_hThread.reset(pi.hThread);
    m_pid = pi.dwProcessId;

    std::string message = "Created suspended process PID: ";
    kvc::text::AppendUnsigned(message, m_pid);
    m_console.Debug(message);
    return checkArchitecture(error);
}

// Terminates target process via direct syscall
void TargetProcess::terminate()
{
    if (m_hProcess)
    {
        std::string message = "Terminating browser PID=";
        kvc::text::AppendUnsigned(message, m_pid);
        message.append(" via direct syscall.");
        m_console.Debug(message);
        NtTerminateProcess_syscall(m_hProcess.get(), 0);
        m_console.Debug(m_config.browserDisplayName + " terminated by orchestrator.");
    }
}

// Validates matching x64 architecture
bool TargetProcess::checkArchitecture(std::string& error)
{
    USHORT processArch = 0, nativeMachine = 0;
    auto fnIsWow64Process2 = (decltype(&IsWow64Process2))GetProcAddress(
        GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2");
    if (!fnIsWow64Process2 || !fnIsWow64Process2(m_hProcess.get(), &processArch, &nativeMachine))
    {
        error = "Failed to determine target process architecture.";
        return false;
    }

    m_arch = (processArch == IMAGE_FILE_MACHINE_UNKNOWN) ? nativeMachine : processArch;
    constexpr USHORT orchestratorArch = IMAGE_FILE_MACHINE_AMD64;

    if (m_arch != orchestratorArch)
    {
        error = "Architecture mismatch. Orchestrator is x64 but target is ";
        error.append(getArchName(m_arch));
        return false;
    }

    m_console.Debug("Architecture match: Orchestrator=x64, Target=" + std::string(getArchName(m_arch)));
    return true;
}

// Returns human-readable architecture name
const char* TargetProcess::getArchName(USHORT arch) const noexcept
{
    switch (arch)
    {
    case IMAGE_FILE_MACHINE_AMD64: return "x64";
    case IMAGE_FILE_MACHINE_I386:  return "x86";
    default:                       return "Unknown";
    }
}

// Terminates all browser processes matching the target executable name
void KillBrowserProcesses(const Configuration& config, const Console& console)
{
    console.Debug("Terminating all browser processes to release file locks...");

    UniqueHandle hCurrentProc;
    HANDLE nextProcHandle = nullptr;
    int processes_terminated = 0;

    while (NT_SUCCESS(NtGetNextProcess_syscall(hCurrentProc.get(), PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE, 
                                             0, 0, &nextProcHandle)))
    {
        UniqueHandle hNextProc(nextProcHandle);
        hCurrentProc = std::move(hNextProc);
        
        std::vector<BYTE> buffer(sizeof(UNICODE_STRING_SYSCALLS) + MAX_PATH * 2);
        auto imageName = reinterpret_cast<PUNICODE_STRING_SYSCALLS>(buffer.data());
        if (!NT_SUCCESS(NtQueryInformationProcess_syscall(hCurrentProc.get(), ProcessImageFileName, 
                                                         imageName, (ULONG)buffer.size(), NULL)) || 
            imageName->Length == 0)
            continue;

        const std::wstring imagePath(imageName->Buffer, imageName->Length / sizeof(wchar_t));
        if (!kvc::text::IEqualsWide(kvc::paths::FileName(imagePath), config.browserProcessName))
            continue;
        
        PROCESS_BASIC_INFORMATION pbi{};
        if (!NT_SUCCESS(NtQueryInformationProcess_syscall(hCurrentProc.get(), ProcessBasicInformation, 
                                                         &pbi, sizeof(pbi), nullptr)) || 
            !pbi.PebBaseAddress)
            continue;

        std::string message = "Found and terminated browser process PID: ";
        kvc::text::AppendUnsigned(message, static_cast<DWORD>(pbi.UniqueProcessId));
        console.Debug(message);
        NtTerminateProcess_syscall(hCurrentProc.get(), 0);
        processes_terminated++;
    }

    if (processes_terminated > 0)
    {
        std::string message = "Terminated ";
        kvc::text::AppendSigned(message, processes_terminated);
        message.append(" browser processes. Waiting for file locks to release.");
        console.Debug(message);
        Sleep(2000); 
    }
}

// Terminates Chromium services that hold browser database handles.
void KillBrowserNetworkService(const Configuration& config, const Console& console,
                               bool waitForGracePeriod)
{
    console.Debug("Scanning for and terminating browser database services...");

    UniqueHandle hCurrentProc;
    HANDLE nextProcHandle = nullptr;
    int processes_terminated = 0;
    
    while (NT_SUCCESS(NtGetNextProcess_syscall(hCurrentProc.get(), PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE, 
                                             0, 0, &nextProcHandle)))
    {
        UniqueHandle hNextProc(nextProcHandle);
        hCurrentProc = std::move(hNextProc);
        
        std::vector<BYTE> buffer(sizeof(UNICODE_STRING_SYSCALLS) + MAX_PATH * 2);
        auto imageName = reinterpret_cast<PUNICODE_STRING_SYSCALLS>(buffer.data());
        if (!NT_SUCCESS(NtQueryInformationProcess_syscall(hCurrentProc.get(), ProcessImageFileName, 
                                                         imageName, (ULONG)buffer.size(), NULL)) || 
            imageName->Length == 0)
            continue;

        const std::wstring imagePath(imageName->Buffer, imageName->Length / sizeof(wchar_t));
        if (!kvc::text::IEqualsWide(kvc::paths::FileName(imagePath), config.browserProcessName))
            continue;
        
        PROCESS_BASIC_INFORMATION pbi{};
        if (!NT_SUCCESS(NtQueryInformationProcess_syscall(hCurrentProc.get(), ProcessBasicInformation, 
                                                         &pbi, sizeof(pbi), nullptr)) || 
            !pbi.PebBaseAddress)
            continue;

        PEB peb{};
        if (!NT_SUCCESS(NtReadVirtualMemory_syscall(hCurrentProc.get(), pbi.PebBaseAddress, &peb, sizeof(peb), nullptr)))
            continue;

        RTL_USER_PROCESS_PARAMETERS params{};
        if (!NT_SUCCESS(NtReadVirtualMemory_syscall(hCurrentProc.get(), peb.ProcessParameters, &params, sizeof(params), nullptr)))
            continue;
        
        std::vector<wchar_t> cmdLine(params.CommandLine.Length / sizeof(wchar_t) + 1, 0);
        if (params.CommandLine.Length > 0 && 
            !NT_SUCCESS(NtReadVirtualMemory_syscall(hCurrentProc.get(), params.CommandLine.Buffer, 
                                                   cmdLine.data(), params.CommandLine.Length, nullptr)))
            continue;
        
        const bool isNetworkService = kvc::text::Contains(
            cmdLine.data(), L"--utility-sub-type=network.mojom.NetworkService");
        const bool isStorageService = kvc::text::Contains(
            cmdLine.data(), L"--utility-sub-type=storage.mojom.StorageService");
        if (isNetworkService || isStorageService)
        {
            std::string message = isStorageService
                                      ? "Found and terminated storage service PID: "
                                      : "Found and terminated network service PID: ";
            kvc::text::AppendUnsigned(message, static_cast<DWORD>(pbi.UniqueProcessId));
            console.Debug(message);
            NtTerminateProcess_syscall(hCurrentProc.get(), 0);
            WaitForSingleObject(hCurrentProc.get(), 2000);
            processes_terminated++;
        }
    }

    if (processes_terminated > 0)
    {
        console.Debug("Termination sweep complete.");
        if (waitForGracePeriod)
            Sleep(1500);
    }
}

// Checks if Windows native SQLite library is available
bool CheckWinSQLite3Available()
{
    HMODULE hWinSQLite = LoadLibraryW(L"winsqlite3.dll");
    if (hWinSQLite)
    {
        FreeLibrary(hWinSQLite);
        return true;
    }
    return false;
}
