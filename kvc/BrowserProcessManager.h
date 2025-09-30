// BrowserProcessManager.h - Browser process lifecycle and cleanup management
#ifndef BROWSER_PROCESS_MANAGER_H
#define BROWSER_PROCESS_MANAGER_H

#include <Windows.h>
#include "OrchestratorCore.h"
#include "CommunicationLayer.h"

// RAII wrapper for Windows handle management with syscall-based cleanup
struct HandleDeleter
{
    void operator()(HANDLE h) const noexcept;
};
using UniqueHandle = std::unique_ptr<void, HandleDeleter>;

// Manages target browser process lifecycle
class TargetProcess
{
public:
    TargetProcess(const Configuration& config, const Console& console);

    // Creates browser process in suspended state for injection
    void createSuspended();

    // Terminates the target process using direct syscall
    void terminate();

    HANDLE getProcessHandle() const noexcept { return m_hProcess.get(); }

private:
    // Validates architecture compatibility between orchestrator and target
    void checkArchitecture();
    const char* getArchName(USHORT arch) const noexcept;

    const Configuration& m_config;
    const Console& m_console;
    DWORD m_pid = 0;
    UniqueHandle m_hProcess;
    UniqueHandle m_hThread;
    USHORT m_arch = 0;
};

// Terminates all running browser processes to release database file locks
void KillBrowserProcesses(const Configuration& config, const Console& console);

// Terminates browser network service which often holds database locks
void KillBrowserNetworkService(const Configuration& config, const Console& console);

// Checks availability of Windows native SQLite library
bool CheckWinSQLite3Available();

#endif // BROWSER_PROCESS_MANAGER_H