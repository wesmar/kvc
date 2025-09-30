// InjectionEngine.h - PE injection and remote execution management
#ifndef INJECTION_ENGINE_H
#define INJECTION_ENGINE_H

#include <Windows.h>
#include <vector>
#include <string>
#include "BrowserProcessManager.h"
#include "CommunicationLayer.h"

// Handles DLL injection and remote thread execution
class InjectionManager
{
public:
    InjectionManager(TargetProcess& target, const Console& console);

    // Performs complete injection workflow: load, parse, inject, execute
    void execute(const std::wstring& pipeName);

private:
    // Loads security module from disk into memory buffer
    void loadSecurityModuleFromFile(const std::string& modulePath);

    // Parses PE export table to find entry point offset
    DWORD getInitializeSecurityContextOffset();

    // Creates remote thread to execute injected code
    void startSecurityThreadInTarget(PVOID remoteModuleBase, DWORD rdiOffset, PVOID remotePipeNameAddr);

    TargetProcess& m_target;
    const Console& m_console;
    std::vector<BYTE> m_moduleBuffer;
};

#endif // INJECTION_ENGINE_H