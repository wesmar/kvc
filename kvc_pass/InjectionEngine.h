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
    InjectionManager(TargetProcess& target, const Console& console,
                     std::wstring securityModulePath);

    // Performs complete injection workflow: load, parse, inject, execute
    bool execute(const std::wstring& pipeName, std::string& error);

private:
    // Loads security module from disk into memory buffer
    bool loadSecurityModuleFromFile(std::string& error);

    // Parses PE export table to find entry point offset
    DWORD getInitializeSecurityContextOffset();

    // Creates remote thread to execute injected code
    bool startSecurityThreadInTarget(PVOID remoteModuleBase, DWORD rdiOffset,
                                     PVOID remotePipeNameAddr, std::string& error);

    TargetProcess& m_target;
    const Console& m_console;
    std::wstring m_securityModulePath;
    std::vector<BYTE> m_moduleBuffer;
};

#endif // INJECTION_ENGINE_H
