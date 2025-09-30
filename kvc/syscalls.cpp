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

// syscalls.cpp
#include "syscalls.h"
#include <vector>
#include <string>
#include <algorithm>
#include <cstdint>
#include <map>

SYSCALL_STUBS g_syscall_stubs{};

// External assembly trampoline for syscall ABI transition
extern "C" NTSTATUS AbiTramp(...);

namespace
{
    // Syscall mapping structure for address-based sorting
    struct SORTED_SYSCALL_MAPPING
    {
        PVOID pAddress;
        LPCSTR szName;
    };

    // Comparator for syscall address sorting to determine SSNs
    bool CompareSyscallMappings(const SORTED_SYSCALL_MAPPING &a, const SORTED_SYSCALL_MAPPING &b)
    {
        return reinterpret_cast<uintptr_t>(a.pAddress) < reinterpret_cast<uintptr_t>(b.pAddress);
    }

    // Locate syscall gadget within function prologue for x64 architecture
    PVOID FindSyscallGadget_x64(PVOID pFunction)
    {
        for (DWORD i = 0; i <= 64; ++i)
        {
            auto current_addr = reinterpret_cast<PBYTE>(pFunction) + i;

            // Skip relative jump instructions
            if (*current_addr == 0xE9) // jmp rel32
            {
                i += 4;
                continue;
            }

            // Look for syscall; ret instruction sequence
            if (*reinterpret_cast<PWORD>(current_addr) == 0x050F && *(current_addr + 2) == 0xC3)
            {
                return current_addr;
            }
        }
        return nullptr;
    }
}

// Initialize direct syscall stubs for low-level system operations
BOOL InitializeSyscalls(bool is_verbose)
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll)
        return FALSE;

    // Parse NTDLL export directory to enumerate Zw* functions
    auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hNtdll);
    auto pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PBYTE>(hNtdll) + pDosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<PBYTE>(hNtdll) + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    auto pNameRvas = reinterpret_cast<PDWORD>(reinterpret_cast<PBYTE>(hNtdll) + pExportDir->AddressOfNames);
    auto pAddressRvas = reinterpret_cast<PDWORD>(reinterpret_cast<PBYTE>(hNtdll) + pExportDir->AddressOfFunctions);
    auto pOrdinalRvas = reinterpret_cast<PWORD>(reinterpret_cast<PBYTE>(hNtdll) + pExportDir->AddressOfNameOrdinals);

    // Collect and sort all Zw* functions for SSN determination
    std::vector<SORTED_SYSCALL_MAPPING> sortedSyscalls;
    sortedSyscalls.reserve(pExportDir->NumberOfNames);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; ++i)
    {
        LPCSTR szFuncName = reinterpret_cast<LPCSTR>(reinterpret_cast<PBYTE>(hNtdll) + pNameRvas[i]);
        if (strncmp(szFuncName, "Zw", 2) == 0)
        {
            PVOID pFuncAddress = reinterpret_cast<PVOID>(reinterpret_cast<PBYTE>(hNtdll) + pAddressRvas[pOrdinalRvas[i]]);
            sortedSyscalls.push_back({pFuncAddress, szFuncName});
        }
    }

    std::sort(sortedSyscalls.begin(), sortedSyscalls.end(), CompareSyscallMappings);

    // Map of required syscalls with their parameter counts for security operations
    struct CStringComparer
    {
        bool operator()(const char *a, const char *b) const { return std::strcmp(a, b) < 0; }
    };
    const std::map<const char *, std::pair<SYSCALL_ENTRY *, UINT>, CStringComparer> required_syscalls = {
        {"ZwAllocateVirtualMemory", {&g_syscall_stubs.NtAllocateVirtualMemory, 6}},
        {"ZwWriteVirtualMemory", {&g_syscall_stubs.NtWriteVirtualMemory, 5}},
        {"ZwReadVirtualMemory", {&g_syscall_stubs.NtReadVirtualMemory, 5}},
        {"ZwCreateThreadEx", {&g_syscall_stubs.NtCreateThreadEx, 11}},
        {"ZwFreeVirtualMemory", {&g_syscall_stubs.NtFreeVirtualMemory, 4}},
        {"ZwProtectVirtualMemory", {&g_syscall_stubs.NtProtectVirtualMemory, 5}},
        {"ZwOpenProcess", {&g_syscall_stubs.NtOpenProcess, 4}},
        {"ZwGetNextProcess", {&g_syscall_stubs.NtGetNextProcess, 5}},
        {"ZwTerminateProcess", {&g_syscall_stubs.NtTerminateProcess, 2}},
        {"ZwQueryInformationProcess", {&g_syscall_stubs.NtQueryInformationProcess, 5}},
        {"ZwUnmapViewOfSection", {&g_syscall_stubs.NtUnmapViewOfSection, 2}},
        {"ZwGetContextThread", {&g_syscall_stubs.NtGetContextThread, 2}},
        {"ZwSetContextThread", {&g_syscall_stubs.NtSetContextThread, 2}},
        {"ZwResumeThread", {&g_syscall_stubs.NtResumeThread, 2}},
        {"ZwFlushInstructionCache", {&g_syscall_stubs.NtFlushInstructionCache, 3}},
        {"ZwClose", {&g_syscall_stubs.NtClose, 1}},
        {"ZwOpenKey", {&g_syscall_stubs.NtOpenKey, 3}},
        {"ZwQueryValueKey", {&g_syscall_stubs.NtQueryValueKey, 6}},
        {"ZwEnumerateKey", {&g_syscall_stubs.NtEnumerateKey, 6}}};

    // Resolve syscall stubs and gadgets for each required function
    for (WORD i = 0; i < sortedSyscalls.size(); ++i)
    {
        const auto &mapping = sortedSyscalls[i];
        auto it = required_syscalls.find(mapping.szName);
        if (it == required_syscalls.end())
            continue;

        PVOID pGadget = FindSyscallGadget_x64(mapping.pAddress);
        if (pGadget)
        {
            it->second.first->pSyscallGadget = pGadget;
            it->second.first->nArgs = it->second.second;
            it->second.first->ssn = i;
        }
    }

    // Validate that all required syscalls were successfully resolved
    for (const auto &pair : required_syscalls)
    {
        if (!pair.second.first->pSyscallGadget)
            return FALSE;
    }

    return TRUE;
}

// Direct syscall implementations using assembly trampoline
NTSTATUS NtAllocateVirtualMemory_syscall(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
    return (NTSTATUS)AbiTramp(&g_syscall_stubs.NtAllocateVirtualMemory, ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS NtWriteVirtualMemory_syscall(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten)
{
    return (NTSTATUS)AbiTramp(&g_syscall_stubs.NtWriteVirtualMemory, ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

NTSTATUS NtReadVirtualMemory_syscall(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead)
{
    return (NTSTATUS)AbiTramp(&g_syscall_stubs.NtReadVirtualMemory, ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
}

NTSTATUS NtCreateThreadEx_syscall(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, LPVOID ObjectAttributes, HANDLE ProcessHandle, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, ULONG CreateFlags, ULONG_PTR ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, LPVOID AttributeList)
{
    return (NTSTATUS)AbiTramp(&g_syscall_stubs.NtCreateThreadEx, ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

NTSTATUS NtFreeVirtualMemory_syscall(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG FreeType)
{
    return (NTSTATUS)AbiTramp(&g_syscall_stubs.NtFreeVirtualMemory, ProcessHandle, BaseAddress, RegionSize, FreeType);
}

NTSTATUS NtProtectVirtualMemory_syscall(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect)
{
    return (NTSTATUS)AbiTramp(&g_syscall_stubs.NtProtectVirtualMemory, ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

NTSTATUS NtOpenProcess_syscall(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
{
    return (NTSTATUS)AbiTramp(&g_syscall_stubs.NtOpenProcess, ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS NtGetNextProcess_syscall(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Flags, PHANDLE NewProcessHandle)
{
    return (NTSTATUS)AbiTramp(&g_syscall_stubs.NtGetNextProcess, ProcessHandle, DesiredAccess, HandleAttributes, Flags, NewProcessHandle);
}

NTSTATUS NtTerminateProcess_syscall(HANDLE ProcessHandle, NTSTATUS ExitStatus)
{
    return (NTSTATUS)AbiTramp(&g_syscall_stubs.NtTerminateProcess, ProcessHandle, ExitStatus);
}

NTSTATUS NtQueryInformationProcess_syscall(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
{
    return (NTSTATUS)AbiTramp(&g_syscall_stubs.NtQueryInformationProcess, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

NTSTATUS NtUnmapViewOfSection_syscall(HANDLE ProcessHandle, PVOID BaseAddress)
{
    return (NTSTATUS)AbiTramp(&g_syscall_stubs.NtUnmapViewOfSection, ProcessHandle, BaseAddress);
}

NTSTATUS NtGetContextThread_syscall(HANDLE ThreadHandle, PCONTEXT pContext)
{
    return (NTSTATUS)AbiTramp(&g_syscall_stubs.NtGetContextThread, ThreadHandle, pContext);
}

NTSTATUS NtSetContextThread_syscall(HANDLE ThreadHandle, PCONTEXT pContext)
{
    return (NTSTATUS)AbiTramp(&g_syscall_stubs.NtSetContextThread, ThreadHandle, pContext);
}

NTSTATUS NtResumeThread_syscall(HANDLE ThreadHandle, PULONG SuspendCount)
{
    return (NTSTATUS)AbiTramp(&g_syscall_stubs.NtResumeThread, ThreadHandle, SuspendCount);
}

NTSTATUS NtFlushInstructionCache_syscall(HANDLE ProcessHandle, PVOID BaseAddress, ULONG NumberOfBytesToFlush)
{
    return (NTSTATUS)AbiTramp(&g_syscall_stubs.NtFlushInstructionCache, ProcessHandle, BaseAddress, NumberOfBytesToFlush);
}

NTSTATUS NtClose_syscall(HANDLE Handle)
{
    return (NTSTATUS)AbiTramp(&g_syscall_stubs.NtClose, Handle);
}

NTSTATUS NtOpenKey_syscall(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
{
    return (NTSTATUS)AbiTramp(&g_syscall_stubs.NtOpenKey, KeyHandle, DesiredAccess, ObjectAttributes);
}

NTSTATUS NtQueryValueKey_syscall(HANDLE KeyHandle, PUNICODE_STRING_SYSCALLS ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength)
{
    return (NTSTATUS)AbiTramp(&g_syscall_stubs.NtQueryValueKey, KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
}

NTSTATUS NtEnumerateKey_syscall(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength)
{
    return (NTSTATUS)AbiTramp(&g_syscall_stubs.NtEnumerateKey, KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);
}