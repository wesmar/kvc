// SelfLoader.h - Minimal position-independent PE loader
#ifndef SelfLoader_H
#define SelfLoader_H
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>

#if defined(_MSC_VER)
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT
#endif

// Function pointer types for dynamic API resolution
typedef HMODULE(WINAPI *LOADLIBRARYA_FN)(LPCSTR);
typedef FARPROC(WINAPI *GETPROCADDRESS_FN)(HMODULE, LPCSTR);
typedef LPVOID(WINAPI *VIRTUALALLOC_FN)(LPVOID, SIZE_T, DWORD, DWORD);
typedef NTSTATUS(NTAPI *NTFLUSHINSTRUCTIONCACHE_FN)(HANDLE, PVOID, ULONG);
typedef BOOL(WINAPI *DLLMAIN_FN)(HINSTANCE, DWORD, LPVOID);

// Hash computation constants for position-independent code
#define HASH_KEY 13

// Pre-computed hashes for API resolution without Import Table
#define KERNEL32DLL_HASH 0x6A4ABC5B
#define NTDLLDLL_HASH 0x3CFA685D

#define LOADLIBRARYA_HASH 0xEC0E4E8E
#define GETPROCADDRESS_HASH 0x7C0DFCAA
#define VIRTUALALLOC_HASH 0x91AFCA54
#define NTFLUSHINSTRUCTIONCACHE_HASH 0x534C0AB8

// Minimal Unicode string for module name access
typedef struct _UNICODE_STRING_LDR
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING_LDR, *PUNICODE_STRING_LDR;

// Minimal LDR entry containing only essential fields for module walking
typedef struct _LDR_DATA_TABLE_ENTRY_MINIMAL
{
    LIST_ENTRY InLoadOrderLinks;           // +0x00
    LIST_ENTRY InMemoryOrderLinks;         // +0x10 Used for CONTAINING_RECORD
    LIST_ENTRY InInitializationOrderLinks; // +0x20
    PVOID DllBase;                         // +0x30 Module base address
    PVOID EntryPoint;                      // +0x38
    ULONG SizeOfImage;                     // +0x40
    UNICODE_STRING_LDR FullDllName;        // +0x48
    UNICODE_STRING_LDR BaseDllName;        // +0x58 Module name for hashing
} LDR_DATA_TABLE_ENTRY_MINIMAL, *PLDR_DATA_TABLE_ENTRY_MINIMAL;

// Minimal PEB LDR data containing only module list
typedef struct _PEB_LDR_DATA_MINIMAL
{
    BYTE Reserved1[8];                     // +0x00
    PVOID Reserved2[3];                    // +0x08  
    LIST_ENTRY InMemoryOrderModuleList;    // +0x20 Module enumeration list
} PEB_LDR_DATA_MINIMAL, *PPEB_LDR_DATA_MINIMAL;

// Minimal PEB structure with only required fields
typedef struct _PEB_MINIMAL
{
    BYTE Reserved1[24];                    // +0x00-0x17 
    PPEB_LDR_DATA_MINIMAL Ldr;            // +0x18 Pointer to loader data
} PEB_MINIMAL, *PPEB_MINIMAL;

// Base relocation entry for PE image fix-ups
typedef struct _IMAGE_RELOC_ENTRY
{
    WORD offset : 12;
    WORD type : 4;
} IMAGE_RELOC_ENTRY, *PIMAGE_RELOC_ENTRY;

// PEB access for position-independent code
#if defined(_M_X64)
#define GET_PEB() reinterpret_cast<PPEB_MINIMAL>(__readgsqword(0x60))
#elif defined(_M_ARM64) 
#define GET_PEB() reinterpret_cast<PPEB_MINIMAL>(__readx18qword(0x60))
#else
#error "Unsupported architecture"
#endif

// Entry point export
DLLEXPORT ULONG_PTR WINAPI InitializeSecurityContext(LPVOID lpParameter);

#endif