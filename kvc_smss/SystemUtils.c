// ============================================================================
// SystemUtils — CRT replacement, string primitives, I/O helpers, INI parser
//
// No standard library is available (NODEFAULTLIB).  All string functions,
// memory operations, and display routines are implemented here.
//
// *_safe  — bounded variant; never writes past destSize WCHARs, always
//           null-terminates; returns full source length (like strlcpy/cat).
// *_check — boolean overflow-check only; does not modify any string.
// *_impl  — internal reimplementation of a standard C function.
//
// DisplayMessage is gated on g_VerboseMode.
// DisplayAlwaysMessage is unconditional and used for critical errors only.
// ============================================================================

#include "SystemUtils.h"

#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)
#define SystemModuleInformation 11

// Stub for the MSVC compiler's stack-probe helper.  The real __chkstk probes
// stack pages on entry to functions with large locals; here it is a no-op
// because the full 1 MB stack is pre-committed at process creation.
void __chkstk(void) {}

// Suppresses NtDisplayString output until [Config] Verbose= has been parsed.
BOOLEAN g_VerboseMode = FALSE;

void* memset_impl(void* dest, int c, SIZE_T count) {
    unsigned char* d = (unsigned char*)dest;
    while (count--) *d++ = (unsigned char)c;
    return dest;
}

void* memcpy_impl(void* dest, const void* src, SIZE_T count) {
    unsigned char* d = (unsigned char*)dest;
    const unsigned char* s = (const unsigned char*)src;
    while (count--) *d++ = *s++;
    return dest;
}

SIZE_T wcslen(const WCHAR* str) {
    const WCHAR* s = str;
    while (*s) s++;
    return s - str;
}

WCHAR* wcscpy(WCHAR* dest, const WCHAR* src) {
    WCHAR* d = dest;
    while ((*d++ = *src++) != 0);
    return dest;
}

WCHAR* wcscat(WCHAR* dest, const WCHAR* src) {
    WCHAR* d = dest + wcslen(dest);
    while ((*d++ = *src++) != 0);
    return dest;
}

int _wcsicmp_impl(const WCHAR* str1, const WCHAR* str2) {
    while (*str1 && *str2) {
        WCHAR c1 = *str1, c2 = *str2;
        if (c1 >= L'a' && c1 <= L'z') c1 -= 32;
        if (c2 >= L'a' && c2 <= L'z') c2 -= 32;
        if (c1 != c2) return (c1 < c2) ? -1 : 1;
        str1++; str2++;
    }
    if (*str1) return 1;
    if (*str2) return -1;
    return 0;
}

// Bounded string length - returns length up to maxLen, never reads beyond
SIZE_T wcsnlen_safe(const WCHAR* str, SIZE_T maxLen) {
    if (!str) return 0;
    
    SIZE_T len = 0;
    while (len < maxLen && str[len] != 0) {
        len++;
    }
    return len;
}

// Safe string copy with size limit
// Returns: length of src (what would be copied if buffer was infinite)
// Result is always null-terminated if destSize > 0
SIZE_T wcscpy_safe(WCHAR* dest, SIZE_T destSize, const WCHAR* src) {
    if (!dest || destSize == 0) {
        return src ? wcslen(src) : 0;
    }
    
    if (!src) {
        dest[0] = 0;
        return 0;
    }
    
    SIZE_T srcLen = wcslen(src);
    SIZE_T copyLen = (srcLen < destSize - 1) ? srcLen : (destSize - 1);
    
    SIZE_T i;
    for (i = 0; i < copyLen; i++) {
        dest[i] = src[i];
    }
    dest[i] = 0;
    
    return srcLen; // Return full source length (may be > copyLen if truncated)
}

// Safe string concatenate with size limit
// Returns: length of dest+src combined (what would be the result if buffer was infinite)
// Result is always null-terminated if destSize > 0
SIZE_T wcscat_safe(WCHAR* dest, SIZE_T destSize, const WCHAR* src) {
    if (!dest || destSize == 0) {
        return src ? wcslen(src) : 0;
    }
    
    if (!src) {
        return wcsnlen_safe(dest, destSize);
    }
    
    // Use bounded length check in case dest is not properly terminated
    SIZE_T destLen = wcsnlen_safe(dest, destSize);
    SIZE_T srcLen = wcslen(src);
    
    // If dest already fills buffer, cannot append
    if (destLen >= destSize - 1) {
        return destLen + srcLen;
    }
    
    SIZE_T remaining = destSize - destLen - 1;
    SIZE_T copyLen = (srcLen < remaining) ? srcLen : remaining;
    
    SIZE_T i;
    for (i = 0; i < copyLen; i++) {
        dest[destLen + i] = src[i];
    }
    dest[destLen + i] = 0;
    
    return destLen + srcLen; // Return total length that would result
}

// Check if concatenation would fit without truncation
BOOLEAN wcscat_check(WCHAR* dest, SIZE_T destSize, const WCHAR* src) {
    if (!dest || !src || destSize == 0) return FALSE;
    
    SIZE_T destLen = wcsnlen_safe(dest, destSize);
    SIZE_T srcLen = wcslen(src);
    
    // Check overflow protection: destLen + srcLen + 1 <= destSize
    if (destLen >= destSize) return FALSE;
    if (srcLen > (destSize - destLen - 1)) return FALSE;
    
    return TRUE;
}

// Validate if adding addLen to currentLen would exceed maxLen
// Protected against arithmetic overflow
BOOLEAN validate_string_space(SIZE_T currentLen, SIZE_T addLen, SIZE_T maxLen) {
    if (currentLen >= maxLen) return FALSE;
    if (addLen > (maxLen - currentLen - 1)) return FALSE;
    return TRUE;
}

SIZE_T UnicodeStringCopySafe(WCHAR* dest, SIZE_T destSize, const UNICODE_STRING* src) {
    SIZE_T srcLen, copyLen, i;

    if (!dest || destSize == 0) {
        return (src && src->Buffer) ? (src->Length / sizeof(WCHAR)) : 0;
    }

    if (!src || !src->Buffer) {
        dest[0] = 0;
        return 0;
    }

    srcLen = src->Length / sizeof(WCHAR);
    copyLen = (srcLen < destSize - 1) ? srcLen : (destSize - 1);

    for (i = 0; i < copyLen; i++) {
        dest[i] = src->Buffer[i];
    }
    dest[i] = 0;

    return srcLen;
}

void TrimString(PWSTR str) {
    PWSTR start = str, end;
    while (*start == L' ' || *start == L'\t' || *start == L'\r' || *start == L'\n') start++;
    if (*start == 0) { *str = 0; return; }
    
    PWSTR semicolon = start;
    while (*semicolon && *semicolon != L';') semicolon++;
    if (*semicolon == L';') *semicolon = 0;
    
    end = start + wcslen(start) - 1;
    while (end > start && (*end == L' ' || *end == L'\t' || *end == L'\r' || *end == L'\n')) end--;
    *(end + 1) = 0;
    if (start != str) wcscpy(str, start);
}

BOOLEAN StringToULONGLONG(PCWSTR str, ULONGLONG* out) {
    ULONGLONG result = 0;
    PCWSTR p = str;
    if (p[0] == L'0' && (p[1] == L'x' || p[1] == L'X')) {
        p += 2;
        while (*p) {
            WCHAR c = *p;
            ULONGLONG digit;
            if (c >= L'0' && c <= L'9') digit = c - L'0';
            else if (c >= L'a' && c <= L'f') digit = c - L'a' + 10;
            else if (c >= L'A' && c <= L'F') digit = c - L'A' + 10;
            else return FALSE;
            result = (result << 4) | digit;
            p++;
        }
    } else {
        while (*p) {
            if (*p < L'0' || *p > L'9') return FALSE;
            result = result * 10 + (*p - L'0');
            p++;
        }
    }
    *out = result;
    return TRUE;
}

BOOLEAN StringToULONG(PCWSTR str, PULONG out) {
    ULONGLONG result;
    if (!StringToULONGLONG(str, &result) || result > 0xFFFFFFFF) return FALSE;
    *out = (ULONG)result;
    return TRUE;
}

void ULONGLONGToHexString(ULONGLONG value, PWSTR buffer, BOOLEAN includePrefix) {
    const WCHAR hexChars[] = L"0123456789ABCDEF";
    int i, offset = 0;
    if (includePrefix) { buffer[0] = L'0'; buffer[1] = L'x'; offset = 2; }
    for (i = 0; i < 16; i++) {
        int nibble = (value >> (60 - i * 4)) & 0xF;
        buffer[offset + i] = hexChars[nibble];
    }
    buffer[offset + 16] = 0;
}

static void DisplayMessageInternal(PCWSTR message) {
    if (!message) return;
    WCHAR tempBuffer[512];
    wcscpy_safe(tempBuffer, sizeof(tempBuffer) / sizeof(tempBuffer[0]), message);
    UNICODE_STRING usMsg;
    RtlInitUnicodeString(&usMsg, tempBuffer);
    NtDisplayString(&usMsg);
}

void DisplayMessage(PCWSTR message) {
    if (!message || !g_VerboseMode) return;
    DisplayMessageInternal(message);
}

void DisplayAlwaysMessage(PCWSTR message) {
    DisplayMessageInternal(message);
}

void DisplayStatus(NTSTATUS status) {
    WCHAR statusMsg[20];
    WCHAR hexChars[] = L"0123456789ABCDEF";
    statusMsg[0] = L' '; statusMsg[1] = L'('; statusMsg[2] = L'0'; statusMsg[3] = L'x';
    for (int i = 0; i < 8; i++) {
        int nibble = (status >> (28 - i * 4)) & 0xF;
        statusMsg[4 + i] = hexChars[nibble];
    }
    statusMsg[12] = L')'; statusMsg[13] = L'\r'; statusMsg[14] = L'\n'; statusMsg[15] = 0;
    DisplayMessage(statusMsg);
}

BOOLEAN AllocateZeroedBuffer(SIZE_T size, PVOID* outBuffer) {
    PVOID base = NULL;
    SIZE_T regionSize;
    NTSTATUS status;

    if (!outBuffer || size == 0) return FALSE;

    regionSize = size;
    status = NtAllocateVirtualMemory((HANDLE)-1, &base, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    memset_impl(base, 0, regionSize);
    *outBuffer = base;
    return TRUE;
}

void FreeAllocatedBuffer(PVOID buffer) {
    SIZE_T regionSize = 0;

    if (!buffer) return;
    NtFreeVirtualMemory((HANDLE)-1, &buffer, &regionSize, MEM_RELEASE);
}

// Allocates a buffer and fills it with the kernel module list.
// Retries up to 4 times with an expanding buffer on STATUS_INFO_LENGTH_MISMATCH.
// Caller must free *outModuleInfo with FreeAllocatedBuffer when done.
BOOLEAN QuerySystemModuleInformation(SYSTEM_MODULE_INFORMATION** outModuleInfo) {
    ULONG returnLength = 0;
    NTSTATUS status;
    ULONG attempt;

    if (!outModuleInfo) return FALSE;
    *outModuleInfo = NULL;

    status = NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &returnLength);
    if (returnLength == 0 && NT_SUCCESS(status)) {
        return FALSE;
    }

    if (returnLength == 0) {
        returnLength = sizeof(SYSTEM_MODULE_INFORMATION) + (sizeof(SYSTEM_MODULE_ENTRY) * 64);
    }

    for (attempt = 0; attempt < 4; attempt++) {
        PVOID buffer = NULL;
        SIZE_T allocSize = (SIZE_T)returnLength + 0x1000;

        if (!AllocateZeroedBuffer(allocSize, &buffer)) {
            return FALSE;
        }

        status = NtQuerySystemInformation(SystemModuleInformation, buffer, (ULONG)allocSize, &returnLength);
        if (NT_SUCCESS(status)) {
            *outModuleInfo = (SYSTEM_MODULE_INFORMATION*)buffer;
            return TRUE;
        }

        FreeAllocatedBuffer(buffer);
        if (status != STATUS_INFO_LENGTH_MISMATCH) {
            return FALSE;
        }
        if (returnLength == 0) {
            returnLength = (ULONG)(allocSize * 2);
        }
    }

    return FALSE;
}

// Reads the entire INI file into a newly allocated wide-character buffer.
// Encoding detection (in order): UTF-16 LE BOM → heuristic (NUL at odd bytes)
// → UTF-8 BOM → ASCII (non-ASCII bytes replaced with '?').
// Caller frees *outBuffer with FreeIniFileBuffer.
BOOLEAN ReadIniFile(PCWSTR filePath, PWSTR* outBuffer) {
    UNICODE_STRING usFilePath;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hFile = NULL;
    NTSTATUS status;
    FILE_STANDARD_INFORMATION fileInfo;
    PUCHAR rawBuffer = NULL;
    PWSTR wideBuffer = NULL;
    LARGE_INTEGER byteOffset;
    SIZE_T rawAllocSize;
    SIZE_T bytesRead;
    SIZE_T start;

    if (!outBuffer) return FALSE;
    *outBuffer = NULL;

    RtlInitUnicodeString(&usFilePath, filePath);
    InitializeObjectAttributes(&oa, &usFilePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenFile(&hFile, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE, 0);
    if (!NT_SUCCESS(status)) return FALSE;

    memset_impl(&fileInfo, 0, sizeof(fileInfo));
    status = NtQueryInformationFile(hFile, &iosb, &fileInfo, sizeof(fileInfo), FileStandardInformation);
    if (!NT_SUCCESS(status)) {
        NtClose(hFile);
        return FALSE;
    }

    if (fileInfo.EndOfFile.QuadPart <= 0) {
        NtClose(hFile);
        return FALSE;
    }

    rawAllocSize = (SIZE_T)fileInfo.EndOfFile.QuadPart + sizeof(WCHAR);
    if (!AllocateZeroedBuffer(rawAllocSize, (PVOID*)&rawBuffer)) {
        NtClose(hFile);
        return FALSE;
    }

    byteOffset.QuadPart = 0;
    status = NtReadFile(hFile, NULL, NULL, NULL, &iosb, rawBuffer, (ULONG)(rawAllocSize - 1), &byteOffset, NULL);
    NtClose(hFile);
    if (!NT_SUCCESS(status) && status != 0x103) {
        FreeAllocatedBuffer(rawBuffer);
        return FALSE;
    }

    bytesRead = (SIZE_T)iosb.Information;
    if (bytesRead == 0) {
        FreeAllocatedBuffer(rawBuffer);
        return FALSE;
    }

    // Detect UTF-16LE BOM or "looks like UTF-16LE" (many NUL bytes in odd positions).
    BOOLEAN isUtf16Le = FALSE;
    start = 0;
    if (bytesRead >= 2 && rawBuffer[0] == 0xFF && rawBuffer[1] == 0xFE) {
        isUtf16Le = TRUE;
        start = 2;
    } else if (bytesRead >= 4 && rawBuffer[1] == 0x00 && rawBuffer[3] == 0x00) {
        isUtf16Le = TRUE;
        start = 0;
    }

    if (isUtf16Le) {
        SIZE_T wcharCount = (bytesRead - start) / sizeof(WCHAR);

        if (!AllocateZeroedBuffer((wcharCount + 1) * sizeof(WCHAR), (PVOID*)&wideBuffer)) {
            FreeAllocatedBuffer(rawBuffer);
            return FALSE;
        }

        memcpy_impl(wideBuffer, rawBuffer + start, wcharCount * sizeof(WCHAR));
        wideBuffer[wcharCount] = 0;
        FreeAllocatedBuffer(rawBuffer);
        *outBuffer = wideBuffer;
        return TRUE;
    }

    // Detect UTF-8 BOM, otherwise treat as ASCII/UTF-8 and widen bytes.
    if (bytesRead >= 3 && rawBuffer[0] == 0xEF && rawBuffer[1] == 0xBB && rawBuffer[2] == 0xBF) {
        start = 3;
    } else {
        start = 0;
    }

    if (!AllocateZeroedBuffer((bytesRead - start + 1) * sizeof(WCHAR), (PVOID*)&wideBuffer)) {
        FreeAllocatedBuffer(rawBuffer);
        return FALSE;
    }

    SIZE_T out = 0;
    for (SIZE_T i = start; i < bytesRead; ++i) {
        UCHAR b = rawBuffer[i];
        if (b == 0) break;
        // INI is ASCII keys/values; non-ASCII is replaced.
        wideBuffer[out++] = (b < 0x80) ? (WCHAR)b : L'?';
    }
    wideBuffer[out] = 0;
    FreeAllocatedBuffer(rawBuffer);
    *outBuffer = wideBuffer;
    return TRUE;
}

void FreeIniFileBuffer(PWSTR buffer) {
    FreeAllocatedBuffer(buffer);
}

// Parses INI content into entries[] and config.
// [Config] fills CONFIG_SETTINGS; [DSE_STATE] is silently skipped;
// any other [name] section fills the next INI_ENTRY.
// Returns the number of completed INI_ENTRY records.
ULONG ParseIniFile(PWSTR iniContent, PINI_ENTRY entries, ULONG maxEntries, PCONFIG_SETTINGS config) {
    ULONG entryCount = 0;
    PWSTR line = iniContent, nextLine;
    WCHAR lineBuf[MAX_PATH_LEN];
    ULONG i;
    int currentEntry = -1;
    BOOLEAN inConfigSection = FALSE;

    // Defaults
    config->Execute = TRUE;
    config->RestoreHVCI = TRUE;
    config->Verbose = TRUE;
    config->DriverDevice[0] = 0;
    config->IoControlCode_Read = 0;
    config->IoControlCode_Write = 0;
    config->Offset_SeCiCallbacks = 0;
    config->Offset_Callback = 0;
    config->Offset_SafeFunction = 0;
    
    if (!iniContent || iniContent[0] == 0) return 0;
    if (iniContent[0] == 0xFEFF) line++;

    while (*line && entryCount < maxEntries) {
        nextLine = line;
        while (*nextLine && *nextLine != L'\r' && *nextLine != L'\n') nextLine++;
        
        i = 0;
        while (line < nextLine && i < (MAX_PATH_LEN - 1)) lineBuf[i++] = *line++;
        lineBuf[i] = 0;
        line = nextLine;
        if (*line == L'\r') line++;
        if (*line == L'\n') line++;
        
        TrimString(lineBuf);
        if (lineBuf[0] == 0 || lineBuf[0] == L';' || lineBuf[0] == L'#') continue;

        if (lineBuf[0] == L'[') {
            if (_wcsicmp_impl(lineBuf, L"[Config]") == 0) {
                inConfigSection = TRUE;
                currentEntry = -1;
                continue;
            }
            if (_wcsicmp_impl(lineBuf, L"[DSE_STATE]") == 0) {
                inConfigSection = FALSE;
                currentEntry = -1;
                continue;
            }
            inConfigSection = FALSE;
            if (currentEntry >= 0) {
                if (entries[currentEntry].DisplayName[0] == 0 && entries[currentEntry].ServiceName[0]) {
                    wcscpy_safe(entries[currentEntry].DisplayName, MAX_PATH_LEN, entries[currentEntry].ServiceName);
                }
                entryCount++;
            }
            if (entryCount < maxEntries) {
                currentEntry = (LONG)entryCount;
                memset_impl(&entries[currentEntry], 0, sizeof(INI_ENTRY));
                wcscpy_safe(entries[currentEntry].DriverType, 16, L"KERNEL");
                wcscpy_safe(entries[currentEntry].StartType, 16, L"DEMAND");
            } else currentEntry = -1;
            continue;
        }

        if (inConfigSection && lineBuf[0] != 0) {
            PWSTR equals = lineBuf;
            while (*equals && *equals != L'=') equals++;
            if (*equals == L'=') {
                *equals = 0;
                PWSTR key = lineBuf, value = equals + 1;
                TrimString(key); TrimString(value);
                if (_wcsicmp_impl(key, L"Execute") == 0) config->Execute = (_wcsicmp_impl(value, L"YES") == 0 || _wcsicmp_impl(value, L"1") == 0);
                else if (_wcsicmp_impl(key, L"RestoreHVCI") == 0) config->RestoreHVCI = (_wcsicmp_impl(value, L"YES") == 0 || _wcsicmp_impl(value, L"1") == 0);
                else if (_wcsicmp_impl(key, L"Verbose") == 0) config->Verbose = (_wcsicmp_impl(value, L"YES") == 0 || _wcsicmp_impl(value, L"1") == 0);
                else if (_wcsicmp_impl(key, L"DriverDevice") == 0) wcscpy_safe(config->DriverDevice, MAX_PATH_LEN, value);
                else if (_wcsicmp_impl(key, L"IoControlCode_Read") == 0) StringToULONG(value, &config->IoControlCode_Read);
                else if (_wcsicmp_impl(key, L"IoControlCode_Write") == 0) StringToULONG(value, &config->IoControlCode_Write);
                else if (_wcsicmp_impl(key, L"Offset_SeCiCallbacks") == 0) StringToULONGLONG(value, &config->Offset_SeCiCallbacks);
                else if (_wcsicmp_impl(key, L"Offset_Callback") == 0) StringToULONGLONG(value, &config->Offset_Callback);
                else if (_wcsicmp_impl(key, L"Offset_SafeFunction") == 0) StringToULONGLONG(value, &config->Offset_SafeFunction);
            }
            continue;
        }

        if (currentEntry >= 0 && (ULONG)currentEntry < maxEntries) {
            PWSTR equals = lineBuf;
            while (*equals && *equals != L'=') equals++;
            if (*equals == L'=') {
                *equals = 0;
                PWSTR key = lineBuf, value = equals + 1;
                TrimString(key); TrimString(value);
                if (_wcsicmp_impl(key, L"Action") == 0) {
                    if (_wcsicmp_impl(value, L"LOAD") == 0) entries[currentEntry].Action = ACTION_LOAD;
                    else if (_wcsicmp_impl(value, L"UNLOAD") == 0) entries[currentEntry].Action = ACTION_UNLOAD;
                    else if (_wcsicmp_impl(value, L"RENAME") == 0) entries[currentEntry].Action = ACTION_RENAME;
                    else if (_wcsicmp_impl(value, L"DELETE") == 0) entries[currentEntry].Action = ACTION_DELETE;
                }
                else if (_wcsicmp_impl(key, L"ServiceName") == 0) wcscpy_safe(entries[currentEntry].ServiceName, MAX_PATH_LEN, value);
                else if (_wcsicmp_impl(key, L"DisplayName") == 0) wcscpy_safe(entries[currentEntry].DisplayName, MAX_PATH_LEN, value);
                else if (_wcsicmp_impl(key, L"ImagePath") == 0) wcscpy_safe(entries[currentEntry].ImagePath, MAX_PATH_LEN, value);
                else if (_wcsicmp_impl(key, L"Type") == 0 || _wcsicmp_impl(key, L"DriverType") == 0) {
                    // Accept both named ("KERNEL","FILE_SYSTEM") and numeric (1,2) forms
                    if      (_wcsicmp_impl(value, L"KERNEL")      == 0 || _wcsicmp_impl(value, L"1") == 0)
                        wcscpy_safe(entries[currentEntry].DriverType, 16, L"KERNEL");
                    else if (_wcsicmp_impl(value, L"FILE_SYSTEM")  == 0 || _wcsicmp_impl(value, L"2") == 0)
                        wcscpy_safe(entries[currentEntry].DriverType, 16, L"FILE_SYSTEM");
                    else
                        wcscpy_safe(entries[currentEntry].DriverType, 16, value);
                }
                else if (_wcsicmp_impl(key, L"StartType") == 0) {
                    // Accept both named and numeric (0-4) forms
                    if      (_wcsicmp_impl(value, L"BOOT")     == 0 || _wcsicmp_impl(value, L"0") == 0)
                        wcscpy_safe(entries[currentEntry].StartType, 16, L"BOOT");
                    else if (_wcsicmp_impl(value, L"SYSTEM")   == 0 || _wcsicmp_impl(value, L"1") == 0)
                        wcscpy_safe(entries[currentEntry].StartType, 16, L"SYSTEM");
                    else if (_wcsicmp_impl(value, L"AUTO")     == 0 || _wcsicmp_impl(value, L"2") == 0)
                        wcscpy_safe(entries[currentEntry].StartType, 16, L"AUTO");
                    else if (_wcsicmp_impl(value, L"DEMAND")   == 0 || _wcsicmp_impl(value, L"3") == 0)
                        wcscpy_safe(entries[currentEntry].StartType, 16, L"DEMAND");
                    else if (_wcsicmp_impl(value, L"DISABLED") == 0 || _wcsicmp_impl(value, L"4") == 0)
                        wcscpy_safe(entries[currentEntry].StartType, 16, L"DISABLED");
                    else
                        wcscpy_safe(entries[currentEntry].StartType, 16, value);
                }
                else if (_wcsicmp_impl(key, L"CheckIfLoaded") == 0) entries[currentEntry].CheckIfLoaded = (_wcsicmp_impl(value, L"YES") == 0);
                else if (_wcsicmp_impl(key, L"AutoPatch") == 0) entries[currentEntry].AutoPatch = (_wcsicmp_impl(value, L"YES") == 0 || _wcsicmp_impl(value, L"1") == 0);
                else if (_wcsicmp_impl(key, L"SourcePath") == 0) wcscpy_safe(entries[currentEntry].SourcePath, MAX_PATH_LEN, value);
                else if (_wcsicmp_impl(key, L"TargetPath") == 0) wcscpy_safe(entries[currentEntry].TargetPath, MAX_PATH_LEN, value);
                else if (_wcsicmp_impl(key, L"ReplaceIfExists") == 0) entries[currentEntry].ReplaceIfExists = (_wcsicmp_impl(value, L"YES") == 0);
                else if (_wcsicmp_impl(key, L"DeletePath") == 0) wcscpy_safe(entries[currentEntry].DeletePath, MAX_PATH_LEN, value);
                else if (_wcsicmp_impl(key, L"RecursiveDelete") == 0) entries[currentEntry].RecursiveDelete = (_wcsicmp_impl(value, L"YES") == 0);
            }
        }
    }
    if (currentEntry >= 0) {
        if (entries[currentEntry].DisplayName[0] == 0 && entries[currentEntry].ServiceName[0]) {
            wcscpy_safe(entries[currentEntry].DisplayName, MAX_PATH_LEN, entries[currentEntry].ServiceName);
        }
        entryCount++;
    }
    return entryCount;
}
