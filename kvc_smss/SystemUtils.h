#ifndef SYSTEM_UTILS_H
#define SYSTEM_UTILS_H

#include "BootBypass.h"

#if DEBUG_LOGGING_ENABLED
    #define DEBUG_LOG(msg) DisplayMessage(msg)
    #define DEBUG_STATUS(status) DisplayStatus(status)
#else
    #define DEBUG_LOG(msg)
    #define DEBUG_STATUS(status)
#endif

extern BOOLEAN g_VerboseMode;

void* memset_impl(void* dest, int c, SIZE_T count);
void* memcpy_impl(void* dest, const void* src, SIZE_T count);
SIZE_T wcslen_impl(const WCHAR* str);
WCHAR* wcscpy_impl(WCHAR* dest, const WCHAR* src);
WCHAR* wcscat_impl(WCHAR* dest, const WCHAR* src);
int _wcsicmp_impl(const WCHAR* str1, const WCHAR* str2);
// Safe string operations with bounds checking
// All size parameters are in WCHAR count (not bytes)
// Returns: actual length of result string (not including null terminator)
// If truncation occurs, returns what WOULD be the full length (like strlcpy/strlcat)
SIZE_T wcscpy_safe(WCHAR* dest, SIZE_T destSize, const WCHAR* src);
SIZE_T wcscat_safe(WCHAR* dest, SIZE_T destSize, const WCHAR* src);
// Check if concatenation would fit without truncation
BOOLEAN wcscat_check(WCHAR* dest, SIZE_T destSize, const WCHAR* src);

// Bounded string length - never reads beyond maxLen characters
SIZE_T wcsnlen_safe(const WCHAR* str, SIZE_T maxLen);
SIZE_T UnicodeStringCopySafe(WCHAR* dest, SIZE_T destSize, const UNICODE_STRING* src);

// Validate if adding addLen to currentLen would exceed maxLen (with overflow protection)
BOOLEAN validate_string_space(SIZE_T currentLen, SIZE_T addLen, SIZE_T maxLen);
void TrimString(PWSTR str);
BOOLEAN StringToULONGLONG(PCWSTR str, ULONGLONG* out);
BOOLEAN StringToULONG(PCWSTR str, PULONG out);
void ULONGLONGToHexString(ULONGLONG value, PWSTR buffer, BOOLEAN includePrefix);
void DisplayMessage(PCWSTR message);
void DisplayAlwaysMessage(PCWSTR message);
void DisplayStatus(NTSTATUS status);
BOOLEAN AllocateZeroedBuffer(SIZE_T size, PVOID* outBuffer);
BOOLEAN ReadIniFile(PCWSTR filePath, PWSTR* outBuffer);
void FreeIniFileBuffer(PWSTR buffer);
BOOLEAN QuerySystemModuleInformation(SYSTEM_MODULE_INFORMATION** outModuleInfo);
void FreeAllocatedBuffer(PVOID buffer);
ULONG ParseIniFile(PWSTR iniContent, PINI_ENTRY entries, ULONG maxEntries, PCONFIG_SETTINGS config);

#endif
