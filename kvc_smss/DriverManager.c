// ============================================================================
// DriverManager — SCM-free kernel driver load/unload via NtLoadDriver
//
// Windows driver loading normally goes through the SCM (Services.exe), which
// is not available at SMSS phase.  This module bypasses SCM by writing the
// required registry key under HKLM\SYSTEM\CurrentControlSet\Services directly,
// then calling NtLoadDriver with the registry path.
//
// IsDriverLoaded checks the kernel module list (NtQuerySystemInformation
// SystemModuleInformation) rather than the registry, which reflects actual
// loaded state regardless of service registration.
// ============================================================================

#include "DriverManager.h"

// Case-insensitive comparison between a narrow ASCII string (as returned by
// SYSTEM_MODULE_ENTRY.ImageName) and a wide string (service image basename).
// Only ASCII printable characters are expected; comparison is exact-length.
static BOOLEAN AsciiWideEqualsIgnoreCase(const char* ascii, PCWSTR wide) {
    ULONG index = 0;

    if (!ascii || !wide) {
        return FALSE;
    }

    while (ascii[index] != 0 && wide[index] != 0) {
        char a = ascii[index];
        WCHAR b = wide[index];

        if (a >= 'a' && a <= 'z') a -= 32;
        if (b >= L'a' && b <= L'z') b -= 32;
        if ((WCHAR)(UCHAR)a != b) {
            return FALSE;
        }
        index++;
    }

    return ascii[index] == 0 && wide[index] == 0;
}

// Returns a pointer into path pointing at the last path component
// (the part after the last backslash or forward slash).
static PCWSTR FindWideBaseName(PCWSTR path, SIZE_T charCount) {
    SIZE_T i;
    PCWSTR base = path;

    for (i = 0; i < charCount; i++) {
        if (path[i] == L'\\' || path[i] == L'/') {
            base = path + i + 1;
        }
    }

    return base;
}

static BOOLEAN WideStringContainsChar(PCWSTR text, WCHAR ch) {
    if (!text) {
        return FALSE;
    }

    while (*text) {
        if (*text == ch) {
            return TRUE;
        }
        text++;
    }

    return FALSE;
}

// Resolves the image filename (basename only, e.g. "mydrv.sys") for a given
// service name.  Lookup order:
//   1. Read ImagePath from HKLM\...\Services\<serviceName>; extract basename.
//   2. Fall back to serviceName + ".sys" if the key is absent or has no path.
static BOOLEAN BuildDriverImageName(PCWSTR serviceName, PWSTR imageName, SIZE_T imageNameCount) {
    WCHAR fullServicePath[MAX_PATH_LEN];
    UNICODE_STRING usServiceName;
    UNICODE_STRING usValueName;
    OBJECT_ATTRIBUTES oa;
    HANDLE hKey = NULL;
    NTSTATUS status;
    ULONG resultLength = 0;
    KEY_VALUE_PARTIAL_INFORMATION* valueInfo = NULL;
    BOOLEAN found = FALSE;

    if (!serviceName || !imageName || imageNameCount == 0) {
        return FALSE;
    }

    imageName[0] = 0;

    if (wcscpy_safe(fullServicePath, MAX_PATH_LEN,
                    L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\") >= MAX_PATH_LEN - 1) {
        return FALSE;
    }
    if (wcscat_safe(fullServicePath, MAX_PATH_LEN, serviceName) >= MAX_PATH_LEN) {
        return FALSE;
    }

    RtlInitUnicodeString(&usServiceName, fullServicePath);
    InitializeObjectAttributes(&oa, &usServiceName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenKey(&hKey, KEY_READ, &oa);
    if (NT_SUCCESS(status)) {
        RtlInitUnicodeString(&usValueName, L"ImagePath");
        status = NtQueryValueKey(hKey, &usValueName, KeyValuePartialInformation, NULL, 0, &resultLength);
        if ((status == STATUS_BUFFER_TOO_SMALL || status == (NTSTATUS)0xC0000004) &&
            resultLength >= sizeof(KEY_VALUE_PARTIAL_INFORMATION)) {
            if (AllocateZeroedBuffer(resultLength, (PVOID*)&valueInfo)) {
                status = NtQueryValueKey(hKey, &usValueName, KeyValuePartialInformation, valueInfo, resultLength, &resultLength);
                if (NT_SUCCESS(status) &&
                    (valueInfo->Type == REG_SZ || valueInfo->Type == REG_EXPAND_SZ) &&
                    valueInfo->DataLength >= sizeof(WCHAR)) {
                    PWSTR valueText = (PWSTR)valueInfo->Data;
                    SIZE_T valueChars = valueInfo->DataLength / sizeof(WCHAR);
                    while (valueChars > 0 && valueText[valueChars - 1] == 0) {
                        valueChars--;
                    }

                    if (valueChars > 0) {
                        PCWSTR baseName = FindWideBaseName(valueText, valueChars);
                        UNICODE_STRING baseNameString;
                        baseNameString.Buffer = (PWSTR)baseName;
                        baseNameString.Length = (USHORT)(valueChars - (SIZE_T)(baseName - valueText)) * sizeof(WCHAR);
                        baseNameString.MaximumLength = baseNameString.Length;
                        if (UnicodeStringCopySafe(imageName, imageNameCount, &baseNameString) < imageNameCount) {
                            found = TRUE;
                        }
                    }
                }
                FreeAllocatedBuffer(valueInfo);
            }
        }
        NtClose(hKey);
    }

    if (!found) {
        SIZE_T serviceLen = wcscpy_safe(imageName, imageNameCount, serviceName);
        if (serviceLen >= imageNameCount) {
            return FALSE;
        }
        if (!WideStringContainsChar(imageName, L'.')) {
            if (wcscat_safe(imageName, imageNameCount, L".sys") >= imageNameCount) {
                return FALSE;
            }
        }
    }

    return TRUE;
}

// Returns TRUE if the driver associated with serviceName is present in the
// running kernel module list.
BOOLEAN IsDriverLoaded(PCWSTR serviceName) {
    WCHAR imageName[MAX_PATH_LEN];
    SYSTEM_MODULE_INFORMATION* moduleInfo = NULL;
    BOOLEAN isLoaded = FALSE;

    if (!BuildDriverImageName(serviceName, imageName, MAX_PATH_LEN)) {
        return FALSE;
    }

    if (!QuerySystemModuleInformation(&moduleInfo)) {
        return FALSE;
    }

    for (ULONG i = 0; i < moduleInfo->Count; i++) {
        const char* moduleName = moduleInfo->Modules[i].ImageName + moduleInfo->Modules[i].ModuleNameOffset;
        if (AsciiWideEqualsIgnoreCase(moduleName, imageName)) {
            isLoaded = TRUE;
            break;
        }
    }

    FreeAllocatedBuffer(moduleInfo);
    return isLoaded;
}

// Creates (or opens) the SCM registry key for serviceName and writes the
// minimum values NtLoadDriver requires: ImagePath, DisplayName, Type, Start,
// ErrorControl.  STATUS_OBJECT_NAME_COLLISION is non-fatal (key already exists).
// driverType: "KERNEL"→Type=1, "FILE_SYSTEM"→Type=2.
// startType:  "BOOT"=0, "SYSTEM"=1, "AUTO"=2, "DISABLED"=4, else DEMAND=3.
NTSTATUS CreateDriverRegistryEntry(PCWSTR serviceName, PCWSTR imagePath, PCWSTR driverType, PCWSTR startType) {
    WCHAR fullServicePath[MAX_PATH_LEN];
    UNICODE_STRING usServiceName, usValueName;
    OBJECT_ATTRIBUTES oa;
    HANDLE hKey = NULL;
    NTSTATUS status;
    ULONG disposition;
    DWORD dwValue;
    WCHAR tempBuffer[MAX_PATH_LEN];
    ULONG dataSize;

    // Safe path construction
    SIZE_T baseLen = wcscpy_safe(fullServicePath, MAX_PATH_LEN, 
                                  L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
    if (baseLen >= MAX_PATH_LEN - 1) return STATUS_OBJECT_NAME_INVALID;
    
    SIZE_T finalLen = wcscat_safe(fullServicePath, MAX_PATH_LEN, serviceName);
    if (finalLen >= MAX_PATH_LEN) return STATUS_OBJECT_NAME_INVALID;
    
    RtlInitUnicodeString(&usServiceName, fullServicePath);
    InitializeObjectAttributes(&oa, &usServiceName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtCreateKey(&hKey, KEY_ALL_ACCESS, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, &disposition);
    if (!NT_SUCCESS(status)) return status;

    // ImagePath value
    RtlInitUnicodeString(&usValueName, L"ImagePath");
    SIZE_T pathLen = wcscpy_safe(tempBuffer, MAX_PATH_LEN, imagePath);
    if (pathLen >= MAX_PATH_LEN) {
        NtClose(hKey);
        return STATUS_OBJECT_NAME_INVALID;
    }
    dataSize = (ULONG)((pathLen + 1) * sizeof(WCHAR));
    status = NtSetValueKey(hKey, &usValueName, 0, REG_EXPAND_SZ, tempBuffer, dataSize);

    // DisplayName value
    RtlInitUnicodeString(&usValueName, L"DisplayName");
    SIZE_T nameLen = wcslen(serviceName);
    if (nameLen >= MAX_PATH_LEN) {
        NtClose(hKey);
        return STATUS_OBJECT_NAME_INVALID;
    }
    dataSize = (ULONG)((nameLen + 1) * sizeof(WCHAR));
    NtSetValueKey(hKey, &usValueName, 0, REG_SZ, (PVOID)serviceName, dataSize);

    // Type value
    dwValue = (_wcsicmp_impl(driverType, L"FILE_SYSTEM") == 0) ? 2 : 1;
    RtlInitUnicodeString(&usValueName, L"Type");
    NtSetValueKey(hKey, &usValueName, 0, REG_DWORD, &dwValue, sizeof(DWORD));

    // Start value
    if (_wcsicmp_impl(startType, L"BOOT") == 0) dwValue = 0;
    else if (_wcsicmp_impl(startType, L"SYSTEM") == 0) dwValue = 1;
    else if (_wcsicmp_impl(startType, L"AUTO") == 0) dwValue = 2;
    else if (_wcsicmp_impl(startType, L"DISABLED") == 0) dwValue = 4;
    else dwValue = 3;

    RtlInitUnicodeString(&usValueName, L"Start");
    NtSetValueKey(hKey, &usValueName, 0, REG_DWORD, &dwValue, sizeof(DWORD));

    // ErrorControl value
    dwValue = 1;
    RtlInitUnicodeString(&usValueName, L"ErrorControl");
    NtSetValueKey(hKey, &usValueName, 0, REG_DWORD, &dwValue, sizeof(DWORD));

    NtClose(hKey);
    return status;
}

// Creates the registry key then calls NtLoadDriver.
NTSTATUS LoadDriver(PCWSTR serviceName, PCWSTR imagePath, PCWSTR driverType, PCWSTR startType) {
    WCHAR fullServicePath[MAX_PATH_LEN];
    UNICODE_STRING usServiceName;
    NTSTATUS status;

    status = CreateDriverRegistryEntry(serviceName, imagePath, driverType, startType);
    if (!NT_SUCCESS(status) && status != STATUS_OBJECT_NAME_COLLISION) return status;

    // Safe path construction
    SIZE_T baseLen = wcscpy_safe(fullServicePath, MAX_PATH_LEN, 
                                  L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
    if (baseLen >= MAX_PATH_LEN - 1) return STATUS_OBJECT_NAME_INVALID;
    
    SIZE_T finalLen = wcscat_safe(fullServicePath, MAX_PATH_LEN, serviceName);
    if (finalLen >= MAX_PATH_LEN) return STATUS_OBJECT_NAME_INVALID;
    
    RtlInitUnicodeString(&usServiceName, fullServicePath);
    return NtLoadDriver(&usServiceName);
}

// Calls NtUnloadDriver.  Registry key and driver file are NOT removed here.
NTSTATUS UnloadDriver(PCWSTR serviceName) {
    WCHAR fullServicePath[MAX_PATH_LEN];
    UNICODE_STRING usServiceName;
    
    // Safe path construction
    SIZE_T baseLen = wcscpy_safe(fullServicePath, MAX_PATH_LEN, 
                                  L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
    if (baseLen >= MAX_PATH_LEN - 1) return STATUS_OBJECT_NAME_INVALID;
    
    SIZE_T finalLen = wcscat_safe(fullServicePath, MAX_PATH_LEN, serviceName);
    if (finalLen >= MAX_PATH_LEN) return STATUS_OBJECT_NAME_INVALID;
    
    RtlInitUnicodeString(&usServiceName, fullServicePath);
    return NtUnloadDriver(&usServiceName);
}
