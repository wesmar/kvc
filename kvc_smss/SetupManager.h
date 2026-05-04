#ifndef SETUP_MANAGER_H
#define SETUP_MANAGER_H

#include "BootBypass.h"
#include "SystemUtils.h"

// Updates the live DeviceGuard registry key Enabled value (cosmetic, no hive write).
NTSTATUS SetHVCIRegistryFlag(BOOLEAN enable);

// XOR+LZNT1 decompress embedded resource IDR_DRV1 (kvc.sys), write to kvc_Log (Sam.evtx).
// Returns TRUE when the file is ready for LoadDriver.
BOOLEAN ExtractkvcFromResource(void);

// Deletes both the kvc_Log temporary file and the SCM registry key.
// Called after NtUnloadDriver in ExecuteAutoPatchLoad step 5.
NTSTATUS Cleanupkvc(void);

// Reads DeviceGuard HVCI registry key; if Enabled==1, patches SYSTEM hive and reboots.
// Returns TRUE if a reboot was initiated (caller must terminate without continuing).
BOOLEAN CheckAndDisableHVCI(void);

// Patches the SYSTEM hive to re-enable HVCI (Enabled=1) for the next boot.
NTSTATUS RestoreHVCI(void);

// XOR+LZNT1 decompress embedded resource IDR_DRV2 (HvciShutdownSvc.exe), write to
// System32\HvciShutdownSvc.exe, and create the HVCIShutdownSvc service registry key.
// Idempotent: existing file/key are silently overwritten / left unchanged.
// Returns TRUE on success; FALSE on resource or decompression error.
BOOLEAN ExtractHvciShutdownSvcAndRegisterService(void);

// Removes HvciShutdownSvc.exe from System32 and the HVCIShutdownSvc service registry
// key.  Called when RestoreHVCI=NO.  Idempotent: missing file/key is not an error.
void CleanupHvciShutdownSvc(void);

#endif
