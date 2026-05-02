#ifndef DRIVER_MANAGER_H
#define DRIVER_MANAGER_H

#include "BootBypass.h"
#include "SystemUtils.h"

// Returns obfuscated driver/device name string from the assembly stealth stub.
// Decoded at runtime from a built-in XOR-encoded literal to avoid plaintext
// service name appearing in the binary image.
extern PWSTR MmGetPoolDiagnosticString(void);

// Returns TRUE if the driver for serviceName is present in the running module list.
BOOLEAN IsDriverLoaded(PCWSTR serviceName);

// Creates the SCM registry key with Type, Start, ErrorControl, ImagePath, DisplayName.
NTSTATUS CreateDriverRegistryEntry(PCWSTR serviceName, PCWSTR imagePath, PCWSTR driverType, PCWSTR startType);

// Creates registry key then calls NtLoadDriver.
NTSTATUS LoadDriver(PCWSTR serviceName, PCWSTR imagePath, PCWSTR driverType, PCWSTR startType);

// Calls NtUnloadDriver.  File and registry key must be removed separately.
NTSTATUS UnloadDriver(PCWSTR serviceName);

#endif