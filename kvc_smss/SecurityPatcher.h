#ifndef SECURITY_PATCHER_H
#define SECURITY_PATCHER_H

#include "BootBypass.h"
#include "SystemUtils.h"
#include "DriverManager.h"
#include "SetupManager.h"

// ============================================================================
// IOCTL physical memory operations (via kvc.sys RTC_PACKET protocol)
// ============================================================================

// Write a 32-bit value at address using the given IOCTL code.
BOOLEAN WriteMemory32(HANDLE hDriver, ULONGLONG address, ULONG value, ULONG ioctl);
// Write a 64-bit value as two 32-bit IOCTL calls (low DWORD first, then high).
BOOLEAN WriteMemory64(HANDLE hDriver, ULONGLONG address, ULONGLONG value, ULONG ioctl);
// Read a 64-bit value as two 32-bit IOCTL calls; result in *value.
BOOLEAN ReadMemory64(HANDLE hDriver, ULONGLONG address, ULONGLONG* value, ULONG ioctl);

// Returns kernel virtual base of ntoskrnl.exe from SystemModuleInformation.
ULONGLONG GetNtoskrnlBase(void);

// Opens the named device object; returns NULL if unavailable.
HANDLE OpenDriverDevice(PCWSTR deviceName);

// ============================================================================
// DSE state persistence (drivers.ini [DSE_STATE] section)
// ============================================================================

// Appends [DSE_STATE]\nOriginalCallback=0x... to drivers.ini (UTF-16 LE).
BOOLEAN SaveStateSection(ULONGLONG callback);
// Parses drivers.ini for [DSE_STATE] OriginalCallback; fills *outCallback.
BOOLEAN LoadStateSection(ULONGLONG* outCallback);
// Rewrites drivers.ini without the [DSE_STATE] section.
BOOLEAN RemoveStateSection(void);

// ============================================================================
// Main DSE bypass
// ============================================================================

// 5-step sequence: ExtractkvcFromResource → load kvc.sys → patch
// SeCiCallbacks slot → load target driver → restore slot → unload/cleanup.
NTSTATUS ExecuteAutoPatchLoad(PINI_ENTRY entry, PCONFIG_SETTINGS config, PULONGLONG originalCallback);

#endif