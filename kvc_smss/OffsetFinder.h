#ifndef OFFSET_FINDER_H
#define OFFSET_FINDER_H

#include "BootBypass.h"

// Scans ntoskrnl.exe on disk to find SeCiCallbacks and other offsets.
// Populates Offset_SeCiCallbacks, Offset_SafeFunction, and Offset_Callback.
// Returns TRUE if at least SeCiCallbacks is found.
BOOLEAN FindKernelOffsetsLocally(PCONFIG_SETTINGS config);

#endif
