#ifndef FILE_MANAGER_H
#define FILE_MANAGER_H

#include "BootBypass.h"
#include "SystemUtils.h"

// Rename SourcePath to TargetPath (NtSetInformationFile rename).
// Skips silently when target exists but source is already gone.
NTSTATUS ExecuteRename(PINI_ENTRY entry);

// Delete DeletePath.  For directories, recurses when RecursiveDelete=YES.
NTSTATUS ExecuteDelete(PINI_ENTRY entry);

#endif