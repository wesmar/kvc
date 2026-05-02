// ============================================================================
// FileManager — file and directory rename/delete operations (NATIVE I/O)
//
// All I/O uses raw NT syscalls (NtOpenFile, NtSetInformationFile, etc.).
// No Win32 API is available at SMSS phase.
// Path convention: NT native namespace (\??\C:\... or \SystemRoot\...).
// ============================================================================

#include "FileManager.h"

// Rename SourcePath to TargetPath.  If TargetPath already exists and SourcePath
// does not, the rename is treated as already complete — STATUS_SUCCESS returned.
NTSTATUS ExecuteRename(PINI_ENTRY entry) {
    UNICODE_STRING usSourcePath, usTargetPath;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hFile;
    NTSTATUS status;
    UCHAR buffer[512];
    PFILE_RENAME_INFORMATION pRename = (PFILE_RENAME_INFORMATION)buffer;

    RtlInitUnicodeString(&usSourcePath, entry->SourcePath);
    RtlInitUnicodeString(&usTargetPath, entry->TargetPath);

    // Check if target already exists
    InitializeObjectAttributes(&oa, &usTargetPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = NtOpenFile(&hFile, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT);
    if (NT_SUCCESS(status)) {
        NtClose(hFile);
        // Target exists, check if source exists
        InitializeObjectAttributes(&oa, &usSourcePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        status = NtOpenFile(&hFile, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT);
        if (!NT_SUCCESS(status)) { 
            DisplayMessage(L"SKIPPED: Rename complete\r\n"); 
            return STATUS_SUCCESS; 
        }
        NtClose(hFile);
    }

    // Open source for rename
    InitializeObjectAttributes(&oa, &usSourcePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = NtOpenFile(&hFile, DELETE | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN_FOR_BACKUP_INTENT | FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(status)) return status;

    // Prepare rename structure with bounds check
    SIZE_T targetLenBytes = usTargetPath.Length;
    SIZE_T requiredSize = sizeof(FILE_RENAME_INFORMATION) + targetLenBytes;
    
    if (requiredSize > sizeof(buffer)) {
        NtClose(hFile);
        DisplayMessage(L"FAILED: Target path too long for rename\r\n");
        return STATUS_BUFFER_TOO_SMALL;
    }
    
    memset_impl(buffer, 0, sizeof(buffer));
    pRename->ReplaceIfExists = entry->ReplaceIfExists ? 1 : 0;
    pRename->FileNameLength = (ULONG)usTargetPath.Length;
    
    SIZE_T charCount = usTargetPath.Length / sizeof(WCHAR);
    for (ULONG i = 0; i < charCount; i++) {
        pRename->FileName[i] = usTargetPath.Buffer[i];
    }

    status = NtSetInformationFile(hFile, &iosb, pRename, (ULONG)requiredSize - sizeof(WCHAR), 10);
    NtClose(hFile);
    
    if (NT_SUCCESS(status)) {
        DisplayMessage(L"SUCCESS: File renamed\r\n");
    }
    return status;
}

// Returns TRUE if the NtQueryDirectoryFile entry name is "." or "..".
// nameLen is in bytes (FileNameLength field of FILE_DIRECTORY_INFORMATION).
BOOLEAN IsDotDirectory(PWSTR name, ULONG nameLen) {
    if (nameLen == sizeof(WCHAR) && name[0] == L'.') return TRUE;
    if (nameLen == 2 * sizeof(WCHAR) && name[0] == L'.' && name[1] == L'.') return TRUE;
    return FALSE;
}

// Recursively deletes all contents of dirPath, then deletes dirPath itself.
// Subdirectories are deleted depth-first.  Returns STATUS_SUCCESS even if
// some entries could not be deleted (best-effort).
NTSTATUS DeleteDirectoryRecursive(PUNICODE_STRING dirPath) {
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hDir;
    NTSTATUS status;
    UCHAR buffer[4096];
    PFILE_DIRECTORY_INFORMATION dirInfo;
    BOOLEAN firstQuery = TRUE;

    InitializeObjectAttributes(&oa, dirPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = NtOpenFile(&hDir, FILE_LIST_DIRECTORY | DELETE | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT);
    if (!NT_SUCCESS(status)) return status;

    while (TRUE) {
        memset_impl(buffer, 0, sizeof(buffer));
        status = NtQueryDirectoryFile(hDir, NULL, NULL, NULL, &iosb, buffer, sizeof(buffer), FileDirectoryInformation, FALSE, NULL, firstQuery);
        if (status == 0x80000006 || !NT_SUCCESS(status)) break;
        firstQuery = FALSE;
        dirInfo = (PFILE_DIRECTORY_INFORMATION)buffer;

        while (TRUE) {
            if (!IsDotDirectory(dirInfo->FileName, dirInfo->FileNameLength)) {
                WCHAR fullPath[MAX_PATH_LEN];
                UNICODE_STRING usFullPath;
                
                // Safe path construction with bounds checking
                SIZE_T baseLen = UnicodeStringCopySafe(fullPath, MAX_PATH_LEN, dirPath);
                if (baseLen >= MAX_PATH_LEN - 1) {
                    NtClose(hDir);
                    return STATUS_BUFFER_TOO_SMALL;
                }
                
                SIZE_T afterSlash = wcscat_safe(fullPath, MAX_PATH_LEN, L"\\");
                if (afterSlash >= MAX_PATH_LEN) {
                    NtClose(hDir);
                    return STATUS_BUFFER_TOO_SMALL;
                }
                
                // Append filename with length validation
                ULONG fnChars = dirInfo->FileNameLength / sizeof(WCHAR);
                SIZE_T currentLen = wcslen(fullPath);
                
                if (!validate_string_space(currentLen, fnChars, MAX_PATH_LEN)) {
                    NtClose(hDir);
                    return STATUS_BUFFER_TOO_SMALL;
                }
                
                for (ULONG i = 0; i < fnChars; i++) {
                    fullPath[currentLen + i] = dirInfo->FileName[i];
                }
                fullPath[currentLen + fnChars] = 0;
                
                RtlInitUnicodeString(&usFullPath, fullPath);

                // Recursively delete subdirectories
                if (dirInfo->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    DeleteDirectoryRecursive(&usFullPath);
                }

                // Delete file/directory
                OBJECT_ATTRIBUTES oaItem;
                HANDLE hItem;
                InitializeObjectAttributes(&oaItem, &usFullPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
                status = NtOpenFile(&hItem, DELETE | SYNCHRONIZE, &oaItem, &iosb, FILE_SHARE_DELETE, FILE_OPEN_FOR_BACKUP_INTENT | FILE_SYNCHRONOUS_IO_NONALERT);
                if (NT_SUCCESS(status)) {
                    FILE_DISPOSITION_INFORMATION dispInfo; 
                    dispInfo.DeleteFile = TRUE;
                    NtSetInformationFile(hItem, &iosb, &dispInfo, sizeof(dispInfo), 13);
                    NtClose(hItem);
                }
            }
            if (dirInfo->NextEntryOffset == 0) break;
            dirInfo = (PFILE_DIRECTORY_INFORMATION)((UCHAR*)dirInfo + dirInfo->NextEntryOffset);
        }
    }
    
    NtClose(hDir);
    
    // Delete the directory itself
    InitializeObjectAttributes(&oa, dirPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = NtOpenFile(&hDir, DELETE | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_DELETE, FILE_DIRECTORY_FILE | FILE_OPEN_FOR_BACKUP_INTENT | FILE_SYNCHRONOUS_IO_NONALERT);
    if (NT_SUCCESS(status)) {
        FILE_DISPOSITION_INFORMATION dispInfo; 
        dispInfo.DeleteFile = TRUE;
        NtSetInformationFile(hDir, &iosb, &dispInfo, sizeof(dispInfo), 13);
        NtClose(hDir);
    }
    return STATUS_SUCCESS;
}

// Delete DeletePath (file or directory).
// For directories: if RecursiveDelete=YES, calls DeleteDirectoryRecursive;
// otherwise attempts a simple directory delete (fails if not empty).
NTSTATUS ExecuteDelete(PINI_ENTRY entry) {
    UNICODE_STRING usPath;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hFile;
    NTSTATUS status;
    FILE_DISPOSITION_INFORMATION dispInfo;
    RtlInitUnicodeString(&usPath, entry->DeletePath);
    InitializeObjectAttributes(&oa, &usPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = NtOpenFile(&hFile, DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN_FOR_BACKUP_INTENT | FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(status)) return status;

    FILE_STANDARD_INFORMATION fileInfo;
    memset_impl(&fileInfo, 0, sizeof(fileInfo));
    status = NtQueryInformationFile(hFile, &iosb, &fileInfo, sizeof(fileInfo), FileStandardInformation);

    if (NT_SUCCESS(status) && fileInfo.Directory) {
        NtClose(hFile);
        if (entry->RecursiveDelete) {
            status = DeleteDirectoryRecursive(&usPath);
            if (NT_SUCCESS(status)) DisplayMessage(L"SUCCESS: Tree deleted\r\n");
        } else {
            status = NtOpenFile(&hFile, DELETE | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_DELETE, FILE_DIRECTORY_FILE | FILE_OPEN_FOR_BACKUP_INTENT | FILE_SYNCHRONOUS_IO_NONALERT);
            if (NT_SUCCESS(status)) {
                dispInfo.DeleteFile = TRUE;
                status = NtSetInformationFile(hFile, &iosb, &dispInfo, sizeof(dispInfo), 13);
                NtClose(hFile);
                if (NT_SUCCESS(status)) DisplayMessage(L"SUCCESS: Directory deleted\r\n");
            }
        }
    } else {
        dispInfo.DeleteFile = TRUE;
        status = NtSetInformationFile(hFile, &iosb, &dispInfo, sizeof(dispInfo), 13);
        NtClose(hFile);
        if (NT_SUCCESS(status)) DisplayMessage(L"SUCCESS: File deleted\r\n");
    }
    return status;
}
