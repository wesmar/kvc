// HiveIO.h
// Registry hive detection and RegSaveKeyExW-based copy.
//
// Mounted hive files (SAM, SYSTEM, SOFTWARE, SECURITY, NTUSER.DAT, etc.) are
// locked by the kernel registry manager, not by a minifilter. The IObitUnlocker
// IOCTL path returns ERROR_SHARING_VIOLATION for these. RegSaveKeyExW bypasses
// this by flushing a consistent snapshot through the registry manager itself.

#pragma once

#include <windows.h>
#include <string>

namespace HiveIO {

struct HiveMatch {
    HKEY         rootKey = nullptr;
    std::wstring subKey;
};

// Returns true if the Win32 path points to a currently mounted registry hive
// (matched against HKLM\SYSTEM\CurrentControlSet\Control\hivelist).
inline bool IsHivePath(const wchar_t* path, HiveMatch& match) noexcept {
    if (!path || !path[0]) return false;

    // Convert Win32 path to NT device path for matching the hivelist values.
    wchar_t drive[3] = { path[0], L':', L'\0' };
    if (!((path[0] >= L'A' && path[0] <= L'Z') ||
          (path[0] >= L'a' && path[0] <= L'z')) ||
        path[1] != L':' || (path[2] != L'\\' && path[2] != L'/'))
        return false;

    wchar_t device[512]{};
    if (!QueryDosDeviceW(drive, device, 512))
        return false;

    std::wstring ntPath(device);
    ntPath += (path + 2);
    for (auto& c : ntPath) { if (c == L'/') c = L'\\'; }

    HKEY hList = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\hivelist",
                      0, KEY_QUERY_VALUE, &hList) != ERROR_SUCCESS)
        return false;

    bool found = false;
    wchar_t vName[512]{};
    wchar_t vData[1024]{};

    for (DWORD idx = 0; ; ++idx) {
        DWORD cchName = 512, cbData = sizeof(vData), type = 0;
        LSTATUS s = RegEnumValueW(hList, idx, vName, &cchName, nullptr, &type,
                                  reinterpret_cast<BYTE*>(vData), &cbData);
        if (s == ERROR_NO_MORE_ITEMS) break;
        if (s != ERROR_SUCCESS) continue;
        if ((type != REG_SZ && type != REG_EXPAND_SZ) || cbData < 4) continue;

        if (CompareStringOrdinal(vData, -1, ntPath.c_str(), -1, TRUE) != CSTR_EQUAL)
            continue;

        // Parse hivelist value name: \REGISTRY\MACHINE\xxx or \REGISTRY\USER\xxx
        static const wchar_t kMachine[] = L"\\REGISTRY\\MACHINE\\";
        static const wchar_t kUser[]    = L"\\REGISTRY\\USER\\";
        constexpr int mLen = _countof(kMachine) - 1;
        constexpr int uLen = _countof(kUser) - 1;
        int nLen = static_cast<int>(cchName);

        if (nLen > mLen &&
            CompareStringOrdinal(vName, mLen, kMachine, mLen, TRUE) == CSTR_EQUAL) {
            match.rootKey = HKEY_LOCAL_MACHINE;
            match.subKey  = vName + mLen;
            found = true;
        } else if (nLen > uLen &&
                   CompareStringOrdinal(vName, uLen, kUser, uLen, TRUE) == CSTR_EQUAL) {
            match.rootKey = HKEY_USERS;
            match.subKey  = vName + uLen;
            found = true;
        }
        break;
    }

    RegCloseKey(hList);
    return found;
}

// Export a live hive to destPath via RegSaveKeyExW (REG_LATEST_FORMAT).
// Enables SeBackupPrivilege, exports to a temp sibling, and publishes
// the completed snapshot via rename. Returns Win32 error (0 = success).
inline DWORD Save(HKEY rootKey, const wchar_t* subKey,
                  const wchar_t* destPath, bool replaceExisting) noexcept {
    if (!destPath || !destPath[0]) return ERROR_INVALID_NAME;
    if (!rootKey || !subKey) return ERROR_INVALID_HANDLE;

    if (!replaceExisting && GetFileAttributesW(destPath) != INVALID_FILE_ATTRIBUTES)
        return ERROR_ALREADY_EXISTS;

    HANDLE hToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(),
                         TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        TOKEN_PRIVILEGES tp{};
        LUID luid{};
        if (LookupPrivilegeValueW(nullptr, SE_BACKUP_NAME, &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, 0, nullptr, nullptr);
        }
        CloseHandle(hToken);
    }

    HKEY hKey = nullptr;
    LSTATUS s = RegOpenKeyExW(rootKey, subKey, 0, KEY_READ, &hKey);
    if (s != ERROR_SUCCESS) return static_cast<DWORD>(s);

    wchar_t fullPath[MAX_PATH]{};
    wchar_t* fileName = nullptr;
    DWORD length = GetFullPathNameW(destPath, MAX_PATH, fullPath, &fileName);
    if (!length || length >= MAX_PATH || !fileName || !*fileName) {
        DWORD error = !length ? GetLastError() :
            (length >= MAX_PATH ? ERROR_FILENAME_EXCED_RANGE : ERROR_INVALID_NAME);
        RegCloseKey(hKey);
        return error;
    }

    wchar_t directory[MAX_PATH]{};
    wcsncpy_s(directory, fullPath, static_cast<size_t>(fileName - fullPath));

    wchar_t staging[MAX_PATH]{};
    if (!GetTempFileNameW(directory, L"fio", 0, staging)) {
        DWORD error = GetLastError();
        RegCloseKey(hKey);
        return error;
    }
    if (!DeleteFileW(staging)) {
        DWORD error = GetLastError();
        RegCloseKey(hKey);
        return error;
    }

    s = RegSaveKeyExW(hKey, staging, nullptr, REG_LATEST_FORMAT);
    RegCloseKey(hKey);

    if (s == ERROR_SUCCESS) {
        DWORD flags = MOVEFILE_WRITE_THROUGH;
        if (replaceExisting) flags |= MOVEFILE_REPLACE_EXISTING;
        if (!MoveFileExW(staging, fullPath, flags))
            s = static_cast<LSTATUS>(GetLastError());
    }
    if (s != ERROR_SUCCESS)
        DeleteFileW(staging);

    return (s == ERROR_SUCCESS) ? 0 : static_cast<DWORD>(s);
}

} // namespace HiveIO
