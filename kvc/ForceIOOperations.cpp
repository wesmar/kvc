// ForceIOOperations.cpp
// High-level ForceIO command implementations for kvc CLI.
// Commands: locks, delete, rename, copy.

#include "common.h"
#include "ForceIOSession.h"
#include "ForceIOStager.h"
#include "HiveIO.h"
#include "resource.h"
#include "Utils.h"
#include <string>
#include <vector>

// ============================================================================
// PATH SAFETY
// ============================================================================

static constexpr int PATH_CAPACITY = 264;

static bool ResolvePath(const wchar_t* path, wchar_t* full) noexcept {
    if (!path || !path[0]) return false;
    DWORD len = GetFullPathNameW(path, PATH_CAPACITY, full, nullptr);
    if (!len || len >= PATH_CAPACITY) return false;
    if (full[0] == L'\\' && full[1] == L'\\' &&
        (full[2] == L'?' || full[2] == L'.'))
        return false;
    for (DWORD i = 0; i < len; ++i)
        if (full[i] == L'/') full[i] = L'\\';
    while (len > 3 && full[len - 1] == L'\\') full[--len] = L'\0';
    return true;
}

static bool CheckReparseChain(const wchar_t* full) noexcept {
    DWORD start = 3;
    if (full[0] == L'\\' && full[1] == L'\\') {
        start = 2;
        while (full[start] && full[start] != L'\\') ++start;
        if (!full[start]) return false;
        ++start;
    }
    wchar_t buf[PATH_CAPACITY]{};
    for (int i = 0; i < PATH_CAPACITY && full[i]; ++i)
        buf[i] = full[i];
    for (DWORD i = start; ; ++i) {
        wchar_t saved = buf[i];
        if (saved != L'\\' && saved != L'\0') continue;
        buf[i] = L'\0';
        DWORD attr = GetFileAttributesW(buf);
        buf[i] = saved;
        if (attr == INVALID_FILE_ATTRIBUTES) {
            DWORD err = GetLastError();
            if (err != ERROR_FILE_NOT_FOUND && err != ERROR_PATH_NOT_FOUND)
                return false;
        } else if (attr & FILE_ATTRIBUTE_REPARSE_POINT) {
            return false;
        }
        if (!saved) break;
    }
    return true;
}

static bool HasWildcard(const std::wstring& path) noexcept;
static bool SplitWildcard(
    const std::wstring& path,
    std::wstring& dir,
    std::wstring& pattern
) noexcept;

static bool SafeResolve(const wchar_t* path, std::wstring& out) noexcept {
    wchar_t full[PATH_CAPACITY]{};
    if (!ResolvePath(path, full)) return false;

    std::wstring resolved(full);
    if (HasWildcard(resolved)) {
        std::wstring dir;
        std::wstring pattern;
        if (!SplitWildcard(resolved, dir, pattern)) return false;

        wchar_t fullDir[PATH_CAPACITY]{};
        if (!ResolvePath(dir.c_str(), fullDir) || !CheckReparseChain(fullDir))
            return false;

        out = std::wstring(fullDir) + L"\\" + pattern;
        return true;
    }

    if (!CheckReparseChain(full)) return false;
    out = std::move(resolved);
    return true;
}

static bool SafeResolvePair(const wchar_t* src, const wchar_t* dst,
                            std::wstring& outSrc, std::wstring& outDst) noexcept {
    if (!SafeResolve(src, outSrc)) return false;
    if (!SafeResolve(dst, outDst)) return false;
    if (CompareStringOrdinal(outSrc.c_str(), -1, outDst.c_str(), -1, TRUE) == CSTR_EQUAL)
        return false;
    return true;
}

// ============================================================================
// WILDCARD UTILITIES
// ============================================================================

static bool HasWildcard(const std::wstring& path) noexcept {
    for (wchar_t c : path)
        if (c == L'*' || c == L'?') return true;
    return false;
}

static bool SplitWildcard(const std::wstring& path, std::wstring& dir, std::wstring& pattern) noexcept {
    auto pos = path.rfind(L'\\');
    if (pos == std::wstring::npos) return false;
    dir = path.substr(0, pos);
    pattern = path.substr(pos + 1);
    if (pattern.empty()) return false;
    for (size_t i = 0; i < pos; ++i)
        if (path[i] == L'*' || path[i] == L'?') return false;
    return true;
}

// ============================================================================
// RESOURCE EXTRACTION HELPER
// ============================================================================

static bool ExtractForceIODriver(std::vector<BYTE>& out) noexcept {
    Utils::ExtractedComponents components;
    if (!Utils::ExtractResourceComponents(
            IDR_MAINICON, Utils::PayloadComponent::ForceIO, components))
        return false;
    if (components.forceIO.empty()) return false;
    out = std::move(components.forceIO);
    return true;
}

// ============================================================================
// RECURSIVE DELETE
// ============================================================================

static DWORD DeleteRecursive(ForceIOSession& session, const std::wstring& path) noexcept {
    std::wstring resolved;
    if (!SafeResolve(path.c_str(), resolved)) return ERROR_INVALID_NAME;

    DWORD attr = GetFileAttributesW(resolved.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) return GetLastError();

    if (attr & FILE_ATTRIBUTE_DIRECTORY) {
        std::wstring pattern = resolved + L"\\*";
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
        if (hFind == INVALID_HANDLE_VALUE) return GetLastError();

        DWORD result = 0;
        do {
            if (fd.cFileName[0] == L'.' &&
                (fd.cFileName[1] == 0 || (fd.cFileName[1] == L'.' && fd.cFileName[2] == 0)))
                continue;
            std::wstring child = resolved + L"\\" + fd.cFileName;
            DWORD err = DeleteRecursive(session, child);
            if (err && !result) result = err;
        } while (FindNextFileW(hFind, &fd));

        DWORD enumErr = GetLastError();
        FindClose(hFind);
        if (!result && enumErr != ERROR_NO_MORE_FILES) result = enumErr;
        if (result) return result;
    }

    return session.Delete(resolved.c_str());
}

// ============================================================================
// RECURSIVE COPY
// ============================================================================

static DWORD CopyRecursive(ForceIOSession& session, const std::wstring& src, const std::wstring& dst) noexcept {
    std::wstring resolvedSrc, resolvedDst;
    if (!SafeResolvePair(src.c_str(), dst.c_str(), resolvedSrc, resolvedDst))
        return ERROR_INVALID_NAME;

    DWORD attr = GetFileAttributesW(resolvedSrc.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) return GetLastError();
    DWORD dstAttr = GetFileAttributesW(resolvedDst.c_str());

    if (attr & FILE_ATTRIBUTE_DIRECTORY) {
        DWORD err = session.Copy(resolvedSrc.c_str(), resolvedDst.c_str());
        if (err == 0) return 0;

        if (dstAttr == INVALID_FILE_ATTRIBUTES) {
            if (!CreateDirectoryW(resolvedDst.c_str(), nullptr))
                return GetLastError();
        } else if (!(dstAttr & FILE_ATTRIBUTE_DIRECTORY)) {
            return ERROR_ALREADY_EXISTS;
        }

        std::wstring pattern = resolvedSrc + L"\\*";
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
        if (hFind == INVALID_HANDLE_VALUE) return GetLastError();

        DWORD result = 0;
        do {
            if (fd.cFileName[0] == L'.' &&
                (fd.cFileName[1] == 0 || (fd.cFileName[1] == L'.' && fd.cFileName[2] == 0)))
                continue;
            std::wstring childSrc = resolvedSrc + L"\\" + fd.cFileName;
            std::wstring childDst = resolvedDst + L"\\" + fd.cFileName;
            DWORD childErr = CopyRecursive(session, childSrc, childDst);
            if (childErr && !result) result = childErr;
        } while (FindNextFileW(hFind, &fd));

        DWORD enumErr = GetLastError();
        FindClose(hFind);
        if (!result && enumErr != ERROR_NO_MORE_FILES) result = enumErr;
        return result;
    }

    if (dstAttr != INVALID_FILE_ATTRIBUTES) return ERROR_ALREADY_EXISTS;

    // Hive interception: if source is a mounted hive, use RegSaveKeyExW
    HiveIO::HiveMatch hive;
    if (HiveIO::IsHivePath(resolvedSrc.c_str(), hive))
        return HiveIO::Save(hive.rootKey, hive.subKey.c_str(), resolvedDst.c_str(), false);

    return session.Copy(resolvedSrc.c_str(), resolvedDst.c_str());
}

// ============================================================================
// LOCK QUERY OUTPUT
// ============================================================================

static void PrintLockList(wchar_t* buf, DWORD nChars) noexcept {
    if (nChars == 0) {
        SUCCESS(L"No processes currently lock this file.");
        return;
    }

    DWORD count = 0;
    wchar_t* entry = buf;
    wchar_t* end   = buf + nChars;

    while (entry < end && *entry) {
        wchar_t* pipe = entry;
        while (pipe < end && *pipe && *pipe != L'|') ++pipe;
        if (pipe == end) break;

        wchar_t* comma = (pipe > entry) ? pipe - 1 : entry;
        while (comma > entry && *comma != L',') --comma;

        if (comma > entry) {
            wchar_t savedPipe = *pipe; *pipe = L'\0';
            wchar_t savedComma = *comma; *comma = L'\0';

            wchar_t* bs = comma;
            while (bs > entry && *bs != L'\\') --bs;
            if (*bs == L'\\') ++bs;

            INFO(L"  PID %-6s  %-20s  (%s)", comma + 1, bs, entry);
            *comma = savedComma;
            *pipe = savedPipe;
        }
        ++count;
        entry = pipe;
        if (entry < end && *entry == L'|') ++entry;
    }
    INFO(L"  %lu process(es) locking the file.", count);
}

// ============================================================================
// COMMAND HANDLERS (called from Kvc.cpp dispatch table)
// ============================================================================

int HandleForceIOLocks(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        ERROR(L"Usage: kvc locks <path>");
        return 1;
    }

    std::wstring path = argv[2];
    for (int i = 3; i < argc; ++i) { path += L' '; path += argv[i]; }

    std::wstring resolved;
    if (!SafeResolve(path.c_str(), resolved)) {
        ERROR(L"Invalid or unsafe path: %s", path.c_str());
        return 1;
    }

    DWORD exitCode = 0;
    if (ForceIOStager::EnsurePadded(&exitCode))
        return static_cast<int>(exitCode);

    std::vector<BYTE> driverData;
    if (!ExtractForceIODriver(driverData)) {
        ERROR(L"Failed to extract forceio.sys from resource");
        return 2;
    }

    ForceIOSession session;
    if (!session.Open(driverData)) {
        ERROR(L"Failed to start ForceIO driver session");
        return 2;
    }

    if (HasWildcard(resolved)) {
        std::wstring dir, pattern;
        if (!SplitWildcard(resolved, dir, pattern)) {
            ERROR(L"Unsupported wildcard path: %s", resolved.c_str());
            return 1;
        }

        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(resolved.c_str(), &fd);
        if (hFind == INVALID_HANDLE_VALUE) {
            ERROR(L"No matching files: %s", resolved.c_str());
            return 1;
        }

        do {
            if (fd.cFileName[0] == L'.' &&
                (fd.cFileName[1] == 0 || (fd.cFileName[1] == L'.' && fd.cFileName[2] == 0)))
                continue;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

            std::wstring child = dir + L"\\" + fd.cFileName;
            INFO(L"LOCKS: %s", child.c_str());

            wchar_t* lockBuf = nullptr;
            DWORD lockChars = 0;
            DWORD err = session.QueryLocks(child.c_str(), &lockBuf, &lockChars);
            if (err == 0) {
                PrintLockList(lockBuf, lockChars);
            } else {
                ERROR(L"  Query failed, error=%lu", err);
            }
            if (lockBuf) VirtualFree(lockBuf, 0, MEM_RELEASE);
        } while (FindNextFileW(hFind, &fd));

        FindClose(hFind);
        return 0;
    }

    INFO(L"LOCKS: %s", resolved.c_str());
    wchar_t* lockBuf = nullptr;
    DWORD lockChars = 0;
    DWORD err = session.QueryLocks(resolved.c_str(), &lockBuf, &lockChars);
    if (err != 0) {
        ERROR(L"Query failed, error=%lu (0x%08X)", err, err);
        return 2;
    }
    PrintLockList(lockBuf, lockChars);
    if (lockBuf) VirtualFree(lockBuf, 0, MEM_RELEASE);
    return 0;
}

int HandleForceIODelete(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        ERROR(L"Usage: kvc delete <path>");
        return 1;
    }

    std::wstring path = argv[2];
    for (int i = 3; i < argc; ++i) { path += L' '; path += argv[i]; }

    std::wstring resolved;
    if (!SafeResolve(path.c_str(), resolved)) {
        ERROR(L"Invalid or unsafe path: %s", path.c_str());
        return 1;
    }

    DWORD exitCode = 0;
    if (ForceIOStager::EnsurePadded(&exitCode))
        return static_cast<int>(exitCode);

    std::vector<BYTE> driverData;
    if (!ExtractForceIODriver(driverData)) {
        ERROR(L"Failed to extract forceio.sys from resource");
        return 2;
    }

    ForceIOSession session;
    if (!session.Open(driverData)) {
        ERROR(L"Failed to start ForceIO driver session");
        return 2;
    }

    if (HasWildcard(resolved)) {
        std::wstring dir, pattern;
        if (!SplitWildcard(resolved, dir, pattern)) {
            ERROR(L"Unsupported wildcard path: %s", resolved.c_str());
            return 1;
        }

        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(resolved.c_str(), &fd);
        if (hFind == INVALID_HANDLE_VALUE) {
            ERROR(L"No matching files: %s", resolved.c_str());
            return 1;
        }

        DWORD result = 0;
        do {
            if (fd.cFileName[0] == L'.' &&
                (fd.cFileName[1] == 0 || (fd.cFileName[1] == L'.' && fd.cFileName[2] == 0)))
                continue;

            std::wstring child = dir + L"\\" + fd.cFileName;
            INFO(L"DELETE: %s", child.c_str());
            DWORD err = DeleteRecursive(session, child);
            if (err == 0) {
                SUCCESS(L"  Deleted.");
            } else {
                ERROR(L"  Failed, error=%lu", err);
                if (!result) result = err;
            }
        } while (FindNextFileW(hFind, &fd));

        FindClose(hFind);
        return result ? 2 : 0;
    }

    INFO(L"DELETE: %s", resolved.c_str());
    DWORD err = DeleteRecursive(session, resolved);
    if (err == 0) {
        SUCCESS(L"Deleted.");
        return 0;
    }
    ERROR(L"Delete failed, error=%lu (0x%08X)", err, err);
    return 2;
}

int HandleForceIORename(int argc, wchar_t* argv[]) {
    if (argc < 4) {
        ERROR(L"Usage: kvc rename <source> <destination>");
        return 1;
    }

    std::wstring srcPath = argv[2];
    std::wstring dstPath = argv[argc - 1];

    // If more than 2 path args and the last one is an absolute path,
    // everything before it is the source (handles unquoted spaces).
    if (argc > 4) {
        srcPath.clear();
        int dstStart = argc - 1;
        for (int i = 3; i < argc; ++i) {
            std::wstring arg = argv[i];
            if (arg.size() >= 2 && ((arg[0] >= L'A' && arg[0] <= L'Z') ||
                (arg[0] >= L'a' && arg[0] <= L'z')) && arg[1] == L':') {
                dstStart = i;
                break;
            }
        }
        srcPath = argv[2];
        for (int i = 3; i < dstStart; ++i) { srcPath += L' '; srcPath += argv[i]; }
        dstPath = argv[dstStart];
        for (int i = dstStart + 1; i < argc; ++i) { dstPath += L' '; dstPath += argv[i]; }
    }

    std::wstring resolvedSrc, resolvedDst;
    if (!SafeResolvePair(srcPath.c_str(), dstPath.c_str(), resolvedSrc, resolvedDst)) {
        ERROR(L"Invalid or unsafe path pair: %s -> %s", srcPath.c_str(), dstPath.c_str());
        return 1;
    }

    DWORD exitCode = 0;
    if (ForceIOStager::EnsurePadded(&exitCode))
        return static_cast<int>(exitCode);

    std::vector<BYTE> driverData;
    if (!ExtractForceIODriver(driverData)) {
        ERROR(L"Failed to extract forceio.sys from resource");
        return 2;
    }

    ForceIOSession session;
    if (!session.Open(driverData)) {
        ERROR(L"Failed to start ForceIO driver session");
        return 2;
    }

    INFO(L"RENAME: %s -> %s", resolvedSrc.c_str(), resolvedDst.c_str());

    // 3-tier fallback: raw rename → MoveFileEx → driver move → copy+delete
    DWORD err = session.Rename(resolvedSrc.c_str(), resolvedDst.c_str());
    if (err == 0) { SUCCESS(L"Renamed."); return 0; }

    if (MoveFileExW(resolvedSrc.c_str(), resolvedDst.c_str(),
                    MOVEFILE_COPY_ALLOWED | MOVEFILE_WRITE_THROUGH)) {
        SUCCESS(L"Renamed (MoveFileEx fallback).");
        return 0;
    }

    if (GetFileAttributesW(resolvedDst.c_str()) != INVALID_FILE_ATTRIBUTES) {
        ERROR(L"Destination already exists: %s", resolvedDst.c_str());
        return 2;
    }

    err = session.Move(resolvedSrc.c_str(), resolvedDst.c_str());
    if (err == 0) { SUCCESS(L"Renamed (move fallback)."); return 0; }

    // Last resort: copy + delete source
    DWORD attr = GetFileAttributesW(resolvedSrc.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        DWORD copyErr = session.Copy(resolvedSrc.c_str(), resolvedDst.c_str());
        if (copyErr == 0) {
            DWORD delErr = session.Delete(resolvedSrc.c_str());
            if (delErr == 0) { SUCCESS(L"Renamed (copy+delete fallback)."); return 0; }
            ERROR(L"Copied but source delete failed, error=%lu", delErr);
            return 2;
        }
    }

    ERROR(L"Rename failed, error=%lu (0x%08X)", err, err);
    return 2;
}

int HandleForceIOCopy(int argc, wchar_t* argv[]) {
    if (argc < 4) {
        ERROR(L"Usage: kvc copy <source> <destination>");
        return 1;
    }

    std::wstring srcPath = argv[2];
    std::wstring dstPath = argv[argc - 1];

    if (argc > 4) {
        srcPath.clear();
        int dstStart = argc - 1;
        for (int i = 3; i < argc; ++i) {
            std::wstring arg = argv[i];
            if (arg.size() >= 2 && ((arg[0] >= L'A' && arg[0] <= L'Z') ||
                (arg[0] >= L'a' && arg[0] <= L'z')) && arg[1] == L':') {
                dstStart = i;
                break;
            }
        }
        srcPath = argv[2];
        for (int i = 3; i < dstStart; ++i) { srcPath += L' '; srcPath += argv[i]; }
        dstPath = argv[dstStart];
        for (int i = dstStart + 1; i < argc; ++i) { dstPath += L' '; dstPath += argv[i]; }
    }

    std::wstring resolvedSrc, resolvedDst;
    if (!SafeResolvePair(srcPath.c_str(), dstPath.c_str(), resolvedSrc, resolvedDst)) {
        ERROR(L"Invalid or unsafe path pair: %s -> %s", srcPath.c_str(), dstPath.c_str());
        return 1;
    }

    DWORD exitCode = 0;
    if (ForceIOStager::EnsurePadded(&exitCode))
        return static_cast<int>(exitCode);

    std::vector<BYTE> driverData;
    if (!ExtractForceIODriver(driverData)) {
        ERROR(L"Failed to extract forceio.sys from resource");
        return 2;
    }

    ForceIOSession session;
    if (!session.Open(driverData)) {
        ERROR(L"Failed to start ForceIO driver session");
        return 2;
    }

    INFO(L"COPY: %s -> %s", resolvedSrc.c_str(), resolvedDst.c_str());
    DWORD err = CopyRecursive(session, resolvedSrc, resolvedDst);
    if (err == 0) {
        SUCCESS(L"Copied.");
        return 0;
    }
    ERROR(L"Copy failed, error=%lu (0x%08X)", err, err);
    return 2;
}
