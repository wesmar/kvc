// ForceIOSession.h
// RAII session for the IObitUnlocker.sys minifilter-bypass driver.
// Owns the SCM service lifecycle, device handle and IOCTL protocol.
//
// Session is atomic: extract → deploy → create service → start → open device.
// Destructor: close device → stop → delete service → remove driver file.

#pragma once

#include <windows.h>
#include <winsvc.h>
#include <string>
#include <vector>

class ForceIOSession {
public:
    static constexpr DWORD IOCTL_ULK_OP  = 0x00222124u;
    static constexpr DWORD IOCTL_ULK_QRY = 0x00222128u;

    static constexpr ULONG OP_DELETE = 1;
    static constexpr ULONG OP_RENAME = 2;
    static constexpr ULONG OP_MOVE   = 3;
    static constexpr ULONG OP_COPY   = 4;

    static constexpr const wchar_t* SERVICE_NAME = L"IObitUnlocker";
    static constexpr const wchar_t* DEVICE_PATH  = L"\\\\.\\IObitUnlockerDevice";
    static constexpr const wchar_t* DRIVER_FILE  = L"forceio.dat";

#pragma pack(push, 1)
    struct ULK_BUFFER {
        wchar_t SourcePath[264];
        wchar_t DestPath[264];
        ULONG   OpType;
        ULONG   Flags;
    };
#pragma pack(pop)
    static_assert(sizeof(ULK_BUFFER) == 0x428, "ULK_BUFFER layout mismatch");

    ForceIOSession() = default;
    ~ForceIOSession() noexcept { Close(); }

    ForceIOSession(const ForceIOSession&) = delete;
    ForceIOSession& operator=(const ForceIOSession&) = delete;

    bool Open(const std::vector<BYTE>& driverData) noexcept {
        if (m_ready) return true;
        if (driverData.empty()) return false;

        if (!BuildDriverPath()) return false;

        SvcStop();
        SvcDelete();

        if (!DeployDriver(driverData)) return false;

        if (!SvcCreateAndStart()) {
            DeleteFileW(m_driverPath);
            return false;
        }

        m_device = CreateFileW(
            DEVICE_PATH,
            GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr
        );
        if (m_device == INVALID_HANDLE_VALUE) {
            SvcStop();
            SvcDelete();
            DeleteFileW(m_driverPath);
            return false;
        }

        m_ready = true;
        return true;
    }

    void Close() noexcept {
        if (m_device != INVALID_HANDLE_VALUE) {
            CloseHandle(m_device);
            m_device = INVALID_HANDLE_VALUE;
        }
        SvcStop();
        SvcDelete();
        if (m_driverPath[0])
            DeleteFileW(m_driverPath);
        m_ready = false;
    }

    bool IsReady() const noexcept { return m_ready; }
    HANDLE Device() const noexcept { return m_device; }

    // ── IOCTL wrappers ──────────────────────────────────────────────────────

    DWORD SendOperation(const wchar_t* src, const wchar_t* dst, ULONG op) noexcept {
        if (!m_ready) return ERROR_INVALID_STATE;

        ULK_BUFFER buf{};
        WCopySafe(buf.SourcePath, src, 264);
        if (dst && dst[0])
            WCopySafe(buf.DestPath, dst, 264);
        buf.OpType = op;
        buf.Flags  = 3;

        ULONG out = 0;
        DWORD ret = 0;
        SetLastError(0);
        DeviceIoControl(m_device, IOCTL_ULK_OP,
                        &buf, sizeof(buf), &out, sizeof(out), &ret, nullptr);
        return GetLastError();
    }

    DWORD Delete(const wchar_t* path) noexcept {
        return SendOperation(path, nullptr, OP_DELETE);
    }

    DWORD Rename(const wchar_t* src, const wchar_t* dst) noexcept {
        return SendOperation(src, dst, OP_RENAME);
    }

    DWORD Move(const wchar_t* src, const wchar_t* dst) noexcept {
        return SendOperation(src, dst, OP_MOVE);
    }

    DWORD Copy(const wchar_t* src, const wchar_t* dst) noexcept {
        return SendOperation(src, dst, OP_COPY);
    }

    DWORD QueryLocks(const wchar_t* path, wchar_t** outBuf, DWORD* outChars) noexcept {
        if (!m_ready) return ERROR_INVALID_STATE;
        *outBuf   = nullptr;
        *outChars = 0;

        wchar_t inPath[264]{};
        WCopySafe(inPath, path, 264);

        static constexpr DWORD kSizes[] = { 0x10000, 0x20000, 0x40000, 0x80000, 0 };
        for (int i = 0; kSizes[i]; ++i) {
            auto* buf = static_cast<wchar_t*>(
                VirtualAlloc(nullptr, kSizes[i], MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
            if (!buf) return GetLastError();

            DWORD returned = 0;
            SetLastError(0);
            DeviceIoControl(m_device, IOCTL_ULK_QRY,
                            inPath, static_cast<DWORD>(264 * sizeof(wchar_t)),
                            buf, kSizes[i], &returned, nullptr);
            DWORD err = GetLastError();

            if (err == ERROR_INSUFFICIENT_BUFFER) {
                VirtualFree(buf, 0, MEM_RELEASE);
                continue;
            }
            if (err != 0) {
                VirtualFree(buf, 0, MEM_RELEASE);
                return err;
            }

            *outBuf   = buf;
            *outChars = returned / static_cast<DWORD>(sizeof(wchar_t));
            return 0;
        }
        return ERROR_INSUFFICIENT_BUFFER;
    }

private:
    HANDLE m_device    = INVALID_HANDLE_VALUE;
    bool   m_ready     = false;
    wchar_t m_driverPath[MAX_PATH]{};

    static void WCopySafe(wchar_t* dst, const wchar_t* src, int maxChars) noexcept {
        int i = 0;
        while (i < maxChars - 1 && src[i]) { dst[i] = src[i]; ++i; }
        dst[i] = L'\0';
    }

    bool BuildDriverPath() noexcept {
        wchar_t winDir[MAX_PATH]{};
        if (GetWindowsDirectoryW(winDir, MAX_PATH - 32) == 0)
            return false;
        int len = 0;
        while (winDir[len]) ++len;
        if (len > 0 && winDir[len - 1] != L'\\')
            winDir[len++] = L'\\';
        const wchar_t* name = DRIVER_FILE;
        int i = 0;
        while (name[i] && len + i < MAX_PATH - 1) {
            winDir[len + i] = name[i];
            ++i;
        }
        winDir[len + i] = L'\0';
        for (int j = 0; j < MAX_PATH; ++j)
            m_driverPath[j] = winDir[j];
        return true;
    }

    bool DeployDriver(const std::vector<BYTE>& data) noexcept {
        HANDLE hFile = CreateFileW(
            m_driverPath, GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr
        );
        if (hFile == INVALID_HANDLE_VALUE) return false;

        DWORD written = 0;
        BOOL ok = WriteFile(hFile, data.data(),
                            static_cast<DWORD>(data.size()), &written, nullptr);
        CloseHandle(hFile);
        return ok && written == static_cast<DWORD>(data.size());
    }

    void SvcStop() noexcept {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (!scm) return;
        SC_HANDLE svc = OpenServiceW(scm, SERVICE_NAME,
                                     SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (svc) {
            SERVICE_STATUS st{};
            ControlService(svc, SERVICE_CONTROL_STOP, &st);
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
    }

    void SvcDelete() noexcept {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (!scm) return;
        SC_HANDLE svc = OpenServiceW(scm, SERVICE_NAME, DELETE);
        if (svc) {
            DeleteService(svc);
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
    }

    bool SvcCreateAndStart() noexcept {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (!scm) return false;

        SC_HANDLE svc = nullptr;
        for (int attempt = 0; attempt < 3; ++attempt) {
            svc = CreateServiceW(
                scm, SERVICE_NAME, SERVICE_NAME,
                SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
                DRIVER_FILE, nullptr, nullptr, nullptr, nullptr, nullptr
            );
            if (svc) break;

            DWORD err = GetLastError();
            if (err == ERROR_SERVICE_EXISTS) {
                svc = OpenServiceW(scm, SERVICE_NAME, SERVICE_ALL_ACCESS);
                if (svc) {
                    ChangeServiceConfigW(
                        svc, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                        SERVICE_ERROR_IGNORE, DRIVER_FILE,
                        nullptr, nullptr, nullptr, nullptr, nullptr, SERVICE_NAME
                    );
                }
                break;
            }
            if (err == ERROR_SERVICE_MARKED_FOR_DELETE) continue;
            break;
        }

        if (!svc) {
            CloseServiceHandle(scm);
            return false;
        }

        BOOL ok = StartServiceW(svc, 0, nullptr);
        if (!ok) {
            DWORD err = GetLastError();
            if (err == ERROR_SERVICE_ALREADY_RUNNING) {
                ok = TRUE;
            } else if (err == ERROR_SERVICE_DISABLED) {
                ChangeServiceConfigW(
                    svc, SERVICE_NO_CHANGE, SERVICE_DEMAND_START,
                    SERVICE_NO_CHANGE, nullptr,
                    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr
                );
                ok = StartServiceW(svc, 0, nullptr);
                if (!ok && GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
                    ok = TRUE;
            }
        }

        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return ok != FALSE;
    }
};
