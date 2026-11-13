// KillerSession.h
// RAII session for the K7 process termination driver.
// Owns the registry policy lease, service state, and device handle.

#pragma once

#include <windows.h>
#include <winsvc.h>
#include <cwctype>
#include <iterator>
#include <string>
#include <vector>

class KillerSession {
public:
    struct KillResult {
        bool processGone = false;
        bool requestAccepted = false;
        bool hasDriverStatus = false;
        DWORD transportError = ERROR_SUCCESS;
        DWORD bytesReturned = 0;
        DWORD driverStatus = 0;

        explicit operator bool() const noexcept { return processGone; }
    };

    KillerSession() = default;
    ~KillerSession() noexcept { (void)Close(); }

    KillerSession(const KillerSession&) = delete;
    KillerSession& operator=(const KillerSession&) = delete;

    bool Open(const std::wstring& driverPath) {
        if (m_ready) return true;

        m_driverPath = driverPath;
        m_driverPathNormalized = NormalizePath(driverPath);

        if (m_driverPathNormalized.empty() || !SaveRegState()) {
            (void)Close();
            return false;
        }
        if (!ConfigureReg()) {
            (void)Close();
            return false;
        }
        if (!AcquireService()) {
            (void)Close();
            return false;
        }
        if (!OpenDevice()) {
            (void)Close();
            return false;
        }
        if (!DoHandshake()) {
            (void)Close();
            return false;
        }

        m_ready = true;
        return true;
    }

    bool Close() noexcept {
        bool ok = true;
        if (!CloseDevice()) ok = false;
        if (!ReleaseService()) ok = false;
        if (!RestoreReg()) ok = false;
        m_ready = false;
        m_driverPath.clear();
        m_driverPathNormalized.clear();
        return ok;
    }

    bool IsReady() const noexcept { return m_ready; }

    KillResult Kill(DWORD pid) noexcept {
        KillResult result{};
        if (!m_ready || m_device == INVALID_HANDLE_VALUE || pid == 0) {
            result.transportError = ERROR_INVALID_STATE;
            return result;
        }

        DWORD status = 0;
        DWORD returned = 0;
        SetLastError(ERROR_SUCCESS);
        result.requestAccepted = DeviceIoControl(
            m_device,
            IOCTL_KILL,
            &pid,
            sizeof(pid),
            &status,
            sizeof(status),
            &returned,
            nullptr
        ) != FALSE;
        result.transportError = GetLastError();
        result.bytesReturned = returned;

        if (returned >= sizeof(status)) {
            result.hasDriverStatus = true;
            result.driverStatus = status;
        }

        // The process outcome is authoritative. A successful termination with
        // no status buffer must not be reported as an IOCTL failure.
        result.processGone = VerifyDead(pid);
        return result;
    }

    static bool VerifyDead(DWORD pid) noexcept {
        HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, pid);
        if (!process) {
            return GetLastError() == ERROR_INVALID_PARAMETER;
        }

        const bool gone = WaitForSingleObject(process, 1500) == WAIT_OBJECT_0;
        CloseHandle(process);
        return gone;
    }

private:
    static constexpr DWORD IOCTL_HANDSHAKE = 0x00222008;
    static constexpr DWORD IOCTL_KILL = 0x00222018;
    static constexpr DWORD MAGIC_ALIVE = 0x77777777;
    static constexpr const wchar_t* REG_KEY =
        L"SOFTWARE\\Wow6432Node\\K7 Computing\\K7TotalSecurity";
    static constexpr const wchar_t* REG_PARENT =
        L"SOFTWARE\\Wow6432Node\\K7 Computing";
    static constexpr const wchar_t* REG_VALUE = L"DirProductBase";
    static constexpr const wchar_t* SVC_NAME = L"K7RKScan";
    static constexpr const wchar_t* DEV_PATH = L"\\\\.\\DosK7RKScnDrv";

    enum class Presence {
        Missing,
        Present,
        Error
    };

    std::wstring m_driverPath;
    std::wstring m_driverPathNormalized;
    bool m_ready = false;

    // ── Registry lease ──────────────────────────────────────────────────────

    struct RegLease {
        bool saved = false;
        bool parentExisted = false;
        bool keyExisted = false;
        bool valueExisted = false;
        DWORD originalType = REG_NONE;
        std::vector<BYTE> originalData;
    } m_reg;

    bool m_regTouched = false;

    static Presence QueryKeyPresence(const wchar_t* path) noexcept {
        HKEY key = nullptr;
        const LONG result = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            path,
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &key
        );
        if (result == ERROR_SUCCESS) {
            RegCloseKey(key);
            return Presence::Present;
        }
        if (result == ERROR_FILE_NOT_FOUND || result == ERROR_PATH_NOT_FOUND) {
            return Presence::Missing;
        }
        return Presence::Error;
    }

    static Presence QueryKeyEmpty(const wchar_t* path, bool& empty) noexcept {
        HKEY key = nullptr;
        const LONG openResult = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            path,
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &key
        );
        if (openResult == ERROR_FILE_NOT_FOUND
            || openResult == ERROR_PATH_NOT_FOUND) {
            empty = true;
            return Presence::Missing;
        }
        if (openResult != ERROR_SUCCESS) {
            return Presence::Error;
        }

        DWORD subkeys = 0;
        DWORD values = 0;
        const LONG queryResult = RegQueryInfoKeyW(
            key,
            nullptr, nullptr, nullptr,
            &subkeys,
            nullptr, nullptr,
            &values,
            nullptr, nullptr, nullptr, nullptr
        );
        RegCloseKey(key);
        if (queryResult != ERROR_SUCCESS) {
            return Presence::Error;
        }

        empty = subkeys == 0 && values == 0;
        return Presence::Present;
    }

    bool SaveRegState() noexcept {
        if (m_reg.saved) return true;

        const Presence parentPresence = QueryKeyPresence(REG_PARENT);
        const Presence keyPresence = QueryKeyPresence(REG_KEY);
        if (parentPresence == Presence::Error || keyPresence == Presence::Error) {
            return false;
        }

        m_reg.parentExisted = parentPresence == Presence::Present;
        m_reg.keyExisted = keyPresence == Presence::Present;

        if (m_reg.keyExisted) {
            HKEY key = nullptr;
            if (RegOpenKeyExW(
                    HKEY_LOCAL_MACHINE,
                    REG_KEY,
                    0,
                    KEY_QUERY_VALUE | KEY_WOW64_64KEY,
                    &key
                ) != ERROR_SUCCESS) {
                return false;
            }

            DWORD type = REG_NONE;
            DWORD size = 0;
            LONG result = RegQueryValueExW(
                key,
                REG_VALUE,
                nullptr,
                &type,
                nullptr,
                &size
            );

            if (result == ERROR_SUCCESS) {
                bool captured = false;
                for (int attempt = 0; attempt < 3; ++attempt) {
                    m_reg.originalData.resize(size);
                    DWORD actualSize = size;
                    result = RegQueryValueExW(
                        key,
                        REG_VALUE,
                        nullptr,
                        &type,
                        m_reg.originalData.empty()
                            ? nullptr
                            : m_reg.originalData.data(),
                        &actualSize
                    );
                    if (result == ERROR_SUCCESS) {
                        m_reg.originalData.resize(actualSize);
                        m_reg.originalType = type;
                        m_reg.valueExisted = true;
                        captured = true;
                        break;
                    }
                    if (result != ERROR_MORE_DATA) break;
                    size = actualSize;
                }
                if (!captured) {
                    RegCloseKey(key);
                    return false;
                }
            } else if (result != ERROR_FILE_NOT_FOUND) {
                RegCloseKey(key);
                return false;
            }

            RegCloseKey(key);
        }

        m_reg.saved = true;
        return true;
    }

    bool ConfigureReg() noexcept {
        wchar_t directory[MAX_PATH]{};
        const DWORD length = GetModuleFileNameW(
            nullptr,
            directory,
            static_cast<DWORD>(std::size(directory))
        );
        if (length == 0 || length >= std::size(directory)) {
            return false;
        }
        if (wchar_t* slash = wcsrchr(directory, L'\\')) {
            *slash = L'\0';
        }

        HKEY key = nullptr;
        if (RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                REG_KEY,
                0,
                nullptr,
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE | KEY_WOW64_64KEY,
                nullptr,
                &key,
                nullptr
            ) != ERROR_SUCCESS) {
            return false;
        }

        // Mark the lease as touched as soon as key creation succeeds. A failed
        // value write may still have created one or both empty parent keys.
        m_regTouched = true;

        const DWORD bytes = static_cast<DWORD>(
            (wcslen(directory) + 1) * sizeof(wchar_t)
        );
        const LONG result = RegSetValueExW(
            key,
            REG_VALUE,
            0,
            REG_SZ,
            reinterpret_cast<const BYTE*>(directory),
            bytes
        );
        RegCloseKey(key);
        return result == ERROR_SUCCESS;
    }

    bool RestoreReg() noexcept {
        if (!m_regTouched) {
            m_reg = {};
            return true;
        }
        if (!m_reg.saved) return false;

        bool ok = true;
        HKEY key = nullptr;

        if (m_reg.valueExisted) {
            if (RegCreateKeyExW(
                    HKEY_LOCAL_MACHINE,
                    REG_KEY,
                    0,
                    nullptr,
                    REG_OPTION_NON_VOLATILE,
                    KEY_SET_VALUE | KEY_WOW64_64KEY,
                    nullptr,
                    &key,
                    nullptr
                ) == ERROR_SUCCESS) {
                const LONG result = RegSetValueExW(
                    key,
                    REG_VALUE,
                    0,
                    m_reg.originalType,
                    m_reg.originalData.empty()
                        ? nullptr
                        : m_reg.originalData.data(),
                    static_cast<DWORD>(m_reg.originalData.size())
                );
                if (result != ERROR_SUCCESS) ok = false;
                RegCloseKey(key);
            } else {
                ok = false;
            }
        } else {
            if (RegOpenKeyExW(
                    HKEY_LOCAL_MACHINE,
                    REG_KEY,
                    0,
                    KEY_SET_VALUE | KEY_WOW64_64KEY,
                    &key
                ) == ERROR_SUCCESS) {
                const LONG result = RegDeleteValueW(key, REG_VALUE);
                if (result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND) {
                    ok = false;
                }
                RegCloseKey(key);
            } else {
                const DWORD error = GetLastError();
                if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
                    ok = false;
                }
            }
        }

        if (!m_reg.keyExisted) {
            bool empty = false;
            const Presence presence = QueryKeyEmpty(REG_KEY, empty);
            if (presence == Presence::Error) {
                ok = false;
            } else if (presence == Presence::Present && empty) {
                const LONG result = RegDeleteKeyExW(
                    HKEY_LOCAL_MACHINE,
                    REG_KEY,
                    KEY_WOW64_64KEY,
                    0
                );
                if (result != ERROR_SUCCESS
                    && result != ERROR_FILE_NOT_FOUND
                    && result != ERROR_PATH_NOT_FOUND) {
                    ok = false;
                }
            }
        }

        if (!m_reg.parentExisted) {
            bool empty = false;
            const Presence presence = QueryKeyEmpty(REG_PARENT, empty);
            if (presence == Presence::Error) {
                ok = false;
            } else if (presence == Presence::Present && empty) {
                const LONG result = RegDeleteKeyExW(
                    HKEY_LOCAL_MACHINE,
                    REG_PARENT,
                    KEY_WOW64_64KEY,
                    0
                );
                if (result != ERROR_SUCCESS
                    && result != ERROR_FILE_NOT_FOUND
                    && result != ERROR_PATH_NOT_FOUND) {
                    ok = false;
                }
            }
        }

        if (ok) {
            m_reg = {};
            m_regTouched = false;
        }
        return ok;
    }

    // ── Service lifecycle ───────────────────────────────────────────────────

    SC_HANDLE m_scm = nullptr;
    SC_HANDLE m_svc = nullptr;
    bool m_ownService = false;
    bool m_startedExistingService = false;

    static std::wstring NormalizePath(std::wstring path) {
        if (path.empty()) return {};

        while (!path.empty() && iswspace(path.front())) path.erase(path.begin());
        while (!path.empty() && iswspace(path.back())) path.pop_back();
        if (path.size() >= 2 && path.front() == L'"' && path.back() == L'"') {
            path = path.substr(1, path.size() - 2);
        }
        if (path.rfind(L"\\??\\", 0) == 0) {
            path.erase(0, 4);
        }
        if (path.rfind(L"\\SystemRoot\\", 0) == 0) {
            wchar_t windowsDirectory[MAX_PATH]{};
            const UINT length = GetWindowsDirectoryW(
                windowsDirectory,
                static_cast<UINT>(std::size(windowsDirectory))
            );
            if (length == 0 || length >= std::size(windowsDirectory)) return {};
            path = std::wstring(windowsDirectory) + path.substr(11);
        }

        std::vector<wchar_t> fullPath(MAX_PATH * 2);
        const DWORD length = GetFullPathNameW(
            path.c_str(),
            static_cast<DWORD>(fullPath.size()),
            fullPath.data(),
            nullptr
        );
        std::wstring normalized = (
            length > 0 && length < fullPath.size()
        ) ? std::wstring(fullPath.data(), length) : path;

        for (wchar_t& character : normalized) {
            character = static_cast<wchar_t>(std::towlower(character));
        }
        return normalized;
    }

    static bool WaitForState(
        SC_HANDLE service,
        DWORD desiredState,
        DWORD timeoutMs
    ) noexcept {
        const ULONGLONG deadline = GetTickCount64() + timeoutMs;
        do {
            SERVICE_STATUS status{};
            if (!QueryServiceStatus(service, &status)) return false;
            if (status.dwCurrentState == desiredState) return true;
            Sleep(50);
        } while (GetTickCount64() < deadline);
        return false;
    }

    bool QueryExistingServicePath(std::wstring& path) const {
        DWORD needed = 0;
        SetLastError(ERROR_SUCCESS);
        QueryServiceConfigW(m_svc, nullptr, 0, &needed);
        const DWORD error = GetLastError();
        if (needed == 0 || error != ERROR_INSUFFICIENT_BUFFER) {
            return false;
        }

        std::vector<BYTE> buffer(needed);
        auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
        if (!QueryServiceConfigW(m_svc, config, needed, &needed)) {
            return false;
        }

        path = config->lpBinaryPathName ? config->lpBinaryPathName : L"";
        return !path.empty();
    }

    bool AcquireService() noexcept {
        m_scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (!m_scm) return false;

        m_svc = OpenServiceW(
            m_scm,
            SVC_NAME,
            SERVICE_START | SERVICE_STOP | DELETE |
            SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG
        );

        if (m_svc) {
            std::wstring existingPath;
            if (!QueryExistingServicePath(existingPath)
                || NormalizePath(existingPath) != m_driverPathNormalized) {
                return false;
            }

            SERVICE_STATUS initialStatus{};
            if (!QueryServiceStatus(m_svc, &initialStatus)) return false;

            if (initialStatus.dwCurrentState == SERVICE_RUNNING) {
                return true;
            }
            if (initialStatus.dwCurrentState != SERVICE_STOPPED) {
                return false;
            }

            if (!StartServiceW(m_svc, 0, nullptr)
                && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
                return false;
            }
            m_startedExistingService = true;
            return WaitForState(m_svc, SERVICE_RUNNING, 5000);
        }

        if (GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST) {
            return false;
        }

        m_svc = CreateServiceW(
            m_scm,
            SVC_NAME,
            SVC_NAME,
            SERVICE_START | SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            m_driverPath.c_str(),
            nullptr, nullptr, nullptr, nullptr, nullptr
        );
        if (!m_svc) return false;
        m_ownService = true;

        if (!StartServiceW(m_svc, 0, nullptr)
            && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
            return false;
        }
        return WaitForState(m_svc, SERVICE_RUNNING, 5000);
    }

    static void StopService(SC_HANDLE service) noexcept {
        SERVICE_STATUS status{};
        ControlService(service, SERVICE_CONTROL_STOP, &status);
        (void)WaitForState(service, SERVICE_STOPPED, 5000);
    }

    bool ReleaseService() noexcept {
        bool ok = true;

        if (m_svc) {
            if (m_ownService) {
                StopService(m_svc);
                if (!DeleteService(m_svc)) {
                    const DWORD error = GetLastError();
                    if (error != ERROR_SERVICE_MARKED_FOR_DELETE
                        && error != ERROR_SERVICE_DOES_NOT_EXIST) {
                        ok = false;
                    }
                }
            } else if (m_startedExistingService) {
                StopService(m_svc);
                SERVICE_STATUS status{};
                if (!QueryServiceStatus(m_svc, &status)
                    || status.dwCurrentState != SERVICE_STOPPED) {
                    ok = false;
                }
            }

            CloseServiceHandle(m_svc);
            m_svc = nullptr;
        }

        if (m_scm) {
            CloseServiceHandle(m_scm);
            m_scm = nullptr;
        }
        m_ownService = false;
        m_startedExistingService = false;
        return ok;
    }

    // ── Device & handshake ──────────────────────────────────────────────────

    HANDLE m_device = INVALID_HANDLE_VALUE;

    bool OpenDevice() noexcept {
        m_device = CreateFileW(
            DEV_PATH,
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr
        );
        return m_device != INVALID_HANDLE_VALUE;
    }

    bool CloseDevice() noexcept {
        if (m_device == INVALID_HANDLE_VALUE) return true;
        const bool ok = CloseHandle(m_device) != FALSE;
        m_device = INVALID_HANDLE_VALUE;
        return ok;
    }

    bool DoHandshake() noexcept {
        DWORD input = MAGIC_ALIVE;
        DWORD output = 0;
        DWORD returned = 0;
        const BOOL accepted = DeviceIoControl(
            m_device,
            IOCTL_HANDSHAKE,
            &input,
            sizeof(input),
            &output,
            sizeof(output),
            &returned,
            nullptr
        );
        return accepted != FALSE
            && returned >= sizeof(output)
            && output == 1;
    }
};
