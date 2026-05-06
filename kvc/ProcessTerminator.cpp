// ProcessTerminator.cpp
// Process termination with automatic PP/PPL elevation and multi-tier fallback.
//
// Termination ladder for a single PID:
//   1. KillProcessInternal(): elevate caller to target's protection level,
//      then TerminateProcess().
//   2. kvcstrm IOCTL_KILL_WESMAR (via KvcStrmClient).
//
// For KillMultipleTargets() a third tier is added when the first two fail:
//   3. kvckiller.sys (signed kernel driver) via DeviceIoControl on Warsaw_PM.
//
// Killed paths are persisted to HKCU\Software\kvc\KilledPaths so that
// TryRelaunchKilledProcess() can restart them later.

#include "Controller.h"
#include "common.h"
#include "Utils.h"
#include <tlhelp32.h>
#include <unordered_map>

extern volatile bool g_interrupted;

// ── Killed-process path cache ────────────────────────────────────────────────

static void CacheKilledProcessPath(const std::wstring& exeName,
                                    const std::wstring& fullPath) noexcept
{
    std::wstring key = exeName;
    StringUtils::ToLower(key);

    HKEY hKey = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\kvc\\KilledPaths",
                        0, nullptr, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
                        nullptr, &hKey, nullptr) == ERROR_SUCCESS)
    {
        const DWORD sz = static_cast<DWORD>((fullPath.size() + 1) * sizeof(wchar_t));
        RegSetValueExW(hKey, key.c_str(), 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(fullPath.c_str()), sz);
        RegCloseKey(hKey);
    }
}

static std::wstring GetCachedKilledProcessPath(std::wstring exeName) noexcept
{
    StringUtils::ToLower(exeName);
    if (exeName.size() < 4 ||
        exeName.compare(exeName.size() - 4, 4, L".exe") != 0)
        exeName += L".exe";

    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\kvc\\KilledPaths",
                      0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return {};

    wchar_t buf[MAX_PATH] = {};
    DWORD sz = sizeof(buf), type = 0;
    const LONG r = RegQueryValueExW(hKey, exeName.c_str(), nullptr, &type,
                                     reinterpret_cast<LPBYTE>(buf), &sz);
    RegCloseKey(hKey);
    return (r == ERROR_SUCCESS && type == REG_SZ) ? buf : L"";
}

// Attempts to restart a previously killed process.
// Step 1: find a Win32 service whose ImagePath contains the exe name and start it.
// Step 2: fall back to ShellExecuteEx on the cached full path.
bool Controller::TryRelaunchKilledProcess(const std::wstring& name) noexcept
{
    std::wstring exeName = name;
    if (exeName.size() < 4 ||
        _wcsicmp(exeName.c_str() + exeName.size() - 4, L".exe") != 0)
        exeName += L".exe";

    std::wstring lowerExe = exeName;
    StringUtils::ToLower(lowerExe);

    // Step 1: service-based relaunch.
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr,
                                     SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT);
    if (hSCM) {
        DWORD needed = 0, returned = 0, resumeHandle = 0;
        EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                               SERVICE_STATE_ALL, nullptr, 0,
                               &needed, &returned, &resumeHandle, nullptr);

        if (GetLastError() == ERROR_MORE_DATA) {
            std::vector<BYTE> buf(needed);
            auto* svcs = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
            resumeHandle = 0;

            if (EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                                       SERVICE_STATE_ALL, buf.data(), needed,
                                       &needed, &returned, &resumeHandle, nullptr))
            {
                for (DWORD i = 0; i < returned; ++i) {
                    SC_HANDLE hSvc = OpenServiceW(hSCM, svcs[i].lpServiceName,
                                                   SERVICE_QUERY_CONFIG | SERVICE_START);
                    if (!hSvc) continue;

                    DWORD cfgBytes = 0;
                    QueryServiceConfigW(hSvc, nullptr, 0, &cfgBytes);
                    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                        std::vector<BYTE> cfgBuf(cfgBytes);
                        auto* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(cfgBuf.data());
                        if (QueryServiceConfigW(hSvc, cfg, cfgBytes, &cfgBytes)) {
                            std::wstring bin = cfg->lpBinaryPathName;
                            StringUtils::ToLower(bin);
                            if (bin.find(lowerExe) != std::wstring::npos) {
                                const bool ok =
                                    StartServiceW(hSvc, 0, nullptr) ||
                                    GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
                                CloseServiceHandle(hSvc);
                                CloseServiceHandle(hSCM);
                                if (ok) {
                                    SUCCESS(L"Relaunched %s via service", name.c_str());
                                    return true;
                                }
                                break;
                            }
                        }
                    }
                    CloseServiceHandle(hSvc);
                }
            }
        }
        CloseServiceHandle(hSCM);
    }

    // Step 2: cached exe path.
    const std::wstring path = GetCachedKilledProcessPath(name);
    if (path.empty()) {
        INFO(L"No cached path for %s — cannot relaunch", name.c_str());
        return false;
    }

    SHELLEXECUTEINFOW sei{sizeof(sei)};
    sei.fMask  = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";
    sei.lpFile = path.c_str();
    sei.nShow  = SW_NORMAL;
    if (ShellExecuteExW(&sei)) {
        if (sei.hProcess) CloseHandle(sei.hProcess);
        SUCCESS(L"Relaunched %s", name.c_str());
        return true;
    }

    INFO(L"ShellExecuteEx failed for %s: %lu", name.c_str(), GetLastError());
    return false;
}

// ── Core termination primitive ───────────────────────────────────────────────

// Terminates a single PID. If the target has PP or PPL protection, elevates
// the current process to the same level before attempting termination.
// Pass insideBatchSession=true when the caller already holds a driver session.
bool Controller::KillProcessInternal(DWORD pid, bool insideBatchSession) noexcept
{
    if (!insideBatchSession && !BeginDriverSession()) {
        ERROR(L"Failed to start driver session for PID %d", pid);
        return false;
    }

    const auto kernelAddr = GetCachedKernelAddress(pid);
    if (!kernelAddr) {
        if (!insideBatchSession) EndDriverSession(true);
        return false;
    }

    if (const auto prot = GetProcessProtection(kernelAddr.value());
        prot && prot.value() > 0)
    {
        const UCHAR targetLevel  = Utils::GetProtectionLevel(prot.value());
        const UCHAR targetSigner = Utils::GetSignerType(prot.value());
        const std::wstring levelStr =
            (targetLevel == static_cast<UCHAR>(PS_PROTECTED_TYPE::Protected))
                ? L"PP" : L"PPL";

        INFO(L"Target process has %s-%s protection — elevating current process",
             levelStr.c_str(), Utils::GetSignerTypeAsString(targetSigner));

        const UCHAR currentProcessProtection =
            Utils::GetProtection(targetLevel, targetSigner);
        if (!SetCurrentProcessProtection(currentProcessProtection))
            ERROR(L"Failed to elevate current process protection");
    }

    HandleGuard process(OpenProcess(PROCESS_TERMINATE, FALSE, pid));
    if (!process)
        process.reset(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid));
    if (!process) {
        ERROR(L"Failed to open process for termination (PID: %d, Error: %d)",
              pid, GetLastError());
        return false;
    }

    const BOOL terminated = TerminateProcess(process.get(), 1);
    if (!terminated)
        DEBUG(L"TerminateProcess PID %d failed (error: %d) — kvcstrm fallback pending",
              pid, GetLastError());

    return terminated != FALSE;
}

// ── Public single-target API ─────────────────────────────────────────────────

// Terminates a process by PID.
// Falls back to kvcstrm IOCTL_KILL_WESMAR if the primary path fails.
bool Controller::KillProcess(DWORD pid) noexcept
{
    bool ok = KillProcessInternal(pid, /*insideBatchSession=*/false);
    EndDriverSession(true);

    if (!ok) {
        bool autoStarted = false;
        if (EnsureStrmOpen(autoStarted)) {
            ok = static_cast<bool>(m_strm.KillProcessLegacy(pid));
            CleanupStrm(autoStarted);
        }
        if (!ok)
            INFO(L"PID %d not terminated (process may no longer exist)", pid);
    }
    return ok;
}

// Terminates all processes whose name matches a pattern (supports wildcards).
bool Controller::KillProcessByName(const std::wstring& processName) noexcept
{
    if (!BeginDriverSession()) return false;

    const auto matches = FindProcessesByName(processName);
    if (matches.empty()) {
        ERROR(L"No process found matching pattern: %s", processName.c_str());
        EndDriverSession(true);
        return false;
    }

    const DWORD total = static_cast<DWORD>(matches.size());
    INFO(L"Found %d processes matching '%s'", total, processName.c_str());

    DWORD successCount = 0;
    for (const auto& match : matches) {
        if (g_interrupted) { INFO(L"Termination interrupted by user"); break; }
        INFO(L"Attempting to terminate %s (PID %d)",
             match.ProcessName.c_str(), match.Pid);
        if (KillProcessInternal(match.Pid, /*insideBatchSession=*/true)) {
            SUCCESS(L"Terminated %s (PID %d)",
                    match.ProcessName.c_str(), match.Pid);
            ++successCount;
        } else {
            ERROR(L"Failed to terminate PID %d", match.Pid);
        }
    }

    EndDriverSession(true);
    INFO(L"Kill by name completed: %d/%d terminated", successCount, total);
    return successCount > 0;
}

// ── Batch kill by PID list ───────────────────────────────────────────────────

bool Controller::KillMultipleProcesses(const std::vector<DWORD>& pids) noexcept
{
    if (pids.empty()) { ERROR(L"No PIDs provided"); return false; }
    if (!BeginDriverSession()) { ERROR(L"Failed to start driver session"); return false; }

    INFO(L"Batch kill: %zu processes", pids.size());
    DWORD successCount = 0;
    for (DWORD pid : pids) {
        if (g_interrupted) { INFO(L"Batch kill interrupted"); break; }
        if (KillProcessInternal(pid, /*insideBatchSession=*/true)) {
            ++successCount;
            SUCCESS(L"Terminated PID %d", pid);
        } else {
            ERROR(L"Failed to terminate PID %d", pid);
        }
    }

    EndDriverSession(true);
    INFO(L"Batch kill completed: %d/%zu", successCount, pids.size());
    return successCount > 0;
}

// ── Batch kill by mixed PID/name targets (with kvckiller.sys fallback) ───────

// Terminates processes by a mixed list of PID strings and name patterns.
// Persists each killed process's full exe path for later relaunch.
// For PIDs that survive the primary kvc.sys session, falls back to
// kvckiller.sys (a digitally-signed driver that does not require HVCI restart).
bool Controller::KillMultipleTargets(
    const std::vector<std::wstring>& targets) noexcept
{
    if (targets.empty()) return false;
    if (!BeginDriverSession()) return false;

    // Resolve all targets to PIDs using the open session.
    std::vector<DWORD> allPids;
    for (const auto& target : targets) {
        if (Utils::IsNumeric(target)) {
            if (const auto pid = Utils::ParsePid(target))
                allPids.push_back(pid.value());
        } else {
            for (const auto& match : FindProcessesByName(target))
                allPids.push_back(match.Pid);
        }
    }

    if (allPids.empty()) {
        ERROR(L"No processes found matching the specified targets");
        EndDriverSession(true);
        return false;
    }

    // Snapshot exe names + full paths while the processes are still alive.
    std::unordered_map<DWORD, std::pair<std::wstring, std::wstring>> pidInfo;
    {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe{sizeof(pe)};
            if (Process32FirstW(hSnap, &pe)) {
                do {
                    for (DWORD pid : allPids) {
                        if (pe.th32ProcessID == pid &&
                            pidInfo.find(pid) == pidInfo.end())
                        {
                            std::wstring fullPath;
                            if (HANDLE hProc = OpenProcess(
                                    PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid))
                            {
                                wchar_t buf[MAX_PATH] = {};
                                DWORD sz = MAX_PATH;
                                if (QueryFullProcessImageNameW(hProc, 0, buf, &sz))
                                    fullPath = buf;
                                CloseHandle(hProc);
                            }
                            pidInfo[pid] = {pe.szExeFile, fullPath};
                        }
                    }
                } while (Process32NextW(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }
    }

    INFO(L"Batch kill: %zu resolved processes", allPids.size());
    DWORD successCount = 0;
    std::vector<DWORD> failedPids;

    for (DWORD pid : allPids) {
        if (g_interrupted) { INFO(L"Batch kill interrupted"); break; }
        if (KillProcessInternal(pid, /*insideBatchSession=*/true)) {
            ++successCount;
            SUCCESS(L"Terminated PID %d", pid);
            if (const auto it = pidInfo.find(pid);
                it != pidInfo.end() && !it->second.second.empty())
                CacheKilledProcessPath(it->second.first, it->second.second);
        } else {
            failedPids.push_back(pid);
        }
    }

    EndDriverSession(true);

    // ── Tier 3: kvckiller.sys fallback ──────────────────────────────────────
    if (!failedPids.empty()) {
        PrivilegeUtils::EnablePrivilege(SE_LOAD_DRIVER_NAME);
        EnsureDriverAvailable();
        const std::wstring killerPath = GetDriverStorePath() + L"\\kvckiller.sys";

        if (GetFileAttributesW(killerPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            for (DWORD pid : failedPids)
                INFO(L"PID %d not terminated (kvckiller.sys not found)", pid);
        } else {
            // Remove any stale wsftprm service registration before installing.
            if (SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS)) {
                if (SC_HANDLE hOld = OpenServiceW(hSCM, L"wsftprm", DELETE)) {
                    DeleteService(hOld);
                    CloseServiceHandle(hOld);
                }
                CloseServiceHandle(hSCM);
            }

            SC_HANDLE hKillerSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
            SC_HANDLE hKillerSvc = nullptr;
            bool      killerLoaded = false;

            if (hKillerSCM) {
                hKillerSvc = CreateServiceW(
                    hKillerSCM, L"wsftprm", L"wsftprm",
                    SERVICE_START | SERVICE_STOP | DELETE,
                    SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                    SERVICE_ERROR_NORMAL, killerPath.c_str(),
                    nullptr, nullptr, nullptr, nullptr, nullptr);
                killerLoaded = hKillerSvc && StartServiceW(hKillerSvc, 0, nullptr);
            }

            if (killerLoaded) {
                HANDLE hDev = CreateFileW(L"\\\\.\\Warsaw_PM",
                                          GENERIC_READ | GENERIC_WRITE,
                                          0, nullptr, OPEN_EXISTING,
                                          FILE_ATTRIBUTE_NORMAL, nullptr);
                if (hDev != INVALID_HANDLE_VALUE) {
                    for (DWORD pid : failedPids) {
                        std::vector<BYTE> buf(1036, 0);
                        *reinterpret_cast<DWORD*>(buf.data()) = pid;
                        DWORD ret = 0;
                        if (DeviceIoControl(hDev, 0x22201C,
                                            buf.data(), static_cast<DWORD>(buf.size()),
                                            nullptr, 0, &ret, nullptr))
                        {
                            ++successCount;
                            SUCCESS(L"PID %d terminated via kvckiller", pid);
                            if (const auto it = pidInfo.find(pid);
                                it != pidInfo.end() && !it->second.second.empty())
                                CacheKilledProcessPath(it->second.first,
                                                        it->second.second);
                        } else {
                            INFO(L"PID %d not terminated (kvckiller IOCTL failed: %lu)",
                                 pid, GetLastError());
                        }
                    }
                    CloseHandle(hDev);
                } else {
                    for (DWORD pid : failedPids)
                        INFO(L"PID %d not terminated (Warsaw_PM unavailable: %lu)",
                             pid, GetLastError());
                }
            } else {
                for (DWORD pid : failedPids)
                    INFO(L"PID %d not terminated (kvckiller service failed to start)", pid);
            }

            // Always stop and delete the temporary service.
            if (hKillerSvc) {
                SERVICE_STATUS ss{};
                ControlService(hKillerSvc, SERVICE_CONTROL_STOP, &ss);
                DeleteService(hKillerSvc);
                CloseServiceHandle(hKillerSvc);
            }
            if (hKillerSCM) CloseServiceHandle(hKillerSCM);
        }
    }

    INFO(L"Kill operation completed: %d/%zu terminated",
         successCount, allPids.size());
    return successCount > 0;
}
