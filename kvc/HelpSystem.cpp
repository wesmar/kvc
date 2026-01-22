#include <windows.h>
#include "HelpSystem.h"
#include <iostream>
#include <iomanip>

extern "C" void ScreenShake(int intensity, int shakes);

// Console color constants for readability
namespace Colors {
    inline constexpr WORD BLUE_BRIGHT = FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    inline constexpr WORD WHITE_BRIGHT = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    inline constexpr WORD YELLOW_BRIGHT = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    inline constexpr WORD RED_BRIGHT = FOREGROUND_RED | FOREGROUND_INTENSITY;
    inline constexpr WORD GREEN_BRIGHT = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    inline constexpr WORD GRAY = FOREGROUND_INTENSITY;
}

void HelpSystem::PrintCentered(std::wstring_view text, HANDLE hConsole, WORD color) noexcept
{
    int textLen = static_cast<int>(text.length());
    int padding = (HelpLayout::WIDTH - textLen) / 2;
    if (padding < 0) padding = 0;
    
    SetConsoleTextAttribute(hConsole, color);
    std::wcout << std::wstring(padding, L' ') << text << L"\n";
}

void HelpSystem::PrintBoxLine(std::wstring_view text, HANDLE hConsole, 
                              WORD borderColor, WORD textColor) noexcept
{
    int textLen = static_cast<int>(text.length());
    int innerWidth = HelpLayout::WIDTH - 2;
    int padding = (innerWidth - textLen) / 2;
    if (padding < 0) padding = 0;
    
    SetConsoleTextAttribute(hConsole, borderColor);
    std::wcout << L"|";
    
    SetConsoleTextAttribute(hConsole, textColor);
    std::wcout << std::wstring(padding, L' ') << text
               << std::wstring(innerWidth - padding - textLen, L' ');
    
    SetConsoleTextAttribute(hConsole, borderColor);
    std::wcout << L"|\n";
}

void HelpSystem::PrintUsage(std::wstring_view programName) noexcept
{
    PrintHeader();
    
    std::wcout << L"Usage: " << programName << L" <command> [arguments]\n\n";
    
    PrintServiceCommands();
    PrintDSECommands();
    PrintDriverCommands();
    PrintBasicCommands();
    PrintModuleCommands();
    PrintProcessTerminationCommands();
    PrintProtectionCommands();
    PrintSessionManagement();
    PrintSystemCommands();
    PrintRegistryCommands();
    PrintBrowserCommands();
    PrintDefenderCommands();
    PrintSecurityEngineCommands();
    PrintDefenderUICommands();
    PrintDPAPICommands();
    PrintWatermarkCommands();
    PrintEntertainmentCommands();
    PrintProtectionTypes();
    PrintExclusionTypes();
    PrintPatternMatching();
    PrintTechnicalFeatures();
    PrintDefenderNotes();
    PrintStickyKeysInfo();
    PrintUndumpableProcesses();
    PrintUsageExamples(programName);
    PrintSecurityNotice();
    PrintFooter();
}

void HelpSystem::PrintHeader() noexcept
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    WORD originalColor = csbi.wAttributes;

    SetConsoleTextAttribute(hConsole, Colors::BLUE_BRIGHT);
    std::wcout << L"\n" << HelpLayout::BORDER_DOUBLE << L"\n";

    PrintCentered(L"Marek Wesolowski - WESMAR - 2025", hConsole, Colors::WHITE_BRIGHT);
    PrintCentered(L"kvc.exe v1.0.1 https://kvc.pl", hConsole, Colors::WHITE_BRIGHT);
    PrintCentered(L"+48 607-440-283, marek@wesolowski.eu.org", hConsole, Colors::WHITE_BRIGHT);
    PrintCentered(L"kvc - Kernel Vulnerability Capabilities Framework", hConsole, Colors::WHITE_BRIGHT);
    PrintCentered(L"Comprehensive Windows Security Research & Penetration Framework", hConsole, Colors::WHITE_BRIGHT);
    PrintCentered(L"Features Process Protection, DPAPI Extraction, Defender Bypass & More", hConsole, Colors::WHITE_BRIGHT);

    SetConsoleTextAttribute(hConsole, Colors::BLUE_BRIGHT);
    std::wcout << HelpLayout::BORDER_DOUBLE << L"\n\n";

    SetConsoleTextAttribute(hConsole, originalColor);
}

void HelpSystem::PrintServiceCommands() noexcept
{
    PrintSectionHeader(L"Service Management Commands (Advanced Scenarios)");
    PrintCommandLine(L"setup", L"Decrypt and deploy combined binary components from kvc.dat");
    PrintCommandLine(L"install", L"Install as NT service with TrustedInstaller privileges");
    PrintCommandLine(L"uninstall", L"Uninstall NT service");
    PrintCommandLine(L"service start", L"Start the Kernel Vulnerability Capabilities Framework service");
    PrintCommandLine(L"service stop", L"Stop the Kernel Vulnerability Capabilities Framework service");
    PrintCommandLine(L"service status", L"Check service status");
    std::wcout << L"\n";
}

void HelpSystem::PrintDSECommands() noexcept
{
    PrintSectionHeader(L"Driver Signature Enforcement (DSE) Control");
    PrintCommandLine(L"dse off", L"Disable DSE (Standard: g_CiOptions or HVCI bypass)");
    PrintCommandLine(L"dse off --safe", L"Disable DSE (Next-Gen: SeCiCallbacks + PDB symbols)");
    PrintCommandLine(L"dse on", L"Restore DSE (Standard method)");
    PrintCommandLine(L"dse on --safe", L"Restore DSE (Next-Gen method)");
    PrintCommandLine(L"dse", L"Check current DSE status (both methods)");
    
    PrintNote(L"Standard method: Modifies g_CiOptions or prepares HVCI bypass");
    PrintNote(L"--safe method: Patches SeCiCallbacks using PDB symbols");
    PrintNote(L"--safe requires Internet on first run to download kernel symbols");
    PrintNote(L"--safe is PatchGuard-resistant on modern Win10/11");
    PrintNote(L"Both methods store state in HKEY_CURRENT_USER\\Software\\kvc\\DSE");
    PrintNote(L"Symbols cached locally in .\\symbols\\ for offline use");
    std::wcout << L"\n";
}

void HelpSystem::PrintDriverCommands() noexcept
{
    PrintSectionHeader(L"External Driver Loading (Auto DSE Bypass)");
    PrintCommandLine(L"driver load <path>", L"Load unsigned driver (Patch -> Start -> Unpatch)");
    PrintCommandLine(L"driver load <path> -s <0-4>", L"Load with specific StartType (0=Boot,1=System,2=Auto,3=Demand,4=Disabled)");
    PrintCommandLine(L"driver reload <n>", L"Reload driver (Stop -> Patch -> Start -> Unpatch)");
    PrintCommandLine(L"driver stop <n>", L"Stop driver service (no delete)");
    PrintCommandLine(L"driver remove <n>", L"Stop and delete driver service");
    
    PrintNote(L"Path can be full (C:\\test.sys) or short name (test -> System32\\drivers\\test.sys)");
    PrintNote(L"Uses Next-Gen DSE bypass (SeCiCallbacks) - PatchGuard resistant");
    PrintNote(L"DSE is automatically restored after driver loads");
    std::wcout << L"\n";
}

void HelpSystem::PrintBasicCommands() noexcept
{
    PrintSectionHeader(L"Memory Dumping Commands");
    PrintCommandLine(L"dump <PID|process_name> [path]", L"Create comprehensive memory dump");
    PrintNote(L"Default path is the Downloads folder - simple: 'kvc dump lsass'");
    PrintWarning(L"MsMpEng dump only works with Defender disabled (otherwise Ctrl+C)");
    std::wcout << L"\n";
    
    PrintSectionHeader(L"Process Information Commands");
    PrintCommandLine(L"list", L"List all protected processes with color coding");
	PrintCommandLine(L"list --gui", L"Launch interactive GUI mode for process management");
    PrintCommandLine(L"get <PID|process_name>", L"Get protection status of specific process");
    PrintCommandLine(L"info <PID|process_name>", L"Get detailed process info including dumpability");
    std::wcout << L"\n";
}

void HelpSystem::PrintModuleCommands() noexcept
{
    PrintSectionHeader(L"Module Enumeration Commands");
    PrintCommandLine(L"modules <PID|process_name>", L"List all loaded modules in target process (alias: mods)");
    PrintCommandLine(L"modules <PID> read <module>", L"Read first 256 bytes from module (PE header)");
    PrintCommandLine(L"modules <PID> read <module> <offset>", L"Read 256 bytes from specified offset");
    PrintCommandLine(L"modules <PID> read <module> <offset> <size>", L"Read custom size (max 4096 bytes)");
    PrintNote(L"Module name supports partial matching: 'ntdll' finds 'ntdll.dll'");
    PrintNote(L"Offset accepts decimal or hex (0x prefix): 0x1000 or 4096");
    PrintNote(L"Uses kernel driver for protected process memory access");
    std::wcout << L"\n";
}

void HelpSystem::PrintProcessTerminationCommands() noexcept
{
    PrintSectionHeader(L"Process Termination Commands");
    PrintCommandLine(L"kill <PID|process_name>", L"Terminate process with automatic protection elevation");
    PrintCommandLine(L"kill <PID1,PID2,name3>", L"Terminate multiple processes (comma-separated)");
    PrintNote(L"Supports process names: 'kill total' terminates Total Commander");
    PrintNote(L"Automatically matches target protection level for protected processes");
    PrintNote(L"Case-insensitive partial matching: 'notepad' matches 'notepad.exe'");
    std::wcout << L"\n";
}

void HelpSystem::PrintProtectionCommands() noexcept
{
    PrintSectionHeader(L"Process Protection Commands");
    PrintCommandLine(L"set <PID|process_name> <PP|PPL> <TYPE>", L"Set protection (force, ignoring current state)");
    PrintCommandLine(L"protect <PID|process_name> <PP|PPL> <TYPE>", L"Protect unprotected process");
    PrintCommandLine(L"unprotect <PID|process_name|SIGNER>", L"Remove protection from process(es)");
    PrintCommandLine(L"unprotect all", L"Remove protection from ALL processes");
    PrintCommandLine(L"unprotect <PID1,PID2,PID3>", L"Remove protection from multiple processes");
    PrintCommandLine(L"set-signer <SIGNER> <PP|PPL> <NEW_SIGNER>", L"Batch modify protection for all processes of specific signer");
    PrintCommandLine(L"list-signer <SIGNER>", L"List all processes with specific signer");
    PrintCommandLine(L"restore <signer_name>", L"Restore protection for specific signer group");
    PrintCommandLine(L"restore all", L"Restore all saved protection states");
    PrintCommandLine(L"history", L"Show saved session history (max 16 sessions)");
    PrintCommandLine(L"cleanup-sessions", L"Delete all sessions except current");
    PrintNote(L"SIGNER can be: Antimalware, WinTcb, Windows, Lsa, WinSystem, etc.");
    std::wcout << L"\n";
}

void HelpSystem::PrintSystemCommands() noexcept
{
    PrintSectionHeader(L"System Integration Commands");
    PrintCommandLine(L"shift", L"Install sticky keys backdoor (5x Shift = SYSTEM cmd)");
    PrintCommandLine(L"unshift", L"Remove sticky keys backdoor");
    PrintCommandLine(L"trusted <command>", L"Run command with elevated system privileges");
    PrintCommandLine(L"install-context", L"Add context menu entries for right-click access");
    PrintCommandLine(L"evtclear", L"Clear all primary system event logs (Application, Security, Setup, System)");
    std::wcout << L"\n";
}

void HelpSystem::PrintRegistryCommands() noexcept
{
    PrintSectionHeader(L"Registry Backup & Defragmentation");
    PrintCommandLine(L"registry backup", L"Backup all registry hives to Downloads");
    PrintCommandLine(L"registry backup C:\\backup", L"Backup to custom directory");
    PrintCommandLine(L"registry restore C:\\backup", L"Restore hives from backup");
    PrintCommandLine(L"registry defrag", L"Defragment registry (backup+compact)");
    PrintNote(L"Backs up: BCD, SAM, SECURITY, SOFTWARE, SYSTEM, NTUSER, etc.");
    PrintNote(L"Default path: Downloads\\Registry_Backup_YYYYMMDD_HHMMSS");
    PrintNote(L"Defrag compacts hives through RegSaveKeyEx (no fragmentation)");
    std::wcout << L"\n";
}

void HelpSystem::PrintDefenderCommands() noexcept
{
    PrintSectionHeader(L"Enhanced Windows Defender Exclusion Management");
    PrintCommandLine(L"add-exclusion <path>", L"Add file/folder to exclusions (legacy syntax)");
    PrintCommandLine(L"add-exclusion Paths <path>", L"Add specific path to exclusions");
    PrintCommandLine(L"add-exclusion Processes <n>", L"Add process to exclusions");
    PrintCommandLine(L"add-exclusion Extensions <ext>", L"Add file extension to exclusions");
    PrintCommandLine(L"add-exclusion IpAddresses <ip>", L"Add IP address/CIDR to exclusions");
    PrintCommandLine(L"remove-exclusion [TYPE] <value>", L"Remove exclusion (same syntax as add)");
    PrintNote(L"When no path specified, adds current program to both Paths and Processes");
    std::wcout << L"\n";
}

void HelpSystem::PrintSecurityEngineCommands() noexcept
{
    PrintSectionHeader(L"Security Engine Management");
    PrintCommandLine(L"secengine disable", L"Disable Windows Defender security engine");
    PrintCommandLine(L"secengine enable", L"Enable Windows Defender security engine"); 
    PrintCommandLine(L"secengine status", L"Check current security engine status");
    PrintCommandLine(L"secengine disable --restart", L"Disable and restart system immediately");
    PrintCommandLine(L"secengine enable --restart", L"Enable and restart system immediately");
    PrintNote(L"Registry-level manipulation - bypasses tamper protection");
    PrintNote(L"System restart required for changes to take effect");
    std::wcout << L"\n";
}

void HelpSystem::PrintDefenderUICommands() noexcept
{
    PrintSectionHeader(L"Windows Defender UI Automation");
    PrintCommandLine(L"rtp on", L"Enable Real-Time Protection");
    PrintCommandLine(L"rtp off", L"Disable Real-Time Protection");
    PrintCommandLine(L"rtp status", L"Check Real-Time Protection status");
    PrintCommandLine(L"tp on", L"Enable Tamper Protection");
    PrintCommandLine(L"tp off", L"Disable Tamper Protection");
    PrintCommandLine(L"tp status", L"Check Tamper Protection status");
    PrintNote(L"Uses ghost mode (invisible window, UAC bypass, pre-warming)");
    PrintNote(L"Fully automated - no user interaction required");
    std::wcout << L"\n";
}

void HelpSystem::PrintSessionManagement() noexcept
{
    PrintSectionHeader(L"Session Management System");
    std::wcout << L"  - Automatic boot detection and session tracking (max 16 sessions)\n";
    std::wcout << L"  - Each 'unprotect' operation saves process states grouped by signer\n";
    std::wcout << L"  - 'restore' commands reapply protection from saved session state\n";
    std::wcout << L"  - Session history persists across reboots until limit reached\n";
    std::wcout << L"  - Oldest sessions auto-deleted when exceeding 16 session limit\n";
    std::wcout << L"  - Manual cleanup available via 'cleanup-sessions' command\n";
    std::wcout << L"  - Status tracking: UNPROTECTED (after unprotect) -> RESTORED (after restore)\n\n";
}

void HelpSystem::PrintBrowserCommands() noexcept
{
    PrintSectionHeader(L"Browser Password Extraction Commands");
    PrintCommandLine(L"browser-passwords", L"Extract Chrome passwords (default)");
    PrintCommandLine(L"bp --chrome", L"Extract Chrome passwords explicitly");
    PrintCommandLine(L"bp --brave", L"Extract Brave browser passwords");  
    PrintCommandLine(L"bp --edge", L"Extract Edge browser passwords");
    PrintCommandLine(L"bp --all", L"Extract from all installed browsers");
    PrintCommandLine(L"bp --output C:\\reports", L"Custom output directory");
    PrintCommandLine(L"bp --edge -o C:\\data", L"Edge passwords to custom path");
    PrintNote(L"Requires kvc_pass.exe for Chrome/Brave/All");
    PrintNote(L"Edge with kvc_pass: JSON + cookies + HTML/TXT reports (full extraction)");
    PrintNote(L"Edge without kvc_pass: HTML/TXT reports only (built-in DPAPI fallback)");
    std::wcout << L"\n";
}

void HelpSystem::PrintDPAPICommands() noexcept
{
    PrintSectionHeader(L"DPAPI Secrets Extraction Commands");
    PrintCommandLine(L"export secrets [path]", L"Extract browser & WiFi secrets using TrustedInstaller");
    PrintNote(L"Default path is the Downloads folder - simple: 'kvc export secrets'");
    PrintNote(L"Extracts Chrome, Edge passwords + WiFi credentials + master keys");
    std::wcout << L"\n";
}

void HelpSystem::PrintWatermarkCommands() noexcept
{
    PrintSectionHeader(L"Watermark Management");
    PrintCommandLine(L"watermark remove", L"Remove Windows desktop watermark (alias: wm remove)");
    PrintCommandLine(L"watermark restore", L"Restore Windows desktop watermark (alias: wm restore)");
    PrintCommandLine(L"watermark status", L"Check current watermark status (alias: wm status)");
    PrintNote(L"Hijacks ExplorerFrame.dll via registry redirection");
    PrintNote(L"Requires Administrator privileges and TrustedInstaller access");
    std::wcout << L"\n";
}

void HelpSystem::PrintEntertainmentCommands() noexcept
{
    PrintSectionHeader(L"Entertainment");
    PrintCommandLine(L"--tetris", L"Launch classic Tetris game (x64 assembly)");
    PrintNote(L"Arrow keys to move/rotate, Space for hard drop, P to pause");
    PrintNote(L"Press F2 to start new game, ESC to exit");
    std::wcout << L"\n";
}

void HelpSystem::PrintProtectionTypes() noexcept
{
    PrintSectionHeader(L"Protection Types");
    std::wcout << L"  PP  - Protected Process (highest protection level)\n";
    std::wcout << L"  PPL - Protected Process Light (medium protection level)\n\n";
    
    PrintSectionHeader(L"Signer Types");
    std::wcout << L"  Authenticode  - Standard code signing authority\n";
    std::wcout << L"  CodeGen       - Code generation process signing\n";
    std::wcout << L"  Antimalware   - Antimalware vendor signing (for security software)\n";
    std::wcout << L"  Lsa           - Local Security Authority signing\n";
    std::wcout << L"  Windows       - Microsoft Windows component signing\n";
    std::wcout << L"  WinTcb        - Windows Trusted Computing Base signing\n";
    std::wcout << L"  WinSystem     - Windows System component signing\n";
    std::wcout << L"  App           - Application store signing\n\n";
}

void HelpSystem::PrintExclusionTypes() noexcept
{
    PrintSectionHeader(L"Exclusion Types");
    std::wcout << L"  Paths         - File/folder paths (C:\\malware.exe, C:\\temp\\)\n";
    std::wcout << L"  Processes     - Process names (malware.exe, cmd.exe)\n";
    std::wcout << L"  Extensions    - File extensions (.exe, .dll, .tmp)\n";
    std::wcout << L"  IpAddresses   - IP addresses/CIDR (192.168.1.1, 10.0.0.0/24)\n\n";
}

void HelpSystem::PrintPatternMatching() noexcept
{
    PrintSectionHeader(L"Process Name Matching");
    std::wcout << L"  - Exact match: 'explorer', 'notepad'\n";
    std::wcout << L"  - Partial match: 'total' matches 'totalcmd64'\n";
    std::wcout << L"  - Wildcards: 'total*' matches 'totalcmd64.exe'\n";
    std::wcout << L"  - Case insensitive matching supported\n";
    std::wcout << L"  - Multiple matches require more specific patterns\n\n";
}

void HelpSystem::PrintTechnicalFeatures() noexcept
{
    PrintSectionHeader(L"TrustedInstaller Features");
    std::wcout << L"  - Executes commands with maximum system privileges\n";
    std::wcout << L"  - Supports .exe files and .lnk shortcuts automatically\n";
    std::wcout << L"  - Adds convenient context menu entries\n";
    std::wcout << L"  - Enhanced Windows Defender exclusion management\n\n";
    
    PrintSectionHeader(L"Technical Features");
    std::wcout << L"  - Dynamic kernel driver loading (no permanent installation)\n";
    std::wcout << L"  - Embedded encrypted driver with steganographic protection\n";
    std::wcout << L"  - Automatic privilege escalation for memory dumping\n";
    std::wcout << L"  - Complete cleanup on exit (no system traces)\n";
    std::wcout << L"  - Advanced process pattern matching\n";
    std::wcout << L"  - Color-coded process protection visualization\n";
    std::wcout << L"  - IFEO sticky keys backdoor with Defender bypass\n";
    std::wcout << L"  - Self-protection capabilities for advanced scenarios\n";
    std::wcout << L"  - Comprehensive Windows Defender exclusion management\n\n";
}

void HelpSystem::PrintDefenderNotes() noexcept
{
    PrintSectionHeader(L"Defender Exclusion Notes");
    std::wcout << L"  Defender exclusions use PowerShell Add-MpPreference commands with TrustedInstaller.\n";
    std::wcout << L"  Extensions: Automatically adds leading dot if missing (.exe, not exe)\n";
    std::wcout << L"  Processes: Extracts filename from full path if provided\n";
    std::wcout << L"  IpAddresses: Supports CIDR notation (192.168.1.0/24)\n";
    std::wcout << L"  Self-protection: When no arguments, adds to both Paths and Processes\n";
    std::wcout << L"  Legacy syntax (kvc add-exclusion file.exe) still works for compatibility\n\n";
}

void HelpSystem::PrintStickyKeysInfo() noexcept
{
    PrintSectionHeader(L"Sticky Keys Backdoor Features");
    std::wcout << L"  - Press 5x Shift on login screen to get SYSTEM cmd.exe\n";
    std::wcout << L"  - Works without login or active session\n";
    std::wcout << L"  - Bypasses Windows Defender with process exclusions\n";
    std::wcout << L"  - Uses Image File Execution Options (IFEO) technique\n";
    std::wcout << L"  - Complete cleanup with 'unshift' command\n\n";
    
    PrintSectionHeader(L"Sticky Keys Backdoor Notes");
    std::wcout << L"  After 'kvc shift', press 5x Shift on Windows login screen to get cmd.exe.\n";
    std::wcout << L"  The cmd runs with SYSTEM privileges without requiring login.\n";
    std::wcout << L"  Defender process exclusions prevent detection of cmd.exe activity.\n";
    std::wcout << L"  Use 'kvc unshift' to completely remove all traces.\n";
    std::wcout << L"  This technique works on Windows 7-11, including Server editions.\n\n";
}

void HelpSystem::PrintUndumpableProcesses() noexcept
{
    PrintSectionHeader(L"Undumpable System Processes");
    std::wcout << L"  - System (PID 4)           - Windows kernel process\n";
    std::wcout << L"  - Secure System (PID 188)  - VSM/VBS protected process\n";
    std::wcout << L"  - Registry (PID 232)       - Kernel registry subsystem\n";
    std::wcout << L"  - Memory Compression       - Kernel memory manager\n";
    std::wcout << L"  - [Unknown] processes      - Transient kernel processes\n\n";
}

void HelpSystem::PrintUsageExamples(std::wstring_view programName) noexcept
{
    PrintSectionHeader(L"Usage Examples");
    
    auto printLine = [](const std::wstring& command, const std::wstring& description) {
        std::wcout << L"  " << std::left << std::setw(HelpLayout::EXAMPLE_CMD_WIDTH) 
                   << command << L"# " << description << L"\n";
    };
    
    // Process inspection and monitoring
    printLine(L"kvc list", L"Show all protected processes");
	printLine(L"kvc list --gui", L"Launch interactive GUI for visual management");
    printLine(L"kvc info lsass", L"Detailed info with dumpability analysis");
    
    // Process protection management
    printLine(L"kvc protect 1044 PPL Antimalware", L"Protect process with PPL-Antimalware");
    printLine(L"kvc set 5678 PP Windows", L"Force set PP-Windows protection");
    printLine(L"kvc unprotect lsass", L"Remove protection from LSASS");
    printLine(L"kvc unprotect 1,2,3,lsass", L"Batch unprotect multiple targets");
    printLine(L"kvc unprotect Antimalware", L"Remove protection from all Antimalware processes");
    printLine(L"kvc unprotect all", L"Remove protection from ALL processes (grouped by signer)");
    printLine(L"kvc set-signer Antimalware PPL WinTcb", L"Change all Antimalware processes to PPL-WinTcb");
    printLine(L"kvc set-signer Windows PP Antimalware", L"Escalate all Windows processes to PP-Antimalware");
    
    // Session state management
    printLine(L"kvc history", L"Show saved sessions (max 16, with status tracking)");
    printLine(L"kvc restore Antimalware", L"Restore protection for Antimalware group");
    printLine(L"kvc restore all", L"Restore all saved protection states from current session");
    printLine(L"kvc cleanup-sessions", L"Delete all old sessions (keep only current)");
    
    // Process termination
    printLine(L"kvc kill 1234", L"Terminate process with PID 1234");
    printLine(L"kvc kill total", L"Terminate Total Commander by name");
    printLine(L"kvc kill 1234,5678,9012", L"Terminate multiple processes");
    printLine(L"kvc kill lsass", L"Terminate protected process (auto-elevation)");
    
    // Memory dumping
    printLine(L"kvc dump lsass C:\\dumps", L"Dump LSASS to specific folder");
    printLine(L"kvc dump 1044", L"Dump PID 1044 to Downloads folder");
    
    // Module enumeration
    printLine(L"kvc modules explorer.exe", L"List all modules loaded in Explorer");
    printLine(L"kvc mods lsass", L"List LSASS modules (auto-elevates for protected)");
    printLine(L"kvc modules 1220", L"List modules by PID");
    printLine(L"kvc modules explorer read ntdll", L"Read PE header (256 bytes) from ntdll.dll");
    printLine(L"kvc mods lsass read lsasrv 0x1000", L"Read 256 bytes at offset 0x1000");
    printLine(L"kvc modules 1234 read kernel32 0 512", L"Read 512 bytes from module start");
    
    // Service installation and management
    printLine(L"kvc install", L"Install as NT service (advanced)");
    printLine(L"kvc service start", L"Start the service");
    printLine(L"kvc uninstall", L"Remove service");
    
    // Driver Signature Enforcement control
    printLine(L"kvc dse off", L"Disable DSE to load unsigned drivers");
    printLine(L"kvc dse off --safe", L"Disable DSE (Next-Gen PDB method)");
    printLine(L"kvc dse on", L"Re-enable DSE for system security");
    printLine(L"kvc dse on --safe", L"Re-enable DSE (Next-Gen method)");
    printLine(L"kvc dse", L"Check current DSE status");

    // External driver loading (auto DSE bypass)
    printLine(L"kvc driver load kvckbd", L"Load driver from System32\\drivers\\kvckbd.sys");
    printLine(L"kvc driver load C:\\test\\mydriver.sys", L"Load driver from full path");
    printLine(L"kvc driver load kvckbd -s 1", L"Load with StartType=SYSTEM");
    printLine(L"kvc driver reload omnidriver", L"Reload driver (stop -> patch -> start -> unpatch)");
    printLine(L"kvc driver stop mydriver", L"Stop driver service (no delete)");
    printLine(L"kvc driver remove mydriver", L"Stop and delete driver service");
    
    // Watermark management
    printLine(L"kvc wm status", L"Check if watermark is removed or active");
    printLine(L"kvc wm remove", L"Remove Windows desktop watermark");
    printLine(L"kvc wm restore", L"Restore original Windows watermark");
    printLine(L"kvc watermark remove", L"Full command syntax (same as 'wm remove')");
    
    // System backdoors
    printLine(L"kvc shift", L"Install sticky keys backdoor");
    printLine(L"kvc unshift", L"Remove sticky keys backdoor");
    
    // TrustedInstaller elevation
    printLine(L"kvc trusted cmd", L"Run command as TrustedInstaller");
    printLine(L"kvc trusted \"C:\\app.exe\" --arg", L"Run application with arguments");
    printLine(L"kvc install-context", L"Add right-click menu entries");
    
    // Windows Defender exclusions
    printLine(L"kvc add-exclusion", L"Add current program to exclusions");
    printLine(L"kvc add-exclusion C:\\malware.exe", L"Add specific file to exclusions");
    printLine(L"kvc add-exclusion Paths C:\\temp", L"Add folder to path exclusions");
    printLine(L"kvc add-exclusion Processes cmd.exe", L"Add process to exclusions");
    printLine(L"kvc add-exclusion Extensions .tmp", L"Add extension to exclusions");
    printLine(L"kvc add-exclusion IpAddresses 1.1.1.1", L"Add IP to exclusions");
    printLine(L"kvc remove-exclusion Processes cmd.exe", L"Remove process exclusion");
    
    // Security engine control
    printLine(L"kvc secengine status", L"Check Windows Defender status");
    printLine(L"kvc secengine disable", L"Disable Windows Defender engine");
    printLine(L"kvc secengine enable", L"Re-enable Windows Defender engine");
    printLine(L"kvc secengine disable --restart", L"Disable Defender and restart system");
    printLine(L"kvc secengine enable --restart", L"Enable Defender and restart system");
    
    // Defender UI automation (Real-Time Protection / Tamper Protection)
    printLine(L"kvc rtp status", L"Check Real-Time Protection status");
    printLine(L"kvc rtp off", L"Disable Real-Time Protection (ghost mode)");
    printLine(L"kvc rtp on", L"Enable Real-Time Protection");
    printLine(L"kvc tp status", L"Check Tamper Protection status");
    printLine(L"kvc tp off", L"Disable Tamper Protection (ghost mode)");
    printLine(L"kvc tp on", L"Enable Tamper Protection");
    
    // Credential extraction
    printLine(L"kvc export secrets", L"Export secrets to Downloads folder");
    printLine(L"kvc export secrets C:\\reports", L"Export secrets to specific folder");
    
    // Registry operations
    printLine(L"kvc registry backup", L"Backup all hives to Downloads");
    printLine(L"kvc registry backup C:\\backup", L"Backup to custom directory");
    printLine(L"kvc registry restore C:\\backup\\Registry_Backup_*", L"Restore from backup");
    printLine(L"kvc registry defrag", L"Defragment registry (backup+restore)");
    
    // Browser password extraction
    printLine(L"kvc bp --edge", L"Edge only (works standalone, no kvc_pass needed)");
    printLine(L"kvc bp --all", L"Extract all browsers (requires kvc_pass.exe)");
    printLine(L"kvc bp --edge -o C:\\passwords", L"Edge with custom output directory");

    // Entertainment
    printLine(L"kvc --tetris", L"Take a break and play Tetris");

    std::wcout << L"\n";
}

void HelpSystem::PrintSecurityNotice() noexcept
{
    PrintSectionHeader(L"SECURITY & LEGAL NOTICE");
    
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    WORD originalColor = csbi.wAttributes;
    
    SetConsoleTextAttribute(hConsole, Colors::RED_BRIGHT);
    std::wcout << L"  WARNING: POWERFUL SECURITY RESEARCH TOOL - USE RESPONSIBLY\n\n";
    SetConsoleTextAttribute(hConsole, originalColor);
    
    std::wcout << L"  CAPABILITIES & REQUIREMENTS:\n";
    std::wcout << L"  - Kernel driver manipulation with advanced memory access techniques\n";
    std::wcout << L"  - DPAPI secret extraction (browser passwords, WiFi credentials, certificates)\n";
    std::wcout << L"  - Windows Defender bypass and exclusion management\n";
    std::wcout << L"  - System persistence mechanisms (sticky keys backdoor, IFEO techniques)\n";
    std::wcout << L"  - TrustedInstaller privilege escalation and system-level operations\n";
    std::wcout << L"  - Process protection manipulation and memory dumping\n";
    std::wcout << L"  - Registry modifications and service installation capabilities\n\n";
    
    std::wcout << L"  TECHNICAL IMPLEMENTATION:\n";
    std::wcout << L"  - Embedded encrypted kernel driver with steganographic protection\n";
    std::wcout << L"  - Dynamic driver loading - temporary deployment with automatic cleanup\n";
    std::wcout << L"  - Administrator privileges required for all security operations\n";
    std::wcout << L"  - Most operations leave no permanent traces except when explicitly requested\n";
    std::wcout << L"  - Some commands (shift, install, add-exclusion) make persistent changes\n";
    std::wcout << L"  - These changes are reversible (via unshift, remove-exclusion, etc.)\n\n";
    
    SetConsoleTextAttribute(hConsole, Colors::YELLOW_BRIGHT);
    std::wcout << L"  LEGAL & ETHICAL RESPONSIBILITY:\n";
    SetConsoleTextAttribute(hConsole, originalColor);
    std::wcout << L"  - Intended for authorized penetration testing and security research only\n";
    std::wcout << L"  - User assumes full legal responsibility for all actions performed\n";
    std::wcout << L"  - Ensure proper authorization before using on any system\n";
    std::wcout << L"  - Misuse may violate computer crime laws in your jurisdiction\n";
    std::wcout << L"  - This tool can modify system security settings and extract sensitive data\n\n";
    
    SetConsoleTextAttribute(hConsole, Colors::GREEN_BRIGHT);
    std::wcout << L"  PROFESSIONAL USE GUIDELINES:\n";
    SetConsoleTextAttribute(hConsole, originalColor);
    std::wcout << L"  - Document all activities for security assessments\n";
    std::wcout << L"  - Use 'unshift' and 'remove-exclusion' commands to clean up after testing\n";
    std::wcout << L"  - Verify system state before and after testing\n";
    std::wcout << L"  - Report findings through appropriate responsible disclosure channels\n\n";
    
    SetConsoleTextAttribute(hConsole, Colors::RED_BRIGHT);
    std::wcout << L"  By using this tool, you acknowledge understanding and accept full responsibility.\n\n";
    SetConsoleTextAttribute(hConsole, originalColor);
}

void HelpSystem::PrintFooter() noexcept
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    WORD originalColor = csbi.wAttributes;

    // Top border
    SetConsoleTextAttribute(hConsole, Colors::BLUE_BRIGHT);
    std::wcout << L"+" << std::wstring(HelpLayout::WIDTH - 2, L'-') << L"+\n";

    // Footer content lines
    PrintBoxLine(L"Support this project - a small donation is greatly appreciated", 
                 hConsole, Colors::BLUE_BRIGHT, Colors::WHITE_BRIGHT);
    PrintBoxLine(L"and helps sustain private research builds.", 
                 hConsole, Colors::BLUE_BRIGHT, Colors::WHITE_BRIGHT);
    PrintBoxLine(L"GitHub source code: https://github.com/wesmar/kvc/", 
                 hConsole, Colors::BLUE_BRIGHT, Colors::WHITE_BRIGHT);
    PrintBoxLine(L"Professional services: marek@wesolowski.eu.org", 
                 hConsole, Colors::BLUE_BRIGHT, Colors::WHITE_BRIGHT);

    // Donation line with colored links
    SetConsoleTextAttribute(hConsole, Colors::BLUE_BRIGHT);
    std::wcout << L"|";
    
    std::wstring_view paypal = L"PayPal: ";
    std::wstring_view paypalLink = L"paypal.me/ext1";
    std::wstring_view middle = L"        ";
    std::wstring_view revolut = L"Revolut: ";
    std::wstring_view revolutLink = L"revolut.me/marekb92";
    
    int totalLen = static_cast<int>(paypal.length() + paypalLink.length() + 
                                   middle.length() + revolut.length() + revolutLink.length());
    int innerWidth = HelpLayout::WIDTH - 2;
    int padding = (innerWidth - totalLen) / 2;
    if (padding < 0) padding = 0;
    
    SetConsoleTextAttribute(hConsole, Colors::WHITE_BRIGHT);
    std::wcout << std::wstring(padding, L' ') << paypal;
    SetConsoleTextAttribute(hConsole, Colors::GREEN_BRIGHT);
    std::wcout << paypalLink;
    SetConsoleTextAttribute(hConsole, Colors::WHITE_BRIGHT);
    std::wcout << middle << revolut;
    SetConsoleTextAttribute(hConsole, Colors::GREEN_BRIGHT);
    std::wcout << revolutLink;
    SetConsoleTextAttribute(hConsole, Colors::WHITE_BRIGHT);
    std::wcout << std::wstring(innerWidth - totalLen - padding, L' ');
    
    SetConsoleTextAttribute(hConsole, Colors::BLUE_BRIGHT);
    std::wcout << L"|\n";

    // Bottom border
    std::wcout << L"+" << std::wstring(HelpLayout::WIDTH - 2, L'-') << L"+\n\n";

    SetConsoleTextAttribute(hConsole, originalColor);
}

void HelpSystem::PrintSectionHeader(const wchar_t* title) noexcept
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    WORD originalColor = csbi.wAttributes;
    
    SetConsoleTextAttribute(hConsole, Colors::YELLOW_BRIGHT);
    std::wcout << L"=== " << title << L" ===\n";
    
    SetConsoleTextAttribute(hConsole, originalColor);
}

void HelpSystem::PrintCommandLine(const wchar_t* command, const wchar_t* description) noexcept
{
    std::wcout << L"  " << std::left << std::setw(HelpLayout::COMMAND_WIDTH) 
               << command << L"- " << description << L"\n";
}

void HelpSystem::PrintNote(const wchar_t* note) noexcept
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    WORD originalColor = csbi.wAttributes;
    
    SetConsoleTextAttribute(hConsole, Colors::GRAY);
    std::wcout << L"  " << note << L"\n";
    
    SetConsoleTextAttribute(hConsole, originalColor);
}

void HelpSystem::PrintWarning(const wchar_t* warning) noexcept
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    WORD originalColor = csbi.wAttributes;
    
    SetConsoleTextAttribute(hConsole, Colors::RED_BRIGHT);
    std::wcout << L"  " << warning << L"\n";
    
    SetConsoleTextAttribute(hConsole, originalColor);
}

void HelpSystem::PrintUnknownCommandMessage(std::wstring_view command) noexcept
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    WORD originalColor = csbi.wAttributes;
    
    SetConsoleTextAttribute(hConsole, Colors::RED_BRIGHT);
    
    std::wcout << L"\nCommand not found: \"" << command << L"\"\n\n";
    std::wcout << L"To display help, use one of the following:\n";
    std::wcout << L"  kvc -h\n";
    std::wcout << L"  kvc help\n";
    std::wcout << L"  kvc | more         (for paginated output)\n";
    std::wcout << L"  kvc help >> \"%USERPROFILE%\\Desktop\\help.txt\"  (save to file)\n\n";
    
    SetConsoleTextAttribute(hConsole, originalColor);
    
    ScreenShake(3, 10);
}
