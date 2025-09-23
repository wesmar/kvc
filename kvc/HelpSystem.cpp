#include <windows.h>
#include "HelpSystem.h"
#include <iostream>
#include <iomanip>

void HelpSystem::PrintUsage(std::wstring_view programName) noexcept
{
    PrintHeader();
    
    std::wcout << L"Usage: " << programName << L" <command> [arguments]\n\n";
    
    PrintServiceCommands();
    PrintBasicCommands();
    PrintProcessTerminationCommands();
    PrintProtectionCommands();
    PrintSystemCommands();
    PrintBrowserCommands();
    PrintDefenderCommands();
    PrintSecurityEngineCommands();
    PrintDPAPICommands();
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

    const int width = 80;

    // Blue header border for visual appeal
    SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    std::wcout << L"\n";
    std::wcout << L"================================================================================\n";

    // Centered text printing with white color for readability
    auto printCentered = [&](const std::wstring& text) {
        int textLen = static_cast<int>(text.length());
        int padding = (width - textLen) / 2;
        if (padding < 0) padding = 0;
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        std::wcout << std::wstring(padding, L' ') << text << L"\n";
    };

    printCentered(L"Marek Wesolowski - WESMAR - 2025");
    printCentered(L"kvc.exe v1.0.1 https://kvc.pl");
    printCentered(L"+48 607-440-283, marek@wesolowski.eu.org");
    printCentered(L"kvc - Kernel Vulnerability Capabilities Framework");
    printCentered(L"Comprehensive Windows Security Research & Penetration Framework");
    printCentered(L"Features Process Protection, DPAPI Extraction, Defender Bypass & More");

    SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    std::wcout << L"================================================================================\n\n";

    // Restore original console color
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

void HelpSystem::PrintBasicCommands() noexcept
{
    PrintSectionHeader(L"Memory Dumping Commands");
    PrintCommandLine(L"dump <PID|process_name> [path]", L"Create comprehensive memory dump");
    PrintNote(L"Default path is the Downloads folder - simple: 'kvc dump lsass'");
    PrintWarning(L"MsMpEng dump only works with Defender disabled (otherwise Ctrl+C)");
    std::wcout << L"\n";
    
    PrintSectionHeader(L"Process Information Commands");
    PrintCommandLine(L"list", L"List all protected processes with color coding");
    PrintCommandLine(L"get <PID|process_name>", L"Get protection status of specific process");
    PrintCommandLine(L"info <PID|process_name>", L"Get detailed process info including dumpability");
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
    PrintCommandLine(L"unprotect <PID|process_name>", L"Remove protection from specific process");
    PrintCommandLine(L"unprotect all", L"Remove protection from ALL processes");
    PrintCommandLine(L"unprotect <PID1,PID2,PID3>", L"Remove protection from multiple processes");
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

void HelpSystem::PrintDefenderCommands() noexcept
{
    PrintSectionHeader(L"Enhanced Windows Defender Exclusion Management");
    PrintCommandLine(L"add-exclusion <path>", L"Add file/folder to exclusions (legacy syntax)");
    PrintCommandLine(L"add-exclusion Paths <path>", L"Add specific path to exclusions");
    PrintCommandLine(L"add-exclusion Processes <name>", L"Add process to exclusions");
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

void HelpSystem::PrintBrowserCommands() noexcept
{
    PrintSectionHeader(L"Browser Password Extraction Commands");
    PrintCommandLine(L"browser-passwords", L"Extract Chrome passwords (default)");
    PrintCommandLine(L"bp --chrome", L"Extract Chrome passwords explicitly");
    PrintCommandLine(L"bp --brave", L"Extract Brave browser passwords");  
    PrintCommandLine(L"bp --edge", L"Extract Edge browser passwords");
    PrintCommandLine(L"bp --output C:\\reports", L"Custom output directory");
    PrintCommandLine(L"bp --edge -o C:\\data", L"Edge passwords to custom path");
    PrintNote(L"Requires kvc_pass.exe in current directory");
    PrintNote(L"Uses COM elevation for advanced browser encryption");
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
    const int commandWidth = 50;
    
    auto printLine = [&](const std::wstring& command, const std::wstring& description) {
        std::wcout << L"  " << std::left << std::setw(commandWidth)
                   << (std::wstring(programName) + L" " + command)
                   << L"# " << description << L"\n";
    };

    // Service and system management examples
    printLine(L"shift", L"Install sticky keys backdoor");
    printLine(L"unshift", L"Remove sticky keys backdoor");
    printLine(L"install", L"Install as NT service (advanced)");
    printLine(L"service start", L"Start the service");
    printLine(L"uninstall", L"Remove service");
    
    // Memory dumping examples
    printLine(L"dump lsass C:\\dumps", L"Dump LSASS to specific folder");
    printLine(L"dump 1044", L"Dump PID 1044 to Downloads folder");
    
    // Process information and protection examples
    printLine(L"list", L"Show all protected processes");
    printLine(L"info lsass", L"Detailed info with dumpability analysis");
    printLine(L"protect 1044 PPL Antimalware", L"Protect process with PPL-Antimalware");
    printLine(L"set 5678 PP Windows", L"Force set PP-Windows protection");
    printLine(L"unprotect lsass", L"Remove protection from LSASS");
    printLine(L"unprotect 1,2,3,lsass", L"Batch unprotect multiple targets");
	
	// Process termination examples
    printLine(L"kill 1234", L"Terminate process with PID 1234");
    printLine(L"kill total", L"Terminate Total Commander by name");
    printLine(L"kill 1234,5678,9012", L"Terminate multiple processes");
    printLine(L"kill lsass", L"Terminate protected process (auto-elevation)");
    
    // TrustedInstaller examples
    printLine(L"trusted cmd", L"Run command as TrustedInstaller");
    printLine(L"trusted \"C:\\app.exe\" --arg", L"Run application with arguments");
    printLine(L"install-context", L"Add right-click menu entries");
    
    // Defender exclusion examples
    printLine(L"add-exclusion", L"Add current program to exclusions");
    printLine(L"add-exclusion C:\\malware.exe", L"Add specific file to exclusions");
    printLine(L"add-exclusion Paths C:\\temp", L"Add folder to path exclusions");
    printLine(L"add-exclusion Processes cmd.exe", L"Add process to exclusions");
    printLine(L"add-exclusion Extensions .tmp", L"Add extension to exclusions");
    printLine(L"add-exclusion IpAddresses 1.1.1.1", L"Add IP to exclusions");
    printLine(L"remove-exclusion Processes cmd.exe", L"Remove process exclusion");
    
    // Security engine management examples
    printLine(L"secengine status", L"Check Windows Defender status");
    printLine(L"secengine disable", L"Disable Windows Defender engine");
    printLine(L"secengine enable", L"Re-enable Windows Defender engine");
    printLine(L"secengine disable --restart", L"Disable Defender and restart system");
    printLine(L"secengine enable --restart", L"Enable Defender and restart system");
    
    // Data extraction examples
    printLine(L"export secrets", L"Export secrets to Downloads folder");
    printLine(L"export secrets C:\\reports", L"Export secrets to specific folder");
    
    std::wcout << L"\n";
}

void HelpSystem::PrintSecurityNotice() noexcept
{
    PrintSectionHeader(L"SECURITY & LEGAL NOTICE");
    
    // Critical warning section with red highlighting for maximum visibility
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    WORD originalColor = csbi.wAttributes;
    
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
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
    
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::wcout << L"  LEGAL & ETHICAL RESPONSIBILITY:\n";
    SetConsoleTextAttribute(hConsole, originalColor);
    std::wcout << L"  - Intended for authorized penetration testing and security research only\n";
    std::wcout << L"  - User assumes full legal responsibility for all actions performed\n";
    std::wcout << L"  - Ensure proper authorization before using on any system\n";
    std::wcout << L"  - Misuse may violate computer crime laws in your jurisdiction\n";
    std::wcout << L"  - This tool can modify system security settings and extract sensitive data\n\n";
    
    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::wcout << L"  PROFESSIONAL USE GUIDELINES:\n";
    SetConsoleTextAttribute(hConsole, originalColor);
    std::wcout << L"  - Document all activities for security assessments\n";
    std::wcout << L"  - Use 'unshift' and 'remove-exclusion' commands to clean up after testing\n";
    std::wcout << L"  - Verify system state before and after testing\n";
    std::wcout << L"  - Report findings through appropriate responsible disclosure channels\n\n";
    
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
    std::wcout << L"  By using this tool, you acknowledge understanding and accept full responsibility.\n\n";
    SetConsoleTextAttribute(hConsole, originalColor);
}

void HelpSystem::PrintFooter() noexcept
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    WORD originalColor = csbi.wAttributes;
    
    const int width = 80;

    // Top border with blue color for professional appearance
    SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    std::wcout << L"+" << std::wstring(width-2, L'-') << L"+\n";

    // Centered footer content - split into multiple lines for readability
    std::wstring line1 = L"Support this project - a small donation is greatly appreciated";
    std::wstring line2 = L"and helps sustain private research builds.";
    std::wstring line3 = L"GitHub source code: https://github.com/wesmar/kvc/";
    std::wstring line4 = L"Professional services: marek@wesolowski.eu.org";
    
    auto printCenteredFooter = [&](const std::wstring& text) {
        int textLen = static_cast<int>(text.length());
        int padding = (width - 2 - textLen) / 2;
        if (padding < 0) padding = 0;

        // Left border in blue
        SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        std::wcout << L"|";

        // Text in white for maximum readability
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        std::wcout << std::wstring(padding, L' ') << text
                   << std::wstring(width - 2 - padding - textLen, L' ');

        // Right border in blue
        SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        std::wcout << L"|\n";
    };

    printCenteredFooter(line1);
    printCenteredFooter(line2);
    printCenteredFooter(line3);
    printCenteredFooter(line4);

    // Donation line with colored links for easy identification
    SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    std::wcout << L"|";
    
    // Calculate spacing for PayPal and Revolut links
    std::wstring paypal = L"PayPal: ";
    std::wstring paypalLink = L"paypal.me/ext1";
    std::wstring middle = L"        ";
    std::wstring revolut = L"Revolut: ";
    std::wstring revolutLink = L"revolut.me/marekb92";
    
    int totalLen = static_cast<int>(paypal.length() + paypalLink.length() + 
                                   middle.length() + revolut.length() + revolutLink.length());
    int padding = (width - totalLen - 2) / 2;
    if (padding < 0) padding = 0;
    
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    std::wcout << std::wstring(padding, L' ') << paypal;
    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::wcout << paypalLink;
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    std::wcout << middle << revolut;
    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::wcout << revolutLink;
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    std::wcout << std::wstring(width - totalLen - padding - 2, L' ');
    
    SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    std::wcout << L"|\n";

    // Bottom border to complete the frame
    std::wcout << L"+" << std::wstring(width-2, L'-') << L"+\n\n";

    // Restore original color for subsequent output
    SetConsoleTextAttribute(hConsole, originalColor);
}

// Helper functions for consistent formatting and color management
void HelpSystem::PrintSectionHeader(const wchar_t* title) noexcept
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    WORD originalColor = csbi.wAttributes;
    
    // Yellow color for section headers to make them stand out
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::wcout << L"=== " << title << L" ===\n";
    
    // Restore original color after header
    SetConsoleTextAttribute(hConsole, originalColor);
}

void HelpSystem::PrintCommandLine(const wchar_t* command, const wchar_t* description) noexcept
{
    const int commandWidth = 50;
    std::wcout << L"  " << std::left << std::setw(commandWidth) 
               << command << L"- " << description << L"\n";
}

void HelpSystem::PrintNote(const wchar_t* note) noexcept
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    WORD originalColor = csbi.wAttributes;
    
    // Gray color for informational notes to differentiate from commands
    SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY);
    std::wcout << L"  " << note << L"\n";
    
    // Restore original color after note
    SetConsoleTextAttribute(hConsole, originalColor);
}

void HelpSystem::PrintWarning(const wchar_t* warning) noexcept
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    WORD originalColor = csbi.wAttributes;
    
    // Red color for warning messages to grab attention
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
    std::wcout << L"  " << warning << L"\n";
    
    // Restore original color after warning
    SetConsoleTextAttribute(hConsole, originalColor);
}