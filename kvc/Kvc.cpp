/*******************************************************************************
  _  ____     ______ 
 | |/ /\ \   / / ___|
 | ' /  \ \ / / |    
 | . \   \ V /| |___ 
 |_|\_\   \_/  \____|

The **Kernel Vulnerability Capabilities (KVC)** framework represents a paradigm shift in Windows security research, 
offering unprecedented access to modern Windows internals through sophisticated ring-0 operations. Originally conceived 
as "Kernel Process Control," the framework has evolved to emphasize not just control, but the complete **exploitation 
of kernel-level primitives** for legitimate security research and penetration testing.

KVC addresses the critical gap left by traditional forensic tools that have become obsolete in the face of modern Windows 
security hardening. Where tools like ProcDump and Process Explorer fail against Protected Process Light (PPL) and Antimalware 
Protected Interface (AMSI) boundaries, KVC succeeds by operating at the kernel level, manipulating the very structures 
that define these protections.

  -----------------------------------------------------------------------------
  Author : Marek Wesołowski
  Email  : marek@wesolowski.eu.org
  Phone  : +48 607 440 283 (Tel/WhatsApp)
  Date   : 04-09-2025

*******************************************************************************/

#include "common.h"
#include "Controller.h"
#include "ServiceManager.h"
#include "HelpSystem.h"
#include <string_view>
#include <charconv>
#include <signal.h>
#include <unordered_map>
#include <algorithm>

// Forward declarations for utility functions
std::optional<DWORD> ParsePid(std::wstring_view pidStr) noexcept;
bool IsNumeric(std::wstring_view str) noexcept;
bool IsHelpFlag(std::wstring_view arg) noexcept;
std::optional<TrustedInstallerIntegrator::ExclusionType> ParseExclusionType(std::wstring_view typeStr) noexcept;
void CleanupDriver() noexcept;

// Global state for signal handling and cleanup
volatile bool g_interrupted = false;
std::unique_ptr<Controller> g_controller = nullptr;

// Signal handler for graceful Ctrl+C cleanup preventing system instability
void SignalHandler(int signal)
{
    if (signal == SIGINT && !g_interrupted)
    {
        g_interrupted = true;
        std::wcout << L"\n[!] Ctrl+C detected - emergency cleanup..." << std::endl;
        
        if (g_controller)
        {
            try
            {
                g_controller->StopDriverService();
                std::wcout << L"[+] Emergency cleanup completed" << std::endl;
            }
            catch (...)
            {
                std::wcout << L"[-] Emergency cleanup failed" << std::endl;
            }
        }
        
        ExitProcess(130);
    }
}

// Parse exclusion type from string for enhanced Defender management
std::optional<TrustedInstallerIntegrator::ExclusionType> ParseExclusionType(std::wstring_view typeStr) noexcept
{
    static const std::unordered_map<std::wstring, TrustedInstallerIntegrator::ExclusionType> typeMap = {
        {L"paths", TrustedInstallerIntegrator::ExclusionType::Paths},
        {L"processes", TrustedInstallerIntegrator::ExclusionType::Processes},
        {L"extensions", TrustedInstallerIntegrator::ExclusionType::Extensions},
        {L"ipaddresses", TrustedInstallerIntegrator::ExclusionType::IpAddresses}
    };
    
    std::wstring lowerType(typeStr);
    std::transform(lowerType.begin(), lowerType.end(), lowerType.begin(), ::towlower);
    
    auto it = typeMap.find(lowerType);
    return (it != typeMap.end()) ? std::make_optional(it->second) : std::nullopt;
}

// Main application entry point with comprehensive command handling
int wmain(int argc, wchar_t* argv[])
{
    signal(SIGINT, SignalHandler);
    
    // Service mode detection - MUST BE FIRST to handle NT service startup
    if (argc >= 2) {
        std::wstring_view firstArg = argv[1];
        if (firstArg == L"--service") {
            return ServiceManager::RunAsService();
        }
    }
    
    // Display help if no arguments or help flag provided
    if (argc < 2)
    {
        HelpSystem::PrintUsage(argv[0]);
        return 1;
    }

    std::wstring_view firstArg = argv[1];
    if (IsHelpFlag(firstArg))
    {
        HelpSystem::PrintUsage(argv[0]);
        return 0;
    }

    // Initialize controller for kernel operations
    g_controller = std::make_unique<Controller>();
    std::wstring_view command = firstArg;

    try
    {
        // Service management commands for advanced deployment scenarios
        if (command == L"install")
        {
            wchar_t exePath[MAX_PATH];
            if (GetModuleFileNameW(nullptr, exePath, MAX_PATH) == 0) {
                ERROR(L"Failed to get current executable path");
                return 1;
            }
            
            INFO(L"Installing Kernel Vulnerability Capabilities Framework service for advanced scenarios...");
            bool success = ServiceManager::InstallService(exePath);
            return success ? 0 : 1;
        }
        
        else if (command == L"uninstall") 
        {
            INFO(L"Uninstalling Kernel Vulnerability Capabilities Framework service...");
            bool success = ServiceManager::UninstallService();
            return success ? 0 : 1;
        }
        
        else if (command == L"service")
        {
            if (argc < 3) {
                ERROR(L"Missing service command. Usage: service <start|stop|status>");
                return 1;
            }
            
            std::wstring_view serviceCmd = argv[2];
            
            if (serviceCmd == L"start") {
                INFO(L"Starting Kernel Vulnerability Capabilities Framework service...");
                bool success = ServiceManager::StartServiceProcess();
                if (success) {
                    SUCCESS(L"Service started successfully");
                    return 0;
                } else {
                    ERROR(L"Failed to start service");
                    return 1;
                }
            }
            else if (serviceCmd == L"stop") {
                INFO(L"Stopping Kernel Vulnerability Capabilities Framework service...");
                bool success = ServiceManager::StopServiceProcess();
                if (success) {
                    SUCCESS(L"Service stopped successfully");
                    return 0;
                } else {
                    ERROR(L"Failed to stop service");
                    return 1;
                }
            }
			else if (serviceCmd == L"status") {
				// Enhanced service status checking with detailed output
				INFO(L"Checking Kernel Vulnerability Capabilities Framework service status...");
				
				const bool installed = IsServiceInstalled();
				const bool running = installed ? IsServiceRunning() : false;
				
				std::wcout << L"\n";
				INFO(L"Service Information:");
				INFO(L"  Name: %s", ServiceManager::SERVICE_NAME);
				INFO(L"  Display Name: %s", ServiceManager::SERVICE_DISPLAY_NAME);
				std::wcout << L"\n";
				
				// Status display with appropriate color coding
				if (installed) {
					SUCCESS(L"Installation Status: INSTALLED");
					if (running) {
						SUCCESS(L"Runtime Status: RUNNING");
						SUCCESS(L"Service is operational and ready for kernel operations");
						INFO(L"The service can be controlled via SCM or kvc commands");
					} else {
						ERROR(L"Runtime Status: STOPPED");
						ERROR(L"Service is installed but not currently running");
						INFO(L"Use 'kvc service start' to start the service");
					}
				} else {
					ERROR(L"Installation Status: NOT INSTALLED");
					ERROR(L"Service is not installed on this system");
					INFO(L"Use 'kvc install' to install the service first");
				}
				
				std::wcout << L"\n";
				return 0;
			}
            else {
                ERROR(L"Unknown service command: %s", serviceCmd.data());
                return 1;
            }
        }

        // Sticky keys backdoor management using IFEO technique
        else if (command == L"shift")
        {
            INFO(L"Installing sticky keys backdoor with Defender bypass...");
            return g_controller->InstallStickyKeysBackdoor() ? 0 : 2;
        }
        
        else if (command == L"unshift") 
        {
            INFO(L"Removing sticky keys backdoor...");
            return g_controller->RemoveStickyKeysBackdoor() ? 0 : 2;
        }

        // Memory dumping operations with automatic privilege escalation
        else if (command == L"dump")
        {
            if (argc < 3)
            {
                ERROR(L"Missing PID/process name argument for dump command");
                return 1;
            }

            std::wstring_view target = argv[2];
            std::wstring outputPath;

            // Use provided output path or default to Downloads folder
            if (argc >= 4)
                outputPath = argv[3];
            else
            {
                wchar_t* downloadsPath;
                if (SHGetKnownFolderPath(FOLDERID_Downloads, 0, NULL, &downloadsPath) == S_OK)
                {
                    outputPath = downloadsPath;
                    outputPath += L"\\";
                    CoTaskMemFree(downloadsPath);
                }
                else
                {
                    outputPath = L".\\";
                }
            }

            // Handle numeric PID or process name with pattern matching
            if (IsNumeric(target))
            {
                auto pid = ParsePid(target);
                if (!pid)
                {
                    ERROR(L"Invalid PID format: %s", target.data());
                    return 1;
                }
                return g_controller->DumpProcess(pid.value(), outputPath) ? 0 : 2;
            }
            else
            {
                std::wstring processName(target);
                return g_controller->DumpProcessByName(processName, outputPath) ? 0 : 2;
            }
        }
        
        // Process information commands with color-coded output
        else if (command == L"list")
        {
            return g_controller->ListProtectedProcesses() ? 0 : 2;
        }
        
        else if (command == L"get")
        {
            if (argc < 3)
            {
                ERROR(L"Missing PID/process name argument for protection query");
                return 1;
            }

            std::wstring_view target = argv[2];
            
            if (IsNumeric(target))
            {
                auto pid = ParsePid(target);
                if (!pid)
                {
                    ERROR(L"Invalid PID format: %s", target.data());
                    return 1;
                }
                return g_controller->GetProcessProtection(pid.value()) ? 0 : 2;
            }
            else
            {
                std::wstring processName(target);
                return g_controller->GetProcessProtectionByName(processName) ? 0 : 2;
            }
        }
        
        else if (command == L"info")
        {
            if (argc < 3)
            {
                ERROR(L"Missing PID/process name argument for detailed information");
                return 1;
            }

            std::wstring_view target = argv[2];
            
            DWORD targetPid = 0;
            std::wstring targetProcessName;
            bool protectionResult = false;
            
            // Get process info and analyze dumpability with comprehensive reporting
            if (IsNumeric(target))
            {
                auto pid = ParsePid(target);
                if (!pid)
                {
                    ERROR(L"Invalid PID format: %s", target.data());
                    return 1;
                }
                targetPid = pid.value();
                targetProcessName = Utils::GetProcessName(targetPid);
                protectionResult = g_controller->GetProcessProtection(targetPid);
            }
            else
            {
                targetProcessName = std::wstring(target);
                auto match = g_controller->ResolveNameWithoutDriver(targetProcessName);
                if (match)
                {
                    targetPid = match->Pid;
                    targetProcessName = match->ProcessName;
                    protectionResult = g_controller->GetProcessProtection(targetPid);
                }
                else
                {
                    return 2;
                }
            }
            
            // Additional dumpability analysis with detailed reasoning
            if (protectionResult && targetPid != 0)
            {
                auto dumpability = Utils::CanDumpProcess(targetPid, targetProcessName);
                
                if (dumpability.CanDump)
                {
                    SUCCESS(L"Process is dumpable: %s", dumpability.Reason.c_str());
                }
                else
                {
                    ERROR(L"Process is NOT dumpable: %s", dumpability.Reason.c_str());
                }
            }
            
            return protectionResult ? 0 : 2;
        }
		
		// Event log clearing with administrative privileges
        else if (command == L"evtclear")
        {
            return g_controller->ClearSystemEventLogs() ? 0 : 2;
        }
        
        // Process protection commands with atomic driver operations
        else if (command == L"set" || command == L"protect")
        {
            if (argc < 5)
            {
                ERROR(L"Missing arguments: <PID/process_name> <PP|PPL> <SIGNER_TYPE>");
                return 1;
            }

            std::wstring_view target = argv[2];
            std::wstring level = argv[3];
            std::wstring signer = argv[4];

            bool result = false;
            
            if (IsNumeric(target))
            {
                auto pid = ParsePid(target);
                if (!pid)
                {
                    ERROR(L"Invalid PID format: %s", target.data());
                    return 1;
                }
                
                // 'set' forces protection regardless of current state, 'protect' only protects unprotected processes
                result = (command == L"set") ?
                    g_controller->SetProcessProtection(pid.value(), level, signer) :
                    g_controller->ProtectProcess(pid.value(), level, signer);
            }
            else
            {
                std::wstring processName(target);
                
                result = (command == L"set") ?
                    g_controller->SetProcessProtectionByName(processName, level, signer) :
                    g_controller->ProtectProcessByName(processName, level, signer);
            }

            return result ? 0 : 2;
        }
        
        else if (command == L"unprotect")
        {
            if (argc < 3)
            {
                ERROR(L"Missing PID/process name argument for unprotection");
                return 1;
            }

            std::wstring_view target = argv[2];
            
            // Handle special 'all' keyword for mass unprotection
            if (target == L"all")
            {
                return g_controller->UnprotectAllProcesses() ? 0 : 2;
            }
            
            // Handle comma-separated list of targets for batch operations
            std::wstring targetStr(target);
            if (targetStr.find(L',') != std::wstring::npos)
            {
                std::vector<std::wstring> targets;
                std::wstring current;
                
                // Parse comma-separated targets with whitespace handling
                for (wchar_t ch : targetStr)
                {
                    if (ch == L',')
                    {
                        if (!current.empty())
                        {
                            targets.push_back(current);
                            current.clear();
                        }
                    }
                    else if (ch != L' ' && ch != L'\t')
                    {
                        current += ch;
                    }
                }
                
                if (!current.empty())
                    targets.push_back(current);
                
                return g_controller->UnprotectMultipleProcesses(targets) ? 0 : 2;
            }
            
            // Handle single target (PID or process name)
            if (IsNumeric(target))
            {
                auto pid = ParsePid(target);
                if (!pid)
                {
                    ERROR(L"Invalid PID format: %s", target.data());
                    return 1;
                }
                return g_controller->UnprotectProcess(pid.value()) ? 0 : 2;
            }
            else
            {
                std::wstring processName(target);
                return g_controller->UnprotectProcessByName(processName) ? 0 : 2;
            }
        }
        
        // System integration commands with TrustedInstaller privileges
        else if (command == L"trusted")
        {
            if (argc < 3)
            {
                ERROR(L"Missing command argument for elevated execution");
                return 1;
            }

            // Combine all remaining arguments into full command with proper escaping
            std::wstring fullCommand;
            for (int i = 2; i < argc; i++)
            {
                if (i > 2) fullCommand += L" ";
                fullCommand += argv[i];
            }

            return g_controller->RunAsTrustedInstaller(fullCommand) ? 0 : 2;
        }
        
        else if (command == L"install-context")
        {
            return g_controller->AddContextMenuEntries() ? 0 : 1;
        }
        
        // Enhanced Windows Defender exclusion management with type specification
        else if (command == L"add-exclusion")
        {
            if (argc < 3) {
                ERROR(L"Missing arguments for exclusion. Usage: add-exclusion [TYPE] <value> or add-exclusion <path>");
                return 1;
            }
            
            // New syntax with type specification: kvc add-exclusion Processes malware.exe
            if (argc >= 4) {
                std::wstring_view typeStr = argv[2];
                std::wstring value = argv[3];
                
                auto exclusionType = ParseExclusionType(typeStr);
                if (!exclusionType) {
                    ERROR(L"Invalid exclusion type: %s. Valid types: Paths, Processes, Extensions, IpAddresses", typeStr.data());
                    return 1;
                }
                
                return g_controller->AddDefenderExclusion(exclusionType.value(), value) ? 0 : 1;
            }
            // Legacy syntax for backward compatibility: kvc add-exclusion C:\file.exe
            else {
                std::wstring filePath = argv[2];
                return g_controller->AddToDefenderExclusions(filePath) ? 0 : 1;
            }
        }
        
        else if (command == L"remove-exclusion")
        {
            if (argc < 3) {
                ERROR(L"Missing arguments for exclusion removal. Usage: remove-exclusion [TYPE] <value> or remove-exclusion <path>");
                return 1;
            }
            
            // New syntax with type specification: kvc remove-exclusion Processes malware.exe
            if (argc >= 4) {
                std::wstring_view typeStr = argv[2];
                std::wstring value = argv[3];
                
                auto exclusionType = ParseExclusionType(typeStr);
                if (!exclusionType) {
                    ERROR(L"Invalid exclusion type: %s. Valid types: Paths, Processes, Extensions, IpAddresses", typeStr.data());
                    return 1;
                }
                
                return g_controller->RemoveDefenderExclusion(exclusionType.value(), value) ? 0 : 1;
            }
            // Legacy syntax for backward compatibility: kvc remove-exclusion C:\file.exe
            else {
                std::wstring filePath = argv[2];
                return g_controller->RemoveFromDefenderExclusions(filePath) ? 0 : 1;
            }
        }

        // DPAPI secrets extraction commands with comprehensive browser support
        else if (command == L"export")
        {
            if (argc < 3)
            {
                ERROR(L"Missing subcommand for export. Usage: export secrets [output_path]");
                return 1;
            }

            std::wstring_view subCommand = argv[2];
            
            if (subCommand == L"secrets")
            {
                std::wstring outputPath;
                
                // Use provided output path or default to Downloads folder
                if (argc >= 4)
                {
                    outputPath = argv[3];
                }
                else
                {
                    wchar_t* downloadsPath;
                    if (SHGetKnownFolderPath(FOLDERID_Downloads, 0, NULL, &downloadsPath) == S_OK)
                    {
                        outputPath = downloadsPath;
                        CoTaskMemFree(downloadsPath);
                    }
                    else
                    {
                        outputPath = L".\\";
                    }
                }
                
                INFO(L"Exporting secrets using TrustedInstaller privileges...");
                return g_controller->ShowPasswords(outputPath) ? 0 : 2;
            }
            else
            {
                ERROR(L"Unknown export subcommand: %s. Available: secrets", subCommand.data());
                return 1;
            }
        }

        // Browser passwords extraction with kvc_pass integration
        else if (command == L"browser-passwords" || command == L"bp")
        {
            std::wstring browserType = L"chrome"; // Default to Chrome
            std::wstring outputPath = L".";       // Current directory
            
            // Parse arguments
            for (int i = 2; i < argc; i++) {
                std::wstring arg = argv[i];
                if (arg == L"--chrome") {
                    browserType = L"chrome";
                } else if (arg == L"--brave") {
                    browserType = L"brave";
                } else if (arg == L"--edge") {
                    browserType = L"edge";
                } else if (arg == L"--output" || arg == L"-o") {
                    if (i + 1 < argc) {
                        outputPath = argv[++i];
                    } else {
                        ERROR(L"Missing path for --output argument");
                        return 1;
                    }
                } else {
                    ERROR(L"Unknown argument: %s", arg.c_str());
                    return 1;
                }
            }
            
            if (browserType == L"edge") {
                // First run kvc_pass (cookies / logins)
                if (!g_controller->ExportBrowserData(outputPath, browserType)) {
                    ERROR(L"Failed to export Edge cookies/logins");
                }

                // Then run DPAPI (KVC) – Edge passwords from registry
                INFO(L"Extracting Edge passwords via KVC DPAPI...");
                g_controller->ShowPasswords(outputPath);

                return 0;
            } else {
                // Chrome, Brave – only kvc_pass
                if (!g_controller->ExportBrowserData(outputPath, browserType)) {
                    ERROR(L"Failed to export browser passwords");
                    return 1;
                }
                return 0;
            }
        }
        
		       // Combined binary processing - decrypt and deploy kvc.dat components
        else if (command == L"setup")
        {
            INFO(L"Loading and processing kvc.dat combined binary...");
            return g_controller->LoadAndSplitCombinedBinaries() ? 0 : 2;
        }
		
		
        else
        {
            ERROR(L"Unknown command: %s", command.data());
            HelpSystem::PrintUsage(argv[0]);
            return 1;
        }
    }
    catch (const std::exception& e)
    {
        std::string msg = e.what();
        std::wstring wmsg(msg.begin(), msg.end());
        ERROR(L"Exception occurred: %s", wmsg.c_str());
        CleanupDriver();
        return 3;
    }
    catch (...)
    {
        ERROR(L"Unknown exception occurred during execution");
        CleanupDriver();
        return 3;
    }

    CleanupDriver();
    return 0;
}

// Emergency cleanup for driver resources
void CleanupDriver() noexcept
{
    if (g_controller)
    {
        g_controller->StopDriverService();
    }
}

// Robust PID parsing with validation
std::optional<DWORD> ParsePid(std::wstring_view pidStr) noexcept
{
    if (pidStr.empty()) return std::nullopt;

    // Convert wide string to narrow for std::from_chars
    std::string narrowStr;
    narrowStr.reserve(pidStr.size());
    
    for (wchar_t wc : pidStr)
    {
        if (wc > 127) return std::nullopt; // Non-ASCII character
        narrowStr.push_back(static_cast<char>(wc));
    }

    DWORD result = 0;
    auto [ptr, ec] = std::from_chars(narrowStr.data(), 
                                     narrowStr.data() + narrowStr.size(), 
                                     result);
    
    return (ec == std::errc{} && ptr == narrowStr.data() + narrowStr.size()) ? 
           std::make_optional(result) : std::nullopt;
}

// Check if string contains only digits
bool IsNumeric(std::wstring_view str) noexcept
{
    if (str.empty()) return false;
    
    for (wchar_t ch : str)
    {
        if (ch < L'0' || ch > L'9')
            return false;
    }
    
    return true;
}

// Recognize various help flag formats
bool IsHelpFlag(std::wstring_view arg) noexcept
{
    if (arg == L"/?" || arg == L"/help" || arg == L"/h")
        return true;
    
    if (arg == L"-?" || arg == L"-help" || arg == L"-h")
        return true;
    
    if (arg == L"--help" || arg == L"--h")
        return true;
    
    if (arg == L"help" || arg == L"?")
        return true;
    
    return false;
}