// ProcessManager.cpp
#include "ProcessManager.h"
#include "Controller.h"
#include "Utils.h"
#include <cwctype>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <TlHelp32.h>
#include <algorithm>
#include <cctype>

extern volatile bool g_interrupted;

// Helper function to check if string contains only digits (PID)
bool ProcessManager::IsNumericPid(std::wstring_view input) noexcept {
    if (input.empty()) return false;
    return std::all_of(input.begin(), input.end(), [](wchar_t c) { return iswdigit(c); });
}

// Find process PIDs by name using Windows toolhelp API
std::vector<DWORD> ProcessManager::FindProcessIdsByName(const std::wstring& processName) noexcept {
    std::vector<DWORD> pids;
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return pids;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);
    
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            std::wstring currentName = pe.szExeFile;
            
            // Remove .exe extension for comparison if present
            if (currentName.size() > 4 && currentName.substr(currentName.size() - 4) == L".exe") {
                currentName = currentName.substr(0, currentName.size() - 4);
            }
            
            // Case-insensitive partial match
            std::wstring lowerCurrent = currentName;
            std::wstring lowerTarget = processName;
            std::transform(lowerCurrent.begin(), lowerCurrent.end(), lowerCurrent.begin(), ::towlower);
            std::transform(lowerTarget.begin(), lowerTarget.end(), lowerTarget.begin(), ::towlower);
            
            if (lowerCurrent.find(lowerTarget) != std::wstring::npos) {
                pids.push_back(pe.th32ProcessID);
            }
            
        } while (Process32NextW(hSnapshot, &pe));
    }
    
    CloseHandle(hSnapshot);
    return pids;
}

// Terminate process with automatic protection elevation
bool ProcessManager::TerminateProcessWithProtection(DWORD processId, Controller* controller) noexcept {
    if (!controller) {
        ERROR(L"Controller not available for protection elevation");
        return false;
    }

    if (g_interrupted) {
        INFO(L"Operation cancelled by user before termination");
        return false;
    }

    std::wstring processName = Utils::GetProcessName(processId);
    INFO(L"Attempting to terminate process: %s (PID %d)", processName.c_str(), processId);

    // Get target process protection level for self-elevation
    auto kernelAddr = controller->GetProcessKernelAddress(processId);
    bool needsSelfProtection = false;
    std::wstring levelStr, signerStr;

    if (kernelAddr) {
        auto targetProtection = controller->GetProcessProtection(kernelAddr.value());
        if (targetProtection && targetProtection.value() > 0) {
            needsSelfProtection = true;
            
            UCHAR targetLevel = Utils::GetProtectionLevel(targetProtection.value());
            UCHAR targetSigner = Utils::GetSignerType(targetProtection.value());

            levelStr = (targetLevel == static_cast<UCHAR>(PS_PROTECTED_TYPE::Protected)) ? L"PP" : L"PPL";
            
            switch (static_cast<PS_PROTECTED_SIGNER>(targetSigner)) {
                case PS_PROTECTED_SIGNER::Lsa: signerStr = L"Lsa"; break;
                case PS_PROTECTED_SIGNER::WinTcb: signerStr = L"WinTcb"; break;
                case PS_PROTECTED_SIGNER::WinSystem: signerStr = L"WinSystem"; break;
                case PS_PROTECTED_SIGNER::Windows: signerStr = L"Windows"; break;
                case PS_PROTECTED_SIGNER::Antimalware: signerStr = L"Antimalware"; break;
                case PS_PROTECTED_SIGNER::Authenticode: signerStr = L"Authenticode"; break;
                case PS_PROTECTED_SIGNER::CodeGen: signerStr = L"CodeGen"; break;
                case PS_PROTECTED_SIGNER::App: signerStr = L"App"; break;
                default: 
                    INFO(L"Unknown signer type - attempting termination without self-protection");
                    needsSelfProtection = false;
                    break;
            }

            if (needsSelfProtection) {
                INFO(L"Target process protection: %s-%s", levelStr.c_str(), signerStr.c_str());
                
                if (!controller->SelfProtect(levelStr, signerStr)) {
                    INFO(L"Self-protection elevation failed: %s-%s (attempting termination anyway)", 
                         levelStr.c_str(), signerStr.c_str());
                    needsSelfProtection = false;
                } else {
                    SUCCESS(L"Self-protection elevated to %s-%s", levelStr.c_str(), signerStr.c_str());
                }
            }
        } else {
            INFO(L"Target process is not protected, proceeding with standard termination");
        }
    } else {
        INFO(L"Could not get kernel address for target process, proceeding without self-protection");
    }

    if (g_interrupted) {
        INFO(L"Operation cancelled by user during protection setup");
        if (needsSelfProtection) {
            controller->SelfProtect(L"none", L"none");
        }
        return false;
    }

    // Attempt process termination
    HANDLE processHandle = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
    bool success = false;
    
    if (processHandle) {
        BOOL result = TerminateProcess(processHandle, 0);
        CloseHandle(processHandle);
        success = (result != FALSE);
    } else {
        DWORD error = GetLastError();
        ERROR(L"Failed to open process for termination (error: %d)", error);
    }

    // Cleanup self-protection
    if (needsSelfProtection) {
        if (!controller->SelfProtect(L"none", L"none")) {
            ERROR(L"Failed to cleanup self-protection after termination");
        } else {
            INFO(L"Self-protection cleaned up successfully");
        }
    }

    return success;
}

// Main command handler for process termination operations with protection elevation
void ProcessManager::HandleKillCommand(int argc, wchar_t* argv[], Controller* controller) noexcept {
    if (argc < 3) {
        PrintKillUsage();
        return;
    }

    if (!controller) {
        ERROR(L"Controller not available - cannot perform protected process termination");
        return;
    }

    INFO(L"Starting process termination with automatic protection elevation...");

    std::vector<DWORD> processIds;
    if (!ParseProcessIds(argv[2], processIds)) {
        ERROR(L"Failed to parse process ID/name list");
        return;
    }

    if (processIds.empty()) {
        ERROR(L"No valid process IDs or names provided");
        return;
    }

    if (g_interrupted) {
        INFO(L"Operation cancelled by user before processing");
        return;
    }

    // Execute termination for each target process with protection elevation
        int successCount = 0;
		for (DWORD pid : processIds) {
			if (g_interrupted) {
				INFO(L"Operation cancelled by user during batch termination");
				break;
			}

			if (controller->KillProcess(pid)) {
				SUCCESS(L"Terminated PID: %u", pid);
				successCount++;
			} else {
				ERROR(L"Failed to terminate PID: %u", pid);
			}
    }
    
    INFO(L"Kill operation completed: %d/%zu processes terminated", 
         successCount, processIds.size());
}

// Parse comma-separated process ID/name list with input validation
bool ProcessManager::ParseProcessIds(std::wstring_view pidList, std::vector<DWORD>& pids) noexcept {
    std::wstring pidStr(pidList);
    size_t pos = 0;
    size_t start = 0;
    
    while (pos != std::wstring::npos) {
        pos = pidStr.find(L',', start);
        std::wstring token;
        
        if (pos != std::wstring::npos) {
            token = pidStr.substr(start, pos - start);
            start = pos + 1;
        } else {
            token = pidStr.substr(start);
        }
        
        // Trim leading and trailing whitespace
        size_t first = token.find_first_not_of(L" \t");
        if (first == std::wstring::npos) continue;
        
        size_t last = token.find_last_not_of(L" \t");
        token = token.substr(first, (last - first + 1));
        
        if (token.empty()) continue;
        
        // Check if token is numeric (PID) or text (process name)
        if (IsNumericPid(token)) {
            try {
                DWORD pid = std::wcstoul(token.c_str(), nullptr, 10);
                if (pid == 0) {
                    ERROR(L"Invalid PID: %s (PID cannot be 0)", token.c_str());
                    continue;
                }
                pids.push_back(pid);
            }
            catch (...) {
                ERROR(L"Invalid PID format: %s", token.c_str());
                continue;
            }
        }
        else {
            // Process name - find matching PIDs using Toolhelp32 (will be handled by Controller later)
            auto foundPids = FindProcessIdsByName(token);
            if (foundPids.empty()) {
                ERROR(L"No process found matching: %s", token.c_str());
                continue;
            }

            INFO(L"Found %zu processes matching '%s'", foundPids.size(), token.c_str());
            for (DWORD pid : foundPids) {
                pids.push_back(pid);
            }
        }
    }
    
    return !pids.empty();
}

// Display command usage and examples
void ProcessManager::PrintKillUsage() noexcept {
    std::wcout << L"Usage: kvc kill <pid1|name1>[,pid2|name2,pid3|name3,...]\n";
    std::wcout << L"  Examples:\n";
    std::wcout << L"    kvc kill 1234\n";
    std::wcout << L"    kvc kill notepad\n";
    std::wcout << L"    kvc kill total\n";
    std::wcout << L"    kvc kill lsass          # Protected process (auto-elevation)\n";
    std::wcout << L"    kvc kill 1234,notepad,calc\n";
    std::wcout << L"    kvc kill \"1234, notepad, 5678\"\n";
    std::wcout << L"  Note: Automatically elevates protection level to match protected targets\n\n";
}