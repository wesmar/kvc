// ControllerModuleOperations.cpp
// Module enumeration and memory inspection operations via kernel driver
// Provides process module listing and kernel-level memory access

#include "Controller.h"
#include "ModuleManager.h"
#include "common.h"
#include "Utils.h"
#include <tlhelp32.h>

extern volatile bool g_interrupted;

// Enumerate all loaded modules in target process by PID
bool Controller::EnumerateProcessModules(DWORD pid) noexcept
{
    // Validate target process exists before attempting enumeration
    std::wstring processName = Utils::GetProcessName(pid);
    if (processName.empty()) {
        ERROR(L"Process with PID %lu not found", pid);
        return false;
    }
    
    INFO(L"Enumerating modules for %s (PID: %lu)", processName.c_str(), pid);
    
    // INIT DRIVER SESSION FIRST - na początku!
    if (!BeginDriverSession()) {
        ERROR(L"Failed to initialize driver for module operations");
        return false;
    }
    
    // Try standard enumeration first
    auto modules = ModuleManager::EnumerateModules(pid);
    bool usedElevation = false;
    
    // If access denied, try with protection elevation
    if (modules.empty()) {
        DEBUG(L"Standard access denied, attempting with protection elevation...");
        
        // Get target process protection level (TERAZ mamy driver!)
        auto kernelAddr = GetCachedKernelAddress(pid);
        if (kernelAddr) {
            auto targetProtection = GetProcessProtection(kernelAddr.value());
            
            if (targetProtection && targetProtection.value() > 0) {
                UCHAR targetLevel = Utils::GetProtectionLevel(targetProtection.value());
                UCHAR targetSigner = Utils::GetSignerType(targetProtection.value());
                
                std::wstring levelStr = (targetLevel == static_cast<UCHAR>(PS_PROTECTED_TYPE::Protected)) ? L"PP" : L"PPL";
                std::wstring signerStr = L"WinTcb";
                
                switch (static_cast<PS_PROTECTED_SIGNER>(targetSigner)) {
                    case PS_PROTECTED_SIGNER::Lsa: signerStr = L"Lsa"; break;
                    case PS_PROTECTED_SIGNER::WinTcb: signerStr = L"WinTcb"; break;
                    case PS_PROTECTED_SIGNER::WinSystem: signerStr = L"WinSystem"; break;
                    case PS_PROTECTED_SIGNER::Windows: signerStr = L"Windows"; break;
                    case PS_PROTECTED_SIGNER::Antimalware: signerStr = L"Antimalware"; break;
                    default: break;
                }
                
                INFO(L"Protected process detected (%s-%s), elevating privileges...", levelStr.c_str(), signerStr.c_str());
                
                if (SelfProtect(levelStr, signerStr)) {
                    usedElevation = true;
                    
                    // Retry module enumeration with elevated privileges
                    modules = ModuleManager::EnumerateModules(pid);
                    
                    // Remove self-protection after enumeration
                    SelfProtect(L"none", L"none");
                }
            }
        }
    }
    
    EndDriverSession(true);
    
    if (modules.empty()) {
        ERROR(L"No modules found or access denied");
        return false;
    }
    
    // Display formatted module list
    ModuleManager::PrintModuleList(modules);
    SUCCESS(L"Found %zu modules%s", modules.size(), usedElevation ? L" (via kernel elevation)" : L"");
    
    return true;
}

// Enumerate modules by process name with pattern matching
bool Controller::EnumerateProcessModulesByName(const std::wstring& processName) noexcept
{
    // Resolve process name to PID using existing infrastructure
    auto match = ResolveNameWithoutDriver(processName);
    
    if (!match) {
        ERROR(L"No process found matching: %s", processName.c_str());
        return false;
    }
    
    INFO(L"Resolved %s to PID %lu", match->ProcessName.c_str(), match->Pid);
    return EnumerateProcessModules(match->Pid);
}

// Read memory from specific module safely
// Uses driver ONLY to strip protection, then uses standard API for reading
bool Controller::ReadModuleMemory(DWORD pid, const std::wstring& moduleName, ULONG_PTR offset, size_t size) noexcept
{
    // Validate parameters
    if (size == 0 || size > 4096) {
        ERROR(L"Invalid size (must be 1-4096 bytes)");
        return false;
    }

    // Validate process exists
    std::wstring processName = Utils::GetProcessName(pid);
    if (processName.empty()) {
        ERROR(L"Process with PID %lu not found", pid);
        return false;
    }

    // 1. Locate the module address
    // We try to find the module using standard Toolhelp32 snapshot first
    std::optional<ModuleInfo> module = ModuleManager::FindModule(pid, moduleName);
    bool usedElevation = false;

    // If module not found (likely due to access denied on PPL), try elevating via driver
    if (!module) {
        // Initialize driver if not ready
        if (BeginDriverSession()) {
            DEBUG(L"Module not found via standard API, attempting kernel elevation...");

            auto kernelAddr = GetCachedKernelAddress(pid);
            if (kernelAddr) {
                // Check current protection
                auto targetProtection = GetProcessProtection(kernelAddr.value());
                if (targetProtection && targetProtection.value() > 0) {
                    UCHAR level = Utils::GetProtectionLevel(targetProtection.value());
                    UCHAR signer = Utils::GetSignerType(targetProtection.value());
                    
                    // Temporarily elevate our own process to matching level to see the modules
                    // Note: This helps Toolhelp32 snapshot succeed
                    std::wstring levelStr = (level == 2) ? L"PP" : L"PPL";
                    // Using WinTcb as a high-privilege signer
                    if (SelfProtect(levelStr, L"WinTcb")) {
                        usedElevation = true;
                        module = ModuleManager::FindModule(pid, moduleName);
                        // Revert self-protection immediately
                        SelfProtect(L"none", L"none");
                    }
                }
            }
        }
    }

    if (!module) {
        // If still not found, it really doesn't exist or we can't see it
        ERROR(L"Module '%s' not found in process %lu (Access Denied or Invalid Name)", moduleName.c_str(), pid);
        EndDriverSession(false);
        return false;
    }

    // Validate read bounds
    if (offset >= module->size) {
        ERROR(L"Offset 0x%llX exceeds module size 0x%08X", offset, module->size);
        EndDriverSession(false);
        return false;
    }

    // Adjust size to not read past module end
    size_t maxReadable = module->size - static_cast<size_t>(offset);
    if (size > maxReadable) {
        INFO(L"Clamping read size to %zu bytes (module boundary)", maxReadable);
        size = maxReadable;
    }

    ULONG_PTR targetAddress = module->baseAddress + offset;
    INFO(L"Target Address: 0x%llX (Module: %s + 0x%llX)", targetAddress, module->name.c_str(), offset);

    // 2. Prepare for reading
    // Try to open process normally first
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);
    bool protectionStripped = false;
    UCHAR originalProtByte = 0;

	// If Access Denied, use the driver to STRIP protection from the target
	// The standard Windows API (OpenProcess) is blocked because the target is a Protected Process (PPL).
	// We temporarily use the kernel driver to disable this protection and gain the necessary handle.
	if (!hProcess && GetLastError() == ERROR_ACCESS_DENIED) {
		INFO(L"Access denied due to Protected Process (PPL). Bypassing protection via kernel driver...");
        
        if (BeginDriverSession()) {
            auto kernelAddr = GetCachedKernelAddress(pid);
            if (kernelAddr) {
                auto prot = GetProcessProtection(kernelAddr.value());
                if (prot) {
                    originalProtByte = prot.value();
                    // Nuke protection (set to 0) so we can open handle
                    if (SetProcessProtection(kernelAddr.value(), 0)) {
                        protectionStripped = true;
                        // Try opening again
                        hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);
                    }
                }
            }
        }
    }

    if (!hProcess) {
        ERROR(L"Failed to open process handle even after protection bypass attempt.");
        if (protectionStripped) {
            // Restore if we failed anyway
            auto kernelAddr = GetCachedKernelAddress(pid);
            if (kernelAddr) SetProcessProtection(kernelAddr.value(), originalProtByte);
        }
        EndDriverSession(true);
        return false;
    }

    // 3. Perform the read using standard API (Safe!)
    // We do NOT use m_rtc->Read here because targetAddress is User Mode virtual memory
    // Driver would interpret it as Kernel Mode virtual memory causing BSOD 0x3B
    std::vector<unsigned char> buffer(size);
    SIZE_T bytesRead = 0;
    
    bool success = ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(targetAddress), 
                                     buffer.data(), size, &bytesRead);

    if (!success) {
        ERROR(L"ReadProcessMemory failed: %d", GetLastError());
    }

    // 4. Cleanup and Restore Protection
    CloseHandle(hProcess);

    if (protectionStripped) {
        auto kernelAddr = GetCachedKernelAddress(pid);
        if (kernelAddr) {
            SetProcessProtection(kernelAddr.value(), originalProtByte);
            INFO(L"Restored original process protection (0x%02X)", originalProtByte);
        }
    }

    EndDriverSession(false);

    if (success && bytesRead > 0) {
        SUCCESS(L"Read %zu bytes successfully", bytesRead);
        ModuleManager::PrintHexDump(buffer.data(), bytesRead, targetAddress);

        // Check for MZ header if reading from start
        if (offset == 0 && ModuleManager::ValidatePESignature(buffer.data(), bytesRead)) {
            SUCCESS(L"Valid PE file detected (MZ signature)");
        }
        return true;
    }

    return false;
}