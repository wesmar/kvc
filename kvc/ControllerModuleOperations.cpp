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
    
    // Try standard enumeration first
    auto modules = ModuleManager::EnumerateModules(pid);
    
    bool usedElevation = false;
    
    // If access denied, try with protection elevation like dump operation
    if (modules.empty()) {
        DEBUG(L"Standard access denied, attempting with protection elevation...");
        
        if (!BeginDriverSession()) {
            ERROR(L"Failed to initialize driver for protected access");
            return false;
        }
        
        // Get target process protection level
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
        
        EndDriverSession(true);
    }
    
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

// Read memory from specific module using kernel driver for protected access
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
    
    // Find target module in process
    auto module = ModuleManager::FindModule(pid, moduleName);
    if (!module) {
        ERROR(L"Module '%s' not found in process %lu", moduleName.c_str(), pid);
        return false;
    }
    
    INFO(L"Reading %zu bytes from %s at offset 0x%llX", size, module->name.c_str(), offset);
    INFO(L"Module base: 0x%llX, Size: 0x%08X", module->baseAddress, module->size);
    
    // Validate offset is within module bounds
    if (offset >= module->size) {
        ERROR(L"Offset 0x%llX exceeds module size 0x%08X", offset, module->size);
        return false;
    }
    
    // Clamp read size to module boundary
    size_t maxReadable = module->size - static_cast<size_t>(offset);
    if (size > maxReadable) {
        INFO(L"Clamping read size to %zu bytes (module boundary)", maxReadable);
        size = maxReadable;
    }
    
    // Initialize driver session for kernel memory access
    if (!BeginDriverSession()) {
        ERROR(L"Failed to initialize driver session");
        return false;
    }
    
    ULONG_PTR targetAddress = module->baseAddress + offset;
    std::vector<unsigned char> buffer(size);
    
    // Read memory in 8-byte chunks using kernel driver
    bool readSuccess = true;
    for (size_t i = 0; i < size && !g_interrupted; i += 8) {
        size_t chunkSize = std::min<size_t>(8, size - i);
        
        if (chunkSize == 8) {
            auto val = m_rtc->Read64(targetAddress + i);
            if (val) {
                memcpy(buffer.data() + i, &val.value(), 8);
            } else {
                readSuccess = false;
                break;
            }
        } else if (chunkSize >= 4) {
            auto val = m_rtc->Read32(targetAddress + i);
            if (val) {
                memcpy(buffer.data() + i, &val.value(), 4);
                if (chunkSize > 4) {
                    // Read remaining bytes individually
                    for (size_t j = 4; j < chunkSize; j++) {
                        auto byte = m_rtc->Read8(targetAddress + i + j);
                        if (byte) {
                            buffer[i + j] = byte.value();
                        } else {
                            readSuccess = false;
                            break;
                        }
                    }
                }
            } else {
                readSuccess = false;
                break;
            }
        } else {
            // Read remaining bytes individually
            for (size_t j = 0; j < chunkSize; j++) {
                auto byte = m_rtc->Read8(targetAddress + i + j);
                if (byte) {
                    buffer[i + j] = byte.value();
                } else {
                    readSuccess = false;
                    break;
                }
            }
        }
    }
    
    EndDriverSession(true);
    
    if (g_interrupted) {
        INFO(L"Read operation interrupted by user");
        return false;
    }
    
    if (!readSuccess) {
        ERROR(L"Failed to read memory at 0x%llX", targetAddress);
        return false;
    }
    
    // Display hex dump of read data
    SUCCESS(L"Read %zu bytes successfully", size);
    ModuleManager::PrintHexDump(buffer.data(), size, targetAddress);
    
    // Check for PE signature at module base
    if (offset == 0 && ModuleManager::ValidatePESignature(buffer.data(), size)) {
        SUCCESS(L"Valid PE file detected (MZ signature)");
    }
    
    return true;
}
