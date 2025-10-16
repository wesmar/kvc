#include "Controller.h"
#include "common.h"
#include "Utils.h"
#include <regex>
#include <charconv>
#include <tlhelp32.h>
#include <unordered_map>

extern volatile bool g_interrupted;

// Checks for active session within 5s window, reuses if available, otherwise initializes new session
bool Controller::BeginDriverSession() 
{
    if (m_driverSessionActive) {
        auto timeSinceLastUse = std::chrono::steady_clock::now() - m_lastDriverUsage;
        if (timeSinceLastUse < std::chrono::seconds(5)) {
            UpdateDriverUsageTimestamp();
            return true;
        }
    }
    
    if (!EnsureDriverAvailable()) {
        ERROR(L"Failed to load driver for session");
        return false;
    }
    
    m_driverSessionActive = true;
    UpdateDriverUsageTimestamp();
    return true;
}

// Ends driver session with optional keep-alive window (10s), clears caches on forced termination
void Controller::EndDriverSession(bool force) 
{
    if (!m_driverSessionActive) return;
    
    if (!force) {
        auto timeSinceLastUse = std::chrono::steady_clock::now() - m_lastDriverUsage;
        if (timeSinceLastUse < std::chrono::seconds(10)) {
            return;
        }
    }
    
    PerformAtomicCleanup();
    m_driverSessionActive = false;
    m_kernelAddressCache.clear();
    m_cachedProcessList.clear();
}

void Controller::UpdateDriverUsageTimestamp() 
{
    m_lastDriverUsage = std::chrono::steady_clock::now();
}

// Clears cache, enumerates all processes, maps PID to kernel EPROCESS address
void Controller::RefreshKernelAddressCache() 
{
    m_kernelAddressCache.clear();
    auto processes = GetProcessList();
    
    for (const auto& entry : processes) {
        m_kernelAddressCache[entry.Pid] = entry.KernelAddress;
    }
    
    m_cacheTimestamp = std::chrono::steady_clock::now();
}

// Returns cached kernel address with 30s TTL, refreshes if stale, falls back to manual search
std::optional<ULONG_PTR> Controller::GetCachedKernelAddress(DWORD pid) 
{
    auto now = std::chrono::steady_clock::now();
    if (m_kernelAddressCache.empty() || (now - m_cacheTimestamp) > std::chrono::seconds(30)) {
        RefreshKernelAddressCache();
    }
    
    auto it = m_kernelAddressCache.find(pid);
    if (it != m_kernelAddressCache.end()) {
        return it->second;
    }
    
    auto processes = GetProcessList();
    for (const auto& entry : processes) {
        if (entry.Pid == pid) {
            m_kernelAddressCache[pid] = entry.KernelAddress;
            return entry.KernelAddress;
        }
    }
    
    ERROR(L"PID %d not found in process list", pid);
    return std::nullopt;
}

// Terminates process by PID with automatic protection elevation
bool Controller::KillProcess(DWORD pid) noexcept 
{
    bool result = KillProcessInternal(pid, false);
    EndDriverSession(true);
    return result;
}

// Terminates all processes matching name pattern with wildcard support
bool Controller::KillProcessByName(const std::wstring& processName) noexcept 
{
    if (!BeginDriverSession()) return false;
    
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
        if (g_interrupted) {
            INFO(L"Process termination interrupted by user");
            break;
        }
        INFO(L"Attempting to terminate process: %s (PID %d)", match.ProcessName.c_str(), match.Pid);
        if (KillProcessInternal(match.Pid, true)) {
            SUCCESS(L"Successfully terminated: %s (PID %d)", match.ProcessName.c_str(), match.Pid);
            successCount++;
        } else {
            ERROR(L"Failed to terminate PID: %d", match.Pid);
        }
    }
    
    EndDriverSession(true);
    INFO(L"Kill operation completed: %d/%d processes terminated", successCount, totalCount);
    return successCount > 0;
}

// Terminates multiple processes by PID list using single driver session
bool Controller::KillMultipleProcesses(const std::vector<DWORD>& pids) noexcept 
{
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
        if (g_interrupted) {
            INFO(L"Batch operation interrupted by user");
            break;
        }
        INFO(L"Processing PID %d", pid);
        if (KillProcessInternal(pid, true)) {
            successCount++;
            SUCCESS(L"Successfully terminated PID %d", pid);
        } else {
            ERROR(L"Failed to terminate PID %d", pid);
        }
    }
    
    EndDriverSession(true);
    INFO(L"Batch operation completed: %d/%d processes terminated", successCount, pids.size());
    return successCount > 0;
}

// Terminates processes by mixed PID/name targets, resolves patterns and deduplicates
bool Controller::KillMultipleTargets(const std::vector<std::wstring>& targets) noexcept 
{
    if (targets.empty()) return false;
    if (!BeginDriverSession()) return false;
    
    std::vector<DWORD> allPids;
    for (const auto& target : targets) {
        if (Utils::IsNumeric(target)) {
            if (auto pid = Utils::ParsePid(target)) allPids.push_back(pid.value());
        } else {
            for (const auto& match : FindProcessesByName(target)) {
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
        if (g_interrupted) {
            INFO(L"Batch operation interrupted by user");
            break;
        }
        INFO(L"Processing PID %d", pid);
        if (KillProcessInternal(pid, true)) {
            successCount++;
            SUCCESS(L"Successfully terminated PID %d", pid);
        } else {
            ERROR(L"Failed to terminate PID %d", pid);
        }
    }

    EndDriverSession(true);
    INFO(L"Kill operation completed: %d/%d processes terminated", successCount, allPids.size());
    return successCount > 0;
}

// Applies protection to process, fails if already protected
bool Controller::ProtectProcess(DWORD pid, const std::wstring& protectionLevel, const std::wstring& signerType) noexcept 
{
    if (!BeginDriverSession()) {
        EndDriverSession(true);
        return false;
    }
    
    auto kernelAddr = GetCachedKernelAddress(pid);
    if (!kernelAddr) {
        EndDriverSession(true);
        return false;
    }

    if (auto prot = GetProcessProtection(kernelAddr.value()); prot && prot.value() > 0) {
        ERROR(L"PID %d is already protected", pid);
        EndDriverSession(true);
        return false;
    }

    auto level = Utils::GetProtectionLevelFromString(protectionLevel);
    auto signer = Utils::GetSignerTypeFromString(signerType);
    if (!level || !signer) {
        ERROR(L"Invalid protection level or signer type");
        EndDriverSession(true);
        return false;
    }

    UCHAR newProtection = Utils::GetProtection(level.value(), signer.value());
    if (!SetProcessProtection(kernelAddr.value(), newProtection)) {
        ERROR(L"Failed to protect PID %d", pid);
        EndDriverSession(true);
        return false;
    }

    SUCCESS(L"Protected PID %d with %s-%s", pid, protectionLevel.c_str(), signerType.c_str());
    EndDriverSession(true);
    return true;
}

// Removes protection from process, fails if not protected
bool Controller::UnprotectProcess(DWORD pid) noexcept 
{
    if (!BeginDriverSession()) {
        EndDriverSession(true);
        return false;
    }
    
    auto kernelAddr = GetCachedKernelAddress(pid);
    if (!kernelAddr) {
        EndDriverSession(true);
        return false;
    }

    auto currentProtection = GetProcessProtection(kernelAddr.value());
    if (!currentProtection || currentProtection.value() == 0) {
        ERROR(L"PID %d is not protected", pid);
        EndDriverSession(true);
        return false;
    }

    if (!SetProcessProtection(kernelAddr.value(), 0)) {
        ERROR(L"Failed to remove protection from PID %d", pid);
        EndDriverSession(true);
        return false;
    }

    SUCCESS(L"Removed protection from PID %d", pid);
    EndDriverSession(true);
    return true;
}

// Sets or overwrites process protection regardless of current state
bool Controller::SetProcessProtection(DWORD pid, const std::wstring& protectionLevel, const std::wstring& signerType) noexcept 
{
    if (!BeginDriverSession()) {
        EndDriverSession(true);
        return false;
    }

    auto level = Utils::GetProtectionLevelFromString(protectionLevel);
    auto signer = Utils::GetSignerTypeFromString(signerType);
    if (!level || !signer) {
        ERROR(L"Invalid protection level or signer type");
        EndDriverSession(true);
        return false;
    }

    auto kernelAddr = GetCachedKernelAddress(pid);
    if (!kernelAddr) {
        EndDriverSession(true);
        return false;
    }

    UCHAR newProtection = Utils::GetProtection(level.value(), signer.value());
    if (!SetProcessProtection(kernelAddr.value(), newProtection)) {
        ERROR(L"Failed to set protection on PID %d", pid);
        EndDriverSession(true);
        return false;
    }

    SUCCESS(L"Set protection %s-%s on PID %d", protectionLevel.c_str(), signerType.c_str(), pid);
    EndDriverSession(true);
    return true;
}

// Protects process by name, fails if multiple matches found
bool Controller::ProtectProcessByName(const std::wstring& processName, const std::wstring& protectionLevel, const std::wstring& signerType) noexcept 
{
    auto match = ResolveNameWithoutDriver(processName);
    return match ? ProtectProcess(match->Pid, protectionLevel, signerType) : false;
}

bool Controller::UnprotectProcessByName(const std::wstring& processName) noexcept 
{
    auto match = ResolveNameWithoutDriver(processName);
    return match ? UnprotectProcess(match->Pid) : false;
}

bool Controller::SetProcessProtectionByName(const std::wstring& processName, const std::wstring& protectionLevel, const std::wstring& signerType) noexcept 
{
    auto match = ResolveNameWithoutDriver(processName);
    return match ? SetProcessProtection(match->Pid, protectionLevel, signerType) : false;
}

// Protects multiple processes in single session, skips already-protected processes
bool Controller::ProtectMultipleProcesses(const std::vector<std::wstring>& targets, 
                                           const std::wstring& protectionLevel, 
                                           const std::wstring& signerType) noexcept 
{
    if (targets.empty()) {
        ERROR(L"No targets provided for batch protect operation");
        return false;
    }
    
    if (!BeginDriverSession()) {
        EndDriverSession(true);
        return false;
    }
    
    auto level = Utils::GetProtectionLevelFromString(protectionLevel);
    auto signer = Utils::GetSignerTypeFromString(signerType);
    if (!level || !signer) {
        ERROR(L"Invalid protection level or signer type");
        EndDriverSession(true);
        return false;
    }
    
    std::vector<DWORD> allPids;
    for (const auto& target : targets) {
        if (Utils::IsNumeric(target)) {
            if (auto pid = Utils::ParsePid(target)) {
                allPids.push_back(pid.value());
            }
        } else {
            for (const auto& match : FindProcessesByName(target)) {
                allPids.push_back(match.Pid);
            }
        }
    }
    
    if (allPids.empty()) {
        ERROR(L"No processes found matching the specified targets");
        EndDriverSession(true);
        return false;
    }
    
    INFO(L"Starting batch protect operation for %zu resolved processes", allPids.size());
    DWORD successCount = 0;
    
    for (DWORD pid : allPids) {
        if (g_interrupted) {
            INFO(L"Batch operation interrupted by user");
            break;
        }
        
        if (ProtectProcessInternal(pid, protectionLevel, signerType, true)) {
            successCount++;
        }
    }
    
    EndDriverSession(true);
    INFO(L"Batch protect completed: %d/%zu processes", successCount, allPids.size());
    return successCount > 0;
}

// Sets protection on multiple processes, overwrites existing protection
bool Controller::SetMultipleProcessesProtection(const std::vector<std::wstring>& targets, 
                                                 const std::wstring& protectionLevel, 
                                                 const std::wstring& signerType) noexcept 
{
    if (targets.empty()) {
        ERROR(L"No targets provided for batch set operation");
        return false;
    }
    
    if (!BeginDriverSession()) {
        EndDriverSession(true);
        return false;
    }
    
    auto level = Utils::GetProtectionLevelFromString(protectionLevel);
    auto signer = Utils::GetSignerTypeFromString(signerType);
    if (!level || !signer) {
        ERROR(L"Invalid protection level or signer type");
        EndDriverSession(true);
        return false;
    }
    
    std::vector<DWORD> allPids;
    for (const auto& target : targets) {
        if (Utils::IsNumeric(target)) {
            if (auto pid = Utils::ParsePid(target)) {
                allPids.push_back(pid.value());
            }
        } else {
            for (const auto& match : FindProcessesByName(target)) {
                allPids.push_back(match.Pid);
            }
        }
    }
    
    if (allPids.empty()) {
        ERROR(L"No processes found matching the specified targets");
        EndDriverSession(true);
        return false;
    }
    
    INFO(L"Starting batch set operation for %zu resolved processes", allPids.size());
    DWORD successCount = 0;
    
    for (DWORD pid : allPids) {
        if (g_interrupted) {
            INFO(L"Batch operation interrupted by user");
            break;
        }
        
        if (SetProcessProtectionInternal(pid, protectionLevel, signerType, true)) {
            successCount++;
        }
    }
    
    EndDriverSession(true);
    INFO(L"Batch set completed: %d/%zu processes", successCount, allPids.size());
    return successCount > 0;
}

// Unprotects multiple processes, returns true only if ALL succeed
bool Controller::UnprotectMultipleProcesses(const std::vector<std::wstring>& targets) noexcept 
{
    if (targets.empty()) return false;
    if (!BeginDriverSession()) {
        EndDriverSession(true);
        return false;
    }

    DWORD successCount = 0;
    DWORD totalCount = static_cast<DWORD>(targets.size());

    for (const auto& target : targets) {
        if (g_interrupted) break;
        bool result = false;
        if (Utils::IsNumeric(target)) {
            try {
                DWORD pid = std::stoul(target);
                result = UnprotectProcess(pid);
            } catch (...) {
                ERROR(L"Invalid PID: %s", target.c_str());
            }
        } else {
            result = UnprotectProcessByName(target);
        }
        if (result) successCount++;
    }

    INFO(L"Batch unprotection completed: %d/%d targets successfully processed", successCount, totalCount);
    EndDriverSession(true);
    return successCount == totalCount;
}

// Unprotects all processes with specified signer, saves state for restoration
bool Controller::UnprotectBySigner(const std::wstring& signerName) noexcept 
{
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
    for (const auto& entry : processes) {
        if (entry.ProtectionLevel > 0 && entry.SignerType == signerType.value()) {
            affectedProcesses.push_back(entry);
        }
    }
    
    if (affectedProcesses.empty()) {
        INFO(L"No protected processes found with signer: %s", signerName.c_str());
        EndDriverSession(true);
        return false;
    }

    INFO(L"Starting batch unprotection of processes signed by: %s", signerName.c_str());
    m_sessionMgr.SaveUnprotectOperation(signerName, affectedProcesses);

    DWORD successCount = 0;
    for (const auto& entry : affectedProcesses) {
        if (g_interrupted) {
            INFO(L"Batch operation interrupted by user");
            break;
        }
        if (SetProcessProtection(entry.KernelAddress, 0)) {
            successCount++;
            SUCCESS(L"Removed protection from PID %d (%s)", entry.Pid, entry.ProcessName.c_str());
        } else {
            ERROR(L"Failed to remove protection from PID %d (%s)", entry.Pid, entry.ProcessName.c_str());
        }
    }
    
    INFO(L"Batch unprotection completed: %d/%d processes successfully unprotected", successCount, affectedProcesses.size());
    EndDriverSession(true); 
    return successCount > 0;
}

// Changes protection for all processes with specified current signer
bool Controller::SetProtectionBySigner(const std::wstring& currentSigner,
                                      const std::wstring& level,
                                      const std::wstring& newSigner) noexcept
{
    auto currentSignerType = Utils::GetSignerTypeFromString(currentSigner);
    if (!currentSignerType) {
        ERROR(L"Invalid current signer type: %s", currentSigner.c_str());
        return false;
    }
    
    auto newSignerType = Utils::GetSignerTypeFromString(newSigner);
    if (!newSignerType) {
        ERROR(L"Invalid new signer type: %s", newSigner.c_str());
        return false;
    }
    
    auto protectionLevel = Utils::GetProtectionLevelFromString(level);
    if (!protectionLevel) {
        ERROR(L"Invalid protection level: %s", level.c_str());
        return false;
    }
    
    if (!BeginDriverSession()) {
        EndDriverSession(true);
        return false;
    }
    
    auto processes = GetProcessList();
    std::vector<ProcessEntry> targetProcesses;
    
    for (const auto& entry : processes) {
        if (entry.SignerType == currentSignerType.value()) {
            targetProcesses.push_back(entry);
        }
    }
    
    if (targetProcesses.empty()) {
        INFO(L"No processes found with signer: %s", currentSigner.c_str());
        EndDriverSession(true);
        return false;
    }
    
    INFO(L"Setting protection for %zu processes (signer: %s -> %s %s)",
         targetProcesses.size(), currentSigner.c_str(), level.c_str(), newSigner.c_str());
    
    UCHAR newProtection = (static_cast<UCHAR>(newSignerType.value()) << 4) | static_cast<UCHAR>(protectionLevel.value());
    
    DWORD successCount = 0;
    for (const auto& entry : targetProcesses) {
        if (g_interrupted) {
            INFO(L"Operation interrupted by user");
            break;
        }
        
        if (SetProcessProtection(entry.KernelAddress, newProtection)) {
            successCount++;
            SUCCESS(L"Set protection for PID %d (%s): %s-%s",
                   entry.Pid, entry.ProcessName.c_str(), level.c_str(), newSigner.c_str());
        } else {
            ERROR(L"Failed to set protection for PID %d (%s)",
                 entry.Pid, entry.ProcessName.c_str());
        }
    }
    
    INFO(L"Batch operation completed: %d/%d processes", successCount, targetProcesses.size());
    EndDriverSession(true);
    return successCount > 0;
}

// Removes protection from all protected processes, groups by signer and saves state
bool Controller::UnprotectAllProcesses() noexcept 
{
    if (!BeginDriverSession()) {
        EndDriverSession(true);
        return false;
    }

    auto processes = GetProcessList();
    std::unordered_map<std::wstring, std::vector<ProcessEntry>> groupedProcesses;
    
    for (const auto& entry : processes) {
        if (entry.ProtectionLevel > 0) {
            groupedProcesses[Utils::GetSignerTypeAsString(entry.SignerType)].push_back(entry);
        }
    }
    
    if (groupedProcesses.empty()) {
        INFO(L"No protected processes found");
        EndDriverSession(true);
        return false;
    }
    
    INFO(L"Starting mass unprotection (%zu signer groups)", groupedProcesses.size());
    DWORD totalSuccess = 0;
    DWORD totalProcessed = 0;
    
    for (const auto& [signerName, group] : groupedProcesses) {
        if (g_interrupted) break;
        INFO(L"Processing signer group: %s (%zu processes)", signerName.c_str(), group.size());
        m_sessionMgr.SaveUnprotectOperation(signerName, group);
        
        for (const auto& entry : group) {
            if (g_interrupted) break;
            totalProcessed++;
            if (SetProcessProtection(entry.KernelAddress, 0)) {
                totalSuccess++;
                SUCCESS(L"Removed protection from PID %d (%s)", entry.Pid, entry.ProcessName.c_str());
            } else {
                ERROR(L"Failed to remove protection from PID %d (%s)", entry.Pid, entry.ProcessName.c_str());
            }
        }
    }
    if (g_interrupted) {
        INFO(L"Mass unprotection interrupted by user");
    }
    
    INFO(L"Mass unprotection completed: %d/%d processes successfully unprotected", totalSuccess, totalProcessed);
    EndDriverSession(true);
    return totalSuccess > 0;
}

// Restores protection for processes unprotected by signer
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

// Restores protection for all previously unprotected processes
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

// Lists all protected processes in formatted table with color coding
bool Controller::ListProtectedProcesses() noexcept 
{
    if (!BeginDriverSession()) {
        EndDriverSession(true);
        return false;
    }
    
    auto processes = GetProcessList();
    EndDriverSession(true);
    
    if (!Utils::EnableConsoleVirtualTerminal()) {
        ERROR(L"Failed to enable console colors");
    }
    
    std::wcout << Utils::ProcessColors::GREEN
        << L"\n -------+------------------------------+---------+-----------------+-----------------------+-----------------------+--------------------\n"
        << Utils::ProcessColors::HEADER
        << L"   PID  |         Process Name         |  Level  |     Signer      |     EXE sig. level    |     DLL sig. level    |    Kernel addr.    "
        << Utils::ProcessColors::RESET << L"\n"
        << Utils::ProcessColors::GREEN
        << L" -------+------------------------------+---------+-----------------+-----------------------+-----------------------+--------------------\n";

    DWORD count = 0;
    for (const auto& entry : processes) {
        if (entry.ProtectionLevel > 0) {
            count++;
            const wchar_t* color = Utils::GetProcessDisplayColor(entry.SignerType, entry.SignatureLevel, entry.SectionSignatureLevel);
            
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
            std::wcout << color << buffer << Utils::ProcessColors::RESET;
        }
    }
    
    std::wcout << Utils::ProcessColors::GREEN
        << L" -------+------------------------------+---------+-----------------+-----------------------+-----------------------+--------------------\n"
        << Utils::ProcessColors::RESET;
    
    if (count == 0) {
        std::wcout << L"No protected processes found.\n";
        return false;
    }
    
    std::wcout << L"\nTotal protected processes: " << count << L"\n";
    return true;
}

// Lists all processes with specific signer type
bool Controller::ListProcessesBySigner(const std::wstring& signerName) noexcept 
{
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
    EndDriverSession(true);

    if (!Utils::EnableConsoleVirtualTerminal()) {
        ERROR(L"Failed to enable console colors");
    }

    std::wcout << Utils::ProcessColors::GREEN
        << L"\n -------+------------------------------+---------+-----------------+-----------------------+-----------------------+--------------------\n"
        << Utils::ProcessColors::HEADER
        << L"   PID  |         Process Name         |  Level  |     Signer      |     EXE sig. level    |     DLL sig. level    |    Kernel addr.    "
        << Utils::ProcessColors::RESET << L"\n"
        << Utils::ProcessColors::GREEN
        << L" -------+------------------------------+---------+-----------------+-----------------------+-----------------------+--------------------\n";

    bool foundAny = false;
    for (const auto& entry : processes) {
        if (entry.SignerType == signerType.value()) {
            foundAny = true;
            const wchar_t* color = Utils::GetProcessDisplayColor(entry.SignerType, entry.SignatureLevel, entry.SectionSignatureLevel);

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
            std::wcout << color << buffer << Utils::ProcessColors::RESET;
        }
    }
    
	if (!foundAny) {
			std::wcout << Utils::ProcessColors::RESET
					   << L"\nNo processes found with signer type: " << signerName << L"\n";
			return false;
		}
		
		std::wcout << Utils::ProcessColors::GREEN
			<< L" -------+------------------------------+---------+-----------------+-----------------------+-----------------------+--------------------\n"
			<< Utils::ProcessColors::RESET;
		return true;
}

// Retrieves and displays detailed protection info for process by PID
bool Controller::GetProcessProtection(DWORD pid) noexcept 
{
    if (!BeginDriverSession()) {
        EndDriverSession(true);
        return false;
    }
    
    auto kernelAddr = GetProcessKernelAddress(pid);
    if (!kernelAddr) {
        ERROR(L"Failed to get kernel address for PID %d", pid);
        EndDriverSession(true);
        return false;
    }
    
    auto currentProtection = GetProcessProtection(kernelAddr.value());
    if (!currentProtection) {
        ERROR(L"Failed to read protection for PID %d", pid);
        EndDriverSession(true);
        return false;
    }

    UCHAR protLevel = Utils::GetProtectionLevel(currentProtection.value());
    UCHAR signerType = Utils::GetSignerType(currentProtection.value());
    
    auto sigLevelOffset = m_of->GetOffset(Offset::ProcessSignatureLevel);
    auto secSigLevelOffset = m_of->GetOffset(Offset::ProcessSectionSignatureLevel);
    
    UCHAR signatureLevel = sigLevelOffset ? 
        m_rtc->Read8(kernelAddr.value() + sigLevelOffset.value()).value_or(0) : 0;
    UCHAR sectionSignatureLevel = secSigLevelOffset ? 
        m_rtc->Read8(kernelAddr.value() + secSigLevelOffset.value()).value_or(0) : 0;

    std::wstring processName = Utils::GetProcessName(pid);
    
    if (!Utils::EnableConsoleVirtualTerminal()) {
        ERROR(L"Failed to enable console colors");
    }
    
    if (protLevel == 0) {
        std::wcout << L"[*] PID " << pid << L" (" << processName << L") is not protected\n";
    } else {
        const wchar_t* color = Utils::GetProcessDisplayColor(
            signerType, signatureLevel, sectionSignatureLevel);
        
        std::wcout << color 
                   << L"[*] PID " << pid << L" (" << processName << L") protection: "
                   << Utils::GetProtectionLevelAsString(protLevel) << L"-"
                   << Utils::GetSignerTypeAsString(signerType)
                   << L" (raw: 0x" << std::hex << std::uppercase << (int)currentProtection.value() 
                   << std::dec << L")\n"
                   << Utils::ProcessColors::RESET;
    }
    
    EndDriverSession(true);
    return true;
}

// Retrieves protection info by name, delegates to GetProcessProtection(DWORD)
bool Controller::GetProcessProtectionByName(const std::wstring& processName) noexcept 
{
    auto match = ResolveNameWithoutDriver(processName);
    return match ? GetProcessProtection(match->Pid) : false;
}

// Terminates process with automatic protection elevation for PP/PPL targets
bool Controller::KillProcessInternal(DWORD pid, bool batchOperation) noexcept 
{
    if (!batchOperation && !BeginDriverSession()) {
        ERROR(L"Failed to start driver session for PID %d", pid);
        return false;
    }
    
    auto kernelAddr = GetCachedKernelAddress(pid);
    if (!kernelAddr) {
        if (!batchOperation) EndDriverSession(true);
        return false;
    }
    
    if (auto prot = GetProcessProtection(kernelAddr.value()); prot && prot.value() > 0) {
        UCHAR targetLevel = Utils::GetProtectionLevel(prot.value());
        UCHAR targetSigner = Utils::GetSignerType(prot.value());
        std::wstring levelStr = (targetLevel == static_cast<UCHAR>(PS_PROTECTED_TYPE::Protected)) ?
            L"PP" : L"PPL";
        INFO(L"Target process has %s-%s protection, elevating current process", levelStr.c_str(), Utils::GetSignerTypeAsString(targetSigner));
        
        UCHAR currentProcessProtection = Utils::GetProtection(targetLevel, targetSigner);
        if (!SetCurrentProcessProtection(currentProcessProtection)) {
            ERROR(L"Failed to elevate current process protection");
        }
    }

    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            ERROR(L"Failed to open process for termination (PID: %d, Error: %d)", pid, GetLastError());
            return false;
        }
    }

    BOOL terminated = TerminateProcess(hProcess, 1);
    DWORD terminationError = GetLastError();
    CloseHandle(hProcess);

    if (!terminated) {
        ERROR(L"Failed to terminate PID: %d (error: %d)", pid, terminationError);
    }
    
    return terminated;
}

// Applies protection in batch mode, skips already-protected processes
bool Controller::ProtectProcessInternal(DWORD pid, const std::wstring& protectionLevel, 
                                         const std::wstring& signerType, bool batchOperation) noexcept 
{
    if (!batchOperation && !BeginDriverSession()) {
        EndDriverSession(true);
        return false;
    }
    
    auto level = Utils::GetProtectionLevelFromString(protectionLevel);
    auto signer = Utils::GetSignerTypeFromString(signerType);
    if (!level || !signer) {
        ERROR(L"Invalid protection level or signer type for PID %d", pid);
        if (!batchOperation) EndDriverSession(true);
        return false;
    }
    
    auto kernelAddr = GetCachedKernelAddress(pid);
    if (!kernelAddr) {
        if (!batchOperation) EndDriverSession(true);
        return false;
    }
    
    if (auto currentProt = GetProcessProtection(kernelAddr.value()); 
        currentProt && currentProt.value() > 0) {
        INFO(L"PID %d already protected, skipping", pid);
        if (!batchOperation) EndDriverSession(true);
        return false;
    }
    
    UCHAR newProtection = Utils::GetProtection(level.value(), signer.value());
    bool result = SetProcessProtection(kernelAddr.value(), newProtection);
    
    if (result) {
        SUCCESS(L"Protected PID %d with %s-%s", pid, protectionLevel.c_str(), signerType.c_str());
    } else {
        ERROR(L"Failed to protect PID %d", pid);
    }
    
    if (!batchOperation) EndDriverSession(true);
    return result;
}

// Sets protection in batch mode, always overwrites existing protection
bool Controller::SetProcessProtectionInternal(DWORD pid, const std::wstring& protectionLevel, 
                                               const std::wstring& signerType, bool batchOperation) noexcept 
{
    if (!batchOperation && !BeginDriverSession()) {
        EndDriverSession(true);
        return false;
    }
    
    auto level = Utils::GetProtectionLevelFromString(protectionLevel);
    auto signer = Utils::GetSignerTypeFromString(signerType);
    if (!level || !signer) {
        ERROR(L"Invalid protection level or signer type for PID %d", pid);
        if (!batchOperation) EndDriverSession(true);
        return false;
    }
    
    auto kernelAddr = GetCachedKernelAddress(pid);
    if (!kernelAddr) {
        if (!batchOperation) EndDriverSession(true);
        return false;
    }
    
    UCHAR newProtection = Utils::GetProtection(level.value(), signer.value());
    bool result = SetProcessProtection(kernelAddr.value(), newProtection);
    
    if (result) {
        SUCCESS(L"Set protection %s-%s on PID %d", protectionLevel.c_str(), signerType.c_str(), pid);
    } else {
        ERROR(L"Failed to set protection on PID %d", pid);
    }
    
    if (!batchOperation) EndDriverSession(true);
    return result;
}

// Enumerates all processes by walking kernel EPROCESS linked list with 10k limit
std::vector<ProcessEntry> Controller::GetProcessList() noexcept 
{
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
        if (g_interrupted) break;

        auto pidPtr = m_rtc->ReadPtr(current + uniqueIdOffset.value());
        if (g_interrupted) break;
        
        auto protection = GetProcessProtection(current);
        
        std::optional<UCHAR> signatureLevel = std::nullopt;
        std::optional<UCHAR> sectionSignatureLevel = std::nullopt;
        
        auto sigLevelOffset = m_of->GetOffset(Offset::ProcessSignatureLevel);
        auto secSigLevelOffset = m_of->GetOffset(Offset::ProcessSectionSignatureLevel);
        
        if (g_interrupted) break;
        
        if (sigLevelOffset) signatureLevel = m_rtc->Read8(current + sigLevelOffset.value());
        if (secSigLevelOffset) sectionSignatureLevel = m_rtc->Read8(current + secSigLevelOffset.value());
        
        if (pidPtr && protection) {
            if (ULONG_PTR pidValue = pidPtr.value(); pidValue > 0 && pidValue <= MAXDWORD) {
                ProcessEntry entry{};
                entry.KernelAddress = current;
                entry.Pid = static_cast<DWORD>(pidValue);
                entry.ProtectionLevel = Utils::GetProtectionLevel(protection.value());
                entry.SignerType = Utils::GetSignerType(protection.value());
                entry.SignatureLevel = signatureLevel.value_or(0);
                entry.SectionSignatureLevel = sectionSignatureLevel.value_or(0);
                
                if (g_interrupted) break;
                
                std::wstring basicName = Utils::GetProcessName(entry.Pid);
                entry.ProcessName = (basicName == L"[Unknown]")
                    ? Utils::ResolveUnknownProcessLocal(entry.Pid, entry.KernelAddress, entry.ProtectionLevel, entry.SignerType)
                    : basicName;
                
                processes.push_back(entry);
                processCount++;
            }
        }

        if (g_interrupted) break;

        auto nextPtr = m_rtc->ReadPtr(current + linksOffset.value());
        if (!nextPtr) break;
        
        current = nextPtr.value() - linksOffset.value();
        
        if (processCount >= 10000) break;
        
    } while (current != initialProcess.value() && !g_interrupted);

    return processes;
}

// Returns kernel address of PsInitialSystemProcess
std::optional<ULONG_PTR> Controller::GetInitialSystemProcessAddress() noexcept 
{
    auto kernelBase = Utils::GetKernelBaseAddress();
    auto offset = m_of->GetOffset(Offset::KernelPsInitialSystemProcess);
    if (!kernelBase || !offset) return std::nullopt;

    ULONG_PTR pPsInitialSystemProcess = Utils::GetKernelAddress(kernelBase.value(), offset.value());
    return m_rtc->ReadPtr(pPsInitialSystemProcess);
}

// Retrieves kernel EPROCESS address for PID by enumerating process list
std::optional<ULONG_PTR> Controller::GetProcessKernelAddress(DWORD pid) noexcept 
{
    auto processes = GetProcessList();
    for (const auto& entry : processes) {
        if (entry.Pid == pid)
            return entry.KernelAddress;
    }
    DEBUG(L"Kernel address not available for PID %d", pid);
    return std::nullopt;
}

// Reads EPROCESS.Protection byte at dynamic offset
std::optional<UCHAR> Controller::GetProcessProtection(ULONG_PTR addr) noexcept 
{
    auto offset = m_of->GetOffset(Offset::ProcessProtection);
    return offset ? m_rtc->Read8(addr + offset.value()) : std::nullopt;
}

// Writes protection byte to EPROCESS structure
bool Controller::SetProcessProtection(ULONG_PTR addr, UCHAR protection) noexcept 
{
    auto offset = m_of->GetOffset(Offset::ProcessProtection);
    return offset ? m_rtc->Write8(addr + offset.value(), protection) : false;
}

// Resolves name to single match with driver, fails on ambiguity
std::optional<ProcessMatch> Controller::ResolveProcessName(const std::wstring& processName) noexcept 
{
    if (!BeginDriverSession()) return std::nullopt;
    
    auto matches = FindProcessesByName(processName);
    EndDriverSession(true);
    
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

// Finds all processes matching pattern with case-insensitive wildcard support
std::vector<ProcessMatch> Controller::FindProcessesByName(const std::wstring& pattern) noexcept 
{
    std::vector<ProcessMatch> matches;
    for (const auto& entry : GetProcessList()) {
        if (IsPatternMatch(entry.ProcessName, pattern)) {
            matches.push_back({entry.Pid, entry.ProcessName, entry.KernelAddress});
        }
    }
    return matches;
}

// Resolves name without driver using Toolhelp snapshot, kernel address will be 0
std::optional<ProcessMatch> Controller::ResolveNameWithoutDriver(const std::wstring& processName) noexcept 
{
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

// Finds processes by pattern using Toolhelp API without driver
std::vector<ProcessMatch> Controller::FindProcessesByNameWithoutDriver(const std::wstring& pattern) noexcept 
{
    std::vector<ProcessMatch> matches;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return matches;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);
    
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (IsPatternMatch(pe.szExeFile, pattern)) {
                matches.push_back({pe.th32ProcessID, pe.szExeFile, 0});
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    
    CloseHandle(hSnapshot);
    return matches;
}

// Case-insensitive pattern matching with exact, substring, and wildcard support
bool Controller::IsPatternMatch(const std::wstring& processName, const std::wstring& pattern) noexcept 
{
    std::wstring lowerProcessName = processName;
    std::wstring lowerPattern = pattern;
    std::transform(lowerProcessName.begin(), lowerProcessName.end(), lowerProcessName.begin(), ::towlower);
    std::transform(lowerPattern.begin(), lowerPattern.end(), lowerPattern.begin(), ::towlower);
    
    if (lowerProcessName == lowerPattern || lowerProcessName.find(lowerPattern) != std::wstring::npos) {
        return true;
    }
    
    std::wstring regexPattern = lowerPattern;
    std::wstring specialChars = L"\\^$.+{}[]|()";
    for (wchar_t ch : specialChars) {
        size_t pos = 0;
        while ((pos = regexPattern.find(ch, pos)) != std::wstring::npos) {
            regexPattern.insert(pos, 1, L'\\');
            pos += 2;
        }
    }
    
    size_t pos = 0;
    while ((pos = regexPattern.find(L'*', pos)) != std::wstring::npos) {
        if (pos == 0 || regexPattern[pos - 1] != L'\\') {
            regexPattern.replace(pos, 1, L".*");
            pos += 2;
        } else {
            pos++;
        }
    }
    
    try {
        return std::regex_search(lowerProcessName, std::wregex(regexPattern, std::regex_constants::icase));
    } catch (const std::regex_error&) {
        return false;
    }
}