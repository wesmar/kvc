/**
 * @file ControllerProcessOperations.cpp
 * @brief Process operations and protection management implementation
 * @author Marek Wesolowski
 * @date 2025
 * @copyright KVC Framework
 * 
 * Implements kernel-level process enumeration, protection manipulation,
 * termination, and batch operations through driver session management.
 * Provides caching for efficient multi-operation workflows.
 */

#include "Controller.h"
#include "common.h"
#include "Utils.h"
#include <regex>
#include <charconv>
#include <tlhelp32.h>
#include <unordered_map>

// ============================================================================
// EXTERNAL GLOBALS
// ============================================================================

/** @brief Global flag for user interruption (Ctrl+C) */
extern volatile bool g_interrupted;

// ============================================================================
// DRIVER SESSION MANAGEMENT
// ============================================================================

/**
 * @brief Begins a driver session with automatic reuse
 * 
 * Session lifecycle management:
 * 1. Checks for active session within 5-second window
 * 2. Reuses existing session if available
 * 3. Initializes new driver session if needed
 * 4. Updates usage timestamp for session tracking
 * 
 * @return bool true if driver session is ready, false on failure
 * 
 * @note Optimizes performance by avoiding repeated driver load/unload
 * @note Session reuse window: 5 seconds
 */
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

/**
 * @brief Ends driver session with optional keep-alive
 * 
 * Cleanup sequence:
 * 1. Checks if session is active
 * 2. If not forced, maintains session for 10 seconds
 * 3. Performs atomic cleanup on forced termination
 * 4. Clears kernel address cache
 * 5. Clears process list cache
 * 
 * @param force If true, terminates immediately; if false, allows keep-alive
 * 
 * @note Keep-alive window optimizes batch operations
 * @note Always clears caches on session end
 */
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

/**
 * @brief Updates driver usage timestamp for session lifetime management
 * 
 * @note Called on every driver operation to extend session lifetime
 */
void Controller::UpdateDriverUsageTimestamp() 
{
    m_lastDriverUsage = std::chrono::steady_clock::now();
}

// ============================================================================
// KERNEL ADDRESS CACHE MANAGEMENT
// ============================================================================

/**
 * @brief Refreshes kernel address cache from current process list
 * 
 * Cache refresh process:
 * 1. Clears existing cache entries
 * 2. Enumerates all running processes
 * 3. Maps PID to kernel EPROCESS address
 * 4. Updates cache timestamp
 * 
 * @note Cache reduces kernel enumeration overhead
 * @note Called automatically when cache expires (30 seconds)
 */
void Controller::RefreshKernelAddressCache() 
{
    m_kernelAddressCache.clear();
    auto processes = GetProcessList();
    
    for (const auto& entry : processes) {
        m_kernelAddressCache[entry.Pid] = entry.KernelAddress;
    }
    
    m_cacheTimestamp = std::chrono::steady_clock::now();
}

/**
 * @brief Retrieves cached kernel address for process ID
 * 
 * Lookup strategy:
 * 1. Checks cache expiration (30-second TTL)
 * 2. Refreshes cache if stale
 * 3. Returns cached address if available
 * 4. Performs manual search if not cached
 * 5. Updates cache with found address
 * 
 * @param pid Process ID to lookup
 * @return std::optional<ULONG_PTR> Kernel EPROCESS address or nullopt
 * 
 * @note Automatically maintains cache freshness
 * @note Falls back to manual search for new processes
 */
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

// ============================================================================
// PROCESS TERMINATION - PUBLIC API
// ============================================================================

/**
 * @brief Terminates process by PID with driver support
 * 
 * @param pid Process ID to terminate
 * @return bool true if termination successful
 * 
 * @note Uses automatic protection elevation for protected processes
 * @note Forces session cleanup after operation
 */
bool Controller::KillProcess(DWORD pid) noexcept 
{
    bool result = KillProcessInternal(pid, false);
    EndDriverSession(true);
    return result;
}

/**
 * @brief Terminates all processes matching name pattern
 * 
 * Termination sequence:
 * 1. Begins driver session
 * 2. Finds all processes matching pattern
 * 3. Terminates each match with protection elevation
 * 4. Tracks success/failure counts
 * 5. Ends driver session
 * 
 * @param processName Process name or pattern (supports wildcards)
 * @return bool true if at least one process terminated
 * 
 * @note Supports wildcard patterns (e.g., "chrome*")
 * @note Respects user interruption (Ctrl+C)
 */
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

/**
 * @brief Terminates multiple processes by PID list
 * 
 * @param pids Vector of process IDs to terminate
 * @return bool true if at least one process terminated
 * 
 * @note Uses single driver session for all operations
 * @note Respects user interruption
 */
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

/**
 * @brief Terminates multiple processes by mixed PID/name targets
 * 
 * Target resolution:
 * 1. Parses each target as PID (numeric) or name (pattern)
 * 2. Resolves all names to PIDs with pattern matching
 * 3. Deduplicates PID list
 * 4. Terminates all resolved processes
 * 
 * @param targets Vector of PIDs (as strings) or process names
 * @return bool true if at least one process terminated
 * 
 * @note Supports mixed input: {"1234", "chrome.exe", "note*"}
 */
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

// ============================================================================
// PROCESS PROTECTION MANIPULATION - PUBLIC API
// ============================================================================

/**
 * @brief Protects process by PID with specified protection level
 * 
 * Protection application:
 * 1. Validates process is not already protected
 * 2. Parses protection level and signer type
 * 3. Calculates combined protection byte
 * 4. Writes to EPROCESS.Protection field
 * 
 * @param pid Process ID to protect
 * @param protectionLevel Protection level string ("PP" or "PPL")
 * @param signerType Signer type string (e.g., "WinTcb", "Antimalware")
 * @return bool true if protection applied successfully
 * 
 * @note Fails if process is already protected
 * @note Use SetProcessProtection to override existing protection
 */
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

/**
 * @brief Removes protection from process by PID
 * 
 * @param pid Process ID to unprotect
 * @return bool true if protection removed successfully
 * 
 * @note Fails if process is not protected
 * @note Sets EPROCESS.Protection to 0
 */
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

/**
 * @brief Sets or overwrites process protection regardless of current state
 * 
 * @param pid Process ID
 * @param protectionLevel Protection level string ("PP" or "PPL")
 * @param signerType Signer type string
 * @return bool true if protection set successfully
 * 
 * @note Unlike ProtectProcess, this overwrites existing protection
 * @note Useful for changing protection levels
 */
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

/**
 * @brief Protects process by name with specified protection level
 * 
 * @param processName Process name or pattern
 * @param protectionLevel Protection level string
 * @param signerType Signer type string
 * @return bool true if protection applied successfully
 * 
 * @note Uses driver-free name resolution
 * @note Fails if multiple processes match pattern
 */
bool Controller::ProtectProcessByName(const std::wstring& processName, const std::wstring& protectionLevel, const std::wstring& signerType) noexcept 
{
    auto match = ResolveNameWithoutDriver(processName);
    return match ? ProtectProcess(match->Pid, protectionLevel, signerType) : false;
}

/**
 * @brief Removes protection from process by name
 * 
 * @param processName Process name or pattern
 * @return bool true if protection removed successfully
 */
bool Controller::UnprotectProcessByName(const std::wstring& processName) noexcept 
{
    auto match = ResolveNameWithoutDriver(processName);
    return match ? UnprotectProcess(match->Pid) : false;
}

/**
 * @brief Sets process protection by name
 * 
 * @param processName Process name or pattern
 * @param protectionLevel Protection level string
 * @param signerType Signer type string
 * @return bool true if protection set successfully
 */
bool Controller::SetProcessProtectionByName(const std::wstring& processName, const std::wstring& protectionLevel, const std::wstring& signerType) noexcept 
{
    auto match = ResolveNameWithoutDriver(processName);
    return match ? SetProcessProtection(match->Pid, protectionLevel, signerType) : false;
}

// ============================================================================
// BATCH PROTECTION OPERATIONS - PUBLIC API
// ============================================================================

/**
 * @brief Protects multiple processes with single driver session
 * 
 * Batch protection sequence:
 * 1. Validates protection parameters
 * 2. Resolves all targets (PIDs/names) to PIDs
 * 3. Opens single driver session
 * 4. Applies protection to each process
 * 5. Tracks success/failure statistics
 * 
 * @param targets Vector of PIDs or process names
 * @param protectionLevel Protection level string
 * @param signerType Signer type string
 * @return bool true if at least one process protected
 * 
 * @note Skips already-protected processes
 * @note More efficient than individual calls due to session reuse
 */
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

/**
 * @brief Sets protection on multiple processes (overwrites existing)
 * 
 * @param targets Vector of PIDs or process names
 * @param protectionLevel Protection level string
 * @param signerType Signer type string
 * @return bool true if at least one process modified
 * 
 * @note Unlike ProtectMultipleProcesses, overwrites existing protection
 */
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

/**
 * @brief Unprotects multiple processes by target list
 * 
 * @param targets Vector of PIDs or process names
 * @return bool true if all targets successfully unprotected
 * 
 * @note Returns true only if ALL targets unprotected
 * @note Use for partial success checking
 */
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

// ============================================================================
// SIGNER-BASED MASS OPERATIONS
// ============================================================================

/**
 * @brief Unprotects all processes with specified signer type
 * 
 * Mass unprotection workflow:
 * 1. Validates signer type
 * 2. Enumerates all protected processes
 * 3. Filters by signer type
 * 4. Saves state to session manager for restoration
 * 5. Removes protection from all matches
 * 
 * @param signerName Signer type name (e.g., "WinTcb", "Antimalware")
 * @return bool true if at least one process unprotected
 * 
 * @note State saved for potential restoration with restore command
 * @note Respects user interruption
 */
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

/**
 * @brief Sets protection for all processes with specified current signer type
 * 
 * Mass protection workflow:
 * 1. Validates current signer, new signer and protection level
 * 2. Enumerates all processes with current signer type  
 * 3. Applies new protection level and signer to all matches
 * 4. Processes protection changes in batch
 * 
 * @param currentSigner Current signer type to filter processes (e.g., "WinTcb", "Microsoft")
 * @param level New protection level to apply (e.g., "Windows", "WindowsLight")
 * @param newSigner New signer type to apply (e.g., "Antimalware", "WinTcb")
 * @return bool true if at least one process protection was successfully modified
 * 
 * @note Changes protection for both currently running and future processes with matching signer
 * @note Respects user interruption during batch operation
 * @warning This operation cannot be automatically restored like unprotection
 */
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

/**
 * @brief Removes protection from all protected processes
 * 
 * Global unprotection workflow:
 * 1. Enumerates all protected processes
 * 2. Groups by signer type
 * 3. Saves state for each signer group
 * 4. Removes protection from all processes
 * 5. Reports statistics per signer group
 * 
 * @return bool true if at least one process unprotected
 * 
 * @note State saved per signer for selective restoration
 * @note Provides detailed progress reporting
 */
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

// ============================================================================
// SESSION STATE RESTORATION
// ============================================================================

/**
 * @brief Restores protection for processes unprotected by signer
 * 
 * @param signerName Signer type to restore
 * @return bool true if restoration successful
 * 
 * @note Requires prior unprotect operation with state saved
 * @note Delegates to SessionManager for state tracking
 */
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

/**
 * @brief Restores protection for all previously unprotected processes
 * 
 * @return bool true if restoration successful
 * 
 * @note Restores all signer groups from current boot session
 */
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

/**
 * @brief Displays session history with restoration states
 * 
 * @note Delegates to SessionManager for display
 */
void Controller::ShowSessionHistory() noexcept 
{
    m_sessionMgr.ShowHistory();
}

// ============================================================================
// PROCESS INFORMATION AND LISTING
// ============================================================================

/**
 * @brief Lists all protected processes in formatted table
 * 
 * Display format includes:
 * - PID
 * - Process name (truncated to 28 chars)
 * - Protection level (PP/PPL)
 * - Signer type
 * - EXE signature level
 * - DLL signature level
 * - Kernel EPROCESS address
 * 
 * @return bool true if at least one protected process found
 * 
 * @note Uses ANSI color codes for visual categorization
 * @note Only displays processes with ProtectionLevel > 0
 */
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

/**
 * @brief Lists all processes with specific signer type
 * 
 * @param signerName Signer type name to filter by
 * @return bool true if at least one process found
 * 
 * @note Uses same display format as ListProtectedProcesses
 * @note Filters both protected and unprotected processes
 */
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
        std::wcout << L"\nNo processes found with signer type: " << signerName << L"\n";
        return false;
    }
    
    std::wcout << Utils::ProcessColors::GREEN
        << L" -------+------------------------------+---------+-----------------+-----------------------+-----------------------+--------------------\n"
        << Utils::ProcessColors::RESET;
    return true;
}

/**
 * @brief Retrieves and displays detailed protection info for process by PID
 * 
 * @param pid Process ID to query
 * @return bool true if information retrieved successfully
 * 
 * @note Displays protection level, signer, signature levels
 * @note Includes dumpability analysis
 */
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
    
    UCHAR signatureLevel = sigLevelOffset ? m_rtc->Read8(kernelAddr.value() + sigLevelOffset.value()).value_or(0) : 0;
    UCHAR sectionSignatureLevel = secSigLevelOffset ? m_rtc->Read8(kernelAddr.value() + secSigLevelOffset.value()).value_or(0) : 0;

    std::wstring processName = Utils::GetProcessName(pid);
    
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
    WORD originalColor = consoleInfo.wAttributes;

	if (protLevel == 0) {
		wprintf(L"[*] PID %d (%s) is not protected\n", pid, processName.c_str());
	} else {
		WORD protectionColor;
		if (signerType == static_cast<UCHAR>(PS_PROTECTED_SIGNER::Lsa)) {
			protectionColor = FOREGROUND_RED | FOREGROUND_INTENSITY;
		}
		else if (signerType == static_cast<UCHAR>(PS_PROTECTED_SIGNER::WinTcb) ||
				 signerType == static_cast<UCHAR>(PS_PROTECTED_SIGNER::WinSystem) ||
				 signerType == static_cast<UCHAR>(PS_PROTECTED_SIGNER::Windows)) {
			protectionColor = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
		}
		else if (signerType == static_cast<UCHAR>(PS_PROTECTED_SIGNER::Antimalware)) {
			protectionColor = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
		}
		else {
			protectionColor = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
		}
		
		SetConsoleTextAttribute(hConsole, protectionColor);
		wprintf(L"[*] PID %d (%s) protection: %s-%s (raw: 0x%02x)\n", 
				pid, processName.c_str(),
				Utils::GetProtectionLevelAsString(protLevel),
				Utils::GetSignerTypeAsString(signerType),
				currentProtection.value());
		SetConsoleTextAttribute(hConsole, originalColor);
	}
    
    EndDriverSession(true);
    return true;
}

// ============================================================================
// PROCESS INFORMATION BY NAME
// ============================================================================

/**
 * @brief Retrieves protection information for process by name
 * 
 * @param processName Process name or pattern
 * @return bool true if information retrieved successfully
 * 
 * @note Resolves name to PID and delegates to GetProcessProtection(DWORD)
 * @note Uses driver-free name resolution for efficiency
 */
bool Controller::GetProcessProtectionByName(const std::wstring& processName) noexcept 
{
    auto match = ResolveNameWithoutDriver(processName);
    return match ? GetProcessProtection(match->Pid) : false;
}

// ============================================================================
// INTERNAL TERMINATION IMPLEMENTATION
// ============================================================================

/**
 * @brief Internal process termination with automatic protection elevation
 * 
 * Termination workflow:
 * 1. Begins driver session if not in batch mode
 * 2. Retrieves process kernel address from cache
 * 3. Reads current protection level
 * 4. Elevates current process if target is protected
 * 5. Attempts termination with PROCESS_TERMINATE
 * 6. Falls back to PROCESS_ALL_ACCESS if needed
 * 7. Ends session if not in batch mode
 * 
 * @param pid Process ID to terminate
 * @param batchOperation If true, assumes session already active
 * @return bool true if termination successful
 * 
 * @note Automatically matches target protection for elevation
 * @note Critical for terminating PP/PPL processes
 */
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

// ============================================================================
// INTERNAL PROTECTION MANIPULATION - BATCH SUPPORT
// ============================================================================

/**
 * @brief Internal process protection with batch operation support
 * 
 * @param pid Process ID to protect
 * @param protectionLevel Protection level string
 * @param signerType Signer type string
 * @param batchOperation If true, assumes session active
 * @return bool true if protection applied
 * 
 * @note Skips already-protected processes with info message
 * @note Optimized for batch operations with session reuse
 */
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

/**
 * @brief Internal protection setter with batch support (overwrites existing)
 * 
 * @param pid Process ID
 * @param protectionLevel Protection level string
 * @param signerType Signer type string
 * @param batchOperation If true, assumes session active
 * @return bool true if protection set successfully
 * 
 * @note Unlike ProtectProcessInternal, always overwrites protection
 */
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

// ============================================================================
// KERNEL-LEVEL PROCESS ENUMERATION
// ============================================================================

/**
 * @brief Enumerates all processes by walking kernel EPROCESS linked list
 * 
 * Enumeration algorithm:
 * 1. Obtains PsInitialSystemProcess address
 * 2. Reads required structure offsets from OffsetFinder
 * 3. Walks ActiveProcessLinks circular list
 * 4. For each EPROCESS:
 *    - Reads UniqueProcessId (PID)
 *    - Reads Protection byte
 *    - Reads SignatureLevel bytes
 *    - Resolves process name
 * 5. Respects user interruption at multiple checkpoints
 * 6. Safety limit: 10,000 processes maximum
 * 
 * @return std::vector<ProcessEntry> All discovered processes with metadata
 * 
 * @note Returns empty vector if interrupted or initialization fails
 * @note Resolves unknown process names using kernel data
 * @note Critical for all protection operations
 */
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

/**
 * @brief Retrieves kernel address of PsInitialSystemProcess
 * 
 * @return std::optional<ULONG_PTR> System process EPROCESS address
 * 
 * @note Entry point for EPROCESS linked list traversal
 */
std::optional<ULONG_PTR> Controller::GetInitialSystemProcessAddress() noexcept 
{
    auto kernelBase = Utils::GetKernelBaseAddress();
    auto offset = m_of->GetOffset(Offset::KernelPsInitialSystemProcess);
    if (!kernelBase || !offset) return std::nullopt;

    ULONG_PTR pPsInitialSystemProcess = Utils::GetKernelAddress(kernelBase.value(), offset.value());
    return m_rtc->ReadPtr(pPsInitialSystemProcess);
}

/**
 * @brief Retrieves kernel EPROCESS address for process ID
 * 
 * @param pid Process ID to lookup
 * @return std::optional<ULONG_PTR> Kernel address or nullopt if not found
 * 
 * @note Enumerates entire process list - consider using cache
 */
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

/**
 * @brief Reads protection byte from EPROCESS structure
 * 
 * @param addr Kernel EPROCESS address
 * @return std::optional<UCHAR> Protection byte value
 * 
 * @note Reads EPROCESS.Protection field at dynamic offset
 */
std::optional<UCHAR> Controller::GetProcessProtection(ULONG_PTR addr) noexcept 
{
    auto offset = m_of->GetOffset(Offset::ProcessProtection);
    return offset ? m_rtc->Read8(addr + offset.value()) : std::nullopt;
}

/**
 * @brief Writes protection byte to EPROCESS structure
 * 
 * @param addr Kernel EPROCESS address
 * @param protection New protection value to write
 * @return bool true if write successful
 * 
 * @warning Direct kernel memory modification - use with caution
 */
bool Controller::SetProcessProtection(ULONG_PTR addr, UCHAR protection) noexcept 
{
    auto offset = m_of->GetOffset(Offset::ProcessProtection);
    return offset ? m_rtc->Write8(addr + offset.value(), protection) : false;
}

// ============================================================================
// PROCESS NAME RESOLUTION AND PATTERN MATCHING
// ============================================================================

/**
 * @brief Resolves process name to single match with driver support
 * 
 * Resolution workflow:
 * 1. Begins driver session
 * 2. Finds all processes matching pattern
 * 3. Validates single match (fails on ambiguity)
 * 4. Returns ProcessMatch with PID, name, kernel address
 * 
 * @param processName Process name or pattern
 * @return std::optional<ProcessMatch> Single match or nullopt
 * 
 * @note Fails if multiple matches found - requires specific pattern
 * @note Uses driver for accurate kernel address retrieval
 */
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

/**
 * @brief Finds all processes matching name pattern with driver
 * 
 * @param pattern Process name pattern (supports wildcards)
 * @return std::vector<ProcessMatch> All matching processes
 * 
 * @note Pattern matching: exact, substring, regex with wildcards
 * @note Case-insensitive matching
 */
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

/**
 * @brief Resolves process name without driver initialization
 * 
 * @param processName Process name or pattern
 * @return std::optional<ProcessMatch> Single match (without kernel address)
 * 
 * @note Uses CreateToolhelp32Snapshot for enumeration
 * @note Kernel address will be 0 - requires driver lookup if needed
 * @note Faster for operations that don't need kernel access
 */
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

/**
 * @brief Finds processes by pattern without driver
 * 
 * @param pattern Process name pattern
 * @return std::vector<ProcessMatch> Matches (kernel addresses will be 0)
 * 
 * @note Uses Windows Toolhelp API for snapshot enumeration
 * @note Useful for pre-driver operations
 */
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

/**
 * @brief Checks if process name matches pattern (case-insensitive)
 * 
 * Pattern matching modes:
 * 1. Exact match: "chrome.exe" matches "chrome.exe"
 * 2. Substring: "chrome" matches "chrome.exe"
 * 3. Wildcard: "chr*" matches "chrome.exe"
 * 4. Complex regex: "ch[ro]me*" uses full regex engine
 * 
 * @param processName Process name to test
 * @param pattern Pattern to match against
 * @return bool true if pattern matches
 * 
 * @note Case-insensitive comparison
 * @note Escapes regex special characters except asterisk
 * @note Asterisk (*) converts to regex ".*" for wildcard matching
 */
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