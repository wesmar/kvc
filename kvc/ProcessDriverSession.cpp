// ProcessDriverSession.cpp
// Manages the kernel driver session lifecycle and kernel address cache.
// All process operations that need driver I/O acquire a session through
// BeginDriverSession / EndDriverSession, which handle load-on-demand,
// keep-alive windows, and cache invalidation.

#include "Controller.h"
#include "common.h"
#include "Utils.h"
#include <chrono>

// ── Driver session lifecycle ─────────────────────────────────────────────────

// Reuses an existing session if it was used within the last 5 s;
// otherwise loads the driver and opens a fresh session.
bool Controller::BeginDriverSession()
{
    if (m_driverSessionActive) {
        if (std::chrono::steady_clock::now() - m_lastDriverUsage < std::chrono::seconds(5)) {
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

// Tears down the driver session.
// With force=false the session is kept alive for another 10 s after last use,
// allowing successive calls to reuse the same session cheaply.
// With force=true the session is ended immediately and all caches are cleared.
void Controller::EndDriverSession(bool force)
{
    if (!m_driverSessionActive)
        return;

    if (!force) {
        if (std::chrono::steady_clock::now() - m_lastDriverUsage < std::chrono::seconds(10))
            return;
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

// ── Kernel address cache ─────────────────────────────────────────────────────

// Rebuilds the PID→EPROCESS address map from a fresh process enumeration.
void Controller::RefreshKernelAddressCache()
{
    m_kernelAddressCache.clear();
    for (const auto& entry : GetProcessList())
        m_kernelAddressCache[entry.Pid] = entry.KernelAddress;
    m_cacheTimestamp = std::chrono::steady_clock::now();
}

// Returns a cached EPROCESS address for the given PID.
// The cache is refreshed if it is empty or older than 30 s.
// Falls back to a fresh process-list scan if the PID is not in the cache.
std::optional<ULONG_PTR> Controller::GetCachedKernelAddress(DWORD pid)
{
    const auto now = std::chrono::steady_clock::now();
    if (m_kernelAddressCache.empty() ||
        (now - m_cacheTimestamp) > std::chrono::seconds(30))
    {
        RefreshKernelAddressCache();
    }

    if (auto it = m_kernelAddressCache.find(pid);
        it != m_kernelAddressCache.end())
        return it->second;

    // Cache miss after refresh — do a single targeted scan.
    for (const auto& entry : GetProcessList()) {
        if (entry.Pid == pid) {
            m_kernelAddressCache[pid] = entry.KernelAddress;
            return entry.KernelAddress;
        }
    }

    ERROR(L"PID %d not found in process list", pid);
    return std::nullopt;
}
