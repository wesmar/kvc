// ProcessEnumerator.cpp
// Kernel-assisted process enumeration, name resolution, and pattern matching.
//
// Core flow: GetProcessList() walks the EPROCESS doubly-linked list via the
// kernel driver, decorates each entry with user-mode data from a single
// Toolhelp32 snapshot, and returns a flat vector of ProcessEntry structs.
// Higher-level finders (FindProcessesByName, ResolveProcessName) operate on
// top of that vector and never touch the driver directly.

#include "Controller.h"
#include "common.h"
#include "Utils.h"
#include <tlhelp32.h>
#include <regex>
#include <unordered_map>

extern volatile bool g_interrupted;

// ── Internal helpers ─────────────────────────────────────────────────────────

// Builds a PID→exe-name map from a single Toolhelp32 snapshot.
// One snapshot for the whole enumeration avoids per-PID OpenProcess() calls.
static std::unordered_map<DWORD, std::wstring> BuildProcessNameMap() noexcept
{
    std::unordered_map<DWORD, std::wstring> map;
    map.reserve(512);

    SnapshotGuard snap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snap) return map;

    PROCESSENTRY32W pe{sizeof(PROCESSENTRY32W)};
    if (Process32FirstW(snap.get(), &pe)) {
        do {
            map.emplace(pe.th32ProcessID, pe.szExeFile);
        } while (Process32NextW(snap.get(), &pe));
    }
    return map;
}

// ── Kernel address primitives ────────────────────────────────────────────────

// Returns the kernel address of PsInitialSystemProcess (the head of the
// EPROCESS linked list).
std::optional<ULONG_PTR> Controller::GetInitialSystemProcessAddress() noexcept
{
    const auto kernelBase = Utils::GetKernelBaseAddress();
    const auto offset     = m_of->GetOffset(Offset::KernelPsInitialSystemProcess);
    if (!kernelBase || !offset) return std::nullopt;

    const ULONG_PTR pPsInitialSystemProcess =
        Utils::GetKernelAddress(kernelBase.value(), offset.value());
    return m_rtc->ReadPtr(pPsInitialSystemProcess);
}

// Locates the EPROCESS address for a PID by walking the full process list.
std::optional<ULONG_PTR> Controller::GetProcessKernelAddress(DWORD pid) noexcept
{
    for (const auto& entry : GetProcessList()) {
        if (entry.Pid == pid)
            return entry.KernelAddress;
    }
    DEBUG(L"Kernel address not available for PID %d", pid);
    return std::nullopt;
}

// Reads the PS_PROTECTION byte from EPROCESS at the dynamic offset.
std::optional<UCHAR> Controller::GetProcessProtection(ULONG_PTR addr) noexcept
{
    const auto offset = m_of->GetOffset(Offset::ProcessProtection);
    return offset ? m_rtc->Read8(addr + offset.value()) : std::nullopt;
}

// Writes the PS_PROTECTION byte to EPROCESS.
bool Controller::SetProcessProtection(ULONG_PTR addr, UCHAR protection) noexcept
{
    const auto offset = m_of->GetOffset(Offset::ProcessProtection);
    return offset && m_rtc->Write8(addr + offset.value(), protection);
}

// Overwrites both SignatureLevel and SectionSignatureLevel in EPROCESS.
bool Controller::SetProcessSignatures(ULONG_PTR addr,
                                       UCHAR exeSig, UCHAR dllSig) noexcept
{
    const auto sigOffset    = m_of->GetOffset(Offset::ProcessSignatureLevel);
    const auto secSigOffset = m_of->GetOffset(Offset::ProcessSectionSignatureLevel);

    bool ok = true;
    if (sigOffset)    ok &= m_rtc->Write8(addr + sigOffset.value(),    exeSig);
    if (secSigOffset) ok &= m_rtc->Write8(addr + secSigOffset.value(), dllSig);
    return ok;
}

// ── Process list enumeration ─────────────────────────────────────────────────

// Enumerates all processes by walking the kernel EPROCESS linked list.
// Offsets are hoisted out of the loop. Names come from a single Toolhelp32
// snapshot; protected processes that are invisible to Toolhelp32 fall back
// to Utils::GetProcessName / ResolveUnknownProcessLocal.
// Aborts early if g_interrupted is set (e.g. Ctrl-C handler).
std::vector<ProcessEntry> Controller::GetProcessList() noexcept
{
    std::vector<ProcessEntry> processes;
    if (g_interrupted) {
        INFO(L"Process enumeration cancelled by user before start");
        return processes;
    }

    const auto initialProcess = GetInitialSystemProcessAddress();
    if (!initialProcess) return processes;

    // Hoist offset lookups — map finds are cheap but not free per iteration.
    const auto uniqueIdOffset    = m_of->GetOffset(Offset::ProcessUniqueProcessId);
    const auto linksOffset       = m_of->GetOffset(Offset::ProcessActiveProcessLinks);
    const auto sigLevelOffset    = m_of->GetOffset(Offset::ProcessSignatureLevel);
    const auto secSigLevelOffset = m_of->GetOffset(Offset::ProcessSectionSignatureLevel);

    if (!uniqueIdOffset || !linksOffset) return processes;

    const auto nameMap = BuildProcessNameMap();
    processes.reserve(512);

    ULONG_PTR current   = initialProcess.value();
    DWORD     processCount = 0;
    constexpr DWORD kMaxProcesses = 10'000;

    do {
        if (g_interrupted) break;

        const auto pidPtr    = m_rtc->ReadPtr(current + uniqueIdOffset.value());
        const auto protection = GetProcessProtection(current);

        if (g_interrupted) break;

        if (pidPtr && protection) {
            const ULONG_PTR pidValue = pidPtr.value();
            if (pidValue > 0 && pidValue <= MAXDWORD) {
                ProcessEntry entry{};
                entry.KernelAddress         = current;
                entry.Pid                   = static_cast<DWORD>(pidValue);
                entry.ProtectionLevel       = Utils::GetProtectionLevel(protection.value());
                entry.SignerType            = Utils::GetSignerType(protection.value());
                entry.SignatureLevel        = sigLevelOffset
                    ? m_rtc->Read8(current + sigLevelOffset.value()).value_or(0) : 0;
                entry.SectionSignatureLevel = secSigLevelOffset
                    ? m_rtc->Read8(current + secSigLevelOffset.value()).value_or(0) : 0;

                if (g_interrupted) break;

                if (const auto it = nameMap.find(entry.Pid); it != nameMap.end()) {
                    entry.ProcessName = it->second;
                } else {
                    // Protected processes (e.g. csrss.exe PPL-WinTcb) may be
                    // hidden from Toolhelp32 but accessible via a direct open.
                    std::wstring fallback = Utils::GetProcessName(entry.Pid);
                    entry.ProcessName = (fallback != L"[Unknown]")
                        ? fallback
                        : Utils::ResolveUnknownProcessLocal(
                              entry.Pid, entry.KernelAddress,
                              entry.ProtectionLevel, entry.SignerType);
                }

                processes.push_back(std::move(entry));
                ++processCount;
            }
        }

        if (g_interrupted) break;

        const auto nextPtr = m_rtc->ReadPtr(current + linksOffset.value());
        if (!nextPtr) break;
        current = nextPtr.value() - linksOffset.value();

    } while (current != initialProcess.value()
             && !g_interrupted
             && processCount < kMaxProcesses);

    return processes;
}

// Extends GetProcessList() with user-mode data (account name, integrity level).
// Used by the GUI which needs the extra columns.
std::vector<ProcessEntry> Controller::GetAllProcessList() noexcept
{
    auto processes = GetProcessList();
    for (auto& entry : processes) {
        if (g_interrupted) break;
        entry.UserName       = Utils::GetProcessUser(entry.Pid);
        entry.IntegrityLevel = Utils::GetProcessIntegrityLevel(entry.Pid);
    }
    return processes;
}

// ── Name resolution ──────────────────────────────────────────────────────────

// Returns all processes whose name matches pattern (case-insensitive,
// supports exact, substring, and wildcard '*' matching).
// Requires an active driver session because it calls GetProcessList().
std::vector<ProcessMatch> Controller::FindProcessesByName(
    const std::wstring& pattern) noexcept
{
    std::vector<ProcessMatch> matches;
    for (const auto& entry : GetProcessList()) {
        if (IsPatternMatch(entry.ProcessName, pattern))
            matches.push_back({entry.Pid, entry.ProcessName, entry.KernelAddress});
    }
    return matches;
}

// Same as FindProcessesByName but uses only the Toolhelp32 API —
// no driver needed. KernelAddress in the returned matches will be 0.
std::vector<ProcessMatch> Controller::FindProcessesByNameWithoutDriver(
    const std::wstring& pattern) noexcept
{
    std::vector<ProcessMatch> matches;
    SnapshotGuard snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot) return matches;

    PROCESSENTRY32W pe{sizeof(PROCESSENTRY32W)};
    if (Process32FirstW(snapshot.get(), &pe)) {
        do {
            if (IsPatternMatch(pe.szExeFile, pattern))
                matches.push_back({pe.th32ProcessID, pe.szExeFile, 0});
        } while (Process32NextW(snapshot.get(), &pe));
    }
    return matches;
}

// Resolves a name to exactly one match using the kernel driver.
// Fails if the name is ambiguous (multiple matches) or not found.
std::optional<ProcessMatch> Controller::ResolveProcessName(
    const std::wstring& processName) noexcept
{
    if (!BeginDriverSession()) return std::nullopt;
    const auto matches = FindProcessesByName(processName);
    EndDriverSession(/*force=*/true);

    if (matches.empty()) {
        ERROR(L"No process found matching pattern: %s", processName.c_str());
        return std::nullopt;
    }
    if (matches.size() == 1) {
        INFO(L"Found process: %s (PID %d)",
             matches[0].ProcessName.c_str(), matches[0].Pid);
        return matches[0];
    }

    ERROR(L"Multiple processes found matching pattern '%s'. "
          L"Please use a more specific name:", processName.c_str());
    for (const auto& m : matches)
        std::wcout << L"  PID " << m.Pid << L": " << m.ProcessName << L"\n";
    return std::nullopt;
}

// Same disambiguation logic as ResolveProcessName but uses Toolhelp32 only
// (no driver required). Useful for name→PID lookups before loading the driver.
std::optional<ProcessMatch> Controller::ResolveNameWithoutDriver(
    const std::wstring& processName) noexcept
{
    const auto matches = FindProcessesByNameWithoutDriver(processName);

    if (matches.empty()) {
        ERROR(L"No process found matching pattern: %s", processName.c_str());
        return std::nullopt;
    }
    if (matches.size() == 1) {
        INFO(L"Found process: %s (PID %d)",
             matches[0].ProcessName.c_str(), matches[0].Pid);
        return matches[0];
    }

    ERROR(L"Multiple processes found matching pattern '%s'. "
          L"Please use a more specific name:", processName.c_str());
    for (const auto& m : matches)
        std::wcout << L"  PID " << m.Pid << L": " << m.ProcessName << L"\n";
    return std::nullopt;
}

// ── Pattern matching ─────────────────────────────────────────────────────────

// Matches processName against pattern using, in order:
//   1. Case-insensitive exact match
//   2. Case-insensitive substring match
//   3. Wildcard '*' expansion to ECMAScript regex (case-insensitive)
// Returns false on regex compilation errors rather than throwing.
bool Controller::IsPatternMatch(const std::wstring& processName,
                                 const std::wstring& pattern) noexcept
{
    std::wstring lowerName    = processName;
    std::wstring lowerPattern = pattern;
    StringUtils::ToLower(lowerName);
    StringUtils::ToLower(lowerPattern);

    // Exact or substring match — fast path, no regex overhead.
    if (lowerName == lowerPattern ||
        lowerName.find(lowerPattern) != std::wstring::npos)
        return true;

    // Escape all regex metacharacters except '*', then expand '*' to '.*'.
    std::wstring regexPattern = lowerPattern;
    static constexpr std::wstring_view kSpecialChars = L"\\^$.+{}[]|()";
    for (wchar_t ch : kSpecialChars) {
        for (size_t pos = 0;
             (pos = regexPattern.find(ch, pos)) != std::wstring::npos; ) {
            regexPattern.insert(pos, 1, L'\\');
            pos += 2;
        }
    }
    for (size_t pos = 0;
         (pos = regexPattern.find(L'*', pos)) != std::wstring::npos; ) {
        if (pos == 0 || regexPattern[pos - 1] != L'\\') {
            regexPattern.replace(pos, 1, L".*");
            pos += 2;
        } else {
            ++pos;
        }
    }

    try {
        return std::regex_search(
            lowerName,
            std::wregex(regexPattern, std::regex_constants::icase));
    } catch (const std::regex_error&) {
        return false;
    }
}
