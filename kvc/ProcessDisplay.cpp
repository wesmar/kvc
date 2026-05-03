// ProcessDisplay.cpp
// Console rendering for process protection tables and detailed process info.
//
// TableFormat namespace: stateless formatting helpers that produce the
// colored ASCII table shown by the 'kvc list' and 'kvc list --signer' commands.
// All width constants are gathered in one place (TableFormat::Columns) so
// adjusting a column only requires changing a single constexpr.

#include "Controller.h"
#include "common.h"
#include "Utils.h"
#include <iomanip>

// ── Table formatter ──────────────────────────────────────────────────────────

namespace TableFormat {
    using namespace std::string_view_literals;

    struct Columns {
        static constexpr size_t PID         = 5;
        static constexpr size_t NAME        = 25;
        static constexpr size_t LEVEL       = 7;
        static constexpr size_t SIGNER      = 15;
        static constexpr size_t EXE_SIG     = 14;
        static constexpr size_t DLL_SIG     = 17;
        static constexpr size_t KERNEL_ADDR = 12;
    };

    inline constexpr std::wstring_view SEP  = L"-+-";
    inline constexpr std::wstring_view VBAR = L" | ";
    inline constexpr std::wstring_view NL   = L"\n";
    inline constexpr wchar_t DASH  = L'-';
    inline constexpr wchar_t SPACE = L' ';

    inline const std::wstring DIVIDER = [] {
        std::wostringstream ss;
        ss << SPACE;
        ss << std::wstring(Columns::PID,         DASH) << SEP;
        ss << std::wstring(Columns::NAME,        DASH) << SEP;
        ss << std::wstring(Columns::LEVEL,       DASH) << SEP;
        ss << std::wstring(Columns::SIGNER,      DASH) << SEP;
        ss << std::wstring(Columns::EXE_SIG,     DASH) << SEP;
        ss << std::wstring(Columns::DLL_SIG,     DASH) << SEP;
        ss << std::wstring(Columns::KERNEL_ADDR, DASH) << NL;
        return ss.str();
    }();

    inline void PrintDivider(const wchar_t* color = Utils::ProcessColors::GREEN)
    {
        std::wcout << color << DIVIDER << Utils::ProcessColors::RESET;
    }

    inline void PrintHeader()
    {
        std::wcout << SPACE << Utils::ProcessColors::HEADER;
        std::wcout << std::left << std::setw(Columns::PID)         << L"  PID"             << VBAR;
        std::wcout << std::left << std::setw(Columns::NAME)        << L"  Process Name"    << VBAR;
        std::wcout << std::left << std::setw(Columns::LEVEL)       << L" Level"            << VBAR;
        std::wcout << std::left << std::setw(Columns::SIGNER)      << L"    Signer"        << VBAR;
        std::wcout << std::left << std::setw(Columns::EXE_SIG)     << L"EXE sig. level"   << VBAR;
        std::wcout << std::left << std::setw(Columns::DLL_SIG)     << L" DLL sig. level"  << VBAR;
        std::wcout << std::left << std::setw(Columns::KERNEL_ADDR) << L"Kern. (ffff)";
        std::wcout << Utils::ProcessColors::RESET << NL;
    }

    inline void PrintTableStart()
    {
        std::wcout << NL;
        PrintDivider();
        PrintHeader();
        std::wcout << Utils::ProcessColors::GREEN << DIVIDER;
    }

    inline void PrintTableEnd() { PrintDivider(); }

    // Right-aligns val within totalWidth, left-padding with spaces after name.
    inline std::wstring FormatRightAligned(const std::wstring& name,
                                            const std::wstring& val,
                                            size_t totalWidth)
    {
        const size_t nameLen = name.length();
        const size_t valLen  = val.length();

        if (nameLen + valLen + 1 > totalWidth) {
            const size_t available = totalWidth - valLen - 1;
            return available > 0
                ? name.substr(0, available) + L" " + val
                : name.substr(0, totalWidth);
        }
        return name + std::wstring(totalWidth - nameLen - valLen, L' ') + val;
    }

    inline void PrintProcessRow(const ProcessEntry& entry)
    {
        const wchar_t* color = Utils::GetProcessDisplayColor(
            entry.SignerType, entry.SignatureLevel, entry.SectionSignatureLevel);

        const std::wstring levelStr  = Utils::GetProtectionLevelAsString(entry.ProtectionLevel);
        const std::wstring signerStr = Utils::GetSignerTypeAsString(entry.SignerType);
        const std::wstring exeStr    = Utils::GetSignatureLevelAsString(entry.SignatureLevel);
        const std::wstring dllStr    = Utils::GetSignatureLevelAsString(entry.SectionSignatureLevel);

        wchar_t buf[32];
        swprintf_s(buf, L"(%d)",   entry.ProtectionLevel);       std::wstring levelNum  = buf;
        swprintf_s(buf, L"(%d)",   entry.SignerType);             std::wstring signerNum = buf;
        swprintf_s(buf, L"(%02x)", entry.SignatureLevel);         std::wstring exeNum    = buf;
        swprintf_s(buf, L"(%02x)", entry.SectionSignatureLevel);  std::wstring dllNum    = buf;

        std::wstring procName = entry.ProcessName;
        if (procName.length() > Columns::NAME)
            procName = procName.substr(0, Columns::NAME - 3) + L"...";

        std::wcout << color << SPACE;
        std::wcout << std::right << std::setw(Columns::PID) << entry.Pid;
        std::wcout << Utils::ProcessColors::RESET << Utils::ProcessColors::GREEN << VBAR << color;

        std::wcout << std::left << std::setw(Columns::NAME) << procName;
        std::wcout << Utils::ProcessColors::RESET << Utils::ProcessColors::GREEN << VBAR << color;

        std::wcout << FormatRightAligned(levelStr,  levelNum,  Columns::LEVEL);
        std::wcout << Utils::ProcessColors::RESET << Utils::ProcessColors::GREEN << VBAR << color;

        std::wcout << FormatRightAligned(signerStr, signerNum, Columns::SIGNER);
        std::wcout << Utils::ProcessColors::RESET << Utils::ProcessColors::GREEN << VBAR << color;

        std::wcout << FormatRightAligned(exeStr,    exeNum,    Columns::EXE_SIG);
        std::wcout << Utils::ProcessColors::RESET << Utils::ProcessColors::GREEN << VBAR << color;

        std::wcout << FormatRightAligned(dllStr,    dllNum,    Columns::DLL_SIG);
        std::wcout << Utils::ProcessColors::RESET << Utils::ProcessColors::GREEN << VBAR << color;

        // Kernel address: strip the constant 0xFFFF prefix (x64 canonical).
        std::wcout << std::right << std::setw(Columns::KERNEL_ADDR)
                   << std::hex << (entry.KernelAddress & 0xFFFFFFFFFFFFULL) << std::dec;
        std::wcout << Utils::ProcessColors::RESET << NL;
    }
} // namespace TableFormat

// ── Controller::GetProcessProtection (display overload) ──────────────────────

// Retrieves and prints protection info for a PID.
bool Controller::GetProcessProtection(DWORD pid) noexcept
{
    if (!BeginDriverSession()) { EndDriverSession(true); return false; }

    const auto kernelAddr = GetProcessKernelAddress(pid);
    if (!kernelAddr) {
        ERROR(L"Failed to get kernel address for PID %d", pid);
        EndDriverSession(true);
        return false;
    }

    const auto currentProtection = GetProcessProtection(kernelAddr.value());
    if (!currentProtection) {
        ERROR(L"Failed to read protection for PID %d", pid);
        EndDriverSession(true);
        return false;
    }

    const UCHAR protLevel  = Utils::GetProtectionLevel(currentProtection.value());
    const UCHAR signerType = Utils::GetSignerType(currentProtection.value());

    const auto sigLevelOffset    = m_of->GetOffset(Offset::ProcessSignatureLevel);
    const auto secSigLevelOffset = m_of->GetOffset(Offset::ProcessSectionSignatureLevel);

    const UCHAR signatureLevel = sigLevelOffset
        ? m_rtc->Read8(kernelAddr.value() + sigLevelOffset.value()).value_or(0) : 0;
    const UCHAR sectionSignatureLevel = secSigLevelOffset
        ? m_rtc->Read8(kernelAddr.value() + secSigLevelOffset.value()).value_or(0) : 0;

    const std::wstring processName = Utils::GetProcessName(pid);

    Utils::EnableConsoleVirtualTerminal();

    if (protLevel == 0) {
        std::wcout << L"[*] PID " << pid << L" (" << processName
                   << L") is not protected\n";
    } else {
        const wchar_t* color = Utils::GetProcessDisplayColor(
            signerType, signatureLevel, sectionSignatureLevel);
        std::wcout << color
                   << L"[*] PID " << pid << L" (" << processName
                   << L") protection: "
                   << Utils::GetProtectionLevelAsString(protLevel) << L"-"
                   << Utils::GetSignerTypeAsString(signerType)
                   << L" (raw: 0x"
                   << std::hex << std::uppercase
                   << static_cast<int>(currentProtection.value())
                   << std::dec << L")\n"
                   << Utils::ProcessColors::RESET;
    }

    EndDriverSession(true);
    return true;
}

bool Controller::GetProcessProtectionByName(
    const std::wstring& processName) noexcept
{
    const auto match = ResolveNameWithoutDriver(processName);
    return match && GetProcessProtection(match->Pid);
}

// ── List commands ────────────────────────────────────────────────────────────

bool Controller::ListProtectedProcesses() noexcept
{
    if (!BeginDriverSession()) { EndDriverSession(true); return false; }

    const auto processes = GetProcessList();
    EndDriverSession(true);

    Utils::EnableConsoleVirtualTerminal();
    TableFormat::PrintTableStart();

    DWORD count = 0;
    for (const auto& entry : processes) {
        if (entry.ProtectionLevel > 0) {
            ++count;
            TableFormat::PrintProcessRow(entry);
        }
    }

    TableFormat::PrintTableEnd();

    if (count == 0) {
        std::wcout << L"No protected processes found.\n";
        return false;
    }

    std::wcout << L"\nTotal protected processes: " << count
               << L"    (Try 'kvc list --gui' for interactive GUI mode)\n";
    return true;
}

bool Controller::ListProcessesBySigner(const std::wstring& signerName) noexcept
{
    const auto signerType = Utils::GetSignerTypeFromString(signerName);
    if (!signerType) {
        ERROR(L"Invalid signer type: %s", signerName.c_str());
        return false;
    }

    if (!BeginDriverSession()) { EndDriverSession(true); return false; }
    const auto processes = GetProcessList();
    EndDriverSession(true);

    Utils::EnableConsoleVirtualTerminal();
    TableFormat::PrintTableStart();

    bool foundAny = false;
    for (const auto& entry : processes) {
        if (entry.SignerType == signerType.value()) {
            foundAny = true;
            TableFormat::PrintProcessRow(entry);
        }
    }

    if (!foundAny) {
        std::wcout << Utils::ProcessColors::RESET
                   << L"\nNo processes found with signer type: "
                   << signerName << L"\n";
        return false;
    }

    TableFormat::PrintTableEnd();
    return true;
}

// ── Detailed per-process information ────────────────────────────────────────

// Prints extended protection data and a dumpability analysis for a PID.
bool Controller::PrintProcessInfo(DWORD pid) noexcept
{
    if (!BeginDriverSession()) { EndDriverSession(true); return false; }

    const auto kernelAddr = GetProcessKernelAddress(pid);
    if (!kernelAddr) {
        ERROR(L"Failed to get kernel address for PID %d", pid);
        EndDriverSession(true);
        return false;
    }

    const auto currentProtection = GetProcessProtection(kernelAddr.value());
    if (!currentProtection) {
        ERROR(L"Failed to read protection for PID %d", pid);
        EndDriverSession(true);
        return false;
    }

    const UCHAR protLevel  = Utils::GetProtectionLevel(currentProtection.value());
    const UCHAR signerType = Utils::GetSignerType(currentProtection.value());

    const auto sigLevelOffset    = m_of->GetOffset(Offset::ProcessSignatureLevel);
    const auto secSigLevelOffset = m_of->GetOffset(Offset::ProcessSectionSignatureLevel);

    const UCHAR signatureLevel = sigLevelOffset
        ? m_rtc->Read8(kernelAddr.value() + sigLevelOffset.value()).value_or(0) : 0;
    const UCHAR sectionSignatureLevel = secSigLevelOffset
        ? m_rtc->Read8(kernelAddr.value() + secSigLevelOffset.value()).value_or(0) : 0;

    const std::wstring processName = Utils::GetProcessName(pid);
    Utils::EnableConsoleVirtualTerminal();

    std::wcout << L"\n[*] Detailed Process Information:\n";
    std::wcout << L"    PID: " << pid << L" (" << processName << L")\n";

    if (protLevel == 0) {
        std::wcout << L"    Protection: NOT PROTECTED\n";
    } else {
        const wchar_t* color = Utils::GetProcessDisplayColor(
            signerType, signatureLevel, sectionSignatureLevel);
        std::wcout << color
                   << L"    Protection: "
                   << Utils::GetProtectionLevelAsString(protLevel) << L"-"
                   << Utils::GetSignerTypeAsString(signerType)
                   << L" (raw: 0x"
                   << std::hex << std::uppercase
                   << static_cast<int>(currentProtection.value())
                   << std::dec << L")"
                   << Utils::ProcessColors::RESET << L"\n";
    }

    std::wcout << L"    Signature Level: "
               << Utils::GetSignatureLevelAsString(signatureLevel)
               << L" (0x" << std::hex << static_cast<int>(signatureLevel)
               << std::dec << L")\n";
    std::wcout << L"    Section Signature Level: "
               << Utils::GetSignatureLevelAsString(sectionSignatureLevel)
               << L" (0x" << std::hex << static_cast<int>(sectionSignatureLevel)
               << std::dec << L")\n";
    std::wcout << L"    Kernel Address: 0x"
               << std::hex << kernelAddr.value() << std::dec << L"\n";

    // Dumpability analysis.
    std::wcout << L"\n[*] Dumpability Analysis:\n";
    const auto dumpability =
        Utils::CanDumpProcess(pid, processName, protLevel, signerType);
    std::wcout << L"    CanDump=" << dumpability.CanDump
               << L", Reason=" << dumpability.Reason << L"\n";

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi{};
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    const WORD originalColor = csbi.wAttributes;

    if (dumpability.CanDump) {
        std::wcout << Utils::ProcessColors::GREEN
                   << L"    [+]  DUMPABLE: " << dumpability.Reason;
        SetConsoleTextAttribute(hConsole, originalColor);
        std::wcout << L"\n";
        if (protLevel > 0)
            std::wcout << L"    Note: Process is protected but can be dumped with elevation\n";
    } else {
        std::wcout << Utils::ProcessColors::RED
                   << L"    [-]  NOT DUMPABLE: " << dumpability.Reason;
        SetConsoleTextAttribute(hConsole, originalColor);
        std::wcout << L"\n";

        if (protLevel > 0)
            std::wcout << L"    Suggestion: Try elevating current process protection first\n";
        if (signerType == static_cast<UCHAR>(PS_PROTECTED_SIGNER::Antimalware))
            std::wcout << L"    Suggestion: Antimalware-protected processes require special handling\n";
        if (signerType == static_cast<UCHAR>(PS_PROTECTED_SIGNER::Lsa))
            std::wcout << L"    Suggestion: LSA-protected process requires PPL-Lsa or higher\n";
    }

    // Token elevation type.
    HandleGuard infoProcess(OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid));
    if (infoProcess) {
        TokenGuard token;
        if (OpenProcessToken(infoProcess.get(), TOKEN_QUERY, token.addressof())) {
            DWORD elevationType = 0, returnLength = 0;
            if (GetTokenInformation(token.get(), TokenElevationType,
                                    &elevationType, sizeof(elevationType),
                                    &returnLength))
            {
                std::wcout << L"\n[*] Process Context:\n";
                std::wcout << L"    Elevation Type: ";
                switch (elevationType) {
                case TokenElevationTypeDefault: std::wcout << L"Default\n";    break;
                case TokenElevationTypeFull:    std::wcout << L"Full (Admin)\n"; break;
                case TokenElevationTypeLimited: std::wcout << L"Limited\n";   break;
                default:                        std::wcout << L"Unknown\n";    break;
                }
            }
        }
    }

    SetConsoleTextAttribute(hConsole, originalColor);
    std::wcout << std::endl;
    EndDriverSession(true);
    return true;
}
