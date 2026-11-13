// SymbolEngine.cpp
// Symbol resolution with local PDB priority and automatic download fallback

#include "SymbolEngine.h"
#include <psapi.h>
#include <shlwapi.h>
#include <shlobj.h>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

// ============================================================================
// CONSTRUCTION / DESTRUCTION
// ============================================================================

SymbolEngine::SymbolEngine() 
    : m_symbolServer(L"https://msdl.microsoft.com/download/symbols")
{
}

SymbolEngine::~SymbolEngine() {
    if (m_initialized) {
        SymCleanup(GetCurrentProcess());
    }
}

// ============================================================================
// PUBLIC INTERFACE
// ============================================================================

std::optional<std::pair<DWORD64, DWORD64>> SymbolEngine::GetKernelSymbolOffsets() noexcept {
    DEBUG(L"[SymbolEngine] Getting kernel symbol offsets...");
    
    if (!Initialize()) {
        ERROR(L"[SymbolEngine] Failed to initialize");
        return std::nullopt;
    }
    
    auto kernelInfo = GetKernelInfo();
    if (!kernelInfo) {
        ERROR(L"[SymbolEngine] Failed to locate kernel");
        return std::nullopt;
    }
    
    return GetSymbolOffsets(kernelInfo->second);
}

std::optional<DWORD64> SymbolEngine::GetSymbolOffset(const std::wstring& modulePath, const std::wstring& symbolName) noexcept {
    DEBUG(L"[SymbolEngine] Resolving symbol '%s' for module: %s", symbolName.c_str(), modulePath.c_str());
    
    if (!Initialize()) {
        ERROR(L"[SymbolEngine] Failed to initialize");
        return std::nullopt;
    }

    // Extract PDB information from module binary
    auto pdbInfo = GetPdbInfoFromPe(modulePath);
    if (!pdbInfo) {
        ERROR(L"[SymbolEngine] Failed to extract PDB info from module: %s", modulePath.c_str());
        return std::nullopt;
    }
    
    auto [pdbName, guid] = *pdbInfo;
    DEBUG(L"[SymbolEngine] PDB: %s, GUID: %s", pdbName.c_str(), guid.c_str());
    
    // Build local PDB path
    std::wstring localPdbPath = GetLocalPdbPath(pdbName, guid);
    if (localPdbPath.empty()) {
        ERROR(L"[SymbolEngine] Failed to build local PDB path");
        return std::nullopt;
    }
    
    // Check if PDB exists locally, otherwise download
    if (!PathFileExistsW(localPdbPath.c_str())) {
        INFO(L"[SymbolEngine] Local PDB not found, downloading...");
        if (!DownloadPdbToDisk(pdbName, guid, localPdbPath)) {
            ERROR(L"[SymbolEngine] Failed to download PDB");
            return std::nullopt;
        }
    }
    
    return CalculateSymbolOffsetFromDisk(localPdbPath, pdbName, symbolName);
}

std::optional<DWORD64> SymbolEngine::CalculateSymbolOffsetFromDisk(
    const std::wstring& pdbPath,
    const std::wstring& pdbName,
    const std::wstring& symbolName) noexcept
{
    (void)pdbName;
    DEBUG(L"[SymbolEngine] Resolving symbol '%s' from PDB: %s", symbolName.c_str(), pdbPath.c_str());

    std::wstring pdbDir = pdbPath.substr(0, pdbPath.find_last_of(L"\\/"));
    
    if (m_initialized) {
        SymCleanup(GetCurrentProcess());
        m_initialized = false;
    }

    std::wstring symbolPath = L"SRV*" + pdbDir;
    DWORD options = SymGetOptions();
    SymSetOptions(options | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_CASE_INSENSITIVE);

    if (!SymInitializeW(GetCurrentProcess(), symbolPath.c_str(), FALSE)) {
        ERROR(L"[SymbolEngine] SymInitializeW failed: %d", GetLastError());
        return std::nullopt;
    }
    m_initialized = true;

    DWORD64 baseAddr = 0x140000000;
    DWORD64 loadedModule = SymLoadModuleExW(GetCurrentProcess(), nullptr,
        pdbPath.c_str(), nullptr, baseAddr, 0, nullptr, 0);

    if (loadedModule == 0) {
        ERROR(L"[SymbolEngine] SymLoadModuleExW failed: %d", GetLastError());
        return std::nullopt;
    }

    std::vector<BYTE> symBuffer(sizeof(SYMBOL_INFOW) + (MAX_SYM_NAME * sizeof(wchar_t)));
    PSYMBOL_INFOW pSymbol = reinterpret_cast<PSYMBOL_INFOW>(symBuffer.data());
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
    pSymbol->MaxNameLen = MAX_SYM_NAME;

    DWORD64 offset = 0;
    if (SymFromNameW(GetCurrentProcess(), symbolName.c_str(), pSymbol)) {
        offset = pSymbol->Address - baseAddr;
        SUCCESS(L"[SymbolEngine] Symbol '%s' resolved to RVA: 0x%llX", symbolName.c_str(), offset);
    } else {
        ERROR(L"[SymbolEngine] Symbol '%s' not found: %d", symbolName.c_str(), GetLastError());
    }

    SymUnloadModule64(GetCurrentProcess(), loadedModule);
    return (offset != 0) ? std::optional<DWORD64>(offset) : std::nullopt;
}

std::optional<std::pair<DWORD64, DWORD64>> SymbolEngine::GetSymbolOffsets(const std::wstring& kernelPath) noexcept {
    DEBUG(L"[SymbolEngine] Processing kernel: %s", kernelPath.c_str());
    
    // Extract PDB information from kernel binary
    auto pdbInfo = GetPdbInfoFromPe(kernelPath);
    if (!pdbInfo) {
        ERROR(L"[SymbolEngine] Failed to extract PDB info from kernel");
        return std::nullopt;
    }
    
    auto [pdbName, guid] = *pdbInfo;
    DEBUG(L"[SymbolEngine] PDB: %s, GUID: %s", pdbName.c_str(), guid.c_str());
    
    // Build local PDB path
    std::wstring localPdbPath = GetLocalPdbPath(pdbName, guid);
    if (localPdbPath.empty()) {
        ERROR(L"[SymbolEngine] Failed to build local PDB path");
        return std::nullopt;
    }
    
    // Check if PDB exists locally
    if (PathFileExistsW(localPdbPath.c_str())) {
        INFO(L"[SymbolEngine] Using local PDB: %s", localPdbPath.c_str());
        return CalculateOffsetsFromDisk(localPdbPath, pdbName);
    }
    
    // PDB not found locally - download directly to target location
    INFO(L"[SymbolEngine] Local PDB not found, downloading from Microsoft symbol server...");
    
    if (!DownloadPdbToDisk(pdbName, guid, localPdbPath)) {
        ERROR(L"[SymbolEngine] Failed to download PDB");
        return std::nullopt;
    }
    
    INFO(L"[SymbolEngine] PDB downloaded and saved: %s", localPdbPath.c_str());

    // Clean up stale GUID directories for this PDB (other kernel versions)
    PurgeStaleGuids(pdbName, guid);

    // Calculate offsets from newly downloaded PDB
    return CalculateOffsetsFromDisk(localPdbPath, pdbName);
}

// ============================================================================
// LOCAL PDB RESOLUTION
// ============================================================================

std::wstring SymbolEngine::GetLocalPdbPath(const std::wstring& pdbName, const std::wstring& guid) noexcept {
    // Get system drive dynamically (no hardcoded C:)
    wchar_t systemDrive[MAX_PATH];
    if (GetEnvironmentVariableW(L"SystemDrive", systemDrive, MAX_PATH) == 0) {
        DEBUG(L"[SymbolEngine] Failed to get SystemDrive, using C: as fallback");
        wcscpy_s(systemDrive, L"C:");
    }
    
    // Build path: %SystemDrive%\ProgramData\dbg\sym\{pdbName}\{GUID}\{pdbName}
    std::wstring basePath = std::wstring(systemDrive) + L"\\ProgramData\\dbg\\sym\\" + 
                            pdbName + L"\\" + guid + L"\\" + pdbName;
    
    DEBUG(L"[SymbolEngine] PDB path: %s", basePath.c_str());
    return basePath;
}

// ============================================================================
// STALE PDB CLEANUP
// ============================================================================

void SymbolEngine::PurgeStaleGuids(const std::wstring& pdbName, const std::wstring& currentGuid) noexcept {
    // Derive base dir from GetLocalPdbPath: strip last two components (guid\pdbName)
    std::wstring samplePath = GetLocalPdbPath(pdbName, currentGuid);
    // samplePath = ...dbg\sym\ntoskrnl.pdb\{GUID}\ntoskrnl.pdb
    auto pos1 = samplePath.find_last_of(L"\\/");                        // strip \ntoskrnl.pdb
    if (pos1 == std::wstring::npos) return;
    auto pos2 = samplePath.find_last_of(L"\\/", pos1 - 1);             // strip \{GUID}
    if (pos2 == std::wstring::npos) return;
    std::wstring baseDir = samplePath.substr(0, pos2);                  // ...dbg\sym\ntoskrnl.pdb

    WIN32_FIND_DATAW fd{};
    std::wstring pattern = baseDir + L"\\*";
    HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    DWORD removed = 0;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (fd.cFileName[0] == L'.') continue;                          // skip . and ..
        if (_wcsicmp(fd.cFileName, currentGuid.c_str()) == 0) continue; // keep current

        std::wstring staleDir = baseDir + L"\\" + fd.cFileName;
        // RemoveDirectoryW only removes empty dirs — use recursive SHFileOperation-free delete
        std::wstring doubleNull = staleDir + L'\0';                     // SHFileOperation needs \0\0
        SHFILEOPSTRUCTW op{};
        op.wFunc  = FO_DELETE;
        op.pFrom  = doubleNull.c_str();
        op.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
        if (SHFileOperationW(&op) == 0 && !op.fAnyOperationsAborted) {
            INFO(L"[SymbolEngine] Removed stale PDB: %s", staleDir.c_str());
            removed++;
        } else {
            DEBUG(L"[SymbolEngine] Failed to remove stale PDB: %s", staleDir.c_str());
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);

    if (removed > 0) {
        INFO(L"[SymbolEngine] Purged %lu stale PDB GUID(s) for %s", removed, pdbName.c_str());
    }
}

// ============================================================================
// INITIALIZATION
// ============================================================================

bool SymbolEngine::Initialize() noexcept {
    if (m_initialized) return true;
    
    DWORD options = SymGetOptions();
    SymSetOptions(options | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | 
                  SYMOPT_DEBUG | SYMOPT_CASE_INSENSITIVE);
    
    if (!SymInitializeW(GetCurrentProcess(), nullptr, FALSE)) {
        ERROR(L"[SymbolEngine] SymInitializeW failed: %d", GetLastError());
        return false;
    }
    
    m_initialized = true;
    DEBUG(L"[SymbolEngine] Initialized");
    return true;
}

// ============================================================================
// KERNEL INFORMATION
// ============================================================================

std::optional<std::pair<DWORD64, std::wstring>> SymbolEngine::GetKernelInfo() noexcept {
    LPVOID drivers[1024];
    DWORD needed;
    
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) {
        ERROR(L"[SymbolEngine] Failed to enumerate device drivers: %d", GetLastError());
        return std::nullopt;
    }
    
    DWORD64 kernelBase = reinterpret_cast<DWORD64>(drivers[0]);
    
    wchar_t kernelPath[MAX_PATH];
    if (!GetDeviceDriverFileNameW(drivers[0], kernelPath, MAX_PATH)) {
        ERROR(L"[SymbolEngine] Failed to get kernel path: %d", GetLastError());
        return std::nullopt;
    }
    
    std::wstring ntPath = kernelPath;
    std::wstring dosPath;
    
    if (ntPath.find(L"\\SystemRoot\\") == 0) {
        wchar_t winDir[MAX_PATH];
        GetWindowsDirectoryW(winDir, MAX_PATH);
        dosPath = std::wstring(winDir) + ntPath.substr(11);
    } else if (ntPath.find(L"\\??\\") == 0) {
        dosPath = ntPath.substr(4);
    } else {
        dosPath = ntPath;
    }
    
    DEBUG(L"[SymbolEngine] Kernel base: 0x%llX, path: %s", kernelBase, dosPath.c_str());
    return std::make_pair(kernelBase, dosPath);
}

// ============================================================================
// PDB INFO EXTRACTION
// ============================================================================

std::optional<std::pair<std::wstring, std::wstring>> SymbolEngine::GetPdbInfoFromPe(const std::wstring& pePath) noexcept {
    HANDLE hFile = CreateFileW(pePath.c_str(), GENERIC_READ, FILE_SHARE_READ, 
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        ERROR(L"[SymbolEngine] Failed to open PE file: %s (error: %d)", pePath.c_str(), GetLastError());
        return std::nullopt;
    }
    
    HANDLE hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMapping) {
        ERROR(L"[SymbolEngine] Failed to create file mapping for PE (error: %d)", GetLastError());
        CloseHandle(hFile);
        return std::nullopt;
    }
    
    LPVOID pBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pBase) {
        ERROR(L"[SymbolEngine] Failed to map view of file (error: %d)", GetLastError());
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return std::nullopt;
    }
    
    std::wstring pdbName, guidStr;
    PIMAGE_DOS_HEADER pDos = static_cast<PIMAGE_DOS_HEADER>(pBase);
    
    if (pDos->e_magic == IMAGE_DOS_SIGNATURE) {
        PIMAGE_NT_HEADERS pNt = reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<BYTE*>(pBase) + pDos->e_lfanew);
        
        if (pNt->Signature == IMAGE_NT_SIGNATURE) {
            DWORD debugDirRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
            DWORD debugDirSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
            
            if (debugDirRva && debugDirSize) {
                // Convert RVA to file offset properly since we mapped the file flat, not as SEC_IMAGE
                PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
                PIMAGE_DEBUG_DIRECTORY pDebugDir = reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>(
                    ImageRvaToVa(pNt, pBase, debugDirRva, &pSection));
                
                if (pDebugDir) {
                    for (DWORD i = 0; i < debugDirSize / sizeof(IMAGE_DEBUG_DIRECTORY); i++) {
                        if (pDebugDir[i].Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
                            struct CV_INFO_PDB70 {
                                DWORD CvSignature;
                                GUID Signature;
                                DWORD Age;
                                char PdbFileName[1];
                            };
                            
                            // PointerToRawData is already a raw file offset
                            CV_INFO_PDB70* pCv = reinterpret_cast<CV_INFO_PDB70*>(
                                reinterpret_cast<BYTE*>(pBase) + pDebugDir[i].PointerToRawData);
                            
                            if (pCv->CvSignature == 0x53445352) {
                                wchar_t guidBuf[64];
                                swprintf_s(guidBuf, L"%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%X",
                                    pCv->Signature.Data1, pCv->Signature.Data2, pCv->Signature.Data3,
                                    pCv->Signature.Data4[0], pCv->Signature.Data4[1],
                                    pCv->Signature.Data4[2], pCv->Signature.Data4[3],
                                    pCv->Signature.Data4[4], pCv->Signature.Data4[5],
                                    pCv->Signature.Data4[6], pCv->Signature.Data4[7],
                                    pCv->Age);
                                guidStr = guidBuf;
                                
                                int len = MultiByteToWideChar(CP_UTF8, 0, pCv->PdbFileName, -1, nullptr, 0);
                                if (len > 0) {
                                    std::vector<wchar_t> wbuf(len);
                                    MultiByteToWideChar(CP_UTF8, 0, pCv->PdbFileName, -1, wbuf.data(), len);
                                    
                                    std::wstring fullPath = wbuf.data();
                                    size_t lastSlash = fullPath.find_last_of(L"\\/");
                                    pdbName = (lastSlash != std::wstring::npos) 
                                        ? fullPath.substr(lastSlash + 1) 
                                        : fullPath;
                                }
                                break;
                            }
                        }
                    }
                } else {
                    ERROR(L"[SymbolEngine] ImageRvaToVa failed to resolve Debug Directory RVA");
                }
            } else {
                ERROR(L"[SymbolEngine] No debug directory found in PE headers");
            }
        } else {
            ERROR(L"[SymbolEngine] Invalid NT signature");
        }
    } else {
        ERROR(L"[SymbolEngine] Invalid DOS signature");
    }
    
    UnmapViewOfFile(pBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    
    if (pdbName.empty() || guidStr.empty()) {
        ERROR(L"[SymbolEngine] Failed to extract PDB info (Name or GUID is empty)");
        return std::nullopt;
    }
    
    return std::make_pair(pdbName, guidStr);
}

// ============================================================================
// PDB DOWNLOAD - DIRECTLY TO TARGET LOCATION
// ============================================================================

bool SymbolEngine::DownloadPdbToDisk(const std::wstring& pdbName, 
                                      const std::wstring& guid,
                                      const std::wstring& targetPath) noexcept {
    // Create directory structure
    std::wstring dirPath = targetPath.substr(0, targetPath.find_last_of(L"\\/"));
    if (!CreateDirectoryTree(dirPath)) {
        ERROR(L"[SymbolEngine] Failed to create directory: %s", dirPath.c_str());
        return false;
    }
    
    // Build download URL
    std::wstring url = m_symbolServer + L"/" + pdbName + L"/" + guid + L"/" + pdbName;
    DEBUG(L"[SymbolEngine] Downloading from: %s", url.c_str());
    DEBUG(L"[SymbolEngine] Target path: %s", targetPath.c_str());
    
    // Download directly to file
    std::vector<BYTE> data;
    if (!HttpDownload(url, data)) {
        ERROR(L"[SymbolEngine] HTTP download failed");
        return false;
    }
    
    DEBUG(L"[SymbolEngine] Downloaded %zu bytes", data.size());
    
    // Write to target file
    HANDLE hFile = CreateFileW(targetPath.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        ERROR(L"[SymbolEngine] Failed to create file: %s (error: %d)", 
              targetPath.c_str(), GetLastError());
        return false;
    }
    
    DWORD bytesWritten = 0;
    BOOL writeSuccess = WriteFile(hFile, data.data(), static_cast<DWORD>(data.size()), 
                                   &bytesWritten, nullptr);
    CloseHandle(hFile);
    
    if (!writeSuccess || bytesWritten != data.size()) {
        ERROR(L"[SymbolEngine] Failed to write PDB file");
        DeleteFileW(targetPath.c_str());
        return false;
    }
    
    SUCCESS(L"[SymbolEngine] PDB saved: %s (%d bytes)", targetPath.c_str(), bytesWritten);
    return true;
}

bool SymbolEngine::CreateDirectoryTree(const std::wstring& path) noexcept {
    if (PathIsDirectoryW(path.c_str())) {
        return true;
    }
    
    // Find parent directory
    size_t pos = path.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        std::wstring parent = path.substr(0, pos);
        if (!CreateDirectoryTree(parent)) {
            return false;
        }
    }
    
    // Create this directory
    if (!CreateDirectoryW(path.c_str(), nullptr)) {
        DWORD err = GetLastError();
        if (err != ERROR_ALREADY_EXISTS) {
            DEBUG(L"[SymbolEngine] CreateDirectory failed: %s (error: %d)", path.c_str(), err);
            return false;
        }
    }
    
    return true;
}

bool SymbolEngine::HttpDownload(const std::wstring& url, std::vector<BYTE>& output) noexcept {
    URL_COMPONENTSW urlParts = { sizeof(urlParts) };
    wchar_t host[256] = { 0 };
    wchar_t path[1024] = { 0 };

    urlParts.lpszHostName = host;
    urlParts.dwHostNameLength = _countof(host);
    urlParts.lpszUrlPath = path;
    urlParts.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &urlParts)) {
        DEBUG(L"[SymbolEngine] WinHttpCrackUrl failed: %d", GetLastError());
        return false;
    }

    HINTERNET hSession = WinHttpOpen(L"SymbolEngine/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

    if (!hSession) {
        DEBUG(L"[SymbolEngine] WinHttpOpen failed: %d", GetLastError());
        return false;
    }

    WinHttpSetTimeouts(hSession, 10000, 10000, 30000, 30000);

    HINTERNET hConnect = WinHttpConnect(hSession, urlParts.lpszHostName, urlParts.nPort, 0);
    if (!hConnect) {
        DEBUG(L"[SymbolEngine] WinHttpConnect failed: %d", GetLastError());
        WinHttpCloseHandle(hSession);
        return false;
    }

    DWORD flags = (urlParts.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", urlParts.lpszUrlPath,
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);

    if (!hRequest) {
        DEBUG(L"[SymbolEngine] WinHttpOpenRequest failed: %d", GetLastError());
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        DEBUG(L"[SymbolEngine] WinHttpSendRequest failed: %d", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        DEBUG(L"[SymbolEngine] WinHttpReceiveResponse failed: %d", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    DWORD statusCode = 0;
    DWORD size = sizeof(statusCode);
    if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &size, WINHTTP_NO_HEADER_INDEX)) {
        DEBUG(L"[SymbolEngine] WinHttpQueryHeaders failed: %d", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    if (statusCode != 200) {
        DEBUG(L"[SymbolEngine] HTTP error: %d", statusCode);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    output.clear();
    BYTE buffer[8192];
    DWORD bytesRead = 0;

    while (WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        const size_t oldSize = output.size();
        output.resize(oldSize + bytesRead);
        memcpy(&output[oldSize], buffer, bytesRead);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    if (output.empty()) {
        DEBUG(L"[SymbolEngine] No data received");
        return false;
    }

    return true;
}

// ============================================================================
// OFFSET CALCULATION FROM LOCAL PDB
// ============================================================================

std::optional<std::pair<DWORD64, DWORD64>> SymbolEngine::CalculateOffsetsFromDisk(
    const std::wstring& pdbPath,
    const std::wstring& pdbName) noexcept
{
    (void)pdbName;
    DEBUG(L"[SymbolEngine] Calculating offsets from PDB: %s", pdbPath.c_str());

    // Extract directory from full path
    std::wstring pdbDir = pdbPath.substr(0, pdbPath.find_last_of(L"\\/"));
    
    // Re-initialize DbgHelp with PDB directory
    if (m_initialized) {
        SymCleanup(GetCurrentProcess());
        m_initialized = false;
    }

    std::wstring symbolPath = L"SRV*" + pdbDir;
    
    DWORD options = SymGetOptions();
    SymSetOptions(options | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | 
                  SYMOPT_DEBUG | SYMOPT_CASE_INSENSITIVE | SYMOPT_LOAD_LINES);

    if (!SymInitializeW(GetCurrentProcess(), symbolPath.c_str(), FALSE)) {
        ERROR(L"[SymbolEngine] SymInitializeW failed: %d", GetLastError());
        return std::nullopt;
    }
    m_initialized = true;

    // Load module
    DWORD64 baseAddr = 0x140000000;
    DWORD64 loadedModule = SymLoadModuleExW(GetCurrentProcess(), nullptr,
        pdbPath.c_str(), nullptr, baseAddr, 0, nullptr, 0);

    if (loadedModule == 0) {
        ERROR(L"[SymbolEngine] SymLoadModuleExW failed: %d", GetLastError());
        SymCleanup(GetCurrentProcess());
        m_initialized = false;
        return std::nullopt;
    }

    DEBUG(L"[SymbolEngine] Module loaded at: 0x%llX", loadedModule);

    // Resolve symbols
    std::vector<BYTE> symBuffer(sizeof(SYMBOL_INFOW) + (MAX_SYM_NAME * sizeof(wchar_t)));
    PSYMBOL_INFOW pSymbol = reinterpret_cast<PSYMBOL_INFOW>(symBuffer.data());
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
    pSymbol->MaxNameLen = MAX_SYM_NAME;

    DWORD64 offSeCi = 0;
    DWORD64 offZwFlush = 0;

    if (SymFromNameW(GetCurrentProcess(), L"SeCiCallbacks", pSymbol)) {
        offSeCi = pSymbol->Address - baseAddr;
        DEBUG(L"[SymbolEngine] SeCiCallbacks RVA: 0x%llX", offSeCi);
    } else {
        DEBUG(L"[SymbolEngine] SeCiCallbacks not found: %d", GetLastError());
    }

    if (SymFromNameW(GetCurrentProcess(), L"ZwFlushInstructionCache", pSymbol)) {
        offZwFlush = pSymbol->Address - baseAddr;
        DEBUG(L"[SymbolEngine] ZwFlushInstructionCache RVA: 0x%llX", offZwFlush);
    } else {
        DEBUG(L"[SymbolEngine] ZwFlushInstructionCache not found: %d", GetLastError());
    }

    // Cleanup DbgHelp
    SymUnloadModule64(GetCurrentProcess(), loadedModule);
    SymCleanup(GetCurrentProcess());
    m_initialized = false;

    // Validate
    if (offSeCi == 0 || offZwFlush == 0) {
        ERROR(L"[SymbolEngine] Failed to resolve symbols: SeCi=0x%llX, ZwFlush=0x%llX", 
              offSeCi, offZwFlush);
        return std::nullopt;
    }

    SUCCESS(L"[SymbolEngine] Symbol resolution successful");
    DEBUG(L"[SymbolEngine] Offsets - SeCi: 0x%llX, ZwFlush: 0x%llX", offSeCi, offZwFlush);
    
    return std::make_pair(offSeCi, offZwFlush);
}

BOOL CALLBACK SymbolEngine::SymbolCallback(HANDLE, ULONG, ULONG64, ULONG64) {
    return TRUE;
}

// ============================================================================
// HEURISTIC SCANNER (SeCiFinder-style fallback when PDB is unavailable)
// ============================================================================
// Implements Fast -> Structural -> Legacy cascade, matching SeCiFinder.cpp logic.
// ZwFlushInstructionCache is resolved from the export table (always available).

namespace {

template<typename T> static T Min(T a, T b) { return a < b ? a : b; }

struct ScnInfo {
    DWORD va, vs, rawPtr, rawSize, chars;
};

struct PeCtx {
    const BYTE* base;
    DWORD       size;
    DWORD       imageBase;  // unused for offsets but kept for clarity
    ScnInfo     sections[32];
    DWORD       sectionCount;
    // Exception directory (.pdata)
    DWORD       exceptionDirVa, exceptionDirSize;
};

static DWORD RvaToOffset(const PeCtx& ctx, DWORD rva) {
    for (DWORD i = 0; i < ctx.sectionCount; i++) {
        DWORD vs = ctx.sections[i].vs ? ctx.sections[i].vs : ctx.sections[i].rawSize;
        if (rva >= ctx.sections[i].va && rva < ctx.sections[i].va + vs)
            return ctx.sections[i].rawPtr + (rva - ctx.sections[i].va);
    }
    return 0;
}

static bool OffsetToRva(const PeCtx& ctx, DWORD off, DWORD& rva, int& secIdx) {
    for (DWORD i = 0; i < ctx.sectionCount; i++) {
        if (off >= ctx.sections[i].rawPtr && off < ctx.sections[i].rawPtr + ctx.sections[i].rawSize) {
            rva = ctx.sections[i].va + (off - ctx.sections[i].rawPtr);
            secIdx = (int)i;
            return true;
        }
    }
    return false;
}

static int SecIdxForRva(const PeCtx& ctx, DWORD rva) {
    for (DWORD i = 0; i < ctx.sectionCount; i++) {
        DWORD vs = ctx.sections[i].vs ? ctx.sections[i].vs : ctx.sections[i].rawSize;
        if (rva >= ctx.sections[i].va && rva < ctx.sections[i].va + vs) return (int)i;
    }
    return -1;
}

static bool IsWritableData(const PeCtx& ctx, int secIdx) {
    if (secIdx < 0 || (DWORD)secIdx >= ctx.sectionCount) return false;
    return (ctx.sections[secIdx].chars & 0x80000000) && !(ctx.sections[secIdx].chars & 0x20000000);
}

static bool IsRipLea(const PeCtx& ctx, DWORD off) {
    if (off + 7 > ctx.size) return false;
    const BYTE* p = ctx.base + off;
    return ((p[0] & 0xF8) == 0x48) && p[1] == 0x8D && ((p[2] & 0xC7) == 0x05);
}

struct Store {
    DWORD off, rva, len, imm32, targetRva;
    int   targetSec;
    bool  isQword;
};

static bool ReadStore(const PeCtx& ctx, DWORD off, Store& s) {
    if (off + 10 > ctx.size) return false;
    const BYTE* p = ctx.base + off;
    DWORD dispOff, len;
    bool isQ = false;
    if (off + 11 <= ctx.size && p[0] == 0x48 && p[1] == 0xC7 && p[2] == 0x05) {
        dispOff = 3; len = 11; isQ = true;
    } else if (p[0] == 0xC7 && p[1] == 0x05) {
        dispOff = 2; len = 10;
    } else return false;

    DWORD rva; int sec;
    if (!OffsetToRva(ctx, off, rva, sec)) return false;

    LONG rel32 = *(const LONG*)(p + dispOff);
    s.off       = off;
    s.rva       = rva;
    s.len       = len;
    s.imm32     = *(const DWORD*)(p + dispOff + 4);
    s.targetRva = (DWORD)((LONGLONG)rva + len + rel32);
    s.targetSec = SecIdxForRva(ctx, s.targetRva);
    s.isQword   = isQ;
    return true;
}

// Returns pair: qword_gap, Store. gap==0 means not found.
static bool FindQwordAfter(const PeCtx& ctx, DWORD startOff, DWORD endOff, DWORD& gap, Store& qs) {
    DWORD maxEnd = Min(endOff, startOff + 0x20);
    for (DWORD o = startOff + 1; o < maxEnd; o++) {
        Store s;
        if (!ReadStore(ctx, o, s)) continue;
        if (!s.isQword || !IsWritableData(ctx, s.targetSec)) continue;
        gap = o - startOff;
        qs = s;
        return true;
    }
    return false;
}

static bool FindRtfBounds(const PeCtx& ctx, DWORD rva, DWORD& beginOff, DWORD& endOff) {
    if (ctx.exceptionDirVa == 0 || ctx.exceptionDirSize < 12) return false;
    DWORD dirOff = RvaToOffset(ctx, ctx.exceptionDirVa);
    if (dirOff == 0 || dirOff >= ctx.size) return false;
    DWORD entries = Min(ctx.exceptionDirSize / 12, (ctx.size - dirOff) / 12);
    for (DWORD i = 0; i < entries; i++) {
        const BYTE* e = ctx.base + dirOff + i * 12;
        DWORD bRva = *(DWORD*)(e), eRva = *(DWORD*)(e + 4);
        if (bRva == 0 || eRva <= bRva || !(bRva <= rva && rva < eRva)) continue;
        DWORD bOff = RvaToOffset(ctx, bRva);
        DWORD eOff = RvaToOffset(ctx, eRva - 1);
        if (!bOff || !eOff) continue;
        beginOff = bOff;
        endOff   = eOff + 1;
        return true;
    }
    return false;
}

// ScoreZeroingWindow: count zeroing indicators near LEA
static int ScoreZero(const PeCtx& ctx, DWORD leaOff, DWORD& zeroSize, bool& hasSize) {
    int score = 0;
    zeroSize = 0; hasSize = false;
    DWORD end = Min((DWORD)ctx.size, leaOff + 96);
    const BYTE* start = ctx.base + leaOff;
    const BYTE* p;
    const BYTE* e = ctx.base + end;

    bool zeroFound = false, callFound = false;
    for (p = start; p + 2 <= e; p++) {
        if ((p[0] == 0x33 && p[1] == 0xD2) || (p[0] == 0x31 && p[1] == 0xD2) ||
            (p + 3 <= e && p[0] == 0x48 && p[1] == 0x33 && p[2] == 0xD2)) {
            zeroFound = true; break;
        }
    }
    for (p = start; p + 6 <= e && !hasSize; p++) {
        if (p[0] == 0x41 && p[1] == 0xB8) {
            DWORD imm = *(DWORD*)(p+2);
            if (imm >= 0x40 && imm <= 0x400) { zeroSize = imm; hasSize = true; }
        }
        if (p + 7 <= e && p[0] == 0x49 && p[1] == 0xC7 && p[2] == 0xC0) {
            DWORD imm = *(DWORD*)(p+3);
            if (imm >= 0x40 && imm <= 0x400) { zeroSize = imm; hasSize = true; }
        }
    }
    for (p = start; p + 5 <= e; p++) {
        if (p[0] == 0xE8) { callFound = true; break; }
    }
    if (zeroFound)  score++;
    if (hasSize)    score++;
    if (callFound)  score++;
    return score;
}

// Count unique MOV targets hitting [seciRva, seciRva+0x28)
static int CountMovHits(const PeCtx& ctx, DWORD matchOff, DWORD seciRva, DWORD radius) {
    DWORD start = matchOff > radius ? matchOff - radius : 0;
    DWORD end   = Min((DWORD)ctx.size, matchOff + radius);
    DWORD seciEnd = seciRva + 0x28;
    DWORD targets[64]; int cnt = 0;
    for (DWORD i = start; i + 6 < end; ) {
        Store s;
        if (i + 11 <= end && ctx.base[i] == 0x48 && ctx.base[i+1] == 0xC7 && ctx.base[i+2] == 0x05) {
            if (ReadStore(ctx, i, s) && seciRva <= s.targetRva && s.targetRva < seciEnd) {
                bool found = false;
                for (int k = 0; k < cnt; k++) if (targets[k] == s.targetRva) { found = true; break; }
                if (!found && cnt < 64) targets[cnt++] = s.targetRva;
            }
            i += 11; continue;
        }
        if (ctx.base[i] == 0xC7 && ctx.base[i+1] == 0x05) {
            if (ReadStore(ctx, i, s) && seciRva <= s.targetRva && s.targetRva < seciEnd) {
                bool found = false;
                for (int k = 0; k < cnt; k++) if (targets[k] == s.targetRva) { found = true; break; }
                if (!found && cnt < 64) targets[cnt++] = s.targetRva;
            }
            i += 10; continue;
        }
        i++;
    }
    return cnt;
}

static DWORD FindExportRva(const PeCtx& ctx, const char* name) {
    // Export directory is DataDirectory[0]
    // Locate from NT headers
    const BYTE* dos = ctx.base;
    if (ctx.size < 0x40 || dos[0] != 'M' || dos[1] != 'Z') return 0;
    DWORD e_lfanew = *(DWORD*)(dos + 0x3C);
    if (e_lfanew + 0x18 + 8 > ctx.size) return 0;
    const BYTE* nth = dos + e_lfanew;
    if (*(DWORD*)nth != 0x00004550) return 0;
    // Optional header starts at nth+24, DataDirectory[0] is at +24+16 = +40 from optional header start
    DWORD optHdrOff = e_lfanew + 24;
    if (optHdrOff + 8 > ctx.size) return 0;
    USHORT magic = *(USHORT*)(dos + optHdrOff);
    DWORD expDirOff = (magic == 0x020B) ? optHdrOff + 112 : optHdrOff + 96;
    if (expDirOff + 8 > ctx.size) return 0;
    DWORD expVa = *(DWORD*)(dos + expDirOff);
    if (expVa == 0) return 0;
    DWORD expOff = RvaToOffset(ctx, expVa);
    if (!expOff || expOff + 40 > ctx.size) return 0;
    const BYTE* exp = dos + expOff;
    DWORD count    = *(DWORD*)(exp + 24);
    DWORD funcVa   = *(DWORD*)(exp + 28);
    DWORD nameVa   = *(DWORD*)(exp + 32);
    DWORD ordVa    = *(DWORD*)(exp + 36);
    DWORD funcOff  = RvaToOffset(ctx, funcVa);
    DWORD nameOff  = RvaToOffset(ctx, nameVa);
    DWORD ordOff   = RvaToOffset(ctx, ordVa);
    if (!funcOff || !nameOff || !ordOff) return 0;
    for (DWORD i = 0; i < count; i++) {
        DWORD nOff = RvaToOffset(ctx, *(DWORD*)(dos + nameOff + i*4));
        if (!nOff || nOff >= ctx.size) continue;
        const char* fn = (const char*)(dos + nOff);
        DWORD j = 0;
        while (name[j] && fn[j] == name[j]) j++;
        if (!name[j] && !fn[j]) {
            WORD ord = *(WORD*)(dos + ordOff + i*2);
            return *(DWORD*)(dos + funcOff + ord*4);
        }
    }
    return 0;
}

static bool ParsePeCtx(PeCtx& ctx) {
    const BYTE* dos = ctx.base;
    if (ctx.size < 0x40 || dos[0] != 'M' || dos[1] != 'Z') return false;
    DWORD e_lfanew = *(DWORD*)(dos + 0x3C);
    if (e_lfanew + sizeof(DWORD) + 20 > ctx.size) return false;
    const BYTE* nth = dos + e_lfanew;
    if (*(DWORD*)nth != 0x00004550) return false;
    WORD numSec = *(WORD*)(nth + 6);
    WORD optLen = *(WORD*)(nth + 20);
    if (numSec > 32) numSec = 32;
    ctx.sectionCount = numSec;

    // Exception directory
    DWORD optOff = e_lfanew + 24;
    USHORT magic = *(USHORT*)(dos + optOff);
    DWORD excDirOff = (magic == 0x020B) ? optOff + 120 : optOff + 104;
    if (excDirOff + 8 <= ctx.size) {
        ctx.exceptionDirVa   = *(DWORD*)(dos + excDirOff);
        ctx.exceptionDirSize = *(DWORD*)(dos + excDirOff + 4);
    }

    const BYTE* secTbl = nth + 4 + 20 + optLen;
    if ((DWORD)(secTbl - dos) + numSec * 40 > ctx.size) return false;
    for (WORD i = 0; i < numSec; i++) {
        const BYTE* s = secTbl + i * 40;
        ctx.sections[i].vs      = *(DWORD*)(s + 8);
        ctx.sections[i].va      = *(DWORD*)(s + 12);
        ctx.sections[i].rawSize = *(DWORD*)(s + 16);
        ctx.sections[i].rawPtr  = *(DWORD*)(s + 20);
        ctx.sections[i].chars   = *(DWORD*)(s + 36);
    }
    return true;
}

// Fast method (same as kvc_smss, score threshold 110)
static DWORD FastFindSeCi(const PeCtx& ctx) {
    LONG bestScore = -1;
    DWORD bestRva = 0;
    const DWORD FAST_MIN_SCORE = 110;
    const DWORD STRUCT_OFFSET = 4;
    const DWORD LEA_LEN = 7;

    for (DWORD i = 0; i < ctx.sectionCount; i++) {
        if (!(ctx.sections[i].chars & 0x20000000)) continue;
        DWORD secStart = ctx.sections[i].rawPtr;
        DWORD secEnd   = secStart + ctx.sections[i].rawSize;
        if (secEnd > ctx.size) secEnd = ctx.size;

        for (DWORD fo = secStart; fo + 10 <= secEnd; fo++) {
            if (ctx.base[fo] != 0xC7 || ctx.base[fo+1] != 0x05) continue;
            if (fo > 0 && ctx.base[fo-1] == 0x48) continue;

            Store st;
            if (!ReadStore(ctx, fo, st) || st.isQword || !IsWritableData(ctx, st.targetSec)) continue;
            if (!(st.imm32 >= 0x40 && st.imm32 <= 0x4000)) continue;

            DWORD searchStart, searchEnd;
            DWORD bOff, eOff;
            DWORD stRva; int stSec;
            OffsetToRva(ctx, fo, stRva, stSec);
            if (FindRtfBounds(ctx, stRva, bOff, eOff)) {
                searchStart = bOff;
                searchEnd   = Min(eOff, fo + 0x40);
            } else {
                searchStart = fo > 0x600 ? fo - 0x600 : 0;
                searchEnd   = Min(ctx.size, fo + 0x40);
            }

            DWORD qgap; Store qs;
            if (!FindQwordAfter(ctx, fo, searchEnd, qgap, qs)) continue;
            if (!IsWritableData(ctx, qs.targetSec)) continue;

            if (fo < LEA_LEN || fo <= searchStart) continue;

            DWORD leaTargetRva = st.targetRva + STRUCT_OFFSET;
            DWORD leaOff = fo - LEA_LEN;
            for (;;) {
                if (IsRipLea(ctx, leaOff)) {
                    DWORD leaRva; int leaSec;
                    if (OffsetToRva(ctx, leaOff, leaRva, leaSec)) {
                        LONG rel32 = *(LONG*)(ctx.base + leaOff + 3);
                        DWORD leaTarget = (DWORD)((LONGLONG)leaRva + LEA_LEN + rel32);
                        if (leaTarget == leaTargetRva && IsWritableData(ctx, SecIdxForRva(ctx, leaTarget))) {
                            DWORD zeroSz; bool hasZero;
                            int zs = ScoreZero(ctx, leaOff, zeroSz, hasZero);
                            if (zs >= 2) {
                                LONG score = 80;
                                score += zs * 12;
                                score += 30 - (LONG)Min(qgap, (DWORD)24);
                                LONG pen = (LONG)((fo - leaOff) / 32); if (pen > 12) pen = 12;
                                score -= pen;
                                DWORD qd = qs.targetRva - st.targetRva;
                                if (qd > 0) score += 8;
                                if (st.imm32 == 0x108) score += 12;
                                if (hasZero) {
                                    if (qs.targetRva - leaTarget == zeroSz) score += 18;
                                    if (st.imm32 == zeroSz + 12) score += 18;
                                    else if (st.imm32 == zeroSz + 8 || st.imm32 == zeroSz + 16) score += 6;
                                }
                                if (qd == st.imm32 - 8) score += 20;
                                if (score > bestScore) { bestScore = score; bestRva = st.targetRva; }
                            }
                        }
                    }
                }
                if (leaOff == searchStart) break;
                leaOff--;
            }
        }
    }
    return bestScore >= (LONG)FAST_MIN_SCORE ? bestRva : 0;
}

// Structural method (exhaustive LEA scan, zero_score>=3)
static DWORD StructuralFindSeCi(const PeCtx& ctx) {
    const DWORD LEA_LEN = 7, STRUCT_OFFSET = 4, FWD = 0x240;
    LONG bestScore = -1;
    DWORD bestRva = 0;

    for (DWORD i = 0; i < ctx.sectionCount; i++) {
        if (!(ctx.sections[i].chars & 0x20000000)) continue;
        DWORD secStart = ctx.sections[i].rawPtr;
        DWORD secEnd   = Min(secStart + ctx.sections[i].rawSize, ctx.size);

        for (DWORD leaOff = secStart; leaOff + LEA_LEN <= secEnd; leaOff++) {
            if (!IsRipLea(ctx, leaOff)) continue;
            DWORD leaRva; int leaSec;
            if (!OffsetToRva(ctx, leaOff, leaRva, leaSec)) continue;
            LONG rel32 = *(LONG*)(ctx.base + leaOff + 3);
            DWORD targetRva = (DWORD)((LONGLONG)leaRva + LEA_LEN + rel32);
            if (!IsWritableData(ctx, SecIdxForRva(ctx, targetRva))) continue;

            DWORD zeroSz; bool hasZero;
            int zs = ScoreZero(ctx, leaOff, zeroSz, hasZero);
            if (zs < 3) continue;

            DWORD seciRva = targetRva - STRUCT_OFFSET;
            DWORD bOff, eOff;
            DWORD searchEnd;
            if (FindRtfBounds(ctx, leaRva, bOff, eOff)) searchEnd = eOff;
            else searchEnd = Min((DWORD)ctx.size, leaOff + FWD);

            for (DWORD pos = leaOff; pos + 10 <= searchEnd; pos++) {
                Store st;
                if (!ReadStore(ctx, pos, st) || st.isQword || st.targetRva != seciRva) continue;
                DWORD qgap; Store qs;
                bool hasQ = FindQwordAfter(ctx, pos, searchEnd, qgap, qs);
                int hits = CountMovHits(ctx, pos, seciRva, 300);
                int score = 30 + zs * 10 + hits;
                DWORD pen = (pos - leaOff) / 32; if (pen > 10) pen = 10;
                score -= (int)pen;
                if (hasQ) {
                    DWORD gc = Min(qgap, (DWORD)16);
                    score += 50 - (int)gc;
                    if (IsWritableData(ctx, qs.targetSec)) score += 5;
                }
                if (st.imm32 >= 0x40 && st.imm32 <= 0x400) score += 5;
                if (st.imm32 == 0x108) score += 10;
                if (hasZero) {
                    if (st.imm32 == zeroSz + 12) score += 10;
                    else if (st.imm32 == zeroSz || st.imm32 == zeroSz + 4 || st.imm32 == zeroSz + 8) score += 5;
                }
                if (score > bestScore) { bestScore = score; bestRva = seciRva; }
            }
        }
    }
    return bestScore >= 0 ? bestRva : 0;
}

// Legacy anchor method
static DWORD LegacyFindSeCi(const PeCtx& ctx) {
    static const BYTE kHead[2] = {0xC7, 0x05};
    static const BYTE kTail[7] = {0x08, 0x01, 0x00, 0x00, 0x48, 0xC7, 0x05};
    const DWORD LEA_LEN = 7, STRUCT_OFFSET = 4;
    LONG bestScore = -1;
    DWORD bestRva = 0;

    for (DWORD pos = 0; pos + 2 <= ctx.size; pos++) {
        if (ctx.base[pos] != kHead[0] || ctx.base[pos+1] != kHead[1]) continue;
        DWORD tailStart = pos + 6;
        if (tailStart + 7 > ctx.size) continue;
        bool match = true;
        for (int k = 0; k < 7; k++) if (ctx.base[tailStart+k] != kTail[k]) { match = false; break; }
        if (!match) continue;

        Store ms;
        if (!ReadStore(ctx, pos, ms)) continue;
        DWORD matchRva; int matchSec;
        if (!OffsetToRva(ctx, pos, matchRva, matchSec)) continue;

        DWORD searchStart, searchEnd;
        DWORD bOff, eOff;
        if (FindRtfBounds(ctx, matchRva, bOff, eOff)) searchStart = bOff;
        else searchStart = pos > 0x600 ? pos - 0x600 : 0;
        searchEnd = pos;
        if (searchEnd < LEA_LEN || searchEnd <= searchStart) continue;

        DWORD leaOff = searchEnd - LEA_LEN;
        for (;;) {
            if (IsRipLea(ctx, leaOff)) {
                DWORD leaRva; int leaSec;
                if (OffsetToRva(ctx, leaOff, leaRva, leaSec)) {
                    LONG rel32 = *(LONG*)(ctx.base + leaOff + 3);
                    DWORD targetRva = (DWORD)((LONGLONG)leaRva + LEA_LEN + rel32);
                    if (IsWritableData(ctx, SecIdxForRva(ctx, targetRva))) {
                        DWORD seciRva = targetRva - STRUCT_OFFSET;
                        int score = CountMovHits(ctx, pos, seciRva, 300);
                        if (seciRva == ms.targetRva) score += 50;
                        if (score > bestScore) { bestScore = score; bestRva = seciRva; }
                    }
                }
            }
            if (leaOff == searchStart) break;
            leaOff--;
        }
    }
    return bestScore >= 1 ? bestRva : 0;
}

} // anonymous namespace

std::optional<std::pair<DWORD64, DWORD64>> SymbolEngine::FindSeCiHeuristicOffsets(
    const std::wstring& kernelPath) noexcept
{
    INFO(L"[SymbolEngine] Starting heuristic SeCiCallbacks scan on: %s", kernelPath.c_str());

    // Load the kernel file into memory
    HANDLE hFile = CreateFileW(kernelPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        ERROR(L"[SymbolEngine] Cannot open kernel: %lu", GetLastError());
        return std::nullopt;
    }
    LARGE_INTEGER fileSize{};
    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart <= 0 || fileSize.QuadPart > 0x10000000) {
        CloseHandle(hFile);
        ERROR(L"[SymbolEngine] Kernel file size invalid");
        return std::nullopt;
    }
    DWORD sz = (DWORD)fileSize.QuadPart;
    std::vector<BYTE> buf(sz);
    DWORD read = 0;
    if (!ReadFile(hFile, buf.data(), sz, &read, nullptr) || read != sz) {
        CloseHandle(hFile);
        ERROR(L"[SymbolEngine] Failed to read kernel");
        return std::nullopt;
    }
    CloseHandle(hFile);

    PeCtx ctx{};
    ctx.base = buf.data();
    ctx.size = sz;
    if (!ParsePeCtx(ctx)) {
        ERROR(L"[SymbolEngine] Failed to parse kernel PE");
        return std::nullopt;
    }

    // Find ZwFlushInstructionCache from export table
    DWORD zwFlushRva = FindExportRva(ctx, "ZwFlushInstructionCache");
    if (!zwFlushRva) {
        ERROR(L"[SymbolEngine] ZwFlushInstructionCache not found in exports");
        return std::nullopt;
    }
    INFO(L"[SymbolEngine] ZwFlushInstructionCache RVA: 0x%lX", zwFlushRva);

    // Fast -> Structural -> Legacy cascade
    DWORD seciRva = FastFindSeCi(ctx);
    if (seciRva) {
        INFO(L"[SymbolEngine] SeCiCallbacks found (Fast heuristic) RVA: 0x%lX", seciRva);
        return std::make_pair((DWORD64)seciRva, (DWORD64)zwFlushRva);
    }

    INFO(L"[SymbolEngine] Fast heuristic failed, trying Structural scan...");
    seciRva = StructuralFindSeCi(ctx);
    if (seciRva) {
        INFO(L"[SymbolEngine] SeCiCallbacks found (Structural) RVA: 0x%lX", seciRva);
        return std::make_pair((DWORD64)seciRva, (DWORD64)zwFlushRva);
    }

    INFO(L"[SymbolEngine] Structural scan failed, trying Legacy anchor...");
    seciRva = LegacyFindSeCi(ctx);
    if (seciRva) {
        INFO(L"[SymbolEngine] SeCiCallbacks found (Legacy) RVA: 0x%lX", seciRva);
        return std::make_pair((DWORD64)seciRva, (DWORD64)zwFlushRva);
    }

    ERROR(L"[SymbolEngine] Heuristic scan exhausted all methods - SeCiCallbacks not found");
    return std::nullopt;
}
