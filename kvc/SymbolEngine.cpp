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
        DEBUG(L"[SymbolEngine] Failed to open PE file: %s", pePath.c_str());
        return std::nullopt;
    }
    
    HANDLE hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMapping) {
        CloseHandle(hFile);
        return std::nullopt;
    }
    
    LPVOID pBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pBase) {
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
                PIMAGE_DEBUG_DIRECTORY pDebugDir = reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>(
                    reinterpret_cast<BYTE*>(pBase) + debugDirRva);
                
                for (DWORD i = 0; i < debugDirSize / sizeof(IMAGE_DEBUG_DIRECTORY); i++) {
                    if (pDebugDir[i].Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
                        struct CV_INFO_PDB70 {
                            DWORD CvSignature;
                            GUID Signature;
                            DWORD Age;
                            char PdbFileName[1];
                        };
                        
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
            }
        }
    }
    
    UnmapViewOfFile(pBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    
    if (pdbName.empty() || guidStr.empty()) {
        DEBUG(L"[SymbolEngine] Failed to extract PDB info");
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
