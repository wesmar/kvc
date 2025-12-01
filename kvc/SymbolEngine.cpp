// SymbolEngine.cpp
// Symbol resolution with automatic temp cleanup and registry caching

#include "SymbolEngine.h"
#include <psapi.h>
#include <shlwapi.h>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")

// ============================================================================
// RAII CLEANUP HELPER
// ============================================================================

class TempPdbCleanup {
public:
    TempPdbCleanup(const std::wstring& dir, const std::wstring& file) 
        : m_dir(dir), m_file(file) {}
    
    ~TempPdbCleanup() {
        // Delete PDB file
        if (!m_file.empty()) {
            DeleteFileW(m_file.c_str());
            DEBUG(L"[Cleanup] Deleted temp PDB: %s", m_file.c_str());
        }
        
        // Delete directory (only if empty)
        if (!m_dir.empty()) {
            if (RemoveDirectoryW(m_dir.c_str())) {
                DEBUG(L"[Cleanup] Deleted temp directory: %s", m_dir.c_str());
            }
        }
    }
    
private:
    std::wstring m_dir;
    std::wstring m_file;
};

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
    
    // 1. Extract PDB information from kernel binary
    auto pdbInfo = GetPdbInfoFromPe(kernelPath);
    if (!pdbInfo) {
        ERROR(L"[SymbolEngine] Failed to extract PDB info from kernel");
        return std::nullopt;
    }
    
    auto [pdbName, guid] = *pdbInfo;
    DEBUG(L"[SymbolEngine] PDB: %s, GUID: %s", pdbName.c_str(), guid.c_str());
    
    // 2. Download PDB into memory
    INFO(L"[SymbolEngine] Downloading symbols...");
    auto pdbData = DownloadPdbToMemory(pdbName, guid);
    if (!pdbData) {
        ERROR(L"[SymbolEngine] Failed to download PDB");
        return std::nullopt;
    }
    
    DEBUG(L"[SymbolEngine] PDB downloaded: %zu bytes", pdbData->size());
    
    // 3. Calculate offsets (with automatic cleanup)
    auto offsets = CalculateOffsetsFromMemory(*pdbData, pdbName);
    
    // 4. Securely wipe PDB data from memory
    if (!pdbData->empty()) {
        SecureZeroMemory(pdbData->data(), pdbData->size());
    }
    
    return offsets;
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
                                std::vector<wchar_t> wideBuf(len);
                                MultiByteToWideChar(CP_UTF8, 0, pCv->PdbFileName, -1, wideBuf.data(), len);
                                
                                std::wstring fullPath = wideBuf.data();
                                size_t lastSlash = fullPath.find_last_of(L"/\\");
                                pdbName = (lastSlash != std::wstring::npos) ? 
                                    fullPath.substr(lastSlash + 1) : fullPath;
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
        ERROR(L"[SymbolEngine] Failed to extract PDB info from PE");
        return std::nullopt;
    }
    
    return std::make_pair(pdbName, guidStr);
}

// ============================================================================
// PDB DOWNLOAD
// ============================================================================

std::optional<std::vector<BYTE>> SymbolEngine::DownloadPdbToMemory(const std::wstring& pdbName, const std::wstring& guid) noexcept {
    std::wstring url = m_symbolServer + L"/" + pdbName + L"/" + guid + L"/" + pdbName;
    
    DEBUG(L"[SymbolEngine] Downloading from: %s", url.c_str());
    
    std::vector<BYTE> pdbData;
    if (!DownloadFileToMemory(url, pdbData)) {
        ERROR(L"[SymbolEngine] Failed to download PDB");
        return std::nullopt;
    }
    
    if (pdbData.empty()) {
        ERROR(L"[SymbolEngine] Downloaded PDB is empty");
        return std::nullopt;
    }
    
    return pdbData;
}

bool SymbolEngine::DownloadFileToMemory(const std::wstring& url, std::vector<BYTE>& output) noexcept {
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

    DEBUG(L"[SymbolEngine] Downloaded %zu bytes", output.size());
    return true;
}

// ============================================================================
// OFFSET CALCULATION WITH AUTO-CLEANUP
// ============================================================================

std::optional<std::pair<DWORD64, DWORD64>> SymbolEngine::CalculateOffsetsFromMemory(
    const std::vector<BYTE>& pdbData,
    const std::wstring& pdbName) noexcept
{
    DEBUG(L"[SymbolEngine] Calculating offsets (%zu bytes)...", pdbData.size());

    // 1. Create unique temp directory
    wchar_t tempDir[MAX_PATH];
    GetTempPathW(MAX_PATH, tempDir);
    
    std::wstring pdbCacheDir = std::wstring(tempDir) + L"kvc_sym_" + 
                               std::to_wstring(GetCurrentProcessId());
    
    if (!CreateDirectoryW(pdbCacheDir.c_str(), nullptr) && 
        GetLastError() != ERROR_ALREADY_EXISTS) {
        ERROR(L"[SymbolEngine] Failed to create temp dir");
        return std::nullopt;
    }

    std::wstring pdbPath = pdbCacheDir + L"\\" + pdbName;
    DEBUG(L"[SymbolEngine] Temp PDB: %s", pdbPath.c_str());

    // 2. RAII cleanup guard (guaranteed cleanup on scope exit)
    TempPdbCleanup cleanup(pdbCacheDir, pdbPath);

    // 3. Write PDB to disk
    HANDLE hFile = CreateFileW(pdbPath.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hFile == INVALID_HANDLE_VALUE) {
        ERROR(L"[SymbolEngine] Failed to create PDB file: %d", GetLastError());
        return std::nullopt;
    }

    DWORD bytesWritten = 0;
    if (!WriteFile(hFile, pdbData.data(), static_cast<DWORD>(pdbData.size()), 
                   &bytesWritten, nullptr)) {
        ERROR(L"[SymbolEngine] Failed to write PDB: %d", GetLastError());
        CloseHandle(hFile);
        return std::nullopt;
    }
    CloseHandle(hFile);

    // 4. Re-initialize DbgHelp with temp cache
    if (m_initialized) {
        SymCleanup(GetCurrentProcess());
        m_initialized = false;
    }

    std::wstring symbolPath = L"SRV*" + pdbCacheDir;
    
    DWORD options = SymGetOptions();
    SymSetOptions(options | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | 
                  SYMOPT_DEBUG | SYMOPT_CASE_INSENSITIVE | SYMOPT_LOAD_LINES);

    if (!SymInitializeW(GetCurrentProcess(), symbolPath.c_str(), FALSE)) {
        ERROR(L"[SymbolEngine] SymInitializeW failed: %d", GetLastError());
        return std::nullopt;
    }
    m_initialized = true;

    // 5. Load module
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

    // 6. Resolve symbols
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

    // 7. Cleanup DbgHelp
    SymUnloadModule64(GetCurrentProcess(), loadedModule);
    SymCleanup(GetCurrentProcess());
    m_initialized = false;

    // 8. Validate (RAII will cleanup temp files automatically)
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