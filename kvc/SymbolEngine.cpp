// SymbolEngine.cpp

#include "SymbolEngine.h"
#include <shlwapi.h>
#include <shlobj.h>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

SymbolEngine::SymbolEngine() 
    : m_symbolServer(L"https://msdl.microsoft.com/download/symbols")
{
    // Use standard cache path structure like drvloader
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    PathRemoveFileSpecW(exePath);
    m_symbolCachePath = std::wstring(exePath) + L"\\symbols";
}

SymbolEngine::~SymbolEngine() {
    if (m_initialized) {
        SymCleanup(GetCurrentProcess());
    }
}

bool SymbolEngine::Initialize() noexcept {
    if (m_initialized) return true;

    if (!EnsureCacheDirectory()) {
        ERROR(L"Failed to create symbol cache directory");
        return false;
    }

    DWORD options = SymGetOptions();
    SymSetOptions(options | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_DEBUG);

    if (!SymInitializeW(GetCurrentProcess(), m_symbolCachePath.c_str(), FALSE)) {
        ERROR(L"SymInitializeW failed: %d", GetLastError());
        return false;
    }

    m_initialized = true;
    DEBUG(L"Symbol engine initialized. Cache: %s", m_symbolCachePath.c_str());
    return true;
}

bool SymbolEngine::EnsureCacheDirectory() noexcept {
    DWORD attrib = GetFileAttributesW(m_symbolCachePath.c_str());
    
    if (attrib == INVALID_FILE_ATTRIBUTES) {
        if (!CreateDirectoryW(m_symbolCachePath.c_str(), nullptr)) {
            ERROR(L"Failed to create cache directory: %s", m_symbolCachePath.c_str());
            return false;
        }
        DEBUG(L"Created symbol cache directory: %s", m_symbolCachePath.c_str());
    }
    
    return true;
}

std::pair<std::wstring, std::wstring> SymbolEngine::GetPdbInfoFromPe(const std::wstring& pePath) noexcept {
    HANDLE hFile = CreateFileW(pePath.c_str(), GENERIC_READ, FILE_SHARE_READ, 
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        DEBUG(L"Failed to open PE file: %s", pePath.c_str());
        return {L"", L""};
    }

    HANDLE hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMapping) {
        CloseHandle(hFile);
        return {L"", L""};
    }

    LPVOID pBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pBase) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return {L"", L""};
    }

    std::wstring pdbName, guidStr;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    
    if (pDos->e_magic == IMAGE_DOS_SIGNATURE) {
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDos->e_lfanew);
        if (pNt->Signature == IMAGE_NT_SIGNATURE) {
            DWORD debugDirRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
            DWORD debugDirSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;

            if (debugDirRva && debugDirSize) {
                PIMAGE_DEBUG_DIRECTORY pDebugDir = (PIMAGE_DEBUG_DIRECTORY)((BYTE*)pBase + debugDirRva);
                
                for (DWORD i = 0; i < debugDirSize / sizeof(IMAGE_DEBUG_DIRECTORY); i++) {
                    if (pDebugDir[i].Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
                        struct CV_INFO_PDB70 {
                            DWORD CvSignature;
                            GUID Signature;
                            DWORD Age;
                            char PdbFileName[1];
                        };
                        
                        CV_INFO_PDB70* pCv = (CV_INFO_PDB70*)((BYTE*)pBase + pDebugDir[i].AddressOfRawData);
                        
                        if (pCv->CvSignature == 0x53445352) { // 'RSDS'
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
                                
                                // Extract filename from full path
                                std::wstring fullPath = wideBuf.data();
                                size_t pos = fullPath.find_last_of(L"\\/");
                                pdbName = (pos != std::wstring::npos) ? fullPath.substr(pos + 1) : fullPath;
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

    return {pdbName, guidStr};
}

bool SymbolEngine::DownloadPdb(const std::wstring& modulePath, const std::wstring& pdbName, const std::wstring& guid) noexcept {
    // Construct URL: Server/PdbName/GUID/PdbName
    std::wstring url = m_symbolServer + L"/" + pdbName + L"/" + guid + L"/" + pdbName;
    
    // Construct local cache path with GUID structure
    std::wstring localDir = m_symbolCachePath + L"\\" + pdbName + L"\\" + guid;
    std::wstring localPath = localDir + L"\\" + pdbName;

    // Check if already cached
    if (GetFileAttributesW(localPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        DEBUG(L"PDB already exists in cache: %s", localPath.c_str());
        return true;
    }

    INFO(L"Downloading symbols for %s...", modulePath.c_str());
    DEBUG(L"PDB Name: %s", pdbName.c_str());
    DEBUG(L"PDB GUID: %s", guid.c_str());
    
    // Create directory structure
    SHCreateDirectoryExW(nullptr, localDir.c_str(), nullptr);
    
    return DownloadFile(url, localPath);
}

bool SymbolEngine::DownloadFile(const std::wstring& url, const std::wstring& outputPath) noexcept {
    DEBUG(L"Downloading: %s", url.c_str());
    
    URL_COMPONENTSW urlParts = { sizeof(urlParts) };
    wchar_t host[256], path[1024];
    urlParts.lpszHostName = host;
    urlParts.dwHostNameLength = _countof(host);
    urlParts.lpszUrlPath = path;
    urlParts.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &urlParts)) {
        ERROR(L"Failed to parse URL");
        return false;
    }

    HINTERNET hSession = WinHttpOpen(L"KVC-SymbolEngine/1.0", 
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, 
        WINHTTP_NO_PROXY_NAME, 
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        ERROR(L"Failed to open HTTP session");
        return false;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, host, urlParts.nPort, 0);
    if (!hConnect) {
        ERROR(L"Failed to connect to server");
        WinHttpCloseHandle(hSession);
        return false;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path, nullptr, 
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 
        (urlParts.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);
    
    if (!hRequest || 
        !WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, 
                           WINHTTP_NO_REQUEST_DATA, 0, 0, 0) || 
        !WinHttpReceiveResponse(hRequest, nullptr)) {
        if (hRequest) WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        ERROR(L"HTTP request failed");
        return false;
    }

    DWORD statusCode = 0;
    DWORD size = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, 
        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &size, WINHTTP_NO_HEADER_INDEX);

    if (statusCode != 200) {
        ERROR(L"Symbol download HTTP error: %d", statusCode);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    HANDLE hFile = CreateFileW(outputPath.c_str(), GENERIC_WRITE, 0, nullptr, 
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        ERROR(L"Failed to create output file: %s", outputPath.c_str());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    DWORD bytesRead, bytesWritten, totalBytes = 0;
    BYTE buffer[8192];
    
    while (WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        if (!WriteFile(hFile, buffer, bytesRead, &bytesWritten, nullptr)) {
            ERROR(L"Failed to write to file");
            CloseHandle(hFile);
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }
        totalBytes += bytesWritten;
    }

    CloseHandle(hFile);
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    SUCCESS(L"Downloaded %d bytes to cache", totalBytes);
    return true;
}

bool SymbolEngine::EnsureSymbolsForModule(const std::wstring& modulePath) noexcept {
    DEBUG(L"Preparing symbols for: %s", modulePath.c_str());
    
    auto [pdbName, guid] = GetPdbInfoFromPe(modulePath);
    if (pdbName.empty() || guid.empty()) {
        ERROR(L"Failed to extract PDB info from PE");
        return false;
    }

    // Check if PDB exists in cache
    std::wstring localPath = m_symbolCachePath + L"\\" + pdbName + L"\\" + guid + L"\\" + pdbName;
    
    if (GetFileAttributesW(localPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        INFO(L"PDB not in cache, downloading...");
        if (!DownloadPdb(modulePath, pdbName, guid)) {
            ERROR(L"Failed to download PDB");
            return false;
        }
    } else {
        DEBUG(L"Using cached PDB: %s", localPath.c_str());
    }
    
    return true;
}

std::optional<DWORD64> SymbolEngine::GetSymbolOffset(const std::wstring& modulePath, const std::wstring& symbolName) noexcept {
    DEBUG(L"Looking up symbol: %s", symbolName.c_str());
    
    // Load module into DbgHelp
    DWORD64 baseAddr = SymLoadModuleExW(GetCurrentProcess(), nullptr, 
        modulePath.c_str(), nullptr, 0x10000000, 0, nullptr, 0);
    if (!baseAddr) {
        ERROR(L"SymLoadModuleExW failed: %d", GetLastError());
        return std::nullopt;
    }

    // Prepare symbol info buffer
    BYTE buffer[sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(wchar_t)];
    PSYMBOL_INFOW pSymbol = (PSYMBOL_INFOW)buffer;
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
    pSymbol->MaxNameLen = MAX_SYM_NAME;

    std::optional<DWORD64> offset = std::nullopt;
    
    if (SymFromNameW(GetCurrentProcess(), symbolName.c_str(), pSymbol)) {
        offset = pSymbol->Address - baseAddr;
        SUCCESS(L"Symbol found: %s at offset 0x%llX", symbolName.c_str(), offset.value());
    } else {
        ERROR(L"Symbol not found: %s (error: %d)", symbolName.c_str(), GetLastError());
    }

    SymUnloadModule64(GetCurrentProcess(), baseAddr);
    return offset;
}