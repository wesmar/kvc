//==============================================================================
// Utils.cpp - System utility functions with modern C++ optimizations
// Enhanced performance, robust error handling, low-level system operations
//==============================================================================

#include "Utils.h"
#include "common.h"
#include <windows.h>
#include <tlhelp32.h>
#include <filesystem>
#include <unordered_map>
#include <algorithm>
#include <array>
#include <string_view>
#include <regex>
#include <memory>

namespace fs = std::filesystem;

namespace Utils {

//==============================================================================
// STRING AND NUMERIC PARSING UTILITIES
//==============================================================================

[[nodiscard]] std::optional<DWORD> ParsePid(const std::wstring& pidStr) noexcept
{
    if (pidStr.empty()) return std::nullopt;
    
    try {
        // Fast path for single digits
        if (pidStr.length() == 1 && std::iswdigit(pidStr[0])) {
            return static_cast<DWORD>(pidStr[0] - L'0');
        }
        
        // Validate all characters are digits before conversion
        if (!std::all_of(pidStr.begin(), pidStr.end(), 
                        [](wchar_t c) { return std::iswdigit(c); })) {
            return std::nullopt;
        }
        
        const unsigned long result = std::wcstoul(pidStr.c_str(), nullptr, 10);
        return (result <= MAXDWORD && result != ULONG_MAX) ? 
               std::make_optional(static_cast<DWORD>(result)) : std::nullopt;
               
    } catch (...) {
        return std::nullopt;
    }
}

[[nodiscard]] bool IsNumeric(const std::wstring& str) noexcept
{
    return !str.empty() && 
           std::all_of(str.begin(), str.end(), 
                      [](wchar_t c) { return c >= L'0' && c <= L'9'; });
}

//==============================================================================
// ADVANCED FILE OPERATIONS WITH ROBUST ERROR HANDLING
//==============================================================================

bool ForceDeleteFile(const std::wstring& path) noexcept 
{
    // Fast path - try normal delete first
    if (DeleteFileW(path.c_str())) {
        return true;
    }

    // Remove file attributes that might prevent deletion
    const DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_NORMAL);
        
        // Retry after attribute removal
        if (DeleteFileW(path.c_str())) {
            return true;
        }
    }

    // Last resort: schedule deletion after reboot
    wchar_t tempPath[MAX_PATH];
    if (GetTempPathW(MAX_PATH, tempPath)) {
        wchar_t tempFile[MAX_PATH];
        if (GetTempFileNameW(tempPath, L"KVC", 0, tempFile)) {
            if (MoveFileExW(path.c_str(), tempFile, MOVEFILE_REPLACE_EXISTING)) {
                return MoveFileExW(tempFile, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
            }
        }
    }

    return false;
}

bool WriteFile(const std::wstring& path, const std::vector<BYTE>& data)
{
    if (data.empty()) return false;
    
    // Ensure parent directory exists
    const fs::path filePath = path;
    std::error_code ec;
    fs::create_directories(filePath.parent_path(), ec);
    
    // Remove existing file if present
    if (fs::exists(filePath)) {
        ForceDeleteFile(path);
    }
    
    // Create file with appropriate security attributes
    const HANDLE hFile = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, 
                                   CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    // Write data in chunks for large files - prevents memory issues
    constexpr DWORD CHUNK_SIZE = 64 * 1024; // 64KB chunks
    DWORD totalWritten = 0;
    
    while (totalWritten < data.size()) {
        const DWORD bytesToWrite = std::min(CHUNK_SIZE, 
                                          static_cast<DWORD>(data.size() - totalWritten));
        DWORD bytesWritten;
        
        if (!::WriteFile(hFile, data.data() + totalWritten, bytesToWrite, 
                        &bytesWritten, nullptr) || bytesWritten != bytesToWrite) {
            CloseHandle(hFile);
            DeleteFileW(path.c_str()); // Cleanup partial file
            return false;
        }
        
        totalWritten += bytesWritten;
    }
    
    // Ensure data is committed to disk
    FlushFileBuffers(hFile);
    CloseHandle(hFile);
    
    return true;
}

std::vector<BYTE> ReadFile(const std::wstring& path)
{
    const HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, 
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return {};
    }
    
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        CloseHandle(hFile);
        return {};
    }
    
    // Use memory mapping for files > 64KB - significant performance boost
    if (fileSize.QuadPart > 65536) {
        const HANDLE hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (hMapping) {
            void* const pData = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
            if (pData) {
                std::vector<BYTE> result(static_cast<const BYTE*>(pData), 
                                       static_cast<const BYTE*>(pData) + fileSize.QuadPart);
                UnmapViewOfFile(pData);
                CloseHandle(hMapping);
                CloseHandle(hFile);
                return result;
            }
            CloseHandle(hMapping);
        }
    }
    
    // Fallback to standard read for small files
    std::vector<BYTE> buffer(static_cast<size_t>(fileSize.QuadPart));
    DWORD bytesRead;
    
    const BOOL success = ::ReadFile(hFile, buffer.data(), static_cast<DWORD>(buffer.size()), 
                                  &bytesRead, nullptr);
    CloseHandle(hFile);
    
    return (success && bytesRead == buffer.size()) ? std::move(buffer) : std::vector<BYTE>{};
}

//==============================================================================
// RESOURCE EXTRACTION WITH VALIDATION
//==============================================================================

std::vector<BYTE> ReadResource(int resourceId, const wchar_t* resourceType)
{
    const HRSRC hRes = FindResource(nullptr, MAKEINTRESOURCE(resourceId), resourceType);
    if (!hRes) return {};
    
    const HGLOBAL hData = LoadResource(nullptr, hRes);
    if (!hData) return {};
    
    const DWORD dataSize = SizeofResource(nullptr, hRes);
    if (dataSize == 0) return {};
    
    void* const pData = LockResource(hData);
    if (!pData) return {};
    
    return std::vector<BYTE>(static_cast<const BYTE*>(pData), 
                           static_cast<const BYTE*>(pData) + dataSize);
}

//==============================================================================
// PROCESS NAME RESOLUTION WITH INTELLIGENT CACHING
//==============================================================================

static thread_local std::unordered_map<DWORD, std::wstring> g_processCache;
static thread_local DWORD g_lastCacheUpdate = 0;

[[nodiscard]] std::wstring GetProcessName(DWORD pid) noexcept
{
    // Use CreateToolhelp32Snapshot for reliable process enumeration
    const HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return L"[Unknown]";
    }
    
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(PROCESSENTRY32W);
    
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                CloseHandle(hSnapshot);
                return std::wstring(pe.szExeFile);
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    
    CloseHandle(hSnapshot);
    return L"[Unknown]";
}

std::wstring ResolveUnknownProcessLocal(DWORD pid, ULONG_PTR kernelAddress, 
                                      UCHAR protectionLevel, UCHAR signerType) noexcept
{
    // Cache management - refresh every 30 seconds for performance
    const DWORD currentTick = static_cast<DWORD>(GetTickCount64());
    if (currentTick - g_lastCacheUpdate > 30000) {
        g_processCache.clear();
        g_lastCacheUpdate = currentTick;
    }
    
    // Check cache first - significant performance improvement
    if (const auto cacheIt = g_processCache.find(pid); cacheIt != g_processCache.end()) {
        return cacheIt->second;
    }
    
    std::wstring processName = L"Unknown";
    
    // Multiple resolution strategies for maximum reliability
    if (const HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)) {
        wchar_t imagePath[MAX_PATH] = {};
        DWORD bufferSize = MAX_PATH;
        
        // Try QueryFullProcessImageName first - most reliable method
        if (QueryFullProcessImageNameW(hProcess, 0, imagePath, &bufferSize)) {
            const std::wstring fullPath(imagePath);
            const size_t lastSlash = fullPath.find_last_of(L'\\');
            processName = (lastSlash != std::wstring::npos) ? 
                         fullPath.substr(lastSlash + 1) : fullPath;
        }
        
        CloseHandle(hProcess);
    }
    
    // Fallback to snapshot-based resolution
    if (processName == L"Unknown") {
        processName = GetProcessName(pid);
    }
    
    // Cache successful resolutions
    if (processName != L"Unknown" && processName != L"[Unknown]") {
        g_processCache[pid] = processName;
    }
    
    return processName;
}

//==============================================================================
// PROTECTION LEVEL PARSING WITH OPTIMIZED LOOKUP TABLES
//==============================================================================

[[nodiscard]] std::optional<UCHAR> GetProtectionLevelFromString(const std::wstring& protectionLevel) noexcept
{
    // Static lookup table - compile-time initialization for optimal performance
    static const std::unordered_map<std::wstring, UCHAR> levels = {
        {L"none", static_cast<UCHAR>(PS_PROTECTED_TYPE::None)},
        {L"ppl",  static_cast<UCHAR>(PS_PROTECTED_TYPE::ProtectedLight)},
        {L"pp",   static_cast<UCHAR>(PS_PROTECTED_TYPE::Protected)}
    };

    if (protectionLevel.empty()) return std::nullopt;

    // Single allocation for case conversion
    std::wstring lower = protectionLevel;
    std::transform(lower.begin(), lower.end(), lower.begin(), 
                   [](wchar_t c) { return std::towlower(c); });

    if (const auto it = levels.find(lower); it != levels.end()) {
        return it->second;
    }

    return std::nullopt;
}

[[nodiscard]] std::optional<UCHAR> GetSignerTypeFromString(const std::wstring& signerType) noexcept
{
    if (signerType.empty()) return std::nullopt;

    // Convert to lowercase for case-insensitive comparison
    std::wstring lower = signerType;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](wchar_t c) { return std::towlower(c); });

    // Direct string comparisons - fastest for small datasets
    if (lower == L"none")         return static_cast<UCHAR>(PS_PROTECTED_SIGNER::None);
    if (lower == L"authenticode") return static_cast<UCHAR>(PS_PROTECTED_SIGNER::Authenticode);
    if (lower == L"codegen")      return static_cast<UCHAR>(PS_PROTECTED_SIGNER::CodeGen);
    if (lower == L"antimalware")  return static_cast<UCHAR>(PS_PROTECTED_SIGNER::Antimalware);
    if (lower == L"lsa")          return static_cast<UCHAR>(PS_PROTECTED_SIGNER::Lsa);
    if (lower == L"windows")      return static_cast<UCHAR>(PS_PROTECTED_SIGNER::Windows);
    if (lower == L"wintcb")       return static_cast<UCHAR>(PS_PROTECTED_SIGNER::WinTcb);
    if (lower == L"winsystem")    return static_cast<UCHAR>(PS_PROTECTED_SIGNER::WinSystem);
    if (lower == L"app")          return static_cast<UCHAR>(PS_PROTECTED_SIGNER::App);
    
    return std::nullopt;
}

//==============================================================================
// STRING REPRESENTATION FUNCTIONS WITH STATIC STORAGE
//==============================================================================

[[nodiscard]] const wchar_t* GetProtectionLevelAsString(UCHAR protectionLevel) noexcept
{
    // Static strings eliminate repeated allocations
    static const std::wstring none = L"None";
    static const std::wstring ppl = L"PPL";
    static const std::wstring pp = L"PP";
    static const std::wstring unknown = L"Unknown";

    switch (static_cast<PS_PROTECTED_TYPE>(protectionLevel)) {
        case PS_PROTECTED_TYPE::None:           return none.c_str();
        case PS_PROTECTED_TYPE::ProtectedLight: return ppl.c_str();
        case PS_PROTECTED_TYPE::Protected:      return pp.c_str();
        default:                                return unknown.c_str();
    }
}

[[nodiscard]] const wchar_t* GetSignerTypeAsString(UCHAR signerType) noexcept
{
    // Jump table approach for maximum performance
    static const std::wstring none = L"None";
    static const std::wstring authenticode = L"Authenticode";
    static const std::wstring codegen = L"CodeGen";
    static const std::wstring antimalware = L"Antimalware";
    static const std::wstring lsa = L"Lsa";
    static const std::wstring windows = L"Windows";
    static const std::wstring wintcb = L"WinTcb";
    static const std::wstring winsystem = L"WinSystem";
    static const std::wstring app = L"App";
    static const std::wstring unknown = L"Unknown";

    switch (static_cast<PS_PROTECTED_SIGNER>(signerType)) {
        case PS_PROTECTED_SIGNER::None:         return none.c_str();
        case PS_PROTECTED_SIGNER::Authenticode: return authenticode.c_str();
        case PS_PROTECTED_SIGNER::CodeGen:      return codegen.c_str();
        case PS_PROTECTED_SIGNER::Antimalware:  return antimalware.c_str();
        case PS_PROTECTED_SIGNER::Lsa:          return lsa.c_str();
        case PS_PROTECTED_SIGNER::Windows:      return windows.c_str();
        case PS_PROTECTED_SIGNER::WinTcb:       return wintcb.c_str();
        case PS_PROTECTED_SIGNER::WinSystem:    return winsystem.c_str();
        case PS_PROTECTED_SIGNER::App:          return app.c_str();
        default:                                return unknown.c_str();
    }
}

[[nodiscard]] const wchar_t* GetSignatureLevelAsString(UCHAR signatureLevel) noexcept
{
    // Static buffer for unknown signature levels - thread-safe
    switch (signatureLevel) {
        case 0x00: return L"None";
        case 0x08: return L"App";
        case 0x0c: return L"Standard";     // Standard DLL verification
        case 0x1c: return L"System";       // System DLL verification  
        case 0x1e: return L"Kernel";       // Kernel EXE verification
        case 0x3c: return L"Service";      // Windows service EXE
        case 0x3e: return L"Critical";     // Critical system EXE
        case 0x07:
        case 0x37: return L"WinSystem";
        default: {
            static thread_local wchar_t buf[32];
            swprintf_s(buf, L"Unknown (0x%02x)", signatureLevel);
            return buf;
        }
    }
}

//==============================================================================
// PROCESS DUMPABILITY ANALYSIS WITH HEURISTICS
//==============================================================================

[[nodiscard]] ProcessDumpability CanDumpProcess(DWORD pid, const std::wstring& processName) noexcept
{
    ProcessDumpability result{false, L""};

    // Known undumpable system processes - hardcoded for performance
    static const std::unordered_set<DWORD> undumpablePids = {
        4,    // System process
        188,  // Secure System
        232,  // Registry process
        3052  // Memory Compression
    };

    static const std::unordered_set<std::wstring> undumpableNames = {
        L"System",
        L"Secure System", 
        L"Registry",
        L"Memory Compression"
    };

    if (undumpablePids.contains(pid)) {
        result.Reason = L"System kernel process - undumpable by design";
        return result;
    }

    if (undumpableNames.contains(processName)) {
        result.Reason = L"Critical system process - protected by kernel";
        return result;
    }

    // Additional heuristics for process dumpability
    if (processName == L"[Unknown]" || processName.empty()) {
        result.Reason = L"Process name unknown - likely kernel process";
        return result;
    }

    // Assume process is dumpable if not in exclusion lists
    result.CanDump = true;
    result.Reason = L"Process appears dumpable with proper privileges";
    return result;
}

//==============================================================================
// HEX STRING PROCESSING UTILITIES
//==============================================================================

[[nodiscard]] bool IsValidHexString(const std::wstring& hexString) noexcept
{
    if (hexString.empty() || (hexString.length() % 2) != 0) {
        return false;
    }

    return std::all_of(hexString.begin(), hexString.end(), 
                      [](wchar_t c) {
                          return (c >= L'0' && c <= L'9') || 
                                 (c >= L'A' && c <= L'F') || 
                                 (c >= L'a' && c <= L'f');
                      });
}

bool HexStringToBytes(const std::wstring& hexString, std::vector<BYTE>& bytes) noexcept
{
    if (!IsValidHexString(hexString)) {
        return false;
    }

    bytes.clear();
    bytes.reserve(hexString.length() / 2);

    for (size_t i = 0; i < hexString.length(); i += 2) {
        const wchar_t highNibble = hexString[i];
        const wchar_t lowNibble = hexString[i + 1];

        auto hexToByte = [](wchar_t c) -> BYTE {
            if (c >= L'0' && c <= L'9') return static_cast<BYTE>(c - L'0');
            if (c >= L'A' && c <= L'F') return static_cast<BYTE>(c - L'A' + 10);
            if (c >= L'a' && c <= L'f') return static_cast<BYTE>(c - L'a' + 10);
            return 0;
        };

        const BYTE byte = (hexToByte(highNibble) << 4) | hexToByte(lowNibble);
        bytes.push_back(byte);
    }

    return true;
}

//==============================================================================
// PE BINARY PARSING AND MANIPULATION
//==============================================================================

[[nodiscard]] std::optional<size_t> GetPEFileLength(const std::vector<BYTE>& data, size_t offset) noexcept
{
    try {
        if (data.size() < offset + 64) return std::nullopt; // Not enough data for DOS header

        // Verify DOS signature "MZ"
        if (data[offset] != 'M' || data[offset + 1] != 'Z') {
            return std::nullopt;
        }

        // Get PE header offset from DOS header
        DWORD pe_offset;
        std::memcpy(&pe_offset, &data[offset + 60], sizeof(DWORD));
        
        const size_t pe_header_start = offset + pe_offset;
        if (data.size() < pe_header_start + 24) return std::nullopt;

        // Verify PE signature "PE\0\0"
        if (std::memcmp(&data[pe_header_start], "PE\0\0", 4) != 0) {
            return std::nullopt;
        }

        // Parse COFF header for section count
        WORD number_of_sections;
        std::memcpy(&number_of_sections, &data[pe_header_start + 6], sizeof(WORD));
        
        if (number_of_sections == 0) return std::nullopt;

        // Calculate section table location
        WORD optional_header_size;
        std::memcpy(&optional_header_size, &data[pe_header_start + 20], sizeof(WORD));
        
        const size_t section_table_offset = pe_header_start + 24 + optional_header_size;
        constexpr size_t section_header_size = 40;
        
        if (data.size() < section_table_offset + (number_of_sections * section_header_size)) {
            return std::nullopt;
        }

        // Find the highest file offset + size from all sections
        size_t max_end = 0;
        for (WORD i = 0; i < number_of_sections; ++i) {
            const size_t sh_offset = section_table_offset + (i * section_header_size);
            
            if (data.size() < sh_offset + 24) {
                return std::nullopt;
            }
            
            DWORD size_of_raw, pointer_to_raw;
            std::memcpy(&size_of_raw, &data[sh_offset + 16], sizeof(DWORD));
            std::memcpy(&pointer_to_raw, &data[sh_offset + 20], sizeof(DWORD));
            
            if (pointer_to_raw == 0) continue; // Skip sections without raw data
            
            const size_t section_end = pointer_to_raw + size_of_raw;
            max_end = std::max(max_end, section_end);
        }
        
        if (max_end > 0) {
            const size_t header_end = section_table_offset + number_of_sections * section_header_size;
            const size_t file_end = std::max(max_end, header_end);
            return std::min(file_end, data.size());
        }
        
        return std::nullopt;
        
    } catch (...) {
        return std::nullopt;
    }
}

bool SplitCombinedPE(const std::vector<BYTE>& combined, 
                     std::vector<BYTE>& first, 
                     std::vector<BYTE>& second) noexcept
{
    try {
        if (combined.empty()) return false;
        
        // Determine exact size of first PE file
        const auto first_size = GetPEFileLength(combined, 0);
        
        if (!first_size || *first_size <= 0 || *first_size >= combined.size()) {
            // Fallback: search for next "MZ" signature
            constexpr size_t search_start = 0x200;
            const size_t search_offset = (combined.size() > search_start) ? search_start : 0;
            
            for (size_t i = search_offset; i < combined.size() - 1; ++i) {
                if (combined[i] == 'M' && combined[i + 1] == 'Z') {
                    // Found potential second PE
                    first.assign(combined.begin(), combined.begin() + i);
                    second.assign(combined.begin() + i, combined.end());
                    return !first.empty() && !second.empty();
                }
            }
            return false;
        }
        
        // Split at calculated boundary
        const size_t split_point = *first_size;
        if (split_point >= combined.size()) return false;
        
        first.assign(combined.begin(), combined.begin() + split_point);
        second.assign(combined.begin() + split_point, combined.end());
        
        return !first.empty() && !second.empty();
        
    } catch (...) {
        return false;
    }
}

//==============================================================================
// XOR DECRYPTION UTILITY
//==============================================================================

[[nodiscard]] std::vector<BYTE> DecryptXOR(const std::vector<BYTE>& encryptedData, 
                                          const std::array<BYTE, 7>& key) noexcept
{
    if (encryptedData.empty()) return {};
    
    std::vector<BYTE> decrypted;
    decrypted.reserve(encryptedData.size());
    
    for (size_t i = 0; i < encryptedData.size(); ++i) {
        const BYTE decrypted_byte = encryptedData[i] ^ key[i % key.size()];
        decrypted.push_back(decrypted_byte);
    }
    
    return decrypted;
}

//==============================================================================
// KERNEL ADDRESS UTILITIES
//==============================================================================

[[nodiscard]] std::optional<ULONG_PTR> GetKernelBaseAddress() noexcept
{
    // Implementation depends on kernel driver communication
    // This is a placeholder for the actual kernel base address retrieval
    return std::nullopt;
}

} // namespace Utils