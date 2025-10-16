// Utils.cpp - Core utility functions for process management, memory operations, and system utilities

#include "Utils.h"
#include "common.h"
#include <algorithm>
#include <tlhelp32.h>
#include <psapi.h>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <fstream>
#include <fdi.h>
#pragma comment(lib, "cabinet.lib")

namespace fs = std::filesystem;

#pragma comment(lib, "psapi.lib")

// ============================================================================
// NT API DEFINITIONS (Missing from Windows headers)
// ============================================================================

#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define SystemModuleInformation 11

typedef struct _SYSTEM_MODULE {
    ULONG_PTR Reserved1;
    ULONG_PTR Reserved2;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT PathLength;
    CHAR ImageName[256];
} SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG Count;
    SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef NTSTATUS (WINAPI *NTQUERYSYSTEMINFORMATION)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

namespace Utils {

// ============================================================================
// CONSTANTS AND DEFINITIONS
// ============================================================================

// Maximum process name length for resolution */
constexpr int MAX_PROCESS_NAME_LENGTH = 256;

// Maximum path length for system operations */
constexpr int MAX_PATH_LENGTH = 32767;

// Buffer size for kernel address resolution */
constexpr int KERNEL_BUFFER_SIZE = 4096;

// ============================================================================
// PROCESS MANAGEMENT UTILITIES
// ============================================================================

/**
 * @brief Resolves process name from PID with comprehensive fallback mechanisms
 * 
 * Attempts multiple resolution strategies:
 * 1. Toolhelp32Snapshot API (primary)
 * 2. OpenProcess + GetModuleFileNameEx (fallback)  
 * 3. Kernel address resolution (last resort)
 * 
 * @param pid Process ID to resolve
 * @return std::wstring Process name or "[Unknown]" if resolution fails
 * 
 * @note This function handles protected processes that may resist standard enumeration
 */
std::wstring GetProcessName(DWORD pid) noexcept
{
    if (pid == 0) return L"System Idle Process";
    if (pid == 4) return L"System";
    
    // Check cache first
    static std::unordered_map<DWORD, std::wstring> processCache;
    static DWORD lastCacheUpdate = 0;
    
    const DWORD currentTick = static_cast<DWORD>(GetTickCount64());
    if (currentTick - lastCacheUpdate > 30000) {
        processCache.clear();
        lastCacheUpdate = currentTick;
    }
    
    auto cacheIt = processCache.find(pid);
    if (cacheIt != processCache.end()) {
        return cacheIt->second;
    }
    
    // Primary resolution: Toolhelp32Snapshot
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnapshot, &pe)) {
            do {
                if (pe.th32ProcessID == pid) {
                    CloseHandle(hSnapshot);
                    std::wstring name(pe.szExeFile);
                    processCache[pid] = name;
                    return name;
                }
            } while (Process32NextW(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    
    // Secondary resolution: OpenProcess method
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess) {
        wchar_t processName[MAX_PATH_LENGTH] = {0};
        DWORD size = MAX_PATH_LENGTH;

        if (GetProcessImageFileNameW(hProcess, processName, size) > 0) {
            CloseHandle(hProcess);
            
            // Extract filename from full path
            std::wstring fullPath(processName);
            size_t lastSlash = fullPath.find_last_of(L'\\');
            if (lastSlash != std::wstring::npos) {
                std::wstring name = fullPath.substr(lastSlash + 1);
                processCache[pid] = name;
                return name;
            }
            processCache[pid] = fullPath;
            return fullPath;
        }
        CloseHandle(hProcess);
    }
    
    return L"[Unknown]";
}

/**
 * @brief Resolves unknown processes using kernel address and protection info
 * 
 * @param pid Process ID
 * @param kernelAddress Kernel address of EPROCESS structure
 * @param protectionLevel Current protection level
 * @param signerType Digital signature authority
 * @return std::wstring Resolved process name or descriptive identifier
 */
std::wstring ResolveUnknownProcessLocal(DWORD pid, ULONG_PTR kernelAddress, 
                                       UCHAR protectionLevel, UCHAR signerType) noexcept
{
    std::wstringstream ss;
    ss << L"[Unknown_PID_" << pid;
    
    if (protectionLevel > 0) {
        ss << L"_" << GetProtectionLevelAsString(protectionLevel)
           << L"-" << GetSignerTypeAsString(signerType);
    }
    
    if (kernelAddress > 0) {
        ss << L"_0x" << std::hex << kernelAddress;
    }
    
    ss << L"]";
    return ss.str();
}

// ============================================================================
// PROTECTION LEVEL MANAGEMENT
// ============================================================================

/**
 * @brief Converts protection byte to human-readable level string
 * 
 * @param protection Raw protection byte from EPROCESS structure
 * @return const wchar_t* String representation ("None", "PPL", "PP")
 * 
 * @see PS_PROTECTED_TYPE for protection level definitions
 */
const wchar_t* GetProtectionLevelAsString(UCHAR protection) noexcept
{
    UCHAR level = GetProtectionLevel(protection);
    
    switch (static_cast<PS_PROTECTED_TYPE>(level)) {
        case PS_PROTECTED_TYPE::None: return L"None";
        case PS_PROTECTED_TYPE::ProtectedLight: return L"PPL";
        case PS_PROTECTED_TYPE::Protected: return L"PP";
        default: return L"Unknown";
    }
}

/**
 * @brief Converts signer type to human-readable string
 * 
 * @param signerType Raw signer type byte
 * @return const wchar_t* String representation ("Windows", "Antimalware", etc.)
 */
const wchar_t* GetSignerTypeAsString(UCHAR signerType) noexcept
{
    switch (static_cast<PS_PROTECTED_SIGNER>(signerType)) {
        case PS_PROTECTED_SIGNER::None: return L"None";
        case PS_PROTECTED_SIGNER::Authenticode: return L"Authenticode";
        case PS_PROTECTED_SIGNER::CodeGen: return L"CodeGen";
        case PS_PROTECTED_SIGNER::Antimalware: return L"Antimalware";
        case PS_PROTECTED_SIGNER::Lsa: return L"Lsa";
        case PS_PROTECTED_SIGNER::Windows: return L"Windows";
        case PS_PROTECTED_SIGNER::WinTcb: return L"WinTcb";
        case PS_PROTECTED_SIGNER::WinSystem: return L"WinSystem";
        case PS_PROTECTED_SIGNER::App: return L"App";
        default: return L"Unknown";
    }
}

/**
 * @brief Converts signature level to human-readable string with detailed mapping
 * 
 * @param signatureLevel Raw signature level byte
 * @return const wchar_t* String representation describing signature level
 */
const wchar_t* GetSignatureLevelAsString(UCHAR signatureLevel) noexcept
{
    static const std::unordered_map<UCHAR, const wchar_t*> levelMap = {
        {0x00, L"None"},
        {0x01, L"Unsigned"},
        {0x02, L"Custom1"},
        {0x04, L"Custom2"},
        {0x08, L"Authenticode"},
        {0x10, L"Catalog"},
        {0x20, L"Catalog2"},
        {0x40, L"Store"},
        {0x80, L"AntiMalware"},
        {0x0C, L"Standard"},
        {0x0F, L"Microsoft"},
        {0x07, L"WinSystem"},
        {0x08, L"App"},
        {0x1C, L"System"},
        {0x1E, L"Kernel"},
        {0x37, L"WinSystem"},
        {0x3C, L"Service"},
        {0x3E, L"Critical"}
    };
    
    auto it = levelMap.find(signatureLevel);
    return (it != levelMap.end()) ? it->second : L"Custom";
}

/**
 * @brief Converts section signature level to human-readable string
 * 
 * @param sectionSignatureLevel Raw section signature level byte
 * @return const wchar_t* String representation describing section signature level
 */
const wchar_t* GetSectionSignatureLevelAsString(UCHAR sectionSignatureLevel) noexcept
{
    // Use the same mapping as signature level for consistency
    return GetSignatureLevelAsString(sectionSignatureLevel);
}

/**
 * @brief Converts protection level string to enumeration value
 * 
 * @param levelStr Protection level string ("PP", "PPL", "None")
 * @return std::optional<UCHAR> Protection level value or nullopt on invalid input
 */
std::optional<UCHAR> GetProtectionLevelFromString(const std::wstring& levelStr) noexcept
{
	std::wstring lower = StringUtils::ToLowerCaseCopy(levelStr);
    
    static const std::unordered_map<std::wstring, UCHAR> levelMap = {
        {L"pp", static_cast<UCHAR>(PS_PROTECTED_TYPE::Protected)},
        {L"ppl", static_cast<UCHAR>(PS_PROTECTED_TYPE::ProtectedLight)},
        {L"none", static_cast<UCHAR>(PS_PROTECTED_TYPE::None)},
        {L"0", static_cast<UCHAR>(PS_PROTECTED_TYPE::None)}
    };
    
    auto it = levelMap.find(lower);
    return (it != levelMap.end()) ? std::make_optional(it->second) : std::nullopt;
}

/**
 * @brief Converts signer type string to enumeration value
 * 
 * @param signerStr Signer type string ("Windows", "Antimalware", etc.)
 * @return std::optional<UCHAR> Signer type value or nullopt on invalid input
 */
std::optional<UCHAR> GetSignerTypeFromString(const std::wstring& signerStr) noexcept
{
	std::wstring lower = StringUtils::ToLowerCaseCopy(signerStr);

    static const std::unordered_map<std::wstring, UCHAR> signerMap = {
        {L"none", static_cast<UCHAR>(PS_PROTECTED_SIGNER::None)},
        {L"authenticode", static_cast<UCHAR>(PS_PROTECTED_SIGNER::Authenticode)},
        {L"codegen", static_cast<UCHAR>(PS_PROTECTED_SIGNER::CodeGen)},
        {L"antimalware", static_cast<UCHAR>(PS_PROTECTED_SIGNER::Antimalware)},
        {L"lsa", static_cast<UCHAR>(PS_PROTECTED_SIGNER::Lsa)},
        {L"windows", static_cast<UCHAR>(PS_PROTECTED_SIGNER::Windows)},
        {L"wintcb", static_cast<UCHAR>(PS_PROTECTED_SIGNER::WinTcb)},
        {L"winsystem", static_cast<UCHAR>(PS_PROTECTED_SIGNER::WinSystem)},
        {L"app", static_cast<UCHAR>(PS_PROTECTED_SIGNER::App)}
    };
    
    auto it = signerMap.find(lower);
    return (it != signerMap.end()) ? std::make_optional(it->second) : std::nullopt;
}

/**
 * @brief Gets recommended signature level for signer type
 * 
 * @param signerType Signer type enumeration value
 * @return std::optional<UCHAR> Signature level or nullopt
 */
std::optional<UCHAR> GetSignatureLevel(UCHAR signerType) noexcept
{
    switch (static_cast<PS_PROTECTED_SIGNER>(signerType)) {
        case PS_PROTECTED_SIGNER::Windows:
        case PS_PROTECTED_SIGNER::WinTcb:
        case PS_PROTECTED_SIGNER::WinSystem:
            return 0x0F; // Microsoft signature
        case PS_PROTECTED_SIGNER::Antimalware:
            return 0x08; // Antimalware signature
        case PS_PROTECTED_SIGNER::Lsa:
            return 0x06; // LSA signature
        default:
            return 0x04; // Standard signature
    }
}

/**
 * @brief Gets recommended section signature level for signer type
 * 
 * @param signerType Signer type enumeration value
 * @return std::optional<UCHAR> Section signature level or nullopt
 */
std::optional<UCHAR> GetSectionSignatureLevel(UCHAR signerType) noexcept
{
    // Usually same as signature level for most processes
    return GetSignatureLevel(signerType);
}

// ============================================================================
// MEMORY OPERATION UTILITIES  
// ============================================================================

/**
 * @brief Comprehensive process dumpability analysis
 * 
 * Evaluates multiple factors to determine if a process can be successfully dumped:
 * - Protection level and signer type
 * - System process restrictions
 * - Known undumpable processes
 * - Memory access permissions
 * 
 * @param pid Target process ID
 * @param processName Process name for additional validation
 * @param protectionLevel Current protection level
 * @param signerType Digital signature authority
 * @return ProcessDumpability Structured result with boolean and reason
 */
ProcessDumpability CanDumpProcess(DWORD pid, const std::wstring& processName, 
                                  UCHAR protectionLevel, UCHAR signerType) noexcept
{
    ProcessDumpability result;
    result.CanDump = false;

    // Known undumpable system processes
    static const std::unordered_set<DWORD> undumpablePids = {
        4, 188, 232, 3052
    };

    static const std::unordered_set<std::wstring> undumpableNames = {
        L"System", L"Secure System", L"Registry", L"Memory Compression"
    };

    if (undumpablePids.find(pid) != undumpablePids.end()) {
        result.CanDump = false;
        result.Reason = L"System kernel process - undumpable by design";
        return result;
    }

    if (undumpableNames.find(processName) != undumpableNames.end()) {
        result.CanDump = false;
        
        if (processName == L"System") {
            result.Reason = L"Windows kernel (PID 4) - undumpable by design";
        } else if (processName == L"Secure System") {
            result.Reason = L"VBS/VSM protected - requires Secure Kernel access";
        } else if (processName == L"Registry") {
            result.Reason = L"Kernel registry subsystem - undumpable by design";
        } else {
            result.Reason = L"System process - undumpable by design";
        }
        return result;
    }

    // Handle Windows Defender processes - dynamically generate required protection
    if (processName == L"MsMpEng.exe" || processName == L"MpDefenderCoreService.exe" || 
        processName == L"NisSrv.exe") {
        result.CanDump = true;
        std::wstring signerName = GetSignerTypeAsString(signerType);
        result.Reason = L"Protected - requires PPL-" + signerName + L" or higher";
        return result;
    }

    // SecurityHealthService
    if (processName == L"SecurityHealthService.exe") {
        result.CanDump = true;
        result.Reason = L"Protected - requires PPL-Windows or higher";
        return result;
    }

    // Generic protected process - use actual signer
    if (protectionLevel > 0) {
        result.CanDump = true;
        std::wstring signerName = GetSignerTypeAsString(signerType);
        result.Reason = L"Protected - requires PPL-" + signerName + L" or higher";
        return result;
    }

    // Default - unprotected process
    result.CanDump = true;
    result.Reason = L"Unprotected process - standard dump privileges sufficient";
    return result;
}

// ============================================================================
// KERNEL ADDRESS RESOLUTION
// ============================================================================

/**
 * @brief Resolves kernel base address using multiple detection methods
 * 
 * Attempts resolution in order:
 * 1. NtQuerySystemInformation with SystemModuleInformation
 * 2. Cached value (expires after 60 seconds)
 * 
 * @return std::optional<ULONG_PTR> Kernel base address or nullopt on failure
 * 
 * @warning Requires administrator privileges for accurate resolution
 */
std::optional<ULONG_PTR> GetKernelBaseAddress() noexcept
{
    static ULONG_PTR cachedBase = 0;
    static DWORD lastCheck = 0;
    
    const DWORD currentTick = static_cast<DWORD>(GetTickCount64());
    if (cachedBase != 0 && (currentTick - lastCheck) < 60000) {
        return cachedBase;
    }
    
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        return std::nullopt;
    }

    auto pNtQuerySystemInformation = reinterpret_cast<NTQUERYSYSTEMINFORMATION>(
        GetProcAddress(hNtdll, "NtQuerySystemInformation"));
    
    if (!pNtQuerySystemInformation) {
        return std::nullopt;
    }

    ULONG bufferSize = 0;
    NTSTATUS status = pNtQuerySystemInformation(
        SystemModuleInformation, 
        nullptr, 
        0, 
        &bufferSize
    );

    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        return std::nullopt;
    }

    std::vector<BYTE> buffer(bufferSize);
    status = pNtQuerySystemInformation(
        SystemModuleInformation,
        buffer.data(),
        bufferSize,
        &bufferSize
    );

    if (status != 0) { // NT_SUCCESS check
        return std::nullopt;
    }

    auto modules = reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(buffer.data());
    if (modules->Count > 0) {
        cachedBase = reinterpret_cast<ULONG_PTR>(modules->Modules[0].ImageBase);
        lastCheck = currentTick;
        return cachedBase;
    }

    return std::nullopt;
}

// ============================================================================
// FILE OPERATION UTILITIES
// ============================================================================

/**
 * @brief Reads entire file into byte vector
 * 
 * @param filePath Path to file to read
 * @return std::vector<BYTE> File contents or empty vector on failure
 */
std::vector<BYTE> ReadFile(const std::wstring& filePath) noexcept
{
    HANDLE hFile = CreateFileW(
        filePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        DEBUG(L"CreateFileW failed for %s: %d", filePath.c_str(), GetLastError());
        return {};
    }

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        DEBUG(L"GetFileSizeEx failed: %d", GetLastError());
        CloseHandle(hFile);
        return {};
    }

    if (fileSize.QuadPart == 0 || fileSize.QuadPart > 0x10000000) { // 256MB limit
        DEBUG(L"Invalid file size: %lld", fileSize.QuadPart);
        CloseHandle(hFile);
        return {};
    }

    std::vector<BYTE> buffer(static_cast<size_t>(fileSize.QuadPart));
    DWORD bytesRead = 0;

    if (!::ReadFile(hFile, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr) || 
        bytesRead != buffer.size()) {
        DEBUG(L"ReadFile failed: %d, read %d/%zu bytes", 
              GetLastError(), bytesRead, buffer.size());
        CloseHandle(hFile);
        return {};
    }

    CloseHandle(hFile);
    return buffer;
}

/**
 * @brief Reads embedded resource from executable
 * 
 * @param resourceId Resource identifier
 * @param resourceType Resource type (e.g., RT_RCDATA)
 * @return std::vector<BYTE> Resource data or empty vector on failure
 */
std::vector<BYTE> ReadResource(int resourceId, const wchar_t* resourceType)
{
    const HRSRC hRes = FindResource(nullptr, MAKEINTRESOURCE(resourceId), resourceType);
    if (!hRes) {
        DEBUG(L"FindResource failed: %d", GetLastError());
        return {};
    }
    
    const HGLOBAL hData = LoadResource(nullptr, hRes);
    if (!hData) {
        DEBUG(L"LoadResource failed: %d", GetLastError());
        return {};
    }
    
    const DWORD dataSize = SizeofResource(nullptr, hRes);
    if (dataSize == 0) {
        DEBUG(L"Resource size is 0");
        return {};
    }
    
    void* pData = LockResource(hData);
    if (!pData) {
        DEBUG(L"LockResource failed");
        return {};
    }
    
    return std::vector<BYTE>(static_cast<const BYTE*>(pData), 
                            static_cast<const BYTE*>(pData) + dataSize);
}

/**
 * @brief Force delete a file, handling read-only, system, and hidden attributes
 * 
 * @param path File path to delete
 * @return bool true if file deleted successfully
 */
bool ForceDeleteFile(const std::wstring& path) noexcept
{
    // First, try normal delete
    if (DeleteFileW(path.c_str())) {
        return true;
    }

    // If that fails, try to remove attributes and delete again
    DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        // Remove read-only, system, hidden attributes
        SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_NORMAL);
    }

    // Try delete again
    if (DeleteFileW(path.c_str())) {
        return true;
    }

    // Final attempt: move to temp and delete after reboot if needed
    wchar_t tempPath[MAX_PATH];
    if (GetTempPathW(MAX_PATH, tempPath)) {
        wchar_t tempFile[MAX_PATH];
        if (GetTempFileNameW(tempPath, L"KVC", 0, tempFile)) {
            if (MoveFileExW(path.c_str(), tempFile, MOVEFILE_REPLACE_EXISTING)) {
                MoveFileExW(tempFile, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
                return true;
            }
        }
    }

    return false;
}

/**
 * @brief Writes byte vector to file with comprehensive error handling
 * 
 * @param filePath Path to output file
 * @param data Data to write
 * @return bool true if write successful
 */
bool WriteFile(const std::wstring& filePath, const std::vector<BYTE>& data) noexcept
{
    if (data.empty()) {
        DEBUG(L"Attempted to write empty data");
        return false;
    }
    
    // Ensure parent directory exists
    const fs::path path = filePath;
    std::error_code ec;
    fs::create_directories(path.parent_path(), ec);
    
    // First, try to delete existing file if it exists
    if (fs::exists(path)) {
        if (!ForceDeleteFile(filePath)) {
            // If we can't delete, try to overwrite by opening with FILE_FLAG_BACKUP_SEMANTICS
            HANDLE hFile = CreateFileW(filePath.c_str(), 
                                    GENERIC_WRITE, 
                                    0,
                                    nullptr, 
                                    OPEN_EXISTING, 
                                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
                                    nullptr);
            if (hFile != INVALID_HANDLE_VALUE) {
                CloseHandle(hFile);
            } else {
                DEBUG(L"Failed to delete or overwrite existing file: %s", filePath.c_str());
                return false;
            }
        }
    }

    // Primary write attempt with optimized flags
    HANDLE hFile = CreateFileW(filePath.c_str(), 
                               GENERIC_WRITE, 
                               0,  // No sharing during write
                               nullptr, 
                               CREATE_ALWAYS, 
                               FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                               nullptr);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        DEBUG(L"CreateFileW failed for %s: %d", filePath.c_str(), GetLastError());
        return false;
    }
    
    // Write data in chunks for large files to handle memory pressure
    constexpr DWORD CHUNK_SIZE = 64 * 1024; // 64KB chunks
    DWORD totalWritten = 0;
    const DWORD totalSize = static_cast<DWORD>(data.size());
    
    while (totalWritten < totalSize) {
        const DWORD bytesToWrite = std::min(CHUNK_SIZE, totalSize - totalWritten);
        DWORD bytesWritten;
        
        if (!::WriteFile(hFile, data.data() + totalWritten, bytesToWrite, &bytesWritten, nullptr)) {
            DEBUG(L"WriteFile failed: %d", GetLastError());
            CloseHandle(hFile);
            return false;
        }
        
        if (bytesWritten != bytesToWrite) {
            DEBUG(L"Incomplete write: %d/%d bytes", bytesWritten, bytesToWrite);
            CloseHandle(hFile);
            return false;
        }
        
        totalWritten += bytesWritten;
    }

    CloseHandle(hFile);
    DEBUG(L"Successfully wrote %d bytes to %s", totalSize, filePath.c_str());
    return true;
}

// ============================================================================
// CRYPTOGRAPHIC UTILITIES
// ============================================================================

/**
 * @brief Decrypts data using XOR cipher with provided key
 * 
 * @param encryptedData Data to decrypt
 * @param key XOR key for decryption
 * @return std::vector<BYTE> Decrypted data or empty vector on failure
 */
std::vector<BYTE> DecryptXOR(const std::vector<BYTE>& encryptedData, 
                            const std::array<BYTE, 7>& key) noexcept
{
    if (encryptedData.empty()) {
        return {};
    }

    std::vector<BYTE> decryptedData = encryptedData;
    
    for (size_t i = 0; i < decryptedData.size(); ++i) {
        decryptedData[i] ^= key[i % key.size()];
    }
    
    return decryptedData;
}

/**
 * @brief Gets PE file length from data with proper validation
 * 
 * @param data Binary data containing PE file
 * @param offset Starting offset in data
 * @return std::optional<size_t> PE file length or nullopt on invalid PE
 */
std::optional<size_t> GetPEFileLength(const std::vector<BYTE>& data, size_t offset) noexcept
{
    if (offset + sizeof(IMAGE_DOS_HEADER) > data.size()) {
        return std::nullopt;
    }
    
    const IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(data.data() + offset);
    
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return std::nullopt;
    }
    
    if (offset + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > data.size()) {
        return std::nullopt;
    }
    
    const IMAGE_NT_HEADERS* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        data.data() + offset + dosHeader->e_lfanew
    );
    
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return std::nullopt;
    }
    
    // Calculate total file size from sections
    DWORD maxOffset = 0;
    const IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHeaders);
    
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
        DWORD sectionEnd = sections[i].PointerToRawData + sections[i].SizeOfRawData;
        if (sectionEnd > maxOffset) {
            maxOffset = sectionEnd;
        }
    }
    
    return maxOffset;
}

/**
 * @brief Splits combined PE binary into separate components
 * 
 * @param combinedData Combined PE data containing multiple binaries
 * @param firstPE Output for first PE component
 * @param secondPE Output for second PE component
 * @return bool true if splitting successful
 */
bool SplitCombinedPE(const std::vector<BYTE>& combinedData,
                    std::vector<BYTE>& firstPE, 
                    std::vector<BYTE>& secondPE) noexcept
{
    if (combinedData.size() < sizeof(IMAGE_DOS_HEADER) * 2) {
        DEBUG(L"Combined data too small for two PE files");
        return false;
    }

    // Get length of first PE
    auto firstLength = GetPEFileLength(combinedData, 0);
    if (!firstLength) {
        DEBUG(L"Failed to parse first PE file");
        return false;
    }
    
    if (*firstLength >= combinedData.size()) {
        DEBUG(L"First PE file length exceeds combined data size");
        return false;
    }
    
    // Validate second PE
    auto secondLength = GetPEFileLength(combinedData, *firstLength);
    if (!secondLength) {
        DEBUG(L"Failed to parse second PE file");
        return false;
    }
    
    if (*firstLength + *secondLength > combinedData.size()) {
        DEBUG(L"Combined PE lengths exceed data size");
        return false;
    }
    
    // Extract both PE files
    firstPE.assign(combinedData.begin(), combinedData.begin() + *firstLength);
    secondPE.assign(combinedData.begin() + *firstLength, 
                   combinedData.begin() + *firstLength + *secondLength);
    
    DEBUG(L"Successfully split PE: first=%zu bytes, second=%zu bytes", 
          firstPE.size(), secondPE.size());
    
    return !firstPE.empty() && !secondPE.empty();
}

// ============================================================================
// STRING AND VALIDATION UTILITIES
// ============================================================================

/**
 * @brief Checks if string represents a numeric value
 * 
 * @param str String to check
 * @return bool true if string contains only digits
 */
bool IsNumeric(const std::wstring& str) noexcept
{
    if (str.empty()) return false;
    
    return std::all_of(str.begin(), str.end(), [](wchar_t c) {
        return c >= L'0' && c <= L'9';
    });
}

/**
 * @brief Parses PID from string with validation
 * 
 * @param pidStr String containing PID
 * @return std::optional<DWORD> Parsed PID or nullopt on failure
 */
std::optional<DWORD> ParsePid(const std::wstring& pidStr) noexcept
{
    if (!IsNumeric(pidStr)) {
        return std::nullopt;
    }
    
    try {
        DWORD pid = std::stoul(pidStr);
        return (pid > 0 && pid <= 0xFFFFFFFF) ? std::optional<DWORD>(pid) : std::nullopt;
    }
    catch (...) {
        return std::nullopt;
    }
}

/**
 * @brief Converts hex string to byte array
 * 
 * @param hexString Hex string to convert (supports 0x prefix and separators)
 * @param bytes Output byte vector
 * @return bool true if conversion successful
 */
bool HexStringToBytes(const std::wstring& hexString, std::vector<BYTE>& bytes) noexcept
{
    if (hexString.empty()) {
        bytes.clear();
        return true;
    }
    
    // Handle common prefixes: 0x, 0X
    size_t startPos = 0;
    if (hexString.length() >= 2 && hexString[0] == L'0' && 
        (hexString[1] == L'x' || hexString[1] == L'X')) {
        startPos = 2;
    }
    
    // Build clean hex string - filter out common separators
    std::wstring cleanHex;
    cleanHex.reserve(hexString.length());
    
    for (size_t i = startPos; i < hexString.length(); ++i) {
        wchar_t c = hexString[i];
        if ((c >= L'0' && c <= L'9') || 
            (c >= L'a' && c <= L'f') || 
            (c >= L'A' && c <= L'F')) {
            cleanHex += c;
        }
        // Skip spaces, commas, dashes, etc.
    }
    
    if (cleanHex.empty() || (cleanHex.length() % 2) != 0) {
        return false;
    }
    
    bytes.clear();
    bytes.reserve(cleanHex.length() / 2);
    
    for (size_t i = 0; i < cleanHex.length(); i += 2) {
        std::wstring byteStr = cleanHex.substr(i, 2);
        wchar_t* end;
        BYTE byte = static_cast<BYTE>(wcstoul(byteStr.c_str(), &end, 16));
        
        if (*end != L'\0') {
            return false;
        }
        
        bytes.push_back(byte);
    }
    
    return true;
}

/**
 * @brief Validates hex string format
 * 
 * @param hexString String to validate
 * @return bool true if valid hex string
 */
bool IsValidHexString(const std::wstring& hexString) noexcept
{
    std::vector<BYTE> dummy;
    return HexStringToBytes(hexString, dummy);
}

/**
 * @brief Enables console virtual terminal processing for colors
 * 
 * @return bool true if virtual terminal enabled successfully
 */
bool EnableConsoleVirtualTerminal() noexcept
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD consoleMode = 0;
    if (!GetConsoleMode(hConsole, &consoleMode)) {
        return false;
    }

    consoleMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    return SetConsoleMode(hConsole, consoleMode);
}

/**
 * @brief Gets display color for process based on protection and signature
 * 
 * @param signerType Process signer type
 * @param signatureLevel Executable signature level
 * @param sectionSignatureLevel DLL signature level
 * @return const wchar_t* ANSI color code for console output
 */
const wchar_t* GetProcessDisplayColor(UCHAR signerType, UCHAR signatureLevel, 
                                     UCHAR sectionSignatureLevel) noexcept
{
    // First, check the most specific cases
    if (signatureLevel == 0x1e && sectionSignatureLevel == 0x1c) {
        return ProcessColors::PURPLE;  // Kernel process
    }
    
    // Then check signerType from most to least restrictive
    if (signerType == static_cast<UCHAR>(PS_PROTECTED_SIGNER::Lsa)) {
        return ProcessColors::RED;
    }
    
    if (signerType == static_cast<UCHAR>(PS_PROTECTED_SIGNER::WinTcb)) {
        return ProcessColors::GREEN;
    }
    
    if (signerType == static_cast<UCHAR>(PS_PROTECTED_SIGNER::WinSystem)) {
        return ProcessColors::BLUE;
    }
    
    if (signerType == static_cast<UCHAR>(PS_PROTECTED_SIGNER::Windows)) {
        return ProcessColors::CYAN;
    }
    
    if (signerType == static_cast<UCHAR>(PS_PROTECTED_SIGNER::Antimalware)) {
        return ProcessColors::YELLOW;
    }
    
    // Finally, check for unsigned/unverified signatures
    bool hasUncheckedSignatures = (signatureLevel == 0x00 || sectionSignatureLevel == 0x00);
    if (hasUncheckedSignatures) {
        return ProcessColors::BLUE;
    }
    
    // Default color for all remaining cases
    return ProcessColors::YELLOW;
}

#include <fdi.h>
#pragma comment(lib, "cabinet.lib")

// ============================================================================
// CAB DECOMPRESSION
// ============================================================================

// FDI callback structures
struct MemoryReadContext {
    const BYTE* data;
    size_t size;
    size_t offset;
};

// Global context for FDI callbacks
static MemoryReadContext* g_cabContext = nullptr;
static std::vector<BYTE>* g_currentFileData = nullptr;

// FDI memory allocation
static void* DIAMONDAPI fdi_alloc(ULONG cb) {
    return malloc(cb);
}

// FDI memory deallocation
static void DIAMONDAPI fdi_free(void* pv) {
    free(pv);
}

// FDI file open - returns memory context
static INT_PTR DIAMONDAPI fdi_open(char* pszFile, int oflag, int pmode) {
    return g_cabContext ? (INT_PTR)g_cabContext : -1;
}

// FDI file read - reads from memory buffer
static UINT DIAMONDAPI fdi_read(INT_PTR hf, void* pv, UINT cb) {
    MemoryReadContext* ctx = (MemoryReadContext*)hf;
    if (!ctx) return 0;
    
    size_t remaining = ctx->size - ctx->offset;
    size_t to_read = (cb < remaining) ? cb : remaining;
    
    if (to_read > 0) {
        memcpy(pv, ctx->data + ctx->offset, to_read);
        ctx->offset += to_read;
    }
    
    return static_cast<UINT>(to_read);
}

// FDI file write - writes to current file buffer
static UINT DIAMONDAPI fdi_write(INT_PTR hf, void* pv, UINT cb) {
    if (g_currentFileData && cb > 0) {
        BYTE* data = static_cast<BYTE*>(pv);
        g_currentFileData->insert(g_currentFileData->end(), data, data + cb);
    }
    return cb;
}

// FDI file close
static int DIAMONDAPI fdi_close(INT_PTR hf) {
    g_currentFileData = nullptr;
    return 0;
}

// FDI file seek - seeks in memory buffer
static LONG DIAMONDAPI fdi_seek(INT_PTR hf, LONG dist, int seektype) {
    MemoryReadContext* ctx = (MemoryReadContext*)hf;
    if (!ctx) return -1;
    
    switch (seektype) {
        case SEEK_SET: ctx->offset = dist; break;
        case SEEK_CUR: ctx->offset += dist; break;
        case SEEK_END: ctx->offset = ctx->size + dist; break;
    }
    
    return static_cast<LONG>(ctx->offset);
}

// FDI notification callback - handles file extraction
static INT_PTR DIAMONDAPI fdi_notify(FDINOTIFICATIONTYPE fdint, PFDINOTIFICATION pfdin) {
    std::vector<BYTE>* extractedData = static_cast<std::vector<BYTE>*>(pfdin->pv);
    
    switch (fdint) {
        case fdintCOPY_FILE:
            // Extract kvc.evtx file
            if (pfdin->psz1) {
                std::string filename = pfdin->psz1;
                if (filename.find("kvc.evtx") != std::string::npos) {
                    g_currentFileData = extractedData;
                    return (INT_PTR)g_cabContext;
                }
            }
            return 0;
            
        case fdintCLOSE_FILE_INFO:
            g_currentFileData = nullptr;
            return TRUE;
            
        default:
            break;
    }
    return 0;
}

// Decompress CAB from memory and extract kvc.evtx
std::vector<BYTE> DecompressCABFromMemory(const BYTE* cabData, size_t cabSize) noexcept
{
    std::vector<BYTE> extractedFile;
    
    MemoryReadContext ctx = { cabData, cabSize, 0 };
    g_cabContext = &ctx;
    
    ERF erf{};
    HFDI hfdi = FDICreate(fdi_alloc, fdi_free, fdi_open, fdi_read, 
                          fdi_write, fdi_close, fdi_seek, cpuUNKNOWN, &erf);
    
    if (!hfdi) {
        DEBUG(L"FDICreate failed: %d", erf.erfOper);
        g_cabContext = nullptr;
        return extractedFile;
    }
    
    char cabName[] = "memory.cab";
    char cabPath[] = "";
    
    BOOL result = FDICopy(hfdi, cabName, cabPath, 0, fdi_notify, nullptr, &extractedFile);
    
    FDIDestroy(hfdi);
    g_cabContext = nullptr;
    
    if (!result) {
        DEBUG(L"FDICopy failed: %d", erf.erfOper);
        return std::vector<BYTE>();
    }
    
    return extractedFile;
}

// Split kvc.evtx into kvc.sys (driver) and ExpIorerFrame.dll
bool SplitKvcEvtx(const std::vector<BYTE>& kvcData, 
                  std::vector<BYTE>& outKvcSys, 
                  std::vector<BYTE>& outDll) noexcept
{
    if (kvcData.size() < 2) {
        DEBUG(L"kvc.evtx too small");
        return false;
    }
    
    // Find all MZ signatures (PE file start markers)
    std::vector<size_t> peOffsets;
    for (size_t i = 0; i < kvcData.size() - 1; i++) {
        if (kvcData[i] == 0x4D && kvcData[i + 1] == 0x5A) {  // MZ signature
            peOffsets.push_back(i);
        }
    }
    
    if (peOffsets.size() != 2) {
        DEBUG(L"Expected 2 PE files in kvc.evtx, found %zu", peOffsets.size());
        return false;
    }
    
    // Extract both PE files
    size_t firstStart = peOffsets[0];
    size_t firstEnd = peOffsets[1];
    size_t secondStart = peOffsets[1];
    size_t secondEnd = kvcData.size();
    
    std::vector<BYTE> firstPE(kvcData.begin() + firstStart, kvcData.begin() + firstEnd);
    std::vector<BYTE> secondPE(kvcData.begin() + secondStart, kvcData.begin() + secondEnd);
    
    // Identify which is driver vs DLL by checking PE subsystem
    auto isDriver = [](const std::vector<BYTE>& pe) -> bool {
        if (pe.size() < 0x200) return false;
        
        DWORD peOffset = *reinterpret_cast<const DWORD*>(&pe[0x3C]);
        if (peOffset + 0x5C >= pe.size()) return false;
        
        WORD subsystem = *reinterpret_cast<const WORD*>(&pe[peOffset + 0x5C]);
        return (subsystem == 1);  // IMAGE_SUBSYSTEM_NATIVE = kernel driver
    };
    
    bool firstIsDriver = isDriver(firstPE);
    bool secondIsDriver = isDriver(secondPE);
    
    // Assign outputs based on subsystem detection
    if (firstIsDriver && !secondIsDriver) {
        outKvcSys = firstPE;
        outDll = secondPE;
    } else if (!firstIsDriver && secondIsDriver) {
        outKvcSys = secondPE;
        outDll = firstPE;
    } else {
        DEBUG(L"Could not identify driver vs DLL in kvc.evtx");
        return false;
    }
    
    DEBUG(L"Split kvc.evtx: kvc.sys=%zu bytes, ExpIorerFrame.dll=%zu bytes",
          outKvcSys.size(), outDll.size());
    
    return true;
}

// Extract kvc.sys and ExpIorerFrame.dll from resource CAB
bool ExtractResourceComponents(int resourceId, 
                                std::vector<BYTE>& outKvcSys, 
                                std::vector<BYTE>& outDll) noexcept
{
    DEBUG(L"[EXTRACT] Loading resource %d", resourceId);
    
    // Step 1: Load resource
    auto resourceData = ReadResource(resourceId, RT_RCDATA);
    if (resourceData.size() <= 3774) {
        ERROR(L"[EXTRACT] Resource too small");
        return false;
    }
    
    // Step 2: Skip icon (3774 bytes)
    std::vector<BYTE> encryptedCAB(
        resourceData.begin() + 3774, 
        resourceData.end()
    );
    
    DEBUG(L"[EXTRACT] Encrypted CAB size: %zu bytes", encryptedCAB.size());
    
    // Step 3: XOR decrypt
    auto decryptedCAB = DecryptXOR(encryptedCAB, KVC_XOR_KEY);
    if (decryptedCAB.empty()) {
        ERROR(L"[EXTRACT] XOR decryption failed");
        return false;
    }
    
    // Step 4: CAB decompress → kvc.evtx
    auto kvcEvtxData = DecompressCABFromMemory(decryptedCAB.data(), decryptedCAB.size());
    if (kvcEvtxData.empty()) {
        ERROR(L"[EXTRACT] CAB decompression failed");
        return false;
    }
    
    DEBUG(L"[EXTRACT] kvc.evtx extracted: %zu bytes", kvcEvtxData.size());
    
    // Step 5: Split into kvc.sys + ExpIorerFrame.dll
    if (!SplitKvcEvtx(kvcEvtxData, outKvcSys, outDll)) {
        ERROR(L"[EXTRACT] Failed to split kvc.evtx");
        return false;
    }
    
    DEBUG(L"[EXTRACT] Success - kvc.sys: %zu bytes, ExpIorerFrame.dll: %zu bytes",
          outKvcSys.size(), outDll.size());
    
    return true;
}

} // namespace Utils