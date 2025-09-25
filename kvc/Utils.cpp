/*******************************************************************************
  _  ____     ______ 
 | |/ /\ \   / / ___|
 | ' /  \ \ / / |    
 | . \   \ V /| |___ 
 |_|\_\   \_/  \____|

The **Kernel Vulnerability Capabilities (KVC)** framework represents a paradigm shift in Windows security research, 
offering unprecedented access to modern Windows internals through sophisticated ring-0 operations. Originally conceived 
as "Kernel Process Control," the framework has evolved to emphasize not just control, but the complete **exploitation 
of kernel-level primitives** for legitimate security research and penetration testing.

KVC addresses the critical gap left by traditional forensic tools that have become obsolete in the face of modern Windows 
security hardening. Where tools like ProcDump and Process Explorer fail against Protected Process Light (PPL) and Antimalware 
Protected Interface (AMSI) boundaries, KVC succeeds by operating at the kernel level, manipulating the very structures 
that define these protections.

  -----------------------------------------------------------------------------
  Author : Marek Wesołowski
  Email  : marek@wesolowski.eu.org
  Phone  : +48 607 440 283 (Tel/WhatsApp)
  Date   : 04-09-2025

*******************************************************************************/

// Utils.cpp - Fixed compilation issues with NtQuerySystemInformation
#include "Utils.h"
#include "common.h"
#include <psapi.h>
#include <tlhelp32.h>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <cctype>
#include <charconv>
#include <fstream>
#include <vector>
#include <filesystem>
#include "resource.h"

namespace fs = std::filesystem;

#pragma comment(lib, "psapi.lib")


namespace Utils
{
    // Optimized kernel address resolution with inline assembly hints
    std::optional<ULONG_PTR> GetKernelBaseAddress() noexcept {
        static ULONG_PTR cachedBase = 0;
        static DWORD lastCheck = 0;
        
        const DWORD currentTick = static_cast<DWORD>(GetTickCount64());
        if (cachedBase != 0 && (currentTick - lastCheck) < 60000) { // Cache for 1 minute
            return cachedBase;
        }
        
        // Method 1: NtQuerySystemInformation
        typedef NTSTATUS(WINAPI* pNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
        const HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return std::nullopt;
        
        const pNtQuerySystemInformation NtQuerySystemInformation = 
            reinterpret_cast<pNtQuerySystemInformation>(
                GetProcAddress(hNtdll, "NtQuerySystemInformation"));
        if (!NtQuerySystemInformation) return std::nullopt;
        
        ULONG bufferSize = 0;
        NtQuerySystemInformation(11, nullptr, 0, &bufferSize); // SystemModuleInformation
        
        if (bufferSize == 0) return std::nullopt;
        
        std::vector<BYTE> buffer(bufferSize);
        const NTSTATUS status = NtQuerySystemInformation(11, buffer.data(), bufferSize, nullptr);
        
        if (status == 0) { // STATUS_SUCCESS
            struct SYSTEM_MODULE {
                ULONG_PTR Reserved[2];
                PVOID Base;
                ULONG Size;
                ULONG Flags;
                USHORT Index;
                USHORT Unknown;
                USHORT LoadCount;
                USHORT ModuleNameOffset;
                CHAR ImageName[256];
            };
            
            struct SYSTEM_MODULE_INFORMATION {
                ULONG ModulesCount;
                SYSTEM_MODULE Modules[1];
            };
            
            const auto* moduleInfo = reinterpret_cast<const SYSTEM_MODULE_INFORMATION*>(buffer.data());
            if (moduleInfo->ModulesCount > 0) {
                cachedBase = reinterpret_cast<ULONG_PTR>(moduleInfo->Modules[0].Base);
                lastCheck = currentTick;
                return cachedBase;
            }
        }
        
        return std::nullopt;
    }

    // Optimized PID parsing with zero-allocation validation
    std::optional<DWORD> ParsePid(const std::wstring& pidStr) noexcept {
        if (pidStr.empty() || pidStr.size() > 10) return std::nullopt;

        DWORD result = 0;
        for (const wchar_t ch : pidStr) {
            if (ch < L'0' || ch > L'9') return std::nullopt;
            
            if (result > (UINT32_MAX - (ch - L'0')) / 10) return std::nullopt;
            
            result = result * 10 + (ch - L'0');
        }
        
        return result;
    }

    // Optimized numeric validation - single pass
    bool IsNumeric(const std::wstring& str) noexcept {
        return !str.empty() && 
               std::all_of(str.begin(), str.end(), [](wchar_t ch) { 
                   return ch >= L'0' && ch <= L'9'; 
               });
    }

    // Force delete a file, handling read-only, system, and hidden attributes
    bool ForceDeleteFile(const std::wstring& path) noexcept {
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

    // Enhanced file writing with comprehensive error handling and retry logic
    bool WriteFile(const std::wstring& path, const std::vector<BYTE>& data) {
        if (data.empty()) return false;
        
        // Ensure parent directory exists
        const fs::path filePath = path;
        std::error_code ec;
        fs::create_directories(filePath.parent_path(), ec);
        
        // First, try to delete existing file if it exists
        if (fs::exists(filePath)) {
            if (!ForceDeleteFile(path)) {
                // If we can't delete, try to overwrite by opening with FILE_FLAG_BACKUP_SEMANTICS
                HANDLE hFile = CreateFileW(path.c_str(), 
                                        GENERIC_WRITE, 
                                        0,
                                        nullptr, 
                                        OPEN_EXISTING, 
                                        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
                                        nullptr);
                if (hFile != INVALID_HANDLE_VALUE) {
                    CloseHandle(hFile);
                } else {
                    return false;
                }
            }
        }

        // Primary write attempt with optimized flags
        HANDLE hFile = CreateFileW(path.c_str(), 
                                   GENERIC_WRITE, 
                                   0,  // No sharing during write
                                   nullptr, 
                                   CREATE_ALWAYS, 
                                   FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                                   nullptr);
        
        if (hFile == INVALID_HANDLE_VALUE) {
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
                CloseHandle(hFile);
                DeleteFileW(path.c_str()); // Cleanup partial file
                return false;
            }
            
            if (bytesWritten != bytesToWrite) {
                CloseHandle(hFile);
                DeleteFileW(path.c_str()); // Cleanup partial file
                return false;
            }
            
            totalWritten += bytesWritten;
        }
        
        // Ensure data is flushed to disk
        FlushFileBuffers(hFile);
        CloseHandle(hFile);
        
        return true;
    }

    // Optimized file reading with memory mapping for large files
    std::vector<BYTE> ReadFile(const std::wstring& path) {
        HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, 
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            return {};
        }
        
        LARGE_INTEGER fileSize;
        if (!GetFileSizeEx(hFile, &fileSize)) {
            CloseHandle(hFile);
            return {};
        }
        
        // Use memory mapping for files > 64KB for better performance
        if (fileSize.QuadPart > 65536) {
            HANDLE hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
            if (hMapping) {
                void* pData = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
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
        
        // Fallback to standard read for small files or mapping failure
        std::vector<BYTE> buffer(static_cast<size_t>(fileSize.QuadPart));
        DWORD bytesRead;
        
        BOOL success = ::ReadFile(hFile, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr);
        CloseHandle(hFile);
        
        if (!success || bytesRead != buffer.size()) {
            return {};
        }
        
        return buffer;
    }

    // Enhanced resource extraction with validation
    std::vector<BYTE> ReadResource(int resourceId, const wchar_t* resourceType) {
        const HRSRC hRes = FindResource(nullptr, MAKEINTRESOURCE(resourceId), resourceType);
        if (!hRes) return {};
        
        const HGLOBAL hData = LoadResource(nullptr, hRes);
        if (!hData) return {};
        
        const DWORD dataSize = SizeofResource(nullptr, hRes);
        if (dataSize == 0) return {};
        
        void* pData = LockResource(hData);
        if (!pData) return {};
        
        return std::vector<BYTE>(static_cast<const BYTE*>(pData), 
                                static_cast<const BYTE*>(pData) + dataSize);
    }

    // Advanced process name resolution with caching
    static std::unordered_map<DWORD, std::wstring> g_processCache;
    static DWORD g_lastCacheUpdate = 0;
    
    std::wstring ResolveUnknownProcessLocal(DWORD pid, ULONG_PTR kernelAddress, UCHAR protectionLevel, UCHAR signerType) noexcept {
        // Cache management - refresh every 30 seconds
        const DWORD currentTick = static_cast<DWORD>(GetTickCount64());
        if (currentTick - g_lastCacheUpdate > 30000) {
            g_processCache.clear();
            g_lastCacheUpdate = currentTick;
        }
        
        // Check cache first
        const auto cacheIt = g_processCache.find(pid);
        if (cacheIt != g_processCache.end()) {
            return cacheIt->second;
        }
        
        std::wstring processName = L"Unknown";
        
        // Try multiple resolution methods
        const HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProcess) {
            wchar_t imageName[MAX_PATH];
            DWORD size = MAX_PATH;
            
            // Method 1: QueryFullProcessImageName (Vista+)
            if (QueryFullProcessImageNameW(hProcess, 0, imageName, &size)) {
                processName = fs::path(imageName).filename().wstring();
            } else {
                // Method 2: GetProcessImageFileName fallback
                if (GetProcessImageFileNameW(hProcess, imageName, MAX_PATH)) {
                    const std::wstring fullPath = imageName;
                    const size_t lastSlash = fullPath.find_last_of(L'\\');
                    if (lastSlash != std::wstring::npos) {
                        processName = fullPath.substr(lastSlash + 1);
                    }
                }
            }
            CloseHandle(hProcess);
        }
        
        // Method 3: Toolhelp snapshot fallback for system processes
        if (processName == L"Unknown") {
            const HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe32;
                pe32.dwSize = sizeof(pe32);
                
                if (Process32FirstW(hSnapshot, &pe32)) {
                    do {
                        if (pe32.th32ProcessID == pid) {
                            processName = pe32.szExeFile;
                            break;
                        }
                    } while (Process32NextW(hSnapshot, &pe32));
                }
                CloseHandle(hSnapshot);
            }
        }
        
        // Cache the result
        g_processCache[pid] = processName;
        return processName;
    }

    // Static string lookup tables for performance
    static constexpr const wchar_t* PROTECTION_LEVELS[] = {
        L"None", L"PPL-Authenticode", L"PPL-Antimalware", L"PPL-App", 
        L"PP-Authenticode", L"PP-Antimalware", L"PP-App", L"PP-Windows"
    };
    
    static constexpr const wchar_t* SIGNER_TYPES[] = {
        L"None", L"Authenticode", L"CodeGen", L"Antimalware", 
        L"Lsa", L"Windows", L"WinTcb", L"WinSystem", L"App"
    };

    // Multi-method process name resolution with fallbacks
    std::wstring GetProcessName(DWORD pid) noexcept
    {
        if (pid == 0)
            return L"System Idle Process";
        if (pid == 4)
            return L"System [NT Kernel Core]";

        static const std::unordered_map<DWORD, std::wstring> knownSystemPids = {
            {188, L"Secure System"},
            {232, L"Registry"}, 
            {3052, L"Memory Compression"},
            {3724, L"Memory Manager"},
            {256, L"VSM Process"},
            {264, L"VBS Process"},
            {288, L"Font Driver Host"},
            {296, L"User Mode Driver Host"}
        };

        if (auto it = knownSystemPids.find(pid); it != knownSystemPids.end()) {
            return it->second;
        }

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) {
            hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        }
        
        if (hProcess) {
            wchar_t processName[MAX_PATH] = {0};
            DWORD size = MAX_PATH;
            
            if (QueryFullProcessImageNameW(hProcess, 0, processName, &size)) {
                std::wstring fullPath(processName);
                size_t lastSlash = fullPath.find_last_of(L'\\');
                if (lastSlash != std::wstring::npos) {
                    CloseHandle(hProcess);
                    return fullPath.substr(lastSlash + 1);
                }
            }

            if (GetProcessImageFileNameW(hProcess, processName, MAX_PATH)) {
                std::wstring fullPath(processName);
                size_t lastSlash = fullPath.find_last_of(L'\\');
                if (lastSlash != std::wstring::npos) {
                    CloseHandle(hProcess);
                    return fullPath.substr(lastSlash + 1);
                }
            }
            CloseHandle(hProcess);
        }

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe;
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
        }

        return L"[Unknown]";
    }

    // Protection level string mappings with static caching
    const wchar_t* GetProtectionLevelAsString(UCHAR protectionLevel) noexcept
    {
        static const std::wstring none = L"None";
        static const std::wstring ppl = L"PPL";
        static const std::wstring pp = L"PP";
        static const std::wstring unknown = L"Unknown";

        switch (static_cast<PS_PROTECTED_TYPE>(protectionLevel))
        {
            case PS_PROTECTED_TYPE::None:           return none.c_str();
            case PS_PROTECTED_TYPE::ProtectedLight: return ppl.c_str();
            case PS_PROTECTED_TYPE::Protected:      return pp.c_str();
            default:                                return unknown.c_str();
        }
    }

    const wchar_t* GetSignerTypeAsString(UCHAR signerType) noexcept
    {
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

        switch (static_cast<PS_PROTECTED_SIGNER>(signerType))
        {
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
	
	const wchar_t* GetSignatureLevelAsString(UCHAR signatureLevel) noexcept
	{
		switch (signatureLevel) {
			case 0x00: return L"None";
			case 0x08: return L"App";
			case 0x0c: return L"Standard";     // Standard DLL verification
			case 0x1c: return L"System";       // System DLL verification  
			case 0x1e: return L"Kernel";       // Kernel EXE verification
			case 0x3c: return L"Service";      // Windows service EXE
			case 0x3e: return L"Critical";     // Critical system EXE
			case 0x07: return L"WinSystem";
			case 0x37: return L"WinSystem";
			default:
				static thread_local wchar_t buf[32];
				swprintf_s(buf, L"Unknown (0x%02x)", signatureLevel);
				return buf;
		}
	}
    // String to protection level parsing for command line input
    std::optional<UCHAR> GetProtectionLevelFromString(const std::wstring& protectionLevel) noexcept
    {
        static const std::unordered_map<std::wstring, UCHAR> levels = {
            {L"none", static_cast<UCHAR>(PS_PROTECTED_TYPE::None)},
            {L"ppl", static_cast<UCHAR>(PS_PROTECTED_TYPE::ProtectedLight)},
            {L"pp", static_cast<UCHAR>(PS_PROTECTED_TYPE::Protected)}
        };

        std::wstring lower = protectionLevel;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

        auto it = levels.find(lower);
        return (it != levels.end()) ? std::make_optional(it->second) : std::nullopt;
    }

    std::optional<UCHAR> GetSignerTypeFromString(const std::wstring& signerType) noexcept
    {
        std::wstring lower = signerType;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

        if (lower == L"none") return static_cast<UCHAR>(PS_PROTECTED_SIGNER::None);
        if (lower == L"authenticode") return static_cast<UCHAR>(PS_PROTECTED_SIGNER::Authenticode);
        if (lower == L"codegen") return static_cast<UCHAR>(PS_PROTECTED_SIGNER::CodeGen);
        if (lower == L"antimalware") return static_cast<UCHAR>(PS_PROTECTED_SIGNER::Antimalware);
        if (lower == L"lsa") return static_cast<UCHAR>(PS_PROTECTED_SIGNER::Lsa);
        if (lower == L"windows") return static_cast<UCHAR>(PS_PROTECTED_SIGNER::Windows);
        if (lower == L"wintcb") return static_cast<UCHAR>(PS_PROTECTED_SIGNER::WinTcb);
        if (lower == L"winsystem") return static_cast<UCHAR>(PS_PROTECTED_SIGNER::WinSystem);
        if (lower == L"app") return static_cast<UCHAR>(PS_PROTECTED_SIGNER::App);
        
        return std::nullopt;
    }

    // Comprehensive process dumpability analysis with detailed reasoning
    ProcessDumpability CanDumpProcess(DWORD pid, const std::wstring& processName) noexcept
    {
        ProcessDumpability result;
		result.CanDump = false; // Initialize

        // Known undumpable system processes
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

        if (undumpablePids.find(pid) != undumpablePids.end())
        {
            result.CanDump = false;
            result.Reason = L"System kernel process - undumpable by design";
            return result;
        }

        if (undumpableNames.find(processName) != undumpableNames.end())
        {
            result.CanDump = false;
            
            if (processName == L"System")
                result.Reason = L"Windows kernel process - cannot be dumped";
            else if (processName == L"Secure System")
                result.Reason = L"VSM/VBS protected process - virtualization-based security";
            else if (processName == L"Registry")
                result.Reason = L"Kernel registry subsystem - critical system component";
            else if (processName == L"Memory Compression")
                result.Reason = L"Kernel memory manager - system critical process";
            else
                result.Reason = L"System process - protected by Windows kernel";
            
            return result;
        }

        // Special case analysis for known processes
        if (processName == L"csrss.exe" || processName == L"csrss") 
        {
            result.CanDump = true;
            result.Reason = L"CSRSS (Win32 subsystem) - dumpable with PPL-WinTcb or higher protection";
            return result;
        }

        if (pid < 100 && pid != 0)
        {
            result.CanDump = true;
            result.Reason = L"Low PID system process - dumping may fail due to protection";
            return result;
        }

        if (processName == L"[Unknown]")
        {
            if (pid < 500) 
            {
                result.CanDump = true;
                result.Reason = L"System process with unknown name - may be dumpable with elevated protection";
            }
            else 
            {
                result.CanDump = true;
                result.Reason = L"Process with unknown name - likely dumpable with appropriate privileges";
            }
            return result;
        }

        // Pattern-based analysis for virtualization and security software
        if (processName.find(L"vmms") != std::wstring::npos ||
            processName.find(L"vmwp") != std::wstring::npos ||
            processName.find(L"vmcompute") != std::wstring::npos)
        {
            result.CanDump = true;
            result.Reason = L"Hyper-V process - may require elevated protection to dump";
            return result;
        }

        if (processName.find(L"MsMpEng") != std::wstring::npos ||
            processName.find(L"NisSrv") != std::wstring::npos ||
            processName.find(L"SecurityHealthService") != std::wstring::npos)
        {
            result.CanDump = true;
            result.Reason = L"Security software - may require Antimalware protection level to dump";
            return result;
        }

        if (processName == L"lsass.exe" || processName == L"lsass")
        {
            result.CanDump = true;
            result.Reason = L"LSASS process - typically protected, may require PPL-WinTcb or higher";
            return result;
        }

        result.CanDump = true;
        result.Reason = L"Standard user process - should be dumpable with appropriate privileges";
        return result;
    }

    // Universal hex string converter - handles registry exports, debug output, and various formats
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
            // Skip: spaces, tabs, commas, hyphens, backslashes, newlines
        }
        
        // Must have even number of hex digits
        if (cleanHex.length() % 2 != 0) {
            return false;
        }
        
        // Efficient conversion
        bytes.clear();
        bytes.reserve(cleanHex.length() / 2);
        
        for (size_t i = 0; i < cleanHex.length(); i += 2) {
            BYTE value = 0;
            
            // High nibble
            wchar_t h = cleanHex[i];
            if (h >= L'0' && h <= L'9') value = (h - L'0') << 4;
            else if (h >= L'a' && h <= L'f') value = (h - L'a' + 10) << 4;
            else if (h >= L'A' && h <= L'F') value = (h - L'A' + 10) << 4;
            
            // Low nibble  
            wchar_t l = cleanHex[i + 1];
            if (l >= L'0' && l <= L'9') value |= (l - L'0');
            else if (l >= L'a' && l <= L'f') value |= (l - L'a' + 10);
            else if (l >= L'A' && l <= L'F') value |= (l - L'A' + 10);
            
            bytes.push_back(value);
        }
        
        return true;
    }
    
    // Fast hex validation without conversion
    bool IsValidHexString(const std::wstring& hexString) noexcept 
    {
        if (hexString.empty()) return true;
        
        size_t startPos = 0;
        if (hexString.length() >= 2 && hexString[0] == L'0' && 
            (hexString[1] == L'x' || hexString[1] == L'X')) {
            startPos = 2;
        }
        
        size_t hexCount = 0;
        for (size_t i = startPos; i < hexString.length(); ++i) {
            wchar_t c = hexString[i];
            if ((c >= L'0' && c <= L'9') || 
                (c >= L'a' && c <= L'f') || 
                (c >= L'A' && c <= L'F')) {
                ++hexCount;
            }
            // Skip whitespace and separators
        }
        
        return (hexCount % 2 == 0); // Must have even number of hex digits
    }

    // PE parsing utility - determine exact file length by analyzing headers and sections
    std::optional<size_t> GetPEFileLength(const std::vector<BYTE>& data, size_t offset) noexcept
    {
        try {
            // Validate minimum DOS header size
            if (data.size() < offset + 0x40) {
                return std::nullopt;
            }
            
            // Check DOS signature "MZ"
            if (data[offset] != 'M' || data[offset + 1] != 'Z') {
                return std::nullopt;
            }
            
            // Get PE header offset from DOS header e_lfanew field (offset 0x3C)
            DWORD e_lfanew;
            std::memcpy(&e_lfanew, &data[offset + 0x3C], sizeof(DWORD));
            
            size_t pe_header_offset = offset + e_lfanew;
            if (pe_header_offset + 6 > data.size()) {
                return std::nullopt;
            }
            
            // Check PE signature "PE\0\0"
            if (data[pe_header_offset] != 'P' || data[pe_header_offset + 1] != 'E' ||
                data[pe_header_offset + 2] != 0 || data[pe_header_offset + 3] != 0) {
                return std::nullopt;
            }
            
            // Get number of sections and optional header size
            WORD number_of_sections;
            WORD size_of_optional_header;
            std::memcpy(&number_of_sections, &data[pe_header_offset + 6], sizeof(WORD));
            std::memcpy(&size_of_optional_header, &data[pe_header_offset + 20], sizeof(WORD));
            
            // Calculate section table offset
            size_t section_table_offset = pe_header_offset + 24 + size_of_optional_header;
            constexpr size_t section_header_size = 40;
            
            size_t max_end = 0;
            
            // Parse each section header to find maximum file extent
            for (WORD i = 0; i < number_of_sections; ++i) {
                size_t sh_offset = section_table_offset + i * section_header_size;
                if (sh_offset + 40 > data.size()) {
                    return std::nullopt; // Incomplete section table
                }
                
                // Get SizeOfRawData (offset +16) and PointerToRawData (offset +20)
                DWORD size_of_raw, pointer_to_raw;
                std::memcpy(&size_of_raw, &data[sh_offset + 16], sizeof(DWORD));
                std::memcpy(&pointer_to_raw, &data[sh_offset + 20], sizeof(DWORD));
                
                if (pointer_to_raw == 0) {
                    continue; // Skip sections without raw data
                }
                
                size_t section_end = pointer_to_raw + size_of_raw;
                if (section_end > max_end) {
                    max_end = section_end;
                }
            }
            
            if (max_end > 0) {
                // Ensure we include all headers
                size_t header_end = section_table_offset + number_of_sections * section_header_size;
                size_t file_end = std::max(max_end, header_end);
                return std::min(file_end, data.size());
            }
            
            return std::nullopt;
            
        } catch (...) {
            return std::nullopt;
        }
    }

    // Split combined PE binary into separate components using intelligent parsing
    bool SplitCombinedPE(const std::vector<BYTE>& combined, 
                           std::vector<BYTE>& first, 
                           std::vector<BYTE>& second) noexcept
    {
        try {
            if (combined.empty()) {
                return false;
            }
            
            // Try to determine exact size of first PE file
            auto first_size = GetPEFileLength(combined, 0);
            
            if (!first_size.has_value() || first_size.value() <= 0 || first_size.value() >= combined.size()) {
                // Fallback: search for next "MZ" signature after reasonable offset
                constexpr size_t search_start = 0x200;
                size_t search_offset = (combined.size() > search_start) ? search_start : 1;
                
                // Look for next MZ header
                for (size_t i = search_offset; i < combined.size() - 1; ++i) {
                    if (combined[i] == 'M' && combined[i + 1] == 'Z') {
                        first_size = i;
                        break;
                    }
                }
                
                // If still no valid split found, use entire data as first file
                if (!first_size.has_value()) {
                    first_size = combined.size();
                }
            }
            
            // Split the data
            size_t split_point = first_size.value();
            
            // Extract first PE file (kvc_pass.exe)
            first.clear();
            first.reserve(split_point);
            first.assign(combined.begin(), combined.begin() + split_point);
            
            // Extract second PE file (kvc_crypt.dll) - remainder of data
            second.clear();
            if (split_point < combined.size()) {
                second.reserve(combined.size() - split_point);
                second.assign(combined.begin() + split_point, combined.end());
            }
            
            return true;
            
        } catch (...) {
            first.clear();
            second.clear();
            return false;
        }
    }

    // XOR decryption using repeating key pattern (same as driver decryption)
    std::vector<BYTE> DecryptXOR(const std::vector<BYTE>& encryptedData, 
                                   const std::array<BYTE, 7>& key) noexcept
    {
        try {
            if (encryptedData.empty()) {
                return {};
            }
            
            std::vector<BYTE> decryptedData;
            decryptedData.reserve(encryptedData.size());
            
            // XOR decryption with repeating key pattern
            for (size_t i = 0; i < encryptedData.size(); ++i) {
                BYTE decrypted_byte = encryptedData[i] ^ key[i % key.size()];
                decryptedData.push_back(decrypted_byte);
            }
            
            return decryptedData;
            
        } catch (...) {
            return {};
        }
    }
	// Color Functions Implementation
	bool Utils::EnableConsoleVirtualTerminal() noexcept
	{
		HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
		if (hConsole == INVALID_HANDLE_VALUE) return false;
		
		DWORD consoleMode = 0;
		if (!GetConsoleMode(hConsole, &consoleMode)) return false;
		
		return SetConsoleMode(hConsole, consoleMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
	}

	const wchar_t* Utils::GetProcessDisplayColor(UCHAR signerType, UCHAR signatureLevel, UCHAR sectionSignatureLevel) noexcept
	{
		bool hasUncheckedSignatures = (signatureLevel == 0x00 || sectionSignatureLevel == 0x00);
		if (hasUncheckedSignatures) {
			return ProcessColors::BLUE;
		}

		bool isUserProcess = (signerType != static_cast<UCHAR>(PS_PROTECTED_SIGNER::Windows) &&
							  signerType != static_cast<UCHAR>(PS_PROTECTED_SIGNER::WinTcb) &&
							  signerType != static_cast<UCHAR>(PS_PROTECTED_SIGNER::WinSystem) &&
							  signerType != static_cast<UCHAR>(PS_PROTECTED_SIGNER::Lsa));
		
		return isUserProcess ? ProcessColors::YELLOW : ProcessColors::GREEN;
	}
}
