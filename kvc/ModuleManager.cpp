// ModuleManager.cpp
// Module enumeration and memory inspection implementation
// Uses Toolhelp32 API for module listing with kernel driver memory access

#include "ModuleManager.h"
#include "common.h"
#include <tlhelp32.h>
#include <iomanip>
#include <algorithm>

// Enumerate all loaded modules in target process using Toolhelp32 snapshot
std::vector<ModuleInfo> ModuleManager::EnumerateModules(DWORD pid) noexcept
{
    std::vector<ModuleInfo> modules;
    
    // Create module snapshot for target process
    HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (hModuleSnap == INVALID_HANDLE_VALUE) {
        // Return empty vector silently - caller handles elevation and error reporting
        return modules;
    }
    
    MODULEENTRY32W me32 = { sizeof(MODULEENTRY32W) };
    
    // Iterate through all modules in the snapshot
    if (Module32FirstW(hModuleSnap, &me32)) {
        do {
            ModuleInfo info;
            info.name = me32.szModule;
            info.path = me32.szExePath;
            info.baseAddress = reinterpret_cast<ULONG_PTR>(me32.modBaseAddr);
            info.size = me32.modBaseSize;
            modules.push_back(info);
            
        } while (Module32NextW(hModuleSnap, &me32));
    }
    
    CloseHandle(hModuleSnap);
    
    // Sort modules by base address for consistent output
    std::sort(modules.begin(), modules.end(), 
        [](const ModuleInfo& a, const ModuleInfo& b) {
            return a.baseAddress < b.baseAddress;
        });
    
    return modules;
}

// Find specific module by name (case-insensitive partial match)
std::optional<ModuleInfo> ModuleManager::FindModule(DWORD pid, const std::wstring& moduleName) noexcept
{
    auto modules = EnumerateModules(pid);
    
    // First try exact match
    for (const auto& mod : modules) {
        if (_wcsicmp(mod.name.c_str(), moduleName.c_str()) == 0) {
            return mod;
        }
    }
    
    // Then try partial match
    std::wstring searchLower = moduleName;
    std::transform(searchLower.begin(), searchLower.end(), searchLower.begin(), ::towlower);
    
    for (const auto& mod : modules) {
        std::wstring modLower = mod.name;
        std::transform(modLower.begin(), modLower.end(), modLower.begin(), ::towlower);
        
        if (modLower.find(searchLower) != std::wstring::npos) {
            return mod;
        }
    }
    
    return std::nullopt;
}

// Display formatted module list with color-coded output
void ModuleManager::PrintModuleList(const std::vector<ModuleInfo>& modules) noexcept
{
    if (modules.empty()) {
        INFO(L"No modules found");
        return;
    }
    
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    WORD originalColor = csbi.wAttributes;
    
    // Print header
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::wcout << L"\n";
    std::wcout << std::left << std::setw(36) << L"Module Name" 
               << std::right << std::setw(18) << L"Base Address" 
               << std::setw(14) << L"Size" << L"\n";
    
    SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY);
    std::wcout << std::wstring(68, L'=') << L"\n";
    
    SetConsoleTextAttribute(hConsole, originalColor);
    
    // Print each module entry
    for (const auto& mod : modules) {
        // Truncate long names for clean formatting
        std::wstring displayName = mod.name;
        if (displayName.length() > 34) {
            displayName = displayName.substr(0, 31) + L"...";
        }
        
        std::wcout << std::left << std::setw(36) << displayName;
        
        // Base address in cyan for visibility
        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
		std::wcout << L"0x" << std::hex << std::setfill(L'0') << std::setw(16) 
                   << mod.baseAddress << std::dec << std::setfill(L' ') << L"  ";
        
        SetConsoleTextAttribute(hConsole, originalColor);
        std::wcout << std::setw(14) << FormatSize(mod.size) << L"\n";
    }
    
    std::wcout << L"\n";
    SetConsoleTextAttribute(hConsole, originalColor);
}

// Display hex dump with address offsets and ASCII representation
void ModuleManager::PrintHexDump(const unsigned char* buffer, size_t size, ULONG_PTR baseAddress) noexcept
{
    if (!buffer || size == 0) {
        ERROR(L"No data to display");
        return;
    }
    
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    WORD originalColor = csbi.wAttributes;
    
    std::wcout << L"\n";
    
    // Print in 16-byte rows with address, hex values, and ASCII
    for (size_t i = 0; i < size; i += 16) {
        // Address column
        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::wcout << std::hex << std::setfill(L'0') << std::setw(8) 
                   << static_cast<unsigned int>(i) << L": ";
        
        // Hex values
        SetConsoleTextAttribute(hConsole, originalColor);
        for (size_t j = 0; j < 16 && (i + j) < size; j++) {
            std::wcout << std::hex << std::setfill(L'0') << std::setw(2) 
                       << static_cast<unsigned int>(buffer[i + j]) << L" ";
        }
        
        // Padding for incomplete rows
        for (size_t j = (size - i < 16 ? size - i : 16); j < 16; j++) {
            std::wcout << L"   ";
        }
        
        // ASCII representation
        SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY);
        std::wcout << L" |";
        for (size_t j = 0; j < 16 && (i + j) < size; j++) {
            unsigned char c = buffer[i + j];
            std::wcout << static_cast<wchar_t>((c >= 32 && c < 127) ? c : L'.');
        }
        std::wcout << L"|\n";
    }
    
    std::wcout << std::dec << std::setfill(L' ') << L"\n";
    SetConsoleTextAttribute(hConsole, originalColor);
}

// Check for valid PE signature (MZ header)
bool ModuleManager::ValidatePESignature(const unsigned char* buffer, size_t size) noexcept
{
    if (!buffer || size < 2) return false;
    return (buffer[0] == 'M' && buffer[1] == 'Z');
}

// Format byte size to human-readable string (KB, MB)
std::wstring ModuleManager::FormatSize(DWORD size) noexcept
{
    wchar_t buf[32];
    
    if (size >= 1024 * 1024) {
        swprintf_s(buf, L"%.2f MB", static_cast<double>(size) / (1024.0 * 1024.0));
    } else if (size >= 1024) {
        swprintf_s(buf, L"%.2f KB", static_cast<double>(size) / 1024.0);
    } else {
        swprintf_s(buf, L"%lu B", size);
    }
    
    return buf;
}
