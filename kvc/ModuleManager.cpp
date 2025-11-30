// ModuleManager.cpp
// Module enumeration and memory inspection implementation
// Uses Toolhelp32 API for module listing with kernel driver memory access

#include "ModuleManager.h"
#include "common.h"
#include <tlhelp32.h>
#include <iomanip>
#include <algorithm>
#include <sstream>

// Console color codes for visual formatting
namespace Colors {
    inline constexpr const wchar_t* YELLOW = L"\033[93m";
    inline constexpr const wchar_t* CYAN = L"\033[96m";
    inline constexpr const wchar_t* GREEN = L"\033[92m";
    inline constexpr const wchar_t* GRAY = L"\033[90m";
    inline constexpr const wchar_t* RESET = L"\033[0m";
}

// Pre-computed table header separator line
namespace {
    inline const std::wstring HEADER_SEPARATOR = []() {
        std::wostringstream ss;
        ss << std::wstring(ModuleTable::Columns::NAME, L'=') << L' '
           << std::wstring(ModuleTable::Columns::ADDR, L'=') << L' '
           << std::wstring(ModuleTable::Columns::SIZE, L'=');
        return ss.str();
    }();
}

std::vector<ModuleInfo> ModuleManager::EnumerateModules(DWORD pid) noexcept
{
    std::vector<ModuleInfo> modules;
    
    HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hModuleSnap == INVALID_HANDLE_VALUE) {
        return modules;
    }
    
    MODULEENTRY32W me32 = { sizeof(MODULEENTRY32W) };
    
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

std::optional<ModuleInfo> ModuleManager::FindModule(DWORD pid, const std::wstring& moduleName) noexcept
{
    auto modules = EnumerateModules(pid);
    
    // First pass: exact match
    for (const auto& mod : modules) {
        if (_wcsicmp(mod.name.c_str(), moduleName.c_str()) == 0) {
            return mod;
        }
    }
    
    // Second pass: partial match with lowercase comparison
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
    
    // Table header
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::wcout << L"\n";
    std::wcout << std::left << std::setw(ModuleTable::Columns::NAME) << L"Module Name" 
               << std::right << std::setw(ModuleTable::Columns::ADDR) << L"Base Address" 
               << std::setw(ModuleTable::Columns::SIZE) << L"Size" << L"\n";
    
    // Header separator
    SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY);
    std::wcout << HEADER_SEPARATOR << L"\n";
    
    SetConsoleTextAttribute(hConsole, originalColor);
    
    // Module entries
    for (const auto& mod : modules) {
        // Truncate long names for clean alignment
        std::wstring displayName = mod.name;
        if (displayName.length() > ModuleTable::Columns::NAME - 2) {
            displayName = displayName.substr(0, ModuleTable::Columns::NAME - 5) + L"...";
        }
        
        std::wcout << std::left << std::setw(ModuleTable::Columns::NAME) << displayName;
        
        // Base address in cyan for visibility
        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        std::wcout << L"0x" << std::hex << std::setfill(L'0') << std::setw(16) 
                   << mod.baseAddress << std::dec << std::setfill(L' ') << L"  ";
        
        SetConsoleTextAttribute(hConsole, originalColor);
        std::wcout << std::setw(ModuleTable::Columns::SIZE) << FormatSize(mod.size) << L"\n";
    }
    
    std::wcout << L"\n";
    SetConsoleTextAttribute(hConsole, originalColor);
}

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
    
    // Process 16-byte rows with address, hex values, and ASCII representation
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
        size_t remaining = (size - i < 16) ? (size - i) : 16;
        for (size_t j = remaining; j < 16; j++) {
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

bool ModuleManager::ValidatePESignature(const unsigned char* buffer, size_t size) noexcept
{
    if (!buffer || size < 2) return false;
    return (buffer[0] == 'M' && buffer[1] == 'Z');
}

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
