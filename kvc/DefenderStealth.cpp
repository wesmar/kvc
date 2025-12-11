// DefenderStealth.cpp
// Console window management and UAC bypass for Windows Defender automation

#include "DefenderStealth.h"
#include <iostream>

#define DEBUG_LOGGING_ENABLED 0

#if DEBUG_LOGGING_ENABLED
    #define DEBUG_LOG(msg) std::wcout << msg << L"\n"
#else
    #define DEBUG_LOG(msg) ((void)0)
#endif

static HWND g_hConsole = NULL;
static WINDOWPLACEMENT g_originalPlacement = { sizeof(WINDOWPLACEMENT) };
static bool g_isTopmost = false;

// ============================================================================
// Console Window Management - TOPMOST Approach
// ============================================================================

bool DefenderStealth::SetConsoleTopmost() {
    g_hConsole = GetConsoleWindow();
    if (!g_hConsole) return false;
    
    // Save original state only on first call
    if (!g_isTopmost) {
        GetWindowPlacement(g_hConsole, &g_originalPlacement);
        g_isTopmost = true;
    }
    
    // Maximize and set TOPMOST to cover everything
    ShowWindow(g_hConsole, SW_SHOWMAXIMIZED);
    SetWindowPos(g_hConsole, HWND_TOPMOST, 0, 0, 0, 0, 
                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    
    return true;
}

bool DefenderStealth::RestoreConsoleNormal() {
    if (!g_hConsole || !g_isTopmost) return false;
    
    // Remove TOPMOST and restore original window state
    SetWindowPos(g_hConsole, HWND_NOTOPMOST, 0, 0, 0, 0, 
                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    SetWindowPlacement(g_hConsole, &g_originalPlacement);
    
    g_isTopmost = false;
    return true;
}

// ============================================================================
// Registry Helpers
// ============================================================================

bool DefenderStealth::ReadRegistryDword(const wchar_t* valueName, DWORD& outValue, bool& existed) {
    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, UAC_REGISTRY_PATH, 0, KEY_READ, &hKey);
    
    if (result != ERROR_SUCCESS) {
        existed = false;
        return false;
    }

    DWORD type = REG_DWORD;
    DWORD size = sizeof(DWORD);
    result = RegQueryValueExW(hKey, valueName, nullptr, &type, (LPBYTE)&outValue, &size);
    RegCloseKey(hKey);
    
    existed = (result == ERROR_SUCCESS && type == REG_DWORD);
    return existed;
}

bool DefenderStealth::WriteRegistryDword(const wchar_t* valueName, DWORD value) {
    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, UAC_REGISTRY_PATH, 0, KEY_WRITE, &hKey);
    
    if (result != ERROR_SUCCESS) return false;

    result = RegSetValueExW(hKey, valueName, 0, REG_DWORD, (LPBYTE)&value, sizeof(DWORD));
    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
}

bool DefenderStealth::DeleteRegistryValue(const wchar_t* valueName) {
    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, UAC_REGISTRY_PATH, 0, KEY_WRITE, &hKey);
    
    if (result != ERROR_SUCCESS) return false;

    result = RegDeleteValueW(hKey, valueName);
    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
}

// ============================================================================
// UAC Logic
// ============================================================================

DWORD DefenderStealth::EncodeUACStatus(DWORD cpba, bool cpbaExisted, DWORD posd, bool posdExisted) {
    DWORD encoded = 0;
    encoded |= (cpbaExisted ? (cpba & 0xFF) : KEY_NOT_EXISTED);
    encoded |= ((posdExisted ? (posd & 0xFF) : KEY_NOT_EXISTED) << 8);
    return encoded;
}

void DefenderStealth::DecodeUACStatus(DWORD encoded, DWORD& cpba, bool& cpbaExisted, DWORD& posd, bool& posdExisted) {
    BYTE cpbaByte = encoded & 0xFF;
    BYTE posdByte = (encoded >> 8) & 0xFF;
    
    cpbaExisted = (cpbaByte != KEY_NOT_EXISTED);
    cpba = cpbaExisted ? cpbaByte : 0;
    
    posdExisted = (posdByte != KEY_NOT_EXISTED);
    posd = posdExisted ? posdByte : 0;
}

bool DefenderStealth::BackupAndDisableUAC() {
    DEBUG_LOG(L"Backing up and disabling UAC prompts");
    
    DWORD cpba = 0, posd = 0;
    bool cpbaExisted = false, posdExisted = false;
    
    ReadRegistryDword(L"ConsentPromptBehaviorAdmin", cpba, cpbaExisted);
    ReadRegistryDword(L"PromptOnSecureDesktop", posd, posdExisted);
    
    DWORD encoded = EncodeUACStatus(cpba, cpbaExisted, posd, posdExisted);
    if (!WriteRegistryDword(UAC_BACKUP_KEY, encoded)) return false;
    
    bool success = true;
    success &= WriteRegistryDword(L"ConsentPromptBehaviorAdmin", 0);
    success &= WriteRegistryDword(L"PromptOnSecureDesktop", 0);
    
    return success;
}

bool DefenderStealth::RestoreUAC() {
    DEBUG_LOG(L"Restoring original UAC settings");
    
    DWORD encoded = 0;
    bool backupExisted = false;
    
    if (!ReadRegistryDword(UAC_BACKUP_KEY, encoded, backupExisted) || !backupExisted) return false;
    
    DWORD cpba = 0, posd = 0;
    bool cpbaExisted = false, posdExisted = false;
    DecodeUACStatus(encoded, cpba, cpbaExisted, posd, posdExisted);
    
    if (cpbaExisted) WriteRegistryDword(L"ConsentPromptBehaviorAdmin", cpba);
    else DeleteRegistryValue(L"ConsentPromptBehaviorAdmin");
    
    if (posdExisted) WriteRegistryDword(L"PromptOnSecureDesktop", posd);
    else DeleteRegistryValue(L"PromptOnSecureDesktop");
    
    DeleteRegistryValue(UAC_BACKUP_KEY);
    return true;
}

bool DefenderStealth::RecoverUACIfNeeded() {
    DWORD encoded = 0;
    bool backupExisted = false;
    if (ReadRegistryDword(UAC_BACKUP_KEY, encoded, backupExisted) && backupExisted) {
        std::wcout << L"[*] Found incomplete UAC backup, restoring\n";
        return RestoreUAC();
    }
    return true;
}

// ============================================================================
// Volatile Registry Marker (Session Persistence)
// ============================================================================

bool DefenderStealth::CheckVolatileWarmMarker() {
    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\kvc\\WinDefCtl", 0, KEY_READ, &hKey);
    
    if (result != ERROR_SUCCESS) {
        return false;
    }

    DWORD value;
    DWORD size = sizeof(DWORD);
    result = RegQueryValueExW(hKey, L"DefenderWarmed", nullptr, nullptr, (LPBYTE)&value, &size);
    RegCloseKey(hKey);
    
    return (result == ERROR_SUCCESS);
}

bool DefenderStealth::SetVolatileWarmMarker() {
    HKEY hKey;
    DWORD disposition;
    
    // Volatile key disappears on logout/reboot
    LONG result = RegCreateKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\kvc\\WinDefCtl",
        0,
        NULL,
        REG_OPTION_VOLATILE,
        KEY_WRITE,
        NULL,
        &hKey,
        &disposition
    );
    
    if (result != ERROR_SUCCESS) {
        return false;
    }

    DWORD marker = 1;
    result = RegSetValueExW(hKey, L"DefenderWarmed", 0, REG_DWORD, (LPBYTE)&marker, sizeof(DWORD));
    RegCloseKey(hKey);
    
    return (result == ERROR_SUCCESS);
}
