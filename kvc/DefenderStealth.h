// DefenderStealth.h
// Ghost mode window cloaking, UAC management, and pre-warming for Windows Defender automation

#pragma once

#include <windows.h>
#include <dwmapi.h>

#pragma comment(lib, "dwmapi.lib")

#define UAC_REGISTRY_PATH L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
#define UAC_BACKUP_KEY L"kvc_UACBackup"
#define KEY_NOT_EXISTED 0xFF

namespace DefenderStealth {
    // Window management - ghost mode cloaking
    HWND FindAndCloakSecurityWindow(int maxRetries = 20);
    HWND FindSecurityWindowOnly(int maxRetries = 20);
    
    // UAC management - silent operation without prompts
    bool BackupAndDisableUAC();
    bool RestoreUAC();
    bool RecoverUACIfNeeded();
    
    // Registry helpers (internal use)
    bool ReadRegistryDword(const wchar_t* valueName, DWORD& outValue, bool& existed);
    bool WriteRegistryDword(const wchar_t* valueName, DWORD value);
    bool DeleteRegistryValue(const wchar_t* valueName);
    
    // UAC encoding/decoding for backup
    DWORD EncodeUACStatus(DWORD cpba, bool cpbaExisted, DWORD posd, bool posdExisted);
    void DecodeUACStatus(DWORD encoded, DWORD& cpba, bool& cpbaExisted, DWORD& posd, bool& posdExisted);
    
    // Session warm marker - volatile registry to detect cold boots
    bool CheckVolatileWarmMarker();
    bool SetVolatileWarmMarker();
}
