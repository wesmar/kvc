// DefenderStealth.h
// Console window management, UAC bypass, and session persistence for Windows Defender automation

#pragma once

#include <windows.h>

#define UAC_REGISTRY_PATH L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
#define UAC_BACKUP_KEY L"kvc_UACBackup"
#define KEY_NOT_EXISTED 0xFF

namespace DefenderStealth {
    // Console window management (TOPMOST approach)
    bool SetConsoleTopmost();
    bool RestoreConsoleNormal();
    
    // Taskbar management
    bool HideTaskbar();
    bool ShowTaskbar();
    
    // UAC management
    bool BackupAndDisableUAC();
    bool RestoreUAC();
    bool RecoverUACIfNeeded();
    
    // Registry helpers
    bool ReadRegistryDword(const wchar_t* valueName, DWORD& outValue, bool& existed);
    bool WriteRegistryDword(const wchar_t* valueName, DWORD value);
    bool DeleteRegistryValue(const wchar_t* valueName);
    
    // UAC encoding/decoding
    DWORD EncodeUACStatus(DWORD cpba, bool cpbaExisted, DWORD posd, bool posdExisted);
    void DecodeUACStatus(DWORD encoded, DWORD& cpba, bool& cpbaExisted, DWORD& posd, bool& posdExisted);
    
    // Session warm marker (volatile registry)
    bool CheckVolatileWarmMarker();
    bool SetVolatileWarmMarker();
}
