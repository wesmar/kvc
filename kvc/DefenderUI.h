// DefenderUI.h
// Windows Defender UI Automation for Real-Time Protection and Tamper Protection control

#pragma once

#include <windows.h>
#include <ole2.h>
#include <UIAutomation.h>
#include <UIAutomationClient.h>
#include <UIAutomationCore.h>
#include <string>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "UIAutomationCore.lib")

// Automates Windows Security interface with TOPMOST console window as visual shield
// Uses structural density strategy for robust UI change detection
class WindowsDefenderAutomation {
private:
    IUIAutomation* pAutomation = nullptr;
    IUIAutomationElement* pRootElement = nullptr;
    HWND hwndSecurity = NULL;

    bool waitForUILoaded(int maxRetries = 20);
    IUIAutomationElement* findFirstToggleSwitch();
    IUIAutomationElement* findLastToggleSwitch();
    
    // Counts all descendant elements for structure change detection
    int countTotalElements();
    
    // Waits for UI element count to change (dialogs appearing/disappearing)
    bool waitForStructureChange(int baselineCount, bool expectIncrease, int timeoutSeconds = 10);
    
    // Cold boot handling - first run after login needs extra initialization
    bool isColdBoot();
    bool preWarmDefender();
    
    // Find the Windows Security window handle
    HWND findSecurityWindow(int maxRetries = 10);

public:
    WindowsDefenderAutomation();
    ~WindowsDefenderAutomation();

    bool openDefenderSettings();

    // Real-Time Protection
    bool toggleRealTimeProtection();
    bool enableRealTimeProtection();
    bool disableRealTimeProtection();
    bool getRealTimeProtectionStatus();

    // Tamper Protection
    bool toggleTamperProtection();
    bool enableTamperProtection();
    bool disableTamperProtection();
    bool getTamperProtectionStatus();

    void closeSecurityWindow();
};
