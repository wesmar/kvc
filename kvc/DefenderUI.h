// DefenderUI.h
// Windows Defender UI Automation for Real-Time Protection and Tamper Protection control

#pragma once

// CRITICAL: UI Automation headers must be included in correct order
#include <windows.h>
#include <ole2.h>
#include <UIAutomation.h>
#include <UIAutomationClient.h>
#include <UIAutomationCore.h>
#include <string>
#include <vector>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "UIAutomationCore.lib")

// Automates Windows Security interface using UI Automation
// Uses "Structural Density" strategy for robust change detection
class WindowsDefenderAutomation {
private:
    IUIAutomation* pAutomation = nullptr;
    IUIAutomationElement* pRootElement = nullptr;
    HWND hwndSecurity = NULL;

    bool waitForUILoaded(int maxRetries = 20);
    IUIAutomationElement* findFirstToggleSwitch();
    IUIAutomationElement* findLastToggleSwitch();

    // Counts all descendant elements for structural change detection
    int countTotalElements();

    // Waits for element count change relative to baseline
    bool waitForStructureChange(int baselineCount, bool expectIncrease, int timeoutSeconds = 10);

    // Cold boot detection and pre-warming
    bool isColdBoot();
    bool preWarmDefender();

public:
    WindowsDefenderAutomation();
    ~WindowsDefenderAutomation();

    bool openDefenderSettings();

    // Real-Time Protection operations
    bool toggleRealTimeProtection();
    bool enableRealTimeProtection();
    bool disableRealTimeProtection();
    bool getRealTimeProtectionStatus();

    // Tamper Protection operations
    bool toggleTamperProtection();
    bool enableTamperProtection();
    bool disableTamperProtection();
    bool getTamperProtectionStatus();

    void closeSecurityWindow();
};
