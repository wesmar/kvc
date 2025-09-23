#include "KeyboardHook.h"
#include "TrustedInstallerIntegrator.h"
#include "common.h"
#include <algorithm>

// Static members
HHOOK KeyboardHook::m_hookHandle = nullptr;
std::vector<KeyboardHook::KeyPress> KeyboardHook::m_leftCtrlSequence;
std::chrono::steady_clock::time_point KeyboardHook::m_lastKeyTime;

KeyboardHook::KeyboardHook()
{
    m_leftCtrlSequence.reserve(SEQUENCE_LENGTH * 2); // Pre-allocate for efficiency
}

KeyboardHook::~KeyboardHook()
{
    Uninstall();
}

bool KeyboardHook::Install() noexcept
{
    if (m_hookHandle) {
        INFO(L"Keyboard hook already installed");
        return true;
    }

    // Install low-level keyboard hook
    m_hookHandle = SetWindowsHookEx(
        WH_KEYBOARD_LL,
        LowLevelKeyboardProc,
        GetModuleHandle(nullptr),
        0  // Global hook
    );

    if (!m_hookHandle) {
        ERROR(L"Failed to install keyboard hook: %d", GetLastError());
        return false;
    }

    // Initialize tracking state
    m_leftCtrlSequence.clear();
    m_lastKeyTime = std::chrono::steady_clock::now();

    INFO(L"Low-level keyboard hook installed successfully");
    INFO(L"Sequence trigger: 5x Left Ctrl within %d ms", SEQUENCE_TIMEOUT_MS);
    return true;
}

void KeyboardHook::Uninstall() noexcept
{
    if (m_hookHandle) {
        if (UnhookWindowsHookEx(m_hookHandle)) {
            INFO(L"Keyboard hook uninstalled successfully");
        } else {
            ERROR(L"Failed to uninstall keyboard hook: %d", GetLastError());
        }
        m_hookHandle = nullptr;
    }

    // Clear tracking state
    m_leftCtrlSequence.clear();
}

LRESULT CALLBACK KeyboardHook::LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    // Must call next hook in chain if nCode < 0
    if (nCode < 0) {
        return CallNextHookEx(m_hookHandle, nCode, wParam, lParam);
    }

    // Process keyboard event
    if (nCode == HC_ACTION) {
        KBDLLHOOKSTRUCT* pKeyboard = reinterpret_cast<KBDLLHOOKSTRUCT*>(lParam);
        
        // Check if it's Left Control key
        if (pKeyboard->vkCode == VK_LCONTROL) {
            bool isKeyDown = (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN);
            bool isKeyUp = (wParam == WM_KEYUP || wParam == WM_SYSKEYUP);
            
            if (isKeyDown || isKeyUp) {
                ProcessLeftCtrlEvent(isKeyDown);
            }
        }
        else {
            // Any other key resets the sequence (prevents accidental triggering)
            if (!m_leftCtrlSequence.empty()) {
                m_leftCtrlSequence.clear();
            }
        }
    }

    // Continue processing
    return CallNextHookEx(m_hookHandle, nCode, wParam, lParam);
}

void KeyboardHook::ProcessLeftCtrlEvent(bool isKeyDown) noexcept
{
    auto now = std::chrono::steady_clock::now();
    
    // Debouncing - ignore events too close together
    auto timeSinceLastKey = std::chrono::duration_cast<std::chrono::milliseconds>(now - m_lastKeyTime).count();
    if (timeSinceLastKey < DEBOUNCE_MS) {
        return;
    }
    
    m_lastKeyTime = now;

    // Only track key press events (down), ignore key release for simplicity
    if (!isKeyDown) {
        return;
    }

    // Add to sequence
    m_leftCtrlSequence.push_back({now, isKeyDown});
    
    // Remove old entries outside time window
    ClearOldEntries();
    
    // Check if sequence is complete
    if (CheckSequenceComplete()) {
        INFO(L"5x Left Ctrl sequence detected! Launching TrustedInstaller CMD...");
        TriggerTrustedInstallerCmd();
        
        // Clear sequence to prevent repeated triggering
        m_leftCtrlSequence.clear();
    }

#if kvc_DEBUG_ENABLED
    LogSequenceState();
#endif
}

bool KeyboardHook::CheckSequenceComplete() noexcept
{
    // Need exactly SEQUENCE_LENGTH key presses
    size_t keyPressCount = 0;
    for (const auto& entry : m_leftCtrlSequence) {
        if (entry.isPress) {
            keyPressCount++;
        }
    }
    
    return keyPressCount >= SEQUENCE_LENGTH;
}

void KeyboardHook::ClearOldEntries() noexcept
{
    auto now = std::chrono::steady_clock::now();
    auto cutoffTime = now - std::chrono::milliseconds(SEQUENCE_TIMEOUT_MS);
    
    // Remove entries older than timeout
    auto it = std::remove_if(m_leftCtrlSequence.begin(), m_leftCtrlSequence.end(),
        [cutoffTime](const KeyPress& entry) {
            return entry.timestamp < cutoffTime;
        });
    
    m_leftCtrlSequence.erase(it, m_leftCtrlSequence.end());
}

void KeyboardHook::TriggerTrustedInstallerCmd() noexcept
{
    // Launch CMD with TrustedInstaller privileges
    if (LaunchCmdWithTrustedInstaller()) {
        SUCCESS(L"TrustedInstaller CMD launched successfully");
    } else {
        ERROR(L"Failed to launch TrustedInstaller CMD");
    }
}

bool KeyboardHook::LaunchCmdWithTrustedInstaller() noexcept
{
    try {
        // Use existing TrustedInstaller infrastructure
        TrustedInstallerIntegrator trustedInstaller;
        
        // Launch cmd.exe with maximum privileges
        std::wstring cmdLine = L"cmd.exe";
        bool success = trustedInstaller.RunAsTrustedInstaller(cmdLine);
        
        if (success) {
            INFO(L"CMD.exe launched with TrustedInstaller privileges via 5x Left Ctrl");
        } else {
            ERROR(L"Failed to launch CMD.exe with TrustedInstaller privileges");
        }
        
        return success;
        
    } catch (const std::exception& e) {
        std::string msg = e.what();
        std::wstring wmsg(msg.begin(), msg.end());
        ERROR(L"Exception launching TrustedInstaller CMD: %s", wmsg.c_str());
        return false;
    } catch (...) {
        ERROR(L"Unknown exception launching TrustedInstaller CMD");
        return false;
    }
}

void KeyboardHook::LogSequenceState() noexcept
{
    if (m_leftCtrlSequence.empty()) {
        return;
    }
    
    size_t keyPressCount = 0;
    for (const auto& entry : m_leftCtrlSequence) {
        if (entry.isPress) {
            keyPressCount++;
        }
    }
    
    DEBUG(L"Left Ctrl sequence: %zu/%d presses tracked", keyPressCount, SEQUENCE_LENGTH);
}