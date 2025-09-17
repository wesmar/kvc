#pragma once

#include "common.h"
#include <chrono>
#include <vector>

// Low-level keyboard hook for 5x Left Ctrl sequence detection
class KeyboardHook
{
public:
    KeyboardHook();
    ~KeyboardHook();

    KeyboardHook(const KeyboardHook&) = delete;
    KeyboardHook& operator=(const KeyboardHook&) = delete;

    // Hook management
    bool Install() noexcept;
    void Uninstall() noexcept;
    bool IsInstalled() const noexcept { return m_hookHandle != nullptr; }

    // Configuration
    static constexpr int SEQUENCE_LENGTH = 5;           // 5x Left Ctrl presses
    static constexpr DWORD SEQUENCE_TIMEOUT_MS = 2000;  // 2 second window
    static constexpr DWORD DEBOUNCE_MS = 50;            // Debounce period

private:
    // Hook callback
    static LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);
    
    // Sequence tracking
    struct KeyPress {
        std::chrono::steady_clock::time_point timestamp;
        bool isPress;  // true for key down, false for key up
    };

    static HHOOK m_hookHandle;
    static std::vector<KeyPress> m_leftCtrlSequence;
    static std::chrono::steady_clock::time_point m_lastKeyTime;

    // Internal logic
    static void ProcessLeftCtrlEvent(bool isKeyDown) noexcept;
    static bool CheckSequenceComplete() noexcept;
    static void ClearOldEntries() noexcept;
    static void TriggerTrustedInstallerCmd() noexcept;
    static bool LaunchCmdWithTrustedInstaller() noexcept;
    
    // Debugging and logging
    static void LogSequenceState() noexcept;
};