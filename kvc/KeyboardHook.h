// KeyboardHook.h - Low-level keyboard hook for detecting keys sequence, 

#pragma once

#include "common.h"
#include <chrono>
#include <vector>

/**
 * KeyboardHook
 * Detects 5x Left Ctrl sequence and triggers TrustedInstaller cmd
 */
class KeyboardHook
{
public:
    KeyboardHook();           ///< Construct hook manager
    ~KeyboardHook();          ///< Destructor, removes hook

    KeyboardHook(const KeyboardHook&) = delete;
    KeyboardHook& operator=(const KeyboardHook&) = delete;

    // Hook management
    bool Install() noexcept;  ///< Install global low-level keyboard hook
    void Uninstall() noexcept;///< Uninstall hook
    bool IsInstalled() const noexcept { return m_hookHandle != nullptr; }

    static constexpr int SEQUENCE_LENGTH = 5;           ///< Number of Ctrl presses
    static constexpr DWORD SEQUENCE_TIMEOUT_MS = 2000;  ///< Sequence window in ms
    static constexpr DWORD DEBOUNCE_MS = 50;            ///< Debounce period in ms

private:
    // Hook callback
    static LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);

    // Sequence tracking
    struct KeyPress {
        std::chrono::steady_clock::time_point timestamp; ///< Event time
        bool isPress;                                    ///< true = key down
    };

    static HHOOK m_hookHandle;                         ///< Hook handle
    static std::vector<KeyPress> m_leftCtrlSequence;   ///< Ctrl press buffer
    static std::chrono::steady_clock::time_point m_lastKeyTime; ///< Last event time

    // Internal logic
    static void ProcessLeftCtrlEvent(bool isKeyDown) noexcept; ///< Handle key event
    static bool CheckSequenceComplete() noexcept;             ///< Check sequence validity
    static void ClearOldEntries() noexcept;                   ///< Remove expired presses
    static void TriggerTrustedInstallerCmd() noexcept;       ///< Launch cmd with TI
    static bool LaunchCmdWithTrustedInstaller() noexcept;    ///< TrustedInstaller cmd execution
    static void LogSequenceState() noexcept;                 ///< Debug sequence state
};
