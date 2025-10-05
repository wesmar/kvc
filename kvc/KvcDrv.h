/**
 * @file kvcDrv.h
 * @brief KVC kernel driver communication interface
 * @author Marek Wesolowski  
 * @date 2025
 * @copyright KVC Framework
 * 
 * Provides low-level IOCTL-based communication with the KVC kernel driver
 * for memory read/write operations in kernel address space.
 * Features type-safe operations, automatic resource management, and
 * connection state tracking.
 */

#pragma once

#include "common.h"
#include <memory>
#include <optional>

// ============================================================================
// DRIVER COMMUNICATION STRUCTURES (ALIGNED FOR IOCTL)
// ============================================================================

/**
 * @brief Memory read request structure with proper alignment
 * 
 * Layout optimized for driver IOCTL communication with explicit padding
 * to ensure consistent structure size across user/kernel boundary.
 * Used for reading kernel memory from user mode.
 */
struct alignas(8) RTC_MEMORY_READ 
{
    BYTE Pad0[8];           ///< Alignment padding for 64-bit alignment
    DWORD64 Address;        ///< Target kernel memory address to read from
    BYTE Pad1[8];           ///< Additional padding for structure alignment
    DWORD Size;             ///< Number of bytes to read (1/2/4/8 bytes)
    DWORD Value;            ///< Returned value from kernel memory
    BYTE Pad3[16];          ///< Final padding for IOCTL buffer alignment
};

/**
 * @brief Memory write request structure with proper alignment
 * 
 * Layout optimized for driver IOCTL communication with explicit padding
 * to ensure consistent structure size across user/kernel boundary.
 * Used for writing to kernel memory from user mode.
 */
struct alignas(8) RTC_MEMORY_WRITE 
{
    BYTE Pad0[8];           ///< Alignment padding for 64-bit alignment
    DWORD64 Address;        ///< Target kernel memory address to write to
    BYTE Pad1[8];           ///< Additional padding for structure alignment
    DWORD Size;             ///< Number of bytes to write (1/2/4/8 bytes)
    DWORD Value;            ///< Value to write to kernel memory
    BYTE Pad3[16];          ///< Final padding for IOCTL buffer alignment
};

// ============================================================================
// KVC DRIVER COMMUNICATION CLASS
// ============================================================================

/**
 * @class kvc
 * @brief Kernel memory operations interface via KVC driver
 * 
 * Provides type-safe memory read/write operations in kernel address space
 * through IOCTL-based communication with the KVC kernel driver.
 * 
 * Features:
 * - Automatic resource management with RAII
 * - Type-safe read/write operations (8/16/32/64-bit)
 * - Connection state management
 * - Smart handle management with automatic cleanup
 * - Error handling with std::optional return values
 * 
 * @warning Kernel memory operations can cause system instability if misused
 * @note Driver must be installed and running before using this class
 */
class kvc
{
public:
    /**
     * @brief Construct kvc driver interface
     * 
     * Initializes device name but does not establish connection.
     * Call Initialize() to connect to driver.
     */
    kvc();
    
    /**
     * @brief Destructor with automatic cleanup
     * 
     * Automatically closes driver connection and releases resources.
     */
    ~kvc();

    // Disable copy semantics to prevent handle duplication
    kvc(const kvc&) = delete;                   ///< Copy constructor deleted
    kvc& operator=(const kvc&) = delete;        ///< Copy assignment deleted
    
    // Enable move semantics for efficient resource transfer
    kvc(kvc&&) noexcept = default;              ///< Move constructor
    kvc& operator=(kvc&&) noexcept = default;   ///< Move assignment

    // ========================================================================
    // DRIVER CONNECTION MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Initializes connection to KVC kernel driver
     * 
     * Attempts to open device handle to driver. Safe to call multiple times.
     * If already connected, returns true without reinitializing.
     * 
     * @return bool true if driver connection established successfully
     * @note Does not perform test operations - just opens device handle
     * @note Device name: "\\\\.\\KVCDriver"
     */
    bool Initialize() noexcept;
    
    /**
     * @brief Cleans up driver resources and closes connection
     * 
     * Flushes buffers and releases device handle. Safe to call multiple times.
     * If not connected, does nothing.
     */
    void Cleanup() noexcept;
    
    /**
     * @brief Checks if driver connection is active
     * 
     * Verifies that device handle is valid and open. Does not test
     * if driver is actually responsive.
     * 
     * @return bool true if device handle is valid and open
     */
    bool IsConnected() const noexcept;

    // ========================================================================
    // MEMORY READ OPERATIONS (TYPE-SAFE)
    // ========================================================================
    
    /**
     * @brief Reads 8-bit value from kernel memory
     * @param address Target kernel address to read from
     * @return std::optional<BYTE> Read value or nullopt on failure
     * @note Uses single byte read operation
     */
    std::optional<BYTE> Read8(ULONG_PTR address) noexcept;
    
    /**
     * @brief Reads 16-bit value from kernel memory
     * @param address Target kernel address to read from
     * @return std::optional<WORD> Read value or nullopt on failure
     * @note Uses 16-bit read operation
     */
    std::optional<WORD> Read16(ULONG_PTR address) noexcept;
    
    /**
     * @brief Reads 32-bit value from kernel memory
     * @param address Target kernel address to read from
     * @return std::optional<DWORD> Read value or nullopt on failure
     * @note Uses 32-bit read operation
     */
    std::optional<DWORD> Read32(ULONG_PTR address) noexcept;
    
    /**
     * @brief Reads 64-bit value from kernel memory
     * @param address Target kernel address to read from
     * @return std::optional<DWORD64> Read value or nullopt on failure
     * @note Performs two 32-bit reads and combines them
     */
    std::optional<DWORD64> Read64(ULONG_PTR address) noexcept;
    
    /**
     * @brief Reads pointer-sized value from kernel memory
     * @param address Target kernel address to read from
     * @return std::optional<ULONG_PTR> Read value or nullopt on failure
     * @note Uses Read64 on x64, Read32 on x86 architectures
     */
    std::optional<ULONG_PTR> ReadPtr(ULONG_PTR address) noexcept;
    
    // ========================================================================
    // MEMORY WRITE OPERATIONS (TYPE-SAFE)
    // ========================================================================
    
    /**
     * @brief Writes 8-bit value to kernel memory
     * @param address Target kernel address to write to
     * @param value Value to write (8-bit)
     * @return bool true if write successful
     * @warning Kernel writes can cause system instability if misused
     * @note Uses single byte write operation
     */
    bool Write8(ULONG_PTR address, BYTE value) noexcept;
    
    /**
     * @brief Writes 16-bit value to kernel memory
     * @param address Target kernel address to write to
     * @param value Value to write (16-bit)
     * @return bool true if write successful
     * @warning Kernel writes can cause system instability if misused
     * @note Uses 16-bit write operation
     */
    bool Write16(ULONG_PTR address, WORD value) noexcept;
    
    /**
     * @brief Writes 32-bit value to kernel memory
     * @param address Target kernel address to write to
     * @param value Value to write (32-bit)
     * @return bool true if write successful
     * @warning Kernel writes can cause system instability if misused
     * @note Uses 32-bit write operation
     */
    bool Write32(ULONG_PTR address, DWORD value) noexcept;
    
    /**
     * @brief Writes 64-bit value to kernel memory
     * @param address Target kernel address to write to
     * @param value Value to write (64-bit)
     * @return bool true if write successful
     * @note Performs two 32-bit writes for 64-bit values
     * @warning Kernel writes can cause system instability if misused
     */
    bool Write64(ULONG_PTR address, DWORD64 value) noexcept;
    
private:
    // ========================================================================
    // SMART HANDLE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Custom deleter for automatic HANDLE cleanup
     * 
     * Ensures proper handle closure when UniqueHandle goes out of scope.
     * Handles INVALID_HANDLE_VALUE gracefully.
     */
    struct HandleDeleter
    {
        /**
         * @brief Close handle if valid
         * @param handle Handle to close
         */
        void operator()(HANDLE handle) const noexcept
        {
            if (handle && handle != INVALID_HANDLE_VALUE) {
                CloseHandle(handle);
            }
        }
    };

    using UniqueHandle = std::unique_ptr<std::remove_pointer_t<HANDLE>, HandleDeleter>;  ///< Smart handle type
    
    // ========================================================================
    // PRIVATE MEMBERS
    // ========================================================================
    
    std::wstring m_deviceName;      ///< Driver device name (e.g., "\\\\.\\KVCDriver")
    UniqueHandle m_deviceHandle;    ///< Smart handle to driver device

    // ========================================================================
    // LOW-LEVEL IOCTL COMMUNICATION
    // ========================================================================
    
    /**
     * @brief Low-level memory read via IOCTL
     * @param address Kernel address to read from
     * @param valueSize Size of value to read (1/2/4 bytes)
     * @return std::optional<DWORD> Read value or nullopt on failure
     * @note Internal implementation used by type-safe read methods
     */
    std::optional<DWORD> Read(ULONG_PTR address, DWORD valueSize) noexcept;
    
    /**
     * @brief Low-level memory write via IOCTL
     * @param address Kernel address to write to
     * @param valueSize Size of value to write (1/2/4 bytes)
     * @param value Value to write
     * @return bool true if write successful
     * @note Internal implementation used by type-safe write methods
     */
    bool Write(ULONG_PTR address, DWORD valueSize, DWORD value) noexcept;
};