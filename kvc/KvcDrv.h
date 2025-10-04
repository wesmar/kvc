/**
 * @file kvcDrv.h
 * @brief KVC kernel driver communication interface
 * @author Marek Wesolowski
 * @date 2025
 * @copyright KVC Framework
 * 
 * Provides low-level IOCTL-based communication with the KVC kernel driver
 * for memory read/write operations in kernel address space.
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
 */
struct alignas(8) RTC_MEMORY_READ 
{
    BYTE Pad0[8];           ///< Alignment padding
    DWORD64 Address;        ///< Target kernel memory address
    BYTE Pad1[8];           ///< Additional padding
    DWORD Size;             ///< Number of bytes to read (1/2/4/8)
    DWORD Value;            ///< Returned value from kernel
    BYTE Pad3[16];          ///< Final padding for alignment
};

/**
 * @brief Memory write request structure with proper alignment
 * 
 * Layout optimized for driver IOCTL communication with explicit padding
 * to ensure consistent structure size across user/kernel boundary.
 */
struct alignas(8) RTC_MEMORY_WRITE 
{
    BYTE Pad0[8];           ///< Alignment padding
    DWORD64 Address;        ///< Target kernel memory address
    BYTE Pad1[8];           ///< Additional padding
    DWORD Size;             ///< Number of bytes to write (1/2/4/8)
    DWORD Value;            ///< Value to write to kernel
    BYTE Pad3[16];          ///< Final padding for alignment
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
 */
class kvc
{
public:
    /**
     * @brief Default constructor
     */
    kvc();
    
    /**
     * @brief Destructor with automatic cleanup
     */
    ~kvc();

    // Disable copy semantics to prevent handle duplication
    kvc(const kvc&) = delete;
    kvc& operator=(const kvc&) = delete;
    
    // Enable move semantics for efficient resource transfer
    kvc(kvc&&) noexcept = default;
    kvc& operator=(kvc&&) noexcept = default;

    // ========================================================================
    // DRIVER CONNECTION MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Initializes connection to KVC kernel driver
     * 
     * Attempts to open device handle to driver. Safe to call multiple times.
     * 
     * @return bool true if driver connection established successfully
     * @note Does not perform test operations - just opens device handle
     */
    bool Initialize() noexcept;
    
    /**
     * @brief Cleans up driver resources and closes connection
     * 
     * Flushes buffers and releases device handle. Safe to call multiple times.
     */
    void Cleanup() noexcept;
    
    /**
     * @brief Checks if driver connection is active
     * 
     * @return bool true if device handle is valid and open
     */
    bool IsConnected() const noexcept;

    // ========================================================================
    // MEMORY READ OPERATIONS (TYPE-SAFE)
    // ========================================================================
    
    /**
     * @brief Reads 8-bit value from kernel memory
     * @param address Target kernel address
     * @return std::optional<BYTE> Read value or nullopt on failure
     */
    std::optional<BYTE> Read8(ULONG_PTR address) noexcept;
    
    /**
     * @brief Reads 16-bit value from kernel memory
     * @param address Target kernel address
     * @return std::optional<WORD> Read value or nullopt on failure
     */
    std::optional<WORD> Read16(ULONG_PTR address) noexcept;
    
    /**
     * @brief Reads 32-bit value from kernel memory
     * @param address Target kernel address
     * @return std::optional<DWORD> Read value or nullopt on failure
     */
    std::optional<DWORD> Read32(ULONG_PTR address) noexcept;
    
    /**
     * @brief Reads 64-bit value from kernel memory
     * @param address Target kernel address
     * @return std::optional<DWORD64> Read value or nullopt on failure
     * @note Performs two 32-bit reads and combines them
     */
    std::optional<DWORD64> Read64(ULONG_PTR address) noexcept;
    
    /**
     * @brief Reads pointer-sized value from kernel memory
     * @param address Target kernel address
     * @return std::optional<ULONG_PTR> Read value or nullopt on failure
     * @note Uses Read64 on x64, Read32 on x86
     */
    std::optional<ULONG_PTR> ReadPtr(ULONG_PTR address) noexcept;
    
    // ========================================================================
    // MEMORY WRITE OPERATIONS (TYPE-SAFE)
    // ========================================================================
    
    /**
     * @brief Writes 8-bit value to kernel memory
     * @param address Target kernel address
     * @param value Value to write
     * @return bool true if write successful
     * @warning Kernel writes can cause system instability if misused
     */
    bool Write8(ULONG_PTR address, BYTE value) noexcept;
    
    /**
     * @brief Writes 16-bit value to kernel memory
     * @param address Target kernel address
     * @param value Value to write
     * @return bool true if write successful
     * @warning Kernel writes can cause system instability if misused
     */
    bool Write16(ULONG_PTR address, WORD value) noexcept;
    
    /**
     * @brief Writes 32-bit value to kernel memory
     * @param address Target kernel address
     * @param value Value to write
     * @return bool true if write successful
     * @warning Kernel writes can cause system instability if misused
     */
    bool Write32(ULONG_PTR address, DWORD value) noexcept;
    
    /**
     * @brief Writes 64-bit value to kernel memory
     * @param address Target kernel address
     * @param value Value to write
     * @return bool true if write successful
     * @note Performs two 32-bit writes
     * @warning Kernel writes can cause system instability if misused
     */
    bool Write64(ULONG_PTR address, DWORD64 value) noexcept;
	
private:
    // ========================================================================
    // SMART HANDLE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Custom deleter for automatic HANDLE cleanup
     */
    struct HandleDeleter
    {
        void operator()(HANDLE handle) const noexcept
        {
            if (handle && handle != INVALID_HANDLE_VALUE) {
                CloseHandle(handle);
            }
        }
    };

    using UniqueHandle = std::unique_ptr<std::remove_pointer_t<HANDLE>, HandleDeleter>;
    
    // ========================================================================
    // PRIVATE MEMBERS
    // ========================================================================
    
    std::wstring m_deviceName;      ///< Driver device name (e.g., "\\.\KVCDriver")
    UniqueHandle m_deviceHandle;    ///< Smart handle to driver device

    // ========================================================================
    // LOW-LEVEL IOCTL COMMUNICATION
    // ========================================================================
    
    /**
     * @brief Low-level memory read via IOCTL
     * @param address Kernel address to read from
     * @param valueSize Size of value (1/2/4 bytes)
     * @return std::optional<DWORD> Read value or nullopt on failure
     */
    std::optional<DWORD> Read(ULONG_PTR address, DWORD valueSize) noexcept;
    
    /**
     * @brief Low-level memory write via IOCTL
     * @param address Kernel address to write to
     * @param valueSize Size of value (1/2/4 bytes)
     * @param value Value to write
     * @return bool true if write successful
     */
    bool Write(ULONG_PTR address, DWORD valueSize, DWORD value) noexcept;
};