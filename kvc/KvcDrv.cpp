/**
 * @file kvcDrv.cpp
 * @brief KVC kernel driver communication implementation
 * @author Marek Wesolowski
 * @date 2025
 * @copyright KVC Framework
 * 
 * Implements low-level IOCTL communication with the KVC kernel driver
 * for safe memory read/write operations in kernel space.
 */

#include "kvcDrv.h"
#include "common.h"

// ============================================================================
// IOCTL COMMAND CODES (DRIVER-SPECIFIC)
// ============================================================================

/** @brief IOCTL code for kernel memory read operations */
constexpr DWORD RTC_IOCTL_MEMORY_READ = 0x80002048;

/** @brief IOCTL code for kernel memory write operations */
constexpr DWORD RTC_IOCTL_MEMORY_WRITE = 0x8000204c;

// ============================================================================
// CONSTRUCTION AND DESTRUCTION
// ============================================================================

/**
 * @brief Default constructor - initializes empty driver object
 */
kvc::kvc() = default;

/**
 * @brief Destructor - ensures proper resource cleanup
 */
kvc::~kvc() 
{
    Cleanup();
}

// ============================================================================
// DRIVER CONNECTION MANAGEMENT
// ============================================================================

/**
 * @brief Cleans up driver resources with proper flushing
 * 
 * Performs orderly shutdown:
 * 1. Flushes file buffers to ensure all pending operations complete
 * 2. Resets smart handle (automatically calls CloseHandle)
 * 3. Clears device name
 * 
 * @note Safe to call multiple times - idempotent operation
 * @note Critical for system stability - prevents hanging IOCTL operations
 */
void kvc::Cleanup() noexcept 
{
    DEBUG(L"kvc::Cleanup() called");
    
    if (m_deviceHandle) {
        DEBUG(L"Closing device handle...");
        
        // Flush buffers before closing to prevent data loss
        FlushFileBuffers(m_deviceHandle.get());
        
        // Reset smart handle - automatically closes via HandleDeleter
        m_deviceHandle.reset();
    }
    
    m_deviceName.clear();
    DEBUG(L"kvc cleanup completed");
}

/**
 * @brief Checks if driver connection is active
 * 
 * @return bool true if device handle is valid and not INVALID_HANDLE_VALUE
 */
bool kvc::IsConnected() const noexcept 
{
    return m_deviceHandle && m_deviceHandle.get() != INVALID_HANDLE_VALUE;
}

/**
 * @brief Establishes connection to KVC kernel driver
 * 
 * Connection sequence:
 * 1. Checks if already connected (idempotent)
 * 2. Constructs device name from service name
 * 3. Initializes dynamic APIs for CreateFileW
 * 4. Opens device handle with read/write access
 * 5. Wraps raw handle in smart pointer for RAII
 * 
 * @return bool true if driver device opened successfully
 * 
 * @note Does NOT perform test operations - just opens device
 * @note Silently fails if driver not loaded (expected behavior)
 * @note Requires dynamic API initialization for CreateFileW
 */
bool kvc::Initialize() noexcept 
{
    // Idempotent check - return early if already connected
    if (IsConnected()) {
        return true;
    }

    // Construct device name if not set
    if (m_deviceName.empty()) {
        m_deviceName = L"\\\\.\\" + GetServiceName();
    }

    // Initialize dynamic APIs (required for CreateFileW pointer)
    if (!InitDynamicAPIs()) {
        DEBUG(L"Failed to initialize dynamic APIs");
        return false;
    }
    
    // Open driver device with read/write access
    HANDLE rawHandle = g_pCreateFileW(
        m_deviceName.c_str(), 
        GENERIC_READ | GENERIC_WRITE, 
        0,                          // No sharing
        nullptr,                    // Default security
        OPEN_EXISTING,              // Device must exist
        0,                          // No special flags
        nullptr                     // No template
    );

    // Silent failure if driver not loaded - this is expected behavior
    if (rawHandle == INVALID_HANDLE_VALUE) {
        DEBUG(L"Failed to open driver device: %s (error: %d)", 
              m_deviceName.c_str(), GetLastError());
        return false;
    }

    // Wrap raw handle in smart pointer for automatic cleanup
    m_deviceHandle = UniqueHandle(rawHandle);
    
    DEBUG(L"Successfully opened driver device: %s", m_deviceName.c_str());
    return true;
}

// ============================================================================
// MEMORY READ OPERATIONS (TYPE-SAFE WRAPPERS)
// ============================================================================

/**
 * @brief Reads 8-bit value from kernel memory
 * 
 * @param address Target kernel address
 * @return std::optional<BYTE> Read value or nullopt on failure
 * 
 * @note Extracts lowest byte from 32-bit read result
 */
std::optional<BYTE> kvc::Read8(ULONG_PTR address) noexcept 
{
    auto value = Read32(address);
    if (!value.has_value()) {
        return std::nullopt;
    }
    return static_cast<BYTE>(value.value() & 0xFF);
}

/**
 * @brief Reads 16-bit value from kernel memory
 * 
 * @param address Target kernel address
 * @return std::optional<WORD> Read value or nullopt on failure
 * 
 * @note Extracts lowest 2 bytes from 32-bit read result
 */
std::optional<WORD> kvc::Read16(ULONG_PTR address) noexcept 
{
    auto value = Read32(address);
    if (!value.has_value()) {
        return std::nullopt;
    }
    return static_cast<WORD>(value.value() & 0xFFFF);
}

/**
 * @brief Reads 32-bit value from kernel memory
 * 
 * @param address Target kernel address
 * @return std::optional<DWORD> Read value or nullopt on failure
 * 
 * @note Direct call to low-level Read() function
 */
std::optional<DWORD> kvc::Read32(ULONG_PTR address) noexcept 
{
    return Read(address, sizeof(DWORD));
}

/**
 * @brief Reads 64-bit value from kernel memory
 * 
 * @param address Target kernel address
 * @return std::optional<DWORD64> Read value or nullopt on failure
 * 
 * @note Performs two 32-bit reads and combines them:
 *       - Low DWORD at address
 *       - High DWORD at address + 4
 * @note Both reads must succeed for operation to succeed
 */
std::optional<DWORD64> kvc::Read64(ULONG_PTR address) noexcept 
{
    auto low = Read32(address);
    auto high = Read32(address + 4);
    
    if (!low || !high) {
        return std::nullopt;
    }
    
    // Combine low and high DWORDs into QWORD
    return (static_cast<DWORD64>(high.value()) << 32) | low.value();
}

/**
 * @brief Reads pointer-sized value from kernel memory
 * 
 * @param address Target kernel address
 * @return std::optional<ULONG_PTR> Read value or nullopt on failure
 * 
 * @note Platform-dependent:
 *       - x64: Uses Read64
 *       - x86: Uses Read32
 */
std::optional<ULONG_PTR> kvc::ReadPtr(ULONG_PTR address) noexcept 
{
#ifdef _WIN64
    auto value = Read64(address);
    if (!value.has_value()) {
        return std::nullopt;
    }
    return static_cast<ULONG_PTR>(value.value());
#else
    auto value = Read32(address);
    if (!value.has_value()) {
        return std::nullopt;
    }
    return static_cast<ULONG_PTR>(value.value());
#endif
}

// ============================================================================
// MEMORY WRITE OPERATIONS (TYPE-SAFE WRAPPERS)
// ============================================================================

/**
 * @brief Writes 8-bit value to kernel memory
 * 
 * @param address Target kernel address
 * @param value Value to write
 * @return bool true if write successful
 * 
 * @warning Kernel memory writes can cause system instability
 */
bool kvc::Write8(ULONG_PTR address, BYTE value) noexcept 
{
    return Write(address, sizeof(value), value);
}

/**
 * @brief Writes 16-bit value to kernel memory
 * 
 * @param address Target kernel address
 * @param value Value to write
 * @return bool true if write successful
 * 
 * @warning Kernel memory writes can cause system instability
 */
bool kvc::Write16(ULONG_PTR address, WORD value) noexcept 
{
    return Write(address, sizeof(value), value);
}

/**
 * @brief Writes 32-bit value to kernel memory
 * 
 * @param address Target kernel address
 * @param value Value to write
 * @return bool true if write successful
 * 
 * @warning Kernel memory writes can cause system instability
 */
bool kvc::Write32(ULONG_PTR address, DWORD value) noexcept 
{
    return Write(address, sizeof(value), value);
}

/**
 * @brief Writes 64-bit value to kernel memory
 * 
 * @param address Target kernel address
 * @param value Value to write
 * @return bool true if write successful
 * 
 * @note Performs two 32-bit writes:
 *       - Low DWORD at address
 *       - High DWORD at address + 4
 * @note Both writes must succeed for operation to succeed
 * 
 * @warning Kernel memory writes can cause system instability
 * @warning Non-atomic operation - system may observe partial write
 */
bool kvc::Write64(ULONG_PTR address, DWORD64 value) noexcept 
{
    DWORD low = static_cast<DWORD>(value & 0xFFFFFFFF);
    DWORD high = static_cast<DWORD>((value >> 32) & 0xFFFFFFFF);
    
    // Both writes must succeed
    return Write32(address, low) && Write32(address + 4, high);
}

// ============================================================================
// LOW-LEVEL IOCTL COMMUNICATION
// ============================================================================

/**
 * @brief Low-level kernel memory read via IOCTL
 * 
 * Communication sequence:
 * 1. Ensures driver connection is initialized
 * 2. Constructs RTC_MEMORY_READ request structure
 * 3. Sends IOCTL_MEMORY_READ command to driver
 * 4. Extracts returned value from response
 * 
 * @param address Kernel address to read from
 * @param valueSize Size of value to read (1/2/4 bytes)
 * @return std::optional<DWORD> Read value or nullopt on failure
 * 
 * @note Uses aligned structure for IOCTL communication
 * @note Driver returns value in response structure
 */
std::optional<DWORD> kvc::Read(ULONG_PTR address, DWORD valueSize) noexcept 
{
    // Construct read request with proper alignment
    RTC_MEMORY_READ memoryRead{};
    memoryRead.Address = address;
    memoryRead.Size = valueSize;

    // Ensure driver connection
    if (!Initialize()) {
        DEBUG(L"Driver not initialized for read operation");
        return std::nullopt;
    }

    DWORD bytesReturned = 0;
    
    // Send IOCTL to driver
    BOOL result = DeviceIoControl(
        m_deviceHandle.get(),           // Device handle
        RTC_IOCTL_MEMORY_READ,          // IOCTL code
        &memoryRead,                    // Input buffer
        sizeof(memoryRead),             // Input size
        &memoryRead,                    // Output buffer (in-place)
        sizeof(memoryRead),             // Output size
        &bytesReturned,                 // Bytes returned
        nullptr                         // No overlapped I/O
    );
    
    if (!result) {
        DEBUG(L"DeviceIoControl failed for read at 0x%llx: %d", 
              address, GetLastError());
        return std::nullopt;
    }

    return memoryRead.Value;
}

/**
 * @brief Low-level kernel memory write via IOCTL
 * 
 * Communication sequence:
 * 1. Ensures driver connection is initialized
 * 2. Constructs RTC_MEMORY_WRITE request structure
 * 3. Sends IOCTL_MEMORY_WRITE command to driver
 * 4. Checks for successful completion
 * 
 * @param address Kernel address to write to
 * @param valueSize Size of value to write (1/2/4 bytes)
 * @param value Value to write
 * @return bool true if write successful
 * 
 * @note Uses aligned structure for IOCTL communication
 * @warning Kernel writes can cause BSOD if address is invalid
 */
bool kvc::Write(ULONG_PTR address, DWORD valueSize, DWORD value) noexcept 
{
    // Construct write request with proper alignment
    RTC_MEMORY_WRITE memoryWrite{};
    memoryWrite.Address = address;
    memoryWrite.Size = valueSize;
    memoryWrite.Value = value;

    // Ensure driver connection
    if (!Initialize()) {
        DEBUG(L"Driver not initialized for write operation");
        return false;
    }

    DWORD bytesReturned = 0;
    
    // Send IOCTL to driver
    BOOL result = DeviceIoControl(
        m_deviceHandle.get(),           // Device handle
        RTC_IOCTL_MEMORY_WRITE,         // IOCTL code
        &memoryWrite,                   // Input buffer
        sizeof(memoryWrite),            // Input size
        &memoryWrite,                   // Output buffer (unused for write)
        sizeof(memoryWrite),            // Output size
        &bytesReturned,                 // Bytes returned
        nullptr                         // No overlapped I/O
    );
    
    if (!result) {
        DEBUG(L"DeviceIoControl failed for write at 0x%llx: %d", 
              address, GetLastError());
        return false;
    }
    
    return true;
}