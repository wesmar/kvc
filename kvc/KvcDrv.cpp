// KVC kernel driver communication implementation- Implements low-level IOCTL communication with the KVC kernel driver

#include "kvcDrv.h"
#include "common.h"

// ============================================================================
// IOCTL COMMAND CODES (DRIVER-SPECIFIC)
// ============================================================================

// IOCTL code for kernel memory read operations
constexpr DWORD RTC_IOCTL_MEMORY_READ = 0x80002048;

// IOCTL code for kernel memory write operations
constexpr DWORD RTC_IOCTL_MEMORY_WRITE = 0x8000204c;

// ============================================================================
// CONSTRUCTION AND DESTRUCTION
// ============================================================================

// Default constructor - initializes empty driver object
kvc::kvc() = default;

// Destructor - ensures proper resource cleanup
kvc::~kvc() 
{
    Cleanup();
}

// ============================================================================
// DRIVER CONNECTION MANAGEMENT
// ============================================================================

// Cleans up driver resources by flushing buffers, closing handle and clearing device name
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

// Checks if driver connection is active
bool kvc::IsConnected() const noexcept 
{
    return m_deviceHandle && m_deviceHandle.get() != INVALID_HANDLE_VALUE;
}

// Establishes connection to KVC kernel driver by opening device handle with read/write access
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

/*    // Silent failure if driver not loaded - this is expected behavior
    if (rawHandle == INVALID_HANDLE_VALUE) {
        DEBUG(L"Failed to open driver device: %s (error: %d)", 
              m_deviceName.c_str(), GetLastError());
        return false;
    }
*/
    // Wrap raw handle in smart pointer for automatic cleanup
    m_deviceHandle = UniqueHandle(rawHandle);
    
    DEBUG(L"Successfully opened driver device: %s", m_deviceName.c_str());
    return true;
}

// ============================================================================
// MEMORY READ OPERATIONS (TYPE-SAFE WRAPPERS)
// ============================================================================

// Reads 8-bit value from kernel memory by extracting lowest byte from 32-bit read
std::optional<BYTE> kvc::Read8(ULONG_PTR address) noexcept 
{
    auto value = Read32(address);
    if (!value.has_value()) {
        return std::nullopt;
    }
    return static_cast<BYTE>(value.value() & 0xFF);
}

// Reads 16-bit value from kernel memory by extracting lowest 2 bytes from 32-bit read
std::optional<WORD> kvc::Read16(ULONG_PTR address) noexcept 
{
    auto value = Read32(address);
    if (!value.has_value()) {
        return std::nullopt;
    }
    return static_cast<WORD>(value.value() & 0xFFFF);
}

// Reads 32-bit value from kernel memory via direct IOCTL call
std::optional<DWORD> kvc::Read32(ULONG_PTR address) noexcept 
{
    return Read(address, sizeof(DWORD));
}

// Reads 64-bit value from kernel memory by performing two 32-bit reads and combining them
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

// Reads pointer-sized value from kernel memory (64-bit on x64, 32-bit on x86)
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

// Writes 8-bit value to kernel memory (WARNING: can cause system instability)
bool kvc::Write8(ULONG_PTR address, BYTE value) noexcept 
{
    return Write(address, sizeof(value), value);
}

// Writes 16-bit value to kernel memory (WARNING: can cause system instability)
bool kvc::Write16(ULONG_PTR address, WORD value) noexcept 
{
    return Write(address, sizeof(value), value);
}

// Writes 32-bit value to kernel memory (WARNING: can cause system instability)
bool kvc::Write32(ULONG_PTR address, DWORD value) noexcept 
{
    return Write(address, sizeof(value), value);
}

// Writes 64-bit value to kernel memory via two 32-bit writes (WARNING: non-atomic, can cause system instability)
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

// Low-level kernel memory read via IOCTL using aligned RTC_MEMORY_READ structure
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

// Low-level kernel memory write via IOCTL (WARNING: can cause BSOD if address is invalid)
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