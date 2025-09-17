#pragma once

#include "common.h"
#include <memory>
#include <optional>

// KVC driver communication structures with proper alignment
struct alignas(8) RTC_MEMORY_READ 
{
    BYTE Pad0[8];           // Alignment padding
    DWORD64 Address;        // Target memory address
    BYTE Pad1[8];           // Additional padding
    DWORD Size;             // Bytes to read
    DWORD Value;            // Returned value
    BYTE Pad3[16];          // Final padding
};

struct alignas(8) RTC_MEMORY_WRITE 
{
    BYTE Pad0[8];           // Alignment padding
    DWORD64 Address;        // Target memory address
    BYTE Pad1[8];           // Additional padding
    DWORD Size;             // Bytes to write
    DWORD Value;            // Value to write
    BYTE Pad3[16];          // Final padding
};

// Kernel memory operations interface via KVC driver
class kvc
{
public:
    kvc();
    ~kvc();

    kvc(const kvc&) = delete;
    kvc& operator=(const kvc&) = delete;
    kvc(kvc&&) noexcept = default;
    kvc& operator=(kvc&&) noexcept = default;

    // Driver connection management
    bool Initialize() noexcept;
    void Cleanup() noexcept;
    bool IsConnected() const noexcept;

    // Memory read operations with type safety
    std::optional<BYTE> Read8(ULONG_PTR address) noexcept;
    std::optional<WORD> Read16(ULONG_PTR address) noexcept;
    std::optional<DWORD> Read32(ULONG_PTR address) noexcept;
    std::optional<DWORD64> Read64(ULONG_PTR address) noexcept;
    std::optional<ULONG_PTR> ReadPtr(ULONG_PTR address) noexcept;
    
    // Memory write operations with type safety
    bool Write8(ULONG_PTR address, BYTE value) noexcept;
    bool Write16(ULONG_PTR address, WORD value) noexcept;
    bool Write32(ULONG_PTR address, DWORD value) noexcept;
    bool Write64(ULONG_PTR address, DWORD64 value) noexcept;

private:
    // Smart handle wrapper for automatic cleanup
    struct HandleDeleter
    {
        void operator()(HANDLE handle) const noexcept
        {
            if (handle && handle != INVALID_HANDLE_VALUE)
                CloseHandle(handle);
        }
    };

    using UniqueHandle = std::unique_ptr<std::remove_pointer_t<HANDLE>, HandleDeleter>;
    
    std::wstring m_deviceName;      // Driver device name
    UniqueHandle m_deviceHandle;    // Handle to driver device

    // Low-level communication via IOCTL
    std::optional<DWORD> Read(ULONG_PTR address, DWORD valueSize) noexcept;
    bool Write(ULONG_PTR address, DWORD valueSize, DWORD value) noexcept;
};