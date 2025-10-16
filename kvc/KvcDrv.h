// kvcDrv.h - KVC kernel driver interface for memory read/write via IOCTL

#pragma once

#include "common.h"
#include <memory>
#include <optional>

// Memory read request for IOCTL, properly aligned
struct alignas(8) RTC_MEMORY_READ 
{
    BYTE Pad0[8];
    DWORD64 Address;    ///< Target kernel address
    BYTE Pad1[8];
    DWORD Size;         ///< Number of bytes to read
    DWORD Value;        ///< Returned value
    BYTE Pad3[16];
};

// Memory write request for IOCTL, properly aligned
struct alignas(8) RTC_MEMORY_WRITE 
{
    BYTE Pad0[8];
    DWORD64 Address;    ///< Target kernel address
    BYTE Pad1[8];
    DWORD Size;         ///< Number of bytes to write
    DWORD Value;        ///< Value to write
    BYTE Pad3[16];
};

// KVC driver communication class for type-safe kernel memory operations
class kvc
{
public:
    kvc();                  ///< Construct driver interface
    ~kvc();                 ///< Destructor with automatic cleanup

    kvc(const kvc&) = delete;
    kvc& operator=(const kvc&) = delete;
    kvc(kvc&&) noexcept = default;
    kvc& operator=(kvc&&) noexcept = default;

    // Driver connection management
    bool Initialize() noexcept;   ///< Connect to KVC driver
    void Cleanup() noexcept;      ///< Close driver connection
    bool IsConnected() const noexcept;  ///< Check connection status

    // Memory read operations
    std::optional<BYTE> Read8(ULONG_PTR address) noexcept;
    std::optional<WORD> Read16(ULONG_PTR address) noexcept;
    std::optional<DWORD> Read32(ULONG_PTR address) noexcept;
    std::optional<DWORD64> Read64(ULONG_PTR address) noexcept;
    std::optional<ULONG_PTR> ReadPtr(ULONG_PTR address) noexcept;

    // Memory write operations
    bool Write8(ULONG_PTR address, BYTE value) noexcept;
    bool Write16(ULONG_PTR address, WORD value) noexcept;
    bool Write32(ULONG_PTR address, DWORD value) noexcept;
    bool Write64(ULONG_PTR address, DWORD64 value) noexcept;

private:
    // Smart handle management
    struct HandleDeleter { void operator()(HANDLE handle) const noexcept { if (handle && handle != INVALID_HANDLE_VALUE) CloseHandle(handle); } };
    using UniqueHandle = std::unique_ptr<std::remove_pointer_t<HANDLE>, HandleDeleter>;

    std::wstring m_deviceName;   ///< Driver device name
    UniqueHandle m_deviceHandle; ///< Managed driver handle

    // Low-level IOCTL operations
    std::optional<DWORD> Read(ULONG_PTR address, DWORD valueSize) noexcept;  ///< Internal read helper
    bool Write(ULONG_PTR address, DWORD valueSize, DWORD value) noexcept;    ///< Internal write helper
};
