// KvcDrv.cpp
#include "kvcDrv.h"
#include "common.h"
#include <format>

// IOCTL command codes for KVC driver communication
constexpr DWORD RTC_IOCTL_MEMORY_READ = 0x80002048;
constexpr DWORD RTC_IOCTL_MEMORY_WRITE = 0x8000204c;

kvc::kvc() = default;

kvc::~kvc() {
    Cleanup();
}

// Force cleanup for atomic driver operations - critical for stability
void kvc::Cleanup() noexcept {
    DEBUG(L"kvc::Cleanup() called");
    
    if (m_deviceHandle) {
        DEBUG(L"Closing device handle...");
        // Force the handle to close
        FlushFileBuffers(m_deviceHandle.get());
        m_deviceHandle.reset(); // This should close the handle
    }
    
    m_deviceName.clear();
    DEBUG(L"kvc cleanup completed");
}

bool kvc::IsConnected() const noexcept {
    return m_deviceHandle && m_deviceHandle.get() != INVALID_HANDLE_VALUE;
}

// Driver connection establishment with device path
bool kvc::Initialize() noexcept {
    if (IsConnected()) {
        return true;
    }

    if (m_deviceName.empty()) {
        m_deviceName = L"\\\\.\\" + GetServiceName();
    }

    if (!InitDynamicAPIs()) return false;
    
    // SIMPLE DEVICE OPEN - without test operations
    HANDLE rawHandle = g_pCreateFileW(m_deviceName.c_str(), 
                                      GENERIC_READ | GENERIC_WRITE, 
                                      0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (rawHandle == INVALID_HANDLE_VALUE) {
        return false; // Silently fail - this is normal when the driver is not running
    }

    m_deviceHandle = UniqueHandle(rawHandle);
    return true;
}

// Memory read operations with type safety
std::optional<BYTE> kvc::Read8(ULONG_PTR address) noexcept {
    auto value = Read32(address);
    if (!value.has_value()) return std::nullopt;
    return static_cast<BYTE>(value.value() & 0xff);
}

std::optional<WORD> kvc::Read16(ULONG_PTR address) noexcept {
    auto value = Read32(address);
    if (!value.has_value()) return std::nullopt;
    return static_cast<WORD>(value.value() & 0xffff);
}

std::optional<DWORD> kvc::Read32(ULONG_PTR address) noexcept {
    return Read(address, sizeof(DWORD));
}

std::optional<DWORD64> kvc::Read64(ULONG_PTR address) noexcept {
    auto low = Read32(address);
    auto high = Read32(address + 4);
    
    if (!low || !high) return std::nullopt;
    
    return (static_cast<DWORD64>(high.value()) << 32) | low.value();
}

std::optional<ULONG_PTR> kvc::ReadPtr(ULONG_PTR address) noexcept {
#ifdef _WIN64
    auto value = Read64(address);
    if (!value.has_value()) return std::nullopt;
    return static_cast<ULONG_PTR>(value.value());
#else
    auto value = Read32(address);
    if (!value.has_value()) return std::nullopt;
    return static_cast<ULONG_PTR>(value.value());
#endif
}

// Memory write operations with type safety
bool kvc::Write8(ULONG_PTR address, BYTE value) noexcept {
    return Write(address, sizeof(value), value);
}

bool kvc::Write16(ULONG_PTR address, WORD value) noexcept {
    return Write(address, sizeof(value), value);
}

bool kvc::Write32(ULONG_PTR address, DWORD value) noexcept {
    return Write(address, sizeof(value), value);
}

bool kvc::Write64(ULONG_PTR address, DWORD64 value) noexcept {
    DWORD low = static_cast<DWORD>(value & 0xffffffff);
    DWORD high = static_cast<DWORD>((value >> 32) & 0xffffffff);
    return Write32(address, low) && Write32(address + 4, high);
}

// Low-level driver communication via IOCTL
std::optional<DWORD> kvc::Read(ULONG_PTR address, DWORD valueSize) noexcept {
    RTC_MEMORY_READ memoryRead{};
    memoryRead.Address = address;
    memoryRead.Size = valueSize;

    if (!Initialize()) return std::nullopt;

    DWORD bytesReturned = 0;
    if (!DeviceIoControl(m_deviceHandle.get(), RTC_IOCTL_MEMORY_READ, 
                        &memoryRead, sizeof(memoryRead), &memoryRead, sizeof(memoryRead), &bytesReturned, nullptr))
        return std::nullopt;

    return memoryRead.Value;
}

bool kvc::Write(ULONG_PTR address, DWORD valueSize, DWORD value) noexcept {
    RTC_MEMORY_WRITE memoryWrite{};
    memoryWrite.Address = address;
    memoryWrite.Size = valueSize;
    memoryWrite.Value = value;

    if (!Initialize()) return false;

    DWORD bytesReturned = 0;
    return DeviceIoControl(m_deviceHandle.get(), RTC_IOCTL_MEMORY_WRITE, 
                          &memoryWrite, sizeof(memoryWrite), &memoryWrite, sizeof(memoryWrite), &bytesReturned, nullptr);
}
