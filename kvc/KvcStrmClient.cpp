// KvcStrmClient.cpp
// Implementacja wrappera kvcstrm IOCTL dla usermode.

#include "KvcStrmClient.h"
#include "common.h"    // INFO, ERROR, DEBUG, etc.

// ============================================================
//  Pomocnicza funkcja: oblicz IOCTL_CODE
//  CTL_CODE(DeviceType, Function, Method, Access)
//  FILE_DEVICE_UNKNOWN = 0x22
//  METHOD_BUFFERED     = 0
//  FILE_ANY_ACCESS     = 0
//  => (0x22 << 16) | (0 << 14) | (function << 2) | 0
// ============================================================

static constexpr DWORD MakeIoctl(DWORD function) noexcept {
    return (0x22UL << 16) | (function << 2);
}

// Weryfikacja formuly MakeIoctl wzgledem wartosci z naglowka (bez dostepu do private)
static_assert(MakeIoctl(0x800) == 0x00222000, "IOCTL_VM_READ");
static_assert(MakeIoctl(0x801) == 0x00222004, "IOCTL_VM_WRITE");
static_assert(MakeIoctl(0x802) == 0x00222008, "IOCTL_VM_BULK");
static_assert(MakeIoctl(0x803) == 0x0022200C, "IOCTL_KILL");
static_assert(MakeIoctl(0x804) == 0x00222010, "IOCTL_SET_PROT");
static_assert(MakeIoctl(0x805) == 0x00222014, "IOCTL_PHYS_READ");
static_assert(MakeIoctl(0x806) == 0x00222018, "IOCTL_PHYS_WRITE");
static_assert(MakeIoctl(0x807) == 0x0022201C, "IOCTL_KILL_WESMAR");
static_assert(MakeIoctl(0x808) == 0x00222020, "IOCTL_FREE");
static_assert(MakeIoctl(0x809) == 0x00222024, "IOCTL_WRITE_PROT");
static_assert(MakeIoctl(0x80A) == 0x00222028, "IOCTL_ELEVATE");
static_assert(MakeIoctl(0x80B) == 0x0022202C, "IOCTL_ALLOC");
static_assert(MakeIoctl(0x810) == 0x00222040, "IOCTL_KILL_NAME");
static_assert(MakeIoctl(0x811) == 0x00222044, "IOCTL_FORCE_HANDLE");

// ============================================================
//  ZARZADZANIE POLACZENIEM
// ============================================================

bool KvcStrmClient::Open() noexcept
{
    if (IsOpen()) return true;

    m_handle = CreateFileW(
        DEVICE_PATH,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (m_handle == INVALID_HANDLE_VALUE) {
        DEBUG(L"[KvcStrmClient] CreateFile(%s) failed: %lu", DEVICE_PATH, GetLastError());
        return false;
    }

    DEBUG(L"[KvcStrmClient] Polaczono z kvcstrm.sys");
    return true;
}

void KvcStrmClient::Close() noexcept
{
    if (IsOpen()) {
        CloseHandle(m_handle);
        m_handle = INVALID_HANDLE_VALUE;
    }
}

/*static*/ bool KvcStrmClient::IsDriverLoaded() noexcept
{
    HANDLE h = CreateFileW(
        DEVICE_PATH,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (h == INVALID_HANDLE_VALUE) return false;
    CloseHandle(h);
    return true;
}

// ============================================================
//  PRYWATNE HELPERY IOCTL
// ============================================================

StrmResult KvcStrmClient::Ioctl(DWORD code, void* buf, DWORD size) noexcept
{
    if (!IsOpen()) return StrmResult::Fail(STATUS_DEVICE_NOT_CONNECTED);

    DWORD returned = 0;
    BOOL ok = DeviceIoControl(
        m_handle,
        code,
        buf,   // inBuffer
        size,
        buf,   // outBuffer (METHOD_BUFFERED - ten sam bufor)
        size,
        &returned,
        nullptr
    );

    if (!ok) {
        DWORD err = GetLastError();
        DEBUG(L"[KvcStrmClient] IOCTL 0x%08X DeviceIoControl failed: %lu", code, err);
        return StrmResult::Fail(HRESULT_FROM_WIN32(err));
    }

    return StrmResult::Ok();
}

StrmResult KvcStrmClient::IoctlWithPayload(DWORD code,
                                            void* header, DWORD headerSize,
                                            const void* payload, SIZE_T payloadSize) noexcept
{
    if (!IsOpen()) return StrmResult::Fail(STATUS_DEVICE_NOT_CONNECTED);

    // Buduj ciagly bufor: [header][payload]
    DWORD totalSize = headerSize + static_cast<DWORD>(payloadSize);
    std::vector<BYTE> buf(totalSize);
    memcpy(buf.data(), header, headerSize);
    memcpy(buf.data() + headerSize, payload, payloadSize);

    DWORD returned = 0;
    BOOL ok = DeviceIoControl(
        m_handle,
        code,
        buf.data(),
        totalSize,
        buf.data(),
        totalSize,
        &returned,
        nullptr
    );

    if (!ok) {
        DWORD err = GetLastError();
        DEBUG(L"[KvcStrmClient] IoctlWithPayload 0x%08X failed: %lu", code, err);
        return StrmResult::Fail(HRESULT_FROM_WIN32(err));
    }

    // Skopiuj header z powrotem (zawiera pole Status)
    memcpy(header, buf.data(), headerSize);
    return StrmResult::Ok();
}

// ============================================================
//  WIRTUALNA PAMIEC R/W
// ============================================================

StrmResult KvcStrmClient::ReadVirtualMemory(ULONG pid, ULONG64 address,
                                             void* buffer, SIZE_T size) noexcept
{
    KVCSTRM_READWRITE_REQUEST req{};
    req.ProcessId = pid;
    req.Address   = address;
    req.Buffer    = reinterpret_cast<ULONG64>(buffer);
    req.Size      = size;
    req.Write     = FALSE;

    auto r = Ioctl(IOCTL_VM_READ, &req, sizeof(req));
    if (!r) return r;
    if (!NT_SUCCESS(req.Status)) return StrmResult::Fail(req.Status);
    return StrmResult::Ok();
}

StrmResult KvcStrmClient::WriteVirtualMemory(ULONG pid, ULONG64 address,
                                              const void* buffer, SIZE_T size) noexcept
{
    KVCSTRM_READWRITE_REQUEST req{};
    req.ProcessId = pid;
    req.Address   = address;
    req.Buffer    = reinterpret_cast<ULONG64>(buffer);
    req.Size      = size;
    req.Write     = TRUE;

    auto r = Ioctl(IOCTL_VM_WRITE, &req, sizeof(req));
    if (!r) return r;
    if (!NT_SUCCESS(req.Status)) return StrmResult::Fail(req.Status);
    return StrmResult::Ok();
}

StrmResult KvcStrmClient::BulkTransfer(KVCSTRM_BULK_OPERATION& bulk) noexcept
{
    if (bulk.Count == 0 || bulk.Count > 64)
        return StrmResult::Fail(STATUS_INVALID_PARAMETER);

    return Ioctl(IOCTL_VM_BULK, &bulk, sizeof(bulk));
}

// ============================================================
//  ZABIJANIE PROCESOW
// ============================================================

StrmResult KvcStrmClient::KillProcess(ULONG pid) noexcept
{
    KVCSTRM_KILL_REQUEST req{};
    req.ProcessId = pid;

    auto r = Ioctl(IOCTL_KILL, &req, sizeof(req));
    if (!r) return r;
    if (!NT_SUCCESS(req.Status)) {
        DEBUG(L"[KvcStrmClient] KillProcess(%lu) NTSTATUS=0x%08X", pid, req.Status);
        return StrmResult::Fail(req.Status);
    }

    INFO(L"[KvcStrmClient] KillProcess(%lu) OK", pid);
    return StrmResult::Ok();
}

StrmResult KvcStrmClient::KillProcessLegacy(ULONG pid) noexcept
{
    // IOCTL_KILL_PROCESS_WESMAR: wejscie to surowy ULONG PID,
    // status operacji wraca jako WDF request completion status (nie w strukturze)
    return Ioctl(IOCTL_KILL_WESMAR, &pid, sizeof(pid));
}

StrmResult KvcStrmClient::KillProcessesByName(const char* name,
                                               ULONG* killedCount) noexcept
{
    if (!name || name[0] == '\0')
        return StrmResult::Fail(STATUS_INVALID_PARAMETER);

    KVCSTRM_KILL_NAME_REQUEST req{};
    strncpy_s(req.ProcessName, sizeof(req.ProcessName), name, _TRUNCATE);

    auto r = Ioctl(IOCTL_KILL_NAME, &req, sizeof(req));
    if (!r) return r;
    if (!NT_SUCCESS(req.Status)) return StrmResult::Fail(req.Status);

    if (killedCount) *killedCount = req.KilledCount;

    INFO(L"[KvcStrmClient] KillByName('%S') zabilem %lu procesow",
         name, req.KilledCount);
    return StrmResult::Ok();
}

// ============================================================
//  MANIPULACJA PP/PPL
// ============================================================

StrmResult KvcStrmClient::SetProtection(ULONG pid,
                                         ULONG64 protectionOffset,
                                         UCHAR   protectionValue) noexcept
{
    if (protectionOffset == 0 || protectionOffset > 0x2000)
        return StrmResult::Fail(STATUS_INVALID_PARAMETER);

    KVCSTRM_PROTECTION_REQUEST req{};
    req.ProcessId        = pid;
    req.ProtectionOffset = protectionOffset;
    req.ProtectionValue  = protectionValue;

    auto r = Ioctl(IOCTL_SET_PROT, &req, sizeof(req));
    if (!r) return r;
    if (!NT_SUCCESS(req.Status)) {
        DEBUG(L"[KvcStrmClient] SetProtection(%lu, 0x%X, 0x%02X) NTSTATUS=0x%08X",
              pid, (ULONG)protectionOffset, protectionValue, req.Status);
        return StrmResult::Fail(req.Status);
    }

    DEBUG(L"[KvcStrmClient] SetProtection(%lu) -> 0x%02X OK", pid, protectionValue);
    return StrmResult::Ok();
}

// ============================================================
//  FIZYCZNA PAMIEC R/W
// ============================================================

StrmResult KvcStrmClient::ReadPhysicalMemory(ULONG64 physAddr,
                                              void* buffer, SIZE_T size) noexcept
{
    KVCSTRM_PHYSMEM_REQUEST req{};
    req.PhysicalAddress = physAddr;
    req.Buffer          = reinterpret_cast<ULONG64>(buffer);
    req.Size            = size;

    auto r = Ioctl(IOCTL_PHYS_READ, &req, sizeof(req));
    if (!r) return r;
    if (!NT_SUCCESS(req.Status)) return StrmResult::Fail(req.Status);
    return StrmResult::Ok();
}

StrmResult KvcStrmClient::WritePhysicalMemory(ULONG64 physAddr,
                                               const void* buffer, SIZE_T size) noexcept
{
    KVCSTRM_PHYSMEM_REQUEST req{};
    req.PhysicalAddress = physAddr;
    req.Buffer          = reinterpret_cast<ULONG64>(const_cast<void*>(buffer));
    req.Size            = size;

    auto r = Ioctl(IOCTL_PHYS_WRITE, &req, sizeof(req));
    if (!r) return r;
    if (!NT_SUCCESS(req.Status)) return StrmResult::Fail(req.Status);
    return StrmResult::Ok();
}

// ============================================================
//  ALOKACJA KERNEL POOL
// ============================================================

ULONG64 KvcStrmClient::AllocKernelMemory(SIZE_T size, ULONG flags) noexcept
{
    KVCSTRM_ALLOC_REQUEST req{};
    req.Size  = size;
    req.Flags = flags;

    auto r = Ioctl(IOCTL_ALLOC, &req, sizeof(req));
    if (!r || !NT_SUCCESS(req.Status)) {
        DEBUG(L"[KvcStrmClient] AllocKernelMemory(%zu) failed", size);
        return 0;
    }

    DEBUG(L"[KvcStrmClient] AllocKernelMemory(%zu) -> 0x%016llX", size, req.Address);
    return req.Address;
}

StrmResult KvcStrmClient::FreeKernelMemory(ULONG64 address) noexcept
{
    if (address == 0) return StrmResult::Fail(STATUS_INVALID_PARAMETER);

    KVCSTRM_FREE_REQUEST req{};
    req.Address = address;

    auto r = Ioctl(IOCTL_FREE, &req, sizeof(req));
    if (!r) return r;
    if (!NT_SUCCESS(req.Status)) return StrmResult::Fail(req.Status);
    return StrmResult::Ok();
}

// ============================================================
//  ZAPIS DO CHRONIONEJ PAMIECI KERNELA (CR0.WP bypass)
// ============================================================

StrmResult KvcStrmClient::WriteProtectedKernelMemory(ULONG64 dstAddress,
                                                      const void* data,
                                                      SIZE_T size) noexcept
{
    if (dstAddress == 0 || !data || size == 0)
        return StrmResult::Fail(STATUS_INVALID_PARAMETER);

    KVCSTRM_PROTECTED_WRITE_REQUEST hdr{};
    hdr.DstAddress = dstAddress;
    hdr.Size       = size;

    auto r = IoctlWithPayload(IOCTL_WRITE_PROT,
                               &hdr, sizeof(hdr),
                               data, size);
    if (!r) return r;
    if (!NT_SUCCESS(hdr.Status)) return StrmResult::Fail(hdr.Status);
    return StrmResult::Ok();
}

// ============================================================
//  TOKEN ELEVATION
// ============================================================

StrmResult KvcStrmClient::ElevateToken(ULONG pid, ULONG64 tokenOffset) noexcept
{
    if (tokenOffset == 0 || tokenOffset > 0x2000)
        return StrmResult::Fail(STATUS_INVALID_PARAMETER);

    KVCSTRM_TOKEN_REQUEST req{};
    req.ProcessId   = pid;
    req.TokenOffset = tokenOffset;

    auto r = Ioctl(IOCTL_ELEVATE, &req, sizeof(req));
    if (!r) return r;
    if (!NT_SUCCESS(req.Status)) {
        DEBUG(L"[KvcStrmClient] ElevateToken(%lu) NTSTATUS=0x%08X", pid, req.Status);
        return StrmResult::Fail(req.Status);
    }

    INFO(L"[KvcStrmClient] ElevateToken(%lu) -> SYSTEM OK", pid);
    return StrmResult::Ok();
}

// ============================================================
//  FORCE CLOSE HANDLE
// ============================================================

StrmResult KvcStrmClient::ForceCloseHandle(ULONG pid, HANDLE handleValue) noexcept
{
    if (!handleValue) return StrmResult::Fail(STATUS_INVALID_PARAMETER);

    KVCSTRM_CLOSE_HANDLE_REQUEST req{};
    req.ProcessId   = pid;
    req.HandleValue = handleValue;

    auto r = Ioctl(IOCTL_FORCE_HANDLE, &req, sizeof(req));
    if (!r) return r;
    if (!NT_SUCCESS(req.Status)) return StrmResult::Fail(req.Status);

    DEBUG(L"[KvcStrmClient] ForceCloseHandle(pid=%lu, handle=0x%p) OK",
          pid, handleValue);
    return StrmResult::Ok();
}
