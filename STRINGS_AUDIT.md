# KVC Binary String Audit

## Scope

- Binary: `bin/kvc.exe`
- Size: 1,445,888 bytes
- SHA-256: `9A6F558FD2C177B04B4EC6CECAC26DCDB4F104831070CCE46FA6935D0BDB6D4D`
- Audit date: 2026-11-12
- Method: exact byte-pattern search for selected security-relevant terms in both
  ASCII and UTF-16LE. Offsets are absolute file offsets.

This is a targeted audit of service names, device names, component filenames,
registry paths, API privilege names, and legacy identifiers. It is not a full
decompilation of embedded resources.

## Summary

The current binary does not contain these retired or encoded identifiers as
plaintext:

```text
RTCore64
Topaz
Warsaw
wsftprm
Warsaw_PM
PROMOSOFT
Promosoft
Secure Folders
wallpaper.bmp
```

`RTCore64` remains encoded by the `MmPoolTelemetry.asm` runtime decoder. The CAB
entry name and processed component data are inside the compressed BMP payload,
so their names do not appear as direct binary strings.

## Plaintext component and service identifiers

| Term | Encoding | Count | File offsets |
|---|---:|---:|---|
| `K7RKScan` | UTF-16LE | 2 | `0x242A8`, `0x39892` |
| `\\.\DosK7RKScnDrv` | UTF-16LE | 1 | `0x24318` |
| `K7 Computing` | UTF-16LE | 2 | `0x2421A`, `0x2426A` |
| `K7TotalSecurity` | UTF-16LE | 1 | `0x24284` |
| `DirProductBase` | UTF-16LE | 1 | `0x242C0` |
| `clrcd` | UTF-16LE | 9 | `0x3D562`, `0x43562`, `0x4363E`, `0x43670`, `0x436F0`, `0x437C4`, `0x43834`, `0x43854`, `0x43870` |
| `BE79F7D853E643089D51EDCDA79805C4` | UTF-16LE | 1 | `0x438C8` |
| `\Device\kvc` | UTF-16LE | 1 | `0x1E312` |

## Plaintext component filenames

| Filename | Encoding | Count | File offsets |
|---|---:|---:|---|
| `kvc.sys` | UTF-16LE | 8 | `0x1DE02`, `0x1DE30`, `0x1DE70`, `0x224A2`, `0x30030`, `0x381EA`, `0x39592`, `0x3E74A` |
| `kvckiller.sys` | UTF-16LE | 10 | `0x1DD3A`, `0x1DEF2`, `0x1DF30`, `0x1DF80`, `0x21DF8`, `0x2475E`, `0x2CAE0`, `0x39874`, `0x3AE72`, `0x3AF5A` |
| `kvcblocker.sys` | UTF-16LE | 8 | `0x1DD5A`, `0x1E002`, `0x1E040`, `0x1E090`, `0x21DD8`, `0x3CEF8`, `0x43470`, `0x43610` |
| `kvcstrm.sys` | UTF-16LE | 5 | `0x1E122`, `0x1E160`, `0x1E1B0`, `0x22A42`, `0x2FFD8` |
| `kvc_smss.exe` | UTF-16LE | 12 | `0x1D108`, `0x1D4CE`, `0x1D570`, `0x1DBF0`, `0x1DC60`, `0x1DCC0`, `0x1ED40`, `0x1EDB2`, `0x1EDE0`, `0x2FFF0`, `0x37C5A`, `0x3E4F4` |
| `ExplorerFrame` | UTF-16LE | 6 | `0x300C8`, `0x304CC`, `0x305FC`, `0x30692`, `0x30766`, `0x3C0C0` |

These strings originate in C++ constants, logging, path construction, and
service management code. They are not hidden by the current implementation.

## Configuration and module files

| Identifier | ASCII | UTF-16LE | Notes |
|---|---:|---:|---|
| `drivers.ini` | 0 | 14 | SMSS configuration path and diagnostics |
| `kvc.dat` | 2 | 16 | Optional browser extraction module |
| `kvcforensic.dat` | 1 | 12 | Optional forensic module |
| `UnderVolter.dat` | 1 | 16 | Optional EFI undervolting module |

These modules intentionally retain their independent XOR format. They are not
part of the `kvc.bmp` component package.

## Windows privilege names

The following strings are expected and intentional:

```text
SeBackupPrivilege
SeDebugPrivilege
SeLoadDriverPrivilege
SeRestorePrivilege
```

They are API identifiers passed to `LookupPrivilegeValueW`. Hiding these names
would not add security because the corresponding privileges are visible through
the process token and system audit events.

## Runtime disclosure

Static string masking does not hide the same identifiers at runtime. Service and
device names become visible through SCM, registry keys, ETW, Process Monitor,
filesystem paths, and kernel debugging. Component files deployed to DriverStore
are also visible by name and hash.

The presence of these plaintext strings is therefore an audit result, not by
itself evidence of unsafe behavior.
