# implementer

Universal small-file container builder for Windows x64.

The tool packs a flat directory into a deterministic CAB, masks the `MSCF`
signature with the KvcKiller byte pattern, embeds the CAB in a valid 24-bit
bitmap, strips the first 128 bytes from PE files, and reconstructs the original
files from `ks.sys` plus the recorded `e_lfanew` after SHA-256 verification.

The container manifest is stored inside the CAB payload. It records file names,
offsets, lengths, and SHA-256 digests. Entry boundaries are never inferred by
scanning for `MZ` signatures.

The template digest covers exactly the first 128 bytes copied from `ks.sys`.
The remainder of `ks.sys` is not part of the container contract and may differ
between Windows builds.

## Build

```powershell
.\build.ps1
.\build.ps1 -Configuration Release -CrtMode Static
.\build.ps1 -Configuration Release -CrtMode Dynamic
.\build.ps1 -Configuration Release -CrtMode None
```

Running `build.ps1` without arguments produces the small freestanding `None`
binary. `Static` and `Dynamic` are explicit alternatives.

No compiler path is passed to the script. `build.ps1` finds `vswhere.exe`
through `PATH`, Program Files, Program Files (x86), or LocalAppData, then
enumerates every Visual Studio installation.

The selected MSVC toolchain must contain the actual x64 `cl.exe`, `link.exe`,
`dumpbin.exe`, include directory, and library directory. The script does not
select a toolchain from a version string alone and does not require `vcvars` to
be loaded in the caller's PowerShell session.

The Windows SDK is selected independently. A candidate must contain
`um\windows.h`, `ucrt\stddef.h`, `kernel32.lib`, `rc.exe`, and `mt.exe`.
Versions are sorted as `[version]`.

## CRT modes

| Mode | Compiler/linker behavior | Intended use |
|---|---|---|
| `Static` | `/MT`, static C and C++ runtime | Default standalone build |
| `Dynamic` | `/MD`, Visual C++ runtime DLLs | Debugging and smaller binaries |
| `None` | `/NODEFAULTLIB`, custom `mainCRTStartup`, no STL | Minimal dependency experiments |

The no-CRT path uses only Win32 APIs and does not allocate through `new`.
`nocrt_runtime.cpp` supplies the small set of memory primitives needed by the
freestanding build.

## Dependency verification

After linking, the script runs:

```text
dumpbin /dependents bin\implementer.exe
```

`Static` and `None` builds fail if the dependency list contains
`vcruntime*.dll`, `msvcp*.dll`, `ucrtbase.dll`, `concrt*.dll`, or
`api-ms-win-crt*.dll`.

The build writes `bin\build-receipt.json` with the selected environments,
source timestamp, output SHA-256, and dependency list.

`-CrtMode` selects the C/C++ runtime linkage. It is not a compiler path:

```text
Static   /MT
Dynamic  /MD
None     freestanding binary without CRT or STL
```

## Current commands

```text
implementer.exe --help
implementer.exe --version
implementer.exe --self-test
implementer.exe pack <input-dir> <output.bmp> <cab-entry-name>
implementer.exe pack --config <file.ini>
implementer.exe inspect <input.bmp>
implementer.exe extract <input.bmp> <output-dir>
```

`--self-test` verifies that `%SystemRoot%\System32\drivers\ks.sys` exists and
contains the expected 128-byte `MZ` template.

Pack options:

```text
--strip-pe             Strip PE DOS headers (default)
--no-strip             Store every file byte-for-byte
--template <path>      Override the default ks.sys template
--keep-temp            Keep temporary payload and CAB files
```

Extract accepts `--template <path>`. The default is always the local
`%SystemRoot%\System32\drivers\ks.sys`.

## INI configuration

`pack --config` uses the numeric `[Files]` order as the canonical binary
order. Input names are not sorted when a configuration file is used.

`sample.ini` is the generic template shipped with the tool. Project-specific
configuration is kept outside `Implementer`: KVC reads `config/kvc.ini`, copies
it to `bin/kvc.ini`, expands `%KVC_ROOT%`, and passes the expanded copy to the
packer. Relative paths in a normal INI are resolved from the directory
containing that INI file; environment variables are expanded first.

```ini
[Config]
Version=1

[Pack]
Output=test-output\photo1.bmp
EntryName=photo1.bmp
Template=%SystemRoot%\System32\drivers\ks.sys
StripPe=1
XorMode=full-cab
XorKeyHex=A0E2808BE2808C

[Files]
1=test-input\systray.exe
2=test-input\beep.sys
3=test-input\null.sys
4=test-input\notepad.exe
```

File indexes must be contiguous from `1`. Unknown sections and keys are
rejected. Relative paths are resolved against the INI directory.

The 7-byte key below is the legacy KVC `Implementer` key. It is not the
KvcKiller transformation:

```text
A0 E2 80 8B E2 80 8C
```

The current KvcKiller `build_bmp.ps1` does **not** apply this full-CAB key. It
only masks the four `MSCF` bytes with `A5 5A F0 0F`. To reproduce that
behavior, use:

```ini
XorMode=mask-magic
```

`go.ps1` stores the CAB in the bitmap without any XOR transformation.

Supported modes:

| Mode | Behavior |
|---|---|
| `none` | Store the CAB unchanged |
| `mask-magic` | XOR only the first four CAB bytes with `A5 5A F0 0F` |
| `full-cab` | XOR the complete CAB with the configured repeating key |

For `full-cab`, pass the same INI to `inspect` and `extract`. The container
manifest records the XOR mode, key length, and key SHA-256. A wrong key or mode
is rejected before extraction.

Example:

```powershell
.\bin\implementer.exe pack .\test-input .\test-output\wallpaper.bmp wallpaper.bmp
.\bin\implementer.exe inspect .\test-output\wallpaper.bmp
.\bin\implementer.exe extract .\test-output\wallpaper.bmp .\test-output\roundtrip
```

## Container layout

```text
24-bit BMP
  BITMAPFILEHEADER
    bfReserved1 + bfReserved2 = CAB length
    bfOffBits                = 54
  pixel array
    masked CAB
      MSCF XOR A5 5A F0 0F
      or full-CAB repeating-key XOR
      selected entry name, for example wallpaper.bmp
        ContainerHeader
        FileRecord[]
        concatenated stored file data
```

`pack` sorts input names case-insensitively, sets a fixed timestamp on the
temporary file set, uses LZX compression, and prints measured pixel entropy.
The maximum representable value is `8.0` bits per byte. The stored template
digest covers only the 0x80-byte DOS header reused during reconstruction, not
the version-specific remainder of `ks.sys`.

Each PE record stores:

```text
original size and SHA-256
stored tail size and SHA-256
original e_lfanew
DOS-header-stripped flag
```

Non-PE files are stored unchanged. The reusable DOS-header template is read at
extraction time, while every reconstructed PE must match its original SHA-256
and contain a valid `PE\0\0` signature at the stored `e_lfanew`.
