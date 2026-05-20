$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Building ExplorerFrame DLL (x64 MASM)"     -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

$VSBASE  = "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64"
$ML64    = "$VSBASE\x64\ml64.exe"
$LINK64  = "$VSBASE\x64\link.exe"
$DUMPBIN = "$VSBASE\x64\dumpbin.exe"

$SDKBASE    = "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0"
$SDKBIN     = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64"
$SDKINCLUDE = "C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0"
$LIBPATH    = "$SDKBASE\um\x64"

$env:PATH    += ";$SDKBIN"
$env:INCLUDE  = "$SDKINCLUDE\um;$SDKINCLUDE\shared"

$OUTDIR = Join-Path $ScriptDir "bin"
if (-not (Test-Path $OUTDIR)) { New-Item -ItemType Directory -Path $OUTDIR | Out-Null }

$BuildSuccess = $true

# Assembly modules (order matters: strutil before others that call it)
$FILES = @("strutil", "patterns", "intercept", "patch", "forward", "main")

Push-Location $ScriptDir

# Compile resource
Write-Host ""
Write-Host ">>> Compiling resources..." -ForegroundColor Cyan
& rc /c65001 /I "$SDKINCLUDE\um" /I "$SDKINCLUDE\shared" /fo ef.res ef.rc
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: rc.exe failed" -ForegroundColor Red
    $BuildSuccess = $false
}

# Assemble each module
if ($BuildSuccess) {
    Write-Host ""
    Write-Host ">>> Assembling modules..." -ForegroundColor Cyan
    foreach ($f in $FILES) {
        Write-Host "    $f.asm" -ForegroundColor Gray
        & $ML64 /c /Cp /Cx /Zi /I x64 /Fo "x64\$f.obj" "x64\$f.asm"
        if ($LASTEXITCODE -ne 0) {
            Write-Host "ERROR: ml64 failed on $f.asm" -ForegroundColor Red
            $BuildSuccess = $false
            break
        }
    }
}

# Link
if ($BuildSuccess) {
    Write-Host ""
    Write-Host ">>> Linking..." -ForegroundColor Cyan

    $objs = $FILES | ForEach-Object { "x64\$_.obj" }

    $linkArgs = $objs + @(
        "ef.res",
        "/DLL",
        "/entry:DllMain",
        "/subsystem:windows",
        "/nodefaultlib",
        "/Brepro",
        "/out:bin\ExplorerFrame.dll",
        "/MANIFEST:EMBED",
        "/MANIFESTINPUT:ef.manifest",
        "/LIBPATH:$LIBPATH",
        "kernel32.lib",
        "user32.lib",
        "gdi32.lib",
        "/DEF:ef.def"
    )

    & $LINK64 $linkArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: link.exe failed" -ForegroundColor Red
        $BuildSuccess = $false
    }
}

# Verify import table
if ($BuildSuccess) {
    Write-Host ""
    Write-Host ">>> Verifying imports with dumpbin..." -ForegroundColor Cyan

    $dllPath = "bin\ExplorerFrame.dll"
    $imports = & $DUMPBIN /imports $dllPath
    $dependents = & $DUMPBIN /dependents $dllPath

    $blockedImportPatterns = @(
        "msvcr",
        "vcruntime",
        "ucrtbase",
        "rstrtmgr",
        "ole32",
        "combase",
        "shlwapi",
        "advapi32"
    )

    $blockedFound = $imports | Select-String ($blockedImportPatterns -join "|")
    if ($blockedFound) {
        $blockedFound | ForEach-Object { Write-Host "ERROR: blocked import detected: $_" -ForegroundColor Red }
        $BuildSuccess = $false
    } else {
        Write-Host "[PASS] No CRT, COM, Restart Manager, registry, or helper-library imports" -ForegroundColor Green
    }

    $allowedDlls = @(
        "GDI32.dll",
        "KERNEL32.dll",
        "USER32.dll"
    )

    $actualDlls = $dependents |
        ForEach-Object {
            if ($_ -match "^\s*([A-Za-z0-9_.-]+\.dll)\s*$") {
                $matches[1]
            }
        } |
        Sort-Object -Unique

    $unexpectedDlls = $actualDlls | Where-Object { $allowedDlls -notcontains $_ }
    if ($unexpectedDlls) {
        $unexpectedDlls | ForEach-Object { Write-Host "ERROR: unexpected dependent DLL: $_" -ForegroundColor Red }
        $BuildSuccess = $false
    } else {
        Write-Host "[PASS] Dependent DLL set is expected" -ForegroundColor Green
    }

    Write-Host "      Dependents: $($actualDlls -join ', ')" -ForegroundColor Gray

    if ($BuildSuccess) {
        Write-Host "[PASS] Import verification complete" -ForegroundColor Green
    }
}

# Set timestamp to 2026-01-01 to match original
if ($BuildSuccess) {
    $out = "bin\ExplorerFrame.dll"
    $ts  = Get-Date "2026-01-01 00:00:00"
    (Get-Item $out).CreationTime  = $ts
    (Get-Item $out).LastWriteTime = $ts
    Write-Host "Timestamp set: 2026-01-01 00:00:00" -ForegroundColor Cyan
}

Pop-Location

# Cleanup
Write-Host ""
Write-Host ">>> Cleaning intermediates..." -ForegroundColor Yellow
Remove-Item "$ScriptDir\x64\*.obj" -ErrorAction SilentlyContinue
Remove-Item "$ScriptDir\*.res"     -ErrorAction SilentlyContinue

Write-Host ""
if ($BuildSuccess) {
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "STATUS: SUCCESS  →  ef\bin\ExplorerFrame.dll" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    exit 0
} else {
    Write-Host "============================================" -ForegroundColor Red
    Write-Host "STATUS: FAILED"                              -ForegroundColor Red
    Write-Host "============================================" -ForegroundColor Red
    exit 1
}
