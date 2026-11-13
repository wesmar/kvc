[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [ValidateSet("Static", "Dynamic", "None")]
    [string]$CrtMode = "None",

    [string]$OutputDir = "",

    [switch]$Clean,
    [switch]$NoDependencyCheck,
    [switch]$NoReceipt
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

$ProjectRoot = [IO.Path]::GetFullPath($PSScriptRoot)
$SourceDir   = Join-Path $ProjectRoot "src"
$BuildRoot   = Join-Path $ProjectRoot "build"
$ObjectDir   = Join-Path $BuildRoot "$Configuration\obj\$CrtMode"
$BinDir      = if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    Join-Path $ProjectRoot "bin"
} elseif ([IO.Path]::IsPathRooted($OutputDir)) {
    [IO.Path]::GetFullPath($OutputDir)
} else {
    [IO.Path]::GetFullPath((Join-Path $ProjectRoot $OutputDir))
}
$BuildReceiptRoot = Join-Path $BuildRoot "receipts"
$OutputExe   = Join-Path $BinDir "implementer.exe"
$ReceiptPath = Join-Path $BuildReceiptRoot "implementer-build-receipt.json"

function Parse-VersionDirectory {
    param([Parameter(Mandatory)][string]$Name)
    $value = $null
    if ([version]::TryParse($Name, [ref]$value)) {
        return $value
    }
    return $null
}

function Get-VsWhereInstallations {
    $vswhere = Get-Command "vswhere.exe" -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty Source
    if (-not $vswhere) {
        $candidates = @(
            (Join-Path $env:ProgramFiles "Microsoft Visual Studio\Installer\vswhere.exe"),
            (Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"),
            (Join-Path $env:LOCALAPPDATA "Microsoft\VisualStudio\Installer\vswhere.exe")
        )
        $vswhere = $candidates |
            Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
            Select-Object -First 1
    }
    if (-not $vswhere) {
        return @()
    }

    $json = & $vswhere -products * -all -prerelease -sort -format json -utf8 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace(($json -join ""))) {
        return @()
    }

    $entries = ($json -join "`n") | ConvertFrom-Json
    return @($entries | ForEach-Object { $_.installationPath } | Select-Object -Unique)
}

function Get-VsFallbackInstallations {
    $roots = @(
        (Join-Path $env:ProgramFiles "Microsoft Visual Studio"),
        (Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio")
    )

    $results = @()
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        foreach ($year in Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue) {
            foreach ($edition in Get-ChildItem -LiteralPath $year.FullName -Directory -ErrorAction SilentlyContinue) {
                if (Test-Path -LiteralPath (Join-Path $edition.FullName "VC\Tools\MSVC") -PathType Container) {
                    $results += $edition.FullName
                }
            }
        }
    }
    return @($results | Select-Object -Unique)
}

function Find-MsvcToolchain {
    $installations = @(
        (Get-VsWhereInstallations) + (Get-VsFallbackInstallations)
    ) | Select-Object -Unique

    $candidates = @()
    foreach ($installation in $installations) {
        $msvcRoot = Join-Path $installation "VC\Tools\MSVC"
        if (-not (Test-Path -LiteralPath $msvcRoot -PathType Container)) { continue }

        foreach ($versionDir in Get-ChildItem -LiteralPath $msvcRoot -Directory -ErrorAction SilentlyContinue) {
            $version = Parse-VersionDirectory -Name $versionDir.Name
            if ($null -eq $version) { continue }

            $binDir = Join-Path $versionDir.FullName "bin\Hostx64\x64"
            $cl      = Join-Path $binDir "cl.exe"
            $link    = Join-Path $binDir "link.exe"
            $dumpbin = Join-Path $binDir "dumpbin.exe"
            $include = Join-Path $versionDir.FullName "include"
            $lib     = Join-Path $versionDir.FullName "lib\x64"

            if ((Test-Path -LiteralPath $cl -PathType Leaf) -and
                (Test-Path -LiteralPath $link -PathType Leaf) -and
                (Test-Path -LiteralPath $dumpbin -PathType Leaf) -and
                (Test-Path -LiteralPath $include -PathType Container) -and
                (Test-Path -LiteralPath $lib -PathType Container)) {
                $candidates += [pscustomobject]@{
                    SortVersion = $version
                    Version     = $versionDir.Name
                    Installation = $installation
                    Root        = $versionDir.FullName
                    BinDir      = $binDir
                    Cl          = $cl
                    Link        = $link
                    Dumpbin     = $dumpbin
                    Include     = $include
                    Lib         = $lib
                }
            }
        }
    }

    if ($candidates.Count -eq 0) {
        throw "No MSVC x64 toolchain with cl.exe, link.exe, and dumpbin.exe was found."
    }

    return $candidates | Sort-Object SortVersion -Descending | Select-Object -First 1
}

function Find-WindowsSdk {
    $roots = @(
        (Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10"),
        (Join-Path $env:ProgramFiles "Windows Kits\10")
    ) | Select-Object -Unique

    $candidates = @()
    foreach ($sdkRoot in $roots) {
        $includeRoot = Join-Path $sdkRoot "Include"
        if (-not (Test-Path -LiteralPath $includeRoot -PathType Container)) { continue }

        foreach ($versionDir in Get-ChildItem -LiteralPath $includeRoot -Directory -ErrorAction SilentlyContinue) {
            $version = Parse-VersionDirectory -Name $versionDir.Name
            if ($null -eq $version) { continue }

            $windowsHeader = Join-Path $versionDir.FullName "um\windows.h"
            $ucrtHeader    = Join-Path $versionDir.FullName "ucrt\stddef.h"
            $kernelLib     = Join-Path $sdkRoot "Lib\$($versionDir.Name)\um\x64\kernel32.lib"
            $rc            = Join-Path $sdkRoot "bin\$($versionDir.Name)\x64\rc.exe"
            $mt            = Join-Path $sdkRoot "bin\$($versionDir.Name)\x64\mt.exe"

            if ((Test-Path -LiteralPath $windowsHeader -PathType Leaf) -and
                (Test-Path -LiteralPath $ucrtHeader -PathType Leaf) -and
                (Test-Path -LiteralPath $kernelLib -PathType Leaf) -and
                (Test-Path -LiteralPath $rc -PathType Leaf) -and
                (Test-Path -LiteralPath $mt -PathType Leaf)) {
                $candidates += [pscustomobject]@{
                    SortVersion = $version
                    Version     = $versionDir.Name
                    Root        = $sdkRoot
                    Include     = $versionDir.FullName
                    Lib         = Join-Path $sdkRoot "Lib\$($versionDir.Name)"
                    Bin         = Join-Path $sdkRoot "bin\$($versionDir.Name)\x64"
                    Rc          = $rc
                    Mt          = $mt
                }
            }
        }
    }

    if ($candidates.Count -eq 0) {
        throw "No complete Windows SDK with headers, x64 libraries, rc.exe, and mt.exe was found."
    }

    return $candidates | Sort-Object SortVersion -Descending | Select-Object -First 1
}

function Remove-ProjectTree {
    param([Parameter(Mandatory)][string]$Path)
    $resolvedRoot = [IO.Path]::GetFullPath($ProjectRoot)
    $resolvedPath = [IO.Path]::GetFullPath($Path)
    if (-not $resolvedPath.StartsWith($resolvedRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove a path outside the project: $resolvedPath"
    }
    if (Test-Path -LiteralPath $resolvedPath) {
        Remove-Item -LiteralPath $resolvedPath -Recurse -Force
    }
}

function Get-Dependencies {
    param(
        [Parameter(Mandatory)][string]$Dumpbin,
        [Parameter(Mandatory)][string]$ImagePath
    )

    $output = & $Dumpbin /nologo /dependents $ImagePath
    if ($LASTEXITCODE -ne 0) {
        throw "dumpbin /dependents failed for $ImagePath"
    }

    return @(
        $output |
        ForEach-Object {
            if ($_ -match '^\s*([A-Za-z0-9_.-]+\.dll)\s*$') {
                $Matches[1]
            }
        } |
        Select-Object -Unique
    )
}

try {
    if (-not (Test-Path -LiteralPath $SourceDir -PathType Container)) {
        throw "Source directory not found: $SourceDir"
    }

    if ($Clean) {
        Remove-ProjectTree -Path $BuildRoot
        if ($BinDir.StartsWith($ProjectRoot, [StringComparison]::OrdinalIgnoreCase)) {
            Remove-ProjectTree -Path $BinDir
        } elseif (Test-Path -LiteralPath $OutputExe) {
            Remove-Item -LiteralPath $OutputExe -Force
        }
    }

    $msvc = Find-MsvcToolchain
    $sdk  = Find-WindowsSdk

    $env:PATH = @(
        $msvc.BinDir,
        $sdk.Bin,
        $env:PATH
    ) -join ";"

    $env:INCLUDE = @(
        $msvc.Include,
        (Join-Path $sdk.Include "ucrt"),
        (Join-Path $sdk.Include "shared"),
        (Join-Path $sdk.Include "um")
    ) -join ";"

    $env:LIB = @(
        $msvc.Lib,
        (Join-Path $sdk.Lib "ucrt\x64"),
        (Join-Path $sdk.Lib "um\x64")
    ) -join ";"

    $env:VCToolsInstallDir = $msvc.Root + "\"
    $env:WindowsSdkDir = $sdk.Root + "\"
    $env:WindowsSDKVersion = $sdk.Version + "\"

    New-Item -ItemType Directory -Path $ObjectDir -Force | Out-Null
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
    New-Item -ItemType Directory -Path $BuildReceiptRoot -Force | Out-Null

    $compilerFlags = @(
        "/nologo",
        "/c",
        "/std:c++latest",
        "/permissive-",
        "/Zc:__cplusplus",
        "/Zc:preprocessor",
        "/W4",
        "/WX",
        "/utf-8",
        "/Brepro",
        "/DUNICODE",
        "/D_UNICODE",
        "/DWIN32_LEAN_AND_MEAN",
        "/DNOMINMAX",
        "/D_CRT_SECURE_NO_WARNINGS",
        "/Fo$ObjectDir\"
    )

    $linkFlags = @(
        "/nologo",
        "/OUT:$OutputExe",
        "/SUBSYSTEM:CONSOLE",
        "/DYNAMICBASE",
        "/NXCOMPAT",
        "/HIGHENTROPYVA",
        "/CETCOMPAT",
        "/GUARD:CF",
        "/INCREMENTAL:NO",
        "/MANIFEST:EMBED",
        "/MANIFESTUAC:NO",
        "/Brepro"
    )

    if ($Configuration -eq "Release") {
        $compilerFlags += @("/O2", "/Oi", "/Gy", "/Gw")
        $linkFlags += @("/OPT:REF", "/OPT:ICF")
    } else {
        $compilerFlags += @("/Od", "/Zi")
        $linkFlags += @("/DEBUG")
    }

    switch ($CrtMode) {
        "Static" {
            $compilerFlags += @("/MT", "/EHsc", "/GR-", "/GS")
        }
        "Dynamic" {
            $compilerFlags += @("/MD", "/EHsc", "/GR-", "/GS")
        }
        "None" {
            $compilerFlags += @(
                "/DIMPLEMENTER_NO_CRT",
                "/EHs-c-",
                "/GR-",
                "/GS-",
                "/Zl"
            )
            $linkFlags += @("/NODEFAULTLIB", "/ENTRY:mainCRTStartup")
        }
    }

    $sources = @(
        Get-ChildItem -LiteralPath $SourceDir -Filter "*.cpp" -File |
        Sort-Object Name
    )

    if ($CrtMode -ne "None") {
        $sources = @($sources | Where-Object { $_.Name -ne "nocrt_runtime.cpp" })
    }

    if ($sources.Count -eq 0) {
        throw "No C++ sources found in $SourceDir"
    }

    Write-Host "MSVC   : $($msvc.Version) @ $($msvc.Installation)"
    Write-Host "Windows: $($sdk.Version) @ $($sdk.Root)"
    Write-Host "Config : $Configuration / $CrtMode"

    $compileOutput = & $msvc.Cl @compilerFlags @($sources.FullName)
    if ($LASTEXITCODE -ne 0) {
        $compileOutput
        throw "Compilation failed with exit code $LASTEXITCODE"
    }

    $objects = @(Get-ChildItem -LiteralPath $ObjectDir -Filter "*.obj" -File | Sort-Object Name)
    if ($objects.Count -eq 0) {
        throw "Compilation produced no object files."
    }

    $libraries = @(
        "kernel32.lib",
        "advapi32.lib",
        "ole32.lib",
        "cabinet.lib",
        "bcrypt.lib"
    )

    $linkOutput = & $msvc.Link @linkFlags @($objects.FullName) @libraries
    if ($LASTEXITCODE -ne 0) {
        $linkOutput
        throw "Link failed with exit code $LASTEXITCODE"
    }

    $dependencies = @(Get-Dependencies -Dumpbin $msvc.Dumpbin -ImagePath $OutputExe)
    Write-Host "Dependencies:"
    $dependencies | ForEach-Object { Write-Host "  $_" }

    if (-not $NoDependencyCheck -and $CrtMode -in @("Static", "None")) {
        $crtDependencies = @(
            $dependencies | Where-Object {
                $_ -match '^(vcruntime|msvcp|ucrtbase|concrt|api-ms-win-crt)'
            }
        )
        if ($crtDependencies.Count -gt 0) {
            throw "CRT dependency detected in $CrtMode mode: $($crtDependencies -join ', ')"
        }
    }

    if (-not $NoReceipt) {
        $receipt = [ordered]@{
            Timestamp          = (Get-Date).ToString("o")
            Configuration      = $Configuration
            CrtMode            = $CrtMode
            VisualStudio       = $msvc.Installation
            MsvcVersion        = $msvc.Version
            WindowsSdkVersion  = $sdk.Version
            Compiler           = $msvc.Cl
            Dumpbin            = $msvc.Dumpbin
            Output             = $OutputExe
            OutputSha256       = (Get-FileHash -LiteralPath $OutputExe -Algorithm SHA256).Hash
            Dependencies       = $dependencies
        }
        $receipt | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ReceiptPath -Encoding utf8
    }

    Write-Host "Built: $OutputExe"
    if (-not $NoReceipt) {
        Write-Host "Receipt: $ReceiptPath"
    }
}
catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
