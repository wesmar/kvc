[CmdletBinding()]
param(
    [string]$Configuration = "Release",
    [string]$Platform      = "x64",
    [string]$Timestamp     = "2027-01-01 00:00:00",

    # Component switches — omit all to build everything
    [switch]$implementer,
    [switch]$kvc,
    [switch]$kvc_crypt,
    [switch]$kvc_pass,
    [switch]$KvcXor,
    [switch]$kvcstrm,
    [switch]$kvc_smss
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

$ProjectRoot = $PSScriptRoot
$BinDir      = Join-Path $ProjectRoot "bin"

# kvc_pass implies kvc_crypt — they are always built as a pair
if ($kvc_pass) { $kvc_crypt = [switch]::new($true) }

# All usermode projects
$UserProjects = @(
    @{ Name = "kvc_crypt";   Switch = $kvc_crypt;   Path = "kvc_pass\kvc_crypt.vcxproj";        OutputName = "kvc_crypt";   OutputExtension = ".dll" },
    @{ Name = "kvc_pass";    Switch = $kvc_pass;    Path = "kvc_pass\kvc_pass.vcxproj";         OutputName = "kvc_pass";    OutputExtension = ".exe" },
    @{ Name = "KvcXor";      Switch = $KvcXor;      Path = "kvcXor\KvcXor.vcxproj";              OutputName = "KvcXor";      OutputExtension = ".exe" },
    @{ Name = "kvc_smss";    Switch = $kvc_smss;    Path = "kvc_smss\BootBypass.vcxproj";        OutputName = "kvc_smss";    OutputExtension = ".exe" }
)

$KvcProjectPath = Join-Path $ProjectRoot "kvc\kvc.vcxproj"
$ImplementerBuild = Join-Path $ProjectRoot "Implementer\build.ps1"
$ProjectConfig = Join-Path $ProjectRoot "config\kvc.ini"
$BinConfig = Join-Path $BinDir "kvc.ini"
$KvcBitmapPath = Join-Path $ProjectRoot "kvc\ICON\kvc.bmp"
$StandalonePassBinDir = Join-Path (Split-Path $ProjectRoot -Parent) "kvc_pass\bin"

# kvcstrm outputs to the solution-level x64\Release\ (not under kvcstrm\)
$DriverProjectPath = Join-Path $ProjectRoot "kvcstrm\kvcstrm.vcxproj"
$DriverBuildRoot   = Join-Path $ProjectRoot "x64\$Configuration"          # C:\Projekty\KVC\x64\Release
$DriverPackageDir  = Join-Path $DriverBuildRoot "kvcstrm"                  # …\x64\Release\kvcstrm (inf/cat end up here)

# If no component switch was set, build everything
$BuildAll = -not ($implementer -or $kvc -or $kvc_crypt -or $kvc_pass -or $KvcXor -or $kvcstrm -or $kvc_smss)
$BuildImplementer = $BuildAll -or $implementer
$BuildKvc = $BuildAll -or $kvc

function Write-Info([string]$Message)    { Write-Host $Message -ForegroundColor Cyan }
function Write-Step([string]$Message)    { Write-Host $Message -ForegroundColor DarkGray }
function Write-Success([string]$Message) { Write-Host $Message -ForegroundColor Green }
function Write-Failure([string]$Message) { Write-Host $Message -ForegroundColor Red }

function Parse-FixedTimestamp([string]$Value) {
    $styles = [System.Globalization.DateTimeStyles]::AllowWhiteSpaces -bor
              [System.Globalization.DateTimeStyles]::AssumeLocal
    try {
        return [datetime]::Parse($Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles)
    }
    catch {
        throw "Invalid -Timestamp '$Value'. Example: 2027-01-01 00:00:00"
    }
}

function Set-FixedFileTimestamp {
    param(
        [Parameter(Mandatory)]
        [string[]]$Paths,
        [Parameter(Mandatory)]
        [datetime]$Value
    )
    foreach ($path in $Paths) {
        $item = Get-Item -LiteralPath $path
        $item.CreationTime   = $Value
        $item.LastWriteTime  = $Value
        $item.LastAccessTime = $Value
    }
}

function Get-LatestVsPath {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path -LiteralPath $vswhere) {
        $p = & $vswhere -products * -requires Microsoft.Component.MSBuild -property installationPath -latest 2>$null
        if ($p) { return $p.Trim() }
        $p = & $vswhere -products * -requires Microsoft.Component.MSBuild -property installationPath -latest -prerelease 2>$null
        if ($p) { return $p.Trim() }
    }
    foreach ($ver in @("18","17","16")) {
        $path = Join-Path ${env:ProgramFiles} "Microsoft Visual Studio\$ver"
        if (Test-Path $path) {
            $edition = Get-ChildItem $path -Directory | Select-Object -First 1
            if ($edition) { return $edition.FullName }
        }
    }
    throw "Visual Studio with MSBuild was not found."
}

function Build-UsermodeProject {
    param(
        [Parameter(Mandatory)][hashtable]$Project,
        [Parameter(Mandatory)][string]$MsBuild,
        [Parameter(Mandatory)][long]$SourceDateEpoch
    )

    $projectPath = Join-Path $ProjectRoot $Project.Path
    if (-not (Test-Path -LiteralPath $projectPath)) {
        throw "Project file not found: $projectPath"
    }

    $projectObjDir = Join-Path (Split-Path $projectPath -Parent) "obj"
    if (Test-Path -LiteralPath $projectObjDir) {
        Remove-Item -LiteralPath $projectObjDir -Recurse -Force
        Write-Step "Cleaned $($Project.Name)\obj\"
    }

    Write-Info "Building $($Project.Name)..."
    & $MsBuild $projectPath `
        /p:Configuration=$Configuration `
        /p:Platform=$Platform `
        /p:SolutionDir="$ProjectRoot\" `
        /p:SOURCE_DATE_EPOCH=$SourceDateEpoch `
        /m /nologo /v:m
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to build $($Project.Name) (exit code $LASTEXITCODE)"
    }
    Write-Success "Built $($Project.Name)"

    if (Test-Path -LiteralPath $projectObjDir) {
        Remove-Item -LiteralPath $projectObjDir -Recurse -Force
        Write-Step "Removed $($Project.Name)\obj\"
    }
}

try {
    $fixedTimestamp     = Parse-FixedTimestamp -Value $Timestamp
    $fixedTimestampText = $fixedTimestamp.ToString("yyyy-MM-dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
    $epoch              = [DateTimeOffset]::new($fixedTimestamp).ToUnixTimeSeconds()
    $env:SOURCE_DATE_EPOCH = [string]$epoch

    Write-Info "Starting KVC Framework Build."
    Write-Step "Fixed output timestamp : $fixedTimestampText"
    Write-Step "SOURCE_DATE_EPOCH      : $($env:SOURCE_DATE_EPOCH)"

    if ($BuildAll) {
        Write-Step "Components: ALL"
    } else {
        $sel = @()
        if ($implementer) { $sel += "implementer" }
        if ($kvc) { $sel += "kvc" }
        $sel += @($UserProjects | Where-Object { $_.Switch } | ForEach-Object { $_.Name })
        if ($kvcstrm) { $sel += "kvcstrm" }
        Write-Step "Components: $($sel -join ', ')"
    }

    # Locate MSBuild
    $vsPath  = Get-LatestVsPath
    $msbuild = Get-ChildItem -Path $vsPath -Filter "MSBuild.exe" -Recurse |
               Where-Object { $_.FullName -match "amd64" } |
               Select-Object -ExpandProperty FullName -First 1
    if (-not $msbuild) {
        $msbuild = Get-ChildItem -Path $vsPath -Filter "MSBuild.exe" -Recurse |
                   Select-Object -ExpandProperty FullName -First 1
    }
    if (-not $msbuild -or -not (Test-Path -LiteralPath $msbuild)) {
        throw "MSBuild.exe was not found under: $vsPath"
    }
    Write-Step "MSBuild: $msbuild"

    # Ensure bin\ exists
    if (-not (Test-Path -LiteralPath $BinDir)) {
        New-Item -ItemType Directory -Path $BinDir | Out-Null
    }

    # ── Regular usermode projects ────────────────────────────────────────────
    foreach ($project in $UserProjects) {
        if (-not $BuildAll -and -not $project.Switch) { continue }
        Build-UsermodeProject -Project $project -MsBuild $msbuild -SourceDateEpoch $epoch
    }

    # ── kvcstrm kernel driver ────────────────────────────────────────────────
    if ($BuildAll -or $kvcstrm) {
        if (-not (Test-Path -LiteralPath $DriverProjectPath)) {
            throw "kvcstrm project not found: $DriverProjectPath"
        }

        Write-Info "Building kvcstrm..."
        & $msbuild $DriverProjectPath `
            /t:Rebuild `
            /p:Configuration=$Configuration `
            /p:Platform=$Platform `
            /p:SolutionDir="$ProjectRoot\" `
            /p:SOURCE_DATE_EPOCH=$epoch `
            /p:SignMode=Off `
            /p:SkipPackageVerification=true `
            /p:ApiValidator_Enable=false `
            /p:Driver_SpectreMitigation=false `
            /p:SpectreMitigation=false `
            /m /nologo /v:m
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to build kvcstrm (exit code $LASTEXITCODE)"
        }
        Write-Success "Built kvcstrm"

        # Copy only kvcstrm.sys to bin — inf/cat not needed for non-PNP deployment
        $sysSrc = Join-Path $DriverBuildRoot "kvcstrm.sys"
        if (-not (Test-Path -LiteralPath $sysSrc)) {
            # Some WDK configurations place the sys inside the package subdir
            $sysSrc = Join-Path $DriverPackageDir "kvcstrm.sys"
            if (-not (Test-Path -LiteralPath $sysSrc)) {
                throw "kvcstrm.sys not found after build (searched $DriverBuildRoot and $DriverPackageDir)"
            }
        }
        Copy-Item -LiteralPath $sysSrc -Destination (Join-Path $BinDir "kvcstrm.sys") -Force
        Write-Step "Staged kvcstrm.sys -> bin\"

        # Remove both x64 build output trees — kvcstrm.sys is already in bin\
        foreach ($buildTree in @(
            $DriverBuildRoot,                                  # C:\Projekty\KVC\x64\Release (and parent x64\)
            (Join-Path $ProjectRoot "kvcstrm\x64")            # C:\Projekty\KVC\kvcstrm\x64
        )) {
            # Walk up to the x64\ root and remove it entirely
            $x64Root = $buildTree
            while ($x64Root -and [System.IO.Path]::GetFileName($x64Root) -ne "x64") {
                $x64Root = [System.IO.Path]::GetDirectoryName($x64Root)
            }
            if ($x64Root -and (Test-Path -LiteralPath $x64Root)) {
                Remove-Item -LiteralPath $x64Root -Recurse -Force
                Write-Step "Removed build tree: $($x64Root.Substring($ProjectRoot.Length + 1))"
            }
        }
    }

    # ── New no-CRT implementer ───────────────────────────────────────────────
    if ($BuildImplementer) {
        if (-not (Test-Path -LiteralPath $ImplementerBuild -PathType Leaf)) {
            throw "Implementer build script not found: $ImplementerBuild"
        }

        Write-Info "Building implementer (no CRT)..."
        & $ImplementerBuild `
            -Configuration $Configuration `
            -CrtMode None `
            -OutputDir $BinDir `
            -Clean `
            -NoReceipt
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to build implementer (exit code $LASTEXITCODE)"
        }

        $implementerExe = Join-Path $BinDir "implementer.exe"
        if (-not (Test-Path -LiteralPath $implementerExe -PathType Leaf)) {
            throw "implementer.exe was not staged to $BinDir"
        }
        Write-Success "Built implementer -> bin\implementer.exe"

        if (-not (Test-Path -LiteralPath $ProjectConfig -PathType Leaf)) {
            throw "Project config not found: $ProjectConfig"
        }
        $env:KVC_ROOT = $ProjectRoot
        Copy-Item -LiteralPath $ProjectConfig -Destination $BinConfig -Force
        $configText = [IO.File]::ReadAllText($BinConfig)
        $expandedConfig = [Environment]::ExpandEnvironmentVariables($configText)
        [IO.File]::WriteAllText(
            $BinConfig,
            $expandedConfig,
            [Text.UTF8Encoding]::new($false)
        )
        & $implementerExe pack --config $BinConfig
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $KvcBitmapPath -PathType Leaf)) {
            throw "Failed to build KVC bitmap payload"
        }
        Write-Success "Built KVC bitmap -> kvc\ICON\kvc.bmp"

        $implementerBuildDir = Join-Path $ProjectRoot "Implementer\build"
        if (Test-Path -LiteralPath $implementerBuildDir) {
            Remove-Item -LiteralPath $implementerBuildDir -Recurse -Force
            Write-Step "Removed Implementer\build\"
        }
    }

    # ── KVC executable last, after payload tools are staged ─────────────────
    if ($BuildKvc) {
        $kvcProject = @{
            Name = "kvc"
            Path = "kvc\kvc.vcxproj"
        }
        Build-UsermodeProject -Project $kvcProject -MsBuild $msbuild -SourceDateEpoch $epoch
    }

    # ── Remove obj\ intermediate directory ──────────────────────────────────
    $objRoot = Join-Path $ProjectRoot "obj"
    if (Test-Path -LiteralPath $objRoot) {
        Remove-Item -LiteralPath $objRoot -Recurse -Force
        Write-Step "Removed build tree: obj\"
    }

    # ── Stamp ALL bin\ files to fixed timestamp ──────────────────────────────
    $outputFiles = @(
        Get-ChildItem -LiteralPath $BinDir -File -ErrorAction SilentlyContinue
        Get-Item -LiteralPath (Join-Path $StandalonePassBinDir "kvc_pass.exe"),
                            (Join-Path $StandalonePassBinDir "kvc_crypt.dll") `
            -ErrorAction SilentlyContinue
    )
    if ($outputFiles) {
        $needsStamp = @($outputFiles |
            Where-Object { $_.LastWriteTime -ne $fixedTimestamp } |
            Select-Object -ExpandProperty FullName)
        if ($needsStamp) {
            Set-FixedFileTimestamp -Paths $needsStamp -Value $fixedTimestamp
            Write-Step "Stamped $($needsStamp.Count) file(s) in bin\ -> $fixedTimestampText"
        } else {
            Write-Step "All bin\ files already have timestamp $fixedTimestampText"
        }
    }

    Write-Success "KVC Framework build completed successfully."
}
catch {
    Write-Failure $_.Exception.Message
    exit 1
}
