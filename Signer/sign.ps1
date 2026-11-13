[CmdletBinding()]
param(
    [switch]$Create,
    [ValidateSet("Auto", "Standard", "Driver")]
    [string]$Profile = "Auto",
    [string]$Name,
    [string]$TargetPath,
    [string]$Timestamp = "2027-01-01 00:00:00",
    [switch]$Force
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

$UtilityRoot = $PSScriptRoot
$RepoRoot = Split-Path -Parent $UtilityRoot
$CertDir = Join-Path $UtilityRoot "cert"
$BinDir = Join-Path $RepoRoot "bin"
$ConfigPath = Join-Path $CertDir "signing.config.json"
$DefaultTargetFiles = @(
    (Join-Path $BinDir "kvc.exe"),
    (Join-Path $BinDir "kvcstrm.sys")
)

function Write-Info([string]$Message) {
    Write-Host $Message -ForegroundColor Cyan
}

function Write-Step([string]$Message) {
    Write-Host $Message -ForegroundColor DarkGray
}

function Write-Success([string]$Message) {
    Write-Host $Message -ForegroundColor Green
}

function Write-WarningLine([string]$Message) {
    Write-Host $Message -ForegroundColor Yellow
}

function Write-Failure([string]$Message) {
    Write-Host $Message -ForegroundColor Red
}

function Get-Slug([string]$Value) {
    $slug = ($Value -replace '[^A-Za-z0-9]+', '_').Trim('_')
    if ([string]::IsNullOrWhiteSpace($slug)) {
        throw "The certificate name produced an empty file prefix."
    }

    return $slug
}

function New-PasswordString([int]$Length = 40) {
    $alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^*_-+="
    $builder = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $Length; $i++) {
        [void]$builder.Append($alphabet[(Get-Random -Minimum 0 -Maximum $alphabet.Length)])
    }

    return $builder.ToString()
}

function ConvertTo-PlainText([securestring]$SecureValue) {
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureValue)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Parse-FixedTimestamp([string]$Value) {
    $styles = [System.Globalization.DateTimeStyles]::AllowWhiteSpaces -bor
              [System.Globalization.DateTimeStyles]::AssumeLocal

    try {
        return [datetime]::Parse(
            $Value,
            [System.Globalization.CultureInfo]::InvariantCulture,
            $styles
        )
    }
    catch {
        throw "Invalid -Timestamp '$Value'. Example: 2027-01-01 00:00:00"
    }
}

function Set-FixedFileTimestamp {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Paths,

        [Parameter(Mandatory = $true)]
        [datetime]$Value
    )

    foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path)) {
            continue
        }

        $item = Get-Item -LiteralPath $path
        $item.CreationTime = $Value
        $item.LastWriteTime = $Value
        $item.LastAccessTime = $Value
    }
}

function Get-LatestSignToolPath {
    $kitsRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
    if (-not (Test-Path -LiteralPath $kitsRoot)) {
        throw "Windows Kits 10 bin directory was not found."
    }

    $versionedTool = $null
    $versionDirs = Get-ChildItem -LiteralPath $kitsRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
        Sort-Object { [version]$_.Name } -Descending

    foreach ($dir in $versionDirs) {
        $candidate = Join-Path $dir.FullName "x64\signtool.exe"
        if (Test-Path -LiteralPath $candidate) {
            $versionedTool = $candidate
            break
        }
    }

    if ($versionedTool) {
        return $versionedTool
    }

    $fallback = Get-ChildItem -LiteralPath $kitsRoot -Recurse -Filter "signtool.exe" -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending |
        Select-Object -ExpandProperty FullName -First 1

    if ($fallback) {
        return $fallback
    }

    throw "signtool.exe was not found in the installed Windows Kits."
}

function New-DefaultConfig {
    return [ordered]@{
        Profiles = [ordered]@{
            Standard = [ordered]@{
                Name = "Microsoft Windows"
            }
            Driver = [ordered]@{
                Name = "Microsoft Windows OS"
            }
        }
    }
}

function Save-Config([hashtable]$Config) {
    $Config | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ConfigPath -Encoding ASCII
}

function Load-JsonFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Convert-ConfigToHashtable([object]$ConfigObject) {
    $config = New-DefaultConfig
    if (-not $ConfigObject) {
        return $config
    }

    if ($ConfigObject.PSObject.Properties.Name -contains "Profiles") {
        foreach ($profileName in @("Standard", "Driver")) {
            $profileConfig = $ConfigObject.Profiles.$profileName
            if ($profileConfig -and -not [string]::IsNullOrWhiteSpace($profileConfig.Name)) {
                $config.Profiles[$profileName].Name = $profileConfig.Name
            }
        }

        return $config
    }

    if ($ConfigObject.PSObject.Properties.Name -contains "Name" -and -not [string]::IsNullOrWhiteSpace($ConfigObject.Name)) {
        $config.Profiles.Standard.Name = $ConfigObject.Name
    }

    return $config
}

function Load-Config {
    $configObject = Load-JsonFile -Path $ConfigPath
    $config = Convert-ConfigToHashtable -ConfigObject $configObject
    Save-Config -Config $config
    return $config
}

function Get-ConfiguredName([hashtable]$Config, [string]$ResolvedProfile, [string]$ExplicitName) {
    if (-not [string]::IsNullOrWhiteSpace($ExplicitName)) {
        return $ExplicitName
    }

    return $Config.Profiles[$ResolvedProfile].Name
}

function Set-ConfiguredName([hashtable]$Config, [string]$ResolvedProfile, [string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) {
        return
    }

    if ($Config.Profiles[$ResolvedProfile].Name -ne $Value) {
        $Config.Profiles[$ResolvedProfile].Name = $Value
        Save-Config -Config $Config
    }
}

function Get-ResolvedProfile([string]$RequestedProfile, [string]$FilePath) {
    if ($RequestedProfile -ne "Auto") {
        return $RequestedProfile
    }

    $extension = [System.IO.Path]::GetExtension($FilePath).ToLowerInvariant()
    if ($extension -eq ".sys") {
        return "Driver"
    }

    return "Standard"
}

function Resolve-TargetPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "Target path must not be empty."
    }

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    $candidateInBin = Join-Path $BinDir $Path
    if (Test-Path -LiteralPath $candidateInBin) {
        return [System.IO.Path]::GetFullPath($candidateInBin)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $UtilityRoot $Path))
}

function Get-TargetFiles([string]$RequestedTargetPath) {
    if (-not [string]::IsNullOrWhiteSpace($RequestedTargetPath)) {
        $resolvedPath = Resolve-TargetPath -Path $RequestedTargetPath
        if (-not (Test-Path -LiteralPath $resolvedPath)) {
            Write-Step "Nothing to do. Target file was not found: $resolvedPath"
            return @()
        }

        if ((Get-Item -LiteralPath $resolvedPath).PSIsContainer) {
            throw "Target path must point to a file, not a directory: $resolvedPath"
        }

        return @($resolvedPath)
    }

    if (-not (Test-Path -LiteralPath $BinDir)) {
        Write-Step "Nothing to do. The bin directory does not exist: $BinDir"
        return @()
    }

    $missingTargets = @($DefaultTargetFiles | Where-Object { -not (Test-Path -LiteralPath $_) })
    if ($missingTargets.Count -gt 0) {
        Write-Step "Nothing to do. Expected target files were not found."
        foreach ($path in $missingTargets) {
            Write-Step "Missing: $path"
        }
        return @()
    }

    return @($DefaultTargetFiles)
}

function Get-PathsForProfile([string]$BaseName, [string]$ResolvedProfile) {
    $slug = Get-Slug $BaseName
    $profileTag = $ResolvedProfile.ToLowerInvariant()
    $prefix = "$slug-$profileTag"

    if ($ResolvedProfile -eq "Driver") {
        $rootSubject = "CN=$BaseName Production Root CA"
        $signerSubject = "CN=$BaseName Embedded Driver Signing"
        $rootFriendlyName = "$BaseName Production Root CA"
        $signerFriendlyName = "$BaseName Embedded Driver Signing"
    }
    else {
        $rootSubject = "CN=$BaseName, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
        $signerSubject = $rootSubject
        $rootFriendlyName = $BaseName
        $signerFriendlyName = $BaseName
    }

    return [ordered]@{
        Name = $BaseName
        Profile = $ResolvedProfile
        Slug = $slug
        RootSubject = $rootSubject
        SignerSubject = $signerSubject
        RootFriendlyName = $rootFriendlyName
        SignerFriendlyName = $signerFriendlyName
        RootCerPath = Join-Path $CertDir "$prefix-root.cer"
        SignerCerPath = Join-Path $CertDir "$prefix-signing.cer"
        PfxPath = Join-Path $CertDir "$prefix-signing.pfx"
        PasswordPath = Join-Path $CertDir "$prefix-signing.pwd"
        LegacyPasswordPath = Join-Path $CertDir "$prefix-signing.password.txt"
        LegacyRootCerPath = Join-Path $CertDir "$slug-root.cer"
        LegacySignerCerPath = Join-Path $CertDir "$slug-signing.cer"
        LegacyPfxPath = Join-Path $CertDir "$slug-signing.pfx"
        LegacyPwdPath = Join-Path $CertDir "$slug-signing.pwd"
        LegacyPasswordTxtPath = Join-Path $CertDir "$slug-signing.password.txt"
    }
}

function Assert-RequiredFiles([hashtable]$Paths) {
    foreach ($path in @($Paths.RootCerPath, $Paths.SignerCerPath, $Paths.PfxPath, $Paths.PasswordPath)) {
        if (-not (Test-Path -LiteralPath $path)) {
            throw "Required certificate asset is missing: $path"
        }
    }
}

function Remove-CertificateByThumbprint([string]$Thumbprint) {
    if ([string]::IsNullOrWhiteSpace($Thumbprint)) {
        return
    }

    $stores = @(
        "Cert:\CurrentUser\My\$Thumbprint",
        "Cert:\CurrentUser\Root\$Thumbprint"
    )

    foreach ($path in $stores) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -DeleteKey -Force -ErrorAction SilentlyContinue
        }
    }
}

function Normalize-CertificateSet([hashtable]$Paths) {
    $moves = @(
        @{ From = $Paths.LegacyRootCerPath; To = $Paths.RootCerPath },
        @{ From = $Paths.LegacySignerCerPath; To = $Paths.SignerCerPath },
        @{ From = $Paths.LegacyPfxPath; To = $Paths.PfxPath },
        @{ From = $Paths.LegacyPwdPath; To = $Paths.PasswordPath },
        @{ From = $Paths.LegacyPasswordTxtPath; To = $Paths.LegacyPasswordPath }
    )

    foreach ($move in $moves) {
        if (($move.From -ne $move.To) -and (-not (Test-Path -LiteralPath $move.To)) -and (Test-Path -LiteralPath $move.From)) {
            Move-Item -LiteralPath $move.From -Destination $move.To -Force
            Set-FixedFileTimestamp -Paths @($move.To) -Value $script:FixedTimestamp
        }
    }

    if ((-not (Test-Path -LiteralPath $Paths.PasswordPath)) -and (Test-Path -LiteralPath $Paths.LegacyPasswordPath)) {
        Move-Item -LiteralPath $Paths.LegacyPasswordPath -Destination $Paths.PasswordPath -Force
        Set-FixedFileTimestamp -Paths @($Paths.PasswordPath) -Value $script:FixedTimestamp
    }
}

function New-CertificateSet([hashtable]$Paths) {
    if (-not (Test-Path -LiteralPath $CertDir)) {
        New-Item -ItemType Directory -Path $CertDir | Out-Null
    }

    $managedFiles = @(
        $Paths.RootCerPath,
        $Paths.SignerCerPath,
        $Paths.PfxPath,
        $Paths.PasswordPath,
        $Paths.LegacyPasswordPath
    )
    $requiredFiles = @(
        $Paths.RootCerPath,
        $Paths.SignerCerPath,
        $Paths.PfxPath,
        $Paths.PasswordPath
    )
    $existingManagedFiles = @($managedFiles | Where-Object { Test-Path -LiteralPath $_ })
    $completeSetExists = (@($requiredFiles | Where-Object { Test-Path -LiteralPath $_ }).Count -eq $requiredFiles.Count)

    if ((-not $Force) -and $completeSetExists) {
        throw "Certificate set already exists. Use -Force to recreate it for $($Paths.Profile): $($Paths.Name)"
    }

    if ($Force) {
        foreach ($path in $existingManagedFiles) {
            Remove-Item -LiteralPath $path -Force
        }
    }

    if ((-not $Force) -and $existingManagedFiles) {
        Write-WarningLine "Removing partial certificate assets before recreating the set for $($Paths.Profile): $($Paths.Name)"
        foreach ($path in $existingManagedFiles) {
            Remove-Item -LiteralPath $path -Force
        }
    }

    $passwordPlain = New-PasswordString
    $securePassword = ConvertTo-SecureString -String $passwordPlain -AsPlainText -Force
    $rootCert = $null
    $signingCert = $null

    try {
        Write-Info "Creating $($Paths.Profile.ToLowerInvariant()) root certificate."
        $rootCert = New-SelfSignedCertificate `
            -Type Custom `
            -Subject $Paths.RootSubject `
            -FriendlyName $Paths.RootFriendlyName `
            -KeyAlgorithm RSA `
            -KeyLength 4096 `
            -HashAlgorithm sha256 `
            -KeyExportPolicy Exportable `
            -KeyUsage CertSign, CRLSign, DigitalSignature `
            -KeyUsageProperty Sign `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -NotAfter (Get-Date).AddYears(10) `
            -TextExtension @(
                "2.5.29.19={critical}{text}CA=true&pathlength=1"
            )

        Write-Info "Creating $($Paths.Profile.ToLowerInvariant()) signing certificate."
        $signingCert = New-SelfSignedCertificate `
            -Type Custom `
            -Subject $Paths.SignerSubject `
            -FriendlyName $Paths.SignerFriendlyName `
            -KeyAlgorithm RSA `
            -KeyLength 4096 `
            -HashAlgorithm sha256 `
            -KeyExportPolicy Exportable `
            -KeySpec Signature `
            -KeyUsage DigitalSignature `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -Signer $rootCert `
            -NotAfter (Get-Date).AddYears(5) `
            -TextExtension @(
                "2.5.29.19={critical}{text}CA=false",
                "2.5.29.37={text}1.3.6.1.4.1.311.10.3.6,1.3.6.1.5.5.7.3.3"
            )

        Export-Certificate -Cert $rootCert -FilePath $Paths.RootCerPath -Type CERT | Out-Null
        Export-Certificate -Cert $signingCert -FilePath $Paths.SignerCerPath -Type CERT | Out-Null
        Export-PfxCertificate -Cert $signingCert -FilePath $Paths.PfxPath -Password $securePassword -ChainOption BuildChain | Out-Null

        $securePassword | ConvertFrom-SecureString | Set-Content -LiteralPath $Paths.PasswordPath -Encoding ASCII

        Set-FixedFileTimestamp -Paths $managedFiles -Value $script:FixedTimestamp
        Write-Success "Certificate set created for $($Paths.Profile): $($Paths.Name)"
    }
    finally {
        if ($signingCert) {
            Remove-CertificateByThumbprint -Thumbprint $signingCert.Thumbprint
        }

        if ($rootCert) {
            Remove-CertificateByThumbprint -Thumbprint $rootCert.Thumbprint
        }

        $passwordPlain = $null
        $securePassword = $null
    }
}

function Get-OrCreatePaths([hashtable]$Config, [string]$ResolvedProfile, [string]$ExplicitName) {
    $effectiveName = Get-ConfiguredName -Config $Config -ResolvedProfile $ResolvedProfile -ExplicitName $ExplicitName
    Set-ConfiguredName -Config $Config -ResolvedProfile $ResolvedProfile -Value $effectiveName

    $paths = Get-PathsForProfile -BaseName $effectiveName -ResolvedProfile $ResolvedProfile
    Normalize-CertificateSet -Paths $paths

    if (-not ((Test-Path -LiteralPath $paths.PfxPath) -and (Test-Path -LiteralPath $paths.PasswordPath) -and (Test-Path -LiteralPath $paths.SignerCerPath) -and (Test-Path -LiteralPath $paths.RootCerPath))) {
        Write-Info "Certificate set was not found for $ResolvedProfile. Creating a new one first."
        New-CertificateSet -Paths $paths
    }

    return $paths
}

function Sign-TargetFile([hashtable]$Paths, [string]$InputPath, [string]$SignToolPath) {
    $securePassword = Get-Content -LiteralPath $Paths.PasswordPath | ConvertTo-SecureString
    $plainPassword = ConvertTo-PlainText -SecureValue $securePassword

    try {
        Write-Info "Signing $([System.IO.Path]::GetFileName($InputPath)) with profile $($Paths.Profile)."
        & $SignToolPath sign /fd sha256 /f $Paths.PfxPath /p $plainPassword /ph $InputPath
        if ($LASTEXITCODE -ne 0) {
            throw "signtool.exe failed with exit code $LASTEXITCODE."
        }
    }
    finally {
        $plainPassword = $null
        $securePassword = $null
    }

    $signature = Get-AuthenticodeSignature -FilePath $InputPath
    if (-not $signature.SignerCertificate) {
        throw "The target file does not contain an embedded signature: $InputPath"
    }

    if ($signature.SignerCertificate.Subject -ne $Paths.SignerSubject) {
        throw "The embedded signature subject does not match the selected signing certificate: $InputPath"
    }

    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        Write-WarningLine "Embedded signature exists, but trust status is $($signature.Status) for $InputPath."
        Write-WarningLine "That is expected until the root certificate is trusted on the target machine."
    }

    Set-FixedFileTimestamp -Paths @($InputPath) -Value $script:FixedTimestamp
    Write-Success "Signed file updated: $InputPath"
}

try {
    $script:FixedTimestamp = Parse-FixedTimestamp -Value $Timestamp

    if (-not (Test-Path -LiteralPath $CertDir)) {
        New-Item -ItemType Directory -Path $CertDir | Out-Null
    }

    $config = Load-Config

    if ($Create) {
        $profilesToCreate = if ($Profile -eq "Auto") { @("Standard", "Driver") } else { @($Profile) }
        if (($profilesToCreate.Count -gt 1) -and (-not [string]::IsNullOrWhiteSpace($Name))) {
            throw "Use -Profile Standard or -Profile Driver together with -Name when creating certificates."
        }

        foreach ($resolvedProfile in $profilesToCreate) {
            $effectiveName = Get-ConfiguredName -Config $config -ResolvedProfile $resolvedProfile -ExplicitName $Name
            Set-ConfiguredName -Config $config -ResolvedProfile $resolvedProfile -Value $effectiveName
            $paths = Get-PathsForProfile -BaseName $effectiveName -ResolvedProfile $resolvedProfile
            Normalize-CertificateSet -Paths $paths
            New-CertificateSet -Paths $paths
        }

        exit 0
    }

    $targets = @(Get-TargetFiles -RequestedTargetPath $TargetPath)
    if ($targets.Count -eq 0) {
        exit 0
    }

    $signTool = Get-LatestSignToolPath
    Write-Step "Using SignTool at $signTool"

    foreach ($target in $targets) {
        $resolvedProfile = Get-ResolvedProfile -RequestedProfile $Profile -FilePath $target
        $paths = Get-OrCreatePaths -Config $config -ResolvedProfile $resolvedProfile -ExplicitName $Name
        Assert-RequiredFiles -Paths $paths
        Sign-TargetFile -Paths $paths -InputPath $target -SignToolPath $signTool
    }
}
catch {
    Write-Failure $_.Exception.Message
    exit 1
}
