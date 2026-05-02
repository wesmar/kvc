# ======================================================================
#  Merge source files into one UTF-8 file optimized for LLM upload
# ======================================================================

param(
    [string]$StartDir = ".",
    [string]$OutputFile = "src.txt",
    [ValidateSet("txt", "md")]
    [string]$Format = "txt",
    [switch]$NoMeta = $true,
    [string[]]$IncludeExt = @(".asm", ".c", ".cpp", ".h", ".html", ".rc", ".lng", ".md", ".php", ".vcxproj", ".filters", ".ps1"),
    [string[]]$ExcludeDirPattern = @("\\.git\\", "\\bin\\", "\\build\\", "\\out\\", "\\x64\\", "\\x86\\", "\\obj\\")
)

$ErrorActionPreference = "Stop"

function Test-IsExcludedPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$Patterns
    )
    foreach ($pattern in $Patterns) {
        if ($Path -match $pattern) {
            return $true
        }
    }
    return $false
}

$baseDirPath = (Resolve-Path $StartDir).Path
$outputPath = if ([System.IO.Path]::IsPathRooted($OutputFile)) {
    $OutputFile
} else {
    Join-Path (Get-Location) $OutputFile
}

$normalizedExt = @($IncludeExt | ForEach-Object { $_.ToLowerInvariant() })

$files = Get-ChildItem -Path $baseDirPath -Recurse -File |
    Where-Object {
        $extOk = $normalizedExt -contains $_.Extension.ToLowerInvariant()
        if (-not $extOk) { return $false }
        -not (Test-IsExcludedPath -Path $_.FullName -Patterns $ExcludeDirPattern)
    } |
    Sort-Object FullName

$outputDir = Split-Path -Parent $outputPath
if ($outputDir -and -not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$writer = [System.IO.StreamWriter]::new($outputPath, $false, $utf8NoBom)

try {
    foreach ($file in $files) {
        $relativePath = $file.FullName.Substring($baseDirPath.Length).TrimStart('\', '/')

        if ($Format -eq "md") {
            $writer.WriteLine(("## FILE: {0}" -f $relativePath))
        } else {
            $writer.WriteLine(("<<<FILE: {0}>>>" -f $relativePath))
        }

        if (-not $NoMeta) {
            $created = $file.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
            $modified = $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
            $sizeKB = [math]::Round($file.Length / 1KB, 2)
            $writer.WriteLine(("Created: {0}" -f $created))
            $writer.WriteLine(("Modified: {0}" -f $modified))
            $writer.WriteLine(("SizeKB: {0}" -f $sizeKB))
        }

        if ($Format -eq "md") {
            $lang = $file.Extension.TrimStart('.').ToLowerInvariant()
            if ([string]::IsNullOrWhiteSpace($lang)) { $lang = "text" }
            $writer.WriteLine(('```{0}' -f $lang))
        }

        $reader = [System.IO.StreamReader]::new($file.FullName, $true)
        try {
            $content = $reader.ReadToEnd()
            $writer.Write($content)
            if ($content.Length -gt 0 -and -not $content.EndsWith("`n")) {
                $writer.WriteLine()
            }
        } finally {
            $reader.Dispose()
        }

        if ($Format -eq "md") {
            $writer.WriteLine('```')
        }

        $writer.WriteLine()
    }
}
finally {
    $writer.Dispose()
}

Write-Host ("Completed. Output file: {0}" -f $outputPath)
Write-Host ("Files merged: {0}" -f $files.Count)
Write-Host ("Format: {0}, NoMeta: {1}" -f $Format, [bool]$NoMeta)
Write-Host "LLM profile: Gemini-friendly (UTF-8, stable file markers, low token overhead)"
