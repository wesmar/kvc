$introText = @"
/*******************************************************************************
  _  ____     ______ 
 | |/ /\ \   / / ___|
 | ' /  \ \ / / |    
 | . \   \ V /| |___ 
 |_|\_\   \_/  \____|

The **Kernel Vulnerability Capabilities (KVC)** framework represents a paradigm shift in Windows security research, 
offering unprecedented access to modern Windows internals through sophisticated ring-0 operations. Originally conceived 
as "Kernel Process Control," the framework has evolved to emphasize not just control, but the complete **exploitation 
of kernel-level primitives** for legitimate security research and penetration testing.

KVC addresses the critical gap left by traditional forensic tools that have become obsolete in the face of modern Windows 
security hardening. Where tools like ProcDump and Process Explorer fail against Protected Process Light (PPL) and Antimalware 
Protected Interface (AMSI) boundaries, KVC succeeds by operating at the kernel level, manipulating the very structures 
that define these protections.

  -----------------------------------------------------------------------------
  Author : Marek Wesołowski
  Email  : marek@wesolowski.eu.org
  Phone  : +48 607 440 283 (Tel/WhatsApp)
  Date   : 04-09-2025

*******************************************************************************/

"@

# Get all .cpp files in current directory
$cppFiles = Get-ChildItem -Path . -Filter "*.cpp"

# Count files with and without intro
$filesWithIntro = 0
$filesWithoutIntro = 0

foreach ($file in $cppFiles) {
    $content = Get-Content -Raw $file.FullName
    $introPattern = [regex]::Escape($introText.Trim())
    
    if ($content -match $introPattern) {
        $filesWithIntro++
    }
    else {
        $filesWithoutIntro++
    }
}

# Display summary
Write-Host "Found intro in $filesWithIntro files" -ForegroundColor Yellow
if ($filesWithIntro -gt 0) {
    $choice = Read-Host "Remove intro from all these files in batch? (Y/N)"
    if ($choice -eq 'Y' -or $choice -eq 'y') {
        foreach ($file in $cppFiles) {
            $content = Get-Content -Raw $file.FullName
            $introPattern = [regex]::Escape($introText.Trim())
            
            if ($content -match $introPattern) {
                $newContent = $content -replace $introPattern, ""
                $newContent = $newContent.TrimStart()
                Set-Content -Path $file.FullName -Value $newContent -NoNewline
                Write-Host "Removed intro from $($file.Name)" -ForegroundColor Green
            }
        }
    }
}

Write-Host "Intro not found in $filesWithoutIntro files" -ForegroundColor Yellow
if ($filesWithoutIntro -gt 0) {
    $choice = Read-Host "Add intro to all these files in batch? (Y/N)"
    if ($choice -eq 'Y' -or $choice -eq 'y') {
        foreach ($file in $cppFiles) {
            $content = Get-Content -Raw $file.FullName
            $introPattern = [regex]::Escape($introText.Trim())
            
            if (-not ($content -match $introPattern)) {
                $newContent = $introText + "`r`n" + $content
                Set-Content -Path $file.FullName -Value $newContent -NoNewline
                Write-Host "Added intro to $($file.Name)" -ForegroundColor Green
            }
        }
    }
}

Write-Host "Batch operation completed" -ForegroundColor Cyan
