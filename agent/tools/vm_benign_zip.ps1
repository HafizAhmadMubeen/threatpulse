# Benign zipping for recordings. Run ONLY inside the lab VM. It only touches dummy files it
# creates itself, and removes them at the end. Zipping many files in Documents looks a
# little like ransomware, which is why it's useful benign data.

param([int]$Minutes = 10)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path 'C:\ThreatPulseLab\LAB_VM')) {
    throw 'Refusing to run: C:\ThreatPulseLab\LAB_VM not found. This script is for the lab VM only.'
}

$folder = Join-Path $env:USERPROFILE 'Documents\ThreatPulseBenign'
$source = Join-Path $folder 'source'
$archive = Join-Path $folder 'archive.zip'
$expanded = Join-Path $folder 'expanded'
$deadline = (Get-Date).AddMinutes($Minutes)

New-Item -ItemType Directory -Force $source | Out-Null
try {
    for ($i = 1; $i -le 50; $i++) {
        Set-Content (Join-Path $source "note$i.txt") ("ThreatPulse benign dummy text $i`r`n" * 200)
    }

    while ((Get-Date) -lt $deadline) {
        Compress-Archive -Path "$source\*" -DestinationPath $archive -Force
        Expand-Archive -Path $archive -DestinationPath $expanded -Force
        Remove-Item -Recurse -Force $expanded
        Remove-Item -Force $archive
        Start-Sleep -Seconds 30
    }
} finally {
    Remove-Item -Recurse -Force $folder -ErrorAction SilentlyContinue
}
