# Slow T1486 for the LIVE DEMO of the documents zone. Run ONLY inside the lab VM.
#
# vm_t1486_script.ps1 is built for recording: it finishes in about 0.3 s and its cleanup
# removes the .locked files a second later. That is too fast to demo containment, because
# the entropy rule R-T1486-002 needs the files to still exist when it reads them, and
# "suspend" needs the process to still exist. This script differs in three ways:
#   - a short pause between files, so the burst lasts seconds and containment can hit it
#   - the process stays alive for -HoldSeconds after the last file
#   - the files stay in place for the whole hold, and for good with -NoCleanup
#
# It only touches dummy files that it creates itself, in its own folder,
# Documents\ThreatPulseDemo. "Encrypting" overwrites a copy of a dummy file with random
# bytes (4096 bytes, about 8 bits per byte), so nothing real is ever changed.
#
# Usage, in a PowerShell window started AFTER the agent:
#   .\demo_t1486.ps1                         40 files, 100 ms apart, then holds 30 s
#   .\demo_t1486.ps1 -FileCount 60 -HoldSeconds 60
#   .\demo_t1486.ps1 -NoCleanup              never remove the folder on exit
#   .\demo_t1486.ps1 -Cleanup                separate step: report, then remove the folder
#
# After the hold, the folder is removed unless -NoCleanup is given. If containment suspends
# the process, that removal waits until it is resumed, so run -Cleanup afterwards: it
# prints how many files were locked before the process stopped ("files lost before
# containment", PLANNING.md Section 4.3).

param(
    [switch]$Cleanup,
    [switch]$NoCleanup,
    [ValidateRange(10, 500)][int]$FileCount = 40,
    [ValidateRange(0, 5000)][int]$PauseMilliseconds = 100,
    [ValidateRange(0, 600)][int]$HoldSeconds = 30
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path 'C:\ThreatPulseLab\LAB_VM')) {
    throw 'Refusing to run: C:\ThreatPulseLab\LAB_VM not found. This script is for the lab VM only.'
}

$folder = Join-Path $env:USERPROFILE 'Documents\ThreatPulseDemo'

# Remove only our own folder, and never follow a link out of it.
function Remove-DemoFolder {
    if (-not (Test-Path $folder)) { return }
    if ((Get-Item $folder -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw "Refusing to remove $folder: it is a link."
    }
    Remove-Item -Recurse -Force $folder
}

if ($Cleanup) {
    if (Test-Path $folder) {
        $locked = @(Get-ChildItem $folder -Filter 'dummy*.locked' -File).Count
        $originals = @(Get-ChildItem $folder -Filter 'dummy*.txt' -File).Count
        Write-Host "Locked before the process stopped: $locked. Originals left: $originals."
    } else {
        Write-Host "Nothing to clean up: $folder does not exist."
    }
    Remove-DemoFolder
    return
}

New-Item -ItemType Directory -Force $folder | Out-Null

for ($i = 1; $i -le $FileCount; $i++) {
    Set-Content (Join-Path $folder "dummy$i.txt") "ThreatPulse demo dummy file $i"
}
Write-Host ("Created {0} dummy files in {1}. Starting at {2:HH:mm:ss.fff}." -f $FileCount, $folder, (Get-Date))

try {
    # The T1486 pattern: write a scrambled copy, then delete the original.
    $random = New-Object System.Random
    for ($i = 1; $i -le $FileCount; $i++) {
        $bytes = New-Object byte[] 4096
        $random.NextBytes($bytes)
        [System.IO.File]::WriteAllBytes((Join-Path $folder "dummy$i.locked"), $bytes)
        Remove-Item (Join-Path $folder "dummy$i.txt")
        Write-Host ("locked {0}/{1} at {2:HH:mm:ss.fff}" -f $i, $FileCount, (Get-Date))
        if ($PauseMilliseconds -gt 0) { Start-Sleep -Milliseconds $PauseMilliseconds }
    }
    Write-Host "Done. Holding for $HoldSeconds s so containment can reach this process (PID $PID)."
    if ($HoldSeconds -gt 0) { Start-Sleep -Seconds $HoldSeconds }
} finally {
    if (-not $NoCleanup) { Remove-DemoFolder }
}
