# Our own harmless T1486 test. Run ONLY inside the lab VM. It only touches dummy files
# that it creates itself, in a dedicated test folder. The "encryption" overwrites copies
# of those dummy files with random bytes, so nothing real is ever changed.
#
# -Cleanup removes the folder. record_session.ps1 runs it as a separate process, so
# that cleanup isn't labelled as part of the attack.

param(
    [switch]$Cleanup,
    [int]$FileCount = 25
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path 'C:\ThreatPulseLab\LAB_VM')) {
    throw 'Refusing to run: C:\ThreatPulseLab\LAB_VM not found. This script is for the lab VM only.'
}

$folder = Join-Path $env:USERPROFILE 'Documents\ThreatPulseTest'

if ($Cleanup) {
    Remove-Item -Recurse -Force $folder -ErrorAction SilentlyContinue
    return
}

New-Item -ItemType Directory -Force $folder | Out-Null

for ($i = 1; $i -le $FileCount; $i++) {
    Set-Content (Join-Path $folder "dummy$i.txt") "ThreatPulse dummy file $i"
}

# The T1486 pattern: write a scrambled copy, then delete the original.
$random = New-Object System.Random
for ($i = 1; $i -le $FileCount; $i++) {
    $bytes = New-Object byte[] 4096
    $random.NextBytes($bytes)
    [System.IO.File]::WriteAllBytes((Join-Path $folder "dummy$i.locked"), $bytes)
    Remove-Item (Join-Path $folder "dummy$i.txt")
}
