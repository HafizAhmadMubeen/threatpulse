# The FIM evidence session. Run ONLY inside the lab VM, through record_session.ps1:
#
#   .\agent\tools\record_session.ps1 -TestId fim-test -Run 1 -Network host-only
#
# It records, in one short labelled session, what FIM reports when the hosts file and a
# Startup folder change, together with the Run, RunOnce and RunOnceEx values that
# vm_test_fim.ps1 also changes. The activity is vm_test_fim.ps1 itself, unchanged: a comment
# line appended to the hosts file, a dummy file created and changed in the per-user Startup
# folder, and test values added, changed and removed in the Run keys. It undoes all of it
# before it ends.
#
# The session's pool is `fim-test-only`. It is evidence for the FIM layer and the rules, and
# is never used to train or evaluate the model (PLANNING.md Section 8.1).
#
# record_session.ps1 runs a script test twice, as two separate processes: once as the test,
# and once more with -Cleanup after the end time. vm_test_fim.ps1 cleans up after itself,
# so -Cleanup here is only a safety net: it removes what the test creates if the test was
# cut short, and does nothing otherwise. Rolling back the snapshot is the real cleanup.

param(
    [switch]$Cleanup,
    [int]$HoldSeconds = 3
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path 'C:\ThreatPulseLab\LAB_VM')) {
    throw 'Refusing to run: C:\ThreatPulseLab\LAB_VM not found. This script is for the lab VM only.'
}
if (-not [Environment]::Is64BitProcess) {
    throw 'Refusing to run: open the 64-bit Windows PowerShell, not Windows PowerShell (x86).'
}

if (-not $Cleanup) {
    & (Join-Path $PSScriptRoot 'vm_test_fim.ps1') -HoldSeconds $HoldSeconds
    return
}

# Cleanup: only the items vm_test_fim.ps1 creates, and only if they are still there.
$valueName = 'ThreatPulseFimTest'
$root = 'Microsoft\Windows\CurrentVersion'
$valueKeys = @(
    "HKCU:\Software\$root\Run",
    "HKCU:\Software\$root\RunOnce",
    "HKLM:\SOFTWARE\$root\Run",
    "HKLM:\SOFTWARE\$root\RunOnce",
    "HKLM:\SOFTWARE\$root\RunOnceEx\0001\Depend",
    "HKLM:\SOFTWARE\WOW6432Node\$root\Run",
    "HKLM:\SOFTWARE\WOW6432Node\$root\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\$root\RunOnceEx\0001\Depend"
)
$startupFile = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup\threatpulse-fim-test.txt'
$hostsFile = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$hostsMarker = "`r`n# ThreatPulse FIM test`r`n"

$removed = 0
foreach ($key in $valueKeys) {
    if ((Test-Path $key) -and (Get-ItemProperty -Path $key -Name $valueName -ErrorAction SilentlyContinue)) {
        Remove-ItemProperty -Path $key -Name $valueName -ErrorAction SilentlyContinue
        "Removed the leftover test value in $key"
        $removed++
    }
}
if (Test-Path $startupFile) {
    Remove-Item $startupFile -Force -ErrorAction SilentlyContinue
    "Removed the leftover test file $startupFile"
    $removed++
}
$hostsText = [System.IO.File]::ReadAllText($hostsFile)
if ($hostsText.Contains($hostsMarker)) {
    [System.IO.File]::WriteAllText($hostsFile, $hostsText.Replace($hostsMarker, ''))
    "Removed the leftover test line from the hosts file"
    $removed++
}
if ($removed -eq 0) { 'Nothing to clean up.' }
