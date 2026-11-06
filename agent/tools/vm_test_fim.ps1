# Harmless changes for testing FIM. Run ONLY inside the lab VM, in a 64-bit PowerShell
# opened with "Run as administrator", while FIM is watching. check_fim_run.py then checks
# the recorded events.
#
# It adds a comment line to the hosts file, adds a test value to the Run, RunOnce and
# RunOnceEx keys and adds a dummy text file to the startup folder. All of it is undone
# before it ends, even if the script fails part-way.
#
# RunOnceEx keeps its values in numbered subkeys and may not exist yet, which is what FIM
# has to cope with. The test creates the keys that are missing, and removes only those.
#
# -Quick changes only the HKCU Run key, to test the 60-second compare with --poll-only.
# Use -Quick -HoldSeconds 70, so that FIM has time to see the value appear and go.

param(
    [switch]$Quick,
    [int]$HoldSeconds = 3
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path 'C:\ThreatPulseLab\LAB_VM')) {
    throw 'Refusing to run: C:\ThreatPulseLab\LAB_VM not found. This script is for the lab VM only.'
}
# In 32-bit PowerShell, HKLM keys and System32 redirect, so the test would change the
# wrong places.
if (-not [Environment]::Is64BitProcess) {
    throw 'Refusing to run: open the 64-bit Windows PowerShell, not Windows PowerShell (x86).'
}

$valueName = 'ThreatPulseFimTest'
$data = 'C:\Windows\System32\notepad.exe'
$root = 'Microsoft\Windows\CurrentVersion'
$allKeys = @(
    "HKCU\Software\$root\Run",
    "HKCU\Software\$root\RunOnce",
    "HKLM\SOFTWARE\$root\Run",
    "HKLM\SOFTWARE\$root\RunOnce",
    "HKLM\SOFTWARE\WOW6432Node\$root\Run",
    "HKLM\SOFTWARE\WOW6432Node\$root\RunOnce"
)

# FIM can only watch a key that already exists, so one that is missing is skipped here.
$keys = @()
foreach ($key in $(if ($Quick) { $allKeys[0] } else { $allKeys })) {
    if (Test-Path "Registry::$key") {
        $keys += $key
    } else {
        Write-Warning "Skipping $key, which does not exist."
    }
}

# The RunOnceEx keys may be missing. Note which of them the test has to create.
$createdKeys = @()
if (-not $Quick) {
    foreach ($treeRoot in @("HKLM\SOFTWARE\$root\RunOnceEx", "HKLM\SOFTWARE\WOW6432Node\$root\RunOnceEx")) {
        $keys += "$treeRoot\0001\Depend"
        foreach ($path in @($treeRoot, "$treeRoot\0001", "$treeRoot\0001\Depend")) {
            if (-not (Test-Path "Registry::$path")) { $createdKeys += $path }
        }
    }
}
Set-Content 'C:\ThreatPulseLab\logs\fim_test_keys.txt' $keys

$hostsFile = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$hostsBefore = [System.IO.File]::ReadAllBytes($hostsFile)
$startupFile = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup\threatpulse-fim-test.txt'

try {
    foreach ($key in $keys) {
        & reg add $key /v $valueName /t REG_SZ /d $data /f | Out-Null
    }
    Start-Sleep -Seconds $HoldSeconds

    if (-not $Quick) {
        & reg add $keys[0] /v $valueName /t REG_SZ /d "$data /changed" /f | Out-Null

        [System.IO.File]::AppendAllText($hostsFile, "`r`n# ThreatPulse FIM test`r`n")

        Set-Content $startupFile 'ThreatPulse FIM test'
        Start-Sleep -Seconds $HoldSeconds
        Add-Content $startupFile 'Changed'
        Start-Sleep -Seconds $HoldSeconds
    }
} finally {
    # With 'Stop', a value that is already gone would end this loop early.
    $ErrorActionPreference = 'Continue'
    foreach ($key in $keys) {
        & reg delete $key /v $valueName /f 2>$null | Out-Null
    }
    # Only keys the test created, each of which holds nothing but the test's own value.
    foreach ($path in $createdKeys) {
        Remove-Item "Registry::$path" -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (-not $Quick) {
        [System.IO.File]::WriteAllBytes($hostsFile, $hostsBefore)
        Remove-Item $startupFile -ErrorAction SilentlyContinue
    }
}

if ($Quick) {
    Start-Sleep -Seconds $HoldSeconds
}
'FIM test activity finished, and everything has been undone.'
