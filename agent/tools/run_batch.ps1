# Runs one batch from batch_plan.json, in its fixed order. A person starts this inside the
# lab VM, in a 64-bit PowerShell opened as administrator, right after a revert.
#
#   run_batch.ps1 -Batch 1 [-FromOrder 4]
#
# It pauses before each manual benign session and says what to do. If a session fails, it
# stops. Export what finished, revert to atomic-ready-3, then resume with -FromOrder.

param(
    [Parameter(Mandatory)][int]$Batch,
    [int]$FromOrder = 1
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path 'C:\ThreatPulseLab\LAB_VM')) {
    throw 'Refusing to run: C:\ThreatPulseLab\LAB_VM not found. This script is for the lab VM only.'
}

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$plan = Get-Content (Join-Path $PSScriptRoot 'batch_plan.json') -Raw | ConvertFrom-Json
$config = Get-Content (Join-Path $repo 'agent\config\recording_tests.json') -Raw | ConvertFrom-Json

$entry = $plan.batches | Where-Object { $_.batch -eq $Batch }
if (-not $entry) {
    throw "Batch $Batch is not in batch_plan.json."
}

$instructions = @{
    'normal-use'        = 'Use the VM normally: File Explorer, Notepad, Settings, Paint, Task Manager. Keep moving between apps.'
    'install-uninstall' = 'Install 7-Zip and PuTTY from C:\ThreatPulseLab\installers, use them briefly, then uninstall both from Settings > Apps. Repeat until the time is up.'
    'windows-update'    = 'Open Settings > Windows Update and click Check for updates. Let it download and install. Do NOT restart the VM.'
}

"Batch $Batch : $($entry.sessions.Count) sessions, network $($entry.network)."

foreach ($session in $entry.sessions) {
    if ($session.order -lt $FromOrder) { continue }

    "`n=== Session $($session.order) of $($entry.sessions.Count): $($session.test_id) $($session.activity) (run $($session.run)) ==="

    $arguments = @{
        TestId  = $session.test_id
        Run     = $session.run
        Network = $entry.network
        Batch   = $Batch
        Order   = $session.order
    }

    if ($session.activity) {
        $arguments.Activity = $session.activity
        if (-not $config.benign.scripted.($session.activity)) {
            "NEXT, YOU DO THIS for $($config.benign.minutes) minutes:"
            "  $($instructions[$session.activity])"
            'Start when the script says "Do the activity now", and stop when it says "Stop the activity now".'
            Read-Host 'Press Enter when you are ready' | Out-Null
        }
    }

    & (Join-Path $PSScriptRoot 'record_session.ps1') @arguments
}

"`nBatch $Batch finished. Export it, disable the shared folder, then revert to atomic-ready-3."
