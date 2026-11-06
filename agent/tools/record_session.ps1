# Records one session: sensors on, one test or one benign period, sensors off, session.json.
# A person starts this inside the lab VM, in a 64-bit PowerShell opened as administrator.
#
#   record_session.ps1 -TestId T1547.001-1 -Run 1 -Network host-only [-Batch 1 -Order 1]
#   record_session.ps1 -TestId benign -Run 1 -Network nat -Activity normal-use [-Minutes 10]
#
# run_batch.ps1 calls this for each session of a batch. It only runs what
# agent/config/recording_tests.json lists, so the T1685 tests that remove Sysmon can't run
# through it. Roll back to atomic-ready-3 after each batch (step 2.6).
#
# After the sensors start, the script waits for the settle time and then the warm-up, so
# that the start of the sensors is over before the session begins. -WarmupSeconds is
# recorded in session.json. Sessions recorded before the warm-up existed count as 0.

param(
    [Parameter(Mandatory)][string]$TestId,
    [Parameter(Mandatory)][int]$Run,
    [Parameter(Mandatory)][ValidateSet('host-only', 'nat')][string]$Network,
    [string]$Activity,
    [int]$Minutes = 0,
    [int]$Batch = 0,  # 0 means a trial, outside the batch plan
    [int]$Order = 0,
    [int]$WarmupSeconds = 60
)

$ErrorActionPreference = 'Stop'

$SettleSeconds = 10
$LateEventSeconds = 30
$AtomicTimeoutSeconds = 120
$AtomicModule = 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1'
$AtomicRepo = 'C:\AtomicRedTeam\atomic-red-team'
$SessionsRoot = 'C:\ThreatPulseLab\logs\sessions'

function Get-UtcStamp {
    return (Get-Date).ToUniversalTime().ToString(
        "yyyy-MM-ddTHH:mm:ss.fffZ", [Globalization.CultureInfo]::InvariantCulture)
}

# Runs one PowerShell command as a new process, so that its PID is the root of the tree.
function Start-TestProcess([string[]]$Arguments) {
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    return Start-Process -FilePath $powershell -PassThru -WorkingDirectory $env:TEMP `
        -ArgumentList (@('-NoProfile', '-ExecutionPolicy', 'Bypass') + $Arguments)
}

function Get-AtomicArguments($Test, [switch]$Cleanup) {
    $flag = if ($Cleanup) { ' -Cleanup' } else { '' }
    $command = "Import-Module '$AtomicModule' -Force; Invoke-AtomicTest $($Test.technique) " +
        "-TestNumbers $($Test.number) -TimeoutSeconds $AtomicTimeoutSeconds$flag"
    return @('-Command', "`"$command`"")
}

function Get-ScriptArguments($Test, [switch]$Cleanup) {
    $arguments = @('-File', "`"$(Join-Path $PSScriptRoot $Test.script)`"")
    if ($Cleanup) { $arguments += '-Cleanup' }
    return $arguments
}

if (-not (Test-Path 'C:\ThreatPulseLab\LAB_VM')) {
    throw 'Refusing to run: C:\ThreatPulseLab\LAB_VM not found. This script is for the lab VM only.'
}
if (-not [Environment]::Is64BitProcess) {
    throw 'Refusing to run: open the 64-bit Windows PowerShell, not Windows PowerShell (x86).'
}

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$config = Get-Content (Join-Path $repo 'agent\config\recording_tests.json') -Raw | ConvertFrom-Json
$benign = $TestId -eq 'benign'
$test = $null

if ($benign) {
    if ($config.benign.activities -notcontains $Activity) {
        throw "Use -Activity with one of: $($config.benign.activities -join ', ')"
    }
    if ($Minutes -le 0) { $Minutes = $config.benign.minutes }
} else {
    $test = $config.tests | Where-Object { $_.id -eq $TestId }
    if (-not $test) {
        throw "$TestId is not in recording_tests.json. Allowed: $($config.tests.id -join ', ')"
    }
    if ($Network -ne $test.network) {
        throw "$TestId must be recorded with -Network $($test.network)."
    }
    if ($test.kind -eq 'atomic') {
        $commit = (& git -C $AtomicRepo rev-parse HEAD).Trim()
        if ($commit -ne $config.atomic_commit) {
            throw "Atomic Red Team is at $commit, not the pinned $($config.atomic_commit)."
        }
    }
}

# Network mode is part of the dataset, so what is recorded must be what is true.
$reachable = Test-NetConnection -ComputerName 'example.com' -Port 443 -InformationLevel Quiet `
    -WarningAction SilentlyContinue
if ($reachable -ne ($Network -eq 'nat')) {
    throw "-Network says $Network, but example.com reachable is $reachable. Check the VM's adapter."
}

$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmss')
$sessionId = "$stamp-$TestId-run$Run"
$sessionDir = Join-Path $SessionsRoot $sessionId

$rootPid = $null
$exitCode = $null
$startUtc = $null
$endUtc = $null

& (Join-Path $PSScriptRoot 'start_lab_sensors.ps1') -Start -SessionDir $sessionDir
try {
    Start-Sleep -Seconds $SettleSeconds
    if ($WarmupSeconds -gt 0) {
        "Warming up for $WarmupSeconds seconds."
        Start-Sleep -Seconds $WarmupSeconds
    }

    # FIM compares with the baseline when it starts, so anything in its log by now means
    # the persistence zone isn't clean. This can't see Defender's state or scheduled tasks.
    # If a harmless rewrite such as Edge's Run value trips it, run the batch again from here.
    if ((Get-Item (Join-Path $sessionDir 'fim.jsonl')).Length -gt 0) {
        throw "Clean-start check failed: FIM reported changes before the session began. See $sessionDir\fim.jsonl"
    }

    if ($benign) {
        $activityScript = $config.benign.scripted.$Activity
        $startUtc = Get-UtcStamp
        if ($activityScript) {
            "Recording benign session ($Activity). This runs by itself for $Minutes minutes."
            $process = Start-TestProcess @('-File', "`"$(Join-Path $PSScriptRoot $activityScript)`"", '-Minutes', $Minutes)
            $process.WaitForExit()
        } else {
            "Recording benign session ($Activity) for $Minutes minutes. Do the activity now."
            Start-Sleep -Seconds ($Minutes * 60)
            "Stop the activity now."
        }
        $endUtc = Get-UtcStamp
    } else {
        $getArguments = if ($test.kind -eq 'atomic') { ${function:Get-AtomicArguments} } else { ${function:Get-ScriptArguments} }

        $startUtc = Get-UtcStamp
        $process = Start-TestProcess (& $getArguments $test)
        $rootPid = $process.Id
        $null = $process.Handle  # keeps the exit code available after the process ends
        $process.WaitForExit()
        $exitCode = $process.ExitCode
        $endUtc = Get-UtcStamp

        # A separate process, after the end time, so cleanup is never labelled as the attack.
        $cleanup = Start-TestProcess (& $getArguments $test -Cleanup)
        $cleanup.WaitForExit()
    }

    Start-Sleep -Seconds $LateEventSeconds
} finally {
    & (Join-Path $PSScriptRoot 'start_lab_sensors.ps1') -Stop
}

$session = [ordered]@{
    session_id    = $sessionId
    test_id       = $TestId
    label         = if ($benign) { 'benign' } else { 'malicious' }
    pool          = if ($benign) { 'unassigned' } else { $test.pool }  # the train/test split comes later
    batch         = $Batch
    order         = $Order
    warmup_seconds = $WarmupSeconds
    technique     = if ($benign) { $null } else { $test.technique }
    test_number   = if ($benign -or $test.kind -ne 'atomic') { $null } else { $test.number }
    activity      = if ($benign) { $Activity } else { $null }
    run           = $Run
    network       = $Network
    root_pid      = $rootPid
    exit_code     = $exitCode
    start_utc     = $startUtc
    end_utc       = $endUtc
    atomic_commit = if ($test -and $test.kind -eq 'atomic') { $config.atomic_commit } else { $null }
    agent_commit  = (& git -C $repo rev-parse HEAD).Trim()
    filters_sha256 = (Get-FileHash (Join-Path $repo 'agent\config\filters.json') -Algorithm SHA256).Hash.ToLower()
}
# Windows PowerShell 5.1 adds a byte order mark with -Encoding UTF8, so write the bytes directly.
[System.IO.File]::WriteAllText(
    (Join-Path $sessionDir 'session.json'),
    ($session | ConvertTo-Json),
    (New-Object System.Text.UTF8Encoding($false)))

"Session finished: $sessionDir"
