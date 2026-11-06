# Starts the agent and FIM together, and stops both. Used for every recording and demo.
# Run ONLY inside the lab VM, in a 64-bit PowerShell opened as administrator.
#
#   start_lab_sensors.ps1 -Start [-SessionDir <folder>]
#   start_lab_sensors.ps1 -Stop
#
# -Start returns once both sensors are working. -Stop asks each to stop through its named
# event, which is the same clean stop as Ctrl+C, so nothing queued is lost. It never
# kills them: that would lose events and leave the ETW session running.

param(
    [switch]$Start,
    [switch]$Stop,
    [string]$SessionDir
)

$ErrorActionPreference = 'Stop'

$AgentStopEvent = 'Global\ThreatPulse-Agent-Stop'
$FimStopEvent = 'Global\ThreatPulse-Fim-Stop'
$StateFile = 'C:\ThreatPulseLab\logs\sensors_running.json'
$StartTimeoutSeconds = 30
$StopTimeoutSeconds = 30

function Test-NamedEvent([string]$Name) {
    $handle = $null
    $found = [System.Threading.EventWaitHandle]::TryOpenExisting($Name, [ref]$handle)
    if ($found) { $handle.Dispose() }
    return $found
}

function Set-NamedEvent([string]$Name) {
    $handle = $null
    if ([System.Threading.EventWaitHandle]::TryOpenExisting($Name, [ref]$handle)) {
        [void]$handle.Set()
        $handle.Dispose()
    }
}

function Wait-Until([scriptblock]$Condition, [string]$What, $Process) {
    $deadline = (Get-Date).AddSeconds($StartTimeoutSeconds)
    while (-not (& $Condition)) {
        if ($Process.HasExited) { throw "$What exited during startup." }
        if ((Get-Date) -gt $deadline) { throw "$What did not start within $StartTimeoutSeconds seconds." }
        Start-Sleep -Milliseconds 200
    }
}

function Stop-Sensors {
    Set-NamedEvent $FimStopEvent
    Set-NamedEvent $AgentStopEvent

    if (-not (Test-Path $StateFile)) { return }
    $state = Get-Content $StateFile -Raw | ConvertFrom-Json
    foreach ($id in @($state.agent_pid, $state.fim_pid)) {
        $process = Get-Process -Id $id -ErrorAction SilentlyContinue
        if ($process -and -not $process.WaitForExit($StopTimeoutSeconds * 1000)) {
            throw "Process $id did not stop within $StopTimeoutSeconds seconds. It was left running."
        }
    }
    Remove-Item $StateFile
    "Sensors stopped. Summaries are in $($state.session_dir)"
}

if (-not (Test-Path 'C:\ThreatPulseLab\LAB_VM')) {
    throw 'Refusing to run: C:\ThreatPulseLab\LAB_VM not found. This script is for the lab VM only.'
}
if (-not [Environment]::Is64BitProcess) {
    throw 'Refusing to run: open the 64-bit Windows PowerShell, not Windows PowerShell (x86).'
}
if ([bool]$Start -eq [bool]$Stop) {
    throw 'Use exactly one of -Start and -Stop.'
}

if ($Stop) {
    Stop-Sensors
    return
}

$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Refusing to run: open PowerShell with "Run as administrator".'
}
if ((Test-NamedEvent $AgentStopEvent) -or (Test-NamedEvent $FimStopEvent)) {
    throw 'A sensor is already running. Stop it first.'
}

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$agentProgram = Join-Path $repo 'agent\build\Release\threatpulse_agent.exe'
$python = Join-Path $repo 'agent\.venv\Scripts\python.exe'
$fimScript = Join-Path $repo 'agent\fim\main.py'

if (-not $SessionDir) {
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmss')
    $SessionDir = "C:\ThreatPulseLab\logs\sessions\manual-$stamp"
}
New-Item -ItemType Directory -Force $SessionDir | Out-Null
$events = Join-Path $SessionDir 'events.jsonl'
$fim = Join-Path $SessionDir 'fim.jsonl'

$agent = Start-Process -FilePath $agentProgram -ArgumentList @('--out', "`"$events`"") -PassThru `
    -WorkingDirectory $repo `
    -RedirectStandardOutput (Join-Path $SessionDir 'agent_summary.txt') `
    -RedirectStandardError (Join-Path $SessionDir 'agent_errors.txt')

$fimProcess = $null
try {
    # The file has data only once the ETW session is delivering events.
    Wait-Until { (Test-Path $events) -and (Get-Item $events).Length -gt 0 } 'The agent' $agent

    $fimProcess = Start-Process -FilePath $python `
        -ArgumentList @('-u', "`"$fimScript`"", 'watch', '--out', "`"$fim`"") -PassThru `
        -WorkingDirectory $repo `
        -RedirectStandardOutput (Join-Path $SessionDir 'fim_summary.txt') `
        -RedirectStandardError (Join-Path $SessionDir 'fim_errors.txt')
    Wait-Until { (Test-NamedEvent $FimStopEvent) -and (Test-Path $fim) } 'FIM' $fimProcess
} catch {
    Set-NamedEvent $FimStopEvent
    Set-NamedEvent $AgentStopEvent
    throw
}

@{ agent_pid = $agent.Id; fim_pid = $fimProcess.Id; session_dir = $SessionDir } |
    ConvertTo-Json | Set-Content $StateFile
"Sensors running. Writing to $SessionDir"
