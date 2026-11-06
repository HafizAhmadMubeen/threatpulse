# Tests the enforcement actions (policy/executor.py, policy/actions_windows.py) on harmless
# targets. Run ONLY inside the lab VM, in a 64-bit PowerShell opened with "Run as
# administrator", signed in as lab. NOT while a dataset batch is recording, and not from a
# snapshot that will be used for recording: it changes the firewall, the Run key, the
# startup folder and (with -TestCfa) Defender, and the journal and quarantine files stay.
# Roll the VM back afterwards.
#
# Prerequisites (NAT on, once): the repository at C:\ThreatPulseLab\threatpulse on the branch
# to test, and a Python 3.12 virtual environment that has the repository's pinned
# PyYAML and jsonschema (see uv.lock):
#   python -m venv C:\ThreatPulseLab\venv-policy
#   C:\ThreatPulseLab\venv-policy\Scripts\python -m pip install pyyaml==6.0.3 jsonschema
# and the built agent (the never-suspend re-check uses its --check-image).
#
# What it checks, each with its undo, and each as the Decision flow does it: the policy
# engine plans a Decision from an Alert, execute() runs it, undo() reverses it.
#   1. The VM guard: with no LAB_VM marker the actions are skipped and nothing changes
#   2. suspend a copy of ping.exe (all threads Suspended), then undo (running again)
#   3. block_network for that copy (an outbound block rule for its path), then undo
#   4. restore, registry: a test Run value (text and DWORD) that is not in the baseline is
#      quarantined and removed, then undo puts back the same value and type
#   5. restore, file: a dummy startup-folder file is quarantined and removed, then undo
#   6. request_delete: waits for approval, then moves a dummy file to quarantine, then undo
#   7. request_kill: runs only after approval, on the process we suspended (no undo)
#   8. never-suspend: explorer.exe is refused even from a stale Alert. Skip with
#      -SkipNeverSuspend. If this check ever failed, explorer would freeze: roll back
#   9. -TestCfa only: enables Controlled Folder Access and undoes it. Do it LAST, and never
#      before taking a snapshot that dataset recording will use
#
# It never touches system processes except in check 8 (which must be refused), and it
# removes what it creates. The exit code is 1 if any check fails.

param(
    [string]$Python = 'C:\ThreatPulseLab\venv-policy\Scripts\python.exe',
    [switch]$SkipNeverSuspend,
    [switch]$TestCfa
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path 'C:\ThreatPulseLab\LAB_VM')) {
    throw 'Refusing to run: C:\ThreatPulseLab\LAB_VM not found. This script is for the lab VM only.'
}
if (-not [Environment]::Is64BitProcess) {
    throw 'Refusing to run: open the 64-bit Windows PowerShell, not Windows PowerShell (x86).'
}
$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Refusing to run: open PowerShell with "Run as administrator".'
}
if (-not (Test-Path $Python)) { throw "No Python at $Python. See the prerequisites at the top of this script." }
if (-not (Test-Path 'C:\ThreatPulseLab\fim\baseline.json')) { throw 'No FIM baseline at C:\ThreatPulseLab\fim\baseline.json.' }

$work = 'C:\ThreatPulseLab\enforcement-test'
$repo = 'C:\ThreatPulseLab\threatpulse'
$driver = Join-Path $work 'driver.py'
$pingCopy = Join-Path $work 'ping_copy.exe'
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$runKeyShown = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
$textValue = 'ThreatPulseEnfTest'
$dwordValue = 'ThreatPulseEnfTestDword'
$startupFile = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup\ThreatPulseEnfTest.txt'
$deleteFile = Join-Path $work 'dummy_delete.txt'
$counter = 0
$failures = 0

# ---- the Python driver: plan, approve, exec, undo ---------------------------------
# It builds an Alert from a small spec, runs policy.decide, and keeps the Alert and Decision
# in files so that each step is a separate process, with Windows checks in between.

$driverSource = @'
import datetime, json, pathlib, sys
sys.path.insert(0, r"C:\ThreatPulseLab\threatpulse")
from detection import zones
from policy import decide, enable_controlled_folder_access, execute, undo
from policy.actions_windows import Layout

WORK = pathlib.Path(r"C:\ThreatPulseLab\enforcement-test")


def stamp(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def build_alert(spec):
    moment = datetime.datetime.now(datetime.timezone.utc)
    run = moment.strftime("%Y%m%dT%H%M%S")
    number = f"{int(spec['counter']):06d}"
    pid = int(spec.get("pid", 0))
    image = spec.get("image", "unknown")
    subject = {"pid": pid, "image": image if pid else "unknown", "signed": bool(pid and spec.get("signed", False)),
               "signer": spec.get("signer") if pid else None,
               "trusted_path": bool(pid and zones.is_trusted_image(image)), "ancestors": []}
    if pid and spec.get("microsoft_root") is not None:
        subject["microsoft_root"] = spec["microsoft_root"]
    return {
        "alert_id": f"a-{run}-{number}", "ts": stamp(moment), "layer": spec["layer"], "rule_id": spec["rule_id"],
        "technique_ids": spec.get("techniques", ["T1486"]), "risk_score": spec.get("risk"),
        "event_type": spec["event_type"], "subject": subject,
        "object": {"zone": spec["zone"], "path": spec.get("path"), "registry_key": spec.get("key"),
                   "access": [], "file_sha256": spec.get("sha256")},
        "evidence_event_ids": [f"e-{run}-000001"] if pid else [],
    }


def load(decision_id):
    return json.loads((WORK / f"{decision_id}.json").read_text(encoding="utf-8"))


def save(decision_id, data):
    (WORK / f"{decision_id}.json").write_text(json.dumps(data, indent=2), encoding="utf-8")


def show(decision):
    return {"id": decision["decision_id"],
            "actions": [{"action": a["action"], "status": a["status"], "reason": a.get("reason"),
                         "reviewed_by": a.get("reviewed_by")} for a in decision["actions"]],
            "notes": decision["attributes"].get("enforcement_notes", [])}


command = sys.argv[1]
if command == "plan":
    spec = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8-sig"))
    alert = build_alert(spec)
    decision = decide(alert, spec.get("context"))
    save(decision["decision_id"], {"alert": alert, "decision": decision})
    print(json.dumps(show(decision)))
elif command == "approve":
    data = load(sys.argv[2])
    moment = stamp(datetime.datetime.now(datetime.timezone.utc))
    for act in data["decision"]["actions"]:
        if act["status"] == "awaiting_approval":
            act.update(status="approved", reviewed_by=sys.argv[3], reviewed_at=moment)
    save(sys.argv[2], data)
    print(json.dumps(show(data["decision"])))
elif command == "exec":
    data = load(sys.argv[2])
    layout = Layout(sys.argv[3]) if len(sys.argv) > 3 else None
    data["decision"] = execute(data["decision"], data["alert"], layout=layout)
    save(sys.argv[2], data)
    print(json.dumps(show(data["decision"])))
elif command == "undo":
    print(json.dumps(undo(None if sys.argv[2] == "all" else sys.argv[2])))
elif command == "cfa":
    print(json.dumps({"previous": enable_controlled_folder_access()}))
else:
    raise SystemExit(f"unknown command {command}")
'@

# ---- helpers ----------------------------------------------------------------------

function Invoke-Driver {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    $text = & $Python -I $driver @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "driver $($Arguments -join ' ') failed: $($text -join ' ')" }
    return (($text -join "`n") | ConvertFrom-Json)
}

function Plan([hashtable]$Spec) {
    $script:counter++
    $Spec['counter'] = $script:counter
    $specFile = Join-Path $work "spec$($script:counter).json"
    [System.IO.File]::WriteAllText($specFile, ($Spec | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    return Invoke-Driver 'plan' $specFile
}

function Check([string]$Name, [bool]$Passed, [string]$Detail = '') {
    if ($Passed) { Write-Host "PASS  $Name" -ForegroundColor Green }
    else { Write-Host "FAIL  $Name  $Detail" -ForegroundColor Red; $script:failures++ }
}

function Wait-Until([scriptblock]$Condition, [int]$Seconds = 6) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        if (& $Condition) { return $true }
        Start-Sleep -Milliseconds 250
    }
    return [bool](& $Condition)
}

function Test-Suspended([int]$ProcessId) {
    $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if (-not $process) { return $false }
    $threads = @($process.Threads)
    if ($threads.Count -eq 0) { return $false }
    $stopped = @($threads | Where-Object { $_.ThreadState -eq 'Wait' -and $_.WaitReason -eq 'Suspended' })
    return $stopped.Count -eq $threads.Count
}

function Get-Action($Result, [string]$Name) { return @($Result.actions | Where-Object { $_.action -eq $Name })[0] }

function Get-FileSha256([string]$Path) { return (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLower() }

$ping = $null
try {
    New-Item -ItemType Directory -Force $work | Out-Null
    [System.IO.File]::WriteAllText($driver, $driverSource, (New-Object System.Text.UTF8Encoding($false)))
    Copy-Item (Join-Path $env:SystemRoot 'System32\PING.EXE') $pingCopy -Force
    $ping = Start-Process -FilePath $pingCopy -ArgumentList '-n', '900', '127.0.0.1' -WindowStyle Hidden -PassThru
    Start-Sleep -Seconds 1
    $victim = @{ layer = 'rule'; rule_id = 'R-ENFTEST-001'; event_type = 'file_delete'; zone = 'documents'
                 risk = 0.9; pid = $ping.Id; image = $pingCopy; signed = $false }

    # 1. The VM guard. A lab folder with no LAB_VM marker: the action must be skipped.
    $noLab = Join-Path $work 'no-such-lab'
    $plan = Plan $victim
    Check 'plan: a high-risk process in the documents zone gets a pending suspend' ((Get-Action $plan 'suspend').status -eq 'pending')
    $guarded = Invoke-Driver 'exec' $plan.id $noLab
    $suspend = Get-Action $guarded 'suspend'
    Check '1. no marker: suspend is skipped as not in lab VM' (($suspend.status -eq 'skipped') -and ($suspend.reason -like 'not in lab VM*')) $suspend.reason
    Check '1. no marker: the process was not suspended' (-not (Test-Suspended $ping.Id))

    # 2. suspend and resume
    $plan = Plan $victim
    $done = Invoke-Driver 'exec' $plan.id
    Check '2. suspend is executed' ((Get-Action $done 'suspend').status -eq 'executed') (Get-Action $done 'suspend').reason
    Check '2. every thread of the process is Suspended' (Wait-Until { Test-Suspended $ping.Id })
    $rows = @(Invoke-Driver 'undo' $plan.id)
    Check '2. undo resumes it' (($rows.Count -eq 1) -and ($rows[0].result -eq 'undone')) ($rows | ConvertTo-Json -Compress)
    Check '2. the process is running again' (Wait-Until { -not (Test-Suspended $ping.Id) })

    # 3. block_network and its undo
    $network = @{ layer = 'rule'; rule_id = 'R-ENFTEST-002'; event_type = 'network_connect'; zone = 'network'
                  risk = 0.9; pid = $ping.Id; image = $pingCopy; signed = $false }
    $plan = Plan $network
    $done = Invoke-Driver 'exec' $plan.id
    Check '3. block_network is executed' ((Get-Action $done 'block_network').status -eq 'executed') (Get-Action $done 'block_network').reason
    $ruleName = "ThreatPulse-Block-$($plan.id)-0"
    $rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    $program = if ($rule) { (Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule).Program } else { $null }
    Check '3. an outbound block rule exists for exactly that program' `
        ($rule -and ($rule.Direction -eq 'Outbound') -and ($rule.Action -eq 'Block') -and ($program -eq $pingCopy)) "program=$program"
    $rows = @(Invoke-Driver 'undo' $plan.id)
    Check '3. undo removes the rule' (($rows[0].result -eq 'undone') -and -not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue))

    # 4. restore, registry: values that are not in the baseline are quarantined and removed
    New-ItemProperty -Path $runKey -Name $textValue -Value 'C:\Windows\System32\notepad.exe' -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $runKey -Name $dwordValue -Value 7 -PropertyType DWord -Force | Out-Null
    foreach ($name in @($textValue, $dwordValue)) {
        $fim = @{ layer = 'fim'; rule_id = 'R-FIM-PERSISTENCE'; event_type = 'fim_change'; zone = 'persistence'
                  techniques = @('T1547.001'); key = "$runKeyShown\$name"; context = @{ fim = @{ differs_from_baseline = $true; settled_seconds = 3 } } }
        $plan = Plan $fim
        $done = Invoke-Driver 'exec' $plan.id
        Check "4. restore of $name is executed" ((Get-Action $done 'restore').status -eq 'executed') (Get-Action $done 'restore').reason
        Check "4. $name is gone from the Run key" ($null -eq (Get-ItemProperty -Path $runKey -Name $name -ErrorAction SilentlyContinue))
        $manifest = Join-Path 'C:\ThreatPulseLab\fim\quarantine' "$($plan.id)-0\manifest.json"
        Check "4. the quarantine holds the full value and type of $name" (Test-Path $manifest)
        $rows = @(Invoke-Driver 'undo' $plan.id)
        Check "4. undo puts $name back" ($rows[0].result -eq 'undone') ($rows | ConvertTo-Json -Compress)
    }
    Check '4. the text value is back as a String' ((Get-Item $runKey).GetValueKind($textValue) -eq 'String' -and (Get-ItemPropertyValue $runKey $textValue) -eq 'C:\Windows\System32\notepad.exe')
    Check '4. the DWORD value is back as a DWord with the same number' ((Get-Item $runKey).GetValueKind($dwordValue) -eq 'DWord' -and (Get-ItemPropertyValue $runKey $dwordValue) -eq 7)
    Remove-ItemProperty -Path $runKey -Name $textValue, $dwordValue -ErrorAction SilentlyContinue

    # 5. restore, file: a new file in the startup folder
    Set-Content -Path $startupFile -Value 'ThreatPulse enforcement test'
    $fimFile = @{ layer = 'fim'; rule_id = 'R-FIM-PERSISTENCE'; event_type = 'fim_change'; zone = 'persistence'
                  techniques = @('T1547.001'); path = $startupFile; context = @{ fim = @{ differs_from_baseline = $true; settled_seconds = 3 } } }
    $plan = Plan $fimFile
    $done = Invoke-Driver 'exec' $plan.id
    Check '5. restore of the startup file is executed' ((Get-Action $done 'restore').status -eq 'executed') (Get-Action $done 'restore').reason
    Check '5. the file is gone from the startup folder' (-not (Test-Path $startupFile))
    Check '5. the quarantine holds a copy' (Test-Path (Join-Path 'C:\ThreatPulseLab\fim\quarantine' "$($plan.id)-0\data.bin"))
    $rows = @(Invoke-Driver 'undo' $plan.id)
    Check '5. undo puts the file back' (($rows[0].result -eq 'undone') -and (Test-Path $startupFile))
    Remove-Item $startupFile -Force -ErrorAction SilentlyContinue

    # 6. request_delete: only after approval, and a move into quarantine
    Set-Content -Path $deleteFile -Value 'THREATPULSE-TEST-MARKER enforcement delete test'
    $hash = Get-FileSha256 $deleteFile
    $signature = @{ layer = 'signature'; rule_id = 'SIG-ENFTEST'; event_type = 'file_scan'; zone = 'none'
                    path = $deleteFile; sha256 = $hash; techniques = @() }
    $plan = Plan $signature
    Check '6. a signature match plans a delete that awaits approval' ((Get-Action $plan 'request_delete').status -eq 'awaiting_approval')
    $waiting = Invoke-Driver 'exec' $plan.id
    Check '6. before approval nothing is deleted' (((Get-Action $waiting 'request_delete').status -eq 'awaiting_approval') -and (Test-Path $deleteFile))
    Invoke-Driver 'approve' $plan.id 'vm-test' | Out-Null
    $done = Invoke-Driver 'exec' $plan.id
    $delete = Get-Action $done 'request_delete'
    Check '6. after approval the delete is executed, with the reviewer kept' (($delete.status -eq 'executed') -and ($delete.reviewed_by -eq 'vm-test')) $delete.reason
    Check '6. the file left its folder and sits in quarantine' ((-not (Test-Path $deleteFile)) -and (Test-Path (Join-Path 'C:\ThreatPulseLab\fim\quarantine' "$($plan.id)-0\data.bin")))
    $rows = @(Invoke-Driver 'undo' $plan.id)
    Check '6. undo moves it back, unchanged' (($rows[0].result -eq 'undone') -and (Test-Path $deleteFile) -and ((Get-FileSha256 $deleteFile) -eq $hash))

    # 7. request_kill: the suspend runs, the kill waits, then runs after approval
    $kill = $victim.Clone(); $kill['risk'] = 0.97; $kill['context'] = @{ suspended_pids = @($ping.Id) }
    $plan = Plan $kill
    Check '7. the plan holds a suspend and a kill request' (((Get-Action $plan 'suspend').status -eq 'pending') -and ((Get-Action $plan 'request_kill').status -eq 'awaiting_approval'))
    $first = Invoke-Driver 'exec' $plan.id
    Check '7. before approval the process is suspended and not killed' (((Get-Action $first 'request_kill').status -eq 'awaiting_approval') -and (Wait-Until { Test-Suspended $ping.Id }))
    Invoke-Driver 'approve' $plan.id 'vm-test' | Out-Null
    $second = Invoke-Driver 'exec' $plan.id
    Check '7. after approval the kill is executed' ((Get-Action $second 'request_kill').status -eq 'executed') (Get-Action $second 'request_kill').reason
    Check '7. the process is gone' (Wait-Until { -not (Get-Process -Id $ping.Id -ErrorAction SilentlyContinue) })
    $rows = @(Invoke-Driver 'undo' $plan.id)
    $killRow = @($rows | Where-Object { $_.action -eq 'request_kill' })[0]
    Check '7. undo says a kill cannot be undone' (($killRow.result -eq 'skipped') -and ($killRow.detail -like "*can't be undone*")) ($rows | ConvertTo-Json -Compress)

    # 8. never-suspend: an Alert that wrongly says explorer is not Microsoft's
    if (-not $SkipNeverSuspend) {
        $explorer = Get-Process -Name explorer -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($explorer) {
            $stale = @{ layer = 'rule'; rule_id = 'R-ENFTEST-003'; event_type = 'file_delete'; zone = 'documents'
                        risk = 0.9; pid = $explorer.Id; image = 'C:\Windows\explorer.exe'; signed = $true
                        signer = 'Microsoft Windows'; microsoft_root = $false }
            $plan = Plan $stale
            Check '8. the stale Alert makes the engine plan a suspend (the live check must catch it)' ((Get-Action $plan 'suspend').status -eq 'pending')
            $done = Invoke-Driver 'exec' $plan.id
            $suspend = Get-Action $done 'suspend'
            Check '8. explorer.exe is refused by the live never-suspend check' (($suspend.status -eq 'skipped') -and ($suspend.reason -like '*never-suspend*')) $suspend.reason
            Check '8. explorer.exe is not suspended' (-not (Test-Suspended $explorer.Id))
        } else {
            Write-Warning 'explorer.exe is not running, so check 8 was skipped.'
        }
    }

    # 9. Controlled Folder Access, only when asked
    if ($TestCfa) {
        $before = (Get-MpPreference).EnableControlledFolderAccess
        $result = Invoke-Driver 'cfa'
        Check '9. Controlled Folder Access is enabled' ((Get-MpPreference).EnableControlledFolderAccess -eq 1)
        $rows = @(Invoke-Driver 'undo' 'setup')
        Check '9. undo puts the previous mode back' (($rows[0].result -eq 'undone') -and ((Get-MpPreference).EnableControlledFolderAccess -eq $before)) "was $before, previous=$($result.previous)"
    }
}
finally {
    if ($ping) { Stop-Process -Id $ping.Id -Force -ErrorAction SilentlyContinue }
    Remove-ItemProperty -Path $runKey -Name $textValue, $dwordValue -ErrorAction SilentlyContinue
    Remove-Item $startupFile, $deleteFile -Force -ErrorAction SilentlyContinue
    if ($ruleName) { Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue }
}

Write-Host ''
if ($failures -eq 0) { Write-Host 'All checks passed.' -ForegroundColor Green; exit 0 }
Write-Host "$failures check(s) failed." -ForegroundColor Red
exit 1
