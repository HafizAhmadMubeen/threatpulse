# ThreatPulse agent

The Sense part of Track A, covering PHASES.md steps 1.1 to 1.4 and 2.1. It's a user-mode C++ program that collects process, file, registry and network activity through ETW, reads Sysmon events from the Windows Event Log, and writes [Event records](../PLANNING.md#51-event-agent--pipeline-one-json-object-per-line-in-eventsjsonl) to a JSONL file. This is the telemetry behind the 3rd-generation behaviour layer and the 4th-generation ML triage.

**The agent only observes.** It changes no system setting, and the only ETW session it ever stops is its own, `ThreatPulse-Agent`.

File Integrity Monitoring for the persistence zone is a separate Python program in the same track. See [fim/README.md](fim/README.md).

**Build and run it only in the lab VM**, never on a developer laptop or from WSL. It refuses to start unless `C:\ThreatPulseLab\LAB_VM` exists and it has administrator rights.

## Build

You need Git, Python 3.12, and Visual Studio Build Tools with "Desktop development with C++", including its CMake tools. Running it also needs Sysmon, installed as in `docs/lab-setup.md`. The VM needs network access (NAT) for the first configure, because CMake downloads krabsetw and nlohmann/json.

In **Developer PowerShell for VS**:

```powershell
git clone https://github.com/HafizAhmadMubeen/threatpulse.git C:\ThreatPulseLab\threatpulse
cd C:\ThreatPulseLab\threatpulse
git switch track-a/agent
cmake -S agent -B agent\build -A x64
cmake --build agent\build --config Release
```

Always build **Release**. In a Debug build, krabsetw's strict type checks can reject valid events.

The result is `agent\build\Release\threatpulse_agent.exe`, with `filters.json` copied next to it.

## Run and stop

In a PowerShell window opened with **Run as administrator**:

```powershell
cd C:\ThreatPulseLab\threatpulse
.\agent\build\Release\threatpulse_agent.exe
```

| Option | Default |
|---|---|
| `--out <file>` | `C:\ThreatPulseLab\logs\events.jsonl` |
| `--config <file>` | `filters.json` next to the program |
| `--no-close-events` | Off. Fallback: use it if Close events cause ETW losses. See "How file paths are resolved" |
| `--rundown` | Off. Untested experiment: asks ETW to report files and keys that are already open. If Windows refuses, the agent stops with an error |
| `--no-sysmon` | Off. Runs without Sysmon, so there are no LSASS signals and no Sysmon registry events. Without this option, a missing Sysmon stops the agent, so a recording can't silently lack zone signals |
| `--check-image <file>` | Off. Prints the signature, Microsoft root and process filter result for one file, then exits without starting ETW |

**To stop it, press Ctrl+C.** The agent stops the session, writes out everything queued and prints a summary. If `--out` already exists, the old file is renamed with a timestamp, so runs never overwrite each other.

If a run crashes, the next start clears the leftover session. To clear it by hand:

```powershell
logman stop "ThreatPulse-Agent" -ets
```

| Exit code | Meaning |
|---|---|
| 0 | Clean stop |
| 1 | Bad arguments |
| 2 | Not the lab VM (`LAB_VM` marker missing) |
| 3 | Not running as administrator |
| 4 | Startup failed (filter file, output file, ETW setup or Sysmon) |
| 5 | The ETW session failed while running |

## Checks

**Setup, once per PowerShell window:**

```powershell
$log = 'C:\ThreatPulseLab\logs\events.jsonl'
function Show-Events($Type, $Like) {
    Select-String -Path $log -SimpleMatch "`"event_type`":`"$Type`"" |
        Where-Object { $_.Line -like "*$Like*" } |
        ForEach-Object { $_.Line | ConvertFrom-Json } |
        Select-Object ts, pid, ppid,
            @{n='image';e={$_.process.image}},
            @{n='cmdline';e={$_.process.cmdline}},
            @{n='user';e={$_.process.user}},
            @{n='signed';e={$_.process.signed}},
            @{n='signer';e={$_.process.signer}},
            @{n='sha256';e={$_.process.sha256}},
            @{n='path';e={$_.target.path}},
            @{n='old_path';e={$_.target.old_path}},
            @{n='registry_key';e={$_.target.registry_key}} |
        Format-List
}
```

**Start the agent, then run this test activity in a second window:**

```powershell
# Process start and stop
Start-Process notepad
Start-Sleep 3
Stop-Process -Name Notepad -ErrorAction SilentlyContinue
Start-Process cmd -ArgumentList '/c timeout /t 3' -Wait

# Run key: harmless, and removed straight away
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v ThreatPulseTest /t REG_SZ /d C:\Windows\System32\notepad.exe /f
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v ThreatPulseTest /f

# File create, write, rename and delete
New-Item -ItemType Directory -Force C:\ThreatPulseLab\agent-test
Set-Content C:\ThreatPulseLab\agent-test\a.txt 'ThreatPulse agent test'
Rename-Item C:\ThreatPulseLab\agent-test\a.txt b.txt
Remove-Item -Recurse C:\ThreatPulseLab\agent-test
```

**Stop the agent with Ctrl+C, then check the output:**

| Step | Command | Pass if |
|---|---|---|
| 1.1, 1.2 | `Show-Events process_start notepad` | A `process_start` appears, with pid, ppid and image filled in |
| 1.1 | `Show-Events process_stop notepad` | A matching `process_stop` appears |
| 1.3 | `Show-Events registry_set ThreatPulseTest` | `registry_key` is `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\ThreatPulseTest` |
| 1.3 | `Show-Events file_create agent-test` | `path` is `...\agent-test\a.txt` |
| 1.3 | `Show-Events file_write agent-test` | `path` is `...\agent-test\a.txt` |
| 1.3 | `Show-Events file_rename agent-test` | `path` ends in `b.txt` and `old_path` in `a.txt` |
| 1.3 | `Show-Events file_delete agent-test` | `path` ends in `b.txt`. The `agent-test` folder itself is not listed |
| 1.3 | `Select-String -Path $log -Pattern '"image":"[^"]*threatpulse_agent'` | No results: the agent's own events are dropped. Its name can still appear as a target, when Sysmon reports another process opening it |
| 1.4 | `Show-Events process_start 'System32\\cmd'` | `signed: True`, `signer: Microsoft Windows`, 64-character `sha256` |
| 1.4 | `Show-Events process_start notepad` | `signed: True`. See the note below |
| 1.2 | Validate the file (below) | `0 invalid` |

**Notepad:** on Windows 11, `notepad` redirects to the Store app under `C:\Program Files\WindowsApps\`, so the `image` differs from the path in `cmdline`. The first VM run showed that image with `signed: True` and `signer: Microsoft Corporation`.

**Path coverage, `file_delete`, network and Sysmon:** `tools/vm_test_activity.ps1` repeats the T1486 pattern on dummy files in `Documents\ThreatPulseTest`: it writes scrambled copies, deletes the originals, renames, and uses delete-on-close. It then adds and removes Run and RunOnce values, requests `https://example.com` (this needs NAT on), and opens a handle to its own dummy `ping` process with mask `0x21410`. That handle includes `vm_read`, but nothing is read from it, and the script never touches LSASS. It removes everything it creates. Run it in a new PowerShell process started after the agent, then check the result:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File agent\tools\vm_test_activity.ps1
# Wait 30 seconds, because Sysmon can report connections late. Stop the agent with Ctrl+C, then:
agent\.venv\Scripts\python agent\tools\check_test_run.py C:\ThreatPulseLab\logs\events.jsonl C:\ThreatPulseLab\logs\test_pid.txt
```

`-ExecutionPolicy Bypass` applies to that one process and changes no setting.

**Pass criteria:**

| Criterion | Where to see it |
|---|---|
| Every write by the test process has a path | `check_test_run.py` |
| Writes under the Documents test folder have paths | `check_test_run.py`. A write with no path can't be placed in a folder, so this relies on the row above |
| No wrong paths | `check_test_run.py` covers writes after a rename. A wrong path looks like a right one, so this also rests on the design below |
| At least 95% of file writes have a path, for all processes started after the agent | `File writes with a path`, `Started after agent` in the shutdown summary |
| No event loss | `Lost by ETW`, `Lost, queue full` and `Sysmon read errors` stay at 0 |
| Sysmon reports the Run and RunOnce writes, and the Run value's removal as `registry_delete` | `check_test_run.py` |
| ETW and Sysmon both report the web request, with the same destination IP | `check_test_run.py`. A byte-order mistake in the ETW fields would fail this or the port 443 check |
| The dummy process access is decoded with `vm_read` | `check_test_run.py`. LSASS itself is an accepted limitation, in PLANNING.md 4.3 |

To see which programs caused any gaps, run `agent\.venv\Scripts\python agent\tools\coverage_report.py <events.jsonl>`.

**Clean stop after a crash:**

```powershell
# With the agent running, from a second administrator window:
Stop-Process -Name threatpulse_agent -Force
logman query "ThreatPulse-Agent" -ets    # the session is still running

# Start the agent: it prints "Stopped a leftover ThreatPulse-Agent session."
# Press Ctrl+C, then:
logman query "ThreatPulse-Agent" -ets    # the session is gone (an error is expected here)
```

## Validate the output

The validator checks every line against `contracts/schemas/event.schema.json`, and checks that `event_id` values are unique.

The VM has no `uv`, so it uses pip with the pinned, hash-checked requirements:

```powershell
cd C:\ThreatPulseLab\threatpulse
python -m venv agent\.venv
agent\.venv\Scripts\python -m pip install --require-hashes -r agent\tools\requirements.txt
agent\.venv\Scripts\python agent\tools\validate_events.py C:\ThreatPulseLab\logs\events.jsonl
```

In WSL, use `cd agent && uv sync`, then `uv run python tools/validate_events.py <file>`.

## Record a session

These scripts run in the VM, in a 64-bit PowerShell opened as administrator. A person starts every recording.

| Script | Job |
|---|---|
| `tools/start_lab_sensors.ps1` | Starts the agent and FIM together, and stops both cleanly. Used for every recording and demo |
| `tools/run_batch.ps1` | Runs one batch from `tools/batch_plan.json` in its fixed order, and pauses before each manual benign session |
| `tools/record_session.ps1` | Records one session, and writes `session.json` |
| `tools/vm_t1486_script.ps1` | Our harmless T1486 test, on dummy files only |
| `tools/vm_benign_admin.ps1`, `tools/vm_benign_zip.ps1` | Scripted benign activities |
| `tools/make_batch_plan.py` | Generated `batch_plan.json`, from a recorded seed |
| `tools/label_session.py` | Writes `labels.csv`, with a `part` column, for one session or a whole batch |
| `config/recording_tests.json` | The only tests that may be recorded, with their runs and network mode |

Each session gets its own folder under `C:\ThreatPulseLab\logs\sessions\`, holding `events.jsonl`, `fim.jsonl`, `session.json` and both sensors' summaries.

`record_session.ps1` refuses a test that isn't on the list, an Atomic install that isn't the pinned commit, and a `-Network` value that doesn't match what the VM can reach. Cleanup runs as a separate process after the end time. Its tree is labelled `harness`, because the cleanup of the T1486 script deletes the same 25 files the test just encrypted and looks exactly like the attack.

After the sensors start, each session waits 10 seconds to settle and then 60 seconds to warm up (`-WarmupSeconds`), and records `warmup_seconds` and, from batch 3, `warmup_end_utc` in `session.json`. **Track B computes features from `start_utc`, the test start, so what happens during the warm-up, such as the `WmiApSrv.exe` bursts below, is not counted.** The sessions per batch come from `tools/batch_plan.json`, and `run_batch.ps1` prints the count. Only a benign activity that isn't scripted pauses for a person: batch 2 had 9 sessions and no pause. It then has to pass a clean-start check: if FIM reports a change from the baseline by then, the recording stops. If a harmless rewrite such as Edge's Run value trips it, run the batch again from that session with `-FromOrder`. The check only covers the persistence zone, not Defender's state or scheduled tasks, which is why T1685 gets a batch of its own.

`pool` in `session.json` says which group of techniques a session belongs to. It isn't the train/test split, which is made later by session.

From batch 2, `session.json` has no byte order mark. Batch 1's files have one and no `warmup_seconds`, so read them with `encoding="utf-8-sig"`, which works for both, and treat a missing `warmup_seconds` as 0. `warmup_end_utc` and `cleanup_root_pid` are in the files from batch 3 on, and are missing from batches 1 and 2. `agent_commit` is the repository commit on the VM, not the build of the agent: all 11 batches use the one binary built before `process.microsoft_root` was added, and the VM only pulls script changes until Phase 4.

**Labels and parts.** `label_session.py` writes one row per event: `event_id`, `label`, `part`, `technique`, `pool`, `session_id`, `network` and `warmup_seconds`.

| `part` | Which events |
|---|---|
| `test` | The test's own processes. For an Atomic test, the process the `Invoke-AtomicTest` wrapper starts to run it, and everything below it. For our T1486 script, the whole tree |
| `harness` | The wrapper itself (the root PowerShell and the `hostname`, `whoami` and `conhost` it starts) and the whole cleanup tree: the `-Cleanup` process that `record_session.ps1` starts after the test, for every test, and everything below it |
| `background` | Everything else, including every event in a benign session |

`label` is still the tree label, so the wrapper's and the cleanup's events are `malicious` there. **Track B must compute all features, including tree shape, from the `test` part only, and leave the `harness` part out of training and evaluation.** Every Atomic session runs the wrapper and no benign session does, so a model that sees it learns the wrapper instead of behaviour, and held-out results would look better than they are.

To label exported data without touching it:

```bash
cd agent && uv run python tools/label_session.py --batch <exported batch folder> --out <new folder>
```

`--out` never overwrites a `labels.csv`, and `--batch` needs it. The current label folders are `batch-01-labels-v3` and `batch-02-labels-v2`; the earlier ones (`-v2`, `batch-02-labels`) left the cleanup as `background` and are superseded. The cleanup tree is found by `cleanup_root_pid` when `session.json` has it, and otherwise as the PowerShell that starts after `end_utc` with the same parent as the test's root and `-Cleanup` in its command line. The test part of T1003.001 is only about 2 events. The split depends on the processes the wrapper starts, so check it again if Atomic Red Team or the wrapper is updated.

**Installers for the `install-uninstall` sessions.** They sit in `C:\ThreatPulseLab\installers` inside the `atomic-ready-3` snapshot, downloaded with NAT on from the publishers' own sites. The hashes are what the VM computed with `Get-FileHash`. They haven't been compared with a publisher's checksum.

| File | SHA-256 |
|---|---|
| `7z2605-x64.exe` | `FD99E86F57D8F429EF5ED045BF98315AF962E2309B0F1BA87A147A44C71647D0` |
| `putty-64bit-0.85-installer.msi` | `2213EBACF962B709411D654A40087508A694756BC4E41C5A1C24AD86596B2511` |

## How it works

```
ETW session "ThreatPulse-Agent"
   | Kernel-Process, Kernel-File, Kernel-Registry, Kernel-Network
   v
ETW thread:    parse -> process table + name maps -> filters -> bounded queue
                                                                 ^     |
Sysmon thread: EvtSubscribe -> map IDs 3, 10, 12, 13 ------------+     |
                                                                       v
Writer thread: SHA-256 + signature (per-image cache) -> JSON -> events.jsonl
```

| Design choice | Why |
|---|---|
| Two threads with a queue | ETW drops events if its callback is slow, so hashing and disk writes stay out of it |
| A process table | File and registry events carry only a pid, so image, ppid and user come from the table |
| Name maps | Write events have a `FileKey` and registry writes a `KeyObject`, not usable paths. Earlier events supply the names |
| Event 30, not event 12, for `file_create` | Event 12 fires on every file open, not only for new files. It only feeds the name map |
| Event 26 for `file_delete` | It has the path and its own keyword. See below |
| `events.jsonl` opened after the session is live | Otherwise the session never sees the open, and System's flushes of the log get no path and can't be filtered |
| Catalog fallback for signatures | Many Windows binaries have no signature inside the file. Without this they would look unsigned |
| Revocation checks off | The VM is often offline during recordings, and a network timeout must not stall the agent |
| Timestamps from the ETW header | They show when the event happened, not when the agent processed it |
| Process events are never filtered | Labelling depends on complete process trees (PHASES.md step 2.4) |
| Process filters need path AND a Microsoft signature | A path alone can be imitated. Same principle as the never-suspend list |
| krabsetw included from one file only | Its headers define `INITGUID`, which risks duplicate-symbol link errors across files |
| Sysmon on its own thread | A slow event log must never delay the ETW callback |
| Sysmon and network events skip the noise filters | The Sysmon config already filters, and a dropped event here could be a missed zone signal |

**ETW events used:**

| Provider | Keywords | Event IDs |
|---|---|---|
| Microsoft-Windows-Kernel-Process | `0x10` | 1 start, 2 stop |
| Microsoft-Windows-Kernel-File | `0x1EB0`, or `0x1E90` with `--no-close-events` | 10, 11 names; 12 open; 14 close; 16 write; 26 delete; 27 rename; 30 new file |
| Microsoft-Windows-Kernel-Registry | `0xB101` | 1, 2 create and open; 4 query; 5 set value; 13 close |
| Microsoft-Windows-Kernel-Network | `0x30` | 12 TCP connect over IPv4; 28 TCP connect over IPv6 |

Kernel-Network's keywords also turn on every send and receive, so an event-ID filter keeps only the two connect events. Its `PID` field is used rather than the event header, which can name a different process. `daddr` and `dport` are read as network byte order, and the VM test checks this.

### How file paths are resolved

The priority is **never a wrong path, then coverage**. A null path is an honest gap, while a wrong path could put an event in the wrong protected zone.

| Step | Source | Rule |
|---|---|---|
| 1 | `FileKey` -> name, from NameCreate | Used for any process |
| 2 | `FileObject` -> name, from event 12 | Used only by the process that opened it, because pointers get reused and System's stream file objects never appear in an open event |
| 3 | `FileKey` -> name, bound on a step 2 match | Lets System's later flushes of the file resolve. Removed when that `FileObject` closes |

Close (event 14) clears old entries. It needs the broad FILEIO keyword, so an event-ID filter removes reads and other operations in the kernel. `--no-close-events` turns off Close, the filter and step 3, and also turns off delete-on-close detection.

A child process writing through a handle its parent opened gets a null path. A script's redirected output is an example.

### Why event 26 for `file_delete`

| Event | Path in the event | Keyword | Verdict |
|---|---|---|---|
| 26 DeletePath | Yes, `FilePath` | Its own, `0x400` | **Used** |
| 18 SetDelete | No | FILEIO only | Same operation, but needs another name lookup |
| 11 NameDelete | Yes | FILENAME | Not a deletion: it means a name left the tracking table |

| Limit | Effect |
|---|---|
| Event 26 comes before the file system's result | `file_delete` means deletion was requested, so a denied delete is still reported |
| FILE_DELETE_ON_CLOSE produces no event 26 | Caught instead from the event 12 flag and the Close event, and credited to the process that opened the file |
| Event 26 also fires for folders | Folders are skipped, using the event 12 flag. A folder opened before the agent started is still reported |

## Sysmon events

| Sysmon ID | Event | Fields |
|---|---|---|
| 3 NetworkConnect | `network_connect` | `dest_ip`, `dest_port`. Only `Initiated=true`: inbound connections are skipped and counted |
| 10 ProcessAccess | `process_access` | `pid` and `process` are the source, `target.pid` and `target.path` the target. `access_mask` is the raw hex and `access_rights` the decoded names |
| 12 RegistryEvent | `registry_delete` | Full key. `CreateKey` is skipped and counted: it writes no value, and `sysmon-modular` excludes it |
| 13 RegistryEvent | `registry_set` | Full key and value |

**Process details:** Sysmon events name the image and user, but have no parent or command line, so those come from the process table. They are used only if the table's image matches Sysmon's, so a reused pid can't give an event another process's details. ETW start events arrive late, so a miss is retried for 2 seconds. After that the event keeps Sysmon's image and user, with `ppid` 0 and `cmdline` null, and adds to `Sysmon, no process info`.

**Registry keys:** `HKU\<sid>\...` becomes `HKCU\...` when the key belongs to the user who wrote it, the same rule as ETW. Sysmon also writes `HKCR` for `HKLM\Classes`, and `CurrentControlSet` where ETW shows `ControlSet001`, so the two sources can differ for those keys.

**How ETW and Sysmon are used together (PLANNING.md Section 10):**

| Use | Source |
|---|---|
| ML counts and rates | `source: etw` only, so one action is never counted twice |
| Zone signals, which may be ML features | Sysmon: LSASS access (ID 10), network (ID 3), registry writer and full key (IDs 12 and 13) |
| Detection rules | Either source |

**What `sysmon-modular` covers.** This was checked by testing sample events against the rules of release `configs-a45dedb13a43`, not against Sysmon itself. In the VM, the installed `sysmonconfig.xml` has the same Run and `0x21410` rules, and the third run produced events for HKCU Run, HKCU RunOnce and `0x21410`. The HKLM rows are not yet tested in the VM. Piping `Sysmon64.exe -c` into `Select-String` finds nothing there, so search the XML file instead.

| Area | Result |
|---|---|
| Run, RunOnce, RunOnceEx, under HKCU and HKLM, including WOW6432Node | Logged, through `TargetObject contains \CurrentVersion\Run` |
| Run key writes by `System`, `backgroundTaskHost.exe` or anything under `C:\$WINDOWS.~BT\` | Not logged, because exclusions win. The config also excludes vendor tools by path. FIM still catches the change |
| Network | Only selected programs and ports. `powershell.exe`, `cmd.exe`, `rundll32.exe` and anything under `C:\Users` are logged. `curl.exe` and programs in `Program Files` on port 443 are not, which is one reason ETW's Kernel-Network is added |
| LSASS access | `0x1010`, `0x1F1FFF`, `0x1FFFFF` and `0x143A` are logged. `0x1000` and `0x1400` are excluded. `0x1410` is logged only with an `UNKNOWN` call trace. See the risk in PLANNING.md Section 9. These rules gave no LSASS event in the VM, where LSA protection is on: see "What the VM has shown" |

## Event field notes

| Field | Behaviour |
|---|---|
| File order | **`events.jsonl` is not strictly time-ordered**, because ETW and Sysmon arrive on separate threads and can be seconds apart. Consumers must sort by `ts` |
| `ts` | UTC. ETW events use the event header, and Sysmon events use its `UtcTime`, which is when the action happened |
| `event_id` | `e-<run start UTC>-<counter>`, for example `e-20261105T101500-000123`. The counter has at least 6 digits and grows past that on long runs |
| `ppid` | 0 when the parent is unknown |
| `process.image` | Full path when known, otherwise `System` or `unknown` |
| `process.cmdline` | Null when the process exited before it could be read. ETW delivers events up to about a second late, so this is common for short-lived processes such as `reg.exe` |
| `process.user`, `process.sha256`, `process.signer` | Null when they could not be read |
| `process.signed` | True only for a verified signature. A failed check is false, so false does not prove a file is unsigned |
| `process.microsoft_root` | Optional. The agent writes it on every event: true only when the signature verified and the certificate chain ends at a Microsoft root, otherwise false. Events recorded before this field existed, and `fim_change` events, don't have it. The agent's output validates only once Lane 2's schema change that allows the field is on the branch, because the schema forbids unknown fields |
| `target.path` | Null when the name could not be proved, usually because the file was opened before the agent started. For `file_rename`, this is the new path. For `file_delete`, this is the deleted file |
| `target.old_path` | Set only for `file_rename` |
| `target.pid`, `target.access_mask`, `target.access_rights` | Set only for `process_access`. For example, `0x21410` decodes to `vm_read`, `query_information`, `query_limited_information` and `read_control`. A bit with no name appears as `unknown_0x...` |
| `target.dest_ip`, `target.dest_port` | Set only for `network_connect` |
| `target.registry_key` | `key\value`, with `(Default)` for an unnamed value. Starts with `HKLM`, `HKCU`, `HKU\<sid>` or `<unresolved>`. After `<unresolved>` comes any known tail of the path, which is never a full key. `KeyName` is empty on SetValueKey events, so this happens when the agent never saw the key being opened |
| `file_write` from `System` or `Registry` | Flushes of cached data, not the application's own write. Count per process and ignore these for write rates |

## Noise filters

`config/filters.json` holds three prefix lists, matched case-insensitively. They apply only to ETW file and registry events:

| List | Drops |
|---|---|
| `ignore_path_prefixes` | File events under these paths |
| `ignore_process_prefixes` | File and registry events from these images, but only if the image also has a verified Microsoft signature. Use full paths, never bare names, because malware can be named `svchost.exe` |
| `ignore_registry_prefixes` | Registry events under these keys |

**Process filters need path AND signature**, the same principle as the never-suspend list. An event is dropped only if all of these are true:

1. The image path matches `ignore_process_prefixes`.
2. WinVerifyTrust verified the image's signature, from the enrichment cache.
3. The signer's certificate chain ends at a Microsoft root.

If the signature check fails or the result is unknown, the event is kept. So a file placed at a filtered path, a tampered Defender binary or an unreadable image all stay visible. Process start and stop events are never filtered.

The third check tests the chain's root key rather than the `signer` name, because any publisher with a trusted certificate could put "Microsoft" in a display name. This check runs on the writer thread, because signatures aren't known on the ETW thread.

The `\Device\...` path entries remove pipes, the console and similar devices, which are not files on disk. They are also left out of the coverage figures.

Keep filters narrow. A filter that covers a protected zone, such as documents or Run keys, blinds the agent there. There is deliberately no filter for `HKLM\SOFTWARE\Microsoft\Windows Defender\`: tampering with that key is part of held-out technique T1685, and Defender's own writes are already covered by the process filter.

After editing `config/filters.json`, rebuild to copy it next to the program, or pass it with `--config`. Use the same filters for every recording in a dataset.

## What the VM has shown

Results of the second VM run, with default options and `tools/vm_test_activity.ps1`:

| Check | Result |
|---|---|
| `validate_events.py` | 4197 events, 0 invalid |
| `check_test_run.py` | 10 of 10 checks passed |
| Writes by the test process with a path | 100% (127 of 127) |
| `Lost by ETW`, `Lost, queue full`, `Handler errors` | 0, 0, 0 |
| File writes with a path, `Started after agent` | 97.9% (137 of 140) |
| File writes with a path, `Started before agent` | 5.1% (119 of 2331) |
| Registry writes with a full key, `Started after agent` | 87.1% (27 of 31) |
| Registry writes with a full key, `Started before agent` | 58.7% (935 of 1594) |

**Path coverage targets (PLANNING.md Section 10):** 100% for the test or attack process and the documents zone, met at 127 of 127, and at least 95% for all processes started after the agent, met at 97.9%. The remaining 3 writes are accepted.

These results predate the Sysmon and network work, so they cover steps 1.1 to 1.4 only.

Results of the third VM run, the first with step 2.1:

| Check | Result |
|---|---|
| `validate_events.py` | 6651 events, 0 invalid |
| `check_test_run.py` | 17 of 17 checks passed |
| Writes by the test process with a path | 100% (132 of 132) |
| `Lost by ETW`, `Lost, queue full`, `Handler errors` | 0, 0, 0 |
| File writes with a path, `Started after agent` | **93.9% (663 of 706), below the 95% target** |
| Registry writes with a full key, `Started after agent` | 96.0% |
| `Sysmon read errors` | **783, about one per poll** |

The cause was most likely that the reader treated an empty subscription's answer, `ERROR_INVALID_OPERATION`, as a failure. It then replaced its subscription each time, so events could be lost in the gap. Don't use this run's Sysmon counts as a measure of what Sysmon logged.

Results of the fourth VM run, with the reader fixed:

| Check | Result |
|---|---|
| `validate_events.py` | 2547 events, 0 invalid |
| `check_test_run.py` | 17 of 17 checks passed |
| Writes by the test process with a path | 100% (132 of 132) |
| `Lost by ETW`, `Lost, queue full`, `Handler errors` | 0, 0, 0 |
| `Sysmon read errors` | 0 |
| `Sysmon events read` against a `Get-WinEvent` count for the same period | 35 and 35 |
| File writes with a path, `Started after agent` | 96.6% (308 of 319), above the 95% target |
| Registry writes with a full key, `Started after agent` | 92.6% (113 of 122). There is no target for this |

**Step 2.1 is verified, except for LSASS.** The `process_access` path works on a dummy process. LSASS itself is an accepted limitation: see below. For the HKLM Run and RunOnce keys, only FIM's handling has been tested in the VM: nothing has checked Sysmon's events for them.

File coverage depends on what Windows is doing during a run. The third run's gaps came from Windows Update (`MpSigStub`, `wuaucltcore`), svchost services and OneDrive, not from the test, so no resolver change is needed. In the fourth run the gaps were svchost (8) and OneDrive (3). Its registry gaps were PowerShell (5), conhost (2) and ping (1).

**Step 2.2 (FIM) is verified.** `check_fim_run.py` passed 12 of 12 checks, and FIM found the change 0.0 seconds after Sysmon. With `--poll-only`, the 60-second compare reported the 2 changes with no notifications, and `check_fim_run.py` passed 2 of 2 checks. See [fim/README.md](fim/README.md).

Settled in the VM:

| Question | Answer | Run |
|---|---|---|
| Is rename `FilePath` the new or the old name? | The new name | First |
| Are cached writes attributed to the real process? | Yes. System also gets a separate write when it flushes the data | First |
| Does ETW attach a SID to these kernel events? | Very likely: `reg.exe` had a `user` but no `cmdline` | First |
| Is `KeyName` usable on SetValueKey? | No. It was empty in the 15 unresolved samples checked | First |
| Do the test script's writes resolve, also after a rename? | Yes. All 127 have a path, and writes after the rename use the new name | Second |
| Does `file_delete` work? | Yes. All 25 originals and the delete-on-close file were reported, and the folder itself was not | Second |
| Does the Close event-ID filter work at this load? | Yes. Windows accepted it, delete-on-close detection worked and no events were lost, so `--no-close-events` wasn't needed | Second |
| Are `daddr` and `dport` in network byte order? | Yes. ETW and Sysmon gave the same IP, on port 443 | Third |
| Does Windows accept the Kernel-Network event-ID filter? | Yes, with no events lost at this load | Third |
| Does the agent decode the access mask, and see Sysmon deletions? | Yes. `0x21410` gave `vm_read`, and removing the Run value gave `registry_delete` | Third |
| Does the Sysmon reader see everything? | Yes. 0 errors, and it read the 35 events Sysmon logged in the same period | Fourth |
| Which programs keep file coverage down? | Background Windows activity, not the test. See the fourth run above | Fourth |
| Is `cmd.exe` signed, with a hash? | Yes. Signed by `Microsoft Windows`, with a SHA-256 | Fifth |
| Are the agent's own events dropped? | Yes. No event had the agent as its process | Fifth |
| Does the agent recover from a crash? | Yes. After `Stop-Process -Force` the session was still `Running`, the next start printed `Stopped a leftover ThreatPulse-Agent session.`, and after Ctrl+C `logman` gave `Data Collector Set was not found.` | Fifth |
| Does the Microsoft root check recognise Defender and Sysmon? | Yes. `--check-image` gave `Verified signature: yes`, `Microsoft root: yes` and `Process filter drops it: yes` for `MsMpEng.exe` (Platform 4.18.26100.4-0) and `Sysmon64.exe`. No file or registry event from them got through, and 8 other events showed they were active | Fifth |

**LSASS result, from Atomic T1003.001 test #2 in step 2.3.** This is an accepted limitation (PLANNING.md 4.3):

| Check | Result |
|---|---|
| LSA protection | On: `RunAsPPL` is `0x2` |
| The dump | Failed with `Access is denied` |
| `validate_events.py` | 5998 events, 0 invalid |
| `process_access` events targeting `lsass.exe` | None. The only `lsass` matches are `file_write` events with LSASS as the writer |
| `process_access` decoding | Works: other events show `vm_read`, for example with target `StoreDesktopExtension.exe` |

Windows blocked the dump, but the agent recorded no sign of the attempt in `process_access`. A single test can't show why, and the project Sysmon config in PLANNING.md Section 9 is untested. Nothing was disabled to get this result.

**Batch 1 of the dataset (PHASES.md steps 2.4 and 2.5).** The batch was recorded with `run_batch.ps1`, exported, and checked read-only. Counts only: the logs stay out of the repo.

| Session | Events | Malicious | Benign | None | Exit code | FIM changes |
|---|---|---|---|---|---|---|
| 1 T1218.011 #9, run 1 | 1258 | 166 | 1092 | 0 | 0 | 0 |
| 2 benign `normal-use`, run 1 | 51490 | 0 | 51490 | 0 | | 2 |
| 3 T1486 script, run 1 | 1384 | 208 | 1176 | 0 | 0 | 0 |
| 4 T1053.005 #2, run 1 | 702 | 131 | 571 | 0 | 0 | 0 |
| 5 T1547.001 #2, run 1 | 571 | 131 | 440 | 0 | 0 | 0 |
| 6 T1547.001 #1, run 1 | 594 | 131 | 461 | 2 | 0 | 2 |
| 7 T1003.001 #2, run 1 | 1002 | 118 | 884 | 0 | 0 | 0 |
| 8 T1059.001 #17, run 1 | 777 | 186 | 591 | 0 | 0 | 0 |
| 9 benign `admin-powershell`, run 2 | 16501 | 0 | 16501 | 0 | | 0 |

| Check | Result |
|---|---|
| `validate_events.py` | 0 invalid in all 9 `events.jsonl` files, and in both non-empty `fim.jsonl` files |
| `label_session.py` on a copy | Gave the same `labels.csv` as the exported ones, for all 9 |
| `Lost by ETW`, `Lost, queue full`, `Handler errors`, `Sysmon read errors` | 0 in all 9 |
| `Sysmon, no process info` | 4 in sessions 6, 8 and 9, 0 in the others |
| `filters.json` hash and agent commit | The same in all 9 (`198be4a`) |
| Clean-start check | Passed for all 9 |

Findings from batch 1. Each was decided afterwards, and PLANNING.md Section 10 records how: the wrapper gets its own `part`, FIM now watches `RunOnceEx`, a 60-second warm-up was added, the restore waits about 2 seconds, and the jump-list writes are accepted.

- **The Atomic harness dominates the malicious label.** In the six Atomic sessions, 64% to 98% of the malicious events come from the `Invoke-AtomicTest` PowerShell wrapper (module import, `hostname`, `whoami`, `conhost`), not from the test's own processes, which add between 2 and 67 events. Sessions 4, 5 and 6 have the same 131 malicious events.
- **FIM doesn't watch `RunOnceEx`.** Atomic T1547.001 #2 is named "Reg Key RunOnce" but writes `HKLM\...\RunOnceEx\0001\Depend`. ETW and Sysmon recorded the add and the delete, and FIM reported nothing, because it watches only `Run` and `RunOnce`.
- **Normal use produces a `fim_change` pair.** Session 2 has two events: Edge's `MicrosoftEdgeAutoLaunch_*` Run value was removed and added again 140 ms later. A FIM rule would fire on this benign session.
- **File path coverage is under 95% in every session.** For processes started after the agent it was 88.1% in session 2, 68.8% in session 9 and 90.9% to 94.5% in the attack sessions. Session 9's gaps came from background Windows work (`CompatTelRunner.exe` 1512 of 3583 writes, `provtool.exe` 470 of 1936), and session 2's from `MoUsoCoreWorker.exe`, Edge and `taskhostw.exe`. The sessions start straight after a revert, when Windows is busiest.
- **The attack processes have 2 or 3 writes with no path in every session** (3 of 106 for the T1486 script), so "100% for the test process" is missed. They are PowerShell's writes to its jump-list file, about 0.3 seconds after it starts. In session 3 they came a second before the first event under the test folder, and all 75 writes under it have a path.
- **Registry key coverage in the attack sessions is 56.8% to 77.4%,** against 91.6% and 98.9% in the benign ones. A short session is dominated by the start of PowerShell and `cmd.exe`, so zone features built from ETW registry keys can undercount persistence there.
- **The exit code is the wrapper's, not the technique's.** It was 0 for every attack session, including one where the technique's own command was denied.

**Batch 2 of the dataset.** Recorded with `run_batch.ps1 -Batch 2` from `atomic-ready-3`, with the 60-second warm-up, exported, and checked read-only. Counts only. Events include the `fim_change` lines.

| Session | Events | Test | Harness | Benign | None | Exit code | FIM changes |
|---|---|---|---|---|---|---|---|
| 1 T1486 script, run 2 | 9583 | 214 | 105 | 9264 | 0 | 0 | 0 |
| 2 T1218.011 #9, run 2 | 2541 | 44 | 246 | 2251 | 0 | 0 | 0 |
| 3 T1547.001 #2, run 2 | 1046 | 14 | 245 | 785 | 2 | 0 | 2 |
| 4 T1547.001 #1, run 2 | 5236 | 14 | 243 | 4977 | 2 | 0 | 2 |
| 5 benign `zip-files`, run 3 | 41120 | 0 | 0 | 41120 | 0 | | 0 |
| 6 T1053.005 #2, run 2 | 953 | 12 | 247 | 694 | 0 | 0 | 0 |
| 7 benign `admin-powershell`, run 4 | 7085 | 0 | 0 | 7085 | 0 | | 0 |
| 8 T1059.001 #17, run 2 | 976 | 70 | 241 | 665 | 0 | 0 | 0 |
| 9 T1003.001 #2, run 2 | 1202 | 2 | 289 | 911 | 0 | 0 | 0 |

| Check | Result |
|---|---|
| `validate_events.py` | 0 invalid in all 9 `events.jsonl` files, and in both non-empty `fim.jsonl` files |
| `Lost by ETW`, `Lost, queue full`, `Handler errors`, `Sysmon read errors` | 0 in all 9 |
| `session.json` | No byte order mark. `warmup_seconds` 60 in all 9. The first event is 72 seconds before the test starts (12 in batch 1) |
| Clean-start check | Passed for all 9 |
| Test part | Same size as batch 1 for every test (T1003.001 still 2) |

Findings from batch 2:

- **The warm-up does not raise path coverage.** For processes started after the agent, file writes with a path were 91% to 94.6% in the attack sessions in both batches. Registry coverage moved both ways (T1218.011 56.8% to 71.4%, T1486 77.4% to 60.9%). T1218.011 run 2 fell to 58.1% because `taskhostw.exe` made 84 of 87 pathless writes, and T1486 run 2 to 84.6% because of `msedgewebview2.exe`. These are Windows tasks that start at any time. The warm-up stays for batches 2 to 11 for consistency.
- **`WmiApSrv.exe` bursts.** T1486 run 2 and T1547.001 #1 run 2 each hold about 4,310 file writes from `WmiApSrv.exe` within a second, 58 and 30 seconds before the test starts, which is inside the warm-up. Batch 1's first benign session had the same burst. It is unrelated to the label, and features computed from `start_utc` don't count it.
- **The cleanup looked like the attack.** Lane 2's real-data run showed the T1486 cleanup was labelled `background`. It is now `harness` in both batches, together with every other test's cleanup tree: 104 to 175 events per session, all within about 3 seconds after `end_utc`. Test counts did not change.
- **FIM's own Python.** `python.exe` in the FIM virtual environment has 6 to 9 events with no path in every session of both batches, so it does not separate the labels.

## Questions to settle in the VM

| Question | How to tell | If the answer is bad |
|---|---|---|
| Do Kernel-Network's connect events include failed connections? | Compare with a connection to a closed port | Document it, because `network_connect` would then mean "attempted" |
| Do event 12, the Close filter and the network filter hold up under heavy load? | `Lost by ETW` stays at 0 while recording the dataset. The second run was small | Increase the buffers in `etw_session.cpp`, then try `--no-close-events` |
| Does QueryKey give complete names? | Compare runs of the same activity with and without keyword `0x8000`. Total registry coverage rose from 25% (49 of 196) to 59% (962 of 1625), but the workload and other fixes changed too, so this doesn't prove it | Remove keyword `0x8000` |

**Rundown was not tested.** `--rundown` stays off, so ETW can't name a handle opened before the agent started, and `Started before agent` is not expected to reach 100%. For Run keys, FIM (step 2.2) and Sysmon Event ID 13 cover that gap.

## Dependencies

| Library | Pin | Why |
|---|---|---|
| [krabsetw](https://github.com/microsoft/krabsetw) | Commit `d626e49c41a2a324ad8b433b186703aa551373b3` | It publishes no tags or releases. This is the commit that bumped its NuGet packages to 4.5.0 |
| [nlohmann/json](https://github.com/nlohmann/json) | Tag `v3.12.0` | Newest tag when pinned |
| [jsonschema](https://pypi.org/project/jsonschema/) | Locked in `uv.lock` and `tools/requirements.txt` | Used only by the validator |
| [pywin32](https://pypi.org/project/pywin32/) | Locked in `uv.lock` and `tools/requirements.txt`, Windows only | Used only by FIM, for the two notification APIs |
| [pytest](https://pypi.org/project/pytest/) | Locked in `uv.lock` as a development dependency | Used only for tests in WSL |

After changing Python dependencies, regenerate the VM file from `agent/`:

```bash
uv export --no-dev --format requirements-txt -o tools/requirements.txt
```
