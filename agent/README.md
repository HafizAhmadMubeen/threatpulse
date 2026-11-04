# ThreatPulse agent

The Sense part of Track A, covering PHASES.md steps 1.1 to 1.4. It's a user-mode C++ program that collects process, file and registry activity through ETW and writes [Event records](../PLANNING.md#51-event-agent--pipeline-one-json-object-per-line-in-eventsjsonl) to a JSONL file. This is the telemetry behind the 3rd-generation behaviour layer and the 4th-generation ML triage.

**The agent only observes.** It changes no system setting, and the only ETW session it ever stops is its own, `ThreatPulse-Agent`.

**Build and run it only in the lab VM**, never on a developer laptop or from WSL. It refuses to start unless `C:\ThreatPulseLab\LAB_VM` exists and it has administrator rights.

## Build

You need Git, Python 3.12, and Visual Studio Build Tools with "Desktop development with C++", including its CMake tools. The VM needs network access (NAT) for the first configure, because CMake downloads krabsetw and nlohmann/json.

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
| 4 | Startup failed (filter file, output file or ETW setup) |
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

# File create, write and rename
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
| 1.3 | `Select-String -Path $log -SimpleMatch 'threatpulse_agent'` | No results: the agent's own events are dropped |
| 1.4 | `Show-Events process_start 'System32\\cmd'` | `signed: True`, `signer: Microsoft Windows`, 64-character `sha256` |
| 1.4 | `Show-Events process_start notepad` | `signed: True`. See the note below |
| 1.2 | Validate the file (below) | `0 invalid` |

**Notepad:** on Windows 11, `notepad` usually redirects to the Store app under `C:\Program Files\WindowsApps\`, so check which `image` was recorded. A Store image may report `signed: False` or a null `sha256`. The `cmd.exe` row shows whether signature checking works. If `cmd.exe` passes and Notepad doesn't, it needs a closer look rather than counting as an agent failure.

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

## How it works

```
ETW session "ThreatPulse-Agent"
   | Kernel-Process, Kernel-File, Kernel-Registry
   v
ETW thread:    parse -> process table + name maps -> filters -> bounded queue
                                                                    |
Writer thread: SHA-256 + signature (per-image cache) -> JSON -> events.jsonl
```

| Design choice | Why |
|---|---|
| Two threads with a queue | ETW drops events if its callback is slow, so hashing and disk writes stay out of it |
| A process table | File and registry events carry only a pid, so image, ppid and user come from the table |
| Name maps | Write events have a `FileKey` and registry writes a `KeyObject`, not usable paths. Earlier events supply the names |
| Event 30, not event 12, for `file_create` | Event 12 fires on every file open, not only for new files |
| Catalog fallback for signatures | Many Windows binaries have no signature inside the file. Without this they would look unsigned |
| Revocation checks off | The VM is often offline during recordings, and a network timeout must not stall the agent |
| Timestamps from the ETW header | They show when the event happened, not when the agent processed it |
| Process events are never filtered | Labelling depends on complete process trees (PHASES.md step 2.4) |
| Process filters need path AND a Microsoft signature | A path alone can be imitated. Same principle as the never-suspend list |
| krabsetw included from one file only | Its headers define `INITGUID`, which risks duplicate-symbol link errors across files |

**ETW events used:**

| Provider | Keywords | Event IDs |
|---|---|---|
| Microsoft-Windows-Kernel-Process | `0x10` | 1 start, 2 stop |
| Microsoft-Windows-Kernel-File | `0x1A10` | 10, 11 names; 16 write; 27 rename; 30 new file |
| Microsoft-Windows-Kernel-Registry | `0x3101` | 1, 2 create and open; 5 set value; 13 close |

## Event field notes

| Field | Behaviour |
|---|---|
| `event_id` | `e-<run start UTC>-<counter>`, for example `e-20261105T101500-000123`. The counter has at least 6 digits and grows past that on long runs |
| `ppid` | 0 when the parent is unknown |
| `process.image` | Full path when known, otherwise `System` or `unknown` |
| `process.cmdline` | Null when the process exited before it could be read. ETW delivers events up to about a second late, so this is common for short-lived processes such as `reg.exe` |
| `process.user`, `process.sha256`, `process.signer` | Null when they could not be read |
| `process.signed` | True only for a verified signature. A failed check is false, so false does not prove a file is unsigned |
| `target.path` | Null when a file was opened before the agent started, so its name was never seen. For `file_rename`, this is the new path |
| `target.old_path` | Set only for `file_rename` |
| `target.registry_key` | `key\value`, with `(Default)` for an unnamed value. Starts with `HKLM`, `HKCU`, `HKU\<sid>` or, if unresolved, `<unresolved>` |

## Noise filters

`config/filters.json` holds three prefix lists, matched case-insensitively:

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

Keep filters narrow. A filter that covers a protected zone, such as documents or Run keys, blinds the agent there. There is deliberately no filter for `HKLM\SOFTWARE\Microsoft\Windows Defender\`: tampering with that key is part of held-out technique T1562.001, and Defender's own writes are already covered by the process filter.

After editing `config/filters.json`, rebuild to copy it next to the program, or pass it with `--config`. Use the same filters for every recording in a dataset.

## Questions to settle in the VM

These can't be answered from documentation. The shutdown summary and the checks above give the answers:

| Question | How to tell | If the answer is bad |
|---|---|---|
| Is rename `FilePath` the new or the old name? | `Renames, new path unknown` is above 0, or `file_rename` shows a null `path` | The new name has to come from another source |
| Do all writes resolve to a path? | `File writes without path` stays low, and the `file_write` check passes | Enable event 12 (keyword `0x80`) to record more names |
| Does ETW attach a SID to these kernel events? | `user` is filled in on `file_write` events from short-lived processes | `user` stays null when the token can't be read |
| Do registry paths resolve? | `Unresolved registry keys` stays low, and the `registry_set` check passes | Sysmon Event IDs 12 and 13 (PLANNING.md 4.2) can cover the gaps |
| Are cached writes attributed to the real process? | `file_write` events show the writing process rather than `System` | Document it, because it affects the ransomware detector's write rates |
| Is event loss acceptable? | `Lost by ETW` and `Lost, queue full` stay at or near 0 | Increase the buffers in `etw_session.cpp`, or add filters |
| Does the Microsoft root check recognise Defender and Sysmon? | No `file_write` events from `MsMpEng.exe` or `Sysmon64.exe` in the log | Safe but noisy: those events stay in the log. Check `chains_to_microsoft_root` in `enrich.cpp` |

## Dependencies

| Library | Pin | Why |
|---|---|---|
| [krabsetw](https://github.com/microsoft/krabsetw) | Commit `d626e49c41a2a324ad8b433b186703aa551373b3` | It publishes no tags or releases. This is the commit that bumped its NuGet packages to 4.5.0 |
| [nlohmann/json](https://github.com/nlohmann/json) | Tag `v3.12.0` | Newest tag when pinned |
| [jsonschema](https://pypi.org/project/jsonschema/) | Locked in `uv.lock` and `tools/requirements.txt` | Used only by the validator |

After changing Python dependencies, regenerate the VM file from `agent/`:

```bash
uv export --no-dev --format requirements-txt -o tools/requirements.txt
```
