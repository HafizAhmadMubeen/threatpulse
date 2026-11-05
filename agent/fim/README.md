# ThreatPulse FIM

File Integrity Monitoring for the persistence zone, covering PHASES.md step 2.2. This is the 2nd-generation integrity layer: it protects the **object**, not the writer. Attackers write Run keys with signed tools such as `reg`, so "who wrote it" says little, while "this changed and nobody approved it" stays true.

**Run it only in the lab VM.** It refuses to start unless `C:\ThreatPulseLab\LAB_VM` exists, and it needs 64-bit Python, because 32-bit Python sees redirected System32 and registry paths.

**FIM only reads what it watches.** It writes only to its own folder and its log. Restoring a change is an enforcement action, which belongs to `policy/` in Phase 3.

## What it watches

| Item | Where | Value in `fim_change` |
|---|---|---|
| Run and RunOnce keys | HKCU and HKLM | Registry data |
| Run and RunOnce keys for 32-bit programs | `HKLM\SOFTWARE\WOW6432Node\...` | Registry data |
| Startup folders | Per-user and all-users, files directly in the folder | SHA-256 |
| Hosts file | `drivers\etc\hosts` only, not the other files in that folder | SHA-256 |

HKCU and the per-user startup folder belong to whoever runs FIM, so always run it as `lab`. The other watched items don't depend on the user.

## Create the baseline

The baseline is the approved state. Create it on a clean system, **before the `atomic-ready` snapshot in step 2.3**, so that every rollback restores it.

From `C:\ThreatPulseLab\threatpulse`:

```powershell
agent\.venv\Scripts\python agent\fim\main.py baseline
```

This saves `C:\ThreatPulseLab\fim\baseline.json`, plus a copy of each watched file in `files\`, named by SHA-256. Phase 3 needs those copies, because a file can't be restored from a hash.

It refuses to replace an existing baseline. The baseline defines what is trusted, so replacing it must be deliberate: delete `baseline.json` first.

## Run it

In a 64-bit PowerShell opened with **Run as administrator**, signed in as `lab`:

```powershell
agent\.venv\Scripts\python agent\fim\main.py watch
```

**To stop it, press Ctrl+C.** It prints how many changes it reported.

| Option | Default |
|---|---|
| `--out <file>` | `C:\ThreatPulseLab\logs\fim.jsonl` |
| `--poll-only` | Off. Uses no notifications, to test the 60-second compare |
| `--dir <folder>`, before the command | `C:\ThreatPulseLab\fim` |

| Exit code | Meaning |
|---|---|
| 0 | Clean stop |
| 1 | No baseline, or `baseline` refused to replace one |
| 2 | Not the lab VM, or not 64-bit Python |

If `fim.jsonl` already exists, the old file is renamed with a timestamp, so runs never overwrite each other.

The agent and FIM write separate files, because the agent holds `events.jsonl` open without write sharing, and FIM must keep working when the agent stops. Consumers merge the two by `ts`. FIM's `event_id` counter starts at 900000000, so the two can't clash.

## How it works

```
RegNotifyChangeKeyValue --+
ReadDirectoryChangesW ----+--> rescan --> compare --> fim_change --> fim.jsonl
60-second timeout --------+
```

| Design choice | Why |
|---|---|
| A notification only means "look now" | Notifications don't say enough to trust. The same rescan and compare run for a notification and for the 60-second backup, so there is one path to test |
| Watches are re-armed before the rescan | Both APIs fire once. A change during the rescan then fires again rather than being missed |
| One thread | One wait covers every notification, the timeout and Ctrl+C |
| `baseline` and `last_seen` are separate | `baseline` is what is approved, `last_seen` is what has been reported. A change that stays isn't reported every 60 seconds |
| The first compare uses the baseline | Anything that changed while FIM was stopped is reported at start. It is reported again after each restart until it's approved or undone |
| `process.image` is `unknown` and `pid` is 0 | FIM doesn't know who made a change, so it doesn't claim to |

| File | Job |
|---|---|
| `targets.py` | What to watch |
| `baseline.py` | Snapshots, compare, save and load |
| `events.py` | Builds `fim_change` events and writes JSONL |
| `monitor.py` | The loop, and `baseline` against `last_seen` |
| `windows_watch.py` | Windows APIs only |
| `main.py` | The commands |

## Test it

**In WSL,** for everything except the Windows API calls in `windows_watch.py` and `main.py`. The tests also check that file's table of Windows constants, which is defined there because pywin32's `win32con` lacks some of them:

```bash
cd agent && uv run pytest
```

**In the VM,** while FIM and the agent are both running, from a 64-bit PowerShell opened with **Run as administrator**:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File agent\tools\vm_test_fim.ps1
# Stop FIM and the agent with Ctrl+C, then:
agent\.venv\Scripts\python agent\tools\check_fim_run.py C:\ThreatPulseLab\logs\fim.jsonl C:\ThreatPulseLab\logs\fim_test_keys.txt --events C:\ThreatPulseLab\logs\events.jsonl
```

The script adds a comment line to `hosts`, test values to the Run and RunOnce keys and a dummy file to the startup folder. It undoes everything, even if it fails part-way. A key that doesn't exist yet is skipped.

**To test the 60-second compare,** run `main.py watch --poll-only`, then:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File agent\tools\vm_test_fim.ps1 -Quick -HoldSeconds 70
# Stop FIM with Ctrl+C, then:
agent\.venv\Scripts\python agent\tools\check_fim_run.py C:\ThreatPulseLab\logs\fim.jsonl C:\ThreatPulseLab\logs\fim_test_keys.txt --poll-only
```

## What the VM has shown

Results of the first complete VM run, with event-driven watching:

| Check | Result |
|---|---|
| `check_fim_run.py` | 12 of 12 checks passed, covering all six Run and RunOnce keys, `hosts` and the startup folder |
| Time after Sysmon's event for the same Run value | 0.0 seconds, so a notification found the change, not the 60-second compare |
| `validate_events.py` on `fim.jsonl` | 0 invalid |
| A second `watch` after the test | `Changes reported: 0`, so the test undid everything and the baseline still matched |

Results of the run with `--poll-only` and `vm_test_fim.ps1 -Quick -HoldSeconds 70`:

| Summary line | Result |
|---|---|
| `Changes reported` | 2, the value being added and then removed |
| `Notifications` | 0, so the 60-second compare found both |
| `Full compares` | 3 |

**Step 2.2 is verified,** for event-driven watching and for the 60-second backup.

## Limits

| Limit | Effect |
|---|---|
| FIM can't see who made a change | `pid` is 0 and `image` is `unknown`. Finding the writer for rule P2b is correlation work in Phase 3, using Sysmon events on the same key |
| A value added and removed before the rescan is missed | Sysmon Event IDs 12 and 13 cover this. FIM counts these under `Notifications with no change`, which also counts writes to other files in the hosts folder |
| Windows removes RunOnce values itself | After a RunOnce entry runs, it appears as `removed` |
| An admin attacker can stop FIM or edit its baseline | Accepted for this prototype |
| A key or folder that doesn't exist can't be watched | FIM prints a warning, and the 60-second compare covers it. It tries to watch it again after each timeout |
| Only one user's HKCU and startup folder are watched | Other users' autostart entries aren't covered. The lab VM has one user |
| The Gate 2 "FIM alert" needs more than this | This step gives `fim_change` events. Turning them into an Alert belongs to the detection layer |
