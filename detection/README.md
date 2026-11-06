# ThreatPulse detection: the file layers and the behaviour rules

This folder has two things. `scan_file` checks files (steps 1.5 to 1.7, below). `match_rules` runs the behaviour rules on events (step 2.7, [at the end](#behaviour-rules)).

## File layers

`scan_file(path)` is PHASES.md steps 1.5 to 1.7. It checks one file with three static layers and returns a list of Alerts. It reads the file and never runs or loads it.

| Layer | Generation | Finds | Weakness |
|---|---|---|---|
| Hash list (`rules/hashes/known_bad.json`) | 1st | Exact known files, with no false positives | One changed byte defeats it |
| YARA (`rules/yara/`) | 1st | Patterns, so it survives small changes | Still only finds what a rule describes |
| PE heuristics (`pe_heuristics.py`) | 2nd | Suspicious structure, even in files nobody has seen | Legitimate software can be packed too |

Packing defeats all three. That's why ThreatPulse watches behaviour as well, and why static results never trigger enforcement on their own.

## Use it

```python
from detection import scan_file

alerts = scan_file(r"C:\ThreatPulseLab\samples\hello.exe")
```

To see every layer's result, including scores below the alert threshold:

```bash
uv run python -m detection <path> [<path> ...]
```

## What an alert looks like

`scan_file` has a path and no process, so its alerts have no known process: `subject.pid` 0, `image` `"unknown"`, `risk_score` null, `event_type` `file_scan`, no evidence events and `object.zone` `none`. When an event triggered the scan, the pipeline fills in the process, evidence and ML score.

| Result | `layer` | `rule_id` | `static_analysis` |
|---|---|---|---|
| Signature match | `signature` | `SIG-<name>` | `score` null, and `reasons` lists every method that matched |
| Heuristic score of 0.50 or more | `heuristic` | `HEUR-<strongest finding>` | `score`, and `reasons` lists every finding |

- **One alert per signature name.** A file matched by both the hash and YARA gives one alert, so one delete request.
- **`static_analysis` is never a `risk_score`.** `risk_score` is the ML score of a process tree, and policy rules use it to contain processes. A static score only says what a file looks like, so it stays out of enforcement. The policy engine ignores `static_analysis`.
- **Reasons are telemetry.** Section names come from the file. They are cleaned, but anything reading them must still treat them as data.

## Heuristic score

The score is a capped sum of one weight per kind of finding, so any score can be checked by adding up its reasons.

| Finding | Weight | Why it matters | Rule name |
|---|---|---|---|
| File claims to be a PE but can't be parsed | 0.50 | Broken on purpose, or just truncated | `UNPARSEABLE-PE` |
| UPX section name | 0.40 | Packed | `UPX-PACKED` |
| Other packer section name | 0.40 | Packed | `PACKER-SECTION` |
| Process injection imports, used together | 0.30 | Allocate, write and run in another process | `INJECTION-IMPORTS` |
| Memory dumping import | 0.30 | Crash reporters use it too, so it can't reach the threshold alone | `DUMP-IMPORTS` |
| Executable section with entropy of 7.2 or more | 0.25 | Compressed or encrypted code | `HIGH-ENTROPY` |
| Executable section with far less raw data than virtual size | 0.15 | Space to unpack into at runtime | `SIZE-MISMATCH` |
| Entry point outside the first code section | 0.15 | Starts in an unpacking stub | `ENTRY-POINT` |
| Fewer than 5 imports | 0.15 | Resolves its real imports at runtime. .NET files are skipped | `FEW-IMPORTS` |

**The weights are hand-set judgement, not measured values.** They haven't been tested against a large set of real software, so the false-positive rate is unknown.

Other limits:
- Files over 64 MiB get the hash check only.
- Import names are only compared with fixed lists, so a file's own import names never reach a reason.
- A file that merely starts with `MZ` counts as a broken PE.
- `signed` is false in these alerts even for a signed file, because Authenticode can't be checked in cross-platform code.

## Safety

- The file is read once into memory, so all three layers judge the same bytes. `pefile` gets those bytes, never a path.
- Only regular files are read, so a FIFO can't hang the scan.
- A malformed file gives "unparseable", and a vanished or locked file gives no alerts. Neither crashes the scan.
- Rules load from fixed repo paths, can't include other files, and are compiled once. A bad rule or hash list stops startup, because a missing layer must not look like a clean scan.
- The repo holds only EICAR's hash and two fragments in its YARA rule. A test checks that no repo file contains the EICAR file.

## Tests

`uv run pytest tests/test_detection.py`. The PE files are built in memory by `tests/pe_builder.py`, with real headers and no working code. The EICAR rule can't be tested here, so its match is checked in the lab VM: see [VM_TEST_PLAN.md](VM_TEST_PLAN.md).

## Behaviour rules

`match_rules(event)` is PHASES.md step 2.7, 3rd generation. Rules are Sigma-style YAML in `rules/behaviour/`, one file per technique. They match what a process **does**: where it writes, how many files it deletes, what it starts, not an Atomic test's own strings.

```python
from detection.replay import replay
alerts = replay(events)          # sorts by time, then runs every rule
```

```bash
uv run python -m detection.replay events.jsonl fim.jsonl
```

**`match_rules` keeps state**, because behaviour spans several events: who started whom, how many files one process deleted, a connection followed by a file. Feed it events in time order. `replay` sorts first, because the agents write events out of time order. Call `reset_engine()` between sessions.

| Rule | Technique | Kind | Looks for |
|---|---|---|---|
| `R-T1547-001`, `-002` | T1547.001 | single | A Run/RunOnce/Winlogon value set, or a file created in a Startup folder |
| `R-FIM-PERSISTENCE`, `R-FIM-HOSTS` | T1547.001 | single, `layer: fim` | A FIM change to an autorun item, or to the hosts file |
| `R-T1003-001` | T1003.001 | single | LSASS opened with `vm_read` |
| `R-T1003-002` | T1003.001 | single | A command line that dumps LSASS (`comsvcs` + `minidump`, `lsass` + `-ma`, `sekurlsa::`) |
| `R-T1059-001` | T1059.001 | single | PowerShell started with an encoded command, a hidden window, or download/decode code |
| `R-T1105-001` | T1105 | sequence | A download-capable program connects out, then writes a file within 30 seconds |
| `R-T1486-001` | T1486 | threshold | 10 or more deletes or renames in user document folders within 30 seconds, by one process |
| `R-T1053-001` | T1053.005 | single | `schtasks /create`, or PowerShell registering a task |
| `R-T1685-001` | T1685 | single | A write to Defender's policy, exclusion or real-time protection settings |
| `R-T1218-001` | T1218.011 | single | A process started by `rundll32.exe` |

- **Why two LSASS rules:** with LSA protection on, Windows denies the read and the sensor sees no `process_access` event (PLANNING.md 4.3). The second rule catches the attempt, but it can't fire when the command line is null.
- **Alerts have no risk score.** `risk_score` is null until the orchestrator adds the ML score (step 3.9). FIM alerts have no process, because FIM doesn't know who made a change.
- **One alert per action.** ETW and Sysmon both report registry writes, so rules raise one alert per process and key. Sensors give each event type a different source, so some rules use either.
- **No allowlist here.** Many Windows components read LSASS. The policy engine owns the allowlist and starts in learning mode.

**All rule thresholds are starting guesses.** Nothing has been tested against benign recordings yet, so the false-positive rate is unknown. Gate 3 (PLANNING.md Section 6) asks for each rule to be checked on the benign sessions.

**Known limits**
- A ransomware that stops after 9 files is not caught by `R-T1486-001`. Our own T1486 script writes 25.
- `cmdline` is null for short-lived processes such as `reg.exe`, so command-line rules can miss them.
- `R-T1053-001` sees only the part that creates the task. The task itself later runs under the Task Scheduler service, outside the launcher's tree.
- `R-T1218-001` needs rundll32's own events earlier in the stream, to know it is the parent.
- The sample set doesn't contain these techniques, so the tests build their own events.

### Rule format

```yaml
- id: R-T1547-001
  title: Autorun registry value set
  layer: rule                 # rule, or fim
  zone: persistence           # documents, persistence, lsass, network or none
  techniques: [T1547.001]
  dedupe_by: [pid, target.registry_key]
  detection:
    selection:                # a map is AND, a list of maps is OR
      event_type: registry_set
      target.registry_key|contains: ['\CurrentVersion\Run\', '\CurrentVersion\RunOnce\']
    filter:                   # optional
      process.image|startswith: 'C:\Program Files\Windows Defender\'
    condition: selection and not filter
```

- **Modifiers:** none (equals), `contains`, `contains_all`, `startswith`, `endswith`. Comparison ignores case, and a list means any of.
- **Kinds:** `type: threshold` (`count`, `window_seconds`, `group_by`) and `type: sequence` (`within_seconds`, `group_by`, `steps`). See `T1486.yaml` and `T1105.yaml`.
- **`parent.image`** is the image of the process that started the event's process, from the engine's process table.

**Rules are untrusted-input safe:**
- Files are read with `yaml.safe_load` and checked field by field at startup. A wrong rule stops startup, so a broken rule can't look like a quiet one.
- Matching is plain text comparison with no regular expressions, so no event text can make a rule run for a long time.
- The condition is fixed text, not an expression.
- An event that isn't well formed is counted in `engine.rejected` and skipped.
- The lists in `zones.py` and the rule files are kept in step by a test.

```bash
uv run pytest tests/test_behaviour.py
```
