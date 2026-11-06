# ThreatPulse detection: the file layers

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
