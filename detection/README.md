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

**All rule thresholds are starting guesses.** Gate 3 (PLANNING.md Section 6) asks for each rule to be checked on the benign sessions. The first real recordings (batch 1, two benign sessions of about 11 minutes) are too few to set any threshold: see "First real recordings" below.

### First real recordings

`python -m detection.session_report <session folders> --out data/runs/<name>` replays sessions and reports which rules fire. It reads the sessions and never writes inside them. `data/runs/` is not committed, because the repo is public.

Batch 1 had 7 attack sessions and 2 benign ones (one of each pool was held out: T1053.005 and T1218.011).

| Result | Detail |
|---|---|
| Every technique was detected | By the technique's own processes, never by the `Invoke-AtomicTest` wrapper |
| T1003.001 | Detected by `R-T1003-002` only. There was no LSASS `process_access` event in any session, as LSA protection predicts |
| T1547.001 #2 | `RunOnceEx\0001\Depend\1`, caught by the existing `RunOnceEx` entry. **FIM saw nothing**, because it doesn't watch that key |
| T1486 | The rule fires on the 10th delete. A second alert comes from the cleanup that removes the test folder afterwards, which deletes the same 25 files |
| Benign false positives | 3, all in one session: Edge removed and re-added its own autolaunch Run value 140 ms apart. FIM saw both changes, and `R-T1547-001` fired once |
| Benign document activity | **Unknown.** No file event with a path was in a document folder, but 22,663 and 7,089 file events in the two sessions had no path at all, so they can't be placed in any zone |

**What the data changed**
- **Duplicate alerts:** ETW wrote `HKCU\SOFTWARE\...` and Sysmon wrote `HKCU\Software\...` for the same key, so one action gave two alerts. De-duplication now ignores case.
- **Command lines are often null:** 2 of 94 and 10 of 59 process starts in the benign sessions, and up to 8 of 21 in a test session. `reg.exe` had a null command line in one test. Rules that don't use the command line still fired.

**What it can't tell us yet**
- `R-T1486-001`'s threshold is untouched. The benign sessions have no document-folder deletes or renames with a path, but no one was working on documents, so they say nothing about a lower threshold. And a file event with no path can't be counted by any zone rule or feature. The same count over all paths reaches 145 and 286 deletes or renames in 30 seconds (Edge's cache), which is why the rule only counts document folders. Choose the threshold after the benign sessions with zipping and admin work are recorded.
- `R-T1105-001` had no data: its test needs NAT and is in a later batch. No benign process made a connection from a listed program either.
- The two held-out sessions only confirm that those two rules fire. They were not used to change anything.

**Known limits**
- A ransomware that stops after 9 files is not caught by `R-T1486-001`. Our own T1486 script writes 25.
- `cmdline` is null for short-lived processes such as `reg.exe`, so command-line rules can miss them.
- `R-T1053-001` sees only the part that creates the task. The task itself later runs under the Task Scheduler service, outside the launcher's tree.
- `R-T1218-001` needs rundll32's own events earlier in the stream, to know it is the parent.
- The sample set doesn't contain these techniques, so the tests build their own events.

### Ransomware: delete burst plus encrypted-looking output (R-T1486-002)

`R-T1486-001` counts deletes, and an archiver extracting a zip trips it exactly like ransomware (batch 2 benign zip session: 1,019 deletes, 51 in 0.1 s, against the attack's 25 in 0.08 s). No count or window separates them. What differs is what replaces the files: encrypted bytes are near random (about 8 bits per byte) with no file header. `detection/entropy.py` and `detection/ransom.py` add that signal (3rd generation, PLANNING.md 5.6 P3 "write rate + entropy").

| Verdict | Meaning | Result |
|---|---|---|
| `high` | at least 5 sampled files, at least 80% suspect | `R-T1486-002` is raised, in addition to `R-T1486-001`. Policy `P3b` suspends; it is also a high-risk (report) alert |
| `low` | at least 5 sampled, at most 20% suspect | `R-T1486-001` only (alert_only) |
| `unknown` | too few files, files gone or unreadable, a limit was hit, or no reader | `R-T1486-001` only. **Never lowers anything, nothing is suppressed** |

A file is **suspect** when its sampled entropy is at least 7.5 bits per byte and it does not look like the format it claims: no known header, or a header for a different type than the extension. JPEG, DOCX and ZIP files are compressed and also score near 8, so entropy alone would flag benign extraction. Thresholds (7.5, 5 files, 80%, 20%) are **starting guesses, not measured on real data**.

**Replay can't read files.** Recorded Windows paths don't exist in WSL, and the files are usually gone after a session. So in a replay without a reader every burst is `unknown` and `R-T1486-002` is never raised; the pipeline summary says so (`entropy.reader: off`). The reader is for the lab VM: `python -m backend.pipeline <sessions> --out <dir> --read-files`, run while the files still exist, or live as events arrive. Files deleted before they are read (an extractor that cleans up) stay `unknown`.

**What is read, and the limits**
- Only files written by the burst's own process, in the documents zone (`zones.is_document_path`), and only files the process created, wrote or renamed to. Never anything else.
- Links are never followed: each path component is checked with `lstat` (symlinks and Windows reparse points refused), and the opened file must be the one checked. Only regular files, read-only. Nothing is executed, loaded or parsed. A race between the check and the open is narrowed, not impossible.
- Limits: files over 64 MiB or under 512 bytes are skipped (a smaller sample cannot reach 7.5 even when random), the first 64 KiB plus 64 KiB from the middle of a big file are read, at most 100 files and 16 MiB per 10 seconds, 200 files per process. A file is read at least 1 s after its last write. Running out of budget gives `unknown`.
- The T1486 test script's output files must be at least 512 bytes, or its verdict stays `unknown`.

**Evasion limits (accepted).** Ransomware that writes low-entropy output, that starts its output with a real file header matching the extension, or that encrypts only part of each file stays at `R-T1486-001`. A ransomware that only deletes or wipes writes nothing to sample and also stays there. `R-T1486-001` is still raised for all of them.

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

### Rule evaluation on batches 1 to 4 (read-only)

`python -m detection.rule_eval` replays every labelled session through a fresh `match_rules` engine and counts what fires. It changes no rule, threshold, session or labels folder (a test checks the rule files byte for byte). It reads `--batch N SESSIONS LABELS` the way `triage.train` does, with `--only-labelled` for batch 3's second run.

```bash
uv run python -m detection.rule_eval --only-labelled --recording-tests recording_tests.json \
  --batch 1 $E/batch-01 $E/batch-01-labels-v3 --batch 2 $E/batch-02 $E/batch-02-labels-v2 \
  --batch 3 $E/batch-03 $E/batch-03-labels --batch 4 $E/batch-04 $E/batch-04-labels \
  --out data/runs/rule-eval-1234
```

**Pools left out.** `rule_eval` skips the sessions of every pool in `excluded_from_ml_pools` (today `fim-test-only`) in Track A's `agent/config/recording_tests.json`, the same way `triage.dataset` does and with the same code: skipped before anything else is read (no labels needed), listed by name with their pool in the report (`## Sessions left out on purpose`, and `sessions_left_out_for_an_excluded_pool` in the JSON together with the file's SHA-256), and never replayed through the rules. The list comes from the file only. The run stops if the file or its key is missing, if a session's pool cannot be read, or if a pool is neither known (`training-technique`, `held-out`, `unassigned`) nor listed. Until Track A's branch is merged, pass a copy with `--recording-tests PATH`; the command below needs it.

How things are counted:
- An attack session's alert is *in the test part* when most of its evidence events are labelled `part=test`. Harness alerts (the wrapper that runs a test) and background alerts are counted apart and are never detections.
- **FIM alerts have no labels**, so they are placed by time: inside the session's test window (`start_utc` to `end_utc`) or not. Those rows say so.
- A technique is *detected* in a session when a rule written for that technique fired in the test part. A rule of another technique firing there is a *cross-fire*, not a hit.
- A benign session counts as having an alert for any alert inside its window. Alerts before `start_utc` or after `end_utc` are counted apart, with the reason (below).
- Every event is replayed or counted as skipped: 431,915 events replayed, 0 skipped as invalid, 0 rejected by the engine.

#### Where each rule comes from (in-sample or not)

- Written: 9a68638, 2026-11-06 19:00 +0500, from the design (PLANNING.md, ATT&CK) and tests that build their own events.
- Rule files changed since: no, never.
- Thresholds: starting guesses, never tuned (detection/README.md): 10 deletes or renames in 30 s (T1486), connect then write within 30 s (T1105).
- Engine change made after data: 5959aee (2026-11-06 19:19 +0500), after replaying batch 1: de-duplication ignores case, because ETW and Sysmon spell one registry key differently. Affects R-T1547-001, R-T1547-002, R-T1685-001.

| Batch | Status for the rules |
|---|---|
| 1 | IN-SAMPLE: replayed while the rules were being finished. It produced the de-duplication fix, and the README's first-real-recordings notes. No rule or threshold changed. |
| 2 | SEEN, not tuned: replayed through the orchestrator work, which noted the R-T1486-001 false positive on the benign zip session. Nothing was changed. |
| 3 | OUT-OF-SAMPLE: not looked at before this evaluation. |
| 4 | OUT-OF-SAMPLE: not looked at before this evaluation. |

#### Per technique: which rules fired in the test part

| Technique | Detected (a rule for it fired in the test part) | Batches 3 and 4 only (out-of-sample) | Rules fired in the test part (alerts) | Harness alerts | Background alerts |
|---|---|---|---|---|---|
| T1003.001 | 3 of 4 (75%, 95% CI 30.1% to 95.4%) | 2 of 2 (100%, 95% CI 34.2% to 100%) | R-T1003-002 x3 | none | none |
| T1053.005 | 3 of 3 (100%, 95% CI 43.8% to 100%) | 1 of 1 (100%, 95% CI 20.7% to 100%) | R-T1053-001 x3 | none | none |
| T1059.001 | 4 of 4 (100%, 95% CI 51% to 100%) | 2 of 2 (100%, 95% CI 34.2% to 100%) | R-T1059-001 x4 | none | none |
| T1218.011 | 3 of 3 (100%, 95% CI 43.8% to 100%) | 1 of 1 (100%, 95% CI 20.7% to 100%) | R-T1218-001 x3 | none | none |
| T1486 | 4 of 4 (100%, 95% CI 51% to 100%) | 2 of 2 (100%, 95% CI 34.2% to 100%) | R-T1486-001 x4 | none | none |
| T1547.001 | 8 of 8 (100%, 95% CI 67.6% to 100%) | 4 of 4 (100%, 95% CI 51% to 100%) | R-FIM-PERSISTENCE x7, R-T1547-001 x8 | none | none |

#### Per rule

| Rule | Written or tuned against | Techniques | Fired in the test part of its own technique | of which batches 3 and 4 | Cross-fired in another technique's test part | Benign sessions with this rule | Benign alerts | Harness alerts | Background alerts (attack sessions) |
|---|---|---|---|---|---|---|---|---|---|
| R-FIM-PERSISTENCE | design and synthetic events; nothing tuned; batches 1 and 2 seen; batches 3 and 4 out-of-sample | T1547.001 | 7 of 8 (87.5%, 95% CI 52.9% to 97.8%) (by time window, FIM has no labels) | 4 of 4 | none | 1 of 8 (12.5%, 95% CI 2.2% to 47.1%) | 2 | 0 | 0 |
| R-FIM-HOSTS | design and synthetic events; nothing tuned; batches 1 and 2 seen; batches 3 and 4 out-of-sample | none | no sessions of its own technique (by time window, FIM has no labels) | none | none | 0 of 8 (0%, 95% CI 0% to 32.4%) | 0 | 0 | 0 |
| R-T1003-001 | design and synthetic events; nothing tuned; batches 1 and 2 seen; batches 3 and 4 out-of-sample | T1003.001 | 0 of 4 (0%, 95% CI 0% to 49%) | 0 of 2 | none | 0 of 8 (0%, 95% CI 0% to 32.4%) | 0 | 0 | 0 |
| R-T1003-002 | design and synthetic events; nothing tuned; batches 1 and 2 seen; batches 3 and 4 out-of-sample; added from the LSA-protection design (PLANNING.md 4.3), not from data | T1003.001 | 3 of 4 (75%, 95% CI 30.1% to 95.4%) | 2 of 2 | none | 0 of 8 (0%, 95% CI 0% to 32.4%) | 0 | 0 | 0 |
| R-T1053-001 | design and synthetic events; nothing tuned; batches 1 and 2 seen; batches 3 and 4 out-of-sample | T1053.005 | 3 of 3 (100%, 95% CI 43.8% to 100%) | 1 of 1 | none | 0 of 8 (0%, 95% CI 0% to 32.4%) | 0 | 0 | 0 |
| R-T1059-001 | design and synthetic events; nothing tuned; batches 1 and 2 seen; batches 3 and 4 out-of-sample | T1059.001 | 4 of 4 (100%, 95% CI 51% to 100%) | 2 of 2 | none | 0 of 8 (0%, 95% CI 0% to 32.4%) | 0 | 0 | 0 |
| R-T1105-001 | design and synthetic events; nothing tuned; batches 1 and 2 seen; batches 3 and 4 out-of-sample | T1105 | no sessions of its own technique | none | none | 0 of 8 (0%, 95% CI 0% to 32.4%) | 0 | 0 | 0 |
| R-T1218-001 | design and synthetic events; nothing tuned; batches 1 and 2 seen; batches 3 and 4 out-of-sample | T1218.011 | 3 of 3 (100%, 95% CI 43.8% to 100%) | 1 of 1 | none | 0 of 8 (0%, 95% CI 0% to 32.4%) | 0 | 0 | 0 |
| R-T1486-001 | design and synthetic events; nothing tuned; batches 1 and 2 seen; batches 3 and 4 out-of-sample; threshold 10 in 30 s is a guess, batch 2's zip false positive was seen and not tuned | T1486 | 4 of 4 (100%, 95% CI 51% to 100%) | 2 of 2 | none | 2 of 8 (25%, 95% CI 7.1% to 59.1%) | 2 | 0 | 0 |
| R-T1547-001 | design and synthetic events; batch 1 IN-SAMPLE (de-duplication fixed after replaying it); batch 2 seen; batches 3 and 4 out-of-sample | T1547.001 | 8 of 8 (100%, 95% CI 67.6% to 100%) | 4 of 4 | none | 1 of 8 (12.5%, 95% CI 2.2% to 47.1%) | 1 | 0 | 0 |
| R-T1547-002 | design and synthetic events; batch 1 IN-SAMPLE (de-duplication fixed after replaying it); batch 2 seen; batches 3 and 4 out-of-sample | T1547.001 | 0 of 8 (0%, 95% CI 0% to 32.4%) | 0 of 4 | none | 0 of 8 (0%, 95% CI 0% to 32.4%) | 0 | 0 | 0 |
| R-T1685-001 | design and synthetic events; batch 1 IN-SAMPLE (de-duplication fixed after replaying it); batch 2 seen; batches 3 and 4 out-of-sample | T1685 | no sessions of its own technique | none | none | 0 of 8 (0%, 95% CI 0% to 32.4%) | 0 | 0 | 0 |

#### Benign sessions

Benign sessions with any alert in their window: 3 of 8 (37.5%, 95% CI 13.7% to 69.4%). Batches 3 and 4 only (out-of-sample): 1 of 4 (25%, 95% CI 4.6% to 69.9%).

| Batch | Benign sessions with any alert |
|---|---|
| 1 | 1 of 2 (50%, 95% CI 9.5% to 90.5%) |
| 2 | 1 of 2 (50%, 95% CI 9.5% to 90.5%) |
| 3 | 1 of 2 (50%, 95% CI 9.5% to 90.5%) |
| 4 | 0 of 2 (0%, 95% CI 0% to 65.8%) |

| Benign session | Batch | Alerts by rule (in the window) |
|---|---|---|
| 20261106T132018-benign-run1 | 1 | R-FIM-PERSISTENCE x2, R-T1547-001 x1 |
| 20261106T133812-benign-run2 | 1 | none |
| 20261106T144718-benign-run3 | 2 | R-T1486-001 x1 |
| 20261106T150136-benign-run4 | 2 | none |
| 20261106T191833-benign-run5 | 3 | R-T1486-001 x1 |
| 20261106T193554-benign-run6 | 3 | none |
| 20261107T051144-benign-run7 | 4 | none |
| 20261107T052338-benign-run8 | 4 | none |

Events replayed: 431915. Skipped as invalid against the Event schema: 0. Rejected by the engine as malformed: 0.

Alerts outside a session's window (before start_utc or after end_utc), not counted above: after_end 11.

| Outside the window | Rule | Session | Part | Alerts |
|---|---|---|---|---|
| after_end | R-FIM-PERSISTENCE | malicious | fim-outside-test-window | 7 |
| after_end | R-T1486-001 | malicious | harness | 4 |

What the numbers say, and what they cannot:
- **25 of 26 attack sessions were detected** (96.2%, 95% CI 81.1% to 99.3%) by a rule written for their technique, and **12 of 12 in batches 3 and 4**, the out-of-sample ones (100%, 95% CI 75.7% to 100%). Nothing from a harness or from background activity was counted as a detection.
- **The one miss is T1003.001 in batch 2** (the test part is one PowerShell start and stop 30 ms apart, with no command line and no LSASS access event). `R-T1003-002`, the command-line rule, caught 3 of 4. `R-T1003-001` (an LSASS read) caught **0 of 4**, as LSA protection predicts: it never sees an access event.
- **`R-FIM-PERSISTENCE` fired in 7 of 8 `T1547.001` sessions.** The miss is batch 1 test 2, which writes `RunOnceEx`, a key FIM did not watch then. The behaviour rule `R-T1547-001` caught all 8. `R-T1547-002` (a file in a Startup folder) fired in 0 of 8, because no recorded test uses a Startup folder, so there is no evidence for or against it.
- **No evidence at all for `R-T1105-001` and `R-T1685-001`**: no recorded session of their techniques yet. `R-FIM-HOSTS` has no technique and no session exercised the hosts file.
- **Benign sessions: 3 of 8 produced any alert** (37.5%, 95% CI 13.7% to 69.4%), and **1 of 4 in batches 3 and 4**. `R-T1486-001` fired in 2 of 8: both are the zip-extraction sessions (batch 2 run 3, and the zip-files session in batch 3). So zip extraction trips it every time it was recorded (2 of 2). No count or window separates it from the attack script (see the first-real-recordings notes). The entropy layer is meant to address this and can only be checked in the VM. `R-T1547-001` and `R-FIM-PERSISTENCE` fired in the batch 1 benign session (Edge rewriting its autolaunch Run value).
- **Outside the windows:** 11 alerts, all from the cleanup that follows a test: 7 `R-FIM-PERSISTENCE` (the cleanup undoing the Run key) and 4 `R-T1486-001` (the cleanup deleting the test folder, labelled harness). They are not counted anywhere above.

**What is in-sample.** All 13 rules were written in one commit (`9a68638`, 2026-11-06 19:00 +0500) from the design and from tests that build their own events, and **no rule file has changed since**: a test fails if one does. The one thing changed after real data was the engine's de-duplication (`5959aee`, after replaying batch 1): it now ignores case, because ETW and Sysmon spell one registry key differently. That affects `R-T1547-001`, `R-T1547-002` and `R-T1685-001`, so batch 1 is **in-sample** for those three. For the other rules batch 1 and batch 2 were looked at and written up with nothing changed, so they are **seen, not tuned**. Batches 3 and 4 were not looked at before this evaluation, and are the out-of-sample results. Thresholds (10 deletes in 30 s, connect then write in 30 s) are guesses and were never tuned. Two limits apply even to the out-of-sample figures:
- **They are repeats of the same scripted tests.** Each batch runs the same Atomic tests and our own T1486 script, so 12 of 12 says the rules fire on those test behaviours again. It does not show they catch a different implementation of the same technique, and the rules were never tried against evasion.
- **The rules were written knowing which techniques were planned**, including the held-out ones. "Held-out" protects the ML model, not the rules.
