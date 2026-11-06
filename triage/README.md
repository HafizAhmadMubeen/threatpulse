# ThreatPulse triage: features for the behavioural model

`triage/features.py` is PHASES.md step 2.8. It turns a recorded session into one row per **process tree**, ready for XGBoost (step 3.4). No model is trained here.

```bash
uv run python -m triage.features <session folder> [<session folder> ...] --out features.csv
```

A session folder is what `agent/tools/record_session.ps1` and `label_session.py` produce: `events.jsonl`, `fim.jsonl`, `labels.csv` and `session.json`. `fim.jsonl` and `labels.csv` are optional. Without labels, rows say `unlabelled`. `session.json` must have `session_id`, `pool`, `batch` and `network`. It may start with a UTF-8 byte order mark, which PowerShell writes.

## The harness is not the technique

`Invoke-AtomicTest` runs each test through a PowerShell wrapper, and the wrapper does far more work than the technique. In the first real recordings most events labelled malicious were the wrapper's. A model trained on them would learn the wrapper, which is Arp et al.'s spurious correlation.

So `labels.csv` has a `part` column: `test`, `harness`, `background`, or empty for FIM events.

- **With a `part` column,** harness events are left out **before** trees are built. Counts and tree shape both describe the test only: the test's own process becomes the root, because its parent no longer has a start event. `harness_excluded` is 1 on every row.
- **Without one** (the first labels, v1), the wrapper is counted as the test, a warning is logged, and `harness_excluded` is 0. **Don't train on those rows.**
- An unknown `part` value stops the run, so a new label is never silently kept.
- Trees made of `background` events stay, labelled benign.

## What counts as a process tree

A **root** is a process whose parent has no `process_start` in the session. A tree is a root and everything it started. The label never decides this, and `root_pid` from `session.json` is not used. If it were, attack trees and benign trees would differ by construction, and the model could learn that instead of behaviour.

- A process that was already running when recording began has no start event. It gets one row with `observed_start` 0. So do the processes it later starts, as their own roots.
- A reused pid is a new process, so it gets a new tree.
- **Every tree is written.** Which ones to train on is decided in step 3.4, using `observed_start`. Keeping unobserved processes in training could teach the model that "no start event" means benign.
- `System` and `Registry` write cache flushes that aren't an application's own writes (see `agent/README.md`). They are separate trees with `observed_start` 0.

## Columns

`METADATA_COLUMNS` are for splitting and reporting. **They are never features.** `network` in particular could become a shortcut for the label, since only T1105 needs NAT.

| Group | Features | Source |
|---|---|---|
| Tree shape | processes, children of the root, depth, duration | ETW |
| Activity | counts and per-second rates of file create, write, rename, delete, registry set, network connect. Peak file operations in 10 s and peak deletes and renames in 30 s | ETW only |
| Network shape | distinct destination addresses and ports, as counts | ETW only |
| Zones touched | events in document folders, Run key writes, Startup folder and hosts file events, and how many of the four zones were touched | ETW |
| Sysmon signals | LSASS access, `vm_read`, network connections, Run key writes and deletes | Sysmon |
| Signing | unsigned processes, signed fraction, whether the root is signed | ETW |
| FIM | FIM changes linked to a write by this tree | `fim.jsonl` |

- **Counts and rates use ETW only,** so one action is never counted twice (PLANNING.md Section 10). Sysmon gives zone signals.
- **No names, paths or command lines are features.** Paths and keys only answer "which zone is this", through `detection/zones.py`, and the answer leaves as a number. A test renames every image, command line, file name, extension, address and registry value, and checks that no feature changes.
- **Not features, on purpose:** `trusted_path`, rule matches, file extensions, and anything about a name. Rule matches stay out so that what we know about held-out techniques can't leak into the model.
- **FIM links.** A change is linked to the tree whose write to that exact item is nearest in time: up to 120 seconds before it, or 0.5 seconds after it. FIM doesn't say who made a change, so this is the only link. Keys are compared ignoring case and `HKU\<sid>` vs `HKCU`.
  - **Why the half second:** FIM and Sysmon use different clocks. In the first real recordings, FIM's "removed" came 45 ms before the Sysmon delete that caused it.
  - **Checked on real keys:** ETW writes `HKCU\SOFTWARE\...` where FIM and Sysmon write `HKCU\Software\...`. Comparing ignoring case handles that, and changes were linked in the recordings that had them.

## First real recordings (batch 1, v2 labels)

9 sessions gave 400 trees: 7 malicious (5 training, 2 held-out) and 393 benign. Every attack session has exactly one malicious tree, rooted at the test's own process. The harness was left out of 6 sessions (116 to 125 events each). FIM changes were linked in the sessions that had them.

**Problems for step 3.4, not solved here**
- **The T1486 cleanup looks like the attack but is labelled benign.** After the script, a second PowerShell deletes the same 25 documents. In the v2 labels it is `background`, not `harness`, so the model would see two trees with identical document-folder behaviour, one labelled malicious and one benign. Labelling it `harness` would fix it.
- **7 malicious trees against 393 benign is far too few to train on.** Batch 1 is only a first look. The recording plan has 30 training and 9 held-out runs.
- **Some attack trees carry almost no signal.** The T1003.001 test part is 1 process and 2 events, because LSA protection stopped the dump. T1053.005 and T1547.001 have 12 to 14 events.
- **Most benign trees are single processes with no start event** (`observed_start` 0), such as System and long-running services. Step 3.4 should filter them, so "no start event" isn't learned as benign.
- **Many file events have no path,** so they can't be placed in a zone. 22,663 and 7,089 in the two benign sessions.

## Known limits

- **LSASS features may be all 0 in the real data.** With LSA protection on, Windows denies the read and the sensor sees no access event (PLANNING.md 4.3).
- **T1053.005's task runs outside the launcher's tree,** so only the part that creates it is in the attack tree.
- **A wrapper process can mix benign and malicious children in one tree.** The tree's label is malicious if any of its events is, and `n_malicious_events` is written so the mix can be seen.
- **A cleanup process is a separate tree.** After each test, a separate process cleans up. It links to a FIM change that undoes the test's change, so one test can link one change to the test and one to the cleanup. Marking cleanup as `harness` in the labels drops it.
- **Zone patterns are a first list.** `detection/zones.py` lists the document folders, which a user's own folders could escape.

```bash
uv run pytest tests/test_features.py
```
