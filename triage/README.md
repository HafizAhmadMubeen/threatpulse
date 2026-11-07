# ThreatPulse triage: features and the behavioural model

`triage/features.py` is PHASES.md step 2.8. It turns a recorded session into one row per **process tree**. `triage/train.py` and `triage/score.py` are steps 3.4 and 3.5: [training and scoring](#training-and-scoring-steps-34-and-35), **preliminary**.

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

## Training and scoring (steps 3.4 and 3.5)

**PRELIMINARY. 2 of 11 batches exist, with 5 training positives per batch. These results show that the pipeline works. They do not say how well the model detects.** Batch 3 waits for Track A to decide which of its two overlapping sets to use.

```bash
uv run python -m triage.train \
  --batch 1 /mnt/e/threatpulse-data/vm-export/batch-01 /mnt/e/threatpulse-data/vm-export/batch-01-labels-v3 \
  --batch 2 /mnt/e/threatpulse-data/vm-export/batch-02 /mnt/e/threatpulse-data/vm-export/batch-02-labels-v2 \
  --out data/runs/training-prelim            # --no-save to skip writing triage/models/
```

Inputs are only read, and `--out` inside an input is refused. It writes `report.json` and `report.txt`, and saves the model to `triage/models/` (gitignored).

**What goes into the training set** (`triage/dataset.py`)
- Features from the test part only: the harness is left out, and events before each session's `start_utc` are dropped (sensor start and warm-up). Labels come from the separate labels folder, since each recording's own `labels.csv` is the old one.
- Positives are trees with test-part malicious events. Negatives are every benign tree, including the background trees of attack sessions.
- Only trees whose start was observed are used. The rest are listed in the class-balance table as dropped.
- **Split by whole batch.** Each batch is tested in turn by a model trained on the others. Never by event or by session.
- **Held-out techniques** (T1053.005, T1685, T1218.011) are only evaluated. A held-out session is kept out of training whole, background trees included, and a loader check stops the run if a session's pool and technique disagree. T1685 has no recording yet.
- Class weights: positives weigh `negatives / positives`. That makes the scores **uncalibrated**: they rank trees and are not probabilities, so the policy's 0.80 threshold means something else here and must be re-chosen on all 11 batches.

**The model** (`triage/model.py`)
- XGBoost, depth 3, 60 rounds, fixed in advance. Nothing is tuned on test or held-out data.
- `MODEL_FEATURES` is `FEATURE_COLUMNS` without `n_fim_changes_linked`: a tree's own events (what `score_process` receives) hold no FIM events, so at scoring time it would always be 0. The policy's persistence rule handles FIM changes whatever the score is.
- Saved as XGBoost JSON, never pickle. A sidecar `.meta.json` holds the feature order, the training batches and sessions, and the model's SHA-256. This catches a damaged or mismatched file. It is not a signature: whoever can write the folder can write both.

**`score_process`** returns `None` (never 0.0) when there is no model, the model is damaged or has other features, the events are not one single tree whose start was observed, or anything is malformed. The pipeline passes it the tree that contains the alerting process, cut at an unobserved parent the way training cuts trees (`events_of_tree_containing`). `score.is_stub()` says whether a model is loaded; tests use an empty model folder (`tests/conftest.py`).

### Preliminary results (batches 1 and 2, 2026-11-07)

Balance of usable trees: batch 1 has 5 training positives and 117 negatives (220 trees dropped for no start event), batch 2 has 5 and 44 (162 dropped). Held-out: 2 positives and 1 negative in batch 1, 2 and 7 in batch 2.

| Train on, test on | Test trees | Precision | Recall | False-positive rate |
|---|---|---|---|---|
| batch 2, test batch 1 | 5 + / 117 − | 0.29 (0.13 to 0.53), 5 of 17 flagged | 1.00 (0.57 to 1.0), 5 of 5 | 0.10 (0.06 to 0.17), 12 of 117 |
| batch 1, test batch 2 | 5 + / 44 − | 1.00 (0.51 to 1.0), 4 of 4 flagged | 0.80 (0.38 to 0.96), 4 of 5 | 0.00 (0 to 0.08), 0 of 44 |

Same at 0.50 and 0.80. Brackets are Wilson 95% intervals. Held-out techniques, scored by the model trained on the other batch:

| Test batch | T1218.011 | T1053.005 | Negatives flagged |
|---|---|---|---|
| 1 | 0.96 | 0.98 | 0 of 1 |
| 2 | 0.84 | 0.76 | 0 of 7 (recall at 0.80 is 1 of 2) |

- **The 12 false positives** are tiny benign trees (2 to 15 events, 1 to 3 processes, under 3 s) in the two benign sessions. The attack trees are tiny as well (2 to 14 events), and 44 training negatives from one batch do not cover that shape.
- **Missed:** the T1003.001 tree (2 events, 0.12) when training on batch 1. LSA protection blocked the dump, so there is almost nothing to see.
- **Score as a tree grows.** The gap is **large**. For example T1547.001 scores 0.26 or 0.12 on its first 10% of events and 0.98 on all of them, while a benign tree can score 0.95 to 0.98 on its first 10% to 25%. Early alert-time scores are not usable, and training on prefix snapshots is the next step, as agreed.
- **Pipeline replay at alert time:** every scored alert gets 0.88 to 0.98, including benign sessions (Edge's autolaunch). The replay tree still holds the wrapper that runs each test, which training left out, and the tree is partial. **With the model loaded, the replay plans `suspend` for benign Edge alerts, so do not let this model's scores drive policy yet.**
- The scoring path and the training path give the same features (maximum difference 0.0, tested).

### Prefix-snapshot training (step 3.4, second version)

Alert-time scores are computed on a partial process tree, so training on complete trees only mismatches what the pipeline scores. The training set now holds **snapshots**: each usable tree as it looked after 10%, 25%, 50%, 75% and 100% of its own time span (`triage/dataset.py`, `snapshot_rows`).
- A snapshot keeps its tree's label. Benign trees get snapshots too, so the model sees partial benign trees as well as partial attacks.
- A partial snapshot needs at least 2 events (a lone process start looks the same for every program). The whole tree is always a snapshot, so no complete-tree row is lost. Two cuts that keep the same events are one snapshot.
- Features come from the same function `score_process` runs, built from the tree's events alone: no label, harness or file is read.
- Snapshots are made on the training side only. Evaluation is still by whole batch and held-out techniques stay out of training.
- The fractions and the minimum were fixed before any result was seen. One correction was made while building the set: the first draft required 2 events for every snapshot, which would have dropped the 58 single-event trees of batch 1 and confounded the comparison, so the whole tree is always kept.

`python -m triage.train` trains the complete-tree model and the snapshot model side by side in every fold, so the comparison is like for like. The saved model is the snapshot model.

**Skew, measured two ways** (batches 1 and 2, PRELIMINARY: a handful of attack trees)
1. *Snapshots of the test trees:* the score at each fraction against the score of the complete tree.
2. *Pipeline replay:* each alert's score when it fires (partial tree) against the score of the same tree at the end of the recording. Both are label-free and contain the wrapper that runs each test.

| | train batch 2, test batch 1 | | train batch 1, test batch 2 | |
|---|---|---|---|---|
| | complete | snapshots | complete | snapshots |
| Complete test trees at 0.50 or 0.80 | TP 5, FP 12 of 117, FN 0 | TP 4, FP 7 of 117, FN 1 | TP 4, FP 0 of 44, FN 1 | TP 4, FP 0 of 44, FN 1 |
| Held-out techniques at 0.80 (recall) | 2 of 2 | 2 of 2 | 1 of 2 | 2 of 2 |
| Attack score vs complete tree, \|difference\|, at 25 to 75% | 0.003 to 0.03 | 0.0005 to 0.005 | **0.79 to 0.87** | **0.008 to 0.05** |
| Attacks still flagged at 0.5 early (25 to 75%) | 7 of 7 | 7 of 7 | **1 of 7** | **7 of 7** |
| Benign trees flagged early only (partial at 0.5, complete below) | 1, 1, 2 of 14, 10, 52 | 1, 1, 1 of 14, 10, 52 | 0 | 0 |
| Alert time vs complete tree, max \|difference\| (scored alerts) | 0.76 (9) | 0.95 (9) | 0.76 (8) | 0.18 (8) |
| Benign-session alerts at or above 0.8 at alert time | 1 | 1 | 1 | 0 |

How to read it:
- **The skew for attacks went away where it was large** (second fold: from about 0.8 down to under 0.05, and 7 of 7 attacks stay flagged early instead of 1 of 7). In the first fold the complete model had little attack skew already, so there is nothing to show.
- **The snapshot model is not clearly better on false positives.** Complete trees: FP 12 down to 7 in one fold, at the price of one missed attack (recall 5 of 5 to 4 of 5); unchanged in the other.
- **One benign alert still scores 0.8 or more at alert time in the first fold**, with both models, and the snapshot model's worst alert-time difference got larger (0.95). Alert-time scoring still must not drive policy: `--use-model` stays off by default.
- Every group here has between 1 and 9 attack trees, so these are differences of a few trees, not rates. The intervals in `report.json` say so.

### Scoring scope: label-free (step 3.5)

`score_process(events)` takes **events and nothing else**. At runtime it sees:
- the events of **one process tree**: the alerting process, its descendants, and its ancestors up to the first one whose start was never seen (`events_of_tree_containing`, the tree definition training used). Only events up to the moment of the alert, from the agent only, with no FIM events;
- from them, counts, rates, zones touched and signing. A path or key is read only to answer "which zone is this", and the answer leaves as a number.

It does **not** see, read or open: labels, `labels.csv`, `session.json`, `start_utc`, the harness (it can't know which process that is), a process name, a path, a command line, any file, the network, or earlier scores.

How training differs from runtime, and what that costs:

| | Training | Runtime |
|---|---|---|
| Positives and negatives | from labels | none: the score ranks, nothing is "known" |
| Harness (the wrapper that runs a test) | left out, using the `part` label | **inside the tree** if its start was seen |
| Events before `start_utc` (sensor start, warm-up) | dropped | present |
| Tree size | snapshots of complete trees | the tree as it is at the alert |
| FIM events | used to build the tree's FIM count, but the model leaves that column out | not in the tree |

The harness and the start-up events exist only in lab recordings. A real endpoint has no harness, but a replay of our recordings does, so replayed alert-time scores describe a harder case than training saw. The pipeline-replay rows in the skew table above are measured this way, label-free.

Enforced by tests: scoring opens no file at all (every file read is blocked while it runs), extra label fields on events change nothing, renaming every process, path, command line and address changes nothing, the scorer and the pipeline's run module never name label files, and `score_process`'s only parameter is `events`.
