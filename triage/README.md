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

**PRELIMINARY. 4 of 11 batches are used, with 4 ordinary attack trees per batch (and T1003.001 apart). These results show that the pipeline works. They do not say how well the model detects.** Batch 3 is its second run only (9 valid sessions, decided by the repository lead). The tables for 2 and 3 batches below are the earlier runs, kept for comparison. **Since the last section, T1003.001 trees are left out of training by default** (a tree of 2 events has no behaviour to learn), and `--include-limited-in-training` puts them back. Batch 4 (7 sessions) is added in the last section.

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

### Batch 3 added (3 of 11 batches, step 3.4 third run)

Batch 3 is the second run only: 9 sessions, labels in `batch-03-labels` (`--only-labelled`). The 6 sessions of the first attempt are left out as a whole and listed by name in the report. Split by whole batch: each batch is tested by a model trained on the other two. Batch 3 is one batch with a busier background than batches 1 and 2 (the VM had been up for over 1 h 40 min), so it is kept together. T1685 is still not recorded, so the held-out techniques are T1053.005 and T1218.011. Batch 4 exists in the export and is not used.

Complete test trees at **0.80**, with the 2-batch run beside the 3-batch run (`complete` = trained on complete trees, `snapshots` = trained on prefix snapshots; each test batch is tested by a model that never saw it). Count is TP, FN, then false positives of negatives.

| Test batch | 2 batches: complete | 2 batches: snapshots | 3 batches: complete | 3 batches: snapshots |
|---|---|---|---|---|
| 1, ordinary | TP 5 FN 0, FP 12/117 | TP 4 FN 1, FP 7/117 | TP 5 FN 0, FP 4/117 | TP 3 FN 2, FP 1/117 |
| 1, held-out | TP 2 FN 0, FP 0/1 | TP 2 FN 0, FP 0/1 | TP 1 FN 1, FP 0/1 | TP 2 FN 0, FP 0/1 |
| 2, ordinary | TP 4 FN 1, FP 0/44 | TP 4 FN 1, FP 0/44 | TP 3 FN 2, FP 0/44 | TP 2 FN 3, FP 0/44 |
| 2, held-out | TP 1 FN 1, FP 0/7 | TP 2 FN 0, FP 0/7 | TP 2 FN 0, FP 0/7 | **TP 0 FN 2**, FP 0/7 |
| 3, ordinary | not tested | not tested | TP 4 FN 1, FP 1/112 | TP 4 FN 1, FP 4/112 |
| 3, held-out | not tested | not tested | TP 2 FN 0, FP 1/11 | TP 2 FN 0, FP 0/11 |
| **Sum of the test batches, ordinary** | recall 9/10, FP 12/161 | recall 8/10, FP 7/161 | recall 12/15, FP 5/273 | recall 9/15, FP 5/273 |
| **Sum of the test batches, held-out** | recall 3/4, FP 0/8 | recall 4/4, FP 0/8 | recall 5/6, FP 1/19 | recall 4/6, FP 0/19 |

Sums add up per-batch counts from different models. They are not one model's results.

Skew between partial and complete trees (snapshots of the test trees at 25, 50 and 75% of their time span, and pipeline alerts, label-free):

| | 2 batches: complete | 2 batches: snapshots | 3 batches: complete | 3 batches: snapshots |
|---|---|---|---|---|
| Attacks still flagged at 0.5 early | 8 of 14 | 14 of 14 | 5 of 21 | 20 of 21 |
| Worst attack \|difference\| to the complete tree | 0.87 | 0.05 | 0.95 | 0.91 |
| Benign trees flagged early only | 3 | 2 | 5 | 5 |
| Benign-session alerts at or above 0.8 at alert time (batch 1, 2, 3) | 1, 1, - | 1, 0, - | 1, 1, 1 | 1, 0, 0 |
| Malicious-session alerts at or above 0.8 at alert time | 8/8, 7/7, - | 8/8, 7/7, - | 8/8, 6/7, 8/8 | 8/8, **2/7**, 8/8 |
| Alert time vs complete tree, max \|difference\| | 0.76, 0.76 | 0.95, 0.18 | 0.91, 0.93, 0.95 | 0.96, 0.63, 0.16 |

What the numbers say, and don't:
- **False positives went down with more data, for both models:** 12 of 161 and 7 of 161 became 5 of 273 (1.8%). More benign trees in training helps, as expected.
- **Recall at 0.80 went down, most for the snapshot model:** 9 of 15 against 12 of 15 for the complete model. Test batch 2 is the weak one for both: adding batch 3, with its busier background, took recall on batch 2 from 4 of 5 to 3 of 5 (complete) and 2 of 5 (snapshots). At 0.50 the snapshot model keeps 3 of 5, and the held-out pair in batch 2 drops from 2 of 2 to 0 of 2 at 0.80. Scores are uncalibrated and the threshold was not tuned, so this is as much a threshold effect as a model one. It needs leave-one-batch-out over more batches.
- **Snapshot training still keeps attacks flagged early** (20 of 21 against 5 of 21), which is what it was for. The skew is not gone: one attack tree has a 0.91 difference at 25% of its span, in the batch 3 fold.
- **At alert time the snapshot model scores fewer benign alerts at or above 0.8** (1 of 3 batches against 3 of 3), but in batch 2 only 2 of 7 malicious-session alerts reach 0.8. Alert-time scoring is still not ready to drive policy, so `--use-model` stays off by default.
- **There is no clear winner.** Each group has 1 to 9 attack trees, so every difference above is a few trees. The intervals in `report.json` say so.
- **The saved model** is the snapshot model trained on batches 1 to 3 (21 training sessions), SHA-256 `dc2907908b81758a9e67b33f23110423deaf8a40692e9aad58ec89a4a1dcf0cd`. It stays local and gitignored.

```bash
uv run python -m triage.train --only-labelled \
  --batch 1 $E/batch-01 $E/batch-01-labels-v3 --batch 2 $E/batch-02 $E/batch-02-labels-v2 \
  --batch 3 $E/batch-03 $E/batch-03-labels --out data/runs/training-snap-123
```

### Batch 4 added: leave-one-batch-out over 4 batches (4 of 11)

Batch 4 is 7 sessions, all labelled (`batch-04-labels`): T1003.001, T1059.001, T1486, T1547.001 twice, and 2 benign. It has no held-out technique, so the held-out pair (T1053.005, T1218.011) has no new trees. T1685 is still not recorded. Each batch is tested by a model trained on the other three (whole-batch split). Three things changed in how results are reported:
- **Counts and intervals.** Every rate is a count with its Wilson 95% interval, for example `15 of 16 (93.8%, 95% CI 71.7% to 98.9%)`.
- **T1003.001 is reported apart.** LSA protection blocks the dump, so its test part has about 2 events. It is a documented limitation and never counts toward recall (recall below is over the ordinary attacks: T1486, T1547.001 twice, T1059.001). In the batch 4 run it was still in training; the default has since changed (see the last section).
- **Threshold.** The fixed 0.50 and 0.80 are reported as they are. A threshold is also *chosen on the training folds only*: for each test batch, leave-one-batch-out inside the other batches, then the lowest value in {0.5, 0.6, 0.7, 0.8, 0.9, 0.95} whose pooled false-positive rate is at most 2%. The rule was fixed before any result was seen. Held-out trees and T1003.001 are not used for choosing, and the test batch is never looked at (a test checks that changing it does not move its threshold). 0.80 is not tuned anywhere.

3 batches here is the earlier 3-batch run re-done with the same code, so T1003.001 is apart and the two columns are comparable. (The first 3-batch table counted it inside recall: 12 of 15 and 9 of 15.) Each batch was scored by a different model, so a sum is not one model's result.

| complete model, summed over the held-out batches | 3 batches | 4 batches |
|---|---|---|
| Ordinary attacks caught, at 0.50 | 11 of 12 (91.7%, 95% CI 64.6% to 98.5%) | 15 of 16 (93.8%, 95% CI 71.7% to 98.9%) |
| Benign trees flagged, at 0.50 | 9 of 273 (3.3%, 95% CI 1.7% to 6.1%) | 9 of 387 (2.3%, 95% CI 1.2% to 4.4%) |
| Ordinary attacks caught, at 0.80 | 11 of 12 (91.7%, 95% CI 64.6% to 98.5%) | 15 of 16 (93.8%, 95% CI 71.7% to 98.9%) |
| Benign trees flagged, at 0.80 | 5 of 273 (1.8%, 95% CI 0.8% to 4.2%) | 3 of 387 (0.8%, 95% CI 0.3% to 2.3%) |
| Ordinary attacks caught, at the threshold chosen on training folds | 11 of 12 (91.7%, 95% CI 64.6% to 98.5%) | 15 of 16 (93.8%, 95% CI 71.7% to 98.9%) |
| Benign trees flagged, at the threshold chosen on training folds | 0 of 273 (0%, 95% CI 0% to 1.4%) | 2 of 387 (0.5%, 95% CI 0.1% to 1.9%) |
| Held-out attacks caught, at 0.80 | 5 of 6 (83.3%, 95% CI 43.6% to 97%) | 6 of 6 (100%, 95% CI 61% to 100%) |
| Held-out benign flagged, at 0.80 | 1 of 19 (5.3%, 95% CI 0.9% to 24.6%) | 0 of 19 (0%, 95% CI 0% to 16.8%) |
| Held-out attacks caught, at the threshold chosen on training folds | 2 of 6 (33.3%, 95% CI 9.7% to 70%) | 6 of 6 (100%, 95% CI 61% to 100%) |
| Held-out benign flagged, at the threshold chosen on training folds | 0 of 19 (0%, 95% CI 0% to 16.8%) | 0 of 19 (0%, 95% CI 0% to 16.8%) |
| T1003.001 flagged at 0.80 (NOT in recall) | 1 of 3 | 2 of 4 |
| Attacks still flagged at 0.50 on 25 to 75% of their span | 5 of 21 (23.8%, 95% CI 10.6% to 45.1%) | 10 of 30 (33.3%, 95% CI 19.2% to 51.2%) |
| Benign trees flagged early only | 5 of 222 (2.3%, 95% CI 1% to 5.2%) | 11 of 314 (3.5%, 95% CI 2% to 6.2%) |
| Benign-session alerts at or above 0.80 when they fire | 3 of 3 (100%, 95% CI 43.8% to 100%) | 3 of 3 (100%, 95% CI 43.8% to 100%) |
| Malicious-session alerts at or above 0.80 when they fire | 20 of 21 (95.2%, 95% CI 77.3% to 99.2%) | 25 of 26 (96.2%, 95% CI 81.1% to 99.3%) |

| snapshots model, summed over the held-out batches | 3 batches | 4 batches |
|---|---|---|
| Ordinary attacks caught, at 0.50 | 11 of 12 (91.7%, 95% CI 64.6% to 98.5%) | 15 of 16 (93.8%, 95% CI 71.7% to 98.9%) |
| Benign trees flagged, at 0.50 | 10 of 273 (3.7%, 95% CI 2% to 6.6%) | 10 of 387 (2.6%, 95% CI 1.4% to 4.7%) |
| Ordinary attacks caught, at 0.80 | 9 of 12 (75%, 95% CI 46.8% to 91.1%) | 15 of 16 (93.8%, 95% CI 71.7% to 98.9%) |
| Benign trees flagged, at 0.80 | 5 of 273 (1.8%, 95% CI 0.8% to 4.2%) | 6 of 387 (1.6%, 95% CI 0.7% to 3.3%) |
| Ordinary attacks caught, at the threshold chosen on training folds | 9 of 12 (75%, 95% CI 46.8% to 91.1%) | 15 of 16 (93.8%, 95% CI 71.7% to 98.9%) |
| Benign trees flagged, at the threshold chosen on training folds | 2 of 273 (0.7%, 95% CI 0.2% to 2.6%) | 6 of 387 (1.6%, 95% CI 0.7% to 3.3%) |
| Held-out attacks caught, at 0.80 | 4 of 6 (66.7%, 95% CI 30% to 90.3%) | 6 of 6 (100%, 95% CI 61% to 100%) |
| Held-out benign flagged, at 0.80 | 0 of 19 (0%, 95% CI 0% to 16.8%) | 0 of 19 (0%, 95% CI 0% to 16.8%) |
| Held-out attacks caught, at the threshold chosen on training folds | 3 of 6 (50%, 95% CI 18.8% to 81.2%) | 6 of 6 (100%, 95% CI 61% to 100%) |
| Held-out benign flagged, at the threshold chosen on training folds | 0 of 19 (0%, 95% CI 0% to 16.8%) | 0 of 19 (0%, 95% CI 0% to 16.8%) |
| T1003.001 flagged at 0.80 (NOT in recall) | 0 of 3 | 2 of 4 |
| Attacks still flagged at 0.50 on 25 to 75% of their span | 20 of 21 (95.2%, 95% CI 77.3% to 99.2%) | 28 of 30 (93.3%, 95% CI 78.7% to 98.2%) |
| Benign trees flagged early only | 5 of 222 (2.3%, 95% CI 1% to 5.2%) | 8 of 314 (2.5%, 95% CI 1.3% to 4.9%) |
| Benign-session alerts at or above 0.80 when they fire | 1 of 3 (33.3%, 95% CI 6.1% to 79.2%) | 1 of 3 (33.3%, 95% CI 6.1% to 79.2%) |
| Malicious-session alerts at or above 0.80 when they fire | 16 of 21 (76.2%, 95% CI 54.9% to 89.4%) | 25 of 26 (96.2%, 95% CI 81.1% to 99.3%) |

Per test batch, 4 batches:

complete model:

| Test batch | Threshold chosen on training folds | Ordinary attacks caught at 0.80 | Benign flagged at 0.80 | Held-out caught at 0.80 | T1003.001 score (events) |
|---|---|---|---|---|---|
| 1 | 0.9 | 4 of 4 (100%, 95% CI 51% to 100%) | 2 of 117 (1.7%, 95% CI 0.5% to 6%) | 2 of 2 (100%, 95% CI 34.2% to 100%) | 0.8965 (2) |
| 2 | 0.8 | 3 of 4 (75%, 95% CI 30.1% to 95.4%) | 0 of 44 (0%, 95% CI 0% to 8%) | 2 of 2 (100%, 95% CI 34.2% to 100%) | 0.0352 (2) |
| 3 | 0.9 | 4 of 4 (100%, 95% CI 51% to 100%) | 0 of 112 (0%, 95% CI 0% to 3.3%) | 2 of 2 (100%, 95% CI 34.2% to 100%) | 0.0208 (2) |
| 4 | 0.8 | 4 of 4 (100%, 95% CI 51% to 100%) | 1 of 114 (0.9%, 95% CI 0.2% to 4.8%) | none | 0.9138 (2) |

snapshots model:

| Test batch | Threshold chosen on training folds | Ordinary attacks caught at 0.80 | Benign flagged at 0.80 | Held-out caught at 0.80 | T1003.001 score (events) |
|---|---|---|---|---|---|
| 1 | 0.8 | 4 of 4 (100%, 95% CI 51% to 100%) | 2 of 117 (1.7%, 95% CI 0.5% to 6%) | 2 of 2 (100%, 95% CI 34.2% to 100%) | 0.8515 (2) |
| 2 | 0.7 | 3 of 4 (75%, 95% CI 30.1% to 95.4%) | 0 of 44 (0%, 95% CI 0% to 8%) | 2 of 2 (100%, 95% CI 34.2% to 100%) | 0.3156 (2) |
| 3 | 0.5 | 4 of 4 (100%, 95% CI 51% to 100%) | 4 of 112 (3.6%, 95% CI 1.4% to 8.8%) | 2 of 2 (100%, 95% CI 34.2% to 100%) | 0.0308 (2) |
| 4 | 0.8 | 4 of 4 (100%, 95% CI 51% to 100%) | 0 of 114 (0%, 95% CI 0% to 3.3%) | none | 0.8856 (2) |

What the numbers say, and don't:
- **Ordinary attacks: 15 of 16 caught with both models at 0.80** (93.8%, 95% CI 71.7% to 98.9%), against 11 of 12 (complete) and 9 of 12 (snapshots) on 3 batches. Benign trees flagged at 0.80: 3 of 387 (0.8%) for the complete model and 6 of 387 (1.6%) for the snapshot model. Held-out techniques: 6 of 6 caught (CI 61% to 100%), 0 of 19 benign flagged for the snapshot model.
- **The one miss is T1059.001 in batch 2** (score 0.08 complete, 0.35 snapshots). It is caught in the other three batches (0.96 to 0.99).
- **The sample is smaller than the counts say.** The attacks are the same scripted tests run again in every batch (the two T1547.001 trees in a batch get the same score), so 16 trees are about 4 behaviours seen 4 times. Trees from different batches are not independent draws, and the intervals do not account for that.
- **T1003.001 scores swing from 0.01 to 0.91** on trees of 2 events, and 2 of 4 were above 0.80 for the complete model. That is a near-empty tree landing at a random place in the model, not detection, and it is why it is not counted. Because these trees are in training as positives, they may teach the model that tiny trees are malicious. Leaving them out of training is tested in the last section, and is now the default.
- **Thresholds.** With 3 batches the inner folds train on a single batch, no value met the 2% cap in 4 of 6 fold models, the rule fell back to 0.95, and held-out recall at the chosen threshold was 2 of 6 for the complete model. With 4 batches the cap is met in every fold (chosen 0.5 to 0.9) and the results match the fixed 0.80: 15 of 16 caught, 6 of 6 held-out. So the rule needs three or more training batches to be useful.
- **Proposed threshold for the saved model: 0.7.** It is chosen by leave-one-batch-out over the same four batches the model is trained on (15 of 16 attacks caught, 6 of 387 benign flagged there), so its numbers are in-sample for the choice. It is a proposal and is not applied anywhere: the policy keeps its own thresholds. I would not move the policy off 0.80 on this.
- **Skew.** Snapshot training keeps attacks flagged early: 28 of 30 (93.3%, 95% CI 78.7% to 98.2%) against 10 of 30 (33.3%, 95% CI 19.2% to 51.2%) for the complete model. Benign trees flagged early only: 8 of 314 and 11 of 314.
- **At alert time** (pipeline replay) only 3 benign-session alerts were scored in all four batches, so the false-alarm evidence is 3 alerts: the snapshot model put 1 of 3 at 0.80 or more, the complete model 3 of 3. Malicious-session alerts at 0.80 or more: 25 of 26 for both. Alert-time scoring is still not ready to drive policy, so `--use-model` stays off by default.
- **The saved model** is the snapshot model trained on batches 1 to 4 (28 training sessions), SHA-256 `e34707ec2e08e58a5085046b1bc514e778fe4cc083fb4bb8307afcc55b738d78`. It stays local and gitignored. **Superseded** by the default retrain in the last section (SHA-256 `c9ee9046…`).

```bash
uv run python -m triage.train --only-labelled \
  --batch 1 $E/batch-01 $E/batch-01-labels-v3 --batch 2 $E/batch-02 $E/batch-02-labels-v2 \
  --batch 3 $E/batch-03 $E/batch-03-labels --batch 4 $E/batch-04 $E/batch-04-labels \
  --out data/runs/training-lobo-1234
uv run python -m triage.compare "3 batches=data/runs/training-lobo-123/report.json" \
  "4 batches=data/runs/training-lobo-1234/report.json"
```

### Leaving T1003.001 out of training (4 batches)

T1003.001 trees (about 2 events, because LSA protection blocks the dump) are reported apart and never count toward recall. **They are now left out of training by default**, everywhere: the outer folds, the threshold's inner folds and the saved model. `--include-limited-in-training` puts them back. Their benign neighbours in the same sessions stay. The comparison below is the same 4 batches, the same leave-one-batch-out and the same threshold rule, with only this changed. **Both versions are reported**: the column "with T1003.001 in training" is the old default, and "without" is the new one.

| complete model, summed over the held-out batches | with T1003.001 in training | without T1003.001 in training |
|---|---|---|
| Ordinary attacks caught, at 0.50 | 15 of 16 (93.8%, 95% CI 71.7% to 98.9%) | 15 of 16 (93.8%, 95% CI 71.7% to 98.9%) |
| Benign trees flagged, at 0.50 | 9 of 387 (2.3%, 95% CI 1.2% to 4.4%) | 2 of 387 (0.5%, 95% CI 0.1% to 1.9%) |
| Ordinary attacks caught, at 0.80 | 15 of 16 (93.8%, 95% CI 71.7% to 98.9%) | 15 of 16 (93.8%, 95% CI 71.7% to 98.9%) |
| Benign trees flagged, at 0.80 | 3 of 387 (0.8%, 95% CI 0.3% to 2.3%) | 0 of 387 (0%, 95% CI 0% to 1%) |
| Ordinary attacks caught, at the threshold chosen on training folds | 15 of 16 (93.8%, 95% CI 71.7% to 98.9%) | 15 of 16 (93.8%, 95% CI 71.7% to 98.9%) |
| Benign trees flagged, at the threshold chosen on training folds | 2 of 387 (0.5%, 95% CI 0.1% to 1.9%) | 2 of 387 (0.5%, 95% CI 0.1% to 1.9%) |
| Held-out attacks caught, at 0.80 | 6 of 6 (100%, 95% CI 61% to 100%) | 6 of 6 (100%, 95% CI 61% to 100%) |
| Held-out benign flagged, at 0.80 | 0 of 19 (0%, 95% CI 0% to 16.8%) | 0 of 19 (0%, 95% CI 0% to 16.8%) |
| Held-out attacks caught, at the threshold chosen on training folds | 6 of 6 (100%, 95% CI 61% to 100%) | 6 of 6 (100%, 95% CI 61% to 100%) |
| Held-out benign flagged, at the threshold chosen on training folds | 0 of 19 (0%, 95% CI 0% to 16.8%) | 1 of 19 (5.3%, 95% CI 0.9% to 24.6%) |
| T1003.001 flagged at 0.80 (NOT in recall) | 2 of 4 | 0 of 4 |
| Attacks still flagged at 0.50 on 25 to 75% of their span | 10 of 30 (33.3%, 95% CI 19.2% to 51.2%) | 10 of 30 (33.3%, 95% CI 19.2% to 51.2%) |
| Benign trees flagged early only | 11 of 314 (3.5%, 95% CI 2% to 6.2%) | 4 of 314 (1.3%, 95% CI 0.5% to 3.2%) |
| Benign-session alerts at or above 0.80 when they fire | 3 of 3 (100%, 95% CI 43.8% to 100%) | 3 of 3 (100%, 95% CI 43.8% to 100%) |
| Malicious-session alerts at or above 0.80 when they fire | 25 of 26 (96.2%, 95% CI 81.1% to 99.3%) | 25 of 26 (96.2%, 95% CI 81.1% to 99.3%) |

| snapshots model, summed over the held-out batches | with T1003.001 in training | without T1003.001 in training |
|---|---|---|
| Ordinary attacks caught, at 0.50 | 15 of 16 (93.8%, 95% CI 71.7% to 98.9%) | 16 of 16 (100%, 95% CI 80.6% to 100%) |
| Benign trees flagged, at 0.50 | 10 of 387 (2.6%, 95% CI 1.4% to 4.7%) | 6 of 387 (1.6%, 95% CI 0.7% to 3.3%) |
| Ordinary attacks caught, at 0.80 | 15 of 16 (93.8%, 95% CI 71.7% to 98.9%) | 16 of 16 (100%, 95% CI 80.6% to 100%) |
| Benign trees flagged, at 0.80 | 6 of 387 (1.6%, 95% CI 0.7% to 3.3%) | 6 of 387 (1.6%, 95% CI 0.7% to 3.3%) |
| Ordinary attacks caught, at the threshold chosen on training folds | 15 of 16 (93.8%, 95% CI 71.7% to 98.9%) | 16 of 16 (100%, 95% CI 80.6% to 100%) |
| Benign trees flagged, at the threshold chosen on training folds | 6 of 387 (1.6%, 95% CI 0.7% to 3.3%) | 6 of 387 (1.6%, 95% CI 0.7% to 3.3%) |
| Held-out attacks caught, at 0.80 | 6 of 6 (100%, 95% CI 61% to 100%) | 5 of 6 (83.3%, 95% CI 43.6% to 97%) |
| Held-out benign flagged, at 0.80 | 0 of 19 (0%, 95% CI 0% to 16.8%) | 0 of 19 (0%, 95% CI 0% to 16.8%) |
| Held-out attacks caught, at the threshold chosen on training folds | 6 of 6 (100%, 95% CI 61% to 100%) | 6 of 6 (100%, 95% CI 61% to 100%) |
| Held-out benign flagged, at the threshold chosen on training folds | 0 of 19 (0%, 95% CI 0% to 16.8%) | 0 of 19 (0%, 95% CI 0% to 16.8%) |
| T1003.001 flagged at 0.80 (NOT in recall) | 2 of 4 | 0 of 4 |
| Attacks still flagged at 0.50 on 25 to 75% of their span | 28 of 30 (93.3%, 95% CI 78.7% to 98.2%) | 29 of 31 (93.5%, 95% CI 79.3% to 98.2%) |
| Benign trees flagged early only | 8 of 314 (2.5%, 95% CI 1.3% to 4.9%) | 4 of 314 (1.3%, 95% CI 0.5% to 3.2%) |
| Benign-session alerts at or above 0.80 when they fire | 1 of 3 (33.3%, 95% CI 6.1% to 79.2%) | 1 of 3 (33.3%, 95% CI 6.1% to 79.2%) |
| Malicious-session alerts at or above 0.80 when they fire | 25 of 26 (96.2%, 95% CI 81.1% to 99.3%) | 25 of 26 (96.2%, 95% CI 81.1% to 99.3%) |

Counts first, each with its 95% interval. As before, each batch is scored by a different model, so a sum is not one model's result.

What changed, in counts:
- **Benign trees flagged at 0.80, complete model: 3 of 387 became 0 of 387.** At 0.50 it went from 9 to 2 of 387, and benign trees flagged only when partial from 11 to 4 of 314. For the snapshot model, benign trees flagged at 0.80 stayed at 6 of 387 (at 0.50: 10 to 6; flagged only when partial: 8 to 4).
- **Ordinary attacks caught at 0.80:** complete model 15 of 16 both ways. Snapshot model **15 of 16 became 16 of 16**: the T1059.001 tree in batch 2, the only miss, went from 0.35 to 0.82. The complete model still misses it (0.08 and 0.09).
- **T1003.001 scores: flagged at 0.80 went from 2 of 4 to 0 of 4.** That confirms that the earlier 0.85 to 0.91 scores were the model reacting to near-empty trees it had been taught were attacks, and not a detection.
- **One held-out tree is lost at 0.80 for the snapshot model: 6 of 6 became 5 of 6.** It is T1218.011 in batch 2, 0.858 to 0.793, just under the line. At the threshold chosen on the training folds it is 6 of 6 both ways.
- Every group is a handful of trees and the intervals overlap, so none of these differences is established. The direction is consistent: fewer false positives, no loss of recall.

**How a tree counts as limited: by technique, not by size.** A tree is set apart when it is an attack tree (its test part is labelled malicious) whose technique is `T1003.001`. That list is `LIMITATION_TECHNIQUES` in `triage/dataset.py`. The number of events plays no part. So a `T1003.001` tree of 56 events that is only normal PowerShell start-up, with no LSASS access, is left out of training and reported apart exactly like the 2-event ones, and a tiny attack tree of any other technique is not limited and trains. (The `MIN_SNAPSHOT_EVENTS` rule is only about partial snapshots and has nothing to do with this.) Tests cover both cases. The reason for going by technique is that LSA protection blocks the credential dump, so what the test part of a `T1003.001` session holds is the launcher's ordinary behaviour, however many events it has: the technique's behaviour is never in it, and labelling it "attack" would teach the model that ordinary PowerShell start-up is malicious.

**Why it is the default: a 2-event tree has no behaviour to learn.** This is the reason, and it does not rest on the numbers above. A tree of 2 events labelled "attack" has no behaviour signature in it, so a model can only memorise how little there is. With so little in it, such a tree looks like many ordinary tiny benign trees, and training on it can only push those up. The evaluation was run to check that nothing is lost, and it agrees in direction: fewer benign flags, no loss of ordinary recall, and none of the 4 T1003.001 trees scoring high by accident. But the differences are a handful of trees with overlapping intervals, and one held-out tree slipped just under 0.80, so they are not what justifies the choice. Detecting T1003.001 is the rule layer's job (`R-T1003-002` fired in 3 of 4 sessions, see `detection/README.md`), not the model's. The trees are still reported apart and never count toward recall, in either version.

To get the old behaviour back, for a comparison:

```bash
uv run python -m triage.train --only-labelled --include-limited-in-training \
  --batch 1 $E/batch-01 $E/batch-01-labels-v3 --batch 2 $E/batch-02 $E/batch-02-labels-v2 \
  --batch 3 $E/batch-03 $E/batch-03-labels --batch 4 $E/batch-04 $E/batch-04-labels \
  --out data/runs/training-lobo-1234
```

`--use-model` stays off by default and the policy threshold stays at 0.80.

### The saved model with the new default

Retrained on batches 1 to 4 with T1003.001 left out of training (the default), prefix snapshots, 28 training sessions, 50 positive and 754 negative training rows:

- **SHA-256: `c9ee90469b20adb98ab4eff56b22ec209ad177e4c10e9309db7a956e8d0c7ff3`** (it replaces `e34707ec2e08e58a5085046b1bc514e778fe4cc083fb4bb8307afcc55b738d78`, the version trained with T1003.001 in). It is local and gitignored. The run summary prints the SHA-256 of whatever model is loaded.
- The leave-one-batch-out results of this run are identical, number for number, to the explicit "without T1003.001" run in the previous section, so the default reproduces it.
- The threshold the rule proposes for it is **0.5**. It is chosen by leave-one-batch-out over the same four batches the model is trained on, so it is in-sample for the choice, and it is only a proposal. Nothing applies it: the policy threshold stays at **0.80** and `--use-model` stays off by default.

### Pools left out of training and evaluation (`excluded_from_ml_pools`)

Track A's `agent/config/recording_tests.json` lists pools that are never used to train or evaluate the model, under `excluded_from_ml_pools` (today `["fim-test-only"]`: the FIM evidence session, a script that changes persistence items whose Run-key writes look like T1547.001, so a model that saw it would learn the script). `triage/dataset.py` reads that list and applies it:

- A session whose pool is in the list is **skipped before anything else is read**, in the loader that feeds both training and evaluation. It needs no labels. It never reaches training, recall, the threshold's inner folds, the snapshot rows, the class-balance table or the pipeline replays of a run.
- **Skipped sessions are reported by name**, with their pool, in the report (`sessions_left_out_for_an_excluded_pool`, and a line per batch at the top of `report.txt`). The report also records the pool list and the SHA-256 of the file it came from.
- **The list comes from the file and nowhere else.** No pool name is written into the loader.
- **The run stops rather than guess.** If the file is missing, is not JSON, or has no `excluded_from_ml_pools` key (an older plan), the run stops with a message. If a session's pool is neither one of the known pools (`training-technique`, `held-out`, `unassigned`) nor excluded, it stops too, so a new pool can never be loaded as ordinary data. A session whose pool cannot be read is not assumed harmless either.
- **Where the file is.** The key is on `track-a/fim-session` or later, so `agent/config/recording_tests.json` may not exist on this branch yet. Until Track A's branch is merged, pass a copy: `--recording-tests PATH` (the commands in the sections above need it now).

`detection/rule_eval.py` (the rule-layer evaluation) applies the same list with the same code (it imports these functions), so it skips those sessions, lists them by name and stops in the same cases. See `detection/README.md`.
