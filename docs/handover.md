# Continuing the project

This is for whoever picks ThreatPulse up next, including its current owner. It says what exists, how far each part was verified, which branches hold what and in which order to merge them, how to resume the lab VM work, where the data lives, and exactly what to do next for each open item.

It contains no passwords, keys or recorded data. Keep it that way: the repository is public.

Read first, in this order: [README.md](../README.md), [CLAUDE.md](../CLAUDE.md), [PLANNING.md](../PLANNING.md) (Section 2.1 is the release scope), [PHASES.md](../PHASES.md), [ROADMAP.md](../ROADMAP.md), [lab-setup.md](lab-setup.md).

Contents:
1. [Rules to keep](#1-rules-to-keep)
2. [Status per generation](#2-status-per-generation)
3. [Branches and merge order](#3-branches-and-merge-order)
4. [Resuming VM work](#4-resuming-vm-work)
5. [NAT lessons](#5-nat-lessons)
6. [Where the data lives](#6-where-the-data-lives)
7. [Running the tests](#7-running-the-tests)
8. [Open items and exact next steps](#8-open-items-and-exact-next-steps)

---

## 1. Rules to keep

These are in CLAUDE.md and PLANNING.md. They are repeated here because breaking one is the expensive mistake.

- **The LLM never triggers enforcement.** Only the deterministic policy engine acts. `policy/` must never import from the RAG or LLM code and never reads LLM output. A test checks this by reading the code.
- **The LLM has no tools,** and telemetry is data: wrapped in `<telemetry>…</telemetry>` in the user message, never in the system prompt. It is called only after triage, never with raw event streams.
- **Humans approve destructive actions.** Automatic actions are suspend, block network and restore from baseline. Kill and delete need an analyst's approval.
- **VM only.** Anything that changes Windows, runs an attack simulation or enforces something runs in the lab VM, never on the host. Enforcement code refuses to act unless `C:\ThreatPulseLab\LAB_VM` exists, and re-checks the never-suspend list (full path plus a Microsoft-rooted signature, never the name alone) against the live process just before acting.
- **No live malware.** Approved test material only: Atomic Red Team (run by a person in the VM), the EICAR file (created only in the VM; the repository holds its hash and YARA rule), UPX on harmless programs, and our own harmless scripts. On the host use the `THREATPULSE-TEST-MARKER` file.
- **Never touch Defender or Windows settings on the host.** Do not call Windows executables from WSL. Run Claude Code in its default permission mode and read each command before approving it.
- **No secrets, no real data, no logs or screenshots in the repository.** Keys live in a gitignored `.env`; `.env.example` lists the names. Recorded data stays on the large drive.
- **`contracts/` changes need all three team members to agree.**
- **Design decisions are recorded in PLANNING.md.** If a task needs one that is not written there, ask first.
- **Commits:** no Co-Authored-By lines and no "Generated with" text. Use the message you were given.
- **ML rules:** features describe behaviour and never names, paths or command text. Split by whole batch or session, never by event. Report held-out techniques and the false-positive rate. Compute features from the `test` part of `labels.csv` only, and leave the `harness` part out.

---

## 2. Status per generation

Terms: *verified in the VM* means it ran in the lab VM against real Windows behaviour. *Verified on recordings* means it ran in WSL over the exported recordings. *Unit-tested* means tested in WSL against sample data or a fake, and not run in the VM. The authoritative table is PLANNING.md Section 2.1.

### 1st generation: signatures
- **Implemented:** SHA-256 known-bad list, YARA rules (test marker and EICAR), `scan_file` (branch `track-b/signatures`, `detection/`).
- **Verified:** unit-tested, with the test-marker file on the host.
- **Left:** the EICAR check in the VM (section 8.3).

### 2nd generation: heuristics and integrity
- **Implemented:** `pefile` heuristics (section entropy, section names, imports, a packer rule) in the same `scan_file`; File Integrity Monitoring in `agent/fim/` (Run, RunOnce and RunOnceEx keys, the two Startup folders, the hosts file).
- **Verified:** FIM in the VM: 12 of 12 checks on the event-driven path and the 60-second compare. Its Run, RunOnce and RunOnceEx changes appear in the recordings. The heuristics are unit-tested only.
- **Left:** the UPX check in the VM (section 8.3); a recorded hosts-file and Startup-folder change (the FIM evidence session, section 8.2); the EMBER static model (section 8.7), which is future work.

### 3rd generation: behaviour
- **Implemented:** the C++ agent (ETW and Sysmon to `events.jsonl`, with signatures and the Microsoft-root flag), the recorder and labeller, and the behaviour rules (`rules/behaviour/`, `match_rules`).
- **Verified:** the agent, recorder and labeller in the VM (46 sessions, 0 invalid events, no event loss). The rules on recordings: Track B's read-only replay over batches 1 to 6, which fired a rule for the technique in 31 of 34 attack sessions (T1003.001 4 of 5 by `R-T1003-002`, T1105 0 of 2) and produced an alert in 5 of 12 benign sessions. `R-T1486-001` fires on all 3 zip-extraction sessions, and Edge's autolaunch Run value raised the persistence rules in the batch 5 normal-use session.
- **Documented limitations:** T1003.001 and T1105. In both the recorded test parts hold no technique behaviour (section 8.4 for T1105; PLANNING.md 4.3 for T1003.001).
- **Left:** a live run of the agent feeding the pipeline (future work).

### 4th generation: AI and access control
- **Implemented:** the XGBoost triage model and `score_process` (preliminary); the ABAC policy engine; the enforcement actions with undo (suspend and resume, firewall block, restore from the FIM baseline into a quarantine, move-to-quarantine for approved deletes, a gated kill, Controlled Folder Access setup); the ransomware entropy rule `R-T1486-002`; ATT&CK retrieval, the prompt template and the technique-ID validator; the replay pipeline; the API and the dashboard.
- **Verified:** the model on recordings (leave-one-batch-out over batches 1 to 6, preliminary). At the 0.80 threshold it catches 20 of 21 ordinary attacks and flags 5 of 661 benign trees (complete model; 6 of 661 for the snapshots model). Held-out techniques: 5 of 6 for the complete model and 3 of 6 for the snapshots model (6 of 6 at 0.50), with 0 of 19 held-out benign trees flagged. T1003.001 (0 of 5) and T1105 (0 of 2) are documented limitations and are not counted in recall. **Alert-time scoring is worse** (18 of 32 malicious-session alerts at or above 0.80 for the snapshots model, 26 of 32 for the complete model, against 25 of 26 on four batches), so `--use-model` stays off. The `windows-update` session is an outlier (one tree of 741,055 events) and was not ablated. The full tables are in PLANNING.md Section 8.3. The policy engine, the enforcement actions (against a fake Windows API), the entropy rule, the validator, the API and the dashboard are unit-tested.
- **Left:** the enforcement test and the entropy check in the VM (sections 8.5 and 8.6), the live zone demos for ransomware and persistence, and the future-work items: `write_report` (it is a stub today, section 8.8), the approval flow and API authentication (section 8.9).

---

## 3. Branches and merge order

`main` already contains `track-a/agent`, `track-a/sysmon-fim`, `track-c/foundation`, and `track-a/atomic` up to the commit that states the LSASS limitation. Nothing is merged for you: merge through pull requests.

### Which branch holds what

| Branch | Holds | Depends on |
|---|---|---|
| `track-a/atomic` | The remaining documentation commits: the release scope, the LLM decision with `.env.example`, the corrected T1003.001 counts, this handover | `main` |
| `track-a/fim-session` | The FIM evidence session: the `fim-test` entry and `excluded_from_ml_pools` in `agent/config/recording_tests.json`, `agent/tools/vm_fim_session.ps1`, tests, docs | `track-a/atomic` (a few commits behind its tip) |
| `track-b/signatures` | `scan_file` (hash list, YARA, `pefile` heuristics); contract changes: run-based alert IDs, `static_analysis`, `file_scan` | `main` |
| `track-c/rag` | ATT&CK retrieval, technique-ID validator, prompt template; `docs/notes/lane2-doc-updates.md` | `track-b/signatures` |
| `track-b/rules` | Behaviour rules, `match_rules`, feature extraction | `track-c/rag` |
| `track-a/policy-engine` | `decide()` with rules P1 to P6; contract changes: `pending` status, action `target`, `process.microsoft_root` | `track-b/rules` |
| `track-a/enforcement` | `execute()`, undo and the Windows actions, `vm_test_enforcement.ps1`. It also contains `policy-engine` | `track-a/policy-engine` |
| `track-c/orchestrator` | The replay pipeline (detection, policy, report stub) | `track-a/policy-engine` |
| `track-b/entropy` | `R-T1486-002`, policy rule P3b, `--read-files` | `track-c/orchestrator` |
| `track-b/training` | The XGBoost model, `score_process`, leave-one-batch-out evaluation, the rule evaluation. It skips sessions of pools listed in `excluded_from_ml_pools` | `track-b/entropy` |

The Track B, Track C and policy branches form one stack: each contains its parent, so a pull request for a branch shows only its own commits if its parents are merged first.

### Merge order

1. **`track-a/atomic`.** It is independent of the stack, and the Lane 2 notes say to apply their documentation changes after it merges.
2. **`track-a/fim-session`.** It **must merge before `track-b/training`.** Track B's training loader and rule evaluation require the key `excluded_from_ml_pools` in `agent/config/recording_tests.json` and stop with an error if it is missing, and that key exists only on this branch. Merge `track-a/atomic` first. **The merge then conflicts in `PLANNING.md` Section 10, in three adjacent rows.** Resolve it by keeping `atomic`'s "Recording plan" and "Recording batches" rows (46 sessions, batches 1 to 6; the copies on `fim-session` are older) and `fim-session`'s "Dataset fields" row (it names the `fim-test-only` pool). The other `PLANNING.md` changes on both sides merge without conflict. **Two sentences on `fim-session` are out of date after that merge:** the new bullet in `PLANNING.md` Section 8.1 and the paragraph "The FIM evidence session" in `agent/README.md` say that Track B's loaders must still be told to skip the pool, and `track-b/training` already skips it. Reword both.
3. **The stack, in order:** `track-b/signatures`, `track-c/rag`, `track-b/rules`, `track-a/policy-engine`.
4. **`track-a/enforcement`**, any time after `policy-engine`. Merging it before the stack is complete would pull the whole stack into one pull request.
5. **`track-c/orchestrator`, `track-b/entropy`, then `track-b/training`.** Training is last, and it was still receiving commits when this was written.
6. **A documentation sync** from `docs/notes/lane2-doc-updates.md`: one documentation-only branch from `main`, after the branches above are merged, with one commit per target document (`CLAUDE.md`, `README.md`, `PLANNING.md`, `PHASES.md`, `ROADMAP.md`). The notes are instructions, not patches, and they were written against an earlier state of those files, so re-check each item before applying it.

Before merging: `track-b/signatures` and `track-a/policy-engine` change `contracts/`, and such changes need all three members to agree.

At the time of writing, a trial merge of every pair of these branches that shares a file gave exactly one conflict, the one in step 2 above. The other pairs (`ROADMAP.md` between `atomic` or `fim-session` and `enforcement`, and `policy/README.md` and `.gitignore` between `enforcement` and the Track B branches) merge without conflict. Repeat the trial (`git merge-tree <merge-base> <a> <b>`, and look for conflict markers) before merging if any branch has moved.

---

## 4. Resuming VM work

### Snapshots

| Snapshot | What it is |
|---|---|
| `clean-baseline` | The VM after steps 0.1 to 0.5 (Windows, Git, Python, build tools, Sysmon), before Atomic Red Team. Fresh start |
| `atomic-ready-3` | Atomic Red Team installed, FIM baseline taken, installers in place |
| `atomic-ready-3.1` | `atomic-ready-3` with the network adapter on NAT. Batch 3 booted from it |
| **`atomic-ready-3.2`** | **`atomic-ready-3.1` with only the adapter set to host-only. This is the recording base for every later batch** |
| `integration-ready` | Planned (step 4.1), not taken |

Every session ends with an export and a rollback to `atomic-ready-3.2`. The baseline in `C:\ThreatPulseLab\fim` is part of the snapshot, so it returns on every revert. For a NAT batch, boot `atomic-ready-3.2` and set the adapter to NAT (section 5).

### Where things are in the VM
The repository is at `C:\ThreatPulseLab\threatpulse`. The built agent is `agent\build\Release\threatpulse_agent.exe`. The agent tools' virtual environment is `agent\.venv`, created with `pip install --require-hashes -r agent\tools\requirements.txt`. Logs go to `C:\ThreatPulseLab\logs\sessions\<session>`. Atomic Red Team is at `C:\AtomicRedTeam`, pinned to commit `edb5039ae07216bf322fdba07b6f686d7c088a03`. The installers for the install and uninstall sessions are in `C:\ThreatPulseLab\installers`. `docs/lab-setup.md` covers building the VM.

### Getting code into the VM
Code travels by Git. The VM has no network on host-only, so fetch with NAT on, then set the adapter back to host-only before recording, because `record_session.ps1` checks that the adapter matches `-Network`. Do not switch branches in the VM repository while a batch is running.

### Recording
Always in a 64-bit PowerShell opened as administrator, signed in as `lab`, from `C:\ThreatPulseLab\threatpulse`:

```powershell
.\agent\tools\run_batch.ps1 -Batch 9                 # one batch from agent\tools\batch_plan.json, in its fixed order
.\agent\tools\run_batch.ps1 -Batch 6 -FromOrder 4    # resume a batch from a session (after a revert)
.\agent\tools\record_session.ps1 -TestId T1547.001-1 -Run 1 -Network host-only -Batch 1 -Order 1   # one session
.\agent\tools\record_session.ps1 -TestId benign -Run 1 -Network nat -Activity normal-use           # a benign session
```

- A session waits 10 seconds to settle and 60 seconds to warm up, runs the test, runs the cleanup as a separate process (labelled `harness`), waits 30 seconds for late events, stops the sensors and writes `session.json`. Track B computes features from `start_utc`.
- `run_batch.ps1` pauses before each manual benign session and tells the person what to do. If a session fails, it stops: export what finished, revert, resume with `-FromOrder`.
- `record_session.ps1` runs only the tests in `agent/config/recording_tests.json`. The clean-start check fails the session if FIM wrote anything before the test began.
- `agent/tools/start_lab_sensors.ps1 -Start` and `-Stop` start and stop the agent and FIM together.

### Export, label, check
After each batch (PLANNING.md 3.2): stop everything, enable the shared folder `vm-export`, copy **only** `.jsonl` and `.csv` logs, `session.json` and the summary `.txt` files, disable the folder, roll back. Never copy executables, scripts, archives or memory dumps out. On the host, in WSL:

```bash
cd ~/threatpulse/agent
uv run python tools/label_session.py --batch /mnt/e/threatpulse-data/vm-export/batch-NN --out /mnt/e/threatpulse-data/vm-export/batch-NN-labels
uv run python tools/validate_events.py <session>/events.jsonl      # 0 invalid is the pass
uv run python tools/coverage_report.py <session>/events.jsonl      # which programs leave file writes without a path
```

`label_session.py --out` never overwrites a `labels.csv`, and labels must stay out of the batch folder. Sensor health is in each session's `agent_summary.txt`: `Lost by ETW`, `Lost, queue full`, `Handler errors` and `Sysmon read errors` should all be 0. A session as large as the `windows-update` session (section 5) needs about 4 GB of memory to label and several minutes to validate.

---

## 5. NAT lessons

Batch 6 is the only NAT batch recorded, and it taught the following.

1. **OneDrive writes three HKCU RunOnce values early on NAT.** They are `Delete Cached Update Binary`, `Delete Cached Standalone Update Binary` and `Uninstall <version>`, under `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`. They did not appear in every NAT boot: in one boot they never appeared in 22 minutes.
2. **FIM then fails the clean-start check.** FIM's first comparison at start-up reports every difference from the baseline as added, whether the values appeared live during the warm-up or were already there when the sensors started. The check fails if `fim.jsonl` has any bytes after the warm-up, and a retry on the same boot fails the same way, because the values stay until the next sign-in.
3. **The prepared-boot procedure fixes it with no code change.** Boot `atomic-ready-3.2`, set the adapter to NAT, and wait until the three values are present. Sign out and in, so Windows runs and removes them. Run a FIM check that must report 0 changes. Then run the batch.

   In a normal PowerShell as `lab`, paste once, then repeat the last line each minute (it stops by itself at 3 of 3):
   ```powershell
   $RunOnce = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
   $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
   function Show-Status {
       $item = Get-ItemProperty -Path $RunOnce -ErrorAction SilentlyContinue
       $names = @($item.PSObject.Properties.Name | Where-Object { $_ -notlike 'PS*' })
       $count = @('Delete Cached Update Binary', 'Delete Cached Standalone Update Binary') |
           Where-Object { $names -contains $_ } | Measure-Object | Select-Object -ExpandProperty Count
       if ($names | Where-Object { $_ -like 'Uninstall *' }) { $count++ }
       $wu = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-WindowsUpdateClient/Operational'; StartTime = $boot } `
           -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'download|install' }).Count
       $busy = @(Get-Process -Name TiWorker -ErrorAction SilentlyContinue).Count
       '{0:HH:mm:ss}  OneDrive RunOnce {1} of 3 | update download/install events {2} | TiWorker {3}' -f (Get-Date), $count, $wu, $busy
       return $count
   }
   do { $n = Show-Status; if ($n -lt 3) { Start-Sleep -Seconds 60 } } while ($n -lt 3)
   ```
   Then `logoff`, sign in again, open a new PowerShell and paste the block again. Wait for OneDrive's setup to finish and confirm the values are gone:
   ```powershell
   while (Get-Process -Name OneDriveSetup, OneDriveStandaloneUpdater -ErrorAction SilentlyContinue) { 'OneDrive setup still running'; Start-Sleep -Seconds 15 }
   Get-ItemProperty $RunOnce | Select-Object * -ExcludeProperty PS*      # prints nothing
   ```
   The FIM check, in a 64-bit PowerShell as administrator (it only reads the baseline, writes a scratch file, and must be stopped before the batch):
   ```powershell
   cd C:\ThreatPulseLab\threatpulse
   agent\.venv\Scripts\python agent\fim\main.py watch --out C:\ThreatPulseLab\logs\prep-fim-check.jsonl
   # wait 90 seconds, press Ctrl+C: "Changes reported:             0" is the pass
   Remove-Item C:\ThreatPulseLab\logs\prep-fim-check.jsonl
   ```
   Do not delete the values by hand, replace `baseline.json`, or run `main.py baseline`. If the check reports anything other than the three OneDrive values, stop and investigate. In batch 6 the first check reported the three changes, and the second, after the sign-out and sign-in, reported 0.
4. **Windows Update acts on its own on NAT.** In one boot its first scan ran about 9.5 minutes after boot, the scan that found 37 to 39 updates at about 15 minutes, and the first download at about 16 minutes, with nobody clicking. In the batch 6 boot nothing downloaded on its own in the 28 minutes before the Windows Update session, and the download began after the person opened Settings. Treat these as a guide from two boots. The consequence is that the planned `windows-update` session (the last of batch 6, after the roughly 12-minute install and uninstall session) can only start from an unspoiled update state in a boot of its own, started within about nine minutes of boot. The supported way is `run_batch.ps1 -Batch 6 -FromOrder 4` in a separate, fresh boot. In batch 6 it ran in the same boot, about 28 minutes after boot, and the data was kept with that stated in PLANNING.md Section 10.
5. **The `windows-update` session is huge.** Session 4 holds 1,180,365 events (805 MB), 89% of batch 6, and 611,206 of them are writes by `TiWorker.exe` to the servicing logs and the component store. Track B must weight by process tree, not by event.
6. **Only about two short sessions fit in the first nine minutes of a NAT boot** (an attack session takes 1:45 to 2:00 from one start to the next).

---

## 6. Where the data lives

Recorded data is never in the repository (it is public). It lives on the large drive, `E:\threatpulse-data`, seen from WSL as `/mnt/e/threatpulse-data`:

```
vm-export/
  batch-01 ... batch-06                 exports: one folder per session, named <start>-<test>-run<N>
  batch-01-labels-v3, batch-02-labels-v2   current labels for batches 1 and 2
  batch-01-labels-v2, batch-02-labels       superseded: they left the cleanup as background
  batch-03-labels ... batch-06-labels       labels, with a README in batch-03-labels
```

- **Each session folder** holds `events.jsonl`, `fim.jsonl`, `session.json`, `agent_summary.txt` and `fim_summary.txt`. Each labels folder has one folder per session with a `labels.csv` (`event_id, label, part, technique, pool, session_id, network, warmup_seconds`).
- **`batch-03` holds two runs** from one boot. Only the second run (sessions starting `20261106T1909` to `T1935`, nine sessions) is dataset. The first attempt (six folders starting `20261106T1729` to `T1739`) is excluded, and `batch-03-labels` has labels for the second run only. Load with `--only-labelled`.
- **Valid sessions per batch:** 9, 9, 9 (batch 3, second run), 7, 8 and 4, so 46 in all.
- **Other ignored locations in the repository:** `data/runs/` (replay and evaluation outputs), `data/attack/` (the ATT&CK data, the embedding model and the vector index). Both are gitignored.

**Regenerating.** The exports cannot be regenerated without recording again in the VM (section 4). Everything derived from them can: labels (`label_session.py`, section 4), replay output (`uv run python -m backend.pipeline <session folders> --labels <labels folder> --out data/runs/<name>`), the rule evaluation (`detection/README.md`, "Rule evaluation") and the model (`triage/README.md`, "Training and scoring"). Do not invent options; those READMEs give the exact commands. Keep a copy of the exports somewhere other than one drive.

---

## 7. Running the tests

| Suite | Where | Command |
|---|---|---|
| Root suite (detection, rules, policy, enforcement, triage, backend, RAG, contracts) | WSL, repo root | `uv sync` then `uv run pytest` |
| ATT&CK-dependent tests | WSL | `uv run python -m backend.rag.fetch` and `uv run python -m backend.rag.index`, then `uv run pytest`. Without them those tests are skipped |
| Agent tools, FIM and the recording tools | WSL | `cd agent && uv sync && uv run pytest` |
| Contract samples | WSL | `uv run python contracts/validate_samples.py` |
| Dashboard | WSL | `cd frontend && npm install`, then `npm test`, `npm run typecheck`, `npm run build` |
| C++ agent | VM only | `cmake -S agent -B agent\build -A x64` then `cmake --build agent\build --config Release` (always Release) |
| Agent checks | VM only | `agent/tools/vm_test_activity.ps1` then `check_test_run.py` (see `agent/README.md`) |
| FIM checks | VM only | `agent/tools/vm_test_fim.ps1` then `check_fim_run.py` (see `agent/fim/README.md`) |
| Enforcement test | VM only | `agent/tools/vm_test_enforcement.ps1` (section 8.5) |
| File-layer checks | VM only | `detection/VM_TEST_PLAN.md` (section 8.3) |

A clean run on the `track-a/enforcement` branch had 724 passed and 20 skipped in the root suite (the skips are the tests that need the downloaded ATT&CK data), and the agent suite had 135 passed on the `track-a/fim-session` branch. Numbers differ by branch. Not every branch contains every suite.

---

## 8. Open items and exact next steps

Each item says what to run and what a pass looks like. After finishing one, update PLANNING.md Section 2.1 (the status table and the counts) and PHASES.md.

### 8.1 Batch 9 (T1685)
Adds the third held-out technique.
1. Revert to `atomic-ready-3.2` (host-only). Open a 64-bit PowerShell as administrator, as `lab`.
2. `cd C:\ThreatPulseLab\threatpulse` then `.\agent\tools\run_batch.ps1 -Batch 9`. It records one session, T1685 #51 run 1, on its own because it tampers with Defender's settings, which FIM cannot see.
3. Export as in section 4 into `vm-export\batch-09`, roll back, label into `batch-09-labels`, validate, and run the coverage report.
4. Never run T1685 tests #14 or #15: they unload and uninstall Sysmon. The recorder only allows #51.
5. Update the counts: 47 sessions, T1685 1 of 3, and the held-out evaluation can then cover three techniques. Batches 10 and 11 (runs 2 and 3) are optional.

### 8.2 The FIM evidence session
Built, unit-tested and ready on the branch `track-a/fim-session`; not run in the VM. It records a hosts-file change and a Startup-folder change as one short session in its own pool, `fim-test-only`, which is kept out of training and evaluation.
1. Boot `atomic-ready-3.2`, set the adapter to NAT, fetch the branch (`git fetch origin`, `git switch track-a/fim-session`), then set the adapter back to host-only.
2. `.\agent\tools\record_session.ps1 -TestId fim-test -Run 1 -Network host-only`
3. Check the session folder: `validate_events.py` on `events.jsonl` and `fim.jsonl`, then `check_fim_run.py <session>\fim.jsonl C:\ThreatPulseLab\logs\fim_test_keys.txt --events <session>\events.jsonl`.
4. Export into a folder of its own (for example `vm-export\fim-test-01`), never into a batch folder, and roll back. Label with `label_session.py --batch` into `fim-test-01-labels`.
5. Merge `track-a/fim-session` before `track-b/training` (section 3, which also lists the conflict to resolve and the two sentences to reword).

### 8.3 EICAR and UPX check (Gate 1)
The full text, with the expected output of every step, is `detection/VM_TEST_PLAN.md` on the branch `track-b/signatures`. In outline, inside the VM only:
1. Take the snapshot `pre-scan-test`. Do not switch branches in a repository a batch is using: use a separate clone, or do this after recording.
2. Create a Python 3.12 virtual environment with `yara-python==4.5.4`, `pefile==2024.8.26` and `jsonschema`. Create `C:\ThreatPulseLab\scan-test` and add a Defender exclusion for that one empty folder, inside the VM only.
3. Marker file: `python -m detection` on it should give hash `TEST-MARKER`, YARA `ThreatPulse_Test_Marker` and one alert `SIG-TEST-MARKER`.
4. EICAR: type the string from eicar.org into Notepad in the VM, save it as `eicar.com` (68 bytes, no BOM, no newline). Expect SHA-256 `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`, hash `EICAR`, YARA `EICAR_Test_File`, and one alert `SIG-EICAR` listing both methods. Never put the string in the repository.
5. UPX: compile a small `hello.c`, pack it with UPX from the official release into `hello_upx.exe`. Pass: `hello.exe` scores 0 to 0.25 with no alert, and `hello_upx.exe` scores 0.50 or more with `HEUR-UPX-PACKED`.
6. Roll back to `pre-scan-test`. Copy nothing out.

### 8.4 The T1105 diagnostic
Why do the T1105 sessions hold no technique behaviour? In both batch 6 sessions the test part is the start and stop of `cmd.exe`: no process started under it, no event names `Atomic-license.txt`, and no connection to the download host is recorded. `MsMpEng.exe` opened a connection while `cmd.exe` was alive, and `SecurityHealthHost.exe` started within 10 ms after it stopped, which is consistent with a Defender block but does not prove one. Run this in a fresh NAT boot, with no recorder and no sensors, in a PowerShell opened as administrator. It has not been run.

**A. Baseline (read-only):**
```powershell
Test-NetConnection raw.githubusercontent.com -Port 443 | Select-Object ComputerName, RemoteAddress, TcpTestSucceeded
Get-MpComputerStatus | Select-Object AMServiceEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, IsTamperProtected, AntivirusSignatureLastUpdated
Get-MpPreference | Select-Object CloudBlockLevel, MAPSReporting, SubmitSamplesConsent, EnableNetworkProtection, ExclusionPath
(Get-MpPreference).AttackSurfaceReductionRules_Ids; (Get-MpPreference).AttackSurfaceReductionRules_Actions
```
Expect `TcpTestSucceeded True` and `C:\AtomicRedTeam` in `ExclusionPath`.

**B. The recorded command, by hand:**
```powershell
Remove-Item "$env:TEMP\Atomic-license.txt" -ErrorAction SilentlyContinue
$t0 = Get-Date; "start: $t0"
cmd.exe /c "powershell.exe iwr -URI https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt -Outfile %temp%\Atomic-license.txt -UseBasicParsing"
"exit code: $LASTEXITCODE"
Get-Item "$env:TEMP\Atomic-license.txt" -ErrorAction SilentlyContinue | Select-Object FullName, Length
```
Then run it the way the recorder does, in a new window, so the text the recorder never saved is visible (`-ShowDetails` first shows the command without running it):
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1' -Force; Invoke-AtomicTest T1105 -TestNumbers 29 -ShowDetails"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1' -Force; Invoke-AtomicTest T1105 -TestNumbers 29 -TimeoutSeconds 120"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1' -Force; Invoke-AtomicTest T1105 -TestNumbers 29 -TimeoutSeconds 120 -Cleanup"
```

**C. The logs around that time:**
```powershell
$since = $t0.AddMinutes(-1)
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Windows Defender/Operational'; StartTime=$since } -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, LevelDisplayName, @{n='Message';e={$_.Message.Split("`n")[0]}} | Format-Table -AutoSize -Wrap
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Windows Defender/Operational'; StartTime=$since; Id=1015,1116,1117,1118,1119,1121,1122 } -ErrorAction SilentlyContinue | Format-List TimeCreated, Id, Message
Get-MpThreatDetection | Where-Object InitialDetectionTime -ge $since | Format-List ThreatID, InitialDetectionTime, ProcessName, Resources, ActionSuccess
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=$since; Id=1,3,11,22 } -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'iwr|Atomic-license|githubusercontent' } | Format-List TimeCreated, Id, Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; StartTime=$since } -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, @{n='Message';e={$_.Message.Substring(0,[Math]::Min(200,$_.Message.Length))}}
```
The Defender event IDs are from Microsoft's event list as remembered (1015 suspicious behaviour, 1116 detection, 1117 action taken, 1118 and 1119 action failed, 1121 and 1122 ASR block and audit); the first command has no ID filter and shows everything.

**What each result means:**

| Result | Meaning |
|---|---|
| File exists, exit 0, Sysmon ID 1 shows the child `powershell.exe` | The command works by hand. The difference is in the recorded boot: timing, Defender's first-seen cloud check, or a sensor gap. Start the sensors with `start_lab_sensors.ps1 -Start`, run the command, stop them, and compare Sysmon ID 1 with `events.jsonl` |
| No file, an "operation … contains a virus" or "Access is denied" style message, and Defender 1116/1117 or 1015 | Defender is blocking by detection or behaviour |
| No file, and 1121 | An ASR rule is blocking. Its ID is in the event |
| No file, exit 1, no Defender events, and a network, DNS or TLS error | A network problem, not Defender |
| Sysmon ID 1 shows no child and the exit is 0 | The command never launched. Compare with the `-ShowDetails` text |

**If Defender is blocking,** the options are: accept T1105 as a documented limitation (no cost, no model signal); put the one blocking ASR rule into audit mode in the VM only (small change, applies only to the NAT boot); a scan exclusion for the output file (it may not help, since it only skips file scanning); or replace the test material with a harmless script of our own (a new script, a documented decision, and a new NAT boot with the preparation of section 5). Do not turn Defender components off: it differs by network mode, adds a hidden second confound, and the project never changes Defender to alter a result. Never touch Defender on the host.

### 8.5 The enforcement test in the VM
On the branch `track-a/enforcement`. It runs every action and its undo on harmless targets (copies of `ping.exe`, a dummy Run value, a dummy Startup file, a dummy file) and never touches a real system process.
1. Prerequisites: a Python 3.12 virtual environment at `C:\ThreatPulseLab\venv-policy` with `pyyaml==6.0.3` and `jsonschema`, and the built agent (the never-suspend re-check uses its `--check-image`).
2. Not while a batch is recording, and not from a snapshot used for recording. In a 64-bit PowerShell as administrator, as `lab`: `.\agent\tools\vm_test_enforcement.ps1`. Add `-SkipNeverSuspend` to skip check 8, and `-TestCfa` to test Controlled Folder Access, which must be last and never before a recording snapshot.
3. Pass: every line `PASS` and exit code 0. Roll back afterwards: the journal and quarantine files stay.

### 8.6 The entropy check in the VM
After a recording and before the rollback, with the test files still present, replay the T1486 session with `python -m backend.pipeline <session> --out data/runs/entropy --read-files`. Expect `R-T1486-001` and `R-T1486-002`, `entropy.bursts_by_verdict` `{"high": 1}`, and decision `P3b-ransomware-entropy` with `suspend` pending. Replay the benign zip session the same way and expect `R-T1486-001` only. Report the sampled files, entropy range and verdict: the thresholds are starting guesses until then. The full text is in `detection/VM_TEST_PLAN.md` on the branch `track-b/entropy`.

### 8.7 The EMBER static model (generation 2)
No code exists. PHASES.md step 2.9: train the static model on EMBER's ready-made feature vectors, with the data on the large drive and not in the repository, and report accuracy on EMBER's test set. EMBER's feature extraction depends on a specific LIEF version, so use a separate virtual environment with pinned versions, and if that blocks, fall back to `pefile` features (PLANNING.md Section 9). Then let `scan_file` carry the score as `static_analysis`, which is shown to analysts and never read by the policy engine. EMBER is used only for the static file model, never for the behaviour model.

### 8.8 `write_report` (the LLM report writer)
Today `backend/pipeline/report_stub.py` makes no LLM call. The prompt template (`backend.rag.prompt.build_messages`, with `is_high_risk` and `reference_for_alert`) and the technique-ID validator (`backend.rag.validator`) exist. To build it:
1. Copy `.env.example` to `.env` (gitignored) and fill in `GEMINI_API_KEY` and, if used, `GROQ_API_KEY`. `LLM_PROVIDER` selects the provider and takes `gemini`, `groq` or `ollama`. Gemini free tier is the primary, local Ollama is the fallback and Groq an alternative. Never put a key in code, logs or commits.
2. Write a provider-agnostic client that reads those three variables. Give the model **no tools**. Send only alerts that `is_high_risk` selects, with the telemetry inside `<telemetry>…</telemetry>` in the user message.
3. Check every technique ID in the result against the ATT&CK data and remove invalid ones or regenerate. Validate the Report against `contracts/`. Replace `report_stub.write_report` in the pipeline.
4. Compare two Gemini models on a sample report, and check that the Ollama fallback produces a valid report.
5. Keep in mind the free-tier limitation: the provider may use prompts to improve its products, so only triaged alerts from the lab VM are ever sent, never raw event streams or personal data.

### 8.9 API authentication and the approval flow
Today the API records an approval or rejection (`reviewed_by`, `reviewed_at`) and nothing acts on it. It has no login, and any local process can call it. Build in this order:
1. Authentication on the backend API, before anything acts on an approval.
2. Connect `POST /decisions/{id}/approve` to `policy.execute` for an approved `request_kill` or `request_delete`, in the VM. `execute` already runs only from status `approved` with a reviewer, refuses outside the lab VM, and moves a deleted file into quarantine.
3. Connect `POST /fim/changes/{id}/approve` to the FIM baseline update and to `undo` of the restore, which puts the quarantined value back.
4. Test with a kill request and a delete request (rules P5 and P6) and with one FIM change, in the VM, and check that a rejection does nothing.
