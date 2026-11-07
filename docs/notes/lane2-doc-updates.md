# Lane 2: pending doc updates

Doc changes from the Track B and Track C work, for the session that edits the docs. Everything below comes from `contracts/`, `detection/` and `backend/rag/` as built on `track-c/rag`.

**Checked against:** `main` at `dbc9f78` and `track-a/atomic` at `198be4a`. Neither has any of these yet, unless an item says so. Earlier changes that are already on `main` aren't listed: the no-process convention, nullable `risk_score`, the FIM approval design, the per-action API body, `GET /fim/changes`, and the no-login risk.

**Apply these after `track-a/atomic` merges.** That branch already edits `CLAUDE.md` line 140, `PLANNING.md` and `PHASES.md`, so applying them first would conflict.

Where the wording matters, the text to use is quoted.

## CLAUDE.md

1. **Team and tracks table:** add `rules/hashes/` to Track B's folders.
2. **Tech stack:**
   - In the RAG line, remove LangChain: `**RAG:** ChromaDB + MITRE ATT&CK STIX data, with no framework.`
   - Add: `**Embeddings:** all-MiniLM-L6-v2 through onnxruntime, local and CPU only.`
3. **Pipeline and interfaces:** `scan_file` returns alerts with no known process. The orchestrator fills in the process when an event triggered the scan (see ROADMAP item 2).
4. **Still open (line 140):** remove ChromaDB vs FAISS. It's decided: ChromaDB. `track-a/atomic` already removes the benign-sessions item.
5. **Current decisions table:** add a row: `| Vector DB | ChromaDB, stored locally. No LangChain |`.
6. **Non-negotiable design rules:**
   - Rule 1: add that `static_analysis` never feeds enforcement.
   - Rule 2: add `static_analysis.reasons` to what counts as telemetry, and say that telemetry is escaped so a value can't close the `<telemetry>` tag.
   - Rule 4: state the report rule: `A report is written when risk_score >= 0.80 or the severity is Confirmed (a signature match, or a FIM change in a protected zone).`
   - Rule 5: revoked IDs are rejected, and the validator reports the final replacement.

## README.md

1. **Tech table, RAG agent row:** `ChromaDB, MITRE ATT&CK STIX data`. Remove LangChain.
2. **Repo layout:** add `rules/hashes/` (known-bad SHA-256 list), `tests/`, `contracts/tools/`, and `data/attack/` (ATT&CK data, model and index, not in git).
3. **Setup:** the RAG needs two commands after `uv sync`: `uv run python -m backend.rag.fetch`, then `uv run python -m backend.rag.index`.

## PLANNING.md

1. **3.2 Rules during simulations:** the Defender exclusion rule only allows the Atomic folder. Add `C:\ThreatPulseLab\scan-test`, used by the steps in `detection/VM_TEST_PLAN.md`, inside the VM only and removed by rolling back.
2. **4.1 or 5.4:** add the report rule, in the same words as CLAUDE.md item 6. Add that a null score and `static_analysis` don't count.
3. **5.2 Alert:**
   - Replace `a-0042` in the example with the new format, such as `a-20261104T115500-000042`, and add this note: `alert_id is a-<run start UTC, yyyymmddThhmmss>-<counter>, the same format as event_id. IDs must stay unique across runs, because the backend keys analyst reviews on them, so a reused ID would hand a new decision an old approval.`
   - Add the optional field to the example: `"static_analysis": { "score": 0.65, "reasons": ["…"] }`.
   - Add this note: `static_analysis holds what file analysis found. score is 0 to 1, and null for a signature match, which is a fact and not a score. reasons lists every finding, or every method that matched a signature. The policy engine ignores it, and it never feeds risk_score rules. Reasons are telemetry.`
   - Add `file_scan` to `event_type`: `Alert only, not Event: a scan with no triggering event.`
   - Extend the `rule_id` note with `HEUR-<name>` for `heuristic` alerts.
   - Add: `One alert per signature name. A file matched by both the hash list and YARA gives one alert, and its reasons list both methods.`
4. **5.3 Decision:**
   - Replace `d-0042` and `a-0042` in the example. Add: `A decision keeps its alert's suffix: d-<run start>-<counter>.`
   - The current text is "They gain `reviewed_by` and `reviewed_at`, set on approve or reject". Replace it with: `reviewed_by and reviewed_at are required once a request action is approved, rejected, executed or failed, and stay after it runs, so a completed kill still records who approved it. They are forbidden on awaiting_approval and on automatic actions.`
5. **5.4 Report:** replace `r-0042` and `a-0042` in the example. Add: `A report keeps its alert's suffix: r-<run start>-<counter>. techniques can be empty, for example for EICAR.`
6. **5.5 Backend API:** add that `/stats` also has a response schema in `contracts/schemas/api/`, and that the FIM item schema is `fim_change.schema.json`.
7. **Section 9 Risks:** add `ATT&CK revokes IDs between releases, as it did with T1562.001 -> T1685. | ATT&CK is pinned by hash. A version bump reruns the test that every technique ID this project uses is still active.`
8. **Section 10, Decided:** add these rows.
   - `| Vector DB | ChromaDB, stored locally in data/attack/chroma |` (and remove it from Open)
   - `| RAG framework | None. LangChain isn't used: retrieval and a prompt template don't need it, and leaving it out keeps "no tools" easy to verify |`
   - `| ATT&CK data | Enterprise v20.1, SHA-256 539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5, 706 active techniques |`
   - `| Embedding model | all-MiniLM-L6-v2 through onnxruntime, SHA-256 913d7300ceae3b2dbc2c50d1de4baacab4be7b9380491c27fab7418616a16ec3, local and CPU only |`
   - `| Retrieval scope | All 706 techniques are indexed. Search covers the 479 Windows ones by default, and can be switched |`
   - `| Static heuristics | Alert at a score of 0.50 or more. Files over 64 MiB get the hash check only. Weights are hand-set, and the false-positive rate is unmeasured |`
   - `| Alert IDs | a-<run start UTC>-<counter>, matching event IDs |`
   - `| Report rule | risk_score >= 0.80 or severity Confirmed |`
9. **Section 11 References:** add the embedding model, and the ATT&CK version in the tools line.

T1562.001 -> T1685 in Section 8.1 is already on `track-a/atomic`, so it needs nothing here.

## PHASES.md

1. **Step 1.6:** the EICAR YARA check is in `detection/VM_TEST_PLAN.md`.
2. **Step 1.7:** the heuristic checks also cover raw vs virtual size, the entry point and import count, and the UPX check is in `detection/VM_TEST_PLAN.md`.
3. **Step 2.10:** the gate becomes `706 of 706 active techniques indexed, from pinned ATT&CK v20.1`. Add that detection text comes from detection strategies and analytics, because `x_mitre_detection` is empty on every active technique.
4. **Step 3.7:** `write_report` uses `backend.rag.prompt.build_messages`, which refuses alerts that aren't high-risk. `static_analysis.reasons` goes inside `<telemetry>`.
5. **Step 3.8:** the ID check exists as `backend.rag.validator`. The step still needs to remove invalid IDs from a report, or regenerate it.
6. **Step 3.9:** the orchestrator fills in `subject`, `evidence_event_ids`, `risk_score` and `event_type` on `scan_file` alerts when an event triggered the scan.
7. **Step 4.1:** the integration VM also needs the fetch and index commands.

## ROADMAP.md

1. **Section 1, folder ownership:** add `rules/hashes/` to Track B, and add rows for `tests/` (everyone) and `data/attack/` (Track C).
2. **Section 2, Python function contracts:** add a note: `scan_file has a path and no process, so it returns no-process alerts with event_type file_scan. The orchestrator fills in the process, evidence and risk_score when an event triggered the scan.`
3. **Section 2, Alert conventions:** add the `HEUR-<name>` rule ID, `static_analysis`, `file_scan` and the alert ID format. The review-field wording needs the same change as PLANNING item 4.
4. **Section 3, Phase 2, Track C:** name ATT&CK v20.1 and the local model. Remove "Compare free-tier providers" only if that work has moved.
5. **Rebalancing table:** nothing to change.

## Not docs: code rules for other tracks

These aren't doc edits, but nothing enforces them yet, because the code doesn't exist.

| Track | Rule |
|---|---|
| A, `policy/` | Treat a null `risk_score` as not matching `risk_score_gte` |
| A, `policy/` | Never read `static_analysis`. Add a test for it |
| A, `policy.execute` | Keep `reviewed_by` and `reviewed_at` when moving an action to `executed` or `failed` |
| A, `policy/` | Never import `backend.rag` |
| C, `write_report` | Use `build_messages`, so telemetry stays escaped and only high-risk alerts reach the LLM |

---

# Added on `track-b/rules` (steps 2.7 and 2.8)

Everything above is unchanged. These come from `detection/behaviour.py`, `rules/behaviour/` and `triage/features.py`.

## CLAUDE.md

1. **Tech stack:** add `PyYAML (safe_load only)` to the Detection line.
2. **Team and tracks table:** `triage/` is also where the feature extractor lives.
3. **ML rules:** add that the feature extractor writes network mode, pool, batch and label as metadata columns that are never features, and that trees are built from parents and never from the label.

## README.md

1. **Repo layout:** `rules/behaviour/` holds the Sigma-style YAML rules, one file per technique.

## PLANNING.md

1. **Section 6, Gate 3:** two lines worth adding.
   - `A behaviour rule that needs a command line can't fire when the command line is null, which is common for short-lived processes such as reg.exe.`
   - `R-T1003-002 exists because of LSA protection: it catches the dump attempt when the read is denied and no process_access event is recorded.`
2. **Section 10, Decided:** add these rows.
   - `| Process tree | A root is a process whose parent has no process_start in the session. The label and root_pid never decide it. Processes already running when recording began are written with observed_start 0, and step 3.4 decides whether to train on them |`
   - `| Behaviour rules | Sigma-style YAML, plain text matching with no regular expressions, one alert per process and key. Thresholds are starting guesses: 10 deletes or renames in 30 seconds (T1486), connect then file write within 30 seconds (T1105) |`
   - `| Rule engine | match_rules(event) keeps state, so events must be replayed in time order. detection/replay.py does this |`
3. **Section 9 Risks:** add `Behaviour rule thresholds are untested on benign data | Gate 3 requires each rule to be checked against the benign sessions, and false positives are documented`.
4. **Section 8.1 or 4.3:** T1053.005 and T1218.011 rules see only the launcher's part of the technique. State this where the held-out results are described.

## PHASES.md

1. **Step 2.7:** the gate "each rule fires on its sample event" is met by tests that build their own events, since the shared samples contain only 6 of the 13 rules' behaviours. The 13 rules are in `detection/README.md`.
2. **Step 2.8:** the output is one row per process tree, written by `python -m triage.features`. The input is a session folder as written by `record_session.ps1` and `label_session.py`.
3. **Step 3.4:** filter on `observed_start`, split by `session_id`, and do not use `network`, `pool`, `batch` or `technique` as features. Use `pool` to find the held-out techniques.
4. **Step 3.9:** FIM alerts (`layer: fim`) have no process. The orchestrator links one using the tree that last wrote the item, as `triage/features.py` does for features.
5. **Step 1.10 or 4.3:** `python -m detection.replay events.jsonl fim.jsonl` replays a recorded session through the rules.

## ROADMAP.md

1. **Section 2, Alert conventions:** `match_rules` alerts have `layer` `rule` or `fim`, `risk_score` null, and `rule_id` `R-<technique>-<number>`. FIM alerts have no process.
2. **Section 2, `match_rules(event)`:** add that it keeps state, and events must arrive in time order.

## Not docs: code rules for other tracks

| Track | Rule |
|---|---|
| A, `agent/` | Check that FIM writes a registry key the same way as ETW. `triage/features.py` links FIM changes to writers by exact key |
| A, `policy/` | The LSASS allowlist belongs in the policy engine. The behaviour rule has none |
| A, `policy/` | Treat `layer: fim` alerts with `subject.pid` 0 like any other no-process alert |

---

# Added after the first real recordings (batch 1)

From `track-b/rules`, after replaying batch 1 through the rules and features. Same rule as above: wait for `track-a/atomic` to merge.

## PLANNING.md

1. **Section 6, Gate 3 or Section 10:** record how the labels are used.
   - `Features and evaluation use the test part of each attack session only. The Invoke-AtomicTest wrapper (harness) is excluded from training and evaluation, because it does far more work than the technique and would become a spurious correlation (Arp et al. 2022).`
   - `Trees are built after the harness is removed, so the test's own process is the root.`
2. **Section 4.3 (accepted limits):** add `Short-lived processes often have no command line (null): up to 8 of 21 process starts in one test session, and 10 of 59 in a benign one. Rules that need a command line can miss them.`
3. **Section 4.3 or Section 9:** add `A file event can have no path: 22,663 and 7,089 in the two benign sessions of batch 1. Zone rules and features can't place those events.` Please check the numbers against `agent_summary.txt` before using them.
4. **Section 8.3 (metrics), "False positives":** batch 1 gave 3 rule alerts in two benign sessions, all from Edge rewriting its own autolaunch Run value. The policy engine's persistence rule would restore it until an analyst approves it. Say so as a known false positive.
5. **Section 10 Decided:** `| FIM link | A fim_change is linked to the nearest write to the same item, up to 120 s before or 0.5 s after, because FIM and Sysmon use different clocks |`.
6. **Section 10 Decided:** the batch 1 results do not change any rule threshold, and say why: the benign sessions have no document activity to tune against. Thresholds are chosen after the zipping and admin benign sessions are recorded.

## PHASES.md

1. **Step 2.4 or 2.6:** `labels.csv` gains a `part` column (`test`, `harness`, `background`). `triage/features.py` requires it for rows to be used in training and writes `harness_excluded` to say if it was present.
2. **Step 2.7:** the Gate 3 line "each rule fires on its Atomic test": met in batch 1 for T1547.001 (both tests), T1003.001, T1059.001, T1486, T1053.005 and T1218.011. T1003.001 is caught only by the command-line rule, because LSA protection hides the read. T1105 and T1685 are in later batches.
3. **Step 3.4:** train only on rows with `harness_excluded` 1, filter on `observed_start`, split by `session_id`.

## For Track A (agent and FIM)

1. **FIM doesn't watch `RunOnceEx`.** Atomic T1547.001 test 2 writes `HKLM\...\RunOnceEx\0001\Depend\1`. The behaviour rule caught it, but FIM reported 0 changes, so the persistence zone's restore would not have run. This is the one gap between the rules and FIM. `agent/fim/README.md` lists only Run and RunOnce.
2. **FIM timestamps can come before the writer's event.** FIM's "removed" was stamped 45 ms before the Sysmon delete that caused it. Anything that orders FIM and writer events must allow for about half a second.
3. **ETW and Sysmon spell registry keys with different case** (`HKCU\SOFTWARE\...` vs `HKCU\Software\...`). Any code that compares keys must ignore case.
4. **The cleanup process deletes the test folder with the same behaviour as the attack.** It fires the ransomware rule too. It should be labelled `harness`.
5. **Edge's autolaunch value** (`MicrosoftEdgeAutoLaunch_*`) is removed and re-added by Edge itself. FIM sees both. The approved-change list will need an entry for it, or the policy will restore it.
6. **An open question for the labels:** v2 labels didn't exist yet when this was written, so `part` values other than `test`, `harness`, `background` and empty will stop `triage/features.py` with an error. Tell me if there are more.

## Added after the v2 labels (batch 1)

1. **For Track A, labels:** in the T1486 session, the cleanup PowerShell that deletes the test folder afterwards (same 25 documents) is labelled `part=background`, `label=benign`. It behaves exactly like the attack, so it would teach the model that ransomware behaviour is benign. It should be `harness`, as in the other sessions. This replaces item 4 of the previous section.
2. **PHASES.md step 2.5 or 3.4:** batch 1 gives 7 malicious process trees and 393 benign ones. State the class balance in the evaluation report, and that most benign trees are single processes with no start event.
3. **PLANNING.md Section 8.3 (ML quality):** report results per process tree, and say that the T1003.001 attack tree has 2 events because LSA protection blocked the dump, so it is expected to be hard to tell apart.

# Added on `track-a/policy-engine` (PHASES step 3.1)

Approved by the repository lead for this task. Apply after `track-a/atomic` merges, since it edits the same sections.

## PLANNING.md
1. **Section 5.1 (Event):** add optional `process.microsoft_root`: true only when the signature verified and the chain ends at a Microsoft root, checked by the agent and never taken from the signer text. Absent means unknown, not false.
2. **Section 5.2 (Alert):** add optional `subject.microsoft_root`, copied from the Event by detection.
3. **Section 5.3 (Decision):**
   - add the status `pending` for planned automatic actions (`executed_at` null). `policy.decide` plans and `policy.execute` runs. Automatic actions use `pending`, `executed`, `failed` and `skipped`.
   - add the optional action `target: {pid, image}`, set for `suspend`, `block_network` and `request_kill`.
   - the example should show `pending`.
4. **Section 5.5 (API):** `GET /stats` `actions_by_status` gains `pending`.
5. **Section 5.6 (`rules/policy.yaml`):** replace the example with the shipped file. Differences:
   - `risk_score_gte` takes a threshold name (`auto_contain`, `request_kill`).
   - new top-level `fim_debounce_seconds: 2`.
   - `never_suspend` entries are `{path, signature}` (default `microsoft`), with `{system: true}` and a `*` for one whole folder name. Our own programs are listed by exact path with `signature: none`, not the `C:\ThreatPulseLab\` tree.
   - `thresholds.alert` is a dashboard threshold only. No rule reads it.
   - new Defender and Sysmon entries.
   - A never-suspend path with an unknown `microsoft_root` counts as protected. Only an explicit `false` means not exempt. Never-suspend also covers `block_network` and `request_kill`.
6. **Section 5.6 text, P2:** the engine restores only when the item differs from the baseline and has been different for at least `fim_debounce_seconds`. The caller supplies that fact.
7. **Section 5.6 text, P2b:** a FIM alert has no process and a null score, so `risk_score_gte` tests the best score in the `writer_tree` the caller passes. Null scores never match.
8. **Section 7 (weaknesses), new row:** administrators can replace the exact files of our own never-suspend entries (agent and FIM Python). Accepted.

## PHASES.md
9. **Step 3.1:** note it is done on `track-a/policy-engine` for `decide` only: rules P1 to P6, the contract changes above, the tests (rules, null score, `static_analysis`, imports, never-suspend, debounce, schema validity). Still open in 3.1: the approved-change list and the LSASS allowlist built from benign data. `execute` is the next step.

## ROADMAP.md
10. **Section 2, `decide` signature:** `decide(alert, context=None, policy=None) -> Decision`. `context` keys: `now`, `suspended_pids`, `fim`, `writer_tree`.
11. **Section 2:** the orchestrator must supply `fim` after the debounce and a `writer_tree` for FIM alerts. The link from a FIM change to the tree that wrote it is not built yet. `triage/features.py:link_fim` has the same idea.

## CLAUDE.md
12. **Protected zones table, persistence row:** "restore every unapproved change" should say "that still differs from the baseline after about 2 seconds".

## For Track A (agent and FIM)
1. **Write `process.microsoft_root` in `agent/src/jsonl_writer.cpp`** from `ImageInfo::microsoft_root` (one line, next to `signed` and `signer`). Without it, every recording has the unknown state, and the never-suspend list protects a listed path regardless of signature.
2. **Confirm the two own-program paths in `rules/policy.yaml` on the VM:** `...\agent\build\Release\threatpulse_agent.exe` and `...\agent\.venv\Scripts\python.exe`. A venv `python.exe` may start the base interpreter as a child, whose path would then need an entry.
3. **Check that `chains_to_microsoft_root` is true on this VM for** `svchost.exe`, `lsass.exe`, `MsMpEng.exe` and `Sysmon64.exe`. Catalog-signed files are the risk: `agent/README.md` already asks this question.
4. **`policy.execute` must re-verify the signature just before a suspend,** and keep the VM guard and undo. It is not part of this step.
5. **Approved-change handling for Edge:** the engine restores only changes that still differ from the baseline after the debounce, so Edge's autolaunch value needs no approved-change entry if it is back at the baseline in 2 seconds. The caller must compare with the baseline *after* the wait.

## For the frontend
13. The dashboard now has a `pending` action status (badge and stats count). Nothing else changed.

# Added on `track-c/orchestrator` (PHASES step 3.9)

Apply after `track-a/atomic` and `track-a/policy-engine` merge.

## PHASES.md
1. **Step 3.9:** done on `track-c/orchestrator` for replay: `python -m backend.pipeline <session folders> --out <dir>`. `score_process` and `write_report` are stubs, so it is not yet "end to end with the real model and LLM". Add the open parts: the real scorer (3.5) and the LLM report (3.7).
2. **Step 3.1 note:** the orchestrator is what supplies `decide`'s context (below).

## ROADMAP.md
3. **Section 2, `score_process`:** the signature is `score_process(events: list[Event]) -> float | None`. `None` means not scored, and is what the stub returns until a model exists. It is not the same as 0.0.
4. **Section 2, `decide` context:** the orchestrator supplies `now`, `suspended_pids`, `fim` (`differs_from_baseline`, `settled_seconds`) and `writer_tree`. In a replay `suspended_pids` is always empty.
5. **Section 2, `write_report`:** `backend/pipeline/report_stub.py` is the stub. The real one is `backend.rag.prompt.build_messages` plus a provider client.
6. **Section 3, Phase 4:** live use still needs a runner that feeds events as they arrive and calls `execute`. The replay pipeline is the model for it: decisions for persistence changes wait for the debounce.

## PLANNING.md
7. **Section 4.1 (data flow) or 5.6:** the orchestrator is `backend/pipeline/`. It is the only part of `backend/` that imports `policy/`. The API modules do not, and `policy/` never imports `backend/`. A test checks both.
8. **Section 5.6 (P2), FIM baseline:** in a replay the baseline is rebuilt from `fim.jsonl`: an item's baseline is what its first reported change replaced. This is an approximation (the VM's `baseline.json` is not exported), wrong for an item changed before recording began.
9. **Section 5.6 (P2b), `writer_tree`:** a FIM change is linked to the nearest write to the same item (120 s before to 0.5 s after), and the tree is that writer plus its parents. The same rule as `triage/features.py`.
10. **Section 8.3 (evaluation):** the rule results on batches 1 and 2 are below.

## Results on batches 1 and 2 (18 sessions, replayed read-only, nothing committed)

- 25 alerts, 25 decisions, 8 reports (all 8 are stub reports for FIM changes, which count as Confirmed). Every `risk_score` is null.
- Every attack technique except one was detected by the technique's own `test` part. **T1003.001 run 2 gave no alert:** its `test` part is one PowerShell start and stop 30 ms apart, with no command line and no LSASS access event (LSA protection). Nothing was observable for the rules to see.
- **A new false positive, `R-T1486-001` on the benign zip session (batch 2, run 3).** PowerShell extracted an archive and deleted its files: 1,019 deletes and renames in the documents folder over 10 minutes, with a peak of 51 inside 0.1 s. The attack script does 25 in 0.08 s. **No count or window separates them**, so raising the threshold would not fix it. A delete rate is not enough: ransomware also writes new content (high entropy) in place of the originals. The planned ransomware detector (write rate and entropy, PLANNING.md Section 5.6 P3) has to supply that. Until then `R-T1486-001` fires on mass deletion by a benign extractor. This was not tuned: the session is `unassigned`.
- Edge's autolaunch rewrite (batch 1) gives 3 alerts and **no restore**: the value is back at the baseline after the debounce.
- A Run key that stays gives `restore` planned (pending). The cleanup that removes it afterwards gives `alert_only`, because the item is back at the baseline.
- `RunOnceEx` in batch 1: FIM did not watch it, so `restore` is skipped (baseline unknown). In batch 2 FIM reports it and `restore` is planned.
- A persistence write gives two decisions when the rule and FIM both report it. Both plan the same restore.

## For Track A
1. **Label the batch 2 T1486 cleanup as `harness`** if not done: batch 1 v3 has it and batch 2 v2 shows the same pattern (a `harness` alert in each T1486 session).
2. **The benign zip session fires `R-T1486-001`.** Please keep zip and extract sessions in the benign set: they are the only data that tells the ransomware rule from an archiver.
3. **FIM's `baseline.json` for each session** would let the replay use the real baseline instead of the approximation. Export it with the recording if it is cheap.

# Added on `track-b/entropy` (ransomware entropy, R-T1486-002)

Apply after `track-a/atomic`, `track-a/policy-engine` and `track-c/orchestrator` merge. The `rules/policy.yaml` change (P3b) was authorised by the repository lead for this task.

## PLANNING.md
1. **Section 5.6 (`rules/policy.yaml`):** add rule `P3b-ransomware-entropy`: `when: { zone: documents, rule_id: R-T1486-002 }`, `actions: [suspend]`. It needs no risk score. Never-suspend still applies. `R-T1486-001` alone stays `alert_only`. The loader gains the `rule_id` condition.
2. **Section 5.6 text, P3:** "write rate + entropy" is now built as a delete burst (`R-T1486-001`) plus a file-entropy verdict (`detection/ransom.py`). `R-T1486-002` is a rule ID raised by the pipeline, not by the rule engine, because it needs to read files.
3. **Section 4.1 / 5.4 report rule:** `R-T1486-002` counts as high-risk (like Confirmed), whatever the score.
4. **Section 10, Decided:** `| Ransomware entropy | Suspect file: entropy >= 7.5 bits/byte and no matching file header. Verdict high: >= 5 sampled files and >= 80% suspect (low: <= 20%). Only high raises R-T1486-002. Starting guesses, unmeasured |`; `| Entropy reads | Documents zone only, no links, regular files only, 64 MiB / 512 byte file limits, 100 files and 16 MiB per 10 s. Live or in the VM only: replay outside the VM is always "unknown" |`.
5. **Section 4.3 / 7 (limits):** ransomware with low-entropy output, a forged matching header, partial encryption, or delete-only (wiper) stays at `R-T1486-001`. Files an extractor deletes before they are read stay "unknown".
6. **Section 8.3 (evaluation):** the benign zip false positive (batch 2 run 3) is handled by the verdict only if files are read in the VM. It is not verified on real data from WSL.

## CLAUDE.md
7. **Protected zones, documents row:** "own detector (write rate + entropy)" now means `R-T1486-001` plus `R-T1486-002`.

## PHASES.md
8. **Step 3.1:** `P3b` added. **Step 3.9:** `--read-files` flag. **Step 4.x:** run the VM checks in `detection/VM_TEST_PLAN.md` ("Ransomware entropy").

## ROADMAP.md
9. **Section 2, Alert conventions:** rule ID `R-T1486-002` (layer `rule`, `risk_score` null, raised by the pipeline). **Section 2, `decide`:** `when` can test `rule_id`.

## For the frontend
10. Done on this branch: `severityOf` ranks `R-T1486-002` as Confirmed (matches `is_confirmed` in `backend/rag/prompt.py`).

## For Track A
1. Make the T1486 test script write at least 512 bytes per output file, or the verdict stays unknown.
2. Run the VM steps in `detection/VM_TEST_PLAN.md` and send back the entropy numbers.
3. Keep zip/extract sessions in the benign set, and record one where the extracted files stay on disk.

# Added on `track-b/training` (PHASES steps 3.4 and 3.5)

Apply after the earlier branches merge. **All results are preliminary: 2 of 11 batches.**

## CLAUDE.md
1. **Tech stack, Triage line:** `Python, XGBoost (xgboost-cpu, CPU only, no scikit-learn).`
2. **ML rules:** add that the model leaves out `n_fim_changes_linked` (a tree's own events hold no FIM events), is saved as JSON and never pickle, and that class weights make scores uncalibrated.

## README.md
3. **Setup / layout:** `triage/models/` holds the trained model (gitignored). `python -m triage.train` writes it.

## PLANNING.md
4. **Section 10, Decided:** `| Triage model | XGBoost, depth 3, 60 rounds, fixed in advance. Class weight negatives/positives. Scores are uncalibrated |`; `| Training set | Test-part trees positive. Attack-session background trees and benign trees negative. Events before start_utc dropped. Only trees with an observed start |`; `| Split | By whole batch. Held-out techniques (T1053.005, T1685, T1218.011) are evaluation only, and a held-out session is kept out of training whole |`; `| Model file | XGBoost JSON with a SHA-256 sidecar, never pickle |`.
5. **Section 8.3 (metrics):** results are per process tree, with Wilson 95% intervals, for precision, recall and false-positive rate, at 0.50 and 0.80. First results (batches 1 and 2) are in `triage/README.md`. Say they are preliminary.
6. **Section 5.6 / thresholds:** the 0.80 `auto_contain` threshold was set before any model existed. Class weights shift the scores, so re-choose it on all 11 batches.
7. **Section 9 Risks:** `The preliminary model scores nearly every replayed alert 0.88 to 0.98, benign ones too, so it would plan suspends for benign processes | The model is local only and gitignored. Prefix-snapshot training and all 11 batches come before it feeds policy`.
8. **Section 4.3 (accepted limits):** tiny benign trees (2 to 15 events) look like the tiny attack trees (T1053.005, T1547.001 have 12 to 14 events). The T1003.001 tree has 2 events because LSA protection blocked the dump, so it is expected to be missed.

## PHASES.md
9. **Step 3.4:** done in preliminary form: `triage/dataset.py`, `triage/train.py`. Open: batch 3 (waiting for Track A's decision on the duplicate sets), the other 8 batches, T1685 held-out, prefix-snapshot training (the gap between partial and complete trees is large), leave-one-batch-out tuning.
10. **Step 3.5:** `score_process` is the model, with `None` when there is no valid model or no single observed tree. The pipeline passes it the feature-tree containing the alerting process.
11. **Step 3.9:** the replay summary says whether a model is loaded.

## ROADMAP.md
12. **Section 2, `score_process`:** `None` is returned for: no model, a damaged model, a different feature list, events that are not one tree with an observed start, malformed events.

## For Track A
1. **Batch 3 has two overlapping sets** (sessions starting 17:29 to 17:38, and 19:09 to 19:47, both "run3" for the same techniques). Say which set to use. The 17:29 set has no benign session.
2. Batch 3 needs `part` labels (a labels folder like `batch-02-labels-v2`) before it can be used.
3. T1685 held-out sessions are not recorded yet.
4. More benign sessions with short-lived processes would help: the 12 false positives in the first results are tiny benign trees.

## Added on `track-b/training` (prefix snapshots)
1. **PLANNING.md Section 10, Decided:** `| Training rows | Snapshots of each tree after 10, 25, 50, 75 and 100% of its time span. A partial snapshot needs 2 events. The whole tree is always kept. A snapshot keeps its tree's label |`.
2. **PLANNING.md Section 8.3:** report the skew between alert-time and complete-tree scores, next to precision, recall and false-positive rate. First numbers are in `triage/README.md` (preliminary).
3. **PHASES.md Step 3.4:** done with prefix snapshots. The skew for attacks fell where it was large, and false positives are not clearly better.

## Added on `track-b/training` (label-free scoring)
1. **PLANNING.md Section 5.6 / 4.1:** the scorer is label-free. It takes a process tree's events and nothing else. It never reads labels, `session.json`, the harness, names, paths or command lines. See `triage/README.md` "Scoring scope".
2. **PLANNING.md Section 4.3 (accepted limits):** a replayed lab recording is scored with the harness inside the tree and with sensor start-up events, which training left out. That is a harder case than a real endpoint, and it makes replayed alert-time scores pessimistic.
3. **ROADMAP.md Section 2, `score_process`:** the signature is `score_process(events)`, and the events are the tree containing the alerting process, cut at the first ancestor whose start was not seen.

## Added on `track-b/training` (batch 3)
1. **PLANNING.md Section 10, Decided:** `| Batch 3 | Second run only (9 sessions). The first attempt (6 sessions) is excluded as a whole. Batch 3 has a busier background than batches 1 and 2, and is kept together in the split |`.
2. **PLANNING.md Section 8.3:** first results on 3 batches are in `triage/README.md`. Recall at 0.80 fell when batch 3 joined training (12 of 15 for the complete-tree model, 9 of 15 for the snapshot model), false positives fell (5 of 273). Nothing is conclusive: each group has 1 to 9 attack trees.
3. **PHASES.md Step 3.4:** batches 1 to 3 done. Open: batches 4 to 11 (batch 4 is in the export), T1685 held-out, leave-one-batch-out to choose thresholds, a decision on how to handle a batch-level shift in the background.
4. **PHASES.md Step 3.9:** `python -m triage.train --only-labelled` leaves out sessions with no labels, and names them.

## Added on `track-b/training` (batch 4, leave-one-batch-out)
1. **PLANNING.md Section 8.3 (metrics):** report every rate as a count with its 95% interval. Report T1003.001 apart as a documented limitation (about 2 events, LSA protection), never inside recall. Results on 4 batches are in `triage/README.md`: 15 of 16 ordinary attacks caught at 0.80, 6 of 387 benign flagged (snapshot model), 6 of 6 held-out. Still preliminary, and the attack trees repeat the same scripted tests, so trees from different batches are not independent.
2. **PLANNING.md Section 10, Decided:** `| Evaluation | Leave-one-batch-out. A threshold is only ever chosen from training folds: inside the training batches, the lowest value in 0.5 to 0.95 with a pooled false-positive rate of at most 2%. The rule needs at least 3 training batches |`; `| Documented limitation | T1003.001 is reported apart and never counts toward recall |`.
3. **PLANNING.md Section 5.6:** a threshold of 0.7 is *proposed* by that rule for the saved model (in-sample for the choice). Nothing applies it. The policy keeps 0.80 until more batches exist.
4. **PHASES.md Step 3.4:** batches 1 to 4 done. Open: batches 5 to 11, T1685 held-out, whether to drop T1003.001 trees from training (untested).
5. **For Track A:** batch 4 has no held-out technique sessions. The held-out pair has no new trees from it.

## Added on `track-b/training` (T1003.001 and training)
1. **PLANNING.md Section 10, Decided / 8.3:** recommended: the T1003.001 attack trees (about 2 events) are left out of training and are still reported apart. On 4 batches this took benign flags at 0.80 for the complete model from 3 of 387 to 0 of 387, and the snapshot model's ordinary recall from 15 of 16 to 16 of 16, at the cost of one held-out tree slipping just under 0.80 (6 of 6 to 5 of 6). A few trees each, so not established. The default is not changed yet: `--exclude-limited-from-training`.
2. **PLANNING.md Section 8.3:** detecting T1003.001 is a rule-layer job (`R-T1003-002`), not a model job. The model's scores on its near-empty trees (0.85 to 0.91 when it had trained on them) are not detections.

## Added on `track-b/training` (behaviour-rule evaluation)
1. **PLANNING.md Section 6, Gate 3 / 8.3:** the rules were checked on 4 batches with `python -m detection.rule_eval`: 25 of 26 attack sessions detected by a rule for their technique, 12 of 12 in the out-of-sample batches 3 and 4. The miss is T1003.001 in batch 2 (no command line, no LSASS event). `R-T1003-001` 0 of 4 as LSA protection predicts. 3 of 8 benign sessions had any alert (1 of 4 in batches 3 and 4): `R-T1486-001` on the 2 zip sessions (2 of 2), and the Edge autolaunch value in batch 1.
2. **PLANNING.md Section 10, Decided:** `| Rule provenance | All rules written in one commit before any replay, from the design. No rule file has changed since (a test checks this). The only change after data is the engine's case-insensitive de-duplication (after batch 1). Batch 1 is in-sample for R-T1547-001, R-T1547-002 and R-T1685-001. Batches 1 and 2 were seen for the rest, 3 and 4 were not |`.
3. **PLANNING.md Section 4.3 (accepted limits):** the rule results are repeats of the same scripted tests, not a test against other implementations or evasion. No session exists yet for `R-T1105-001`, `R-T1685-001`, `R-FIM-HOSTS`, and none uses a Startup folder for `R-T1547-002`.
4. **PHASES.md Step 2.7:** the gate "each rule fires on its Atomic test" is met for T1003.001 (by `R-T1003-002` in 3 of 4), T1053.005, T1059.001, T1218.011, T1486 and T1547.001. T1105 and T1685 are still open.
5. **For Track A:** record sessions for T1105 (needs NAT) and T1685, a hosts-file change, and a Startup-folder persistence test, so the rules with no evidence yet can be checked. Keep the zip and extract sessions in the benign set.
