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
