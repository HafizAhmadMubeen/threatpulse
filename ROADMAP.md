# ThreatPulse: Team Roadmap

How the work is split so **each track can be built independently**. The phases and validation gates are defined in [PLANNING.md](PLANNING.md#6-phases-outcomes-and-validation-gates), and the step-by-step tasks in [PHASES.md](PHASES.md). This file says who owns what.

---

## Release scope

The tasks below are the full plan. The current release is the subset in [PLANNING.md Section 2.1](PLANNING.md#21-release-scope), and [PHASES.md](PHASES.md#release-scope) marks it step by step. Here a task marked **Future work** is designed but not part of the release, and one marked **Release:** is in the release in the form the marker states. Ownership does not change.

| Track | In the release | Future work |
|---|---|---|
| **A** | Agent, FIM, policy engine, the enforcement actions with their undo (unit-tested, the VM test is to run), the dataset (batches 1 to 6, 46 sessions, batch 6 the NAT batch), live zone demos for documents and persistence | Batch 9 (T1685) and further batches, the FIM evidence session (ready on `track-a/fim-session`), the T1105 diagnostic, the LSASS allowlist and enforcing mode, a live run of the agent feeding the pipeline, a demonstration of the LSASS zone |
| **B** | Hash list, YARA, `pefile` heuristics, behaviour rules, feature extraction, XGBoost triage, the ransomware entropy check, the evaluation (leave-one-batch-out, per-technique table with two held-out techniques, false-positive rate, rule-layer results) | The EMBER static model, tuning thresholds on live data |
| **C** | Backend, ATT&CK vector DB, retrieval, prompt template, report validator, the dashboard demo from replayed sessions, the enforcement half of the prompt-injection demo, the demo video | The LLM report writer (`write_report`), connecting an approval to an action, backend API authentication |
| **All** | Verification in the VM (EICAR and UPX, entropy, enforcement test), the evaluation report, the design review | A full live end-to-end integration |

**Evaluation status.** Track B has run the evaluation over batches 1 to 6 (preliminary; counts and 95% intervals in [PLANNING.md Section 8.3](PLANNING.md#83-metrics)). At the 0.80 threshold the model catches 20 of 21 ordinary attacks and flags 5 of 661 benign trees (complete model), and catches 5 of 6 held-out attacks (3 of 6 for the snapshots model, 6 of 6 at 0.50). T1003.001 and T1105 are documented limitations (0 of 5 and 0 of 2 flagged by the model). The behaviour rules fired in 31 of 34 attack sessions, `R-T1486-001` fires on all 3 zip-extraction sessions, and Edge's autolaunch Run value raised the persistence rules in the batch 5 normal-use session. Scoring at alert time is worse (18 of 32 against 25 of 26 on four batches), so `--use-model` stays off. The `windows-update` session is an outlier that was not ablated. The rule thresholds were not tuned.

---

## 1. The split: three independent tracks

The pipeline has three natural parts. Each track is owned end to end.

| Track | Owner | Short name | Owns | Scanner generations covered |
|---|---|---|---|---|
| **A** | Ahmed Mubeen (repository lead) | **Sense & Enforce** | C++ ETW/Sysmon agent, FIM, ABAC policy engine, enforcement actions, lab VM, data recording | 2nd (integrity), 3rd (telemetry), 4th (access control) |
| **B** | Haider Shahid / Ahmed Muaz | **Detect & Score** | Hash list, YARA, static heuristics + EMBER model (the EMBER model is future work), behaviour rules, feature extraction, XGBoost triage | 1st, 2nd (heuristics), 3rd (rules), 4th (ML) |
| **C** | Haider Shahid / Ahmed Muaz | **Explain & Show** | FastAPI backend, pipeline orchestration, ATT&CK vector DB, RAG agent, report validator, React dashboard | 4th (AI reports), presentation layer |

### Folder ownership

| Folder | Owner | Others may |
|---|---|---|
| `agent/` | A | Read only |
| `policy/` | A | Read only |
| `detection/`, `triage/` | B | Read only |
| `backend/`, `frontend/` | C | Read only |
| `rules/yara/`, `rules/behaviour/` | B | Suggest via pull request |
| `rules/policy.yaml` | A | Suggest via pull request |
| `.claude/`, `.gitignore`, repo settings | A (repository lead) | Suggest via pull request |
| `contracts/` | **Everyone, changes need all 3 to agree** | — |
| `data/`, `docs/` | Everyone | — |

## 2. How we stay independent

1. **Contracts first.** In Phase 0 we agree the Event, Alert, Decision and Report formats and the API (PLANNING.md Section 5). After that, nobody codes against anyone else's code, only against the contracts.
2. **Sample files instead of waiting.** `contracts/samples/` contains hand-written example events, alerts, decisions and reports. Everyone develops and tests with these until the real component is ready.
3. **One lab VM, owned by Track A.**
   - Tracks B and C develop entirely in WSL, using sample files and the logs Track A exports from the lab VM.
   - Checks that need Windows (EICAR, UPX, live demos) are run by Track A in the lab VM, after B or C push their code.
4. **Plain interfaces.**
   - A → B: a JSONL file of events.
   - B → A and C: Python functions that take events and return alerts.
   - A → C: Python functions that take an alert and return a decision.
   - C → dashboard: HTTP API.
5. **One branch per track** (`track-a/...`, `track-b/...`, `track-c/...`), merged to `main` through pull requests. Each PR must keep `main` working with the sample files.

### Python function contracts (agreed in Phase 0)

```python
# Track B: detection/  and  triage/
def scan_file(path: str) -> list[Alert]: ...            # hash + YARA + static heuristics
def match_rules(event: Event) -> list[Alert]: ...       # behaviour rules
def score_process(events: list[Event]) -> float: ...    # XGBoost risk score, 0.0–1.0

# Track A: policy/
def decide(alert: Alert, context: dict) -> Decision: ...   # ABAC, deterministic
def execute(decision: Decision, alert: Alert) -> Decision: ...   # runs the actions in the lab VM, updates status

# Track C: backend/
def write_report(alert: Alert, events: list[Event]) -> Report: ...  # LLM, text only, no tools
```

Until a real function exists, its owner provides a **stub** that returns sample data. That way the other tracks can call it from day one.

Rules these functions share (PLANNING.md 5.2, 5.3 and 5.5):

- **Alerts with no known process** have `pid` 0, `image` `"unknown"`, `signed` false, `trusted_path` false and `risk_score` null. `evidence_event_ids` may be empty only then.
- **`risk_score` is nullable.** Null means not scored, and `decide` treats null as not matching `risk_score_gte`.
- **`rule_id`** is `ML-TRIAGE` for `ml` alerts and `SIG-<name>` for `signature` alerts.
- **Decisions** have a decision-level `ts`, and each action has `executed_at`. `request_kill` and `request_delete` have `reviewed_by` and `reviewed_at`, set on approve or reject. Automatic actions use only `executed`, `failed` and `skipped`. `reason` is required on `skipped` and `failed`, and `policy_rules` may be empty.
- **`execute` takes the Alert too.** A `restore` or `request_delete` action names no item, so the registry value or file comes from `alert.object`; process actions use the `target` in the Decision. It acts only in the lab VM, and a request action only once it is `approved`. Details: `policy/README.md`.
- **`/fim/changes/{id}/approve`** takes the `event_id` of the `fim_change` event as `{id}`.

## 3. Phase-by-phase tasks

### Phase 0: Foundation

| Member | Tasks | Done when |
|---|---|---|
| **All** | Agree contracts, test technique list, held-out techniques, number of benign sessions. Set up WSL and Claude Code (`docs/lab-setup.md` Parts 2–3) | Committed to `contracts/` and PLANNING.md |
| **A** | Lab VM (`docs/lab-setup.md` Part 1). Create the GitHub repo, `.gitignore`, and commit `.claude/settings.json` | Repo visible to all three. VM snapshot `clean-baseline` exists |
| **B** | Python environment for ML in WSL. Download EMBER (to the large drive, not the repo) **(future work)**. Check each listed Atomic technique has a Windows test | Technique list confirmed |
| **C** | JSON Schemas, sample files and `validate_samples.py`. Create free-tier LLM API keys for testing | Samples validate |

**Dependencies:** none. This is the only phase where all three work together.

### Phase 1: Sensing and first detections

| Member | Tasks | Done when |
|---|---|---|
| **A** | C++ agent using krabsetw: process, file, registry events to `events.jsonl` | Events from the VM pass the schema check |
| **B** | `scan_file`: SHA-256 hash list, YARA rules (test marker + EICAR), `pefile` heuristics (entropy, sections, imports) | Marker caught in WSL. EICAR and the UPX test pass in the lab VM |
| **C** | FastAPI backend that reads sample JSONL and alerts and serves `/alerts`, `/alerts/{id}`. React dashboard skeleton: alert list and detail pages using mock data | Dashboard shows sample alerts |

**Dependencies:** none (everyone uses sample files).

### Phase 2: Data, behaviour rules and FIM

| Member | Tasks | Done when |
|---|---|---|
| **A** | Add network events and Sysmon Event IDs 3 (network), 10 (LSASS access), 12 and 13 (registry). FIM module for Run/RunOnce keys, startup folders, hosts file. **Record the dataset**: benign sessions, Atomic runs and our T1486 script, labelled by the launched process tree. **Release: batches 1 to 6 only, 46 sessions (PLANNING.md 2.1). T1685 is not recorded.** Export logs before each rollback (PLANNING.md 3.2) | Labelled dataset shared with B (shared folder or drive, not the repo) |
| **B** | Behaviour rules in Sigma-style YAML for each test technique, and `match_rules`. Feature extraction code written and tested on sample events or public pre-recorded data (e.g. OTRF Security-Datasets converted to our schema). Train the EMBER static model **(future work)** | Each rule fires on its sample; features compute without errors |
| **C** | Load ATT&CK STIX data into ChromaDB. Retrieval tests. RAG prompt template with `<telemetry>` delimiters. Compare two Gemini models on a sample report, and check that the local Ollama fallback produces a valid report **(future work, with `write_report`)**. Dashboard pages for decisions, reports and FIM change approval (mock data) | "process reads LSASS memory" retrieves T1003.001 |

**Dependency (small):** B needs A's labelled dataset **at the end of Phase 2** to train the real model. Until then B builds and tests the feature code on samples and public data, so B never stops working.

### Phase 3: ML triage, policy engine and AI reports

| Member | Tasks | Done when |
|---|---|---|
| **A** | ABAC policy engine `decide` reading `rules/policy.yaml`. Enforcement `execute`: suspend, firewall block, restore from baseline, Controlled Folder Access setup, each with undo and VM guard. Build the LSASS allowlist from benign data **(future work, with the LSASS demonstration)**. **Test only in the VM** | Every policy rule has a passing test. Each action works on a harmless process |
| **B** | Train XGBoost on A's dataset (split by session). **Release: leave-one-batch-out, so every session from one boot stays on one side, and a per-technique table. The held-out evaluation covers two techniques, because T1685 was not recorded.** Evaluate on test split and held-out techniques. Choose a risk threshold. Package `score_process`. Ransomware detector features (write rate, entropy of written files) | Metrics table written (precision, recall, FPR, held-out results) |
| **C** | `write_report` with the LLM (no tools), behind a provider-agnostic client **(future work: it is a stub today)**. Report validator for technique IDs. Pipeline orchestrator that calls B's and A's functions (stubs if not ready yet) | Report generated from a sample alert. Fake ID caught by the validator |

**Dependencies (small):** C's orchestrator calls A's and B's functions, but stubs exist from Phase 0, so C is never blocked.

### Phase 4: Integration

All three work together on `main`. Each fixes problems in their own track.

**Release:** recorded sessions replayed through detection, policy and stub reports into the dashboard, plus live zone demos in the VM. A full live end-to-end integration is future work (PLANNING.md 2.1).

| Member | Tasks |
|---|---|
| **A** | Run the agent live in the lab VM feeding the pipeline **(future work)**. Fix enforcement issues. Run the four zone demos **(release: documents and persistence, screen-recorded. The network zone's block action is verified by the enforcement test, and the LSASS demo is future work)** |
| **B** | Tune thresholds on live data **(future work)**. Fix false positives. Confirm rules and model work on live agent output **(future work)** |
| **C** | Connect the real functions in place of the stubs. Add the approve/reject flow **(future work: the API records the decision and nothing acts on it; connecting it to an action needs backend API authentication)**. Build the prompt-injection demo. Polish the dashboard |

**Gate 4 checklist:** see PLANNING.md Phase 4, including its release-scope note.

### Phase 5: Evaluation and release

| Member | Tasks |
|---|---|
| **A** | Zone demos **(release: documents and persistence)**, latency measurements, limitations section (detect-then-contain) |
| **B** | ML evaluation **(release: leave-one-batch-out)**, per-technique detection table, false-positive analysis |
| **C** | LLM filtering stats, report accuracy, injection test results, demo video **(release: documents and persistence demos, the dashboard replay and the enforcement half of the prompt-injection test)** |
| **All** | Bring the design docs in line with the code, write the evaluation report, hold an internal design review. **Everyone must be able to explain all layers**, not only their own |

## 4. Dependency map (the only handoffs)

```
Phase 0:      all three agree contracts + samples   (together)
Phase 1–3:    B, C push code --> A runs VM-only checks (EICAR, UPX)
Phase 2 end:  A --labelled dataset--> B             (small dependency; B works on samples until then)
Phase 3:      A, B functions --> C orchestrator      (stubs used until real ones are ready)
Phase 4:      integration in the lab VM              (together; in the release: replayed sessions and the zone demos, the full live run is future work)
```

Everything else is independent.

## 5. Working routine

- **One short sync per week** (15–20 minutes): what I finished, what I'm doing next, anything blocking me.
- **Any change to `contracts/`** needs a message to the group and agreement from all three before merging.
- **End of each phase:** run the gate checklist together before starting the next phase.

## 6. Rebalancing if a track falls behind

Simplify a layer, **never remove it**. All four generations must still exist in the final demo.

| If behind | Simplify to |
|---|---|
| A: C++ agent | Read Sysmon events first (via the Windows Event Log API), add raw ETW providers after |
| A: enforcement | Implement suspend and firewall block first; restore and CFA after |
| B: ML | Fewer features; static model from `pefile` features if EMBER setup blocks. In the release the EMBER model is future work, so the `pefile` heuristics stand for generation 2 |
| B: rules | Fewer, well-tested behaviour rules |
| C: dashboard | Plain tables and one detail page; styling last |
| C: RAG | Retrieval + one prompt; skip multi-step agent chains |

If one track is far ahead, its owner picks up policy-rule tests (help A), labelling scripts (help A/B), or dashboard pages (help C), working through pull requests to the owner.
