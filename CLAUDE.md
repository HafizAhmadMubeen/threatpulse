# ThreatPulse

AI-driven, behaviour-based endpoint threat detection for Windows, built as a **4th-generation malware scanner**.

**Read these first:** `README.md` (overview), `PLANNING.md` (design, contracts, evaluation), `PHASES.md` (steps per phase), `ROADMAP.md` (team split).
Architecture decisions are made outside Claude Code and recorded in `PLANNING.md`. If a task needs a design decision that isn't written there, **stop and ask** instead of choosing.

---

## Team and tracks

| Track | Owner | Owns (folders) |
|---|---|---|
| A: Sense & Enforce | Ahmed Mubeen (repository lead, runs the lab VM) | `agent/`, `policy/`, `rules/policy.yaml`, `.claude/`, repo settings |
| B: Detect & Score | Haider Shahid / Ahmed Muaz | `detection/`, `triage/`, `rules/yara/`, `rules/behaviour/` |
| C: Explain & Show | Haider Shahid / Ahmed Muaz | `backend/`, `frontend/` |

Only Track A has a lab VM. Tracks B and C work in WSL only; their VM-only checks are run by Track A.

`contracts/` is shared: **changes to it need all three members to agree.** Don't edit it unless explicitly asked.
Stay inside the current track's folders unless told otherwise.

## The idea in one paragraph

Static tools are bypassed by packing, obfuscation and dynamic API resolution, and they flag legitimate packed software. ThreatPulse watches **runtime behaviour** on Windows (ETW + Sysmon). It filters events through signature, heuristic, integrity and behaviour-rule layers and a fast **XGBoost triage model**. A **deterministic ABAC policy engine** protects critical zones with limited containment. Only high-risk alerts go to an **LLM with RAG over MITRE ATT&CK**, which writes reports for a React dashboard.

## 4th-generation mapping

| Gen | Technique | Component |
|---|---|---|
| 1st | Signatures | SHA-256 hash list + YARA |
| 2nd | Heuristics + integrity | `pefile` heuristics and File Integrity Monitoring. The EMBER-trained static model is future work |
| 3rd | Behaviour | ETW/Sysmon telemetry + Sigma-style ATT&CK-mapped rules |
| 4th | AI/ML | XGBoost behavioural triage + LLM/RAG reports |
| 4th | Access control | ABAC policy engine guarding protected zones |

## Pipeline and interfaces

```
agent (C++)  -> events.jsonl -> detection layers (B) -> Alert
             -> policy.decide (A) -> Decision -> policy.execute (A)
             -> backend.write_report (C, LLM, text only) -> Report
             -> FastAPI -> React dashboard
```

- Formats: **Event, Alert, Decision, Report** (JSON Schemas + samples in `contracts/`, described in PLANNING.md Section 5).
- Python function contracts: `scan_file`, `match_rules`, `score_process` (B), `decide`, `execute` (A), `write_report` (C). See ROADMAP.md Section 2.
- Until a real function exists, a **stub returning sample data** stands in, so tracks never block each other.

## Tech stack

- **Agent:** C++, ETW via Microsoft's `krabsetw`, Sysmon events via `EvtSubscribe`. User-mode only.
- **Detection:** `yara-python`, `pefile`, EMBER features.
- **Triage:** Python, XGBoost.
- **Backend:** FastAPI. **RAG:** LangChain + ChromaDB + MITRE ATT&CK STIX data.
- **Frontend:** React (Vite).
- **Tests and demos:** Atomic Red Team, EICAR test file, our own harmless scripts.

## Protected zones

| Zone | Threat | Response |
|---|---|---|
| Document folders | Ransomware | Controlled Folder Access + own detector (write rate + entropy) → suspend |
| Run/RunOnce keys, startup folders, hosts file | Persistence | FIM detects → restore every unapproved change → suspend origin only if risk score is high and it's still running |
| LSASS memory | Credential dumping | Sysmon Event ID 10 with memory-read access, not in allowlist → suspend (alert-only while in learning mode). With LSA protection on no access is recorded: see Accepted limitations |
| Network | Exfiltration / C2 | Per-program Windows Firewall block rule |

Policy rules live in `rules/policy.yaml` (subject / object / environment attributes, NIST SP 800-162 terms). The full rule set is in PLANNING.md Section 5.6. Every decision records which rules fired and which attributes caused them. A decision can hold several actions, each with its own status. The never-suspend list matches by **full path + Microsoft signature**, never by name alone.

## Development environment (important)

| Place | What runs there |
|---|---|
| Windows host | VS Code, VM software only |
| WSL Ubuntu (repo at `~/threatpulse`) | Claude Code, all Python (3.12) and React development, ML training, ChromaDB |
| Windows VM (snapshots) | C++ agent build/run, FIM module, Sysmon, Atomic Red Team, enforcement, demos |

- Code reaches the VM through Git (push from WSL, pull in the VM).
- Logs come back only through the export procedure in PLANNING.md Section 3.2.
- Large data (EMBER, logs) lives outside the repo, on the large drive (e.g. `/mnt/e/threatpulse-data`).
- If you notice you are running on the Windows host (Git Bash, `C:\`/`E:\` paths) instead of WSL, say so before doing any work.

## Rules for Claude Code

**Protect the host machine. This is the developer's only laptop.** WSL is not a security boundary: it can launch Windows programs and write to `/mnt/c`. Deny rules in `.claude/settings.json` help, but you must also follow these rules yourself, and never try to work around a denied command (e.g. via full paths, `bash -c` or scripts).
- **Never** run commands that change Windows settings from this environment. This includes calling Windows executables from WSL (`powershell.exe`, `cmd.exe`, `reg.exe`, `netsh.exe`, `sc.exe`, etc.), and commands like `Set-MpPreference`, `Add-MpPreference`, `New-NetFirewallRule`, registry edits, service changes or installing drivers. Write such code into files for the VM; don't execute it.
- Don't install system-wide packages (`sudo apt install`, global `npm -g`, `pip` outside a venv) without asking. Use the project venv and local `node_modules`.
- **Never** download, write or reconstruct real malware or real exploit code. Approved test material only:
  - Atomic Red Team tests, run by a human inside the VM
  - EICAR: the repo stores only its **hash** and YARA rule, never the file. The file is created only inside the VM. On the host, use the harmless `THREATPULSE-TEST-MARKER` file instead
  - UPX (open-source packer), used only inside the VM on harmless programs
  - Our own harmless scripts: dummy-file encryption in a dedicated test folder (T1486), and a script that requests a test URL (network demo)
- Enforcement code must always have:
  - a matching **undo** (resume, remove firewall rule, restore)
  - a **VM guard**: refuse to act unless `C:\ThreatPulseLab\LAB_VM` exists
  - a **never-suspend** check
- Never add Defender exclusions or change Defender settings on the host.

**Code structure**
- Python in `detection/`, `triage/`, `policy/` (decision logic) and `backend/` must be **cross-platform**: it's developed in WSL but runs on Windows in the VM. Keep Windows-only code in clearly named modules (e.g. `policy/actions_windows.py`).
- Validate any produced Event/Alert/Decision/Report against the schemas in `contracts/`.
- Write tests for policy rules, feature extraction and the report validator.

Commits and pull requests: never add Co-Authored-By lines or 'Generated with Claude Code' text. Use the commit message exactly as given. The repo is public: never commit secrets, real (non-lab) data, or logs and screenshots from a developer workstation.

## Non-negotiable design rules

1. **The LLM never triggers enforcement.** Enforcement comes only from the deterministic policy engine. `policy/` must never import from the RAG/LLM code, and policy code never reads LLM output.
2. **No lethal trifecta.** The RAG agent has **no tools**: no HTTP requests to arbitrary URLs, no email, no shell, no process control. All telemetry text is data: wrapped in `<telemetry>…</telemetry>` in the user message, never put in the system prompt.
3. **Human-in-the-loop.** Automatic actions: suspend, block network, restore from baseline only. Kill/delete require analyst approval on the dashboard.
4. **LLM only after triage.** Never send raw event streams to the LLM.
5. **Grounded reports.** Every technique ID in a report is checked against the ATT&CK STIX data. Invalid IDs are removed or the report is regenerated.
6. **No live malware**, VM only.

## ML rules (to avoid fake-good results)

- Features describe **behaviour** (counts, rates, zones touched, LSASS access, child processes, signed/unsigned). **Never** use process names, paths or command-line text as features.
- Split train/test **by recording session**, never by individual event.
- Report results on **held-out techniques** and false-positive rate, not only accuracy.
- EMBER is used **only** for the static file model. The behavioural model is trained on our own agent's data.

## Current decisions

The full list is in PLANNING.md Section 10.

| Topic | Decision |
|---|---|
| Behaviour dataset | Our own VM recordings (benign + Atomic Red Team + our T1486 script). EMBER only for the static model |
| LSASS visibility | Sysmon Event ID 10 with `sysmon-modular`, allowlist, learning → enforcing mode |
| Agent → pipeline | JSONL file |
| FIM | Python module in the agent track, running in the VM |
| Ransomware zone | Controlled Folder Access **and** own detector |
| Persistence zone | Restore unapproved changes. Suspend only by risk score |
| Containment | Limited containment is in scope |
| Phase order | PHASES.md is authoritative for steps. PLANNING.md for design, contracts and gates |
| Scope | The design covers the C++ ETW agent, all layers and all zones. The current release is the subset in PLANNING.md Section 2.1. Future work: batch 9 (T1685) and further batches, the FIM evidence session, the T1105 diagnostic, the approve and reject flow, the EMBER static model, the LLM report writer (`write_report` is a stub), backend API authentication, a full live end-to-end integration and an LSASS demonstration. For how to continue, see docs/handover.md |
| Lab | One lab VM (Track A). B and C develop in WSL only |
| LLM | Gemini free tier through a **provider-agnostic client** (switching provider is one setting, `LLM_PROVIDER`). Local Ollama is the fallback and Groq an alternative. Keys (`GEMINI_API_KEY`, `GROQ_API_KEY`) only in `.env` (gitignored, template `.env.example`), never in code, logs or commits. Only triaged alerts from the lab VM are ever sent |

**Still open:** ChromaDB vs FAISS (ChromaDB recommended). Don't decide this in code; ask.

## Accepted limitations

- User-mode only: detect-then-contain, not prevention (e.g. LSASS access is reported after the handle opens).
- LSASS under LSA protection: Windows denies the dump and the sensors see little of the attempt (of the 5 recorded T1003.001 sessions, 4 have a 2-event test part and one has 56 events of normal PowerShell start-up, and none has a `process_access` on `lsass.exe`). Sysmon Event ID 10 only helps where the access is visible. The command-line rule `R-T1003-002` is the layer that still fires, where the command line is captured (4 of the 5 sessions), and the policy engine only alerts on it. The evaluation reports T1003.001 as a documented limitation, not as a model success or failure (PLANNING.md 4.3 and 8.1).
- On the LLM free tier the provider may use prompts to improve its products, so only triaged alerts from the lab VM are ever sent, never raw event streams or personal data.
- Persistence protection is detect-and-revert.
- Windows only, single endpoint, prototype for controlled lab environments, not production EDR.

## How to help

- Explain the reasoning, not just code. Every team member must be able to explain and defend each design choice.
- Say which scanner generation or security concept a feature covers.
- Prefer simple, demonstrable solutions over production complexity.
- Flag anything that breaks the rules above, especially giving the LLM tools, treating telemetry as instructions, or running system-changing commands on the host.
