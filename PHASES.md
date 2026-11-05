# ThreatPulse: Phases and Steps

Every phase is split into small steps. Each step has an **owner** and a **check** (a quick way to confirm the step really works).

Owners:
- **A** = Sense & Enforce
- **B** = Detect & Score
- **C** = Explain & Show
- **All** = everyone
- **Repo admin** = repository lead (Track A)

**Lab VM:** there is one lab VM, run by Track A. When a B or C step says "in the VM", the owner pushes the code and Track A runs the check in the lab VM.

A phase is finished only when its **gate** passes. Gates are defined in [PLANNING.md](PLANNING.md#6-phases-outcomes-and-validation-gates). This file is authoritative for **step order**. PLANNING.md is authoritative for design, contracts and gates.

---

## Where things run

This applies to every developer workstation (Windows 11 with WSL2 Ubuntu). Only Track A's workstation hosts the lab VM.

| Place | What runs there | Why |
|---|---|---|
| **Windows host** | VS Code, Git for Windows (optional), the VM software | Only normal apps. No system settings changed |
| **WSL Ubuntu** | Claude Code, all Python work (detection layers, ML training, policy logic, backend, RAG), React dashboard, ChromaDB | Keeps Python/Node installs off Windows and gives Linux tooling |
| **Windows VM** | C++ agent build and run, FIM module, Sysmon, Atomic Red Team, enforcement actions, live demos | Anything that needs admin rights or changes Windows lives here |

**Rules for this setup**
- **WSL is not a security boundary.** It can start Windows programs and write to `/mnt/c`. The real protection is:
  - Claude Code in **default permission mode** (it asks before each command; read before approving)
  - `.claude/settings.json` deny rules
  - the VM guard in enforcement code

  See PLANNING.md Section 3.3.
- Keep the **repo** inside the WSL filesystem (`~/threatpulse`), not under `/mnt/c` or `/mnt/e`, because file access across the boundary is slow. Open it with VS Code's WSL extension and run Claude Code from the WSL terminal.
- **Large data** (EMBER, recorded logs, the VM, the ISO) lives on the drive with the most free space, e.g. `E:\threatpulse-data` (seen from WSL as `/mnt/e/threatpulse-data`). WSL's own disk is on C: by default; move it if C: is low on space (`docs/lab-setup.md` 2.1).
- Code reaches the VM through **Git** (push from WSL, pull inside the VM). Logs come back through the **export procedure** (PLANNING.md Section 3.2). No permanent shared folders.
- Python code in `detection/`, `triage/`, `policy/` (decision logic) and `backend/` must stay **cross-platform**. Windows-only code (agent, FIM, enforcement actions) lives in clearly separate files.
- Use **Python 3.12** in both WSL and the VM, so behaviour matches.
- **RAM:** WSL2 can use up to half of your RAM. Before heavy VM testing, run `wsl --shutdown` from your own PowerShell window. It only stops WSL and changes nothing permanently.

---

## Phase 0: Foundation

**Goal:** owners recorded, safe lab, shared repo, agreed contracts, safeguards in place.

Full instructions for steps 0.1–0.5 and 0.7–0.8: [docs/lab-setup.md](docs/lab-setup.md).

| Step | Owner | What to do | Check |
|---|---|---|---|
| 0.0 | All | Record track owners in ROADMAP.md | ROADMAP.md has names |
| 0.1 | A | Install **VMware Workstation Pro** (free; download needs a free Broadcom account) or **VirtualBox**. Install it yourself, not through Claude Code. If the installer offers **Windows Hypervisor Platform (WHP)**, accept it: it lets VMware run alongside WSL2 and can be turned off later. Don't remove Hyper-V (it breaks WSL). Install VMware to the default C: path, **uncheck** "add console tools to PATH" and skip the Enhanced Keyboard Driver. No other Windows features need changing | VM software opens. WSL still works |
| 0.2 | A | Download the **Windows 11 Enterprise Evaluation** ISO. Create a VM with **6 GB RAM, 4 cores, 80 GB dynamic disk, virtual TPM enabled**, NAT network, stored on the drive with the most free space | VM boots to the desktop |
| 0.3 | A | Inside the VM: Windows updates, Git, Python 3.12, Visual Studio Build Tools with "Desktop development with C++". Create the VM-guard marker file `C:\ThreatPulseLab\LAB_VM` | `git --version`, `python --version`, `cl` work. Marker file exists |
| 0.4 | A | Inside the VM: install Sysmon with the **`sysmon-modular`** config | `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5` shows events. (LSASS Event ID 10 is checked in Phase 2 with Atomic T1003.001) |
| 0.5 | A | Shut down the VM, take snapshot **`clean-baseline`**, then test restoring it | Restore works |
| 0.6 | Repo admin | Create the public GitHub repo with the folder layout from the README, a `.gitkeep` in each empty folder, and a `.gitignore` (`.venv/`, `node_modules/`, `.env`, `*.jsonl` logs, `data/raw/`, model files, EMBER data). Add README, PLANNING, PHASES, ROADMAP and CLAUDE.md | All three can see the repo |
| 0.7 | All | Set up WSL (Python 3.12 via `uv`, Node via `nvm`, Windows PATH not appended), install VS Code's WSL extension, clone the repo into `~/threatpulse`, install Claude Code inside WSL, and open the repo from WSL | `pwd` shows `/home/<user>/threatpulse`. Claude Code reads CLAUDE.md |
| 0.8 | Repo admin | Commit `.claude/settings.json` (default mode, auto/bypass disabled, deny rules for `*.exe`, `/mnt/*` programs and `sudo`; see `docs/lab-setup.md` Part 3) | Claude Code refuses a denied command in a test |
| 0.9 | C | Write JSON Schemas in `contracts/` for Event, Alert, Decision, Report (PLANNING.md Section 5), plus sample files and `validate_samples.py` | All samples validate |
| 0.10 | B | Check that each Atomic technique in PLANNING.md 8.1 has a Windows test in the Atomic Red Team repo. Replace any that don't | Confirmed list committed |
| 0.11 | All | Agree on the held-out techniques and the number of benign sessions. Write function **stubs** that return sample data (ROADMAP Section 2) | Stubs importable |

**→ Gate 0**

---

## Phase 1: Sensing and first detections

**Goal:** the agent produces real events, and the 1st/2nd-gen file checks work.

| Step | Owner | What to do | Check |
|---|---|---|---|
| 1.1 | A | In the VM: a minimal C++ program with **krabsetw** that prints process-start events from `Microsoft-Windows-Kernel-Process` | Starting Notepad prints a line |
| 1.2 | A | Write events as JSON lines to `events.jsonl` in the Event schema | Output passes `validate_samples.py` |
| 1.3 | A | Add file and registry providers. Filter out the agent's own activity and obvious noise | `reg add` on a Run key in the VM shows a `registry_set` event |
| 1.4 | A | Enrich process info: SHA-256 of the image and signature status (WinVerifyTrust) | `notepad.exe` shows `signed: true` |
| 1.5 | B | Hash-list lookup (EICAR hash plus a small known-bad list). Develop with the test-marker file on the host | Marker hash flagged in a unit test |
| 1.6 | B | YARA rules and `scan_file` (`yara-python`), including a rule for the test marker and one for EICAR | Marker rule matches on the host. EICAR rule matches **in the VM** |
| 1.7 | B | Static heuristics with `pefile`: section entropy, unusual section names, suspicious imports | **In the VM:** UPX-packed copy of a harmless program scores higher than the original |
| 1.8 | C | FastAPI backend that reads sample alerts and serves `/alerts` and `/alerts/{id}` | `curl localhost:8000/alerts` returns samples |
| 1.9 | C | React app (Vite) with alert list and alert detail pages using the API | Dashboard shows sample alerts |
| 1.10 | All | Run B's `scan_file` and C's backend on a real `events.jsonl` exported from A's VM | No schema errors |

**→ Gate 1**

---

## Phase 2: Data collection, behaviour rules, FIM

**Goal:** labelled behaviour dataset and rule-based detection.

| Step | Owner | What to do | Check |
|---|---|---|---|
| 2.1 | A | Add network events, and read Sysmon Event IDs 3, 10, 12 and 13 through the Windows Event Log API (`EvtSubscribe`). Decode the access mask into rights like `vm_read`. Event IDs 12 and 13 give full registry paths where ETW can't name a key | LSASS access shows as a `process_access` event with decoded rights. A Run key write shows as a `registry_set` event with `source: sysmon` and the full key |
| 2.2 | A | FIM module (Python, `agent/fim/`): baseline of Run/RunOnce keys, startup folders and the hosts file. Periodic comparison emits `fim_change` events | Editing the hosts file produces a `fim_change` event |
| 2.3 | A | Install Atomic Red Team in the VM (`Invoke-AtomicRedTeam`). Take snapshot **`atomic-ready`** | `Invoke-AtomicTest T1547.001 -ShowDetails` works |
| 2.4 | A | Recording script: start agent → launch one test (Atomic or our T1486 script) and record its PID and start/end time → stop. Labelling script: events from that process tree = malicious | One labelled log file per test |
| 2.5 | A | Record benign sessions, including "noisy" normal activity: install/uninstall software, Windows Update, admin PowerShell, zipping files | Agreed number of benign sessions recorded |
| 2.6 | A | After **each** recording: export procedure (stop everything → enable `vm-export` → copy only `.jsonl`/`.csv` → disable → roll back to `atomic-ready`) | Logs present on the host. VM back to snapshot |
| 2.7 | B | Behaviour rules in Sigma-style YAML for each test technique, plus `match_rules` | Each rule fires on its sample event |
| 2.8 | B | Feature extraction per process (counts, rates, zones touched, LSASS access, child processes, signed or not). **No names, paths or command text as features.** Develop on samples or public pre-recorded data until A's dataset arrives | Features computed on samples without errors |
| 2.9 | B | Train the static model on EMBER's ready-made feature vectors (data stored on the large drive, not in the repo) | Accuracy reported on EMBER's test set |
| 2.10 | C | Download ATT&CK STIX data (`enterprise-attack.json`), split into one document per technique, embed into ChromaDB | Number of techniques loaded matches the file |
| 2.11 | C | Retrieval tests with plain-language queries | "process reads LSASS memory" → T1003.001 in top results |
| 2.12 | C | Dashboard pages for decisions, reports and FIM change approval, using sample data | Pages render |

**→ Gate 2**

---

## Phase 3: ML triage, policy engine, AI reports

**Goal:** risk scores, deterministic access control and grounded reports, each tested on its own.

| Step | Owner | What to do | Check |
|---|---|---|---|
| 3.1 | A | Policy engine `decide` reading `rules/policy.yaml` (PLANNING.md 5.6): multiple actions per decision, never-suspend (path + signature), LSASS learning/enforcing mode, approved-change list. Pure Python, developed in WSL, with a unit test for every rule | All policy tests pass |
| 3.2 | A | Enforcement in the VM (`policy/actions_windows.py`), each action with an **undo** and the **VM guard** check: suspend/resume, add/remove firewall block rule, restore registry/file from baseline, enable Controlled Folder Access | Each action and undo work on a harmless process in the VM. Each refuses to run without the marker file |
| 3.3 | A | Build the LSASS allowlist from benign recordings, then switch `lsass_mode` to `enforcing` | List committed with evidence for each entry. Benign replay causes no LSASS suspensions |
| 3.4 | B | Train XGBoost on A's dataset. **Split by recording session, not by event**, so the same run never appears in both training and test data | Metrics on the test split |
| 3.5 | B | Test on held-out techniques. Choose the risk threshold. Package `score_process` | Held-out results written in `docs/` |
| 3.6 | B | Ransomware detector: file write rate + entropy of written files per process | Our T1486 script scores high. Zipping files is documented either way |
| 3.7 | C | `write_report`: system prompt with rules, telemetry wrapped in `<telemetry>` tags in the user message, retrieved ATT&CK text added, **no tools given to the model** | Report generated from a sample alert |
| 3.8 | C | Report validator: every technique ID must exist in the STIX data | A deliberately fake ID gets caught |
| 3.9 | C | Pipeline orchestrator: events → B's functions → alerts → A's `decide` → C's `write_report`, using stubs where needed | Runs end to end on sample files |

**→ Gate 3**

---

## Phase 4: Integration

**Goal:** the full system runs end to end in the VM.

| Step | Owner | What to do | Check |
|---|---|---|---|
| 4.1 | A | Prepare the integration VM with Python dependencies, the built agent, the built dashboard and the LLM key (in `.env`, never committed). Take snapshot **`integration-ready`** | Snapshot exists |
| 4.2 | C | Replace all stubs with the real functions | No stub imports remain |
| 4.3 | All | **Replay mode first:** feed recorded `events.jsonl` files through the pipeline (no live attack) | Alerts and decisions match expectations |
| 4.4 | All | Live benign run (30–60 minutes of normal use) | False alarms counted and reviewed |
| 4.5 | A | Live zone demos: documents, persistence, LSASS, network (PLANNING.md 8.2), with NAT on | All four work |
| 4.6 | C | Approve/reject flow for kill requests (P5), delete requests (P6) and FIM change approval | Approval triggers the action. Rejection doesn't |
| 4.7 | C | Prompt-injection demo: a file named like an instruction | Same decision as without the injected text |
| 4.8 | B | Tune thresholds on live data and fix false positives | Updated threshold documented |
| 4.9 | All | Freeze features, tag `v0.9` | Tag pushed |

**→ Gate 4**

---

## Phase 5: Evaluation and release

**Goal:** measured results, complete documentation, and a design every team member can explain.

| Step | Owner | What to do | Check |
|---|---|---|---|
| 5.1 | All | Full evaluation from a fresh `integration-ready` snapshot (PLANNING.md 8.3) | Every metric has a number |
| 5.2 | A | Limitations section: detect-then-contain, user-mode limits, Defender dependency | Written |
| 5.3 | All | Bring all design docs in line with what was built (scope, dataset, containment) | Docs match the code |
| 5.4 | All | Evaluation report and architecture diagram in `docs/` | Draft reviewed by all three |
| 5.5 | C | Record the demo video | Covers all four zones and the injection test |
| 5.6 | All | Internal design review: each member walks through *every* layer, not only their own | Each member can answer questions on all tracks |
| 5.7 | All | Release tag `v1.0` | Tag pushed |

**→ Gate 5**

---

## Snapshots summary

| Snapshot | Taken at | Used for |
|---|---|---|
| `clean-baseline` | Step 0.5 | Fresh start |
| `atomic-ready` | Step 2.3 | Each data-recording run |
| `integration-ready` | Step 4.1 | Demos and final evaluation |
