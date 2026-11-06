# ThreatPulse policy engine: who may do what, decided by rules

`policy.decide(alert, context) -> Decision` is PHASES.md step 3.1. It is the **access control** part of the 4th generation: an ABAC engine (NIST SP 800-162) that reads attributes of the subject (the process), the object (the protected zone) and the environment (LSASS mode, what is already suspended), and applies the rules in `rules/policy.yaml`.

```python
from policy import decide

decision = decide(alert, {
    "now": "2026-11-05T09:30:06.000Z",
    "suspended_pids": [6120],
    "fim": {"differs_from_baseline": True, "settled_seconds": 3.1},
    "writer_tree": [{"pid": 5332, "image": "...\\reg.exe", "alive": True, "risk_score": 0.91}],
})
```

`decide` only **plans**: nothing in `engine.py`, `loader.py` or `paths.py` touches Windows, so it runs the same in WSL and in the VM. `execute` (PHASES.md step 3.2, below) runs the plan, and only in the lab VM.

## What a decision looks like

- It is deterministic: the same alert, context and policy give the same Decision. There is no clock, no randomness and no I/O. The decision time is `context["now"]`, or the alert's `ts`.
- It can hold several actions, each with its own status. Rules run in file order, and the same action on the same process is one action.
- **Automatic actions leave as `pending`** with `executed_at` null. `execute()` moves them to `executed`, `failed` or `skipped`.
- `request_kill` and `request_delete` leave as `awaiting_approval`, never automatic.
- `alert_only` is `executed` at once, because there is nothing to run. It is the default when no rule fires, and it is dropped when a real action exists.
- An action aimed at a process names it in `target: {pid, image}`.
- Every decision validates against `contracts/schemas/decision.schema.json`. A test checks about 1,200 sampled combinations of inputs, twice each.

## The rules

| Rule | Fires when | Action |
|---|---|---|
| `P1-lsass-read` | A `process_access` of LSASS with `vm_read`, by a process not on `lsass_allowlist` | `suspend`, or `alert_only` while `lsass_mode` is `learning` |
| `P2-persistence-change` | Persistence zone, and the change is not known to be approved | `restore`, only if the item still differs from the baseline after the debounce |
| `P2b-persistence-origin` | Persistence zone and a risk score of at least `auto_contain` | `suspend` the highest-risk live process in the writer's tree |
| `P3-ransomware` | Documents zone and a risk score of at least `auto_contain` | `suspend` |
| `P4-exfil` | `network_connect` and a risk score of at least `auto_contain` | `block_network` |
| `P5-kill-request` | The process is already suspended and the risk score is at least `request_kill` | `request_kill` (awaits the analyst) |
| `P6-delete-request` | `alert.layer` is `signature` | `request_delete` (awaits the analyst) |

Default: `alert_only`. Thresholds, the debounce and the lists all come from the YAML.

### Persistence: restore, then maybe suspend

- **Restore is for the object.** Signed tools such as `reg.exe` write Run keys, so "who wrote it" says little (PLANNING.md Section 5.6).
- **The debounce** (`fim_debounce_seconds`, 2) is from PLANNING.md Section 10. The caller waits, compares the item with the baseline, and passes `fim`. The engine restores only when `differs_from_baseline` is true and `settled_seconds` is at least the debounce.
  - Back at the baseline: P2 doesn't fire and the decision is `alert_only`. This is Edge rewriting its autolaunch value.
  - Differs but not yet settled, or baseline unknown: P2 fires and `restore` is `skipped` with a reason. Decide again later.
- **P2b and the writer's tree.** A FIM alert has no process and a null score, so the alert can't say who to suspend. The caller passes `writer_tree`. For an alert with no process, `risk_score_gte` tests the best score in that tree. It picks the highest-risk process that is still alive and not protected. If every process has exited, `suspend` is `skipped`. If none is scored high enough, P2b doesn't fire.

### LSASS: learning and enforcing

`lsass_mode: learning` turns P1's `suspend` into `alert_only`, so an empty allowlist can't suspend Windows components. The allowlist matches **full path and a verified Microsoft root**, because signed `rundll32.exe` can dump LSASS. A process whose `microsoft_root` is unknown is **not** allowlisted, since a wrong yes would hide an attack.

## Two walls (tests enforce both)

1. **A null `risk_score` never matches `risk_score_gte`.** Null means not scored, and that includes a threshold of 0.
2. **`static_analysis` is never read, and `policy/` never imports `backend/`.** A static score says what a file looks like, and the LLM must have no way into enforcement (CLAUDE.md design rule 1). `tests/test_policy_isolation.py` reads the code with `ast`, imports the package with the backend blocked, and checks that a decision doesn't change when `static_analysis` does, including text that tries to give instructions.

## Never suspend

A process on `never_suspend` is never suspended, never has its network blocked and is never offered for kill. The decision shows `skipped` with the reason (for a request, the reason is in `attributes.not_requested`).

An entry matches by **full path plus a verified Microsoft signature**, never by name:
- The path is normalised first: case, `/` and `\`, `.` and `..`, `\\?\`, trailing dots and spaces. `*` replaces one whole folder name only (Defender's versioned folder).
- **Paths that can't be resolved don't match:** relative paths, `..` out of the drive, and 8.3 short names such as `PROGRA~1`, which an attacker can choose.
- **The signature fact is `microsoft_root`,** a boolean the agent sets only when the signature verified **and** the chain ends at a Microsoft root. The signer text is display-only and the engine never reads it.
- **Three states:**

  | `microsoft_root` | Path on the list |
  |---|---|
  | `true` | Protected |
  | absent (unknown, e.g. an old recording) | **Protected**, reason `microsoft_root unknown`. A wrong "no" could freeze Windows |
  | `false` | Not exempt: the file at that path is not Microsoft's |
- **System** is matched as pid 4 with image `System`.

### Our own programs

The agent and the FIM Python are not Microsoft-signed, so they are listed by **exact executable path** with `signature: none`. The whole `C:\ThreatPulseLab\` tree is **not** listed.

**Limit:** an administrator can replace those exact files and inherit the protection. That is accepted for this prototype, as with FIM's own baseline (`agent/fim/README.md`). Track A should confirm the two paths on the VM: a venv's `python.exe` may start the base interpreter as a child, and then that interpreter's path also needs an entry.

## The contract changes this step needed

Approved by the repository lead.
- **Decision:** a `pending` status for planned automatic actions, and an optional `target: {pid, image}` on actions.
- **Event:** optional `process.microsoft_root`. **Alert:** optional `subject.microsoft_root`, copied by `detection/behaviour.py` and never invented.
- **API stats:** `pending` in `actions_by_status`. The backend counts it and the dashboard shows it.
- **Not done here:** the agent must write `microsoft_root` (a one-line change in `jsonl_writer.cpp`, from `ImageInfo::microsoft_root` which already exists). Until it does, recordings have no field, so the unknown state above applies.

## Policy file checks

`rules/policy.yaml` is read with `yaml.safe_load` and checked field by field. A wrong file stops startup: unknown keys, thresholds outside 0 to 1 or out of order, unknown actions, conditions or zones, duplicate rule IDs, relative paths and a `*` anywhere but a whole folder name. A broken policy must never look like a quiet one.

## Enforcement: `execute(decision, alert)` (step 3.2)

```python
from policy import decide, execute, undo

decision = decide(alert, context)          # plans
decision = execute(decision, alert)        # runs it, in the lab VM only
undo(decision["decision_id"])              # reverses it, newest first
```

`execute` takes the **Alert** as well as the Decision (ROADMAP.md Section 2), because a `restore` or `request_delete` action names no item: the registry value or file comes from `alert["object"]`. Process actions use the `target` in the Decision.

| Module | Job |
|---|---|
| `policy/executor.py` | `execute`, `undo`, `enable_controlled_folder_access`. Cross-platform: validates the inputs, fills in statuses and reasons, never raises for one failed action |
| `policy/actions_windows.py` | The actions, and `WindowsApi`, which holds **every** call that touches the machine. Importing it does nothing. Each real call refuses when the system isn't Windows |

### Rules every action follows

1. **VM guard.** Refuses unless this is Windows and `C:\ThreatPulseLab\LAB_VM` exists, checked in `execute` and again in each action. Elsewhere an automatic action becomes `skipped` with "not in lab VM", and an approved request stays `approved` with a note in `attributes.enforcement_notes`.
2. **Never-suspend, re-checked just before acting,** against the live process and not the Decision: the pid must still run the image the Decision names (a reused pid is refused), pid 4 and the enforcement process itself are refused, and a path on the list is protected unless the file's signature verified **and** chains to a Microsoft root. That is asked of the agent's own `--check-image`, and a check that can't be done counts as protected. A path not on the list needs no signature check. It also covers `block_network` and `request_kill`.
3. **Journal first.** `C:\ThreatPulseLab\enforcement\journal.jsonl` is append-only. An entry holding what the undo needs is written *before* the change (`started`), then `done` or `failed`, then `undone`. A failed action stays undoable, because a change that broke half-way may have left something behind.
4. **Check the result.** The action re-reads what it changed (the rule exists, the value matches the baseline) and fails if it doesn't.
5. **Idempotent.** Only `pending` automatic actions and `approved` requests run, so a second `execute` does nothing.

### The actions

| Action | Does | Undo |
|---|---|---|
| `suspend` | `NtSuspendProcess` on a handle opened and checked against the creation time, so a pid reused between check and act is refused | `NtResumeProcess`, only if the pid still has the same creation time |
| `block_network` | `netsh` outbound block rule `ThreatPulse-Block-<decision>-<n>` for the exact program path. An exited process is fine: the rule is per program | Remove the rule by name |
| `restore`, registry | The persistence-zone value goes back to the baseline value and type. A value that isn't in the baseline is removed. What was there is first saved **in full, with its type**, in `fim\quarantine\<decision>-<n>\manifest.json` | Put the quarantined value back. This is also what approving a change means |
| `restore`, file | A startup-folder file or the hosts file is copied back from `fim\files\<sha256>`, after checking that copy's hash. A file that isn't in the baseline is **moved to quarantine**, not erased | Copy or move it back |
| `request_delete` | After approval only: the file must still have the alert's `file_sha256`, must not be under `C:\Windows`, the lab's FIM, enforcement or repository folders, and is **moved to quarantine** | Move it back (not over a file that exists again) |
| `request_kill` | After approval only: `TerminateProcess` on the process **ThreatPulse itself suspended** (the journal must show that pid and creation time) | **None.** A terminated process can't be restored, so the gate is hard instead. `undo` reports it as `skipped` |
| Controlled Folder Access | `enable_controlled_folder_access()`: not a decision action, never called by `execute`, journaled with the previous mode | `undo("setup")` sets the previous mode back |

`restore` touches only the persistence zone, the same items `agent/fim/targets.py` watches (a test keeps the two lists equal), and refuses everything else. FIM's text encoding of registry data is decoded back to its type; a `REG_MULTI_SZ` that contains an empty string does not survive that encoding, which is a limit of the baseline format.

**Approval.** `request_kill` and `request_delete` run only from status `approved`, with `reviewed_by` and `reviewed_at`. `awaiting_approval` and `rejected` are never touched. A refused request becomes `failed` with its reason, because the schema has no `skipped` for a request.

**Running it.** In the VM, as `lab` in an elevated 64-bit shell: HKCU is the logged-in user's hive, the same one FIM baselined. It needs the repository's Python dependencies (PyYAML, jsonschema) and the built agent.

**Tests.** `tests/test_executor.py` and `tests/test_actions_windows.py` run the whole flow against `tests/fake_windows_api.py`, and fail if a test tries to start a program. They check, among other things, that every real system call refuses on a machine that isn't Windows. `agent/tools/vm_test_enforcement.ps1` is the real test for the VM.

## Not here yet

- Running the actions in the VM: the unit tests use a fake, and `agent/tools/vm_test_enforcement.ps1` is the real test, to be run after the dataset is recorded.
- Updating the FIM baseline when an analyst approves a persistence change. `undo()` puts a quarantined value back, but the baseline update belongs to `agent/fim` and the approve API.
- Linking a FIM change to the tree that wrote it, which the caller does for `writer_tree`. `triage/features.py` has a similar link.
- The LSASS allowlist, built from benign recordings.
- Authentication on the approve and reject API.

```bash
uv run pytest tests/test_policy.py tests/test_policy_isolation.py tests/test_executor.py tests/test_actions_windows.py
```
