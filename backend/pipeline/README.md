# ThreatPulse pipeline: replay a recording, plan the response

`python -m backend.pipeline` is PHASES.md step 3.9. It reads a recorded session (`events.jsonl` and `fim.jsonl`), runs the detection layers and the policy engine over it in time order, and writes `alerts.json`, `decisions.json` and `reports.json` where the backend can serve them.

```bash
uv run python -m backend.pipeline /mnt/e/threatpulse-data/vm-export/batch-01 /mnt/e/threatpulse-data/vm-export/batch-02 \
  --labels /mnt/e/threatpulse-data/vm-export/batch-02-labels-v2 --out data/runs/<name>
```

- **Inputs are only read.** `--out` inside an input folder is refused. Real recordings must go to a gitignored folder such as `data/runs/` (the repo is public).
- A folder with `events.jsonl` is a session. Any other folder is searched for session folders.
- `--labels` is used for the summary only (alerts per `part`). It never reaches a decision.
- `--scan-files` also runs `scan_file` on process images that exist on the machine. Off by default, because a recording's Windows paths don't exist in WSL. It is meant for the VM.

## What it does, per event, in time order

| Step | What | State |
|---|---|---|
| 1 | Remember processes (parent, alive), who wrote each key or file, and FIM's view of each item | causal: only events already seen |
| 2 | `match_rules` (stateful), and a check of a started process's own SHA-256 against the known-bad list | real |
| 3 | `score_process` on the alert's process tree | **STUB: always None** |
| 4 | `decide(alert, context)` | real. **Plans only**: automatic actions stay `pending` |
| 5 | `write_report`, only for a high-risk alert (Confirmed, or a score of at least 0.80) | **STUB: no LLM call** |

`decide` runs before the report is written, and never sees it.

## The context given to `decide`

| Key | Value in a replay |
|---|---|
| `now` | The alert's time. A persistence-zone alert waits until its item has been unchanged for `fim_debounce_seconds` (2), longer if it changes again |
| `suspended_pids` | **Always empty.** Nothing is executed, so nothing is suspended |
| `fim` | `differs_from_baseline` and `settled_seconds` for the alert's item, from `fim.jsonl`. Absent when FIM never reported the item |
| `writer_tree` | The process that wrote the item (a FIM change: the nearest write to the same item, up to 120 s before or 0.5 s after) and its parents, each with `alive` as of the decision time |

**FIM baseline is an approximation.** The VM's `baseline.json` is not in the export, so an item's baseline is taken to be what the first reported change replaced. That is wrong for an item changed before recording began. Every summary says so.

## Output

`<out>/<session_id>/`: `alerts.json`, `decisions.json`, `reports.json`, copies of `events.jsonl` and `fim.jsonl` (the dashboard shows an alert's evidence), and `pipeline_summary.json`. For more than one session there is also `<out>/_all/` with everything merged (all FIM events, but only the evidence events of the agent), and `<out>/summary.json`.

- Alert, decision and report IDs carry the **recording's** run start, so a replay gives the same IDs every time and two recordings never share one. This matters because the review store is keyed on them.
- Everything is validated against `contracts/` before it is written.

## Known gaps

- **No risk scores**, so P2b, P3, P4 and P5 never fire on real data until `score_process` is a model. A replay has no labels, so a tree includes the wrapper that runs each test, which training excluded. Fix both together in steps 3.4 and 3.5.
- Recordings 1 to 11 have no `process.microsoft_root`, so every process is "unknown" to the never-suspend list.
- A persistence write gives two decisions when both the rule and FIM report it (one per alert). Both plan the same restore, which is safe to repeat.
- A report is a template ("STUB report, no LLM call"), not an analysis.

```bash
uv run pytest tests/test_pipeline.py tests/test_pipeline_real.py
```
