# ThreatPulse pipeline: replay a recording, plan the response

`python -m backend.pipeline` is PHASES.md step 3.9. It reads a recorded session (`events.jsonl` and `fim.jsonl`), runs the detection layers and the policy engine over it in time order, and writes `alerts.json`, `decisions.json` and `reports.json` where the backend can serve them.

```bash
uv run python -m backend.pipeline /mnt/e/threatpulse-data/vm-export/batch-01 /mnt/e/threatpulse-data/vm-export/batch-02 \
  --labels /mnt/e/threatpulse-data/vm-export/batch-02-labels-v2 --out data/runs/<name>
```

- **Inputs are only read.** `--out` inside an input folder is refused. Real recordings must go to a gitignored folder such as `data/runs/` (the repo is public).
- A folder with `events.jsonl` is a session. Any other folder is searched for session folders.
- `--labels` is used for the summary only (alerts per `part`). It never reaches a decision.
- `--read-files` samples the document files a delete burst's process wrote (see below). VM only.
- `--scan-files` also runs `scan_file` on process images that exist on the machine. Off by default, because a recording's Windows paths don't exist in WSL. It is meant for the VM.

## What it does, per event, in time order

| Step | What | State |
|---|---|---|
| 1 | Remember processes (parent, alive), who wrote each key or file, and FIM's view of each item | causal: only events already seen |
| 2 | `match_rules` (stateful), and a check of a started process's own SHA-256 against the known-bad list | real |
| 3 | `score_process` on the tree that contains the alert's process | **None without a model in `triage/models/`.** A preliminary model is not safe to act on: see below |
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

## Ransomware entropy (R-T1486-002)

After `match_rules`, a process that tripped `R-T1486-001` is judged by `detection/ransom.py`: do the document files it wrote look encrypted? A `high` verdict adds `R-T1486-002` (once per process, as well as the burst alert), and policy rule `P3b` plans a suspend. **Only with `--read-files`**, which opens document-zone files on this machine and so belongs in the lab VM. Without it every burst is `unknown`, `R-T1486-002` is never raised, and replay output is unchanged. The summary has an `entropy` block (reader on/off, bursts by verdict, files not read and why). Details and limits: `detection/README.md`.

## Known gaps

- **Risk scores need a model, and the preliminary one is not safe to act on.** Without `triage/models/` every score is null and P2b to P5 never fire. With the preliminary model (2 of 11 batches), a replay scores nearly every alert 0.88 to 0.98, benign Edge included, because the replay tree still holds the wrapper that runs each test (training left it out) and is partial at alert time. It then plans `suspend` for benign alerts. See `triage/README.md`. Do not enable it for real use before prefix training and all 11 batches.
- Recordings 1 to 11 have no `process.microsoft_root`, so every process is "unknown" to the never-suspend list.
- A persistence write gives two decisions when both the rule and FIM report it (one per alert). Both plan the same restore, which is safe to repeat.
- A report is a template ("STUB report, no LLM call"), not an analysis.

```bash
uv run pytest tests/test_pipeline.py tests/test_pipeline_real.py
```
