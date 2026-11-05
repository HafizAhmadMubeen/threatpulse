# Contracts

The formats the tracks build against, described in `PLANNING.md` Section 5. Changes here need all three members to agree.

| Path | What it is |
|---|---|
| `schemas/` | JSON Schema 2020-12 for Event, Alert, Decision and Report |
| `schemas/api/` | Backend responses with no core format: `/stats` and FIM changes |
| `samples/` | One consistent lab VM session: `events.jsonl`, `alerts.json`, `decisions.json`, `reports.json` |
| `samples/invalid/` | Files that must fail, one mistake each. The name's first word selects the schema |
| `validate_samples.py` | Checks the samples, the links between them, and the invalid files |
| `tools/make_samples.py` | Generates `samples/` |

Run these from the repo root, after `uv sync`.

## Check the samples

```bash
uv run python contracts/validate_samples.py
uv run pytest
```

Exit code 0 means valid, 1 means problems were found, 2 means a file could not be read.

## Change the samples

Edit `tools/make_samples.py`, not the sample files. Then regenerate and check:

```bash
uv run python contracts/tools/make_samples.py
uv run pytest
```

The output is deterministic, so a rerun with no edits changes nothing. `tests/test_contracts.py` fails if the committed samples differ from the generator's output. Regenerating rewrites `samples/invalid/`, so a case removed from the generator disappears from there too.

File hashes in the samples are placeholders, derived from the image path so they can't match a real file. EICAR's is its real, public hash, and the file itself is never stored.

## Keep in mind

- `event.schema.json` comes from Track A. When it changes, update the samples and the copied values listed in `tests/test_contracts.py`.
- `events.jsonl` includes `fim_change` events, as the merged view. The agent writes those to its own `fim.jsonl`.
- `events.jsonl` is not strictly time-ordered, like real agent output. Sort by `ts`.
- Invalid samples are `.json`, because `.gitignore` ignores `.jsonl` below `samples/`.
