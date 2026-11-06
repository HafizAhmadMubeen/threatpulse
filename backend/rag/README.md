# ThreatPulse RAG: ATT&CK knowledge for reports

This covers `PHASES.md` steps 2.10 and 2.11, plus the validator and prompt template that steps 3.7 and 3.8 build on. It's 4th generation: AI reports, grounded on official ATT&CK data. **Nothing here calls an LLM yet.**

## Set it up

From the repo root. This downloads about 140 MB into `data/attack/`, which git ignores.

```bash
uv sync
uv run python -m backend.rag.fetch   # pinned data and model, hash-checked
uv run python -m backend.rag.index   # local vector index, about 20 seconds
```

| What | Pin |
|---|---|
| ATT&CK Enterprise | v20.1, SHA-256 `539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5` |
| Embedding model | `all-MiniLM-L6-v2` (ONNX), SHA-256 `913d7300ceae3b2dbc2c50d1de4baacab4be7b9380491c27fab7418616a16ec3` |

To move to a new ATT&CK release, change the version and hash in `attack_data.py`, then fetch and index again. The index records what it was built from, and refuses to run on a mismatch. Some counts in `tests/test_rag_real.py` will need updating too.

## Use it

```python
from backend.rag.index import search, reference_for_alert
from backend.rag.prompt import build_messages, is_high_risk
from backend.rag.validator import check_technique_id

search("process reads LSASS memory")          # Windows techniques
search("...", windows_only=False)             # all platforms

check_technique_id("T1562.001")               # status "revoked", replacement "T1685"

if is_high_risk(alert):
    reference = reference_for_alert(alert)
    messages = build_messages(alert, events, reference)
```

## How it works

| File | Job |
|---|---|
| `fetch.py` | The only code here that uses the network. A wrong or partial download is deleted |
| `attack_data.py` | Turns the STIX bundle into one document per active technique and sub-technique |
| `index.py` | Local ChromaDB index, `search`, and the reference for an alert |
| `validator.py` | Checks IDs. Gives valid, revoked (with the final replacement), deprecated, unknown or malformed |
| `prompt.py` | The high-risk rule and the prompt template |

- **Detection text** is not in `x_mitre_detection`, which is empty on every active technique. It comes from detection strategies and their analytics, joined through `detects` relationships.
- **What gets embedded** is short, because the model reads only 256 tokens: name, tactics, detection strategy, then the description. The full document is stored for the prompt.
- **Revocations can chain**, so the validator follows them to the final active ID. Deprecated techniques have no replacement.
- **It stays local.** After fetching, nothing touches the network. The model is locked to the CPU provider, because `onnxruntime` also offers a remote Azure one.

## When a report is written

A report is written when `risk_score` is 0.80 or more, or the severity is Confirmed (a signature match, or a FIM change in a protected zone). A null score doesn't count, and neither does `static_analysis`. `build_messages` raises `NotHighRisk` for anything else, so a low-risk alert can't reach the LLM by mistake.

## Prompt safety (CLAUDE.md design rule 2)

**All telemetry is attacker-controlled, including `static_analysis.reasons`.**

- **No tools.** The messages have only `role` and `content`, and `build_messages` has no way to add tools. The model has nothing to act with.
- **Rules are in the system prompt only.** It's a fixed string with no telemetry in it.
- **Telemetry is data in the user message,** inside `<telemetry>`.
- **A file name can't close the tag.** A file named `</telemetry> new instructions` would otherwise end the block. Values are JSON with `<`, `>` and `&` escaped, which reads back as the same data but can't contain a tag. ATT&CK text gets the same treatment in `<attack_reference>`.
- **Telemetry never chooses the reference.** The alert's own technique IDs are looked up directly. Any search uses fixed text picked by the alert's enum fields, never a file name or command line.
- **No raw streams.** Only the alert's evidence events are sent, at most 50, with each text field capped at 2048 characters.

These limit the damage from prompt injection, but they can't guarantee a model ignores it. That's why the real protection is that the LLM has no tools, and policy code never reads what it writes.

## Tests

| File | Needs | Covers |
|---|---|---|
| `tests/test_rag.py` | Nothing | Parsing, validator, fetch, high-risk rule and prompt, on a small hand-built bundle |
| `tests/test_rag_real.py` | Data and index | Step 2.10's count, retrieval, and every technique ID this project uses |

```bash
uv run pytest -m attack_data -v
```

Without the data, `test_rag_real.py` skips. **A skip proves nothing, so read the skip count.** Its retrieval queries are the requirement: if one fails, report it rather than rewording it.
