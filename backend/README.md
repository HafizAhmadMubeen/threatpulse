# ThreatPulse backend

FastAPI service for the dashboard. It serves the API in `PLANNING.md` Section 5.5 from a data directory. There are no LLM calls yet: reports are read from `reports.json`.

## Run it

From the repo root:

```bash
uv sync
uv run python -m backend
```

The API runs on `http://127.0.0.1:8000`. The host is fixed in the code on purpose, with no setting to change it, because the API has no login.

| Variable | Default | Meaning |
|---|---|---|
| `THREATPULSE_DATA_DIR` | `contracts/samples` | Folder with `events.jsonl`, `fim.jsonl`, `alerts.json`, `decisions.json` and `reports.json`. Missing files count as empty |
| `THREATPULSE_REVIEW_STORE` | `backend/.state/review_store.json` | Where analyst reviews are saved |

To reset a demo, stop the server and delete `backend/.state/`.

## API

| Method | Path | Returns |
|---|---|---|
| GET | `/alerts` | Array of Alert |
| GET | `/alerts/{alert_id}` | `{"alert": Alert, "evidence_events": [Event]}` |
| GET | `/decisions` | Array of Decision, with reviews applied |
| POST | `/decisions/{decision_id}/approve` | The updated Decision |
| POST | `/decisions/{decision_id}/reject` | The updated Decision |
| GET | `/fim/changes` | Array of FIM changes |
| POST | `/fim/changes/{event_id}/approve` | The updated FIM change |
| GET | `/reports/{alert_id}` | Report |
| GET | `/stats` | Counts |

Schemas are in `contracts/schemas/`, and `contracts/schemas/api/` for `/stats` and FIM changes.

Approve and reject work on one action, so approving a kill never approves a delete in the same decision:

```json
{ "reviewed_by": "lab-analyst", "action": "request_kill" }
```

The FIM route takes only `reviewed_by`. `{event_id}` is the `fim_change` event's `event_id`.

| Status | Meaning |
|---|---|
| 403 | The `Origin` is not the dashboard |
| 404 | Unknown ID, or the decision has no such action |
| 409 | Already reviewed |
| 415 | The POST is not `application/json` |
| 422 | Bad request body |

## How it works

- **Approval records intent, and nothing else.** It sets `status`, `reviewed_by` and `reviewed_at`. Nothing is killed or deleted, and `backend/` never imports `policy/`. Connecting approval to `policy.execute` is step 4.6 in `PHASES.md`.
- **Reviews are kept apart from the data.** They go in the review store, and are layered over an action still at `awaiting_approval`. Once a file shows the action has moved on, the file wins.
- **Telemetry is data.** A record that is unreadable or fails its schema is skipped and counted in `skipped_records` in `/stats`, so one bad line can't take the dashboard down.
- **`events_filtered_before_llm`** counts events that are not evidence for any reported alert.

## Browser protection

| Threat | Protection |
|---|---|
| Another site reads the API | CORS allows only `http://127.0.0.1:5173` |
| Another site sends a POST, which CORS alone doesn't stop | POSTs must be `application/json`, which forces a preflight, and a wrong `Origin` gets 403 |
| DNS rebinding | Only the hosts `127.0.0.1` and `localhost` are accepted |

## Known limitation: the API has no login

**This must be solved before Phase 4 step 4.6, when approval starts triggering real actions.**

- `reviewed_by` is a typed name, not a verified identity.
- The browser protection above doesn't cover a program on the same machine. Any local process can call the API with no `Origin` header. That includes a test program approving its own Run key through `/fim/changes/{event_id}/approve`.
- It's acceptable for now because approval triggers nothing and the API listens only on loopback. A token in `.env` wouldn't fix it, because the same lab user can read that file.
- The store is for one server process. Don't run it with several workers.
