"""FastAPI app for the dashboard (PLANNING.md Section 5.5).

Approving records the analyst's decision and nothing else. Enforcement belongs to the
policy engine, so this package never imports policy/ and never runs an action.
No LLM is called here: reports are read from the data directory.
"""

import copy
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, StringConstraints
from starlette.middleware.trustedhost import TrustedHostMiddleware

from backend import views
from backend.data import DataDirectory
from backend.store import ReviewStore

HOST = "127.0.0.1"
PORT = 8000
DASHBOARD_ORIGIN = "http://127.0.0.1:5173"
ALLOWED_HOSTS = ["127.0.0.1", "localhost"]

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA_DIR = REPO_ROOT / "contracts" / "samples"
DEFAULT_STORE_PATH = REPO_ROOT / "backend" / ".state" / "review_store.json"

AnalystName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True, min_length=1, max_length=64, pattern=r"^[^\x00-\x1f\x7f]+$"
    ),
]


class ActionReview(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reviewed_by: AnalystName
    action: Literal["request_kill", "request_delete"]


class FimReview(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reviewed_by: AnalystName


def now() -> str:
    moment = datetime.now(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def find_one(items: list[dict], key: str, value: str, label: str) -> dict:
    for item in items:
        if item[key] == value:
            return item
    raise HTTPException(status_code=404, detail=f"{label} not found")


def add_browser_guards(app: FastAPI) -> None:
    """CORS only limits what a page can read, so a hostile page could still send a POST.

    The last middleware added runs first: host check, then CORS, then the POST guard.
    The host check stops DNS rebinding. Requiring JSON forces a CORS preflight, and the
    Origin check refuses other sites. A request with no Origin is not from a browser
    page, which is the unauthenticated local access described in backend/README.md.
    """

    @app.middleware("http")
    async def guard_writes(request: Request, call_next):
        if request.method == "POST":
            origin = request.headers.get("origin")
            if origin is not None and origin != DASHBOARD_ORIGIN:
                return JSONResponse({"detail": "origin not allowed"}, status_code=403)
            content_type = request.headers.get("content-type", "")
            if content_type.split(";")[0].strip().lower() != "application/json":
                return JSONResponse({"detail": "send application/json"}, status_code=415)
        return await call_next(request)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[DASHBOARD_ORIGIN],
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)


def create_app(data_dir: Path = DEFAULT_DATA_DIR, store_path: Path = DEFAULT_STORE_PATH) -> FastAPI:
    app = FastAPI(title="ThreatPulse API", version="0.1.0")
    add_browser_guards(app)
    directory = DataDirectory(data_dir)
    store = ReviewStore(store_path)
    decision_validator = directory.validators["decision"]

    def review_action(decision_id: str, body: ActionReview, status: str) -> dict:
        with store.lock:
            data = directory.load()
            stored = find_one(data.decisions, "decision_id", decision_id, "decision")
            decision = views.with_reviews(stored, store)
            matching = [a for a in decision["actions"] if a["action"] == body.action]
            if not matching:
                raise HTTPException(404, f"decision has no {body.action} action")
            if matching[0]["status"] != "awaiting_approval":
                raise HTTPException(409, f"action is already {matching[0]['status']}")

            review = {"status": status, "reviewed_by": body.reviewed_by, "reviewed_at": now()}
            updated = copy.deepcopy(decision)  # the loaded data is shared between requests
            next(a for a in updated["actions"] if a["action"] == body.action).update(review)
            if not decision_validator.is_valid(updated):
                raise HTTPException(500, "review would produce an invalid decision")
            store.add_decision_review(decision_id, body.action, review)
            return updated

    @app.get("/alerts")
    def list_alerts() -> list[dict]:
        return directory.load().alerts

    @app.get("/alerts/{alert_id}")
    def get_alert(alert_id: str) -> dict:
        """Evidence sits beside the alert, because the Alert schema has no field for it."""
        data = directory.load()
        alert = find_one(data.alerts, "alert_id", alert_id, "alert")
        wanted = set(alert["evidence_event_ids"])
        return {
            "alert": alert,
            "evidence_events": [e for e in data.events if e["event_id"] in wanted],
        }

    @app.get("/decisions")
    def list_decisions() -> list[dict]:
        return views.decisions(directory.load(), store)

    @app.post("/decisions/{decision_id}/approve")
    def approve_action(decision_id: str, body: Annotated[ActionReview, Body()]) -> dict:
        return review_action(decision_id, body, "approved")

    @app.post("/decisions/{decision_id}/reject")
    def reject_action(decision_id: str, body: Annotated[ActionReview, Body()]) -> dict:
        return review_action(decision_id, body, "rejected")

    @app.get("/fim/changes")
    def list_fim_changes() -> list[dict]:
        return views.fim_changes(directory.load(), store)

    @app.post("/fim/changes/{event_id}/approve")
    def approve_fim_change(event_id: str, body: Annotated[FimReview, Body()]) -> dict:
        with store.lock:
            changes = views.fim_changes(directory.load(), store)
            change = find_one(changes, "event_id", event_id, "FIM change")
            if change["status"] == "approved":
                raise HTTPException(409, "change is already approved")
            review = {"reviewed_by": body.reviewed_by, "reviewed_at": now()}
            store.add_fim_review(event_id, review)
            return {**change, "status": "approved", **review}

    @app.get("/reports/{alert_id}")
    def get_report(alert_id: str) -> dict:
        return find_one(directory.load().reports, "alert_id", alert_id, "report")

    @app.get("/stats")
    def get_stats() -> dict:
        return views.stats(directory.load(), store)

    return app


def app_from_environment() -> FastAPI:
    return create_app(
        Path(os.environ.get("THREATPULSE_DATA_DIR", DEFAULT_DATA_DIR)),
        Path(os.environ.get("THREATPULSE_REVIEW_STORE", DEFAULT_STORE_PATH)),
    )
