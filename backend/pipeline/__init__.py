"""The orchestrator (PHASES.md step 3.9): events -> alerts -> decisions -> reports.

An offline pipeline. It reads a recorded session and writes alerts.json, decisions.json
and reports.json for the backend to serve. It plans only: every automatic action stays
`pending`, because policy.execute is a later step.

This is the one place in `backend/` that imports `policy/`. The API modules (`app`,
`views`, `data`, `store`) must not, and a test checks it. `policy/` never imports
`backend/`, and no report text reaches `decide`.
"""

from backend.pipeline.run import SessionResult, run_session

__all__ = ["run_session", "SessionResult"]
