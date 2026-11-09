"""ThreatPulse policy engine: deterministic ABAC decisions (PHASES.md step 3.1).

Decisions are planned by `decide` (pure, no I/O) and run by `execute` (step 3.2), whose
Windows calls are all in `actions_windows.py` and refuse outside the lab VM. It must never
import from `backend/`.
"""

from policy.engine import AlertError, ContextError, decide
from policy.executor import ExecuteError, enable_controlled_folder_access, execute, undo
from policy.loader import Policy, PolicyError, load_policy

__all__ = ["execute", "undo", "enable_controlled_folder_access", "ExecuteError", "decide", "load_policy", "Policy", "PolicyError", "AlertError", "ContextError"]
