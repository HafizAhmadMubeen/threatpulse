"""ThreatPulse policy engine: deterministic ABAC decisions (PHASES.md step 3.1).

Decision logic only. Actions are planned here and run by a later step, and nothing in
this package touches Windows. It must never import from `backend/`.
"""

from policy.engine import AlertError, ContextError, decide
from policy.loader import Policy, PolicyError, load_policy

__all__ = ["decide", "load_policy", "Policy", "PolicyError", "AlertError", "ContextError"]
