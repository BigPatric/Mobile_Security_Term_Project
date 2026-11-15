"""gateway — Secure MCP Gateway (three-layer lightweight defense proxy).

Layer 1 : IdentifierTokenizer  (tokenizer.py)      — identifier opacity  [ACTIVE]
Layer 2 : Provenance & Taint   (taint_tracker.py)  — untrusted-driven block [ACTIVE]
Layer 3 : Procedure-Aware FSM  (verifier.py)       — planned

The enforcement point sits behind the agent's ToolClient seam, so the agent code
never changes: a GatewayToolClient drops in where the LocalToolClient was.
"""
from .tokenizer import IdentifierTokenizer  # noqa: F401
from .taint_tracker import TaintTracker  # noqa: F401
from .mcp_gateway import GatewayToolClient  # noqa: F401
