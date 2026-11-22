"""gateway — Secure MCP Gateway (config-driven, three-layer defense proxy).

Policy pipeline : PolicyEngine (policy.py) — per-tool ordered check chains from config
Layer 1 : identifier opacity  — IdentifierTokenizer (tokenizer.py) + identifier check
Layer 2 : provenance / taint  — TaintTracker (taint_tracker.py) + provenance check,
          signed operator capabilities (capability.py)
Layer 3 : procedure-aware     — fsm / rate / core_precheck checks (checks/), procedures.py
Baseline: deny check (L0) expresses a generic RBAC allow-list in the same language

The enforcement point sits behind the agent's ToolClient seam, so the agent code
never changes: a GatewayToolClient drops in where the LocalToolClient was.
"""
from .tokenizer import IdentifierTokenizer  # noqa: F401
from .taint_tracker import TaintTracker  # noqa: F401
from .capability import CapabilityAuthority  # noqa: F401
from .policy import DEFAULT_POLICY, PolicyEngine  # noqa: F401
from .mcp_gateway import GatewayToolClient, build_gateway_client  # noqa: F401
