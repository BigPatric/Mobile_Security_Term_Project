"""gateway/base.py — the contract every policy check implements.

Which checks apply to which tool is decided by the policy config, not by the check."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class CallContext:
    tool: str
    args: Dict[str, Any]        # exactly as the agent sent them (opaque tokens)
    real_args: Dict[str, Any]   # detokenized: what the core will see


class Check:
    kind: str = "check"
    layer: str = "L1"

    def screen(self, ctx: CallContext) -> Optional[Dict[str, Any]]:
        """None = pass, a block dict = stop the call."""
        raise NotImplementedError

    def describe(self) -> str:
        return self.kind

    def block(self, ctx: CallContext, reason: str, violation: str, **extra: Any) -> Dict[str, Any]:
        return {"status": "blocked", "layer": self.layer, "check": self.kind, "tool": ctx.tool,
                "reason": reason, "violation": violation, **extra}
