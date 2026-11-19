"""
gateway/checks/provenance.py — L2 provenance / taint check
==========================================================
Thin policy adapter over TaintTracker: screen() refuses a high-risk call driven
by untrusted content.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .base import Check, CallContext
from ..taint_tracker import TaintTracker


class ProvenanceCheck(Check):
    kind = "provenance"
    layer = "L2"

    def __init__(self, taint: TaintTracker, allow_authorized: bool = True):
        self.taint = taint
        self.allow_authorized = allow_authorized

    def screen(self, ctx: CallContext) -> Optional[Dict[str, Any]]:
        block = self.taint.check_sink(ctx.tool, ctx.real_args, allow_authorized=self.allow_authorized)
        if block is not None:
            block.setdefault("check", self.kind)
            block.setdefault("violation", f"taint-{block.get('taint_kind') or 'untrusted'}")
        return block
    # Taint propagation (observe) is done once per result by the PolicyEngine on
    # the shared TaintTracker, not per ProvenanceCheck instance.
