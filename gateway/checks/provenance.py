"""
gateway/checks/provenance.py — L2 provenance / taint check
==========================================================
Thin policy adapter over TaintTracker: screen() refuses a high-risk call driven
by untrusted content. Options (config):
    allow_authorized      a valid operator authorization lets a tainted call through
    verify_authorization  the authorization must be a gateway-signed capability
                          (default). false = legacy: any non-empty claim passes.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .base import Check, CallContext
from ..taint_tracker import TaintTracker


class ProvenanceCheck(Check):
    kind = "provenance"
    layer = "L2"

    def __init__(self, taint: TaintTracker, allow_authorized: bool = True,
                 verify_authorization: bool = True):
        self.taint = taint
        self.allow_authorized = allow_authorized
        self.verify_authorization = verify_authorization

    def describe(self) -> str:
        return self.kind if self.verify_authorization or not self.allow_authorized else "provenance(claim)"

    def screen(self, ctx: CallContext) -> Optional[Dict[str, Any]]:
        block = self.taint.check_sink(ctx.tool, ctx.real_args, allow_authorized=self.allow_authorized,
                                      verify_authorization=self.verify_authorization)
        if block is not None:
            block.setdefault("check", self.kind)
            block.setdefault("violation", f"taint-{block.get('taint_kind') or 'untrusted'}")
        return block
    # Taint propagation (observe) is done once per result by the PolicyEngine on
    # the shared TaintTracker, not per ProvenanceCheck instance.
