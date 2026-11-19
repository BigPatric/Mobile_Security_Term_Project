"""
gateway/checks/allowlist.py — generic deny rule (RBAC / allow-list baseline)
============================================================================
`deny` refuses the call outright. Put it on "*" and list the permitted tools
explicitly to get a classic role allow-list. Layer "L0" = not part of the
three-layer defense; it is always on, and exists so a generic RBAC baseline can
be expressed in the same policy language and compared head to head.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .base import Check, CallContext


class DenyCheck(Check):
    kind = "deny"
    layer = "L0"

    def screen(self, ctx: CallContext) -> Optional[Dict[str, Any]]:
        return self.block(ctx, f"tool {ctx.tool!r} is not on the allow-list for this role",
                          violation="not-allowed")
