"""
gateway/policy.py — ordered check chain per tool, from config
=============================================================
    policy:
      untrusted_sources: [get_alert_logs]
      identifier_params: [supi_token, supi, imsi]
      tools:
        "*":                         {checks: [identifier]}     # tools with no own entry
        trigger_pdu_session_release: {checks: [identifier, {freshness: {max_age_sec: 1}}]}

The first check that blocks stops the call before it reaches the core. Unknown check
types are rejected when the engine is built, not at call time.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .base import CallContext, Check
from .l1 import FreshnessCheck, IdentifierCheck, IdentifierTokenizer, L1ViewClient

DEFAULT_POLICY: Dict[str, Any] = {
    "untrusted_sources": ["get_alert_logs"],
    "identifier_params": ["supi_token", "supi", "imsi"],
    "tools": {"*": {"checks": ["identifier"]}},
}


def _parse_entry(entry: Any) -> Tuple[str, Dict[str, Any]]:
    if isinstance(entry, str):
        return entry, {}
    if isinstance(entry, dict) and len(entry) == 1:
        kind, opts = next(iter(entry.items()))
        return kind, dict(opts or {})
    raise ValueError(f"bad check entry {entry!r}: use a name or a single-key mapping")


class PolicyEngine:
    def __init__(self, spec: Dict[str, Any], tokenizer: IdentifierTokenizer,
                 views: Optional[L1ViewClient] = None):
        self.identifier_params: List[str] = sorted(spec.get("identifier_params")
                                                   or DEFAULT_POLICY["identifier_params"])
        self._identifier = IdentifierCheck(tokenizer, self.identifier_params)
        self._views = views
        self.chains: Dict[str, List[Check]] = {
            tool: [self._build(tool, e) for e in (t or {}).get("checks", [])]
            for tool, t in (spec.get("tools") or {}).items()}
        self.chains.setdefault("*", [self._identifier])     # never an unchecked default

    def _build(self, tool: str, entry: Any) -> Check:
        kind, opts = _parse_entry(entry)
        if kind == "identifier":
            return self._identifier
        if kind == "freshness":
            if self._views is None:
                raise ValueError(f"tool {tool!r}: 'freshness' needs a synchronized core (L1ViewClient)")
            return FreshnessCheck(self._views, **opts)
        raise ValueError(f"tool {tool!r}: unknown check type {kind!r} (known: identifier, freshness)")

    def screen(self, ctx: CallContext) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, str]]]:
        trace: List[Dict[str, str]] = []
        for check in self.chains.get(ctx.tool, self.chains["*"]):
            block = check.screen(ctx)
            trace.append({"check": check.describe(), "outcome": "block" if block else "pass"})
            if block is not None:
                return block, trace
        return None, trace
