"""
gateway/mcp_gateway.py — the enforcing ToolClient in front of the agent
=======================================================================
    agent --args(tokens)--> [checks] [detokenize identifier args] --> inner --> core
    agent <--result-------- [tokenize / mask] <----------------------- inner <-- core

It implements the agent's ToolClient interface, so it drops into the seam without
changing the agent. Build one per agent session with build_l1_gateway().
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

from agent.tool_client import ToolClient
from .base import CallContext
from .l1 import IdentifierTokenizer, L1ViewClient, SyncEngine
from .policy import DEFAULT_POLICY, PolicyEngine

logger = logging.getLogger(__name__)


class GatewayToolClient(ToolClient):
    def __init__(self, inner: ToolClient, tokenizer: IdentifierTokenizer,
                 policy: Optional[Dict[str, Any]] = None, views: Optional[L1ViewClient] = None):
        spec = policy if policy is not None else DEFAULT_POLICY
        self.inner, self.tokenizer = inner, tokenizer
        self.engine = PolicyEngine(spec, tokenizer, views)
        self.untrusted_sources = set(spec.get("untrusted_sources") or [])
        # Attacker-writable results: mask identifiers instead of tokenizing them, so a
        # SUPI planted in a log never yields its token.
        self.untrusted_identifiers = spec.get("untrusted_identifiers", "mask")
        if self.untrusted_identifiers not in ("mask", "tokenize"):
            raise ValueError("untrusted_identifiers must be 'mask' or 'tokenize'")
        self.decisions: List[Dict[str, Any]] = []

    def list_schema(self) -> List[Dict[str, Any]]:
        return self.inner.list_schema()

    def _outbound(self, name: str, obj: Any) -> Any:
        untrusted = name in self.untrusted_sources or (
            isinstance(obj, dict) and obj.get("provenance") == "UNTRUSTED")
        if untrusted and self.untrusted_identifiers == "mask":
            return self.tokenizer.mask(obj)
        return self.tokenizer.tokenize(obj)

    def invoke(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        t0 = time.perf_counter()
        arguments = arguments or {}
        real_args = self.tokenizer.detokenize_fields(arguments, self.engine.identifier_params)
        block, trace = self.engine.screen(CallContext(name, arguments, real_args))
        rec: Dict[str, Any] = {"seq": len(self.decisions) + 1, "tool": name, "trace": trace,
                               "decision": "block" if block else "allow",
                               "check_ms": round((time.perf_counter() - t0) * 1e3, 3)}
        self.decisions.append(rec)
        if block is not None:
            rec.update(check=block["check"], violation=block["violation"])
            logger.warning("[GW] BLOCKED %s by %s: %s", name, block["check"], block["violation"])
            return self.tokenizer.redact({**block, "trace": trace})     # never mints
        return self._outbound(name, self.inner.invoke(name, real_args))


def build_l1_gateway(inner: ToolClient, sync: SyncEngine, cfg: Dict[str, Any], secret: bytes,
                     scope: str, **tokenizer_kw) -> GatewayToolClient:
    """Gateway for ONE agent session (`scope`) over a synchronized core. `cfg` is the
    `l1` section of config.yaml; `sync` is shared by every session in front of the core."""
    tok = IdentifierTokenizer(secret, scope=scope, population=sync.store.supis,
                              **{**(cfg.get("tokens") or {}), **tokenizer_kw})
    views = L1ViewClient(inner, sync, tok, secret=secret, **(cfg.get("views") or {}))
    return GatewayToolClient(views, tok, policy=cfg["policy"], views=views)
