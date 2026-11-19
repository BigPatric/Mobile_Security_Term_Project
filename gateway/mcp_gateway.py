"""
gateway/mcp_gateway.py — Secure MCP Gateway main proxy
======================================================
The gateway implements the agent's ``ToolClient`` interface, so it drops into
the exact seam where ``LocalToolClient`` sat ([agent/tool_client.py]) without
touching the agent. Every tool call the agent makes crosses this boundary:

    agent --args(tokens)--> [detokenize] [policy chain for this tool] --> inner tool --> free5GC
    agent <--result(tokens)-- [tokenize]  [observe: taint, FSM, ...]  <-- inner tool <-- free5GC

The policy chain is config-driven (gateway/policy.py): each tool declares an
ordered list of checks; the first one that blocks stops the call before it
reaches the core. Checks belong to three layers:

      L1 Identifier opacity      — identifier check (+ the tokenize transform)
      L2 Provenance / taint      — provenance check
      L3 Procedure-aware         — fsm, rate, core_precheck checks

Every decision (allow/block, which check, gateway overhead) is recorded in
``decisions`` for the evidence log.

``inner`` is any ToolClient: today the in-process LocalToolClient (direct calls
to free5gc_tools); later an McpToolClient speaking MCP to a remote 5GC.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Set

from agent.tool_client import ToolClient
from .checks import CallContext
from .policy import DEFAULT_POLICY, PolicyEngine
from .tokenizer import IdentifierTokenizer
from .taint_tracker import TaintTracker
from .verifier import ProcedureVerifier

logger = logging.getLogger(__name__)


class GatewayToolClient(ToolClient):
    """Enforcing wrapper around an inner ToolClient.

    Layers are individually switchable for the ablation study (proposal slide 8):
        enable_tokenizer -> L1 (identifier opacity + identifier check)
        enable_taint     -> L2 (provenance / taint check)
        enable_verifier  -> L3 (fsm / rate / core_precheck checks)

    ``policy`` is a policy spec (see gateway/policy.py); default DEFAULT_POLICY.
    ``verifier`` (legacy) replaces the L3 checks on the PDU-release tool with a
    given ProcedureVerifier instance.
    """

    def __init__(self, inner: ToolClient, tokenizer: Optional[IdentifierTokenizer] = None,
                 identifier_params: Optional[Set[str]] = None,
                 enable_tokenizer: bool = True, enable_taint: bool = True,
                 enable_verifier: bool = True,
                 taint: Optional[TaintTracker] = None,
                 verifier: Optional[ProcedureVerifier] = None,
                 policy: Optional[Dict[str, Any]] = None,
                 now_fn=time.monotonic):
        self.inner = inner
        self.tokenizer = tokenizer or IdentifierTokenizer()
        self.enable_tokenizer = enable_tokenizer
        spec = dict(policy if policy is not None else DEFAULT_POLICY)
        if identifier_params is not None:
            spec["identifier_params"] = sorted(identifier_params)
        self.engine = PolicyEngine(
            spec,
            layers={"tokenizer": enable_tokenizer, "taint": enable_taint,
                    "verifier": enable_verifier or verifier is not None},
            tokenizer=self.tokenizer, taint=taint, now_fn=now_fn)
        if verifier is not None:
            for tool in verifier.HIGH_RISK_SINKS:
                self.engine.replace_layer(tool, "L3", verifier)
        self.decisions: List[Dict[str, Any]] = []

    # -- introspection -------------------------------------------------------
    @property
    def taint(self) -> TaintTracker:
        return self.engine.taint

    def active_layers(self) -> List[str]:
        names = {"L0": "allowlist", "L1": "tokenizer", "L2": "taint", "L3": "verifier"}
        layers = set(self.engine.active_layers())
        if self.enable_tokenizer:
            layers.add("L1")
        return [names.get(l, l) for l in sorted(layers)]

    def list_schema(self) -> List[Dict[str, Any]]:
        return self.inner.list_schema()    # tool discovery is transparent

    # -- the boundary --------------------------------------------------------
    def _internal_invoke(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Trusted gateway->core call (e.g. core_precheck). Never shown to the agent,
        but its result still updates gateway state (FSM, taint)."""
        result = self.inner.invoke(name, args)
        self.engine.observe(name, args, result)
        return result

    def _outbound(self, obj: Any) -> Any:
        return self.tokenizer.tokenize(obj) if self.enable_tokenizer else obj

    def invoke(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        t0 = time.perf_counter()
        arguments = arguments or {}
        real_args = self.tokenizer.detokenize(arguments) if self.enable_tokenizer else arguments

        ctx = CallContext(name, arguments, real_args, self._internal_invoke)
        block, trace = self.engine.screen(ctx)
        if block is not None:
            logger.warning("[GW:%s] BLOCKED %s by %s: %s", block.get("layer"), name,
                           block.get("check"), block.get("reason"))
            block["trace"] = trace
            self._record(name, "block", trace, t0, core_ms=0.0, block=block)
            # A block must not leak identifiers either: known SUPIs become their
            # tokens, unknown ones are redacted (never mint tokens for injected IDs).
            return self.tokenizer.redact(block) if self.enable_tokenizer else block

        t_core = time.perf_counter()
        result = self.inner.invoke(name, real_args)
        core_ms = (time.perf_counter() - t_core) * 1000
        self.engine.observe(name, real_args, result)
        self._record(name, "allow", trace, t0, core_ms=core_ms)
        return self._outbound(result)

    def _record(self, tool: str, decision: str, trace, t0: float, core_ms: float,
                block: Optional[Dict[str, Any]] = None) -> None:
        total_ms = (time.perf_counter() - t0) * 1000
        rec = {"seq": len(self.decisions) + 1, "tool": tool, "decision": decision,
               "trace": trace, "gateway_overhead_ms": round(total_ms - core_ms, 3),
               "core_ms": round(core_ms, 3)}
        if block is not None:
            rec.update({"layer": block.get("layer"), "check": block.get("check"),
                        "violation": block.get("violation")})
        self.decisions.append(rec)


def build_gateway_client(inner: ToolClient, policy: Optional[Dict[str, Any]] = None,
                         layers: Optional[Dict[str, bool]] = None) -> GatewayToolClient:
    """Wrap an inner ToolClient in the Secure MCP Gateway from a policy spec."""
    layers = layers or {}
    return GatewayToolClient(inner, policy=policy,
                             enable_tokenizer=layers.get("tokenizer", True),
                             enable_taint=layers.get("taint", True),
                             enable_verifier=layers.get("verifier", True))
