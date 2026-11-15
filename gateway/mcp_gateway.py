"""
gateway/mcp_gateway.py — Secure MCP Gateway main proxy
======================================================
The gateway implements the agent's ``ToolClient`` interface, so it drops into
the exact seam where ``LocalToolClient`` sat ([agent/tool_client.py]) without
touching the agent. Every tool call the agent makes now crosses the gateway
boundary, where the three defense layers are enforced:

    agent --args(tokens)-->  [L1 detokenize]  [L2 taint*]  [L3 verify*] --> inner tool --> free5GC
    agent <--result(tokens)-- [L1 tokenize]                               <-- inner tool <-- free5GC

      L1 Identifier Tokenizer   — ACTIVE
      L2 Provenance/Taint       — ACTIVE (hooks the same invoke boundary, both directions)
      L3 Procedure-Aware FSM    — * planned

``inner`` is any ToolClient: today the in-process LocalToolClient (direct calls
to free5gc_tools); later an McpToolClient speaking MCP to a remote 5GC. The
gateway is agnostic to which.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set

from agent.tool_client import ToolClient
from .tokenizer import IdentifierTokenizer
from .taint_tracker import TaintTracker

logger = logging.getLogger(__name__)

# Argument names that are supposed to carry a subscriber identifier. A value in
# one of these MUST be a valid gateway-minted token (proposal slide 6, Rule B).
_IDENTIFIER_PARAMS: Set[str] = {"supi_token", "supi", "imsi"}


class GatewayToolClient(ToolClient):
    """Enforcing wrapper around an inner ToolClient.

    Layers are individually switchable so the evaluation harness can run the
    ablation study (proposal slide 8): drop each layer and re-measure.
        enable_tokenizer -> Layer 1 (identifier opacity + raw-SUPI rejection)
        enable_taint     -> Layer 2 (provenance / taint tracking)
    """

    def __init__(self, inner: ToolClient, tokenizer: Optional[IdentifierTokenizer] = None,
                 identifier_params: Optional[Set[str]] = None,
                 enable_tokenizer: bool = True, enable_taint: bool = True,
                 taint: Optional[TaintTracker] = None):
        self.inner = inner
        self.tokenizer = tokenizer or IdentifierTokenizer()
        self.identifier_params = identifier_params if identifier_params is not None else _IDENTIFIER_PARAMS
        self.enable_tokenizer = enable_tokenizer
        self.taint = taint if taint is not None else (TaintTracker() if enable_taint else None)

    def active_layers(self) -> List[str]:
        layers = []
        if self.enable_tokenizer:
            layers.append("tokenizer")
        if self.taint is not None:
            layers.append("taint")
        return layers

    # The agent discovers tools unchanged — the gateway is transparent here.
    def list_schema(self) -> List[Dict[str, Any]]:
        return self.inner.list_schema()

    # ------------------------------------------------------------------ #
    # L1 argument policy (proposal slide 6): reject identifier arguments that
    # are not valid gateway tokens — a raw SUPI can only come from untrusted
    # input, and an unknown token was never issued by this gateway.
    # ------------------------------------------------------------------ #
    def _screen_args(self, name: str, arguments: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        for key, val in arguments.items():
            if not isinstance(val, str):
                continue
            # Rule A — a raw SUPI must never appear in ANY argument.
            if self.tokenizer.contains_raw_supi(val):
                return self._blocked(name, key,
                    f"raw identifier in argument {key!r}; the agent is only ever handed "
                    f"opaque tokens, so a raw SUPI can only originate from untrusted input")
            # Rule B — a designated identifier argument must be a VALID token.
            if key in self.identifier_params and not self.tokenizer.is_known_token(val):
                return self._blocked(name, key,
                    f"argument {key!r}={val!r} is not a valid gateway-issued token")
        return None

    @staticmethod
    def _blocked(name: str, key: str, reason: str) -> Dict[str, Any]:
        return {"status": "blocked", "layer": "L1", "tool": name, "argument": key, "reason": reason}

    def invoke(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        arguments = arguments or {}

        if self.enable_tokenizer:
            # L1 policy gate — reject raw SUPI / invalid token before anything
            # reaches the core (runs on the agent-supplied args).
            block = self._screen_args(name, arguments)
            if block is not None:
                logger.warning("[GW:L1] BLOCKED %s(%s): %s", name, arguments, block["reason"])
                return block
            # IN (agent -> core): restore real SUPIs from the opaque tokens.
            real_args = self.tokenizer.detokenize(arguments)
            if real_args != arguments:
                logger.info("[GW:L1] detokenized args for %s", name)
        else:
            real_args = arguments

        # L2 taint gate — reject an untrusted-driven high-risk call BEFORE it
        # reaches the core (runs on the real, detokenized args).
        if self.taint is not None:
            block = self.taint.screen_call(name, real_args)
            if block is not None:
                logger.warning("[GW:L2] BLOCKED %s: %s", name, block["reason"])
                return block

        result = self.inner.invoke(name, real_args)

        # L2: propagate taint from untrusted sources (raw result, pre-tokenize).
        if self.taint is not None:
            self.taint.observe_result(name, result)

        if self.enable_tokenizer:
            # OUT (core -> agent): replace every real SUPI with an opaque token.
            safe_result = self.tokenizer.tokenize(result)
            if safe_result != result:
                logger.info("[GW:L1] tokenized %d identifier(s) in %s result",
                            self.tokenizer.mapping_count(), name)
            return safe_result
        return result


def build_gateway_client(inner: ToolClient) -> GatewayToolClient:
    """Wrap an inner ToolClient in the Secure MCP Gateway (Layer 1 active)."""
    return GatewayToolClient(inner, IdentifierTokenizer())
