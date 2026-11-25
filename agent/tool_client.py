"""
agent/tool_client.py — the tool-invocation seam between the agent and the 5G tools
==================================================================================
The agent never imports `free5gc_tools` and never calls a tool function by
reference. It talks to a ToolClient, whose entire contract is:

    list_schema() -> list[dict]        # tool declarations advertised to the LLM
    invoke(name, arguments) -> dict    # call a tool, return its JSON result

Today the only implementation is `LocalToolClient` (in-process calls straight to
the tool registry). When the Secure MCP Gateway is built, an `McpToolClient`
implementing the SAME interface drops in here and the agent code does not change.

This is what makes the agent "gateway-ready": the enforcement point — identifier
tokenization, synchronized views, freshness checks — lives BEHIND this
seam (in the gateway), not inside the agent. The agent only ever sees opaque
tool names, whatever identifier tokens it is handed, and JSON results; it has no
knowledge of whether a tool ran locally or behind a remote MCP gateway.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class ToolClient:
    """Interface the agent depends on. Implementations: LocalToolClient (now),
    McpToolClient (once the gateway exists)."""

    def list_schema(self) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def invoke(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError


class LocalToolClient(ToolClient):
    """
    In-process tool client — a stand-in for the future MCP gateway client.

    It calls the tool functions directly. The agent is written against the
    ToolClient interface, so swapping this for an McpToolClient that speaks MCP
    to the Secure Gateway requires no change to the agent.
    """

    def __init__(self, tool_registry: Dict[str, Callable[..., Dict[str, Any]]],
                 schema: Optional[List[Dict[str, Any]]] = None):
        self._registry = dict(tool_registry)
        self._schema = list(schema) if schema else []

    def list_schema(self) -> List[Dict[str, Any]]:
        return self._schema

    def invoke(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        fn = self._registry.get(name)
        if fn is None:
            logger.error("[TOOLCLIENT] unknown tool requested: %s", name)
            return {"status": "error", "error": f"Unknown tool: {name}"}
        return fn(**(arguments or {}))


def default_local_client() -> LocalToolClient:
    """Build a LocalToolClient wired to the real free5gc_tools registry + schema."""
    from free5gc_tools import TOOL_REGISTRY, TOOL_SCHEMA
    return LocalToolClient(TOOL_REGISTRY, TOOL_SCHEMA)
