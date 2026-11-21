"""
gateway/policy.py — config-driven policy pipeline
=================================================
Turns a declarative policy spec into an ordered chain of checks per tool:

    policy:
      untrusted_sources: [get_alert_logs]
      identifier_params: [supi_token, supi, imsi]
      procedures: { pdu_session: {...} }            # see gateway/checks/fsm.py
      tools:
        "*":                            {checks: [identifier]}     # tools with no own entry
        trigger_pdu_session_release:
          checks:                        # run in order; first block wins
            - identifier
            - provenance: {allow_authorized: true}
            - fsm:  {procedure: pdu_session, event: release}
            - rate: {bucket: pdu_release, max: 2, window_sec: 60}
            - core_precheck: {via: ..., args: {...}, expect: {...}}

Check types and their layer (for ablation toggles):
    identifier    L1    provenance    L2    fsm / rate / core_precheck    L3
    deny          L0  (generic allow-list rule, always on — for the RBAC baseline)

Disabling a layer drops its checks from every chain. Unknown check types,
procedures or events are rejected when the engine is built, not at call time.
"""

from __future__ import annotations

import copy
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from .checks import (Check, CallContext, CorePrecheck, DenyCheck, FsmCheck, IdentifierCheck,
                     ProcedureStore, ProvenanceCheck, RateBucket, RateCheck)
from .procedures import pdu_session_procedure
from .taint_tracker import TaintTracker
from .tokenizer import IdentifierTokenizer

CHECK_LAYERS = {"deny": "L0", "identifier": "L1", "provenance": "L2",
                "fsm": "L3", "rate": "L3", "core_precheck": "L3"}

# Layer toggle names used in config.yaml (gateway.layers) -> layer id.
LAYER_NAMES = {"tokenizer": "L1", "taint": "L2", "verifier": "L3"}

# Code default: equivalent to the pre-pipeline gateway. config.yaml overrides it.
# core_precheck is NOT in the default because it needs a live core to query.
DEFAULT_POLICY: Dict[str, Any] = {
    "untrusted_sources": ["get_alert_logs"],
    "identifier_params": ["supi_token", "supi", "imsi"],
    "procedures": {"pdu_session": pdu_session_procedure()},
    "tools": {
        "*": {"checks": ["identifier"]},
        "trigger_pdu_session_release": {"checks": [
            "identifier",
            {"provenance": {"allow_authorized": True}},
            {"fsm": {"procedure": "pdu_session", "event": "release"}},
            {"rate": {"bucket": "pdu_release", "max": 3, "window_sec": 60}},
        ]},
    },
}


class SharedCoreState:
    """Procedure (FSM) state and rate budgets that belong to the CORE, not to one
    agent session.

    Taint is per session: one poisoned alert should not taint other sessions.
    But "at most N releases per window" and "this session is already RELEASED"
    are facts about the core. If every agent session built its own gateway with
    its own buckets, an attacker who triggers k sessions would get k budgets and
    no session would know what another had released. A deployment therefore
    passes ONE SharedCoreState to the gateway of every session that fronts the
    same core. Without it, each gateway keeps private state (the per-run setup
    used by the experiments, where every run starts from a fresh core anyway)."""

    def __init__(self) -> None:
        self.procedures: Dict[str, ProcedureStore] = {}
        self.buckets: Dict[str, RateBucket] = {}


def _parse_entry(entry: Any) -> Tuple[str, Dict[str, Any]]:
    if isinstance(entry, str):
        return entry, {}
    if isinstance(entry, dict) and len(entry) == 1:
        kind, opts = next(iter(entry.items()))
        return kind, dict(opts or {})
    raise ValueError(f"bad check entry {entry!r}: use a name or a single-key mapping")


class PolicyEngine:
    def __init__(self, spec: Optional[Dict[str, Any]] = None,
                 layers: Optional[Dict[str, bool]] = None,
                 tokenizer: Optional[IdentifierTokenizer] = None,
                 taint: Optional[TaintTracker] = None,
                 now_fn: Callable[[], float] = time.monotonic,
                 shared: Optional[SharedCoreState] = None):
        self.spec = copy.deepcopy(spec if spec is not None else DEFAULT_POLICY)
        self.enabled_layers = {"L0"} | {lid for name, lid in LAYER_NAMES.items()
                                        if (layers or {}).get(name, True)}
        self.tokenizer = tokenizer or IdentifierTokenizer()
        self._now = now_fn

        self.taint = taint or TaintTracker(untrusted_sources=self.spec.get("untrusted_sources"))
        # FSM state and rate buckets: private to this gateway, or shared with every
        # other session's gateway in front of the same core (see SharedCoreState).
        proc_pool = shared.procedures if shared is not None else {}
        self.procedures: Dict[str, ProcedureStore] = {}
        for name, p in (self.spec.get("procedures") or {}).items():
            if name not in proc_pool:
                proc_pool[name] = ProcedureStore(name, p)
            self.procedures[name] = proc_pool[name]
        self.buckets: Dict[str, RateBucket] = shared.buckets if shared is not None else {}
        # shared singletons so state (taint, tokens) is one per session
        self._identifier = IdentifierCheck(self.tokenizer,
                                           self.spec.get("identifier_params", ["supi_token", "supi", "imsi"]))
        self._provenance: Dict[bool, ProvenanceCheck] = {}

        self.chains: Dict[str, List[Check]] = {}
        for tool, tspec in (self.spec.get("tools") or {}).items():
            self.chains[tool] = [c for c in (self._build(tool, e) for e in (tspec or {}).get("checks", []))
                                 if c is not None]

    # ------------------------------------------------------------------ #
    def _build(self, tool: str, entry: Any) -> Optional[Check]:
        kind, opts = _parse_entry(entry)
        if kind not in CHECK_LAYERS:
            raise ValueError(f"tool {tool!r}: unknown check type {kind!r} (known: {sorted(CHECK_LAYERS)})")
        if CHECK_LAYERS[kind] not in self.enabled_layers:
            return None
        if kind == "deny":
            return DenyCheck()
        if kind == "identifier":
            return self._identifier
        if kind == "provenance":
            allow = bool(opts.get("allow_authorized", True))
            if allow not in self._provenance:
                self._provenance[allow] = ProvenanceCheck(self.taint, allow_authorized=allow)
            return self._provenance[allow]
        if kind == "fsm":
            proc = opts.get("procedure")
            if proc not in self.procedures:
                raise ValueError(f"tool {tool!r}: fsm references unknown procedure {proc!r}")
            return FsmCheck(self.procedures[proc], opts["event"], tool=tool,
                            exempt_authorized=bool(opts.get("exempt_authorized", False)))
        if kind == "rate":
            name = opts.get("bucket", tool)
            if name not in self.buckets:
                self.buckets[name] = RateBucket(name, opts.get("max", 3), opts.get("window_sec", 60),
                                                now_fn=self._now)
            return RateCheck(self.buckets[name], exempt_authorized=bool(opts.get("exempt_authorized", False)))
        if kind == "core_precheck":
            return CorePrecheck(opts["via"], opts.get("args", {}), opts.get("expect", {}))
        raise AssertionError(kind)

    def replace_layer(self, tool: str, layer: str, check: Check) -> None:
        """Swap every `layer` check on `tool` for a single given check (keeps order)."""
        chain = self.chains.setdefault(tool, list(self.chains.get("*", [])))
        out, placed = [], False
        for c in chain:
            if c.layer == layer:
                if not placed:
                    out.append(check)
                    placed = True
            else:
                out.append(c)
        if not placed:
            out.append(check)
        self.chains[tool] = out

    @property
    def identifier_params(self) -> List[str]:
        return sorted(self._identifier.identifier_params)

    # ------------------------------------------------------------------ #
    def chain_for(self, tool: str) -> List[Check]:
        return self.chains.get(tool, self.chains.get("*", []))

    def screen(self, ctx: CallContext) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, str]]]:
        trace: List[Dict[str, str]] = []
        for check in self.chain_for(ctx.tool):
            block = check.screen(ctx)
            trace.append({"check": check.describe(), "layer": check.layer,
                          "outcome": "block" if block else "pass"})
            if block is not None:
                return block, trace
        return None, trace

    def all_checks(self) -> List[Check]:
        seen, out = set(), []
        for chain in self.chains.values():
            for c in chain:
                if id(c) not in seen:
                    seen.add(id(c))
                    out.append(c)
        return out

    def observe(self, tool: str, args: Dict[str, Any], result: Dict[str, Any]) -> None:
        if not isinstance(result, dict):
            return
        for store in self.procedures.values():
            store.observe(tool, result)
        # taint is session-wide state: propagate it exactly once per result
        self.taint.observe_result(tool, result)
        for c in self.all_checks():
            c.observe(tool, args, result)

    # ------------------------------------------------------------------ #
    def active_layers(self) -> List[str]:
        return sorted({c.layer for c in self.all_checks()})

    def describe(self) -> Dict[str, List[str]]:
        return {tool: [c.describe() for c in chain] for tool, chain in self.chains.items()}

    def state(self) -> Dict[str, Any]:
        return {"taint": self.taint.state(),
                "procedures": {n: s.snapshot() for n, s in self.procedures.items()},
                "rate": {n: f"{b.count()}/{b.max} in {b.window_sec:g}s" for n, b in self.buckets.items()}}
