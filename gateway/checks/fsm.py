"""
gateway/checks/fsm.py — L3 generic procedure state machine
==========================================================
A procedure (e.g. the TS 23.502 PDU-session life-cycle) is declared as DATA:

    procedures:
      pdu_session:
        key: ["supi_token|supi|imsi", "pdu_session_id"]   # arg fields; "a|b" = first present
        initial: UNKNOWN                                    # state of a never-seen instance
        states: [UNKNOWN, ACTIVE, RELEASED]
        observe:                                            # learn state from results
          - tool: query_subscriber_session
            when: {status: ok}
            for_each: subscriber.pdu_sessions
            key: [subscriber.supi, item.id]                 # item.* = the for_each element
            set: ACTIVE
            keep: [RELEASED]                                # never overwrite these
        transitions:
          release: {from: [ACTIVE, UNKNOWN], to: RELEASED,
                    commit_when: {status: ok, verified: true}}

A ProcedureStore holds the live state of every instance of one procedure. An
FsmCheck guards ONE event (transition) on ONE tool: it blocks the call if the
instance's current state is not in the transition's `from` set, and commits the
`to` state when the tool's result satisfies `commit_when`.

Adding a procedure (establishment, modification, slice change, …) is a config
change, not a code change.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from .base import Check, CallContext, get_path, is_authorized, matches

logger = logging.getLogger(__name__)

Key = Tuple[str, ...]


def _norm(v: Any) -> str:
    return "" if v is None else str(v)


class ProcedureStore:
    def __init__(self, name: str, spec: Dict[str, Any]):
        self.name = name
        self.key_fields: List[str] = list(spec["key"])
        self.initial: str = spec.get("initial", "UNKNOWN")
        self.states = set(spec.get("states", [])) | {self.initial}
        self.transitions: Dict[str, Dict[str, Any]] = dict(spec.get("transitions", {}))
        self.observe_rules: List[Dict[str, Any]] = list(spec.get("observe", []))
        self.state: Dict[Key, str] = {}
        self._validate()

    def _validate(self) -> None:
        for ev, t in self.transitions.items():
            bad = [s for s in list(t.get("from", [])) + [t.get("to")] if s not in self.states]
            if bad:
                raise ValueError(f"procedure {self.name!r}: transition {ev!r} uses undeclared state(s) {bad}")
        for r in self.observe_rules:
            if r.get("set") not in self.states:
                raise ValueError(f"procedure {self.name!r}: observe rule sets undeclared state {r.get('set')!r}")
            if len(r.get("key", [])) != len(self.key_fields):
                raise ValueError(f"procedure {self.name!r}: observe rule key must have {len(self.key_fields)} parts")

    # -- keys --------------------------------------------------------------
    def key_from_args(self, args: Dict[str, Any]) -> Key:
        parts = []
        for field in self.key_fields:
            val = None
            for alt in field.split("|"):
                if args.get(alt) is not None:
                    val = args[alt]
                    break
            parts.append(_norm(val))
        return tuple(parts)

    def get(self, key: Key) -> str:
        return self.state.get(key, self.initial)

    def set(self, key: Key, value: str) -> None:
        self.state[key] = value

    # -- observation rules -----------------------------------------------
    def observe(self, tool: str, result: Dict[str, Any]) -> None:
        for rule in self.observe_rules:
            if rule.get("tool") != tool or not matches(result, rule.get("when")):
                continue
            items = get_path(result, rule["for_each"]) if rule.get("for_each") else [None]
            for item in items or []:
                key = tuple(_norm(get_path({"item": item}, p) if p.startswith("item.")
                                  else get_path(result, p)) for p in rule["key"])
                if self.get(key) in set(rule.get("keep", [])):
                    continue
                self.set(key, rule["set"])

    def snapshot(self) -> Dict[str, str]:
        return {"#".join(k): v for k, v in self.state.items()}


class FsmCheck(Check):
    kind = "fsm"
    layer = "L3"

    def __init__(self, store: ProcedureStore, event: str, tool: str, exempt_authorized: bool = False):
        if event not in store.transitions:
            raise ValueError(f"procedure {store.name!r} has no transition {event!r}")
        self.store = store
        self.event = event
        self.tool = tool
        self.transition = store.transitions[event]
        self.allowed_from = set(self.transition.get("from", []))
        self.exempt_authorized = exempt_authorized

    def describe(self) -> str:
        return f"fsm({self.store.name}.{self.event})"

    def screen(self, ctx: CallContext) -> Optional[Dict[str, Any]]:
        if self.exempt_authorized and is_authorized(ctx.real_args):
            return None
        key = self.store.key_from_args(ctx.real_args)
        state = self.store.get(key)
        if state in self.allowed_from:
            return None
        inst = "#".join(key)
        if state == self.store.initial:
            violation = "fsm-no-context"
            reason = (f"out-of-state: no established {self.store.name} context observed for {inst}; "
                      f"'{self.event}' requires one of {sorted(self.allowed_from)}")
        else:
            violation = "fsm-out-of-state"
            reason = (f"out-of-state: {self.store.name} {inst} is {state}; "
                      f"'{self.event}' is only legal from {sorted(self.allowed_from)}")
        return self.block(ctx, reason, violation=violation, procedure=self.store.name,
                          event=self.event, fsm_state=state, instance=list(key))

    def observe(self, tool: str, args: Dict[str, Any], result: Dict[str, Any]) -> None:
        if tool != self.tool or not matches(result, self.transition.get("commit_when")):
            return
        key = self.store.key_from_args(args)
        self.store.set(key, self.transition["to"])
        logger.info("[GW:L3] FSM %s %s -> %s", self.store.name, "#".join(key), self.transition["to"])
