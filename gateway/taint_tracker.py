"""
gateway/taint_tracker.py — Layer 2: Provenance & Taint Tracking
===============================================================
Layer 1 makes identifiers opaque; it does NOT stop the agent from *acting* on an
injected directive. Layer 2 does: it tracks whether content from an untrusted
source has influenced the session, and refuses to let that content drive a
high-risk, state-changing operation on the 5G core.

Model (proposal slide 6 — "value-level provenance at the tool-call boundary"):

  * SOURCES  — tools whose output is attacker-controllable (alert logs). When one
    returns, the session is marked TAINTED and the concrete values it carried
    (e.g. SUPIs named in the log) are recorded as tainted fingerprints.

  * SINKS    — high-risk, state-changing tools (PDU release, slice-quota change).
    Before such a call reaches the core, Layer 2 rejects it when:
      (a) one of its argument values matches a tainted fingerprint  — the action
          is literally parameterised by injected content (value-level taint), or
      (b) the session is tainted at all and the call carries no operator
          authorization — a high-risk change driven by untrusted influence
          (control-flow taint / taint laundering).

A legitimate, operator-authorised maintenance action passes by carrying an
explicit authorization capability, so benign operations are not blocked
(keeping the benign false-positive rate low — proposal slide 8).

Aligns with Progent (privilege control on tool calls) and CaMeL (untrusted data
must not trigger security-sensitive actions).
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# 15-digit SUPI with or without the imsi- prefix; group(1) is the bare digits.
_ID_RE = re.compile(r"(?:imsi-)?(\d{15})")


class TaintTracker:
    # Tools whose output is untrusted monitoring telemetry (the injection surface).
    UNTRUSTED_SOURCES: Set[str] = {"get_alert_logs"}
    # State-changing, high-risk sinks that untrusted input must never drive.
    HIGH_RISK_SINKS: Set[str] = {"trigger_pdu_session_release", "modify_slice_quota"}

    def __init__(self) -> None:
        self.tainted_active: bool = False
        self.tainted_fingerprints: Set[str] = set()
        self.provenance: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # OUT path: after a tool returns, propagate taint from untrusted sources.
    # Runs on the RAW (pre-tokenize) result so fingerprints are real values.
    # ------------------------------------------------------------------ #
    def observe_result(self, tool_name: str, result: Dict[str, Any]) -> None:
        untrusted = tool_name in self.UNTRUSTED_SOURCES or (
            isinstance(result, dict) and result.get("provenance") == "UNTRUSTED")
        if not untrusted:
            return
        self.tainted_active = True
        text = json.dumps(result, ensure_ascii=False) if not isinstance(result, str) else result
        for digits in _ID_RE.findall(text):
            self.tainted_fingerprints.add(digits)
        src_id = result.get("log", {}).get("id") if isinstance(result, dict) else None
        self.provenance.append({"source_tool": tool_name, "source_id": src_id})
        logger.warning("[GW:L2] taint propagated from %s (id=%s); %d fingerprint(s)",
                       tool_name, src_id, len(self.tainted_fingerprints))

    # ------------------------------------------------------------------ #
    # IN path: before a high-risk tool runs, reject untrusted-driven calls.
    # Runs on the DETOKENIZED (real) args so value matching sees real SUPIs.
    # ------------------------------------------------------------------ #
    def screen_call(self, tool_name: str, real_args: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if tool_name not in self.HIGH_RISK_SINKS:
            return None
        if self._authorized(real_args):
            logger.info("[GW:L2] high-risk %s permitted — operator authorization present", tool_name)
            return None

        argtext = json.dumps(real_args, ensure_ascii=False)
        matched = sorted(fp for fp in self.tainted_fingerprints if fp in argtext)
        if matched:
            return self._blocked(tool_name,
                f"value-level taint: argument value(s) {matched} were introduced by {self._sources_str()}; "
                f"a high-risk state change cannot be parameterised by injected content",
                taint_kind="value-level", matched_values=matched)
        if self.tainted_active:
            return self._blocked(tool_name,
                f"control-flow taint: high-risk state change attempted after untrusted content from "
                f"{self._sources_str()} was consumed this session, with no operator authorization "
                f"(suspected prompt injection / taint laundering)",
                taint_kind="control-flow")
        return None

    @staticmethod
    def _authorized(args: Dict[str, Any]) -> bool:
        return bool(args.get("operator_authorization") or args.get("authorized"))

    def _sources_str(self) -> str:
        """Human-readable list of the untrusted sources that tainted the session."""
        if not self.provenance:
            return "an untrusted source"
        return ", ".join(f"{p.get('source_id') or '?'} (via {p['source_tool']}, UNTRUSTED)"
                         for p in self.provenance)

    def _blocked(self, tool_name: str, reason: str, taint_kind: str = "",
                 matched_values: Optional[List[str]] = None) -> Dict[str, Any]:
        return {"status": "blocked", "layer": "L2", "tool": tool_name, "reason": reason,
                "taint_kind": taint_kind, "matched_values": matched_values or [],
                "tainted_by": [p.get("source_id") for p in self.provenance],
                "provenance": list(self.provenance)}

    # ------------------------------------------------------------------ #
    # introspection — surface the taint state so the block is explainable,
    # not a black box (this is the provenance story the project sells).
    # ------------------------------------------------------------------ #
    def state(self) -> Dict[str, Any]:
        return {"tainted_active": self.tainted_active,
                "fingerprints": sorted(self.tainted_fingerprints),
                "provenance": list(self.provenance)}

    def explain(self) -> str:
        if not self.tainted_active:
            return "session is CLEAN — no untrusted source has been consumed"
        lines = [f"session is TAINTED by: {self._sources_str()}"]
        if self.tainted_fingerprints:
            lines.append(f"tainted value fingerprints: {sorted(self.tainted_fingerprints)}")
        return "\n".join(lines)
