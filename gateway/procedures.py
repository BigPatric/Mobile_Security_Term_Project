"""
gateway/procedures.py — 3GPP procedure specs, declared as data
==============================================================
The PDU-session life-cycle (TS 23.502 §4.3; UE-side states TS 24.501 §6.1.3.2)
as seen from the agent→core tool boundary. Only the release event is exposed
as a tool today; establishment / modification are added the same way.
"""

from __future__ import annotations

import copy
from typing import Any, Dict


def pdu_session_procedure(require_established: bool = False) -> Dict[str, Any]:
    """require_established=True: a release is only legal from an observed ACTIVE
    context. Default False: also allow from UNKNOWN (never observed), so a
    legitimate release is not blocked merely because the gateway hasn't seen the
    session yet — use core_precheck for a ground-truth existence check instead."""
    return copy.deepcopy({
        "key": ["supi_token|supi|imsi", "pdu_session_id"],
        "initial": "UNKNOWN",
        "states": ["UNKNOWN", "ACTIVE", "RELEASED"],
        "observe": [{
            "tool": "query_subscriber_session",
            "when": {"status": "ok"},
            "for_each": "subscriber.pdu_sessions",
            "key": ["subscriber.supi", "item.id"],
            "set": "ACTIVE",
            # a session this gateway saw released stays RELEASED even if the AMF
            # view is stale (a direct SMF release does not notify the UE/AMF).
            "keep": ["RELEASED"],
        }],
        "transitions": {
            "release": {
                "from": ["ACTIVE"] if require_established else ["ACTIVE", "UNKNOWN"],
                "to": "RELEASED",
                "commit_when": {"status": "ok", "verified": True},
            },
        },
    })
