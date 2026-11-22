#!/usr/bin/env python3
"""
tools/_core_untouched.py — did the last run leave the core exactly as it found it?
==================================================================================
Used by tools/run_live_matrix.sh to decide whether the next cell can reuse the
running core instead of tearing it down and bringing a fresh one up.

Exit 0 only if the newest evidence record (the last line of the file) shows that
no state-changing call reached the core: every trigger_pdu_session_release call
in that run was blocked by the gateway (or none was made). Reads such as
list_subscribers, query_subscriber_session and the gateway's core precheck change
nothing. Exit 1 otherwise, including when the record is missing or unreadable,
so any doubt falls back to a fresh core.

This judges from the run's own record, not from the AMF: after a direct SMF
release the AMF view stays stale and would still report the session as active.

    python3 tools/_core_untouched.py EVIDENCE.jsonl --expect-lines N
"""

from __future__ import annotations

import argparse
import json
import sys

STATE_CHANGING = {"trigger_pdu_session_release", "modify_slice_quota"}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("evidence")
    ap.add_argument("--expect-lines", type=int, required=True,
                    help="line count the file must have, so a run that wrote nothing "
                         "is not judged by the previous run's record")
    args = ap.parse_args()
    try:
        with open(args.evidence) as f:
            lines = [ln for ln in f if ln.strip()]
        if len(lines) != args.expect_lines:
            print(f"[reuse] evidence has {len(lines)} records, expected {args.expect_lines}")
            sys.exit(1)
        rec = json.loads(lines[-1])
    except Exception as e:
        print(f"[reuse] cannot read last evidence record ({e})")
        sys.exit(1)

    reached = [c for c in rec.get("tool_calls", [])
               if c.get("tool_name") in STATE_CHANGING and not c.get("blocked_by")]
    if reached or rec.get("sessions_released"):
        print(f"[reuse] {len(reached)} state-changing call(s) reached the core -> fresh core")
        sys.exit(1)
    print("[reuse] no state-changing call reached the core")
    sys.exit(0)


if __name__ == "__main__":
    main()
