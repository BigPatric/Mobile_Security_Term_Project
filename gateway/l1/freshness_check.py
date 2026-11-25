"""
gateway/l1/freshness_check.py — act on the state you saw, or do not act
=======================================================================
The agent always reads a copy, so its view can be out of date by the time it acts.
Before a state-changing call:

    1. the target's record must be at most `max_age_sec` old, else re-read that ONE UE;
    2. the session must still exist, and the SMF must still hold its SM context;
    3. if the agent passes the `etag` it saw (always, with require_etag), it must be
       that same session instance, not a new one under the same id.

Cost: at most two core GETs, and only on state-changing calls. Anything that cannot
be determined blocks. The remaining window (check -> SMF) is closed by the release
tool, which refuses if the SM-context ref is no longer the one checked here.
"""

from __future__ import annotations

import hmac
from typing import Any, Dict, Optional

from ..base import CallContext, Check
from .sync import SourceError
from .views import L1ViewClient


class FreshnessCheck(Check):
    kind = "freshness"
    layer = "L1"

    def __init__(self, views: L1ViewClient, max_age_sec: float = 1.0, require_etag: bool = True):
        self.views, self.max_age_sec, self.require_etag = views, float(max_age_sec), bool(require_etag)

    def describe(self) -> str:
        return f"freshness(<= {self.max_age_sec:g}s{', etag' if self.require_etag else ''})"

    def screen(self, ctx: CallContext) -> Optional[Dict[str, Any]]:
        sync = self.views.sync
        supi, psi = ctx.real_args.get("supi_token"), ctx.real_args.get("pdu_session_id")
        rec = sync.store.get(supi) if isinstance(supi, str) else None
        if isinstance(supi, str) and (rec is None or sync._now() - rec.read_at > self.max_age_sec):
            try:
                sync.refresh(supi)
            except SourceError as e:
                return self.block(ctx, f"the core could not be read to confirm the target ({e})",
                                  violation="state-unverifiable")
        sess = self.views.find_session(supi, psi) if isinstance(supi, str) else None
        if sess is None:
            return self.block(ctx, "the target session no longer exists; read the UE again",
                              violation="stale-target")
        alive = sync.source.session_alive(sess.ref) if sess.ref else None
        if alive is None:
            return self.block(ctx, "the SMF could not confirm the target session",
                              violation="state-unverifiable")
        if not alive:
            sync.mark_released(supi, sess.ref)
            return self.block(ctx, "the SMF has already released the target session",
                              violation="stale-target")
        etag = ctx.args.get("if_etag")
        if etag is None and not self.require_etag:
            return None
        if not isinstance(etag, str) or not any(
                hmac.compare_digest(etag.encode(), e.encode()) for e in self.views.etags(sess.ref)):
            return self.block(ctx, "if_etag is missing or names a different session instance; "
                                   "read the UE again before acting", violation="stale-view")
        return None
