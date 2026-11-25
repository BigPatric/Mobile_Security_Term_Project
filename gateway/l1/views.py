"""
gateway/l1/views.py — what the agent sees of 1000+ UEs
======================================================
One L1ViewClient per agent session, between the gateway proxy and the core tools.
It replaces the two tools that do not scale (list_subscribers dumps everything,
query_subscriber_session costs three core requests) with views over the store:

    get_network_summary()            fixed size at any N
    list_ues(page_token, limit, ...) bounded page
    get_ue(supi_token)               one UE
    get_changes(cursor)              only what changed, each UE once, bounded

Privacy rules, by construction rather than by filtering:
* Allow-list: a view is built from named fields. GPSI, PEI, GUTI, UE IP, per-UE
  location and SM-context refs are never copied in.
* Token order: pages are sorted by token, a keyed pseudo-random order. Core order is
  IMSI order, so with sequentially provisioned SIMs the k-th row would BE the k-th IMSI.
  Paging by key also keeps pages stable while UEs come and go.
* Small groups: a per-area count below `min_group` is merged into "other".
* `etag` names one session instance for this agent session only. It lets a later
  release say "the session I saw" without exposing the SM-context ref.
"""

from __future__ import annotations

import hashlib
import hmac
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from agent.tool_client import ToolClient
from ..secret import derive_key, resolve_master
from .store import Record, Session
from .sync import SyncEngine
from .tokenizer import IdentifierTokenizer

RELEASE_TOOL = "trigger_pdu_session_release"
EXPECTED_REF = "expected_sm_context_ref"      # gateway -> core tool only, never from the agent
_LETTERS = str.maketrans("0123456789abcdef", "abcdefghijklmnop")

VIEW_SCHEMA: List[Dict[str, Any]] = [
    {"name": "get_network_summary",
     "description": "Counts over all registered UEs (connection state, DNN, slice, area). Start here.",
     "parameters": {"type": "object", "properties": {}, "required": []}},
    {"name": "list_ues",
     "description": "One page of registered UEs. Pass next_page back as page_token for the next page.",
     "parameters": {"type": "object", "properties": {
         "page_token": {"type": "string"}, "limit": {"type": "integer"},
         "cm_state": {"type": "string", "enum": ["CONNECTED", "IDLE"]},
         "dnn": {"type": "string"}}, "required": []}},
    {"name": "get_ue",
     "description": "Current state of one UE.",
     "parameters": {"type": "object", "properties": {
         "supi_token": {"type": "string", "description": "Opaque UE token from a view."}},
         "required": ["supi_token"]}},
    {"name": "get_changes",
     "description": ("UEs that changed or left since `cursor` (from any earlier view). If "
                     "resync_required, start again from get_network_summary / list_ues."),
     "parameters": {"type": "object", "properties": {"cursor": {"type": "string"}},
                    "required": ["cursor"]}},
]


class L1ViewClient(ToolClient):
    HIDDEN = {"list_subscribers", "query_subscriber_session"}

    def __init__(self, inner: ToolClient, sync: SyncEngine, tokenizer: IdentifierTokenizer,
                 secret: Optional[bytes] = None, page_size: int = 50, max_changes: int = 100,
                 min_group: int = 5) -> None:
        self.inner, self.sync, self.tokenizer = inner, sync, tokenizer
        self._key = derive_key(resolve_master(secret), "etag")
        self.page_size, self.max_changes, self.min_group = page_size, max_changes, min_group
        self._views = {"get_network_summary": self._summary, "list_ues": self._list,
                       "get_ue": self._get, "get_changes": self._changes}

    def list_schema(self) -> List[Dict[str, Any]]:
        return VIEW_SCHEMA + [s for s in self.inner.list_schema() if s.get("name") not in self.HIDDEN]

    def invoke(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        args = dict(arguments or {})
        if name in self._views:
            try:
                return self._views[name](**args)
            except (TypeError, ValueError) as e:
                return {"status": "error", "error": f"bad arguments for {name}: {type(e).__name__}"}
        if name in self.HIDDEN:
            return {"status": "error", "error": f"Unknown tool: {name}"}
        if name == RELEASE_TOOL:
            return self._release(args)
        return self.inner.invoke(name, args)

    # -- release: address the exact session, then write the outcome through -----
    def _release(self, args: Dict[str, Any]) -> Dict[str, Any]:
        args.pop("if_etag", None)
        args.pop(EXPECTED_REF, None)
        supi = args.get("supi_token", "")
        sess = self.find_session(supi, args.get("pdu_session_id"))
        if sess is not None and sess.ref:
            args[EXPECTED_REF] = sess.ref
        out = self.inner.invoke(RELEASE_TOOL, args)
        if sess is not None and out.get("status") == "ok" and out.get("verified") is True:
            self.sync.mark_released(supi, sess.ref)
        return out

    def find_session(self, supi: str, psi: Any) -> Optional[Session]:
        rec = self.sync.store.get(supi)
        return next((s for s in rec.state.sessions if str(s.id) == str(psi)), None) if rec else None

    # -- building blocks --------------------------------------------------------
    def etags(self, ref: str) -> List[str]:
        """Accepted etags for a session (current epoch first, then grace)."""
        return [hmac.new(self._key, f"{len(self.tokenizer.scope)}:{self.tokenizer.scope}|{e}|{ref}".encode(),
                         hashlib.sha256).hexdigest()[:12].translate(_LETTERS)
                for e in self.tokenizer.live_epochs()]

    def _ue(self, token: str, rec: Record) -> Dict[str, Any]:
        return {"supi_token": token, "cm_state": rec.state.cm_state,
                "sessions": [{"id": s.id, "dnn": s.dnn, "slice": f"{s.sst}-{s.sd}",
                              "etag": self.etags(s.ref)[0]} for s in rec.state.sessions]}

    def _meta(self, version: int) -> Dict[str, Any]:
        age = self.sync.store.age()
        return {"status": "ok", "cursor": self._cursor(version),
                "age_sec": None if age is None else round(age, 2), "stale": self.sync.is_stale()}

    def _cursor(self, version: int) -> str:
        return f"c{self.tokenizer.epoch()}.{version}"

    def _sorted(self, items: List[Tuple[str, Record]]) -> List[Tuple[str, Record]]:
        return sorted(((self.tokenizer.token_for(s), r) for s, r in items), key=lambda x: x[0])

    # -- views ------------------------------------------------------------------
    def _summary(self) -> Dict[str, Any]:
        version, items = self.sync.store.items()
        states = [r.state for _, r in items]
        sess = [s for st in states for s in st.sessions]

        def small_merged(c: Counter) -> Dict[str, int]:
            out = {k: v for k, v in c.items() if v >= self.min_group}
            rest = sum(c.values()) - sum(out.values())
            return {**dict(sorted(out.items())), **({"other": rest} if rest else {})}
        return {**self._meta(version), "ues": len(states),
                "by_cm_state": dict(sorted(Counter(s.cm_state for s in states).items())),
                "sessions": len(sess),
                "by_dnn": dict(sorted(Counter(s.dnn for s in sess).items())),
                "by_slice": dict(sorted(Counter(f"{s.sst}-{s.sd}" for s in sess).items())),
                "by_area": small_merged(Counter(s.tac for s in states))}

    def _list(self, page_token: str = "", limit: Optional[int] = None,
              cm_state: str = "", dnn: str = "") -> Dict[str, Any]:
        limit = max(1, min(int(limit or self.page_size), self.page_size))
        version, items = self.sync.store.items()
        if page_token:
            epoch, _, after = str(page_token).partition(".")
            if epoch != f"p{self.tokenizer.epoch()}":
                return {**self._meta(version), "resync_required": True,
                        "reason": "tokens rotated; list again from the first page"}
        else:
            after = ""
        rows = [(t, r) for t, r in self._sorted(items)
                if t > after and (not cm_state or r.state.cm_state == cm_state)
                and (not dnn or any(s.dnn == dnn for s in r.state.sessions))]
        page = rows[:limit]
        more = len(rows) > limit
        return {**self._meta(version), "matching_from_here": len(rows),
                "ues": [self._ue(t, r) for t, r in page],
                "next_page": f"p{self.tokenizer.epoch()}.{page[-1][0]}" if more else None}

    def _get(self, supi_token: str) -> Dict[str, Any]:     # already detokenized by the gateway
        rec = self.sync.store.get(supi_token)
        version = self.sync.store.version
        if rec is None:
            return {**self._meta(version), "registered": False}
        return {**self._meta(version), "registered": True,
                "ue": self._ue(self.tokenizer.token_for(supi_token), rec)}

    def _changes(self, cursor: str) -> Dict[str, Any]:
        epoch, _, ver = str(cursor).partition(".")
        version = int(ver)
        if epoch != f"c{self.tokenizer.epoch()}":
            return {**self._meta(self.sync.store.version), "resync_required": True,
                    "reason": "tokens rotated"}
        ch = self.sync.store.changes_since(version)
        if ch.resync or len(ch.updated) + len(ch.removed) > self.max_changes:
            return {**self._meta(ch.version), "resync_required": True,
                    "changed": None if ch.resync else len(ch.updated) + len(ch.removed),
                    "reason": "cursor too old" if ch.resync else
                              "too many changes to send as a delta; start from get_network_summary"}
        return {**self._meta(ch.version), "resync_required": False,
                "updated": [self._ue(t, r) for t, r in self._sorted(ch.updated)],
                "removed": sorted(self.tokenizer.token_for(s) for s, _ in ch.removed)}
