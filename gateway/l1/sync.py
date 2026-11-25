"""
gateway/l1/sync.py — keep the gateway's UE state in step with the core
======================================================================
What free5GC v4.1.0 allows (checked in the vendored source):

* Push is not available. The AMF's Namf_EventExposure accepts and stores a
  subscription, but nothing in the AMF ever sends to its EventNotifyUri. So: poll.
* One GET returns every registered UE (AMF OAM /registered-ue-context without a
  SUPI). A cycle therefore costs 1 request at any N, instead of ~3 per UE.
* The AMF view goes stale when a session is released directly at the SMF. The bulk
  poll alone would report that session as alive forever, so the engine remembers
  contexts known to be dead and audits a few sessions per cycle against the SMF.

Failure rule: a failed, malformed or implausible read never removes a UE. The last
good state is kept and its age grows until it is reported stale.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import replace
from typing import Any, Callable, Dict, List, Optional, Tuple

from .store import Session, UEState, UEStateStore

logger = logging.getLogger(__name__)


class SourceError(RuntimeError):
    """The core could not be read. State is UNKNOWN, not empty."""


class CoreSource:
    def snapshot(self) -> Dict[str, UEState]:
        raise NotImplementedError

    def read_ue(self, supi: str) -> Optional[UEState]:
        """None only if the core positively says the UE is not registered."""
        raise NotImplementedError

    def session_alive(self, ref: str) -> Optional[bool]:
        """SMF's view of one SM context. None = could not be determined."""
        raise NotImplementedError


# --------------------------------------------------------------------------- #
class Free5GCSource(CoreSource):
    """free5GC v4.1.0 over the WebConsole REST API.
    Limit inherited from the WebConsole: it only asks the first AMF / first SMF."""

    def __init__(self, get: Optional[Callable[[str], Any]] = None) -> None:
        self._get = get

    def _fetch(self, path: str):
        from free5gc_tools import core_state as cs
        try:
            return (self._get or cs.wc_get)(path)
        except cs.CoreUnavailable as e:
            raise SourceError(str(e)) from e

    @staticmethod
    def _json(resp) -> Any:
        try:
            return resp.json()
        except ValueError as e:
            raise SourceError(f"unparseable answer: {e}") from e

    @staticmethod
    def _parse(entries: Any) -> Dict[str, UEState]:
        if entries is None:             # Go nil slice: genuinely no registered UE
            return {}
        if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
            raise SourceError("unexpected registered-ue-context shape")
        out: Dict[str, UEState] = {}
        try:
            for e in entries:
                supi = e["Supi"]
                sessions = [Session(int(s["PduSessionId"]), str(s.get("Dnn") or ""),
                                    str(s.get("Sst") or ""), str(s.get("Sd") or ""),
                                    str(s.get("SmContextRef") or ""))
                            for s in (e.get("PduSessions") or [])]
                prev = out.get(supi)    # 3GPP + non-3GPP access of one UE
                cm = str(e.get("CmState") or "UNKNOWN")
                if prev:
                    sessions += prev.sessions
                    cm = "CONNECTED" if "CONNECTED" in (cm, prev.cm_state) else cm
                out[supi] = UEState(supi, cm, str(e.get("Tac") or ""),
                                    tuple(sorted(sessions, key=lambda s: (s.id, s.ref))))
        except (KeyError, TypeError, ValueError) as e:
            raise SourceError(f"unexpected registered-ue-context entry: {e!r}") from e
        return out

    def snapshot(self) -> Dict[str, UEState]:
        resp = self._fetch("/api/registered-ue-context")
        if resp.status_code != 200:     # incl. 404 "No AMF Found": unknown, not empty
            raise SourceError(f"registered-ue-context HTTP {resp.status_code}")
        return self._parse(self._json(resp))

    def read_ue(self, supi: str) -> Optional[UEState]:
        resp = self._fetch(f"/api/registered-ue-context/{supi}")
        if resp.status_code == 404:
            # The WebConsole also answers 404 when it knows no AMF at all.
            body = self._json(resp)
            if isinstance(body, dict) and body.get("cause") == "CONTEXT_NOT_FOUND":
                return None
            raise SourceError("registered-ue-context 404 without CONTEXT_NOT_FOUND")
        if resp.status_code != 200:
            raise SourceError(f"registered-ue-context HTTP {resp.status_code}")
        return self._parse(self._json(resp)).get(supi)

    def session_alive(self, ref: str) -> Optional[bool]:
        try:
            code = self._fetch(f"/api/ue-pdu-session-info/{ref}").status_code
        except SourceError:
            return None
        return {200: True, 404: False}.get(code)    # "No SMF Found" is a 500


# --------------------------------------------------------------------------- #
class SyncEngine:
    def __init__(self, source: CoreSource, store: Optional[UEStateStore] = None,
                 interval_sec: float = 2.0, max_age_sec: Optional[float] = None,
                 audit_per_cycle: int = 10, shrink_guard: float = 0.5,
                 shrink_min: int = 20, now_fn: Callable[[], float] = time.monotonic) -> None:
        """`max_age_sec`: older than this, views are flagged stale (default 3 intervals).
        `audit_per_cycle`: SM contexts checked against the SMF each cycle, so an
        out-of-band release is noticed within sessions/audit_per_cycle cycles.
        `shrink_guard`: a snapshot missing more than this share of the UEs must be
        confirmed by the next one before it is believed."""
        self.source = source
        self.store = store or UEStateStore(now_fn=now_fn)
        self.interval_sec = float(interval_sec)
        self.max_age_sec = float(max_age_sec) if max_age_sec is not None else 3 * self.interval_sec
        self.audit_per_cycle = int(audit_per_cycle)
        self.shrink_guard, self.shrink_min = shrink_guard, shrink_min
        self._now = now_fn
        self._lock = threading.RLock()
        self._dead: Dict[str, str] = {}      # SM-context ref -> SUPI: released, AMF may still list it
        self._audit_pos = 0
        self._shrink_pending = False
        self.stats = {"cycles": 0, "failed": 0, "held": 0, "refreshes": 0, "audited": 0, "audit_dead": 0}
        self.last_error: Optional[str] = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # -- one cycle ------------------------------------------------------------
    def step(self) -> bool:
        """One poll. True if the store now reflects a fresh, accepted snapshot."""
        with self._lock:
            self.stats["cycles"] += 1
        read_at = self._now()
        try:
            snap = self.source.snapshot()
        except SourceError as e:
            with self._lock:
                self.stats["failed"] += 1
                self.last_error = str(e)
            logger.warning("[L1:sync] snapshot failed, keeping last state: %s", e)
            return False
        with self._lock:
            have = len(self.store)
            if have >= self.shrink_min and len(snap) < have * (1 - self.shrink_guard) \
                    and not self._shrink_pending:
                self._shrink_pending = True
                self.stats["held"] += 1
                self.last_error = f"snapshot shrank {have} -> {len(snap)}; waiting for confirmation"
                logger.warning("[L1:sync] %s", self.last_error)
                return False
            self._shrink_pending = False
            listed = {s.ref for st in snap.values() for s in st.sessions}
            self._dead = {r: u for r, u in self._dead.items() if r in listed}
            self.store.apply_snapshot({u: self._without_dead(st) for u, st in snap.items()}, read_at)
            self.last_error = None
        self._audit()
        return True

    def _without_dead(self, st: UEState) -> UEState:
        if not any(s.ref in self._dead for s in st.sessions):
            return st
        return replace(st, sessions=tuple(s for s in st.sessions if s.ref not in self._dead))

    def _audit(self) -> None:
        if self.audit_per_cycle <= 0:
            return
        _, items = self.store.items()
        targets: List[Tuple[str, str]] = sorted(
            (u, s.ref) for u, r in items for s in r.state.sessions if s.ref)
        if not targets:
            return
        n = min(self.audit_per_cycle, len(targets))
        start = self._audit_pos % len(targets)
        self._audit_pos = start + n
        for supi, ref in (targets + targets)[start:start + n]:
            self.stats["audited"] += 1
            if self.source.session_alive(ref) is False:
                self.stats["audit_dead"] += 1
                self.mark_released(supi, ref)

    # -- targeted updates -----------------------------------------------------
    def mark_released(self, supi: str, ref: str) -> None:
        """Write-through: this SM context is gone, whatever the AMF still lists."""
        with self._lock:
            self._dead[ref] = supi
            rec = self.store.get(supi)
            if rec is not None:
                self.store.apply_ue(supi, self._without_dead(rec.state))

    def refresh(self, supi: str) -> None:
        """Read one UE from the core now. Raises SourceError if it cannot be read."""
        read_at = self._now()
        st = self.source.read_ue(supi)
        with self._lock:
            self.stats["refreshes"] += 1
            self.store.apply_ue(supi, self._without_dead(st) if st else None, read_at)

    def is_stale(self) -> bool:
        age = self.store.age()
        return age is None or age > self.max_age_sec

    # -- background thread ----------------------------------------------------
    def start(self) -> None:
        if self._thread is not None:
            return

        def loop():
            while not self._stop.is_set():
                t0 = time.monotonic()
                try:
                    self.step()
                except Exception:          # a bug must not silently stop synchronization
                    with self._lock:
                        self.stats["failed"] += 1
                    logger.exception("[L1:sync] cycle crashed; state will go stale")
                self._stop.wait(max(0.0, self.interval_sec - (time.monotonic() - t0)))
        self._thread = threading.Thread(target=loop, name="l1-sync", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=10)
            self._thread = None
        self._stop.clear()
