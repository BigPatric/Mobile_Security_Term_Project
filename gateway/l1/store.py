"""
gateway/l1/store.py — the gateway's versioned copy of UE state
==============================================================
One store per core, shared by every agent session. It holds REAL identifiers and
lives only inside the gateway; agents see it through gateway/l1/views.py.

* Every snapshot that changes something gets the next global `version`; a UE record
  remembers the version it last changed at (`rev`). An identical snapshot changes
  nothing. All changes of one snapshot share ONE version on purpose: numbering them
  one by one would reveal the order the core listed the UEs in, i.e. IMSI order.
* `changes_since(v)` returns each changed UE once, in its latest state, so catching
  up costs O(UEs that changed), not O(events). Nothing is replayed to the agent.
* A departed UE leaves a tombstone so a reader that is behind still learns it left.
  Tombstones are bounded; a reader older than the oldest dropped one is told to
  resync rather than silently missing a departure.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class Session:
    id: int
    dnn: str = ""
    sst: str = ""
    sd: str = ""
    ref: str = ""            # SMF SM-context reference (gateway-internal)


@dataclass(frozen=True)
class UEState:
    supi: str
    cm_state: str = "UNKNOWN"
    # Location: aggregated only, never shown per UE. Not compared: a UE that only moved
    # must not turn up in get_changes, or the agent would learn that it moved.
    tac: str = field(default="", compare=False)
    sessions: Tuple[Session, ...] = ()


@dataclass
class Record:
    state: UEState
    rev: int
    read_at: float           # when the core last confirmed this state


@dataclass
class ApplyResult:
    joined: int = 0
    changed: int = 0
    left: int = 0

    @property
    def total(self) -> int:
        return self.joined + self.changed + self.left


@dataclass
class Changes:
    resync: bool
    version: int
    updated: List[Tuple[str, Record]] = field(default_factory=list)
    removed: List[Tuple[str, int]] = field(default_factory=list)


class UEStateStore:
    def __init__(self, max_tombstones: int = 4096,
                 now_fn: Callable[[], float] = time.monotonic) -> None:
        self._lock = threading.RLock()
        self._now = now_fn
        self._recs: Dict[str, Record] = {}
        self._tombs: "OrderedDict[str, int]" = OrderedDict()   # supi -> version it left at
        self._left_at: Dict[str, float] = {}                   # supi -> when it left
        self._max_tombs = max_tombstones
        self._floor = 0                 # readers older than this must resync
        self.version = 0
        self.membership_version = 0     # bumps only when a UE joins or leaves
        self.synced_at: Optional[float] = None

    # -- writing --------------------------------------------------------------
    def apply_snapshot(self, states: Dict[str, UEState], read_at: Optional[float] = None) -> ApplyResult:
        """Replace the whole view. `read_at` = when the read STARTED: a record
        confirmed after that instant (a targeted refresh or a release that raced this
        snapshot) is newer than the snapshot and is kept."""
        at = self._now() if read_at is None else read_at
        res = ApplyResult()
        with self._lock:
            nxt = self.version + 1
            for supi, st in states.items():
                rec = self._recs.get(supi)
                if rec is None:
                    if self._left_at.get(supi, at) > at:
                        continue        # it left after this snapshot was read
                    self._put(supi, st, at, nxt, res)
                elif rec.read_at <= at:
                    self._put(supi, st, at, nxt, res)
            for supi in [s for s, r in self._recs.items() if s not in states and r.read_at <= at]:
                self._drop(supi, at, nxt)
                res.left += 1
            self.synced_at = max(at, self.synced_at if self.synced_at is not None else at)
        return res

    def apply_ue(self, supi: str, state: Optional[UEState], read_at: Optional[float] = None) -> None:
        """Targeted update (refresh, or a verified change). None = the UE is gone."""
        at = self._now() if read_at is None else read_at
        with self._lock:
            rec = self._recs.get(supi)
            if rec is not None and rec.read_at > at:
                return
            if state is not None:
                self._put(supi, state, at, self.version + 1, ApplyResult())
            elif rec is not None:
                self._drop(supi, at, self.version + 1)

    def _put(self, supi: str, st: UEState, at: float, ver: int, res: ApplyResult) -> None:
        rec = self._recs.get(supi)
        if rec is None:
            self.version = ver
            self.membership_version += 1
            self._tombs.pop(supi, None)
            self._left_at.pop(supi, None)
            self._recs[supi] = Record(st, ver, at)
            res.joined += 1
            return
        if rec.state != st:
            self.version = ver
            rec.rev = ver
            res.changed += 1
        rec.state, rec.read_at = st, at

    def _drop(self, supi: str, at: float, ver: int) -> None:
        del self._recs[supi]
        self.version = ver
        self.membership_version += 1
        self._tombs[supi] = ver
        self._tombs.move_to_end(supi)
        self._left_at[supi] = at
        while len(self._tombs) > self._max_tombs:
            old, v = self._tombs.popitem(last=False)
            self._left_at.pop(old, None)
            self._floor = max(self._floor, v)

    # -- reading --------------------------------------------------------------
    def get(self, supi: str) -> Optional[Record]:
        with self._lock:
            r = self._recs.get(supi)
            return Record(r.state, r.rev, r.read_at) if r else None

    def items(self) -> Tuple[int, List[Tuple[str, Record]]]:
        """(version, records) as one consistent cut."""
        with self._lock:
            return self.version, [(s, Record(r.state, r.rev, r.read_at))
                                  for s, r in self._recs.items()]

    def supis(self) -> Tuple[int, List[str]]:
        with self._lock:
            return self.membership_version, list(self._recs)

    def changes_since(self, version: int) -> Changes:
        with self._lock:
            if version < self._floor or version > self.version:
                return Changes(True, self.version)
            return Changes(
                False, self.version,
                [(s, Record(r.state, r.rev, r.read_at))
                 for s, r in self._recs.items() if r.rev > version],
                [(s, v) for s, v in self._tombs.items() if v > version])

    def age(self) -> Optional[float]:
        return None if self.synced_at is None else self._now() - self.synced_at

    def __len__(self) -> int:
        return len(self._recs)
