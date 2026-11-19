"""
gateway/checks/rate.py — L3 sliding-window volume limit
=======================================================
At most `max` calls may pass this check within `window_sec`. Buckets are named,
so several tools can share one budget (e.g. every teardown-type operation).
A call counts as an *attempt* once it passes this check, even if a later check
or the core then refuses it.
"""

from __future__ import annotations

import time
from collections import deque
from typing import Any, Callable, Deque, Dict, Optional

from .base import Check, CallContext, is_authorized


class RateBucket:
    def __init__(self, name: str, max_calls: int, window_sec: float,
                 now_fn: Callable[[], float] = time.monotonic):
        self.name = name
        self.max = int(max_calls)
        self.window_sec = float(window_sec)
        self._now = now_fn
        self.times: Deque[float] = deque()

    def count(self) -> int:
        self._prune(self._now())
        return len(self.times)

    def try_take(self) -> bool:
        now = self._now()
        self._prune(now)
        if len(self.times) >= self.max:
            return False
        self.times.append(now)
        return True

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_sec
        while self.times and self.times[0] < cutoff:
            self.times.popleft()


class RateCheck(Check):
    kind = "rate"
    layer = "L3"

    def __init__(self, bucket: RateBucket, exempt_authorized: bool = False):
        self.bucket = bucket
        self.exempt_authorized = exempt_authorized

    def describe(self) -> str:
        return f"rate({self.bucket.name}: {self.bucket.max}/{self.bucket.window_sec:g}s)"

    def screen(self, ctx: CallContext) -> Optional[Dict[str, Any]]:
        if self.exempt_authorized and is_authorized(ctx.real_args):
            return None
        if self.bucket.try_take():
            return None
        n = len(self.bucket.times)
        return self.block(ctx,
            f"rate limit: {n} call(s) in bucket '{self.bucket.name}' within the last "
            f"{self.bucket.window_sec:g}s (max {self.bucket.max}); refusing bulk {ctx.tool} "
            f"(control-plane DoS), regardless of authorization",
            violation="rate-limit", bucket=self.bucket.name,
            window=self.bucket.window_sec, count=n)
