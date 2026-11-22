"""
gateway/capability.py — signed operator-authorization capabilities (Layer 2)
============================================================================
L2 originally accepted any non-empty `operator_authorization` string, so an
attacker who wrote "change-ticket CHG-20481" into an alert log, which the agent
then copied onto its calls, satisfied it (taint laundering, DOS-02).

Here, an authorization is a capability the GATEWAY minted and signed, issued only
on the trusted operator-task path, never derived from anything the agent reads:

    gwcap1.<tool>.<max_uses>.<expiry>.<nonce>.<hmac>

    hmac = HMAC-SHA256(k_capability, "gwcap1|tool|max_uses|expiry|nonce")

nonce and hmac are written in a letters-only hex alphabet (a-p for 0-f) so a
capability can never contain a 15-digit run that L1 would mistake for a SUPI.

L2 accepts a call's authorization only if the signature verifies, the
capability names this tool, it has not expired, and it has uses left (each
accepted call consumes one, so a copied or replayed capability is bounded by
max_uses). Text an attacker writes into a log cannot carry a valid signature
because the key never leaves the gateway.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time
from typing import Callable, Dict, Optional, Tuple

from .secret import derive_key, resolve_master

VERSION = "gwcap1"
_CAP_RE = re.compile(r"^gwcap1\.([A-Za-z0-9_]+)\.(\d+)\.(\d+)\.([a-p]{16})\.([a-p]{64})$")
_LETTERS = str.maketrans("0123456789abcdef", "abcdefghijklmnop")


def _letters(hexstr: str) -> str:
    return hexstr.translate(_LETTERS)


class CapabilityAuthority:
    """Mints and verifies capabilities. One instance per gateway (shares its secret)."""

    def __init__(self, secret: Optional[bytes] = None,
                 now_fn: Callable[[], float] = time.time) -> None:
        self._key = derive_key(resolve_master(secret), "capability")
        self._now = now_fn
        self._uses: Dict[str, int] = {}     # nonce -> times accepted

    def _mac(self, tool: str, max_uses: int, expiry: int, nonce: str) -> str:
        msg = f"{VERSION}|{tool}|{max_uses}|{expiry}|{nonce}".encode()
        return _letters(hmac.new(self._key, msg, hashlib.sha256).hexdigest())

    # ------------------------------------------------------------------ #
    def issue(self, tool: str, max_uses: int = 1, ttl_sec: float = 300) -> str:
        """Mint a capability for `tool`. Call this only from the trusted operator path."""
        if not re.fullmatch(r"[A-Za-z0-9_]+", tool):
            raise ValueError(f"bad tool name {tool!r}")
        if max_uses < 1:
            raise ValueError("max_uses must be >= 1")
        expiry = int(self._now() + ttl_sec)
        nonce = _letters(secrets.token_hex(8))
        return f"{VERSION}.{tool}.{max_uses}.{expiry}.{nonce}.{self._mac(tool, max_uses, expiry, nonce)}"

    def check(self, value: object, tool: str, consume: bool = True) -> Tuple[bool, str]:
        """(ok, reason). On ok with consume=True one use is spent."""
        if not isinstance(value, str) or not value:
            return False, "no authorization capability"
        m = _CAP_RE.match(value.strip())
        if not m:
            return False, "authorization is not a gateway-issued capability (unsigned claim)"
        cap_tool, max_uses, expiry, nonce, mac = m.groups()
        max_uses, expiry = int(max_uses), int(expiry)
        if not hmac.compare_digest(mac, self._mac(cap_tool, max_uses, expiry, nonce)):
            return False, "capability signature invalid (forged or tampered)"
        if cap_tool != tool:
            return False, f"capability is scoped to {cap_tool}, not {tool}"
        if self._now() > expiry:
            return False, "capability expired"
        used = self._uses.get(nonce, 0)
        if used >= max_uses:
            return False, f"capability already used {used}/{max_uses} time(s) (replay)"
        if consume:
            self._uses[nonce] = used + 1
        return True, f"valid capability ({used + 1}/{max_uses} use(s))"
