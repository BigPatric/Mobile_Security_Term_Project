"""
gateway/l1/tokenizer.py — L1 identifier opacity, at the scale of a whole network
================================================================================
Boundary transform on the identifier axis:

    core -> agent  (results)   real SUPI    -> opaque token
    agent -> core  (arguments) opaque token -> real SUPI   (identifier arguments only)

    token = "token_sub_" + letters(HMAC-SHA256(k, scope | epoch | "imsi-<digits>")[:64 bits])

Three properties matter once there are 1000+ UEs and more than one gateway:

* Wide and stateless. A token depends only on (key, scope, epoch, SUPI), never on
  the order in which UEs were seen. The v1 token kept 16 bits and lengthened on
  collision, so at 1000 UEs two gateways sharing one key disagreed on some
  tokens, and one could resolve a token to the WRONG UE
  (experiments/l1_scale.py, E1).
* Epochs. With `epoch_sec` > 0 tokens rotate, so data leaked in one epoch cannot
  be joined to the next by token. The previous epoch is still accepted as an
  argument for `grace_sec`, so a call already in flight does not fail.
* Scopes. Two agent sessions with different `scope` hold different tokens for the
  same UE, so they cannot join what they saw by token.

Letters-only (a-p) digests: a token can never contain a 15-digit run that L1 itself
would mistake for a SUPI.

Only the SUPI gets a token, because only the SUPI is needed to name a UE in a call.
Every other identifier (GPSI, PEI, GUTI, UE IP, SM-context reference) is MASKED.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from ..secret import derive_key, resolve_master

_SUPI_RE = re.compile(r"(?:imsi-)?(\d{15})|imsi-(\d{5,14})(?!\d)")
_TOKEN_RE = re.compile(r"token_sub_[0-9a-p]{4,}")
_IPV4_RE = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])")
_LETTERS = str.maketrans("0123456789abcdef", "abcdefghijklmnop")

# Identifiers recognizable in free text. Checked BEFORE the SUPI pattern, since an
# IMEI also has 15 digits.
_MASK_TEXT: List[Tuple[str, "re.Pattern[str]"]] = [
    ("pei", re.compile(r"imei(?:sv)?-\d{14,16}", re.I)),
    ("gpsi", re.compile(r"msisdn-\d{5,15}", re.I)),
    ("gpsi", re.compile(r"extid-[^\s\"'@]+@[^\s\"']+", re.I)),
    ("suci", re.compile(r"suci-[0-9a-f][0-9a-f-]+", re.I)),
    ("smref", re.compile(r"urn:uuid:[0-9a-f-]{36}", re.I)),
]
# Identifiers recognizable only by the field they sit in.
_MASK_FIELDS = {
    "gpsi": "gpsi", "msisdn": "gpsi", "gpsis": "gpsi",
    "pei": "pei", "imei": "pei", "imeisv": "pei",
    "guti": "guti", "tmsi": "guti", "suci": "suci",
    "pduaddress": "ueip", "ueipv4": "ueip", "ueipv4address": "ueip", "ueip": "ueip",
    "smcontextref": "smref",
}
DEFAULT_UE_POOLS = ("10.60.0.0/15",)          # free5GC smfcfg: 10.60.0.0/16 and 10.61.0.0/16


def _norm_field(name: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


class IdentifierTokenizer:
    """SUPI <-> token mapper plus masking of every other subscriber identifier."""

    TOKEN_PREFIX = "token_sub_"
    DIGEST_HEX = 16                           # 64 bits

    def __init__(self, secret: Optional[bytes] = None, scope: str = "",
                 epoch_sec: float = 0, grace_sec: float = 0,
                 now_fn: Callable[[], float] = time.time,
                 population: Optional[Callable[[], Tuple[Any, Iterable[str]]]] = None,
                 ue_pools: Iterable[str] = DEFAULT_UE_POOLS) -> None:
        """`population` returns (membership_version, SUPIs). It lets this gateway
        resolve tokens another gateway instance minted for the same scope: the
        mapping is re-derived from the synchronized UE population, not replicated."""
        if epoch_sec and grace_sec > epoch_sec:
            raise ValueError("grace_sec must not exceed epoch_sec (one previous epoch is kept)")
        self._key = derive_key(resolve_master(secret), "tokenize")
        self.scope = scope
        self.epoch_sec, self.grace_sec = float(epoch_sec), float(grace_sec)
        self._now = now_fn                    # wall clock: gateway instances must agree on epochs
        self._population = population
        self._pools = [ipaddress.ip_network(p) for p in ue_pools]
        self._lock = threading.RLock()
        # epoch -> tables. Only live epochs are kept; these never leave the gateway.
        self._fwd: Dict[int, Dict[str, str]] = {}
        self._rev: Dict[int, Dict[str, str]] = {}
        self._indexed: Dict[int, Any] = {}    # epoch -> population version it was indexed at

    # -- epochs ---------------------------------------------------------------
    def epoch(self) -> int:
        return int(self._now() // self.epoch_sec) if self.epoch_sec else 0

    def live_epochs(self) -> List[int]:
        """Epochs whose tokens are accepted now, newest first. Drops dead tables."""
        cur = self.epoch()
        live = [cur]
        if self.epoch_sec and self._now() - cur * self.epoch_sec < self.grace_sec:
            live.append(cur - 1)
        with self._lock:
            for table in (self._fwd, self._rev, self._indexed):
                for e in [e for e in table if e not in live]:
                    del table[e]
        return live

    # -- minting / resolving --------------------------------------------------
    @staticmethod
    def _canonical(digits: str) -> str:
        return digits if digits.startswith("imsi-") else f"imsi-{digits}"

    def _mint(self, canon: str, epoch: int) -> str:
        with self._lock:
            fwd = self._fwd.setdefault(epoch, {})
            tok = fwd.get(canon)
            if tok is None:
                # scope is length-prefixed so no (scope, epoch) pair can alias another
                msg = f"{len(self.scope)}:{self.scope}|{epoch}|{canon}".encode()
                digest = hmac.new(self._key, msg, hashlib.sha256).hexdigest()[:self.DIGEST_HEX]
                tok = self.TOKEN_PREFIX + digest.translate(_LETTERS)
                rev = self._rev.setdefault(epoch, {})
                if rev.get(tok, canon) != canon:   # ~3e-14 at 1000 UEs: fail closed, never guess
                    raise RuntimeError("token collision: refusing to issue an ambiguous identifier")
                fwd[canon], rev[tok] = tok, canon
            return tok

    def token_for(self, supi: str) -> str:
        return self._mint(self._canonical(supi), self.epoch())

    def resolve(self, token: str) -> Optional[str]:
        """Real SUPI for a live token, else None."""
        for epoch in self.live_epochs():
            with self._lock:
                supi = self._rev.get(epoch, {}).get(token)
                if supi is None and self._population is not None:
                    version, supis = self._population()
                    if self._indexed.get(epoch) != version:  # re-index only if membership changed
                        for s in supis:
                            self._mint(self._canonical(s), epoch)
                        self._indexed[epoch] = version
                        supi = self._rev.get(epoch, {}).get(token)
            if supi is not None:
                return supi
        return None

    # -- text transforms ------------------------------------------------------
    def _mask_text(self, text: str) -> str:
        for kind, rx in _MASK_TEXT:
            text = rx.sub(f"[REDACTED:{kind}]", text)

        def ip(m):
            try:
                addr = ipaddress.ip_address(m.group(0))
            except ValueError:
                return m.group(0)
            return "[REDACTED:ueip]" if any(addr in p for p in self._pools) else m.group(0)
        return _IPV4_RE.sub(ip, text)

    def tokenize_text(self, text: str) -> str:
        return _SUPI_RE.sub(lambda m: self.token_for(m.group(1) or m.group(2)), self._mask_text(text))

    def detokenize_text(self, text: str) -> str:
        """Unknown or expired tokens are left as they are."""
        return _TOKEN_RE.sub(lambda m: self.resolve(m.group(0)) or m.group(0), text)

    def redact_text(self, text: str) -> str:
        """For gateway-written messages: never mints. A SUPI this session already
        holds a token for becomes that token, any other is masked."""
        cur = self._fwd.get(self.epoch(), {})
        return _SUPI_RE.sub(lambda m: cur.get(self._canonical(m.group(1) or m.group(2)),
                                              "imsi-[REDACTED]"), self._mask_text(text))

    def mask_text(self, text: str) -> str:
        """For attacker-writable content: no SUPI becomes a token. Otherwise an
        attacker who writes a known SUPI into a log learns which token is that
        subscriber (a confirmation oracle that undoes the pseudonymity)."""
        return _SUPI_RE.sub("imsi-[REDACTED]", self._mask_text(text))

    # -- structural transforms ------------------------------------------------
    def tokenize(self, obj: Any) -> Any:
        return self._walk(obj, self.tokenize_text, mask_fields=True)

    def mask(self, obj: Any) -> Any:
        return self._walk(obj, self.mask_text, mask_fields=True)

    def redact(self, obj: Any) -> Any:
        return self._walk(obj, self.redact_text, mask_fields=True)

    def detokenize(self, obj: Any) -> Any:
        return self._walk(obj, self.detokenize_text)

    def detokenize_fields(self, args: Dict[str, Any], fields) -> Dict[str, Any]:
        """Restore tokens ONLY in the named identifier arguments. Tokens in free text
        stay opaque, so no outbound tool can be used to un-tokenize data (a confused
        deputy)."""
        fields = set(fields)
        return {k: (self._walk(v, self.detokenize_text) if k in fields else v)
                for k, v in (args or {}).items()}

    def _walk(self, obj: Any, fn, mask_fields: bool = False, field: Any = None) -> Any:
        kind = _MASK_FIELDS.get(_norm_field(field)) if mask_fields and field is not None else None
        if isinstance(obj, dict):
            # keys too: a result may be keyed by SUPI ({"imsi-...": {...}})
            return {(fn(k) if isinstance(k, str) else k): self._walk(v, fn, mask_fields, k)
                    for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return type(obj)(self._walk(v, fn, mask_fields, field) for v in obj)
        if kind and obj not in (None, "", False, True):
            return f"[REDACTED:{kind}]"
        if isinstance(obj, str):
            return fn(obj)
        if mask_fields and isinstance(obj, int) and not isinstance(obj, bool) \
                and 10 ** 14 <= obj < 10 ** 15:
            return fn(str(obj))               # a SUPI serialized as a JSON number
        return obj

    # -- argument screening ---------------------------------------------------
    def contains_raw_supi(self, text: str) -> bool:
        return bool(_SUPI_RE.search(text))

    def contains_raw_identifier(self, text: str) -> bool:
        return self.contains_raw_supi(text) or any(rx.search(text) for _, rx in _MASK_TEXT)

    def is_known_token(self, value: str) -> bool:
        return self.resolve(value) is not None

    def mapping_count(self) -> int:
        return len(self._fwd.get(self.epoch(), {}))
