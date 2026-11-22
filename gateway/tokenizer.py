"""
gateway/tokenizer.py — Layer 1: Identifier Tokenizer (identifier opacity)
=========================================================================
Structurally severs the LLM agent from real 3GPP sensitive identifiers
(SUPI / IMSI). This is the gateway's boundary transform on the identifier axis:

    core -> agent  (tool RESULT path):   real SUPI  ──tokenize──>  opaque token
    agent -> core  (tool ARG  path):     opaque token ──detokenize──> real SUPI

The agent only ever holds opaque tokens (e.g. ``token_sub_a8f9``). Therefore,
even if the agent is *fully* compromised by an injected directive and coerced
into dumping its entire context or exfiltrating data to an attacker, what leaks
is a meaningless token — never a real subscriber identity.

    Guarantee:  Identifier Leakage Rate = 0%.

This follows CaMeL (Debenedetti et al., 2025): do not rely on the model
resisting injection; remove its *capability* to touch the secret in the first
place via structural isolation rather than fragile text filtering.

Tokens are **stable** (the same SUPI always maps to the same token within a
gateway instance) so the round-trip works across multiple tool calls, and
**reversible only inside the gateway** via the private mapping table.

Tokens are derived with a keyed MAC, HMAC-SHA256(k_tokenize, "imsi-<digits>"),
where k_tokenize comes from the gateway's private secret (gateway/secret.py).
An unkeyed hash would let anyone who sees a token hash every SUPI of a known
PLMN offline and map the token back; without the key that is not possible.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any, Dict, Optional

from .secret import derive_key, resolve_master

# free5GC SUPI/IMSI formats:
#   - "imsi-208930000000001"  (WebConsole ueId / AMF supi — the common case)
#   - bare "208930000000001"  (15-digit SUPI printed without the imsi- prefix)
# The optional prefix is consumed so the whole identifier is replaced atomically.
_SUPI_RE = re.compile(r"(?:imsi-)?(\d{15})")

# Tokens this layer mints. Matched for reversal on the argument path.
_TOKEN_RE = re.compile(r"token_sub_[0-9a-f]{4,}")


class IdentifierTokenizer:
    """Bidirectional SUPI <-> opaque-token mapper for the gateway boundary."""

    TOKEN_PREFIX = "token_sub_"

    def __init__(self, secret: Optional[bytes] = None) -> None:
        # Keyed derivation: `secret` is the gateway master secret (random per
        # instance unless MCP_GATEWAY_SECRET is set). It is never exposed.
        self._key = derive_key(resolve_master(secret), "tokenize")
        # Private mapping tables — live ONLY inside the gateway, never exposed
        # to the agent.
        self.supi_to_token: Dict[str, str] = {}
        self.token_to_supi: Dict[str, str] = {}

    # ------------------------------------------------------------------ #
    # canonical identifier form is always "imsi-<15 digits>", matching what
    # free5gc_tools.core_state.norm_supi() expects when the call reaches the core.
    # ------------------------------------------------------------------ #
    @staticmethod
    def _canonical(digits: str) -> str:
        return f"imsi-{digits}"

    def _token_for(self, digits: str) -> str:
        """Return the stable token for a SUPI, minting+recording it on first sight."""
        canon = self._canonical(digits)
        tok = self.supi_to_token.get(canon)
        if tok is not None:
            return tok
        digest = hmac.new(self._key, canon.encode(), hashlib.sha256).hexdigest()
        n = 4
        tok = f"{self.TOKEN_PREFIX}{digest[:n]}"
        # Resolve the astronomically unlikely short-hash collision by lengthening.
        while tok in self.token_to_supi and self.token_to_supi[tok] != canon:
            n += 1
            tok = f"{self.TOKEN_PREFIX}{digest[:n]}"
        self.supi_to_token[canon] = tok
        self.token_to_supi[tok] = canon
        return tok

    # ------------------------------------------------------------------ #
    # string-level transforms
    # ------------------------------------------------------------------ #
    def tokenize_text(self, text: str) -> str:
        """Replace every real SUPI occurrence in a string with its opaque token."""
        return _SUPI_RE.sub(lambda m: self._token_for(m.group(1)), text)

    def detokenize_text(self, text: str) -> str:
        """Restore every known token in a string back to its real SUPI.

        Unknown tokens (never minted by this gateway) are left untouched — the
        gateway does not invent identities it was never given.
        """
        return _TOKEN_RE.sub(lambda m: self.token_to_supi.get(m.group(0), m.group(0)), text)

    # ------------------------------------------------------------------ #
    # structural transforms — walk dict / list / str payloads recursively.
    # Dict KEYS are left untouched (identifiers appear in values, and rewriting
    # keys would corrupt the tool contract).
    # ------------------------------------------------------------------ #
    def tokenize(self, obj: Any) -> Any:
        """Return a copy of a tool RESULT with all real SUPIs tokenized."""
        return self._walk(obj, self.tokenize_text)

    def detokenize(self, obj: Any) -> Any:
        """Return a copy of tool ARGS with all tokens restored to real SUPIs."""
        return self._walk(obj, self.detokenize_text)

    def detokenize_fields(self, args: Dict[str, Any], fields) -> Dict[str, Any]:
        """Restore tokens ONLY in the named identifier arguments.

        Any other argument (free text, a report body, a ticket comment) keeps its
        tokens as-is. Otherwise a compromised agent could paste tokens into a
        free-text argument of an outbound tool and have the gateway turn them
        back into real SUPIs for it (a confused deputy)."""
        fields = set(fields)
        return {k: (self._walk(v, self.detokenize_text) if k in fields else v)
                for k, v in (args or {}).items()}

    def redact_text(self, text: str) -> str:
        """Like tokenize_text, but NEVER mints: a SUPI this gateway already
        tokenized becomes its token; any other SUPI (e.g. one an injected log
        introduced) is masked. Used for gateway-generated messages such as
        block reasons, so a block can't hand the agent a fresh valid token."""
        def sub(m):
            return self.supi_to_token.get(self._canonical(m.group(1)), "imsi-[REDACTED]")
        return _SUPI_RE.sub(sub, text)

    def redact(self, obj: Any) -> Any:
        return self._walk(obj, self.redact_text)

    def _walk(self, obj: Any, fn):
        if isinstance(obj, str):
            return fn(obj)
        if isinstance(obj, dict):
            return {k: self._walk(v, fn) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._walk(v, fn) for v in obj]
        if isinstance(obj, tuple):
            return tuple(self._walk(v, fn) for v in obj)
        return obj

    # ------------------------------------------------------------------ #
    # argument screening (proposal slide 6: "Reject calls whose identifier
    # argument is not a valid token, e.g. a raw SUPI injected via logs")
    # ------------------------------------------------------------------ #
    def contains_raw_supi(self, text: str) -> bool:
        """True if a raw SUPI/IMSI appears in the string. The agent is only ever
        handed opaque tokens, so a raw identifier in an argument can only have
        come from untrusted content (e.g. an injected alert log)."""
        return bool(_SUPI_RE.search(text))

    def is_known_token(self, value: str) -> bool:
        """True iff the value is an opaque token this gateway actually minted."""
        return value in self.token_to_supi

    # ------------------------------------------------------------------ #
    # introspection (for evidence logging / ablation reporting)
    # ------------------------------------------------------------------ #
    def mapping_count(self) -> int:
        return len(self.supi_to_token)
