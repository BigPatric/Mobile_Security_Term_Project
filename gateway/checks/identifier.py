"""
gateway/checks/identifier.py — L1 argument policy (identifier opacity)
======================================================================
Rule A: no argument may contain a raw SUPI. The agent is only ever handed opaque
        tokens, so a raw SUPI can only originate from untrusted input.
Rule B: an identifier argument must be a token this gateway actually minted.

Runs on the AGENT-supplied args (before detokenization).
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, Optional

from .base import Check, CallContext
from ..tokenizer import IdentifierTokenizer


class IdentifierCheck(Check):
    kind = "identifier"
    layer = "L1"

    def __init__(self, tokenizer: IdentifierTokenizer, identifier_params: Iterable[str]):
        self.tokenizer = tokenizer
        self.identifier_params = set(identifier_params)

    def screen(self, ctx: CallContext) -> Optional[Dict[str, Any]]:
        for key, val in ctx.args.items():
            if not isinstance(val, str):
                continue
            if self.tokenizer.contains_raw_supi(val):
                return self.block(ctx,
                    f"raw identifier in argument {key!r}; the agent is only ever handed "
                    f"opaque tokens, so a raw SUPI can only originate from untrusted input",
                    violation="raw-identifier", argument=key)
            if key in self.identifier_params and not self.tokenizer.is_known_token(val):
                return self.block(ctx,
                    f"argument {key!r}={val!r} is not a valid gateway-issued token",
                    violation="unknown-token", argument=key)
        return None
