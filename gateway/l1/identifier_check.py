"""
gateway/l1/identifier_check.py — L1 argument policy (identifier opacity)
========================================================================
Rule A: no argument may contain a raw subscriber identifier, at any depth. The agent
        is only ever handed opaque tokens, so a raw one came from untrusted input.
Rule B: an identifier argument must be ONE live token this gateway issues.

Runs on the AGENT-supplied args (before detokenization).
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, Iterator, Optional

from ..base import Check, CallContext
from .tokenizer import IdentifierTokenizer


def _leaves(obj: Any) -> Iterator[str]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k)
            yield from _leaves(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _leaves(v)
    elif isinstance(obj, (str, int)) and not isinstance(obj, bool):
        yield str(obj)


class IdentifierCheck(Check):
    kind = "identifier"
    layer = "L1"

    def __init__(self, tokenizer: IdentifierTokenizer, identifier_params: Iterable[str]):
        self.tokenizer = tokenizer
        self.identifier_params = set(identifier_params)

    def screen(self, ctx: CallContext) -> Optional[Dict[str, Any]]:
        for key, val in ctx.args.items():
            if any(self.tokenizer.contains_raw_identifier(s) for s in _leaves({key: val})):
                return self.block(ctx,
                    f"raw identifier in argument {key!r}; the agent is only ever handed "
                    f"opaque tokens, so a raw identifier can only originate from untrusted input",
                    violation="raw-identifier", argument=key)
            if key in self.identifier_params and not (
                    isinstance(val, str) and self.tokenizer.is_known_token(val)):
                return self.block(ctx,
                    f"argument {key!r} is not a live gateway-issued token (never issued, or its "
                    f"epoch ended); list UEs again to get current tokens",
                    violation="unknown-token", argument=key)
        return None
