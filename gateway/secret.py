"""
gateway/secret.py — the gateway's private key material
======================================================
One master secret per gateway instance. It never leaves the gateway, is never
written to the repo, and is never shown to the agent. Two keys are derived
from it, one per purpose, so a key used for one job can't be abused for the other:

    tokenize    L1: SUPI -> opaque token   (HMAC, so tokens can't be guessed offline)
    capability  L2: signing operator authorization capabilities

Source of the master secret, in order:
    1. the MCP_GATEWAY_SECRET environment variable (hex string), so several gateway
       processes can share one key if they must agree on tokens / capabilities;
    2. otherwise 32 fresh random bytes at start-up (tokens and capabilities then
       live only as long as the gateway process, which is what the experiments use).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from typing import Optional

ENV_VAR = "MCP_GATEWAY_SECRET"


def load_master_secret(env_var: str = ENV_VAR) -> bytes:
    value = os.environ.get(env_var)
    if value:
        try:
            key = bytes.fromhex(value.strip())
        except ValueError:
            raise ValueError(f"{env_var} must be a hex string") from None
        if len(key) < 16:
            raise ValueError(f"{env_var} must be at least 16 bytes (32 hex chars)")
        return key
    return secrets.token_bytes(32)


def derive_key(master: bytes, purpose: str) -> bytes:
    """Per-purpose subkey: HMAC-SHA256(master, purpose)."""
    return hmac.new(master, purpose.encode(), hashlib.sha256).digest()


def resolve_master(master: Optional[bytes]) -> bytes:
    return master if master is not None else load_master_secret()
