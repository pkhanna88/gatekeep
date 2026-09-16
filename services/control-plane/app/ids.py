"""Sortable identifiers in the handbook's shape: gr_01HQ3K8W7X..., run-01HQ3K9Z2P...

A ULID: 48 bits of millisecond time then 80 random bits, Crockford base32.
Sorts by creation time, which makes grant and session lists readable in order.
"""

import secrets
import time

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def ulid() -> str:
    value = (int(time.time() * 1000) << 80) | secrets.randbits(80)
    out = []
    for _ in range(26):
        out.append(_ALPHABET[value & 31])
        value >>= 5
    return "".join(reversed(out))


def grant_id() -> str:
    return f"gr_{ulid()}"


def session_id() -> str:
    return f"run-{ulid()}"


def token_id() -> str:
    return f"tok_{ulid()}"
