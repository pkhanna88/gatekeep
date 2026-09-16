"""
Shared terminal helpers for tools/gk.py (the console stand-in), tools/agent.py
(the demo agent) and tools/demo.py (the narrated demo).

Nothing in here makes a security decision. It logs humans in against Keycloak,
calls the Gatekeep APIs, and prints what came back in a readable way.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import textwrap
from datetime import UTC, datetime

import httpx

REPO_SERVICES = os.path.join(os.path.dirname(__file__), "..", "services", "control-plane")
sys.path.insert(0, os.path.abspath(REPO_SERVICES))
from app import settings  # noqa: E402

KEYCLOAK_TOKEN_URL = f"{settings.KEYCLOAK_ISSUER}/protocol/openid-connect/token"

# The three seeded Keycloak users (deploy/keycloak-realm.json). Dev passwords.
USERS = {
    "priya": ("priya@acme.test", "priya"),
    "admin": ("admin@acme.test", "admin"),
    "auditor": ("auditor@acme.test", "auditor"),
}

NO_COLOR = bool(os.environ.get("NO_COLOR")) or not sys.stdout.isatty()


def c(code: str, s: str) -> str:
    return s if NO_COLOR else f"\033[{code}m{s}\033[0m"


def green(s):
    return c("32", s)


def red(s):
    return c("31", s)


def yellow(s):
    return c("33", s)


def cyan(s):
    return c("36", s)


def bold(s):
    return c("1", s)


def dim(s):
    return c("2", s)


def wrap(text: str, indent: int = 2, width: int = 78) -> str:
    pad = " " * indent
    return "\n".join(
        textwrap.fill(p, width=width, initial_indent=pad, subsequent_indent=pad)
        if p.strip()
        else ""
        for p in textwrap.dedent(text).strip("\n").split("\n")
    )


# --- identity -------------------------------------------------------------------


def human_token(who: str) -> str:
    """Log a seeded user in against Keycloak (OIDC password grant, dev realm only).

    The browser console would do this with authorization code + PKCE. The token
    that comes back is the same shape either way.
    """
    if who not in USERS:
        raise SystemExit(f"Unknown user {who!r}. Use one of: {', '.join(USERS)}")
    username, password = USERS[who]
    r = httpx.post(
        KEYCLOAK_TOKEN_URL,
        data={
            "grant_type": "password",
            "client_id": "gatekeep-console",
            "username": username,
            "password": password,
            "scope": "openid",
        },
        timeout=10,
    )
    if r.status_code != 200:
        raise SystemExit(
            f"Keycloak login for {username} failed: HTTP {r.status_code} {r.text[:200]}"
        )
    return r.json()["access_token"]


def decode_unverified(token: str) -> tuple[dict, dict]:
    """Read a JWT's header and payload WITHOUT checking the signature.

    Display only - to show that a JWT payload is readable by anyone (section 2.4).
    Nothing that makes a decision does this; the PEP verifies against JWKS.
    """

    def part(i: int) -> dict:
        seg = token.split(".")[i]
        return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))

    return part(0), part(1)


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def control_plane() -> httpx.Client:
    return httpx.Client(base_url=settings.CONTROL_PLANE_URL, timeout=15)


# --- rendering ------------------------------------------------------------------


def show_http(method: str, url: str, status: int | None = None, body: dict | None = None) -> None:
    print(dim(f"  {method} {url}"))
    if status is not None:
        colour = green if status < 300 else red
        print(dim("  -> ") + colour(f"HTTP {status}"))
    if body is not None:
        print(indent_json(body, 6))


def indent_json(obj, n: int = 4, max_lines: int = 40) -> str:
    lines = json.dumps(obj, indent=2, default=str).splitlines()
    if len(lines) > max_lines:
        lines = lines[: max_lines - 1] + [f"... ({len(lines) - max_lines + 1} more lines)"]
    return "\n".join(dim(" " * n + ln) for ln in lines)


def humanise_expiry(iso: str) -> str:
    seconds = int((datetime.fromisoformat(iso) - datetime.now(UTC)).total_seconds())
    if seconds <= 0:
        return "expired"
    minutes = seconds // 60
    return f"{minutes} minutes" if minutes else f"{seconds} seconds"


def grant_card(g: dict) -> None:
    """The approval screen, section 3.9: purpose in plain English, scopes as sentences."""
    status_colour = {"pending": yellow, "active": green}.get(g["status"], red)
    print(f"  +{'-' * 72}+")
    left, status = f"Grant {g['id']}", g["status"].upper()
    gap = " " * (70 - len(left) - len(status))
    print(f"  | {bold(left)}{gap}{status_colour(status)} |")
    print(f"  +{'-' * 72}+")
    print(f"    {bold('Agent')}      {g['agent_id']}")
    print(f"    {bold('On behalf')}  {g['principal_sub']}")
    print(f"    {bold('Purpose')}    {g['purpose']}")
    print(f"    {bold('Wants to')}")
    for d in g["scope_descriptions"]:
        print(f"      - {d}")
    print(f"    {bold('For')}        {humanise_expiry(g['expires_at'])}")
    if g.get("approved_by"):
        print(f"    {bold('Approved')}   by {g['approved_by']}")
    if g.get("revoked_by") or g.get("revoke_reason"):
        print(
            f"    {bold('Stopped')}    {g.get('revoke_reason') or ''} "
            f"{dim(g.get('revoked_by') or '')}"
        )
    print(f"  +{'-' * 72}+")


def audit_table(events: list[dict]) -> None:
    print(dim(f"  {'seq':>4}  {'time':8}  {'decision':8}  {'event':22} {'resource':28} reason"))
    for e in events:
        decision = e["decision"] or ""
        mark = green(f"{decision:8}") if decision == "allow" else red(f"{decision:8}")
        ts = e["ts"][11:19]
        resource = f"{e['action'] or ''} {e['resource'] or ''}".strip()
        print(
            f"  {e['seq']:>4}  {ts:8}  {mark}  {e['event_type']:22} {resource[:28]:28} "
            f"{dim((e['reason'] or '')[:40])}"
        )


def token_explained(token: str) -> None:
    header, claims = decode_unverified(token)
    left = claims["exp"] - claims["iat"]
    print(bold("  Header") + dim("  (how it was signed)"))
    print(
        f"    alg  {header['alg']:<28} "
        f"{dim('RSA signature + SHA-256; the only algorithm the PEP accepts')}"
    )
    print(f"    kid  {header['kid']:<28} {dim('which OpenBao key version signed it')}")
    print()
    print(bold("  Payload") + dim("  (readable by anyone - never put secrets here)"))
    rows = [
        ("sub", claims["sub"], "THE HUMAN whose authority this is"),
        ("act.sub", claims["act"]["sub"], "THE AGENT actually acting (RFC 8693 actor)"),
        ("act.instance", claims["act"]["instance"], "this run of the agent - its session"),
        ("aud", claims["aud"], "only the PEP should accept it"),
        ("grant_id", claims["grant_id"], "the approval it came from"),
        ("purpose", claims["purpose"], "what Priya was told"),
        ("exp - iat", f"{left} seconds", "five minutes, then useless"),
        ("jti", claims["jti"], "unique id for this token"),
    ]
    for k, v, why in rows:
        colour = green if k in ("sub", "act.sub") else (lambda s: s)
        print(f"    {k:<13} {colour(str(v)):<40} {dim(why)}")
    print(f"    {'scope':<13} {dim('exactly these records and actions, nothing else:')}")
    for s in claims["scope"]:
        print(f"      {cyan(s)}")
