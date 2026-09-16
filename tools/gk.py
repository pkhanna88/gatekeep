"""
gk - the console, in a terminal. Stand-in for apps/console until a web UI exists.

Every command logs in as a real Keycloak user and calls the real control plane
API, so what you see is exactly what the console would show - the same
permission checks apply. `--as` picks who you are: priya, admin or auditor.

    make gk ARGS="pending --as priya"                  the approval queue
    make gk ARGS="approve gr_01... --as priya"         approve (Invariant 1 runs here)
    make gk ARGS="reject gr_01... --as priya"
    make gk ARGS="revoke gr_01... --as priya"
    make gk ARGS="grants --as admin [--status active]"
    make gk ARGS="agents --as admin"
    make gk ARGS="sessions --as admin [--status running]"
    make gk ARGS="killswitch --as admin --reason 'suspected prompt injection'"
    make gk ARGS="audit --as auditor [--grant gr_01...] [--decision deny] [--limit 30]"
    make gk ARGS="watch --as auditor"                  live audit feed, Ctrl+C to stop
    make gk ARGS="verify --as auditor"                 chain integrity
    make gk ARGS="decode <jwt>"                        explain an agent token
"""

from __future__ import annotations

import argparse
import sys
import time

import httpx
from gklib import (
    audit_table,
    bearer,
    bold,
    control_plane,
    dim,
    grant_card,
    green,
    human_token,
    red,
    token_explained,
    yellow,
)


def fail(r: httpx.Response) -> int:
    try:
        body = r.json()
        print(red(f"  Refused ({r.status_code}) {body.get('error')}: {body.get('message')}"))
        for s in body.get("offending_scopes", []):
            print(red(f"    - {s}"))
    except ValueError:
        print(red(f"  HTTP {r.status_code}: {r.text[:300]}"))
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="gk", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "command",
        choices=[
            "pending",
            "grants",
            "show",
            "approve",
            "reject",
            "revoke",
            "agents",
            "sessions",
            "killswitch",
            "audit",
            "watch",
            "verify",
            "decode",
        ],
    )
    ap.add_argument("target", nargs="?", help="grant id, or a JWT for `decode`")
    ap.add_argument("--as", dest="who", default="priya", choices=["priya", "admin", "auditor"])
    ap.add_argument("--status")
    ap.add_argument("--reason", default="revoked from gk")
    ap.add_argument("--grant")
    ap.add_argument("--decision", choices=["allow", "deny"])
    ap.add_argument("--limit", type=int, default=30)
    ap.add_argument("--yes", action="store_true", help="skip the kill switch confirmation")
    a = ap.parse_args()

    if a.command == "decode":
        if not a.target:
            ap.error("decode needs a token")
        token_explained(a.target)
        return 0

    needs_target = {"show", "approve", "reject", "revoke"}
    if a.command in needs_target and not a.target:
        ap.error(f"{a.command} needs a grant id")

    h = bearer(human_token(a.who))
    cp = control_plane()
    print(dim(f"  signed in as {a.who} via Keycloak\n"))

    if a.command in ("pending", "grants"):
        status = "pending" if a.command == "pending" else a.status
        r = cp.get("/v1/grants", params={"status": status} if status else {}, headers=h)
        if r.status_code != 200:
            return fail(r)
        grants = r.json()["grants"]
        if not grants:
            print(dim(f"  No {status or ''} grants visible to {a.who}."))
        for g in grants:
            grant_card(g)
            if g["status"] == "pending":
                print(dim(f"    approve:  make gk ARGS=\"approve {g['id']} --as priya\""))
            print()
        return 0

    if a.command == "show":
        r = cp.get(f"/v1/grants/{a.target}", headers=h)
        if r.status_code != 200:
            return fail(r)
        grant_card(r.json())
        return 0

    if a.command in ("approve", "reject"):
        r = cp.post(f"/v1/grants/{a.target}/{a.command}", headers=h)
        if r.status_code != 200:
            return fail(r)
        grant_card(r.json())
        print(green(f"  {a.command}d."))
        return 0

    if a.command == "revoke":
        r = cp.post(f"/v1/grants/{a.target}/revoke", headers=h, json={"reason": a.reason})
        if r.status_code != 200:
            return fail(r)
        grant_card(r.json())
        print(green("  Revoked. The agent's next request is refused."))
        return 0

    if a.command == "agents":
        r = cp.get("/v1/agents", headers=h)
        if r.status_code != 200:
            return fail(r)
        for ag in r.json()["agents"]:
            print(
                f"  {bold(ag['id']):<50} {ag['display_name']:<24} "
                f"owner {ag['owner_email']}  {ag['status']}"
            )
        return 0

    if a.command == "sessions":
        r = cp.get("/v1/sessions", params={"status": a.status} if a.status else {}, headers=h)
        if r.status_code != 200:
            return fail(r)
        for s in r.json()["sessions"]:
            colour = green if s["status"] == "running" else red
            print(
                f"  {s['id']}  {colour(s['status']):<18} {s['agent_id']}  for {s['principal_sub']}"
            )
            print(
                dim(
                    f"      {s['purpose']}   grant {s['grant_id']}   "
                    f"started {s['started_at'][11:19]}"
                )
            )
        return 0

    if a.command == "killswitch":
        r = cp.get("/v1/killswitch/preview", headers=h)
        if r.status_code != 200:
            return fail(r)
        p = r.json()
        print(red(bold("  KILL SWITCH")))
        print(
            f"  This revokes {bold(str(p['grants_to_revoke']))} grant(s) and stops "
            f"{bold(str(p['sessions_to_kill']))} running agent session(s), estate-wide."
        )
        if not a.yes and input(yellow("  Type KILL to confirm: ")).strip() != "KILL":
            print(dim("  Cancelled."))
            return 1
        r = cp.post("/v1/killswitch", headers=h, json={"reason": a.reason})
        if r.status_code != 200:
            return fail(r)
        k = r.json()
        print(red(f"  Activated by {k['activated_by']} at {k['activated_at'][11:19]}"))
        for n in range(k["sessions_killed"], -1, -1):
            print(f"\r  running sessions: {bold(str(n))}  ", end="", flush=True)
            time.sleep(0.15)
        print(f"\n  {k['grants_revoked']} grant(s) revoked.")
        return 0

    if a.command == "audit":
        params = {"limit": a.limit}
        if a.grant:
            params["grant_id"] = a.grant
        if a.decision:
            params["decision"] = a.decision
        r = cp.get("/v1/audit", params=params, headers=h)
        if r.status_code != 200:
            return fail(r)
        audit_table(list(reversed(r.json()["events"])))
        return 0

    if a.command == "watch":
        last = 0
        print(dim("  live audit feed - Ctrl+C to stop\n"))
        try:
            while True:
                r = cp.get("/v1/audit", params={"limit": 50}, headers=h)
                if r.status_code == 401:  # Keycloak token expired on a long watch
                    h = bearer(human_token(a.who))
                    continue
                if r.status_code != 200:
                    return fail(r)
                new = [e for e in reversed(r.json()["events"]) if e["seq"] > last]
                if new:
                    audit_table(new) if last else audit_table(new[-10:])
                    last = new[-1]["seq"]
                time.sleep(1)
        except KeyboardInterrupt:
            return 0

    if a.command == "verify":
        r = cp.get("/v1/audit/verify", headers=h)
        if r.status_code != 200:
            return fail(r)
        v = r.json()
        print(
            green(f"  CHAIN INTACT  {v['message']}")
            if v["valid"]
            else red(f"  CHAIN BROKEN  {v['message']}")
        )
        return 0 if v["valid"] else 1

    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except httpx.ConnectError as e:
        print(f"\n  Cannot reach Gatekeep: {e}\n  Is it running?  make services\n")
        sys.exit(2)
