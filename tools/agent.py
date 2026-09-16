"""
The demo agent: an invoice reconciler for Northwind Traders.

It is deliberately a plain HTTP client, not an LLM - what the demo proves is
what Gatekeep lets it do, and a deterministic agent makes that repeatable. It
does what section 10.1 describes: request a grant, wait for Priya, exchange the
grant for a token, read the opportunity and the invoice, spot the discrepancy,
write a note - every call through the PEP.

    python tools/agent.py                 do the job once (approve it with: make gk ARGS="pending")
    python tools/agent.py --loop          keep re-reading every 2s - run this in a second terminal,
                                          hit the kill switch in the first, watch it stop

The agent never holds a Salesforce credential. It holds a bootstrap credential
that proves who it is, and five-minute tokens that prove what it may do.
"""

from __future__ import annotations

import argparse
import json
import sys
import time

import httpx
from gklib import bearer, bold, dim, green, human_token, red, settings, yellow

AGENT_ID = "agent://acme/invoice-reconciler"
PRINCIPAL = "priya@acme.test"
PURPOSE = "Reconcile August invoices for Northwind Traders"

OPPORTUNITY, INVOICE, NOTE = "0065g00001NWD", "0INV00001NWD", "0NOT00001NWD"
SCOPES = [
    f"salesforce:opportunity:read:{OPPORTUNITY}",
    f"salesforce:invoice:read:{INVOICE}",
    f"salesforce:note:write:{NOTE}",
]
SOBJECTS = "services/data/v60.0/sobjects"


class Agent:
    def __init__(self, credential: str):
        self.credential = credential
        self.token: str | None = None
        self.session_id: str | None = None
        self.grant_id: str | None = None

    # -- control plane ------------------------------------------------------------

    def request_grant(self, scopes: list[str] = SCOPES, ttl_minutes: int = 30) -> httpx.Response:
        return httpx.post(
            f"{settings.CONTROL_PLANE_URL}/v1/grants",
            headers=bearer(self.credential),
            json={
                "agent_id": AGENT_ID,
                "principal_sub": PRINCIPAL,
                "purpose": PURPOSE,
                "scopes": scopes,
                "constraints": {"max_records": 500, "rate_limit_rpm": 60},
                "ttl_minutes": ttl_minutes,
            },
            timeout=15,
        )

    # -- token service ------------------------------------------------------------

    def exchange(
        self, grant_id: str, scope: str | None = None, refresh: bool = False
    ) -> httpx.Response:
        form = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": grant_id,
            "subject_token_type": "urn:gatekeep:params:token-type:grant",
            "actor_token": self.credential,
            "actor_token_type": "urn:gatekeep:params:token-type:agent",
        }
        if scope:
            form["scope"] = scope
        if refresh and self.session_id:
            form["session_id"] = self.session_id
        r = httpx.post(f"{settings.TOKEN_SERVICE_URL}/oauth/token", data=form, timeout=15)
        if r.status_code == 200:
            body = r.json()
            self.token, self.session_id, self.grant_id = (
                body["access_token"],
                body["session_id"],
                grant_id,
            )
        return r

    # -- PEP ----------------------------------------------------------------------

    def call(
        self, method: str, obj: str, rid: str, body: dict | None = None, token: str | None = None
    ):
        url = f"{settings.PEP_URL}/proxy/salesforce/{SOBJECTS}/{obj}/{rid}"
        return httpx.request(
            method, url, headers=bearer(token or self.token or ""), json=body, timeout=15
        )


def register(admin_token: str) -> str:
    """Admin registers the agent; returns the bootstrap credential (shown once)."""
    r = httpx.post(
        f"{settings.CONTROL_PLANE_URL}/v1/agents",
        headers=bearer(admin_token),
        json={"id": AGENT_ID, "display_name": "Invoice reconciler", "owner_email": PRINCIPAL},
        timeout=15,
    )
    if r.status_code != 201:
        raise SystemExit(
            f"Could not register {AGENT_ID}: {r.status_code} {r.text[:200]}\n"
            f"Already registered? Reset first:  make demo-reset"
        )
    return r.json()["bootstrap_credential"]


def reconcile(agent: Agent, log=print) -> dict:
    """The job itself. Returns what it found. Raises on any refusal."""
    opp = agent.call("GET", "Opportunity", OPPORTUNITY)
    opp.raise_for_status()
    inv = agent.call("GET", "Invoice__c", INVOICE)
    inv.raise_for_status()
    o, i = opp.json(), inv.json()
    diff = o["Amount"] - i["Amount__c"]
    summary = (
        f"August reconciliation: opportunity {o['Name']} closed at {o['Amount']:,.2f}; "
        f"invoice {i['Name']} billed {i['Amount__c']:,.2f}. "
        f"Under-billed by {diff:,.2f}. Flagged for finance review. "
        f"Written by {AGENT_ID} on behalf of {PRINCIPAL}."
    )
    note = agent.call("PATCH", "Note", NOTE, {"Body": summary})
    note.raise_for_status()
    return {"opportunity": o, "invoice": i, "difference": diff, "note": summary}


def main() -> int:
    sys.stdout.reconfigure(line_buffering=True)  # readable when piped or tailed
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--loop", action="store_true", help="keep working until stopped or refused")
    args = ap.parse_args()

    print(bold(f"\n  {AGENT_ID}"))
    print(dim("  registering (as admin@acme.test)..."))
    agent = Agent(register(human_token("admin")))

    r = agent.request_grant()
    grant = r.json()
    print(f"  grant requested  {bold(grant['id'])}  {yellow('PENDING')}")
    print(dim(f"  waiting for {PRINCIPAL} to approve. In another terminal:"))
    print(f"      make gk ARGS=\"approve {grant['id']} --as priya\"")

    while True:
        r = agent.exchange(grant["id"])
        if r.status_code == 200:
            break
        if r.json().get("error") != "grant_pending":
            print(red(f"  refused: {r.json()}"))
            return 1
        time.sleep(2)
    print(green("  approved. token received, session ") + agent.session_id)

    rounds = 0
    while True:
        rounds += 1
        try:
            if rounds > 1 and rounds % 60 == 0:  # refresh well inside the 5-minute lifetime
                rr = agent.exchange(grant["id"], refresh=True)
                if rr.status_code != 200:
                    print(red(f"  refresh refused: {rr.json()['error']} - stopping"))
                    return 0
            result = reconcile(agent)
            print(
                f"  {time.strftime('%H:%M:%S')}  {green('ok')}  read opportunity + invoice, "
                f"difference {result['difference']:,.2f}, note written"
            )
        except httpx.HTTPStatusError as e:
            body = (
                e.response.json()
                if e.response.headers.get("content-type", "").startswith("application/json")
                else {}
            )
            print(
                f"  {time.strftime('%H:%M:%S')}  {red('REFUSED')}  "
                f"{body.get('error')}: {body.get('message')}"
            )
            print(dim("  The agent has lost its authority. Stopping."))
            return 0
        if not args.loop:
            print(
                json.dumps({"difference": result["difference"], "note": result["note"]}, indent=2)
            )
            return 0
        time.sleep(2)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except httpx.ConnectError as e:
        print(f"\n  Cannot reach Gatekeep: {e}\n  Is it running?  make services\n")
        sys.exit(2)
