"""
Mock Salesforce - port 8003. Connector one (docs/CONNECTOR-NOTES.md).

A stand-in for the real Salesforce REST API, shaped like it closely enough that
the PEP's connector does real work: `/services/data/v60.0/sobjects/<Object>/<Id>`,
Salesforce-style error bodies, per-record data.

Two things make it useful as evidence rather than a prop:

  1. It only answers the PEP. Requests must carry the connector credential,
     which only the PEP holds (section 4.4, PEP -> Salesforce). An agent calling
     it directly gets 401 - the bypass attempt in the demo.
  2. It logs every request that ARRIVES, authenticated or not, at
     GET /_gatekeep/requests. The demo reads this to prove a denied request never
     reached "Salesforce" at all. Dev-only inspection; the real Salesforce has
     its own event monitoring.

The records match deploy/seed/fga-tuples.json, so a denial in the demo is a real
policy denial, not a missing fixture.
"""

from __future__ import annotations

import copy
import hmac
from datetime import UTC, datetime

from app import settings
from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse

API = "/services/data/v60.0/sobjects"

NORTHWIND, CONTOSO = "0015g00001XYZ", "0015g00099ABC"

SEED: dict[str, dict[str, dict]] = {
    "Account": {
        NORTHWIND: {"Id": NORTHWIND, "Name": "Northwind Traders", "Industry": "Wholesale"},
        CONTOSO: {"Id": CONTOSO, "Name": "Contoso Ltd", "Industry": "Manufacturing"},
    },
    "Opportunity": {
        "0065g00001NWD": {
            "Id": "0065g00001NWD",
            "AccountId": NORTHWIND,
            "Name": "Northwind - August renewal",
            "StageName": "Closed Won",
            "CloseDate": "2026-08-12",
            "Amount": 48500.00,
        },
        "0065g00099CTO": {
            "Id": "0065g00099CTO",
            "AccountId": CONTOSO,
            "Name": "Contoso - platform expansion",
            "StageName": "Negotiation",
            "CloseDate": "2026-09-30",
            "Amount": 220000.00,
        },
    },
    "Invoice__c": {
        "0INV00001NWD": {
            "Id": "0INV00001NWD",
            "Account__c": NORTHWIND,
            "Name": "INV-2026-0817",
            "Invoice_Date__c": "2026-08-17",
            "Amount__c": 45200.00,
            "Status__c": "Sent",
            "Opportunity__c": "0065g00001NWD",
        },
        "0INV00099CTO": {
            "Id": "0INV00099CTO",
            "Account__c": CONTOSO,
            "Name": "INV-2026-0903",
            "Invoice_Date__c": "2026-09-03",
            "Amount__c": 110000.00,
            "Status__c": "Draft",
        },
    },
    "Note": {
        "0NOT00001NWD": {
            "Id": "0NOT00001NWD",
            "ParentId": NORTHWIND,
            "Title": "Reconciliation notes",
            "Body": "",
        },
    },
}

app = FastAPI(title="Mock Salesforce", version="0.1.0")
app.state.data = copy.deepcopy(SEED)
app.state.requests = []


def _authorised(authorization: str | None) -> bool:
    expected = f"Bearer {settings.MOCK_SALESFORCE_SECRET}"
    return hmac.compare_digest((authorization or "").encode(), expected.encode())


def _sf_error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content=[{"errorCode": code, "message": message}])


@app.middleware("http")
async def log_arrivals(request: Request, call_next):
    if not request.url.path.startswith("/_gatekeep"):
        app.state.requests.append(
            {
                "at": datetime.now(UTC).isoformat(),
                "method": request.method,
                "path": request.url.path,
                "authenticated": _authorised(request.headers.get("authorization")),
            }
        )
    return await call_next(request)


@app.get(API + "/{obj}/{rid}")
async def get_record(obj: str, rid: str, authorization: str | None = Header(None)):
    if not _authorised(authorization):
        return _sf_error(401, "INVALID_SESSION_ID", "Session expired or invalid")
    record = app.state.data.get(obj, {}).get(rid)
    if record is None:
        return _sf_error(404, "NOT_FOUND", f"The requested resource does not exist: {obj} {rid}")
    return {"attributes": {"type": obj, "url": f"{API}/{obj}/{rid}"}, **record}


@app.patch(API + "/{obj}/{rid}")
async def update_record(
    obj: str, rid: str, request: Request, authorization: str | None = Header(None)
):
    if not _authorised(authorization):
        return _sf_error(401, "INVALID_SESSION_ID", "Session expired or invalid")
    record = app.state.data.get(obj, {}).get(rid)
    if record is None:
        return _sf_error(404, "NOT_FOUND", f"The requested resource does not exist: {obj} {rid}")
    changes = await request.json()
    if not isinstance(changes, dict) or "Id" in changes:
        return _sf_error(400, "INVALID_FIELD", "Body must be an object and may not change Id")
    record.update(changes)
    return JSONResponse(status_code=200, content={"id": rid, "success": True, "errors": []})


@app.get("/_gatekeep/requests")
async def arrivals():
    return {"count": len(app.state.requests), "requests": app.state.requests}


@app.post("/_gatekeep/reset")
async def reset(authorization: str | None = Header(None)):
    if not _authorised(authorization):
        return _sf_error(401, "INVALID_SESSION_ID", "Session expired or invalid")
    app.state.data = copy.deepcopy(SEED)
    app.state.requests = []
    return {"reset": True}


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "service": "mock-salesforce"}
