"""
Salesforce-shaped connector, pointed at the mock (docs/CONNECTOR-NOTES.md).

Mapping is deliberately narrow - exactly one record per request:

    GET   .../sobjects/Opportunity/0065g00001NWD  ->  salesforce:opportunity:read:0065g00001NWD
    PATCH .../sobjects/Note/0NOT00001NWD          ->  salesforce:note:write:0NOT00001NWD

Anything else - SOQL queries, DELETE, unknown objects, odd paths - raises
UnmappedRequest and the PEP denies it. A query endpoint would read many records
under one request, which a per-record scope cannot authorise; supporting it
means filtering results per record, and that is Phase 2.

`forward` rebuilds the upstream URL from the parsed Action rather than passing
the agent's raw path through, so nothing the agent put in the path beyond what
was authorised (encoded slashes, `..`, extra segments) reaches upstream.
"""

from __future__ import annotations

import re

import httpx
from app import settings

from pep_proxy.connectors.base import Action, ProxiedResponse, UnmappedRequest

_PATH = re.compile(r"^services/data/v(\d{2}\.\d)/sobjects/([A-Za-z_]+)/([A-Za-z0-9]{1,64})$")
_OBJECTS = {
    "Account": "account",
    "Opportunity": "opportunity",
    "Invoice__c": "invoice",
    "Note": "note",
}
_VERBS = {"GET": "read", "PATCH": "write"}
MAX_BODY_BYTES = 64_000


class MockSalesforceConnector:
    name = "salesforce"

    def __init__(self, client: httpx.AsyncClient | None = None):
        self._client = client or httpx.AsyncClient(
            base_url=settings.MOCK_SALESFORCE_URL,
            headers={"Authorization": f"Bearer {settings.MOCK_SALESFORCE_SECRET}"},
            timeout=10.0,
        )

    def map_request(self, method: str, path: str) -> Action:
        m = _PATH.match(path)
        if not m:
            raise UnmappedRequest(f"unrecognised path {path!r}")
        _, obj, rid = m.groups()
        if obj not in _OBJECTS:
            raise UnmappedRequest(f"unsupported object {obj!r}")
        if method not in _VERBS:
            raise UnmappedRequest(f"unsupported method {method}")
        return Action("salesforce", _OBJECTS[obj], _VERBS[method], rid, obj)

    async def forward(self, action: Action, method: str, body: bytes | None) -> ProxiedResponse:
        if body and len(body) > MAX_BODY_BYTES:
            raise UnmappedRequest("request body too large")
        url = f"/services/data/v60.0/sobjects/{action.upstream_object}/{action.rid}"
        r = await self._client.request(
            method, url, content=body or None, headers={"Content-Type": "application/json"}
        )
        return ProxiedResponse(
            r.status_code, r.content, r.headers.get("content-type", "application/json")
        )

    async def aclose(self) -> None:
        await self._client.aclose()
