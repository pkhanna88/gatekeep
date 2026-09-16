"""
The connector interface. Section 3.12: this boundary is what actually matters
architecturally - Salesforce is one implementation, the mock another, SAP and
ServiceNow later.

A connector answers two questions and nothing else:

  map_request   "what is this HTTP request, as a scope?"   (no I/O, no decisions)
  forward       "send the already-authorised request upstream"

It never decides allow or deny. That stays in the PEP pipeline, identical for
every connector, so adding a connector cannot add a way around enforcement.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class UnmappedRequest(Exception):
    """The connector does not recognise this request. The PEP denies it."""


@dataclass(frozen=True)
class Action:
    system: str
    rtype: str
    verb: str  # read | write
    rid: str
    upstream_object: str  # the connector's own name for rtype, e.g. Invoice__c

    @property
    def scope(self) -> str:
        return f"{self.system}:{self.rtype}:{self.verb}:{self.rid}"

    @property
    def relation(self) -> str:
        return "editor" if self.verb == "write" else "viewer"

    @property
    def fga_object(self) -> str:
        return f"{self.rtype}:{self.rid}"


@dataclass(frozen=True)
class ProxiedResponse:
    status: int
    content: bytes
    content_type: str


class Connector(Protocol):
    name: str

    def map_request(self, method: str, path: str) -> Action: ...

    async def forward(self, action: Action, method: str, body: bytes | None) -> ProxiedResponse: ...
