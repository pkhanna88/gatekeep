"""
The scope string, section 5.3:  system : resource_type : action : resource_id

    salesforce:opportunity:read:0065g00001NWD

Parsing is strict on purpose. Every part is checked against a closed list, and
the resource id against a character class, because the parsed pieces are glued
straight into an OpenFGA object (`{rtype}:{rid}`) on the enforcement path.
Anything that does not parse is refused - there is no "best effort" scope.

Wildcards (`salesforce:opportunity:read:*`) are allowed by section 5.3 but are
NOT supported in this MVP: an OpenFGA check cannot answer "does Priya hold every
opportunity", so Invariant 1 could not be proven for one. Refusing is the
deny-by-default answer. Recorded in docs/DECISIONS.md.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

SYSTEMS = frozenset({"salesforce"})

# Must match the types in policy/fga-model.fga.
RESOURCE_TYPES = frozenset({"account", "opportunity", "invoice", "note"})

# Section 7.1: write needs `editor`, everything else needs `viewer`.
ACTION_RELATION = {"read": "viewer", "write": "editor"}

_RID = re.compile(r"^[A-Za-z0-9]{1,64}$")


class ScopeError(ValueError):
    pass


@dataclass(frozen=True)
class Scope:
    system: str
    rtype: str
    action: str
    rid: str

    def __str__(self) -> str:
        return f"{self.system}:{self.rtype}:{self.action}:{self.rid}"

    @property
    def relation(self) -> str:
        return ACTION_RELATION[self.action]

    @property
    def fga_object(self) -> str:
        return f"{self.rtype}:{self.rid}"


def parse_scope(raw: str) -> Scope:
    parts = raw.split(":") if isinstance(raw, str) else []
    if len(parts) != 4:
        raise ScopeError(f"{raw!r} is not system:resource_type:action:resource_id")
    system, rtype, action, rid = parts
    if system not in SYSTEMS:
        raise ScopeError(f"{raw!r}: unknown system {system!r}")
    if rtype not in RESOURCE_TYPES:
        raise ScopeError(f"{raw!r}: unknown resource type {rtype!r}")
    if action not in ACTION_RELATION:
        raise ScopeError(f"{raw!r}: unknown action {action!r}")
    if rid == "*":
        raise ScopeError(f"{raw!r}: wildcard scopes are not supported in this MVP")
    if not _RID.match(rid):
        raise ScopeError(f"{raw!r}: resource id must be 1-64 letters and digits")
    return Scope(system, rtype, action, rid)


def parse_scopes(raw: Iterable[str]) -> list[Scope]:
    """Parse all, report all failures at once, reject duplicates and empties."""
    raw = list(raw)
    if not raw:
        raise ScopeError("at least one scope is required")
    errors, parsed = [], []
    for s in raw:
        try:
            parsed.append(parse_scope(s))
        except ScopeError as e:
            errors.append(str(e))
    if errors:
        raise ScopeError("; ".join(errors))
    if len(set(parsed)) != len(parsed):
        raise ScopeError("duplicate scopes")
    return parsed


def is_subset(requested: Iterable[str], held: Iterable[str]) -> list[str]:
    """Invariant 2 helper. Returns requested scopes NOT present in `held`.

    Exact string match only. Held scopes are already strictly parsed, so there
    is no wildcard or prefix logic to get wrong.
    """
    held_set = set(held)
    return [s for s in requested if s not in held_set]
