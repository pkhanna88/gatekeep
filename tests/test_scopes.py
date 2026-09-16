"""Scope parsing and the subset rule. Pure functions - no stack needed."""

import pytest
from app.scopes import ScopeError, is_subset, parse_scope, parse_scopes


def test_parses_the_handbook_shape():
    s = parse_scope("salesforce:opportunity:read:0065g00001NWD")
    assert (s.system, s.rtype, s.action, s.rid) == (
        "salesforce",
        "opportunity",
        "read",
        "0065g00001NWD",
    )
    assert s.relation == "viewer"
    assert s.fga_object == "opportunity:0065g00001NWD"
    assert str(s) == "salesforce:opportunity:read:0065g00001NWD"


def test_write_needs_editor():
    assert parse_scope("salesforce:note:write:0NOT00001NWD").relation == "editor"


@pytest.mark.parametrize(
    "raw",
    [
        "salesforce:read:*",  # the coarse scope section 5.3 warns against
        "salesforce:opportunity:read:*",  # wildcard - unsupported in the MVP
        "sap:opportunity:read:1",  # unknown system
        "salesforce:contact:read:1",  # unknown type
        "salesforce:opportunity:delete:1",  # unknown action
        "salesforce:opportunity:read:",  # empty id
        "salesforce:opportunity:read:abc#viewer",  # would smuggle into the FGA object
        "salesforce:opportunity:read:../x",
        "salesforce:opportunity:read:1:extra",
        "",
    ],
)
def test_rejects_anything_not_strictly_valid(raw):
    with pytest.raises(ScopeError):
        parse_scope(raw)


def test_reports_every_bad_scope_at_once():
    with pytest.raises(ScopeError) as e:
        parse_scopes(["sap:a:read:1", "salesforce:opportunity:read:*"])
    assert "sap" in str(e.value) and "wildcard" in str(e.value)


def test_rejects_empty_and_duplicate_lists():
    with pytest.raises(ScopeError):
        parse_scopes([])
    with pytest.raises(ScopeError):
        parse_scopes(["salesforce:note:write:1", "salesforce:note:write:1"])


def test_subset_is_exact_match_only():
    held = ["salesforce:opportunity:read:0065g00001NWD"]
    assert is_subset(held, held) == []
    # a read scope does not cover write on the same record, and no prefix matching
    assert is_subset(["salesforce:opportunity:write:0065g00001NWD"], held)
    assert is_subset(["salesforce:opportunity:read:0065g00001NW"], held)
