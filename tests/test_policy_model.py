"""
Day 3 acceptance: the policy model is loaded, seeded, and answers correctly.

Day 3 asks INF to verify relationship queries by hand in the playground. Doing
it by hand is the right way to learn it and the wrong way to keep it true - the
next person to edit a relation has no way of knowing what the answers were
supposed to be. deploy/seed/fga-checks.json is that verification written down,
and this file runs it on every push.

The negatives are the point. Eleven checks, six of which must come back False.
A model that says yes correctly and never says no is not an authorization model,
and both invariants are ultimately assertions about what OpenFGA refuses.
"""

import json
import pathlib
import re

import httpx
import pytest

OPENFGA = "http://localhost:8081"
STORE_NAME = "gatekeep"

REPO = pathlib.Path(__file__).resolve().parent.parent
SEED_DIR = REPO / "deploy" / "seed"
DSL = REPO / "policy" / "fga-model.fga"

NOT_SEEDED = (
    "No OpenFGA store named 'gatekeep'. Run `make seed`. If you are in CI, the "
    "seed step should run between the health-check wait and pytest."
)


def _load(name: str) -> dict:
    raw = json.loads((SEED_DIR / name).read_text())
    return {k: v for k, v in raw.items() if not k.startswith("_")}


@pytest.fixture(scope="session")
def store() -> tuple[str, str]:
    """(store_id, model_id) for the seeded store, found by name.

    Looked up rather than read from deploy/seed/.seeded.json so the tests work
    on a machine that did not run the seed itself.
    """
    try:
        r = httpx.get(f"{OPENFGA}/stores", timeout=10)
    except httpx.ConnectError:
        pytest.skip("OpenFGA is not reachable")
    r.raise_for_status()

    matches = [s for s in r.json().get("stores", []) if s["name"] == STORE_NAME]
    if not matches:
        pytest.skip(NOT_SEEDED)
    store_id = matches[0]["id"]

    models = httpx.get(f"{OPENFGA}/stores/{store_id}/authorization-models", timeout=10)
    models.raise_for_status()
    authorization_models = models.json().get("authorization_models", [])
    if not authorization_models:
        pytest.skip(f"Store {store_id} exists but has no authorization model. Run `make seed`.")
    return store_id, authorization_models[0]["id"]


# --- the model is the model we think it is ---------------------------------


def _relations_from_dsl() -> dict[str, set[str]]:
    """Pull {type: {relations}} out of the .fga DSL.

    Deliberately not a real parser. It only needs to catch the failure that
    actually happens - someone edits one representation and forgets the other.
    """
    found: dict[str, set[str]] = {}
    current = None
    for line in DSL.read_text().splitlines():
        if line.startswith("#"):
            continue
        if m := re.match(r"^type\s+(\w+)", line):
            current = m.group(1)
            found[current] = set()
        elif current and (m := re.match(r"^\s+define\s+(\w+):", line)):
            found[current].add(m.group(1))
    return found


def _relations_from_json() -> dict[str, set[str]]:
    model = _load("fga-model.json")
    return {t["type"]: set(t.get("relations", {})) for t in model["type_definitions"]}


def test_dsl_and_json_describe_the_same_model():
    """policy/fga-model.fga is human-readable; deploy/seed/fga-model.json is what
    the API accepts. Transpiling the DSL needs the `fga` CLI, which we did not
    want in everyone's PATH on Day 1, so we keep both - and keep them honest."""
    dsl, js = _relations_from_dsl(), _relations_from_json()
    assert dsl == js, (
        "policy/fga-model.fga and deploy/seed/fga-model.json have drifted.\n"
        f"  only in .fga:  { {k: v for k, v in dsl.items() if js.get(k) != v} }\n"
        f"  only in .json: { {k: v for k, v in js.items() if dsl.get(k) != v} }"
    )


def test_model_has_the_four_day_two_types():
    """Day 2 asks for account, opportunity, invoice, note. §3.4 only shows two of
    them, so this is the line that says we did the Day 2 work rather than
    shipping the handbook's illustration."""
    types = set(_relations_from_json())
    assert {
        "account",
        "opportunity",
        "invoice",
        "note",
    } <= types, f"Model is missing Day 2 types. Has: {sorted(types)}"


# --- the model answers correctly -------------------------------------------


CHECKS = _load("fga-checks.json")["checks"]


@pytest.mark.parametrize(
    "check",
    CHECKS,
    ids=[f"{c['user'].removeprefix('user:')}-{c['relation']}-{c['object']}" for c in CHECKS],
)
def test_check_matrix(store, check):
    store_id, model_id = store
    r = httpx.post(
        f"{OPENFGA}/stores/{store_id}/check",
        json={
            "tuple_key": {
                "user": check["user"],
                "relation": check["relation"],
                "object": check["object"],
            },
            "authorization_model_id": model_id,
        },
        timeout=10,
    )
    r.raise_for_status()
    got = r.json().get("allowed", False)
    assert got == check["expect"], (
        f"{check['user']} {check['relation']} {check['object']} -> {got}, "
        f"expected {check['expect']}.\n{check['why']}"
    )


def test_the_matrix_actually_contains_denials():
    """Guards the guard. If someone 'fixes' a failing check by flipping its
    expectation, this catches the case where the matrix stops testing refusal."""
    denials = [c for c in CHECKS if c["expect"] is False]
    assert len(denials) >= 5, (
        f"Only {len(denials)} negative checks. The denials are what the product "
        f"is; do not let the matrix drift into only proving access."
    )


def test_read_access_does_not_confer_write_access(store):
    """The asymmetry, called out on its own because it is the single line that
    stops a read-only analyst delegating write authority (§7.1 maps
    action=='write' to relation 'editor').

    auditor@acme.test is a viewer on Northwind and never an owner, so they must
    read its children and never write them.
    """
    store_id, model_id = store

    def check(relation: str) -> bool:
        r = httpx.post(
            f"{OPENFGA}/stores/{store_id}/check",
            json={
                "tuple_key": {
                    "user": "user:auditor@acme.test",
                    "relation": relation,
                    "object": "opportunity:0065g00001NWD",
                },
                "authorization_model_id": model_id,
            },
            timeout=10,
        )
        r.raise_for_status()
        return r.json().get("allowed", False)

    assert check("viewer") is True, "viewer should inherit from the parent's viewer"
    assert check("editor") is False, (
        "A viewer on the parent account was granted editor on its child. "
        "`editor` must inherit from the parent's OWNER, not its viewer - "
        "otherwise read-only users can delegate write authority."
    )


def test_engine_can_explain_an_inheritance_path(store):
    """`make fga-explain` replaced the playground, and it works by asking the
    engine to expand a relation rather than by guessing at the reasoning.

    Appendix A asks new joiners to explain the inheritance path that produced
    an answer, so this asserts the path is actually retrievable: the
    opportunity has no direct viewer, and the engine points at the parent
    account instead.
    """
    store_id, model_id = store
    r = httpx.post(
        f"{OPENFGA}/stores/{store_id}/expand",
        json={
            "tuple_key": {"relation": "viewer", "object": "opportunity:0065g00001NWD"},
            "authorization_model_id": model_id,
        },
        timeout=10,
    )
    r.raise_for_status()
    nodes = r.json()["tree"]["root"]["union"]["nodes"]

    direct = [n for n in nodes if "users" in n.get("leaf", {})]
    assert direct, "Expand returned no direct-grant branch"
    assert not (direct[0]["leaf"]["users"].get("users") or []), (
        "Someone added a direct viewer tuple on the demo opportunity. The whole "
        "point of that record is that access to it is INHERITED - a direct grant "
        "makes the Appendix A explanation wrong and weakens the demo."
    )

    inherited = [n for n in nodes if "tupleToUserset" in n.get("leaf", {})]
    assert inherited, "Expand shows no inheritance branch - the model changed shape"
    t2u = inherited[0]["leaf"]["tupleToUserset"]
    assert t2u["tupleset"].endswith("#parent")
    assert any(
        cmp["userset"] == "account:0015g00001XYZ#viewer" for cmp in t2u["computed"]
    ), f"Inheritance does not point at the Northwind account: {t2u['computed']}"
