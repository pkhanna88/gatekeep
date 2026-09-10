"""
Day 3 (INF): load the policy model, seed the tuples, verify the answers.
Day 6 (INF): make sure a signing key exists in OpenBao transit.

    make seed

This is what `make seed` used to claim it did. It previously ran
exercises/fga_check.py, which builds a throwaway store with a two-type model -
useful as an onboarding exercise, not a seeded environment. Nothing in the repo
loaded the four-type Day 2 model, and nothing created a signing key.

Design rules for this file:

  Idempotent. Run it as many times as you like. It finds the store by name
  rather than creating a new one each run, and it clears tuples before writing
  so a re-run converges rather than accumulating.

  It verifies. Loading a model proves nothing; the model has to answer
  correctly, including saying no. deploy/seed/fga-checks.json is the acceptance
  matrix and this script exits non-zero if any row disagrees. That is Day 3's
  "relationship queries verified by hand in the playground", written down so it
  runs in CI instead of living in someone's memory.

  It never fails quietly. A seed step that half-works produces a demo that
  half-works, an hour before the demo.
"""

import json
import os
import pathlib
import sys

import httpx

FGA = os.environ.get("GATEKEEP_FGA_URL", "http://localhost:8081")
BAO = os.environ.get("GATEKEEP_BAO_URL", "http://localhost:8200")
BAO_TOKEN = os.environ.get("GATEKEEP_BAO_TOKEN", "root")

STORE_NAME = "gatekeep"
SIGNING_KEY = "gk-signing"

# exercises/fga_check.py creates one of these every time a new joiner runs it,
# and the memory engine means they are pure litter. Safe to remove: the
# exercise is disposable by design and rebuilds its own store on next run.
DISPOSABLE_STORE_NAME = "gatekeep-day0"

HERE = pathlib.Path(__file__).resolve().parent
STATE_FILE = HERE / ".seeded.json"


def load_json(name: str) -> dict:
    """Read a seed data file, dropping the `_comment` keys used to document it.

    The API rejects unknown fields, but a bare wall of relation JSON is
    unreadable six weeks later, so the files carry their own explanation and we
    strip it here.
    """
    raw = json.loads((HERE / name).read_text())
    return {k: v for k, v in raw.items() if not k.startswith("_")}


def find_or_create_store(c: httpx.Client) -> str:
    stores = c.get("/stores").raise_for_status().json().get("stores", [])

    disposable = [s for s in stores if s["name"] == DISPOSABLE_STORE_NAME]
    for s in disposable:
        c.delete(f"/stores/{s['id']}")
    if disposable:
        print(f"pruned      {len(disposable)} disposable exercise store(s)")

    for s in stores:
        if s["name"] == STORE_NAME:
            print(f"store       {s['id']}  (reused)")
            return s["id"]

    store_id = c.post("/stores", json={"name": STORE_NAME}).raise_for_status().json()["id"]
    print(f"store       {store_id}  (created)")
    return store_id


def write_model(c: httpx.Client, store_id: str) -> str:
    model = load_json("fga-model.json")
    r = c.post(f"/stores/{store_id}/authorization-models", json=model)
    if r.status_code != 201 and r.status_code != 200:
        sys.exit(
            f"\n  OpenFGA rejected the authorization model (HTTP {r.status_code}).\n"
            f"  {r.text[:400]}\n\n"
            f"  deploy/seed/fga-model.json is the machine-readable copy of\n"
            f"  policy/fga-model.fga. If you edited the .fga DSL, edit this too -\n"
            f"  tests/test_policy_model.py checks that they still agree.\n"
        )
    model_id = r.json()["authorization_model_id"]
    types = [t["type"] for t in model["type_definitions"]]
    print(f"model       {model_id}")
    print(f"types       {', '.join(types)}")
    return model_id


def reset_tuples(c: httpx.Client, store_id: str) -> int:
    """Clear then write, so a re-run converges instead of erroring on duplicates."""
    # An empty body reads every tuple. Passing `tuple_key: {}` explicitly is a
    # validation error - OpenFGA requires an object type once the field is present.
    old: list[dict] = []
    body: dict = {"page_size": 100}
    while True:
        page = c.post(f"/stores/{store_id}/read", json=body).raise_for_status().json()
        old.extend(t["key"] for t in page.get("tuples", []))
        token = page.get("continuation_token") or ""
        if not token:
            break
        body = {"page_size": 100, "continuation_token": token}

    if old:
        c.post(
            f"/stores/{store_id}/write",
            json={"deletes": {"tuple_keys": old}},
        ).raise_for_status()

    tuples = load_json("fga-tuples.json")["tuples"]
    c.post(
        f"/stores/{store_id}/write",
        json={"writes": {"tuple_keys": tuples}},
    ).raise_for_status()

    cleared = f", {len(old)} cleared first" if old else ""
    print(f"tuples      {len(tuples)} written{cleared}")
    return len(tuples)


def run_checks(c: httpx.Client, store_id: str, model_id: str) -> int:
    """Run the acceptance matrix. Returns the number of wrong answers."""
    checks = load_json("fga-checks.json")["checks"]
    print(f"\nverifying   {len(checks)} checks against the seeded model\n")

    failures = 0
    for chk in checks:
        r = c.post(
            f"/stores/{store_id}/check",
            json={
                "tuple_key": {
                    "user": chk["user"],
                    "relation": chk["relation"],
                    "object": chk["object"],
                },
                "authorization_model_id": model_id,
            },
        )
        r.raise_for_status()
        got = r.json().get("allowed", False)
        ok = got == chk["expect"]
        failures += 0 if ok else 1
        mark = "ok  " if ok else "FAIL"
        user = chk["user"].removeprefix("user:")
        print(f"  {mark} {user:22} {chk['relation']:7} {chk['object']:28} -> {str(got):5}")
        if not ok:
            print(f"       expected {chk['expect']}. {chk['why']}")

    return failures


def ensure_transit() -> None:
    """Mount the transit engine and create the token-signing key.

    Section 3.5: the private key that signs agent tokens is the most sensitive
    material in the system, and the token service must never hold it. Transit
    signs on our behalf and does not release the key - `make verify-signing`
    proves that by trying to export it and being refused.

    BE2 needs this on Day 6. Standing it up now means Day 6 starts with a key
    that exists rather than a bare OpenBao.
    """
    h = {"X-Vault-Token": BAO_TOKEN}
    with httpx.Client(base_url=BAO, headers=h, timeout=10.0) as c:
        mounts = c.get("/v1/sys/mounts").raise_for_status().json()
        mounted = "transit/" in (mounts.get("data") or mounts)
        if not mounted:
            r = c.post("/v1/sys/mounts/transit", json={"type": "transit"})
            if r.status_code not in (200, 204):
                sys.exit(f"\n  Could not mount OpenBao transit: {r.status_code} {r.text[:200]}\n")
            print("transit     mounted")
        else:
            print("transit     already mounted")

        r = c.get(f"/v1/transit/keys/{SIGNING_KEY}")
        if r.status_code == 404:
            c.post(
                f"/v1/transit/keys/{SIGNING_KEY}",
                json={"type": "rsa-2048"},
            ).raise_for_status()
            r = c.get(f"/v1/transit/keys/{SIGNING_KEY}").raise_for_status()
            created = True
        else:
            r.raise_for_status()
            created = False

        d = r.json()["data"]
        versions = sorted(d["keys"], key=int)
        state = "created" if created else "exists"
        print(f"signing key {SIGNING_KEY}  ({d['type']}, {state})")
        print(f"key versions {', '.join(versions)}  -> kid {SIGNING_KEY}-v{d['latest_version']}")
        if d["exportable"]:
            sys.exit(
                f"\n  {SIGNING_KEY} is marked exportable, which defeats the point of\n"
                f"  using transit at all. Recreate it without exportable=true.\n"
            )


def main() -> int:
    print(f"OpenFGA     {FGA}")
    print(f"OpenBao     {BAO}\n")

    with httpx.Client(base_url=FGA, timeout=15.0) as c:
        store_id = find_or_create_store(c)
        model_id = write_model(c, store_id)
        reset_tuples(c, store_id)
        failures = run_checks(c, store_id, model_id)

    print()
    ensure_transit()

    STATE_FILE.write_text(
        json.dumps({"store_id": store_id, "model_id": model_id, "store_name": STORE_NAME}, indent=2)
        + "\n"
    )

    if failures:
        print(
            f"\n  {failures} check(s) disagreed with deploy/seed/fga-checks.json.\n"
            f"  The environment is NOT correctly seeded. Do not demo from it.\n"
        )
        return 1

    print(f"\nSeeded. Store id written to {STATE_FILE.relative_to(HERE.parent.parent)}")
    print("Every policy check answered as expected, including the denials.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except httpx.ConnectError as e:
        print(f"\n  Cannot reach a dependency: {e}\n\n  Is the stack up?  make dev\n")
        sys.exit(2)
