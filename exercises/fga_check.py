"""
Appendix A comprehension item 2:
  "Run one OpenFGA check by hand and explain the inheritance path that
   produced the answer."

Creates a store, writes the model and the §3.4 tuples, then runs the check
that §7.1 (Invariant 1) and §7.2 step 5 both make.

    pip install httpx
    python exercises/fga_check.py

Requires only `docker compose up -d openfga`.
"""

import sys

import httpx

FGA = "http://localhost:8081"

# The §3.4 model, expressed as JSON. (The .fga DSL needs the `fga` CLI to
# transpile; this is the same model in the form the HTTP API accepts.)
MODEL = {
    "schema_version": "1.1",
    "type_definitions": [
        {"type": "user"},
        {
            "type": "account",
            "relations": {
                "owner": {"this": {}},
                "viewer": {
                    "union": {
                        "child": [
                            {"this": {}},
                            {"computedUserset": {"relation": "owner"}},
                        ]
                    }
                },
            },
            "metadata": {
                "relations": {
                    "owner": {"directly_related_user_types": [{"type": "user"}]},
                    "viewer": {"directly_related_user_types": [{"type": "user"}]},
                }
            },
        },
        {
            "type": "opportunity",
            "relations": {
                "parent": {"this": {}},
                "viewer": {
                    "union": {
                        "child": [
                            {"this": {}},
                            {
                                "tupleToUserset": {
                                    "tupleset": {"relation": "parent"},
                                    "computedUserset": {"relation": "viewer"},
                                }
                            },
                        ]
                    }
                },
                "editor": {
                    "union": {
                        "child": [
                            {"this": {}},
                            {
                                "tupleToUserset": {
                                    "tupleset": {"relation": "parent"},
                                    "computedUserset": {"relation": "owner"},
                                }
                            },
                        ]
                    }
                },
            },
            "metadata": {
                "relations": {
                    "parent": {"directly_related_user_types": [{"type": "account"}]},
                    "viewer": {"directly_related_user_types": [{"type": "user"}]},
                    "editor": {"directly_related_user_types": [{"type": "user"}]},
                }
            },
        },
    ],
}

TUPLES = [
    {"user": "user:priya@acme.com", "relation": "owner", "object": "account:northwind"},
    {"user": "account:northwind", "relation": "parent", "object": "opportunity:0065g"},
]


def main() -> int:
    with httpx.Client(base_url=FGA, timeout=10.0) as c:
        store = c.post("/stores", json={"name": "gatekeep-day0"}).json()
        store_id = store["id"]
        print(f"store       {store_id}")

        model = c.post(f"/stores/{store_id}/authorization-models", json=MODEL).json()
        print(f"model       {model['authorization_model_id']}")

        c.post(
            f"/stores/{store_id}/write",
            json={"writes": {"tuple_keys": TUPLES}},
        ).raise_for_status()
        print(f"tuples      {len(TUPLES)} written\n")

        checks = [
            # The one that matters. Priya has NO direct tuple on this
            # opportunity — the True comes entirely from inheritance.
            ("user:priya@acme.com", "viewer", "opportunity:0065g", True),
            # Write authority: also inherited, but via `owner from parent`.
            ("user:priya@acme.com", "editor", "opportunity:0065g", True),
            # A different account's opportunity — no path, so no access.
            ("user:priya@acme.com", "viewer", "opportunity:0099x", False),
            # Someone with no tuples at all.
            ("user:ravi@acme.com", "viewer", "opportunity:0065g", False),
        ]

        failures = 0
        for user, relation, obj, expected in checks:
            r = c.post(
                f"/stores/{store_id}/check",
                json={"tuple_key": {"user": user, "relation": relation, "object": obj}},
            ).json()
            got = r.get("allowed", False)
            ok = "ok " if got == expected else "FAIL"
            if got != expected:
                failures += 1
            print(f"{ok}  {user:24} {relation:7} {obj:22} -> {got}")

        print(
            "\nThe inheritance path for check 1, in the words you should be able\n"
            "to say out loud:\n"
            "  opportunity:0065g has no direct viewer tuple for Priya, so OpenFGA\n"
            "  falls to `viewer from parent`. The parent tuple points at\n"
            "  account:northwind. account.viewer is `[user] or owner`, and Priya\n"
            "  has an owner tuple on that account. Two hops, zero roles.\n"
            "  RBAC would have needed a role per account to say the same thing."
        )
        return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except httpx.ConnectError:
        print(f"Cannot reach OpenFGA at {FGA} — is `docker compose up -d` running?")
        sys.exit(2)
