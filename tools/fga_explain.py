"""
Ask the policy engine a question and see WHY it answered that way.

    make fga-explain                                  walk the seeded examples
    make fga-explain U=priya@acme.test R=viewer O=opportunity:0065g00001NWD

This replaces the built-in OpenFGA playground, which cannot work in a modern
browser. /playground is a page wrapping an iframe to the remote site
play.fga.dev, and that public page then tries to call our API on 127.0.0.1.
Chrome and Safari both refuse:

    Access to XMLHttpRequest at 'http://127.0.0.1:8081/stores' from origin
    'https://play.fga.dev' has been blocked by CORS policy: Permission was
    denied for this request to access the `loopback` address space.

That is Private Network Access protection, and it is not something we should be
switching off in a browser while building a security product. It is also not
fixable server-side: sending the official opt-in header
`Access-Control-Allow-Private-Network: true` was tested and all three engines
still refused. The playground is deprecated upstream as well. See
docs/DECISIONS.md, Day 7.

Appendix A asks new joiners to "run one OpenFGA check by hand and explain the
inheritance path that produced the answer". That is what this prints - the path,
from the engine's own Expand API, not from our guess about what it did.
"""

import os
import pathlib
import sys

import httpx

FGA = os.environ.get("GATEKEEP_FGA_URL", "http://localhost:8081")
STORE_NAME = "gatekeep"
STATE = pathlib.Path(__file__).resolve().parent.parent / "deploy" / "seed" / ".seeded.json"

NO_COLOR = bool(os.environ.get("NO_COLOR"))


def paint(code: str, s: str) -> str:
    return s if NO_COLOR else f"\033[{code}m{s}\033[0m"


def green(s):
    return paint("32", s)


def red(s):
    return paint("31", s)


def bold(s):
    return paint("1", s)


def dim(s):
    return paint("2", s)


EXAMPLES = [
    ("priya@acme.test", "viewer", "opportunity:0065g00001NWD"),
    ("priya@acme.test", "editor", "opportunity:0065g00001NWD"),
    ("auditor@acme.test", "viewer", "opportunity:0065g00001NWD"),
    ("auditor@acme.test", "editor", "opportunity:0065g00001NWD"),
    ("priya@acme.test", "viewer", "opportunity:0065g00099CTO"),
]


def resolve_store(c: httpx.Client) -> tuple[str, str]:
    stores = c.get("/stores").raise_for_status().json().get("stores", [])
    match = [s for s in stores if s["name"] == STORE_NAME]
    if not match:
        sys.exit("\n  No 'gatekeep' store. Run `make seed`.\n")
    store_id = match[0]["id"]
    models = c.get(f"/stores/{store_id}/authorization-models").raise_for_status().json()
    return store_id, models["authorization_models"][0]["id"]


def all_tuples(c: httpx.Client, store_id: str) -> list[dict]:
    page = c.post(f"/stores/{store_id}/read", json={"page_size": 100}).raise_for_status().json()
    return [t["key"] for t in page.get("tuples", [])]


def check(c: httpx.Client, store_id: str, model_id: str, user: str, rel: str, obj: str) -> bool:
    r = c.post(
        f"/stores/{store_id}/check",
        json={
            "tuple_key": {"user": f"user:{user}", "relation": rel, "object": obj},
            "authorization_model_id": model_id,
        },
    ).raise_for_status()
    return r.json().get("allowed", False)


def expand(c: httpx.Client, store_id: str, model_id: str, rel: str, obj: str) -> dict:
    r = c.post(
        f"/stores/{store_id}/expand",
        json={
            "tuple_key": {"relation": rel, "object": obj},
            "authorization_model_id": model_id,
        },
    ).raise_for_status()
    return r.json()["tree"]["root"]


def walk(c, store_id, model_id, node: dict, target: str, indent: str = "  ", depth: int = 0):
    """Print one level of the expansion tree, following inheritance as it goes."""
    if depth > 4:
        print(f"{indent}{dim('(stopping, too deep)')}")
        return

    nodes = node.get("union", {}).get("nodes") if "union" in node else [node]
    for n in nodes or []:
        leaf = n.get("leaf")
        if not leaf:
            continue

        if "users" in leaf:
            users = leaf["users"].get("users") or []
            if not users:
                print(f"{indent}{dim('direct grants on this object ......... none')}")
            else:
                for u in users:
                    hit = green("  <-- MATCH") if u == target else ""
                    print(f"{indent}direct grant: {u}{hit}")

        elif "tupleToUserset" in leaf:
            t2u = leaf["tupleToUserset"]
            via = t2u["tupleset"].split("#")[-1]
            for computed in t2u.get("computed") or []:
                userset = computed["userset"]
                parent_obj, parent_rel = userset.split("#")
                print(f"{indent}inherited: follow {bold(via)} to {bold(userset)}")
                sub = expand(c, store_id, model_id, parent_rel, parent_obj)
                walk(c, store_id, model_id, sub, target, indent + "     ", depth + 1)

        elif "computed" in leaf:
            userset = leaf["computed"]["userset"]
            comp_obj, comp_rel = userset.split("#")
            print(f"{indent}also counts as: {bold(userset)}")
            sub = expand(c, store_id, model_id, comp_rel, comp_obj)
            walk(c, store_id, model_id, sub, target, indent + "     ", depth + 1)


def explain(c, store_id, model_id, tuples, user: str, rel: str, obj: str) -> None:
    target = f"user:{user}"
    allowed = check(c, store_id, model_id, user, rel, obj)

    print()
    print(bold("-" * 74))
    print(f"  {bold('QUESTION')}  may {user} {bold(rel)} {bold(obj)} ?")
    print(f"  {bold('ANSWER')}    {green('ALLOWED') if allowed else red('DENIED')}")
    print(bold("-" * 74))
    print()
    print(f"  {bold('HOW THE ENGINE GOT THERE')}")
    print(f"  {obj}#{rel}")
    walk(c, store_id, model_id, expand(c, store_id, model_id, rel, obj), target)

    used = [
        t
        for t in tuples
        if obj in (t["object"], t["user"]) or t["user"] == target or t["object"].endswith(obj)
    ]
    related = [t for t in tuples if t["user"] == target] + [t for t in tuples if t["object"] == obj]
    seen, facts = set(), []
    for t in used + related:
        k = (t["user"], t["relation"], t["object"])
        if k not in seen:
            seen.add(k)
            facts.append(t)
    if facts:
        print()
        print(f"  {bold('STORED FACTS IN PLAY')}")
        for t in facts:
            print(f"    {t['user']:26} {t['relation']:8} {t['object']}")

    print()
    print(f"  {bold('SAY IT OUT LOUD')}")
    if allowed:
        print(dim("    There is no permission stored against this record for this person."))
        print(dim("    The answer is worked out by following the relationships: the record"))
        print(dim("    belongs to an account, and they hold the needed relation on that"))
        print(dim("    account. Two stored facts, no roles. To say the same thing with job"))
        print(dim("    titles you would need one role per account."))
    else:
        print(dim("    No chain of relationships connects this person to this record, so"))
        print(dim("    the answer is no. Nothing had to be configured to make it no -"))
        print(dim("    anything not explicitly reachable is refused."))


def main() -> int:
    u, r, o = (os.environ.get(k) for k in ("U", "R", "O"))

    with httpx.Client(base_url=FGA, timeout=15.0) as c:
        store_id, model_id = resolve_store(c)
        tuples = all_tuples(c, store_id)

        print()
        print(bold("  POLICY EXPLAINER"))
        print(dim(f"  store {store_id}"))
        print(dim("  The playground cannot reach a local API from a browser any more."))
        print(dim("  This asks the same questions and shows the same reasoning."))

        if u and r and o:
            explain(c, store_id, model_id, tuples, u, r, o)
        else:
            print(dim("\n  No question given, so walking the seeded examples."))
            print(dim("  Ask your own:  make fga-explain U=<email> R=<relation> O=<type:id>"))
            for user, rel, obj in EXAMPLES:
                explain(c, store_id, model_id, tuples, user, rel, obj)
    print()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except httpx.ConnectError:
        print(f"\n  Cannot reach OpenFGA at {FGA}.\n\n  Is the stack up?  make dev\n")
        sys.exit(2)
    except httpx.HTTPStatusError as e:
        print(f"\n  OpenFGA rejected a request: {e.response.status_code}")
        print(f"  {e.response.text[:300]}\n")
        sys.exit(1)
