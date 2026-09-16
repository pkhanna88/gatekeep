"""
OpenFGA client: the Policy Decision Point (section 2.8).

One question only - `check` - because section 3.4 warns ListObjects is too
expensive for the request path. Any failure to get a clear answer raises, and
every caller treats a raise as a denial. There is no code path where an
unreachable OpenFGA turns into `allowed=True` (section 4.5: OpenFGA down means
deny everything).
"""

from __future__ import annotations

import json

import httpx

from app import settings


class PolicyUnavailable(RuntimeError):
    pass


class FGA:
    def __init__(self, client: httpx.AsyncClient | None = None):
        self._client = client or httpx.AsyncClient(base_url=settings.FGA_URL, timeout=5.0)
        self._store_id: str | None = None
        self._model_id: str | None = None

    async def _resolve(self) -> tuple[str, str]:
        if self._store_id and self._model_id:
            return self._store_id, self._model_id
        # Prefer what `make seed` recorded; fall back to looking the store up by name.
        if settings.FGA_SEED_STATE.exists():
            state = json.loads(settings.FGA_SEED_STATE.read_text())
            store_id, model_id = state["store_id"], state["model_id"]
            r = await self._client.get(f"/stores/{store_id}")
            if r.status_code == 200:
                self._store_id, self._model_id = store_id, model_id
                return store_id, model_id
        r = await self._client.get("/stores")
        r.raise_for_status()
        store = next((s for s in r.json()["stores"] if s["name"] == settings.FGA_STORE_NAME), None)
        if store is None:
            raise PolicyUnavailable("OpenFGA store 'gatekeep' not found. Run `make seed`.")
        r = await self._client.get(f"/stores/{store['id']}/authorization-models")
        r.raise_for_status()
        models = r.json()["authorization_models"]
        if not models:
            raise PolicyUnavailable("OpenFGA store has no model. Run `make seed`.")
        self._store_id, self._model_id = store["id"], models[0]["id"]
        return self._store_id, self._model_id

    async def check(self, user: str, relation: str, obj: str) -> bool:
        try:
            store_id, model_id = await self._resolve()
            r = await self._client.post(
                f"/stores/{store_id}/check",
                json={
                    "tuple_key": {"user": user, "relation": relation, "object": obj},
                    "authorization_model_id": model_id,
                },
            )
        except httpx.HTTPError as e:
            raise PolicyUnavailable(f"OpenFGA unreachable: {e}") from e
        if r.status_code != 200:
            # A store id from a previous OpenFGA process (memory engine) - forget
            # it so the next call re-resolves, and deny this one.
            self._store_id = self._model_id = None
            raise PolicyUnavailable(f"OpenFGA check failed: HTTP {r.status_code} {r.text[:200]}")
        return r.json().get("allowed") is True

    async def aclose(self) -> None:
        await self._client.aclose()
