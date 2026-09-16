"""
Every address and name the services agree on, in one place.

Defaults match docker-compose.yml and the `localhost everywhere` decision in
docs/DECISIONS.md. Override with environment variables; never by editing one
service's copy of a hostname (README, "Two things to know").
"""

import os
import pathlib

REPO = pathlib.Path(__file__).resolve().parents[3]


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


# Services connect as gatekeep_app, which cannot UPDATE or DELETE audit rows.
APP_DSN = _env("GATEKEEP_APP_DSN", "postgres://gatekeep_app:gatekeep_app@localhost:5432/gatekeep")
REDIS_URL = _env("GATEKEEP_REDIS_URL", "redis://localhost:6379/0")

FGA_URL = _env("GATEKEEP_FGA_URL", "http://localhost:8081")
FGA_STORE_NAME = "gatekeep"
FGA_SEED_STATE = REPO / "deploy" / "seed" / ".seeded.json"

BAO_URL = _env("GATEKEEP_BAO_URL", "http://localhost:8200")
BAO_TOKEN = _env("GATEKEEP_BAO_TOKEN", "root")
SIGNING_KEY = "gk-signing"

# Human identity (Keycloak). Issuer must match byte for byte - section 3.3.
KEYCLOAK_ISSUER = _env("GATEKEEP_KEYCLOAK_ISSUER", "http://localhost:8080/realms/gatekeep")
KEYCLOAK_JWKS = f"{KEYCLOAK_ISSUER}/protocol/openid-connect/certs"
HUMAN_AUDIENCE = "gatekeep-control-plane"

# Agent tokens (ours).
CONTROL_PLANE_URL = _env("GATEKEEP_CONTROL_PLANE_URL", "http://localhost:8000")
TOKEN_SERVICE_URL = _env("GATEKEEP_TOKEN_SERVICE_URL", "http://localhost:8001")
PEP_URL = _env("GATEKEEP_PEP_URL", "http://localhost:8002")
AGENT_TOKEN_ISSUER = _env("GATEKEEP_AGENT_TOKEN_ISSUER", TOKEN_SERVICE_URL)
AGENT_TOKEN_AUDIENCE = "gatekeep-pep"
AGENT_TOKEN_TTL_SECONDS = 300

# Section 3.3: allow 30 seconds of clock skew when verifying.
CLOCK_LEEWAY_SECONDS = 30

# The mock Salesforce (connector one - docs/CONNECTOR-NOTES.md). Only the PEP
# holds this credential; an agent calling the mock directly is refused.
MOCK_SALESFORCE_URL = _env("GATEKEEP_MOCK_SALESFORCE_URL", "http://localhost:8003")
MOCK_SALESFORCE_SECRET = _env(
    "GATEKEEP_MOCK_SALESFORCE_SECRET", "dev-connector-secret-not-for-production"
)
