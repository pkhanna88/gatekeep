-- 0002 — agents, grants and agent sessions, section 5.1.
--
-- Same raw-SQL runner as 0001 (see docs/DECISIONS.md). Idempotent.
--
-- One deviation from section 5.1: agents carry `bootstrap_key_id`. The bootstrap
-- credential is `gkb.<key_id>.<secret>` and only an argon2id hash of the whole
-- thing is stored. argon2 is salted, so a hash cannot be looked up by value -
-- the token service needs a public, non-secret handle to find which row to
-- verify against. The key id is that handle. It proves nothing on its own.

CREATE TABLE IF NOT EXISTS agents (
  id                TEXT PRIMARY KEY,                 -- agent://acme/invoice-reconciler
  display_name      TEXT NOT NULL,
  owner_email       TEXT NOT NULL,
  bootstrap_key_id  TEXT NOT NULL UNIQUE,             -- public lookup handle
  bootstrap_hash    TEXT NOT NULL,                    -- argon2id, never the raw credential
  status            TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'suspended')),
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS grants (
  id              TEXT PRIMARY KEY,                   -- gr_01HQ3K8W7X...
  principal_sub   TEXT NOT NULL,                      -- the human (the `principal` claim)
  agent_id        TEXT NOT NULL REFERENCES agents(id),
  purpose         TEXT NOT NULL,
  scopes          JSONB NOT NULL,
  constraints     JSONB NOT NULL DEFAULT '{}',
  status          TEXT NOT NULL
                  CHECK (status IN ('pending', 'active', 'rejected', 'revoked', 'expired')),
  approved_at     TIMESTAMPTZ,
  approved_by     TEXT,
  expires_at      TIMESTAMPTZ NOT NULL,
  revoked_at      TIMESTAMPTZ,
  revoked_by      TEXT,
  revoke_reason   TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS grants_status_expires_idx    ON grants (status, expires_at);
CREATE INDEX IF NOT EXISTS grants_principal_created_idx ON grants (principal_sub, created_at DESC);

CREATE TABLE IF NOT EXISTS agent_sessions (
  id          TEXT PRIMARY KEY,                       -- run-01HQ3K9Z2P...
  grant_id    TEXT NOT NULL REFERENCES grants(id),
  agent_id    TEXT NOT NULL REFERENCES agents(id),
  started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  ended_at    TIMESTAMPTZ,
  status      TEXT NOT NULL
              CHECK (status IN ('running', 'completed', 'killed', 'failed'))
);
CREATE INDEX IF NOT EXISTS agent_sessions_status_started_idx ON agent_sessions (status, started_at DESC);

-- Services connect as gatekeep_app (created in 0001). These tables are ordinary
-- state, so the app may update them - but never delete. A revoked grant is a
-- fact the audit trail refers to; it stays.
GRANT SELECT, INSERT, UPDATE ON agents, grants, agent_sessions TO gatekeep_app;
REVOKE DELETE ON agents, grants, agent_sessions FROM gatekeep_app;
