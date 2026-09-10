-- 0001 — the audit chain table, section 5.1.
--
-- [INF stand-in.] BE1 owns migrations and wires alembic into `make migrate` on
-- Day 1. This is raw SQL because Day 4's audit chain cannot be written, run or
-- tested against a table that does not exist, and Day 1 has not happened. When
-- alembic lands, fold this in as the initial revision and delete this file.
--
-- Idempotent on purpose: `make migrate` is in the Appendix A checklist and new
-- joiners run it more than once.

CREATE TABLE IF NOT EXISTS audit_events (
  seq             BIGSERIAL PRIMARY KEY,
  ts              TIMESTAMPTZ NOT NULL DEFAULT now(),
  event_type      TEXT NOT NULL,
  principal_sub   TEXT,
  agent_id        TEXT,
  session_id      TEXT,
  grant_id        TEXT,
  resource        TEXT,
  action          TEXT,
  decision        TEXT,                    -- allow | deny
  reason          TEXT,
  payload_digest  TEXT,                    -- SHA-256 of body — NEVER the body
  prev_hash       TEXT NOT NULL,
  entry_hash      TEXT NOT NULL
);

-- The three queries the console makes (section 3.6).
CREATE INDEX IF NOT EXISTS audit_events_ts_idx            ON audit_events (ts DESC);
CREATE INDEX IF NOT EXISTS audit_events_session_idx       ON audit_events (session_id);
CREATE INDEX IF NOT EXISTS audit_events_principal_ts_idx  ON audit_events (principal_sub, ts DESC);

-- Append-only, enforced at the database level rather than in application code.
--
-- Section 5.1 says to REVOKE UPDATE and DELETE from gatekeep_app. That role did
-- not exist: docker-compose.yml creates one superuser, `gatekeep`, and services
-- were going to connect as it. Revoking from a superuser accomplishes nothing -
-- superusers bypass permission checks entirely, and a table's owner keeps its
-- rights regardless. So the REVOKE as written would have been decoration.
--
-- The role is created here so the guarantee is real. Services connect as
-- gatekeep_app; only migrations connect as gatekeep.
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'gatekeep_app') THEN
    CREATE ROLE gatekeep_app LOGIN PASSWORD 'gatekeep_app';
  END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO gatekeep_app;
GRANT SELECT, INSERT ON audit_events TO gatekeep_app;
-- append() calls nextval() explicitly, because seq is inside the hash.
GRANT USAGE, SELECT ON SEQUENCE audit_events_seq_seq TO gatekeep_app;

REVOKE UPDATE, DELETE ON audit_events FROM gatekeep_app;
