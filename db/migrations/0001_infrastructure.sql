-- 0001_infrastructure.sql
-- Extensions, shared domains, generic triggers and the append-only machinery
-- that later migrations depend on.

CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS btree_gist;

-- ---------------------------------------------------------------------------
-- Shared domains
--
-- A DOMAIN is used rather than a bare type so that the rule lives with the data
-- and cannot be forgotten by a new table. currency_code and money_minor are the
-- database-side half of the "integer minor units, currency always attached"
-- rule that internal/platform/money enforces in Go.
-- ---------------------------------------------------------------------------

CREATE DOMAIN currency_code AS CHAR(3)
  CHECK (VALUE ~ '^[A-Z]{3}$');

-- Amounts are signed: the ledger needs negative postings. Range is bounded well
-- inside int64 so that a summation over a realistic number of rows cannot
-- overflow BIGINT inside Postgres either.
CREATE DOMAIN money_minor AS BIGINT
  CHECK (VALUE BETWEEN -9000000000000000 AND 9000000000000000);

CREATE DOMAIN basis_points AS INTEGER
  CHECK (VALUE BETWEEN 0 AND 1000000);

CREATE DOMAIN public_id AS TEXT
  CHECK (VALUE ~ '^[a-z]{3,4}_[0-9A-Z]{26}$');

CREATE DOMAIN email_blind_index AS BYTEA
  CHECK (octet_length(VALUE) = 32);

CREATE DOMAIN sha256_digest AS BYTEA
  CHECK (octet_length(VALUE) = 32);

-- ---------------------------------------------------------------------------
-- Generic triggers
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION set_updated_at() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

-- forbid_mutation makes a table append-only at the database level. Application
-- bugs, a compromised application account and an operator with a psql prompt
-- are all stopped by the same rule. Only a superuser disabling the trigger can
-- bypass it, and that is an auditable action on the database host.
CREATE OR REPLACE FUNCTION forbid_mutation() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION
    'table % is append-only: % is not permitted', TG_TABLE_NAME, TG_OP
    USING ERRCODE = 'P0001',
          HINT = 'Record a compensating entry instead of altering history.';
END;
$$;

-- forbid_update_of_columns freezes named columns while allowing the rest of the
-- row to change. Used where a row has a mutable status but an immutable
-- financial or identity core.
CREATE OR REPLACE FUNCTION forbid_update_of_columns() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
DECLARE
  col  TEXT;
  oldv TEXT;
  newv TEXT;
BEGIN
  FOREACH col IN ARRAY TG_ARGV LOOP
    EXECUTE format('SELECT ($1).%I::text, ($2).%I::text', col, col)
      INTO oldv, newv USING OLD, NEW;
    IF oldv IS DISTINCT FROM newv THEN
      RAISE EXCEPTION 'column %.% is immutable once written', TG_TABLE_NAME, col
        USING ERRCODE = 'P0001';
    END IF;
  END LOOP;
  RETURN NEW;
END;
$$;

-- ---------------------------------------------------------------------------
-- Schema migrations
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS schema_migrations (
  version      TEXT PRIMARY KEY,
  checksum     sha256_digest NOT NULL,
  applied_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  duration_ms  INTEGER NOT NULL
);

COMMENT ON TABLE schema_migrations IS
  'Applied migrations with a content checksum: editing an already-applied migration is detected at boot and refuses to start.';

-- ---------------------------------------------------------------------------
-- Hash-chained audit log
--
-- Each row carries the digest of the previous row, so removing or editing any
-- historical entry breaks the chain and is detectable by a verifier that walks
-- the table. This is tamper-evidence, not tamper-proofing: it makes silent
-- alteration impossible without also rewriting every subsequent row.
-- ---------------------------------------------------------------------------

CREATE TABLE audit_log (
  seq           BIGSERIAL PRIMARY KEY,
  occurred_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor_kind    TEXT NOT NULL CHECK (actor_kind IN ('user','seller','admin','system','provider','anonymous')),
  actor_id      UUID,
  actor_ip      INET,
  action        TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 80),
  subject_type  TEXT NOT NULL CHECK (length(subject_type) BETWEEN 1 AND 60),
  subject_id    TEXT,
  request_id    TEXT CHECK (request_id IS NULL OR length(request_id) <= 64),
  -- Payloads are already PII-scrubbed by the application; the column exists so
  -- an investigation can see what changed, not who it belonged to.
  metadata      JSONB NOT NULL DEFAULT '{}'::jsonb,
  prev_hash     sha256_digest,
  entry_hash    sha256_digest NOT NULL
);

CREATE INDEX audit_log_subject_idx   ON audit_log (subject_type, subject_id, seq DESC);
CREATE INDEX audit_log_actor_idx     ON audit_log (actor_id, seq DESC) WHERE actor_id IS NOT NULL;
CREATE INDEX audit_log_occurred_idx  ON audit_log (occurred_at DESC);
CREATE INDEX audit_log_action_idx    ON audit_log (action, seq DESC);

CREATE OR REPLACE FUNCTION audit_log_chain() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
DECLARE
  prev sha256_digest;
BEGIN
  SELECT entry_hash INTO prev FROM audit_log ORDER BY seq DESC LIMIT 1;
  NEW.prev_hash := prev;
  NEW.entry_hash := digest(
      coalesce(encode(prev, 'hex'), '')
      || '|' || NEW.occurred_at::text
      || '|' || NEW.actor_kind
      || '|' || coalesce(NEW.actor_id::text, '')
      || '|' || NEW.action
      || '|' || NEW.subject_type
      || '|' || coalesce(NEW.subject_id, '')
      || '|' || coalesce(NEW.request_id, '')
      || '|' || NEW.metadata::text,
      'sha256');
  RETURN NEW;
END;
$$;

CREATE TRIGGER audit_log_chain_before_insert
  BEFORE INSERT ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_chain();

CREATE TRIGGER audit_log_append_only
  BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

-- verify_audit_chain walks the log and returns the first sequence number whose
-- stored hash does not match a recomputation. NULL means the chain is intact.
CREATE OR REPLACE FUNCTION verify_audit_chain(from_seq BIGINT DEFAULT 0)
RETURNS TABLE (broken_at BIGINT, reason TEXT)
LANGUAGE plpgsql AS $$
DECLARE
  r        RECORD;
  expected sha256_digest;
  prev     sha256_digest;
  started  BOOLEAN := FALSE;
BEGIN
  FOR r IN SELECT * FROM audit_log WHERE seq > from_seq ORDER BY seq LOOP
    IF NOT started THEN
      SELECT entry_hash INTO prev FROM audit_log WHERE seq < r.seq ORDER BY seq DESC LIMIT 1;
      started := TRUE;
    END IF;
    IF r.prev_hash IS DISTINCT FROM prev THEN
      broken_at := r.seq; reason := 'prev_hash does not match the preceding row';
      RETURN NEXT; RETURN;
    END IF;
    expected := digest(
        coalesce(encode(prev, 'hex'), '')
        || '|' || r.occurred_at::text
        || '|' || r.actor_kind
        || '|' || coalesce(r.actor_id::text, '')
        || '|' || r.action
        || '|' || r.subject_type
        || '|' || coalesce(r.subject_id, '')
        || '|' || coalesce(r.request_id, '')
        || '|' || r.metadata::text,
        'sha256');
    IF expected IS DISTINCT FROM r.entry_hash THEN
      broken_at := r.seq; reason := 'entry_hash does not match a recomputation of the row';
      RETURN NEXT; RETURN;
    END IF;
    prev := r.entry_hash;
  END LOOP;
  RETURN;
END;
$$;

COMMENT ON FUNCTION verify_audit_chain IS
  'Returns the first tampered sequence number, or no rows when the chain verifies.';

-- ---------------------------------------------------------------------------
-- Transactional outbox
--
-- The dual-write problem is solved by writing domain state and the intent to
-- publish inside the same transaction. The dispatcher then moves messages out
-- at least once; every consumer is idempotent.
-- ---------------------------------------------------------------------------

CREATE TABLE outbox_messages (
  id             UUID PRIMARY KEY,
  topic          TEXT NOT NULL CHECK (length(topic) BETWEEN 1 AND 80),
  aggregate_type TEXT NOT NULL CHECK (length(aggregate_type) BETWEEN 1 AND 60),
  aggregate_id   TEXT NOT NULL,
  payload        JSONB NOT NULL,
  headers        JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  available_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  locked_at      TIMESTAMPTZ,
  locked_by      TEXT,
  attempts       INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  max_attempts   INTEGER NOT NULL DEFAULT 12 CHECK (max_attempts > 0),
  dispatched_at  TIMESTAMPTZ,
  failed_at      TIMESTAMPTZ,
  last_error     TEXT,
  -- Ordering key: messages sharing a key are dispatched in insertion order so
  -- that, for example, two updates to one order cannot be reordered.
  ordering_key   TEXT
);

-- The dispatcher's hot query. A partial index keeps it proportional to the
-- backlog rather than to total history.
CREATE INDEX outbox_pending_idx
  ON outbox_messages (available_at, id)
  WHERE dispatched_at IS NULL AND failed_at IS NULL;

CREATE INDEX outbox_ordering_idx
  ON outbox_messages (ordering_key, id)
  WHERE dispatched_at IS NULL AND failed_at IS NULL AND ordering_key IS NOT NULL;

CREATE INDEX outbox_aggregate_idx ON outbox_messages (aggregate_type, aggregate_id, created_at DESC);
CREATE INDEX outbox_dead_idx      ON outbox_messages (failed_at DESC) WHERE failed_at IS NOT NULL;

COMMENT ON TABLE outbox_messages IS
  'Transactional outbox. Rows are written in the same transaction as the state change they describe; the dispatcher guarantees at-least-once delivery.';

-- ---------------------------------------------------------------------------
-- Background jobs (Postgres-backed queue; no Redis dependency at launch)
-- ---------------------------------------------------------------------------

CREATE TABLE jobs (
  id            UUID PRIMARY KEY,
  kind          TEXT NOT NULL CHECK (length(kind) BETWEEN 1 AND 80),
  payload       JSONB NOT NULL DEFAULT '{}'::jsonb,
  queue         TEXT NOT NULL DEFAULT 'default',
  priority      SMALLINT NOT NULL DEFAULT 100 CHECK (priority BETWEEN 0 AND 1000),
  run_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  locked_at     TIMESTAMPTZ,
  locked_by     TEXT,
  attempts      INTEGER NOT NULL DEFAULT 0,
  max_attempts  INTEGER NOT NULL DEFAULT 12,
  completed_at  TIMESTAMPTZ,
  failed_at     TIMESTAMPTZ,
  last_error    TEXT,
  -- A unique key makes enqueueing idempotent: "schedule the settlement release
  -- for order X" can be requested many times and will exist once.
  unique_key    TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX jobs_unique_key_idx
  ON jobs (unique_key)
  WHERE unique_key IS NOT NULL AND completed_at IS NULL AND failed_at IS NULL;

CREATE INDEX jobs_ready_idx
  ON jobs (queue, priority, run_at, id)
  WHERE completed_at IS NULL AND failed_at IS NULL;

CREATE INDEX jobs_dead_idx ON jobs (failed_at DESC) WHERE failed_at IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Idempotency keys
--
-- Follows the Stripe model: a key is claimed before the work starts, and the
-- stored response is replayed on retry. The request fingerprint stops the same
-- key being reused for a different request, which would otherwise return one
-- caller's response to another.
-- ---------------------------------------------------------------------------

CREATE TABLE idempotency_keys (
  id                UUID PRIMARY KEY,
  scope             TEXT NOT NULL,
  idempotency_key   TEXT NOT NULL CHECK (length(idempotency_key) BETWEEN 8 AND 255),
  user_id           UUID,
  request_fingerprint sha256_digest NOT NULL,
  status            TEXT NOT NULL DEFAULT 'in_progress'
                      CHECK (status IN ('in_progress','completed','failed')),
  response_status   INTEGER,
  response_body     JSONB,
  resource_id       TEXT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at      TIMESTAMPTZ,
  expires_at        TIMESTAMPTZ NOT NULL DEFAULT now() + INTERVAL '24 hours'
);

CREATE UNIQUE INDEX idempotency_keys_unique_idx
  ON idempotency_keys (scope, idempotency_key, coalesce(user_id, '00000000-0000-0000-0000-000000000000'::uuid));

CREATE INDEX idempotency_keys_expiry_idx ON idempotency_keys (expires_at);

-- ---------------------------------------------------------------------------
-- Cross-replica rate limiting (GCRA state)
-- ---------------------------------------------------------------------------

CREATE TABLE rate_limit_buckets (
  bucket_key   TEXT PRIMARY KEY,
  tat          TIMESTAMPTZ NOT NULL,
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX rate_limit_buckets_gc_idx ON rate_limit_buckets (tat);

-- rate_limit_allow implements GCRA atomically inside the database so that the
-- limit holds across every application replica.
CREATE OR REPLACE FUNCTION rate_limit_allow(
  p_key               TEXT,
  p_emission_interval INTERVAL,
  p_delay_tolerance   INTERVAL,
  p_cost              INTEGER DEFAULT 1
) RETURNS TABLE (allowed BOOLEAN, retry_after INTERVAL)
LANGUAGE plpgsql AS $$
DECLARE
  now_ts   TIMESTAMPTZ := clock_timestamp();
  cur_tat  TIMESTAMPTZ;
  new_tat  TIMESTAMPTZ;
  allow_at TIMESTAMPTZ;
BEGIN
  INSERT INTO rate_limit_buckets (bucket_key, tat)
  VALUES (p_key, now_ts)
  ON CONFLICT (bucket_key) DO UPDATE SET bucket_key = EXCLUDED.bucket_key
  RETURNING tat INTO cur_tat;

  IF cur_tat < now_ts THEN
    cur_tat := now_ts;
  END IF;

  new_tat  := cur_tat + (p_emission_interval * p_cost);
  allow_at := new_tat - p_delay_tolerance;

  IF allow_at > now_ts THEN
    allowed := FALSE;
    retry_after := allow_at - now_ts;
    RETURN NEXT;
    RETURN;
  END IF;

  UPDATE rate_limit_buckets
     SET tat = new_tat, updated_at = now_ts
   WHERE bucket_key = p_key;

  allowed := TRUE;
  retry_after := INTERVAL '0';
  RETURN NEXT;
END;
$$;
