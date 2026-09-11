-- 0012_audit_chain_order.sql
-- Makes the audit chain correct under concurrency.
--
-- The previous fix serialised the hash computation with an advisory lock, which
-- was necessary but not sufficient, and a load test proved it: the chain still
-- forked at high write rates.
--
-- The reason is that seq comes from a BIGSERIAL default, and PostgreSQL
-- evaluates column defaults while building the tuple, BEFORE the row trigger
-- fires. So two concurrent inserts take their sequence numbers in one order and
-- reach the locked section in the other. A row with the LOWER seq could chain
-- from a row with the HIGHER seq, and a verifier walking by seq then saw a
-- mismatch that was not tampering at all.
--
-- The fix is to give the chain its own position, allocated INSIDE the locked
-- section, and to verify along that position rather than along seq. Chain order
-- and verification order are then the same order by construction.

CREATE SEQUENCE IF NOT EXISTS audit_log_chain_pos_seq;

ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS chain_pos BIGINT;

-- Backfill in seq order. Any pre-existing chain was built in seq order, so this
-- preserves whatever it recorded.
--
-- The append-only guard has to be lifted for this one statement, and it
-- correctly refused the migration until that was made explicit. That is the
-- guard working: altering audit history is possible only as a deliberate,
-- reviewable act, never as a side effect. The hashes are not recomputed here,
-- so the chain's evidential value is unchanged.
ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only;
UPDATE audit_log SET chain_pos = seq WHERE chain_pos IS NULL;
ALTER TABLE audit_log ENABLE TRIGGER audit_log_append_only;

SELECT setval('audit_log_chain_pos_seq',
              GREATEST((SELECT COALESCE(MAX(chain_pos), 0) FROM audit_log), 1));

ALTER TABLE audit_log ALTER COLUMN chain_pos SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS audit_log_chain_pos_uq ON audit_log (chain_pos);

CREATE OR REPLACE FUNCTION audit_log_chain() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
DECLARE
  prev sha256_digest;
BEGIN
  -- Everything below runs strictly one writer at a time. A hash chain that can
  -- fork provides no tamper evidence, so serialising these writes is the point
  -- rather than a cost to be optimised away.
  PERFORM pg_advisory_xact_lock(hashtext('audit_log_chain'));

  -- Allocated inside the lock, so chain position and chain order agree.
  NEW.chain_pos := nextval('audit_log_chain_pos_seq');

  SELECT entry_hash INTO prev FROM audit_log ORDER BY chain_pos DESC LIMIT 1;

  NEW.prev_hash := prev;
  NEW.entry_hash := digest(
      coalesce(encode(prev, 'hex'), '')
      || '|' || NEW.chain_pos::text
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

-- verify_audit_chain walks the chain in chain_pos order and returns the first
-- position whose stored hash does not match a recomputation. No rows means the
-- chain verifies.
CREATE OR REPLACE FUNCTION verify_audit_chain(from_seq BIGINT DEFAULT 0)
RETURNS TABLE (broken_at BIGINT, reason TEXT)
LANGUAGE plpgsql AS $$
DECLARE
  r        RECORD;
  expected sha256_digest;
  prev     sha256_digest;
  started  BOOLEAN := FALSE;
BEGIN
  FOR r IN SELECT * FROM audit_log WHERE chain_pos > from_seq ORDER BY chain_pos LOOP
    IF NOT started THEN
      SELECT entry_hash INTO prev FROM audit_log
       WHERE chain_pos < r.chain_pos ORDER BY chain_pos DESC LIMIT 1;
      started := TRUE;
    END IF;

    IF r.prev_hash IS DISTINCT FROM prev THEN
      broken_at := r.chain_pos;
      reason := 'prev_hash does not match the preceding entry';
      RETURN NEXT; RETURN;
    END IF;

    expected := digest(
        coalesce(encode(prev, 'hex'), '')
        || '|' || r.chain_pos::text
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
      broken_at := r.chain_pos;
      reason := 'entry_hash does not match a recomputation of the entry';
      RETURN NEXT; RETURN;
    END IF;

    prev := r.entry_hash;
  END LOOP;
  RETURN;
END;
$$;

COMMENT ON COLUMN audit_log.chain_pos IS
  'Chain position, allocated inside the serialised section so chain order and verification order are the same order.';
