-- 0011_contention.sql
-- Removes the hot rows that a load test showed aborting transactions under
-- concurrency, and makes the audit chain correct when several writers run at
-- once.
--
-- Every change here was driven by an observed failure, not by speculation:
-- ops/stress-test.sh produced serialization aborts on the invoice series, the
-- platform turnover row, the seller turnover row and the lazy seller-account
-- helper, and a forked audit chain.

-- ---------------------------------------------------------------------------
-- 1. Order numbers
--
-- An order number is a human reference, not a statutory document, so it does
-- not have to be gapless. Allocating it from a sequence removes the row lock
-- that previously serialised every checkout behind one counter. Tax invoice
-- numbers DO have to be gapless and keep their locked-row allocator below.
-- ---------------------------------------------------------------------------

CREATE SEQUENCE IF NOT EXISTS order_number_seq;

CREATE OR REPLACE FUNCTION next_order_number(p_fy_start DATE)
RETURNS TEXT
LANGUAGE plpgsql AS $$
DECLARE
  n BIGINT;
BEGIN
  -- nextval does not take a row lock and never aborts a transaction. The
  -- sequence may skip values on rollback, which is acceptable and expected for
  -- a reference number.
  n := nextval('order_number_seq');
  RETURN 'ORD/' || to_char(p_fy_start, 'YY')
                || to_char(p_fy_start + INTERVAL '1 year', 'YY')
                || '/' || lpad(n::text, 8, '0');
END;
$$;

COMMENT ON FUNCTION next_order_number IS
  'Non-blocking order reference. Gaps are possible and acceptable; invoice numbers, which must be gapless, use next_invoice_number instead.';

-- ---------------------------------------------------------------------------
-- 2. Turnover counters
--
-- A single platform-wide row that every order updates is a guaranteed
-- bottleneck: concurrent writers either serialise behind a row lock or abort.
-- Writes become append-only deltas, and a reader adds the rolled-up total to
-- the un-rolled tail. This is the same shape that already works for ledger
-- balances.
-- ---------------------------------------------------------------------------

CREATE TABLE turnover_deltas (
  seq             BIGSERIAL PRIMARY KEY,
  scope           TEXT NOT NULL CHECK (scope IN ('seller','platform')),
  seller_id       UUID REFERENCES sellers (id) ON DELETE CASCADE,
  fy_start        DATE NOT NULL,
  currency        currency_code NOT NULL,
  gross_supply    money_minor NOT NULL DEFAULT 0,
  taxable_supply  money_minor NOT NULL DEFAULT 0,
  tds_deducted    money_minor NOT NULL DEFAULT 0,
  tcs_collected   money_minor NOT NULL DEFAULT 0,
  refunded_amount money_minor NOT NULL DEFAULT 0,
  commission      money_minor NOT NULL DEFAULT 0,
  export_supply   money_minor NOT NULL DEFAULT 0,
  order_count     INTEGER NOT NULL DEFAULT 0,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT turnover_deltas_seller_scope CHECK (scope <> 'seller' OR seller_id IS NOT NULL)
);

CREATE INDEX turnover_deltas_seller_idx   ON turnover_deltas (seller_id, fy_start, currency, seq);
CREATE INDEX turnover_deltas_platform_idx ON turnover_deltas (fy_start, currency, seq) WHERE scope = 'platform';

CREATE TRIGGER turnover_deltas_append_only
  BEFORE UPDATE OR DELETE ON turnover_deltas
  FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

-- Watermarks so a rollup never double-counts.
ALTER TABLE seller_turnover   ADD COLUMN IF NOT EXISTS through_seq BIGINT NOT NULL DEFAULT 0;
ALTER TABLE platform_turnover ADD COLUMN IF NOT EXISTS through_seq BIGINT NOT NULL DEFAULT 0;

-- seller_fy_gross is what the section 194-O threshold check reads: the rolled
-- total plus everything recorded since the last rollup.
CREATE OR REPLACE FUNCTION seller_fy_gross(p_seller UUID, p_fy DATE, p_currency currency_code)
RETURNS BIGINT
LANGUAGE plpgsql STABLE AS $$
DECLARE
  rolled BIGINT := 0;
  wm     BIGINT := 0;
  tail   BIGINT := 0;
BEGIN
  SELECT gross_supply, through_seq INTO rolled, wm
    FROM seller_turnover
   WHERE seller_id = p_seller AND fy_start = p_fy AND currency = p_currency;

  SELECT COALESCE(SUM(gross_supply), 0) INTO tail
    FROM turnover_deltas
   WHERE scope = 'seller' AND seller_id = p_seller
     AND fy_start = p_fy AND currency = p_currency AND seq > COALESCE(wm, 0);

  RETURN COALESCE(rolled, 0) + tail;
END;
$$;

-- rollup_turnover folds deltas into the aggregate rows. The worker calls it;
-- it is idempotent and safe to run concurrently with new writes.
CREATE OR REPLACE FUNCTION rollup_turnover()
RETURNS INTEGER
LANGUAGE plpgsql AS $$
DECLARE
  ceiling BIGINT;
  touched INTEGER := 0;
  n       INTEGER;
BEGIN
  SELECT COALESCE(MAX(seq), 0) INTO ceiling FROM turnover_deltas;

  INSERT INTO seller_turnover (seller_id, fy_start, currency, gross_supply, taxable_supply,
                               tds_deducted, tcs_collected, refunded_amount, order_count,
                               through_seq, updated_at)
  SELECT d.seller_id, d.fy_start, d.currency,
         SUM(d.gross_supply), SUM(d.taxable_supply), SUM(d.tds_deducted),
         SUM(d.tcs_collected), SUM(d.refunded_amount), SUM(d.order_count),
         ceiling, now()
    FROM turnover_deltas d
    LEFT JOIN seller_turnover t
      ON t.seller_id = d.seller_id AND t.fy_start = d.fy_start AND t.currency = d.currency
   WHERE d.scope = 'seller' AND d.seq > COALESCE(t.through_seq, 0) AND d.seq <= ceiling
   GROUP BY d.seller_id, d.fy_start, d.currency
  ON CONFLICT (seller_id, fy_start, currency) DO UPDATE
    SET gross_supply    = seller_turnover.gross_supply    + EXCLUDED.gross_supply,
        taxable_supply  = seller_turnover.taxable_supply  + EXCLUDED.taxable_supply,
        tds_deducted    = seller_turnover.tds_deducted    + EXCLUDED.tds_deducted,
        tcs_collected   = seller_turnover.tcs_collected   + EXCLUDED.tcs_collected,
        refunded_amount = seller_turnover.refunded_amount + EXCLUDED.refunded_amount,
        order_count     = seller_turnover.order_count     + EXCLUDED.order_count,
        through_seq     = EXCLUDED.through_seq,
        updated_at      = now();
  GET DIAGNOSTICS n = ROW_COUNT;
  touched := touched + n;

  INSERT INTO platform_turnover (fy_start, currency, domestic_gmv, export_gmv,
                                 commission_income, order_count, through_seq, updated_at)
  SELECT d.fy_start, MIN(d.currency),
         SUM(d.gross_supply), SUM(d.export_supply), SUM(d.commission), SUM(d.order_count),
         ceiling, now()
    FROM turnover_deltas d
    LEFT JOIN platform_turnover p ON p.fy_start = d.fy_start
   WHERE d.scope = 'platform' AND d.seq > COALESCE(p.through_seq, 0) AND d.seq <= ceiling
   GROUP BY d.fy_start
  ON CONFLICT (fy_start) DO UPDATE
    SET domestic_gmv      = platform_turnover.domestic_gmv      + EXCLUDED.domestic_gmv,
        export_gmv        = platform_turnover.export_gmv        + EXCLUDED.export_gmv,
        commission_income = platform_turnover.commission_income + EXCLUDED.commission_income,
        order_count       = platform_turnover.order_count       + EXCLUDED.order_count,
        through_seq       = EXCLUDED.through_seq,
        updated_at        = now();
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN touched + n;
END;
$$;

-- ---------------------------------------------------------------------------
-- 3. Lazy seller ledger accounts
--
-- The previous implementation did INSERT ... DO NOTHING and then SELECT, which
-- races: the SELECT cannot see a row a concurrent transaction has not yet
-- committed. A single statement that returns the row in both cases is correct.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION seller_ledger_account(p_seller_id UUID, p_purpose TEXT, p_currency currency_code)
RETURNS UUID
LANGUAGE plpgsql AS $$
DECLARE
  v_code TEXT;
  v_name TEXT;
  v_id   UUID;
BEGIN
  IF p_purpose NOT IN ('payable', 'reserve') THEN
    RAISE EXCEPTION 'unknown seller account purpose %', p_purpose USING ERRCODE = 'P0001';
  END IF;

  v_code := 'seller.' || replace(p_seller_id::text, '-', '') || '.' || p_purpose || '.' || lower(p_currency);

  -- The common path: the account already exists.
  SELECT id INTO v_id FROM ledger_accounts WHERE code = v_code;
  IF v_id IS NOT NULL THEN
    RETURN v_id;
  END IF;

  v_name := CASE p_purpose
              WHEN 'payable' THEN 'Seller payable'
              WHEN 'reserve' THEN 'Seller rolling reserve'
            END || ' - ' || p_seller_id::text || ' (' || p_currency || ')';

  -- DO UPDATE rather than DO NOTHING so the row is returned whichever
  -- transaction won the race.
  INSERT INTO ledger_accounts (id, code, name, kind, normal_balance, currency, owner_type, owner_id)
  VALUES (gen_random_uuid(), v_code, v_name, 'liability', 'credit', p_currency, 'seller', p_seller_id)
  ON CONFLICT (code) DO UPDATE SET name = ledger_accounts.name
  RETURNING id INTO v_id;

  RETURN v_id;
END;
$$;

-- ---------------------------------------------------------------------------
-- 4. Audit chain under concurrency
--
-- The chain read "the last row" and hashed from it. Two concurrent inserts read
-- the same last row and both chained from it, forking the chain: the load test
-- reported "prev_hash does not match the preceding row".
--
-- A transaction-level advisory lock makes the critical section genuinely
-- serial, which is what a hash chain requires. Audit writes are low volume
-- relative to everything else, so serialising them is the right trade: a chain
-- that can fork provides no tamper evidence at all.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION audit_log_chain() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
DECLARE
  prev sha256_digest;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('audit_log_chain'));

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

COMMENT ON FUNCTION audit_log_chain IS
  'Serialised by a transaction advisory lock: a hash chain that can fork under concurrency provides no tamper evidence.';
