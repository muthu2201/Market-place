-- 0004_ledger.sql
-- An immutable, double-entry accounting journal.
--
-- The platform never holds customer funds. The ledger nevertheless models every
-- economic event in balanced debits and credits because that is what makes
-- reconciliation against the provider provably correct: a missing payment, a
-- duplicated transfer, a mismatched amount or an orphaned transaction all show
-- up as an account that does not net to the provider's record.
--
-- Three database-level guarantees, none of which the application can bypass:
--   1. Entries balance. A deferred constraint trigger refuses a commit where
--      debits <> credits, per entry and per currency.
--   2. History is immutable. Corrections are new, compensating entries.
--   3. Lines never cross currencies within an entry.

CREATE TYPE ledger_account_kind AS ENUM ('asset','liability','equity','income','expense');
CREATE TYPE ledger_normal_balance AS ENUM ('debit','credit');
CREATE TYPE ledger_direction AS ENUM ('debit','credit');

CREATE TABLE ledger_accounts (
  id              UUID PRIMARY KEY,
  code            TEXT NOT NULL UNIQUE CHECK (code ~ '^[a-z][a-z0-9_.:-]{2,120}$'),
  name            TEXT NOT NULL,
  kind            ledger_account_kind NOT NULL,
  normal_balance  ledger_normal_balance NOT NULL,
  currency        currency_code NOT NULL,
  -- Owner scoping lets us answer "what does this seller's payable stand at"
  -- without string-parsing the account code.
  owner_type      TEXT NOT NULL DEFAULT 'platform'
                    CHECK (owner_type IN ('platform','seller','provider','tax_authority','buyer')),
  owner_id        UUID,
  -- A control account must never be posted to directly; it is the parent of a
  -- family of subsidiary accounts.
  is_control      BOOLEAN NOT NULL DEFAULT FALSE,
  closed_at       TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT ledger_accounts_kind_matches_normal_balance CHECK (
    (kind IN ('asset','expense')    AND normal_balance = 'debit') OR
    (kind IN ('liability','equity','income') AND normal_balance = 'credit')
  ),
  CONSTRAINT ledger_accounts_owner_id_required CHECK (
    owner_type = 'platform' OR owner_type = 'tax_authority' OR owner_type = 'provider' OR owner_id IS NOT NULL
  )
);

CREATE INDEX ledger_accounts_owner_idx ON ledger_accounts (owner_type, owner_id);
CREATE INDEX ledger_accounts_kind_idx  ON ledger_accounts (kind, currency);

CREATE TRIGGER ledger_accounts_immutable_core BEFORE UPDATE ON ledger_accounts
  FOR EACH ROW EXECUTE FUNCTION forbid_update_of_columns('id','code','kind','normal_balance','currency','created_at');

-- ---------------------------------------------------------------------------
-- Journal entries
-- ---------------------------------------------------------------------------

CREATE TABLE journal_entries (
  id              UUID PRIMARY KEY,
  public_id       public_id NOT NULL UNIQUE,
  kind            TEXT NOT NULL CHECK (kind IN (
                    'order_capture','platform_fee','psp_fee','tcs_collection','tds_deduction',
                    'seller_transfer','settlement_release','rolling_reserve_hold','rolling_reserve_release',
                    'refund','transfer_reversal','chargeback','chargeback_representment_won',
                    'payout','tax_remittance','adjustment','opening_balance','fx_revaluation')),
  currency        currency_code NOT NULL,
  occurred_at     TIMESTAMPTZ NOT NULL,
  posted_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  description     TEXT NOT NULL CHECK (length(description) BETWEEN 1 AND 500),
  reference_type  TEXT NOT NULL CHECK (length(reference_type) BETWEEN 1 AND 60),
  reference_id    TEXT NOT NULL,
  -- Correcting an entry never edits it; it posts a reversal that points back.
  reverses_entry_id UUID REFERENCES journal_entries (id),
  -- The idempotency key is what makes webhook replay and outbox at-least-once
  -- delivery safe: a repeated event cannot double-post.
  idempotency_key TEXT NOT NULL,
  metadata        JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE UNIQUE INDEX journal_entries_idempotency_uq ON journal_entries (idempotency_key);
CREATE INDEX journal_entries_reference_idx ON journal_entries (reference_type, reference_id);
CREATE INDEX journal_entries_kind_time_idx ON journal_entries (kind, occurred_at DESC);
CREATE INDEX journal_entries_occurred_idx  ON journal_entries (occurred_at DESC);

CREATE TRIGGER journal_entries_append_only
  BEFORE UPDATE OR DELETE ON journal_entries
  FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

-- ---------------------------------------------------------------------------
-- Journal lines
--
-- amount_minor is always positive; direction carries the sign. Storing a signed
-- amount plus a direction would allow two encodings of the same fact.
-- ---------------------------------------------------------------------------

CREATE TABLE journal_lines (
  seq           BIGSERIAL PRIMARY KEY,
  id            UUID NOT NULL UNIQUE,
  entry_id      UUID NOT NULL REFERENCES journal_entries (id) ON DELETE RESTRICT,
  line_no       SMALLINT NOT NULL CHECK (line_no > 0),
  account_id    UUID NOT NULL REFERENCES ledger_accounts (id) ON DELETE RESTRICT,
  direction     ledger_direction NOT NULL,
  amount_minor  money_minor NOT NULL CHECK (amount_minor > 0),
  currency      currency_code NOT NULL,
  memo          TEXT CHECK (memo IS NULL OR length(memo) <= 240),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (entry_id, line_no)
);

CREATE INDEX journal_lines_account_idx ON journal_lines (account_id, seq);
CREATE INDEX journal_lines_entry_idx   ON journal_lines (entry_id);

CREATE TRIGGER journal_lines_append_only
  BEFORE UPDATE OR DELETE ON journal_lines
  FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

-- A line must match its account's currency and must not post to a control account.
CREATE OR REPLACE FUNCTION journal_line_account_rules() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
DECLARE
  acct RECORD;
  ent  RECORD;
BEGIN
  SELECT currency, is_control, closed_at INTO acct FROM ledger_accounts WHERE id = NEW.account_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ledger account % does not exist', NEW.account_id USING ERRCODE = 'P0001';
  END IF;
  IF acct.is_control THEN
    RAISE EXCEPTION 'ledger account % is a control account and cannot be posted to directly', NEW.account_id
      USING ERRCODE = 'P0001';
  END IF;
  IF acct.closed_at IS NOT NULL THEN
    RAISE EXCEPTION 'ledger account % is closed', NEW.account_id USING ERRCODE = 'P0001';
  END IF;
  IF acct.currency <> NEW.currency THEN
    RAISE EXCEPTION 'line currency % does not match account currency %', NEW.currency, acct.currency
      USING ERRCODE = 'P0001';
  END IF;
  SELECT currency INTO ent FROM journal_entries WHERE id = NEW.entry_id;
  IF ent.currency <> NEW.currency THEN
    RAISE EXCEPTION 'line currency % does not match entry currency %', NEW.currency, ent.currency
      USING ERRCODE = 'P0001';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER journal_lines_account_rules
  BEFORE INSERT ON journal_lines
  FOR EACH ROW EXECUTE FUNCTION journal_line_account_rules();

-- ---------------------------------------------------------------------------
-- The balance rule
--
-- Deferred to COMMIT so that an entry and its lines can be inserted in any
-- order inside one transaction, but the transaction cannot commit unbalanced.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION journal_entry_must_balance() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
DECLARE
  target UUID;
  dr     BIGINT;
  cr     BIGINT;
  n      INTEGER;
BEGIN
  -- The same rule guards two tables, which do not share a column name for the
  -- entry: journal_lines references it, journal_entries is it. PL/pgSQL binds
  -- NEW.<field> eagerly, so the table must be branched on rather than COALESCEd.
  IF TG_TABLE_NAME = 'journal_lines' THEN
    target := NEW.entry_id;
  ELSE
    target := NEW.id;
  END IF;

  SELECT
    COALESCE(SUM(amount_minor) FILTER (WHERE direction = 'debit'), 0),
    COALESCE(SUM(amount_minor) FILTER (WHERE direction = 'credit'), 0),
    COUNT(*)
  INTO dr, cr, n
  FROM journal_lines
  WHERE entry_id = target;

  IF n = 0 THEN
    RAISE EXCEPTION 'journal entry % has no lines', target USING ERRCODE = 'P0001';
  END IF;
  IF n < 2 THEN
    RAISE EXCEPTION 'journal entry % has a single line; double entry requires at least two', target
      USING ERRCODE = 'P0001';
  END IF;
  IF dr <> cr THEN
    RAISE EXCEPTION 'journal entry % does not balance: debits % <> credits %', target, dr, cr
      USING ERRCODE = 'P0001',
            HINT = 'Every economic event must be expressed as equal debits and credits.';
  END IF;
  RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER journal_lines_balance_check
  AFTER INSERT ON journal_lines
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION journal_entry_must_balance();

CREATE CONSTRAINT TRIGGER journal_entries_balance_check
  AFTER INSERT ON journal_entries
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION journal_entry_must_balance();

-- ---------------------------------------------------------------------------
-- Balances
--
-- Journal writes are pure appends, so they never contend. Materialising a
-- running balance with an UPDATE per posting would serialise every order behind
-- one hot row (the platform commission account), so instead a rollup job
-- advances a watermark and the current balance is "rolled-up + the tail".
-- ---------------------------------------------------------------------------

CREATE TABLE ledger_account_balances (
  account_id    UUID PRIMARY KEY REFERENCES ledger_accounts (id) ON DELETE RESTRICT,
  currency      currency_code NOT NULL,
  debit_minor   money_minor NOT NULL DEFAULT 0 CHECK (debit_minor >= 0),
  credit_minor  money_minor NOT NULL DEFAULT 0 CHECK (credit_minor >= 0),
  through_seq   BIGINT NOT NULL DEFAULT 0,
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ledger_balance returns the signed balance in the account's natural direction:
-- positive means "in line with the account's normal balance".
CREATE OR REPLACE FUNCTION ledger_balance(p_account_id UUID)
RETURNS BIGINT
LANGUAGE plpgsql STABLE AS $$
DECLARE
  rolled   RECORD;
  tail_dr  BIGINT := 0;
  tail_cr  BIGINT := 0;
  normal   ledger_normal_balance;
  wm       BIGINT := 0;
BEGIN
  SELECT normal_balance INTO normal FROM ledger_accounts WHERE id = p_account_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ledger account % does not exist', p_account_id USING ERRCODE = 'P0001';
  END IF;

  SELECT debit_minor, credit_minor, through_seq INTO rolled
  FROM ledger_account_balances WHERE account_id = p_account_id;

  IF FOUND THEN
    wm := rolled.through_seq;
  END IF;

  SELECT
    COALESCE(SUM(amount_minor) FILTER (WHERE direction = 'debit'), 0),
    COALESCE(SUM(amount_minor) FILTER (WHERE direction = 'credit'), 0)
  INTO tail_dr, tail_cr
  FROM journal_lines
  WHERE account_id = p_account_id AND seq > wm;

  IF normal = 'debit' THEN
    RETURN (COALESCE(rolled.debit_minor, 0) + tail_dr) - (COALESCE(rolled.credit_minor, 0) + tail_cr);
  ELSE
    RETURN (COALESCE(rolled.credit_minor, 0) + tail_cr) - (COALESCE(rolled.debit_minor, 0) + tail_dr);
  END IF;
END;
$$;

-- ledger_rollup advances the watermark for every account, bounded by a batch
-- size so the job never holds long locks.
CREATE OR REPLACE FUNCTION ledger_rollup(p_max_seq BIGINT DEFAULT NULL)
RETURNS INTEGER
LANGUAGE plpgsql AS $$
DECLARE
  ceiling BIGINT;
  touched INTEGER := 0;
BEGIN
  ceiling := COALESCE(p_max_seq, (SELECT COALESCE(MAX(seq), 0) FROM journal_lines));

  INSERT INTO ledger_account_balances (account_id, currency, debit_minor, credit_minor, through_seq, updated_at)
  SELECT l.account_id,
         MIN(l.currency),
         COALESCE(SUM(l.amount_minor) FILTER (WHERE l.direction = 'debit'), 0),
         COALESCE(SUM(l.amount_minor) FILTER (WHERE l.direction = 'credit'), 0),
         ceiling,
         now()
  FROM journal_lines l
  LEFT JOIN ledger_account_balances b ON b.account_id = l.account_id
  WHERE l.seq > COALESCE(b.through_seq, 0) AND l.seq <= ceiling
  GROUP BY l.account_id
  ON CONFLICT (account_id) DO UPDATE
    SET debit_minor  = ledger_account_balances.debit_minor  + EXCLUDED.debit_minor,
        credit_minor = ledger_account_balances.credit_minor + EXCLUDED.credit_minor,
        through_seq  = EXCLUDED.through_seq,
        updated_at   = now();

  GET DIAGNOSTICS touched = ROW_COUNT;
  RETURN touched;
END;
$$;

-- ---------------------------------------------------------------------------
-- Trial balance
--
-- The single most valuable invariant in the system: across every account, in
-- every currency, total debits must equal total credits. Any non-zero row is a
-- bug or a tampering event and pages the operator.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE VIEW ledger_trial_balance AS
SELECT
  a.currency,
  SUM(l.amount_minor) FILTER (WHERE l.direction = 'debit')  AS total_debits,
  SUM(l.amount_minor) FILTER (WHERE l.direction = 'credit') AS total_credits,
  COALESCE(SUM(l.amount_minor) FILTER (WHERE l.direction = 'debit'), 0)
    - COALESCE(SUM(l.amount_minor) FILTER (WHERE l.direction = 'credit'), 0) AS difference
FROM journal_lines l
JOIN ledger_accounts a ON a.id = l.account_id
GROUP BY a.currency;

COMMENT ON VIEW ledger_trial_balance IS
  'difference must be 0 for every currency. A non-zero row is an incident.';

-- ---------------------------------------------------------------------------
-- Reconciliation against provider records
-- ---------------------------------------------------------------------------

CREATE TABLE reconciliation_runs (
  id            UUID PRIMARY KEY,
  provider      TEXT NOT NULL,
  period_start  DATE NOT NULL,
  period_end    DATE NOT NULL,
  status        TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running','completed','failed')),
  ledger_total  money_minor,
  provider_total money_minor,
  currency      currency_code NOT NULL DEFAULT 'INR',
  difference_count INTEGER NOT NULL DEFAULT 0,
  started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at   TIMESTAMPTZ,
  error         TEXT,
  CONSTRAINT reconciliation_runs_period CHECK (period_end >= period_start)
);

CREATE INDEX reconciliation_runs_provider_idx ON reconciliation_runs (provider, period_start DESC);

CREATE TABLE reconciliation_differences (
  id             UUID PRIMARY KEY,
  run_id         UUID NOT NULL REFERENCES reconciliation_runs (id) ON DELETE CASCADE,
  kind           TEXT NOT NULL CHECK (kind IN
                   ('missing_in_ledger','missing_at_provider','amount_mismatch','currency_mismatch',
                    'duplicate_at_provider','duplicate_in_ledger','status_mismatch','orphan_transfer')),
  provider_ref   TEXT,
  ledger_ref     TEXT,
  expected_minor money_minor,
  actual_minor   money_minor,
  currency       currency_code NOT NULL DEFAULT 'INR',
  detail         JSONB NOT NULL DEFAULT '{}'::jsonb,
  resolved_at    TIMESTAMPTZ,
  resolved_by    UUID REFERENCES users (id),
  resolution     TEXT,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX reconciliation_differences_run_idx  ON reconciliation_differences (run_id);
CREATE INDEX reconciliation_differences_open_idx ON reconciliation_differences (created_at DESC) WHERE resolved_at IS NULL;
