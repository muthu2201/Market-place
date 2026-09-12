-- 0007_delivery_tax_payouts.sql
-- Entitlements and delivery, statutory tax aggregation, invoices and payouts.

-- ---------------------------------------------------------------------------
-- Licences: the server-side entitlement
--
-- The client is never trusted with a download decision. A licence row is the
-- only thing that authorises delivery, and it is resolved fresh on every
-- request from the buyer's session, not from anything the client presents.
-- ---------------------------------------------------------------------------

CREATE TABLE licenses (
  id                UUID PRIMARY KEY,
  public_id         public_id NOT NULL UNIQUE,
  order_item_id     UUID NOT NULL UNIQUE REFERENCES order_items (id) ON DELETE RESTRICT,
  user_id           UUID NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
  product_id        UUID NOT NULL REFERENCES products (id) ON DELETE RESTRICT,
  variant_id        UUID NOT NULL REFERENCES product_variants (id) ON DELETE RESTRICT,

  license_type      TEXT NOT NULL,
  terms_snapshot    TEXT NOT NULL,
  -- A licence key is issued for products whose delivery is a key rather than a
  -- file. It is stored hashed; the plaintext is shown once at issue.
  license_key_hash  sha256_digest,

  status            TEXT NOT NULL DEFAULT 'active'
                      CHECK (status IN ('active','expired','revoked','refunded')),
  revoked_reason    TEXT,
  -- A time-limited grant restricts further downloads after this instant. It is
  -- described to the buyer as a limited licence, never as a rental, because a
  -- file already downloaded cannot be recalled.
  access_expires_at TIMESTAMPTZ,
  download_limit    INTEGER NOT NULL DEFAULT 10 CHECK (download_limit > 0),
  download_count    INTEGER NOT NULL DEFAULT 0 CHECK (download_count >= 0),
  issued_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT licenses_downloads_within_limit CHECK (download_count <= download_limit)
);

CREATE INDEX licenses_user_idx    ON licenses (user_id, issued_at DESC);
CREATE INDEX licenses_product_idx ON licenses (product_id);
CREATE INDEX licenses_expiry_idx  ON licenses (access_expires_at) WHERE status = 'active' AND access_expires_at IS NOT NULL;

CREATE TRIGGER licenses_set_updated_at BEFORE UPDATE ON licenses
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER licenses_immutable_core BEFORE UPDATE ON licenses
  FOR EACH ROW EXECUTE FUNCTION forbid_update_of_columns(
    'id','public_id','order_item_id','user_id','product_id','variant_id','issued_at');

-- ---------------------------------------------------------------------------
-- Download grants: a single-use, short-lived, bound ticket
--
-- A signed URL alone is a bearer token that leaks through referrers, proxies
-- and shared screenshots. Binding each grant to one licence, one asset, one
-- use and a short window converts a leaked URL into a near-useless artefact.
-- ---------------------------------------------------------------------------

CREATE TABLE download_grants (
  id            UUID PRIMARY KEY,
  license_id    UUID NOT NULL REFERENCES licenses (id) ON DELETE CASCADE,
  asset_id      UUID NOT NULL REFERENCES product_assets (id) ON DELETE RESTRICT,
  user_id       UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  nonce_hash    sha256_digest NOT NULL UNIQUE,
  issued_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at    TIMESTAMPTZ NOT NULL,
  consumed_at   TIMESTAMPTZ,
  issued_ip     INET,
  consumed_ip   INET,
  CONSTRAINT download_grants_window CHECK (expires_at > issued_at)
);

CREATE INDEX download_grants_license_idx ON download_grants (license_id, issued_at DESC);
CREATE INDEX download_grants_gc_idx      ON download_grants (expires_at) WHERE consumed_at IS NULL;

CREATE TABLE download_events (
  id          BIGSERIAL PRIMARY KEY,
  license_id  UUID NOT NULL REFERENCES licenses (id) ON DELETE CASCADE,
  asset_id    UUID NOT NULL REFERENCES product_assets (id) ON DELETE RESTRICT,
  user_id     UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  grant_id    UUID REFERENCES download_grants (id) ON DELETE SET NULL,
  bytes_sent  BIGINT NOT NULL DEFAULT 0 CHECK (bytes_sent >= 0),
  outcome     TEXT NOT NULL CHECK (outcome IN ('served','denied_entitlement','denied_expired','denied_limit','denied_revoked','aborted','error')),
  ip          INET,
  user_agent_hash sha256_digest,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX download_events_license_idx ON download_events (license_id, occurred_at DESC);
CREATE INDEX download_events_user_idx    ON download_events (user_id, occurred_at DESC);
CREATE INDEX download_events_time_idx    ON download_events (occurred_at DESC);

CREATE TRIGGER download_events_append_only
  BEFORE UPDATE OR DELETE ON download_events
  FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

COMMENT ON TABLE download_events IS
  'Evidence of delivery. This is the primary exhibit in chargeback representment and in a "never received it" dispute.';

-- ---------------------------------------------------------------------------
-- Invoices
--
-- Two documents exist per order item and they are not interchangeable:
--   * the seller's tax invoice for the supply to the buyer, and
--   * the platform's tax invoice to the seller for the commission.
-- Number series are per financial year and strictly gapless, which GST audit
-- expects.
-- ---------------------------------------------------------------------------

CREATE TABLE invoice_series (
  id             UUID PRIMARY KEY,
  kind           TEXT NOT NULL CHECK (kind IN ('seller_supply','platform_commission','credit_note')),
  fy_start       DATE NOT NULL,
  prefix         TEXT NOT NULL,
  next_number    BIGINT NOT NULL DEFAULT 1 CHECK (next_number > 0),
  UNIQUE (kind, fy_start)
);

CREATE TABLE invoices (
  id                UUID PRIMARY KEY,
  public_id         public_id NOT NULL UNIQUE,
  kind              TEXT NOT NULL CHECK (kind IN ('seller_supply','platform_commission','credit_note')),
  invoice_number    TEXT NOT NULL,
  fy_start          DATE NOT NULL,
  order_id          UUID REFERENCES orders (id) ON DELETE RESTRICT,
  order_item_id     UUID REFERENCES order_items (id) ON DELETE RESTRICT,
  seller_id         UUID REFERENCES sellers (id) ON DELETE RESTRICT,
  buyer_id          UUID REFERENCES users (id) ON DELETE RESTRICT,
  reverses_invoice_id UUID REFERENCES invoices (id),

  supplier_gstin    CHAR(15),
  supplier_name     TEXT NOT NULL,
  supplier_state    SMALLINT,
  recipient_gstin   CHAR(15),
  recipient_name_ciphertext BYTEA,
  place_of_supply_country CHAR(2) NOT NULL DEFAULT 'IN',
  place_of_supply_state   SMALLINT,

  currency          currency_code NOT NULL,
  taxable_value_minor money_minor NOT NULL CHECK (taxable_value_minor >= 0),
  cgst_minor        money_minor NOT NULL DEFAULT 0 CHECK (cgst_minor >= 0),
  sgst_minor        money_minor NOT NULL DEFAULT 0 CHECK (sgst_minor >= 0),
  igst_minor        money_minor NOT NULL DEFAULT 0 CHECK (igst_minor >= 0),
  total_minor       money_minor NOT NULL CHECK (total_minor >= 0),
  sac_code          TEXT,

  issued_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  pdf_object_key    TEXT,
  UNIQUE (kind, fy_start, invoice_number),
  CONSTRAINT invoices_total_matches
    CHECK (total_minor = taxable_value_minor + cgst_minor + sgst_minor + igst_minor),
  CONSTRAINT invoices_tax_split_exclusive
    CHECK (igst_minor = 0 OR (cgst_minor = 0 AND sgst_minor = 0))
);

CREATE INDEX invoices_order_idx  ON invoices (order_id);
CREATE INDEX invoices_seller_idx ON invoices (seller_id, issued_at DESC);
CREATE INDEX invoices_fy_idx     ON invoices (kind, fy_start, invoice_number);

CREATE TRIGGER invoices_append_only
  BEFORE UPDATE OR DELETE ON invoices
  FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

-- next_invoice_number hands out a gapless number under a row lock. Taking the
-- lock in the same transaction as the insert is what guarantees no gaps even
-- under concurrent checkout.
CREATE OR REPLACE FUNCTION next_invoice_number(p_kind TEXT, p_fy_start DATE, p_prefix TEXT)
RETURNS TEXT LANGUAGE plpgsql AS $$
DECLARE
  n BIGINT;
  p TEXT;
BEGIN
  INSERT INTO invoice_series (id, kind, fy_start, prefix)
  VALUES (gen_random_uuid(), p_kind, p_fy_start, p_prefix)
  ON CONFLICT (kind, fy_start) DO NOTHING;

  UPDATE invoice_series
     SET next_number = next_number + 1
   WHERE kind = p_kind AND fy_start = p_fy_start
  RETURNING next_number - 1, prefix INTO n, p;

  RETURN p || '/' || to_char(p_fy_start, 'YY') || to_char(p_fy_start + INTERVAL '1 year', 'YY') || '/' || lpad(n::text, 6, '0');
END;
$$;

-- ---------------------------------------------------------------------------
-- Statutory tax aggregation
--
-- GSTR-8 (TCS under s.52) is filed monthly, by the 10th of the following month.
-- s.194-O TDS is deposited monthly and reported quarterly in Form 26Q.
-- These tables are the filing-ready aggregates, derived from order_items.
-- ---------------------------------------------------------------------------

CREATE TABLE tcs_periods (
  id              UUID PRIMARY KEY,
  period_month    DATE NOT NULL UNIQUE,
  status          TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','closed','filed','amended')),
  gross_supply_minor   money_minor NOT NULL DEFAULT 0,
  returns_minor        money_minor NOT NULL DEFAULT 0,
  net_supply_minor     money_minor NOT NULL DEFAULT 0,
  tcs_cgst_minor       money_minor NOT NULL DEFAULT 0,
  tcs_sgst_minor       money_minor NOT NULL DEFAULT 0,
  tcs_igst_minor       money_minor NOT NULL DEFAULT 0,
  currency        currency_code NOT NULL DEFAULT 'INR',
  due_on          DATE NOT NULL,
  closed_at       TIMESTAMPTZ,
  filed_at        TIMESTAMPTZ,
  filing_reference TEXT,
  CONSTRAINT tcs_periods_is_month_start CHECK (EXTRACT(DAY FROM period_month) = 1)
);

CREATE TABLE tcs_period_lines (
  id            UUID PRIMARY KEY,
  period_id     UUID NOT NULL REFERENCES tcs_periods (id) ON DELETE CASCADE,
  seller_id     UUID NOT NULL REFERENCES sellers (id) ON DELETE RESTRICT,
  seller_gstin  CHAR(15),
  gross_supply_minor money_minor NOT NULL DEFAULT 0,
  returns_minor      money_minor NOT NULL DEFAULT 0,
  net_supply_minor   money_minor NOT NULL DEFAULT 0,
  tcs_cgst_minor     money_minor NOT NULL DEFAULT 0,
  tcs_sgst_minor     money_minor NOT NULL DEFAULT 0,
  tcs_igst_minor     money_minor NOT NULL DEFAULT 0,
  order_count   INTEGER NOT NULL DEFAULT 0,
  UNIQUE (period_id, seller_id)
);

CREATE INDEX tcs_period_lines_seller_idx ON tcs_period_lines (seller_id);

CREATE TABLE tds_periods (
  id            UUID PRIMARY KEY,
  period_month  DATE NOT NULL UNIQUE,
  status        TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','closed','deposited','filed')),
  gross_minor   money_minor NOT NULL DEFAULT 0,
  tds_minor     money_minor NOT NULL DEFAULT 0,
  currency      currency_code NOT NULL DEFAULT 'INR',
  due_on        DATE NOT NULL,
  challan_reference TEXT,
  deposited_at  TIMESTAMPTZ,
  CONSTRAINT tds_periods_is_month_start CHECK (EXTRACT(DAY FROM period_month) = 1)
);

CREATE TABLE tds_period_lines (
  id           UUID PRIMARY KEY,
  period_id    UUID NOT NULL REFERENCES tds_periods (id) ON DELETE CASCADE,
  seller_id    UUID NOT NULL REFERENCES sellers (id) ON DELETE RESTRICT,
  seller_pan   CHAR(10),
  pan_available BOOLEAN NOT NULL DEFAULT TRUE,
  gross_minor  money_minor NOT NULL DEFAULT 0,
  tds_minor    money_minor NOT NULL DEFAULT 0,
  rate_bps     basis_points NOT NULL,
  order_count  INTEGER NOT NULL DEFAULT 0,
  UNIQUE (period_id, seller_id)
);

-- ---------------------------------------------------------------------------
-- Payouts
--
-- In split-settlement mode the provider pays the seller directly and a payout
-- row records that fact for reconciliation. In bridge mode the platform
-- instructs a payout explicitly. Either way the platform never holds a balance.
-- ---------------------------------------------------------------------------

CREATE TABLE payout_batches (
  id            UUID PRIMARY KEY,
  public_id     public_id NOT NULL UNIQUE,
  provider      TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'building'
                  CHECK (status IN ('building','submitted','partially_settled','settled','failed')),
  currency      currency_code NOT NULL DEFAULT 'INR',
  total_minor   money_minor NOT NULL DEFAULT 0 CHECK (total_minor >= 0),
  payout_count  INTEGER NOT NULL DEFAULT 0,
  scheduled_for DATE NOT NULL,
  submitted_at  TIMESTAMPTZ,
  settled_at    TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE payouts (
  id                 UUID PRIMARY KEY,
  public_id          public_id NOT NULL UNIQUE,
  batch_id           UUID REFERENCES payout_batches (id) ON DELETE RESTRICT,
  seller_id          UUID NOT NULL REFERENCES sellers (id) ON DELETE RESTRICT,
  payout_account_id  UUID NOT NULL REFERENCES seller_payout_accounts (id) ON DELETE RESTRICT,
  provider           TEXT NOT NULL,
  provider_payout_id TEXT,
  amount_minor       money_minor NOT NULL CHECK (amount_minor > 0),
  reserve_withheld_minor money_minor NOT NULL DEFAULT 0 CHECK (reserve_withheld_minor >= 0),
  offset_applied_minor   money_minor NOT NULL DEFAULT 0 CHECK (offset_applied_minor >= 0),
  currency           currency_code NOT NULL,
  status             TEXT NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending','submitted','processing','settled','failed','reversed','cancelled')),
  utr                TEXT,
  failure_code       TEXT,
  failure_message    TEXT,
  settled_at         TIMESTAMPTZ,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX payouts_provider_uq ON payouts (provider, provider_payout_id) WHERE provider_payout_id IS NOT NULL;
CREATE INDEX payouts_seller_idx ON payouts (seller_id, created_at DESC);
CREATE INDEX payouts_status_idx ON payouts (status) WHERE status IN ('pending','submitted','processing');

CREATE TRIGGER payouts_set_updated_at BEFORE UPDATE ON payouts
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- A payout may only be made to a validated destination that has cleared its
-- cool-off. This is enforced in the database so that no code path, and no
-- operator with direct SQL access, can bypass it.
CREATE OR REPLACE FUNCTION payouts_destination_guard() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
DECLARE
  acct RECORD;
  slr  RECORD;
BEGIN
  SELECT validation_status, active_from, disabled_at, seller_id
    INTO acct FROM seller_payout_accounts WHERE id = NEW.payout_account_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'payout destination % does not exist', NEW.payout_account_id USING ERRCODE = 'P0001';
  END IF;
  IF acct.seller_id <> NEW.seller_id THEN
    RAISE EXCEPTION 'payout destination % does not belong to seller %', NEW.payout_account_id, NEW.seller_id
      USING ERRCODE = 'P0001';
  END IF;
  IF acct.disabled_at IS NOT NULL THEN
    RAISE EXCEPTION 'payout destination % is disabled', NEW.payout_account_id USING ERRCODE = 'P0001';
  END IF;
  IF acct.validation_status <> 'validated' THEN
    RAISE EXCEPTION 'payout destination % has not passed beneficiary validation', NEW.payout_account_id
      USING ERRCODE = 'P0001';
  END IF;
  IF acct.active_from > now() THEN
    RAISE EXCEPTION 'payout destination % is still within its change cool-off (active from %)',
      NEW.payout_account_id, acct.active_from USING ERRCODE = 'P0001';
  END IF;

  SELECT status, kyc_status, provider_account_status INTO slr FROM sellers WHERE id = NEW.seller_id;
  IF slr.kyc_status <> 'verified' THEN
    RAISE EXCEPTION 'seller % is not KYC verified and cannot be paid', NEW.seller_id USING ERRCODE = 'P0001';
  END IF;
  IF slr.status NOT IN ('active','restricted') THEN
    RAISE EXCEPTION 'seller % is % and cannot be paid', NEW.seller_id, slr.status USING ERRCODE = 'P0001';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER payouts_destination_guard
  BEFORE INSERT ON payouts
  FOR EACH ROW EXECUTE FUNCTION payouts_destination_guard();

-- ---------------------------------------------------------------------------
-- Settlement offsets
--
-- The wallet-free answer to a negative balance. A refund or a lost chargeback
-- on an already-settled sale creates an offset that is netted out of the
-- seller's NEXT settlement. No internal debit balance is ever created, which is
-- precisely what keeps the platform outside payment-aggregator territory.
-- ---------------------------------------------------------------------------

CREATE TABLE settlement_offsets (
  id             UUID PRIMARY KEY,
  public_id      public_id NOT NULL UNIQUE,
  seller_id      UUID NOT NULL REFERENCES sellers (id) ON DELETE RESTRICT,
  origin         TEXT NOT NULL CHECK (origin IN ('refund','chargeback','fee_correction','manual_adjustment')),
  origin_id      UUID,
  amount_minor   money_minor NOT NULL CHECK (amount_minor > 0),
  applied_minor  money_minor NOT NULL DEFAULT 0 CHECK (applied_minor >= 0),
  currency       currency_code NOT NULL,
  status         TEXT NOT NULL DEFAULT 'outstanding'
                   CHECK (status IN ('outstanding','partially_applied','settled','written_off')),
  note           TEXT,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT settlement_offsets_applied_within_amount CHECK (applied_minor <= amount_minor)
);

CREATE INDEX settlement_offsets_seller_idx ON settlement_offsets (seller_id)
  WHERE status IN ('outstanding','partially_applied');

CREATE TRIGGER settlement_offsets_set_updated_at BEFORE UPDATE ON settlement_offsets
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();
