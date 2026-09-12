-- 0003_sellers.sql
-- Seller onboarding, KYC/KYB gating, payout destinations and the turnover
-- tracking that drives both GST registration relief and s.194-O thresholds.

CREATE TABLE sellers (
  id                    UUID PRIMARY KEY,
  public_id             public_id NOT NULL UNIQUE,
  user_id               UUID NOT NULL UNIQUE REFERENCES users (id) ON DELETE RESTRICT,
  handle                TEXT NOT NULL UNIQUE CHECK (handle ~ '^[a-z0-9][a-z0-9_-]{2,31}$'),
  display_name          TEXT NOT NULL CHECK (length(display_name) BETWEEN 2 AND 120),
  bio                   TEXT CHECK (bio IS NULL OR length(bio) <= 2000),

  -- Legal identity. Held encrypted under the seller's subject key; the plain
  -- columns are only those a tax return legitimately needs in the clear.
  legal_name_ciphertext BYTEA,
  entity_type           TEXT NOT NULL DEFAULT 'individual'
                          CHECK (entity_type IN ('individual','huf','proprietorship','partnership','llp','private_limited','public_limited','trust','society','foreign')),
  country               CHAR(2) NOT NULL DEFAULT 'IN' CHECK (country ~ '^[A-Z]{2}$'),
  state_code            SMALLINT CHECK (state_code IS NULL OR state_code BETWEEN 1 AND 99),
  pan                   CHAR(10) CHECK (pan IS NULL OR pan ~ '^[A-Z]{5}[0-9]{4}[A-Z]$'),
  gstin                 CHAR(15) CHECK (gstin IS NULL OR gstin ~ '^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][0-9A-Z]Z[0-9A-Z]$'),
  gst_registered        BOOLEAN NOT NULL DEFAULT FALSE,

  -- KYC/KYB. Publishing and settlement are gated on this independently:
  -- a seller may list while KYB is pending but cannot be paid.
  kyc_status            TEXT NOT NULL DEFAULT 'unverified'
                          CHECK (kyc_status IN ('unverified','submitted','under_review','verified','rejected','expired')),
  kyc_verified_at       TIMESTAMPTZ,
  kyc_rejected_reason   TEXT,
  -- DSA Article 30 trader traceability: retained for six months after the
  -- relationship ends, which trader_verification_expires_at records.
  trader_verified_at    TIMESTAMPTZ,
  trader_verification_expires_at TIMESTAMPTZ,

  -- Provider linkage. A Route linked account is only usable once the provider
  -- reports its own KYC as activated; transfers to a non-activated account can
  -- fail or hold funds, so settlement checks this column, not ours.
  provider              TEXT CHECK (provider IN ('razorpay_route','bridge','mor')),
  provider_account_id   TEXT,
  provider_account_status TEXT NOT NULL DEFAULT 'none'
                          CHECK (provider_account_status IN ('none','created','needs_clarification','under_review','activated','suspended')),
  provider_account_activated_at TIMESTAMPTZ,

  settlement_hold_days  SMALLINT NOT NULL DEFAULT 14 CHECK (settlement_hold_days BETWEEN 0 AND 180),
  rolling_reserve_bps   basis_points NOT NULL DEFAULT 500,
  rolling_reserve_days  SMALLINT NOT NULL DEFAULT 90 CHECK (rolling_reserve_days BETWEEN 0 AND 365),

  status                TEXT NOT NULL DEFAULT 'pending'
                          CHECK (status IN ('pending','active','restricted','suspended','closed')),
  suspension_reason     TEXT,
  -- Chargeback exposure drives automatic tightening; see docs/runbooks.
  chargeback_count_90d  INTEGER NOT NULL DEFAULT 0,
  order_count_90d       INTEGER NOT NULL DEFAULT 0,

  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),

  -- A GST-registered seller must supply a GSTIN; the platform verifies the
  -- GSTIN before listing because TCS collected from an unregistered vendor is
  -- exactly what GST-department analytics flags.
  CONSTRAINT sellers_gstin_required_when_registered
    CHECK (NOT gst_registered OR gstin IS NOT NULL),
  -- An activated provider account must name which provider it belongs to.
  CONSTRAINT sellers_provider_consistency
    CHECK (provider_account_status = 'none' OR (provider IS NOT NULL AND provider_account_id IS NOT NULL))
);

CREATE INDEX sellers_status_idx   ON sellers (status);
CREATE INDEX sellers_kyc_idx      ON sellers (kyc_status) WHERE kyc_status <> 'verified';
CREATE INDEX sellers_provider_idx ON sellers (provider, provider_account_id);
CREATE UNIQUE INDEX sellers_gstin_uq ON sellers (gstin) WHERE gstin IS NOT NULL;

CREATE TRIGGER sellers_set_updated_at BEFORE UPDATE ON sellers
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER sellers_immutable_core BEFORE UPDATE ON sellers
  FOR EACH ROW EXECUTE FUNCTION forbid_update_of_columns('id', 'public_id', 'user_id', 'created_at');

-- ---------------------------------------------------------------------------
-- Payout destinations
--
-- Bank details are encrypted under the seller's subject key. A destination is
-- unusable until penny-drop validation confirms the beneficiary name, which is
-- what stops a typo'd or hijacked account silently receiving settlements.
-- ---------------------------------------------------------------------------

CREATE TABLE seller_payout_accounts (
  id                    UUID PRIMARY KEY,
  seller_id             UUID NOT NULL REFERENCES sellers (id) ON DELETE CASCADE,
  method                TEXT NOT NULL DEFAULT 'bank_account' CHECK (method IN ('bank_account','vpa')),
  account_ciphertext    BYTEA NOT NULL,
  ifsc                  CHAR(11) CHECK (ifsc IS NULL OR ifsc ~ '^[A-Z]{4}0[A-Z0-9]{6}$'),
  account_last4         CHAR(4),
  beneficiary_name_ciphertext BYTEA,
  fingerprint           sha256_digest NOT NULL,

  validation_status     TEXT NOT NULL DEFAULT 'pending'
                          CHECK (validation_status IN ('pending','in_progress','validated','failed')),
  validation_method     TEXT CHECK (validation_method IN ('penny_drop','provider_fund_account','manual')),
  validated_at          TIMESTAMPTZ,
  validation_reference  TEXT,
  validation_failure    TEXT,
  name_match_score      SMALLINT CHECK (name_match_score IS NULL OR name_match_score BETWEEN 0 AND 100),

  provider_fund_account_id TEXT,
  is_default            BOOLEAN NOT NULL DEFAULT FALSE,
  -- A newly added or changed destination is quarantined: settlements continue
  -- to the previous validated account until the cool-off elapses. This is the
  -- control that blunts account-takeover payout redirection.
  active_from           TIMESTAMPTZ NOT NULL DEFAULT now() + INTERVAL '48 hours',
  disabled_at           TIMESTAMPTZ,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX seller_payout_accounts_default_uq
  ON seller_payout_accounts (seller_id) WHERE is_default AND disabled_at IS NULL;
CREATE UNIQUE INDEX seller_payout_accounts_fingerprint_uq
  ON seller_payout_accounts (seller_id, fingerprint) WHERE disabled_at IS NULL;
CREATE INDEX seller_payout_accounts_seller_idx ON seller_payout_accounts (seller_id);

CREATE TRIGGER seller_payout_accounts_set_updated_at BEFORE UPDATE ON seller_payout_accounts
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- KYC documents
-- ---------------------------------------------------------------------------

CREATE TABLE seller_documents (
  id            UUID PRIMARY KEY,
  seller_id     UUID NOT NULL REFERENCES sellers (id) ON DELETE CASCADE,
  kind          TEXT NOT NULL CHECK (kind IN
                  ('pan_card','gst_certificate','address_proof','bank_statement','incorporation_certificate','identity_proof','authorised_signatory')),
  object_key    TEXT NOT NULL,
  content_type  TEXT NOT NULL,
  size_bytes    BIGINT NOT NULL CHECK (size_bytes > 0),
  checksum      sha256_digest NOT NULL,
  scan_status   TEXT NOT NULL DEFAULT 'pending' CHECK (scan_status IN ('pending','clean','infected','error')),
  review_status TEXT NOT NULL DEFAULT 'pending' CHECK (review_status IN ('pending','accepted','rejected')),
  reviewed_by   UUID REFERENCES users (id),
  reviewed_at   TIMESTAMPTZ,
  review_note   TEXT,
  -- Retention: KYC evidence is purged on this schedule unless a legal hold
  -- applies. The column makes the policy executable rather than aspirational.
  purge_after   TIMESTAMPTZ NOT NULL DEFAULT now() + INTERVAL '8 years',
  legal_hold    BOOLEAN NOT NULL DEFAULT FALSE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX seller_documents_seller_idx ON seller_documents (seller_id, kind);
CREATE INDEX seller_documents_review_idx ON seller_documents (review_status) WHERE review_status = 'pending';
CREATE INDEX seller_documents_purge_idx  ON seller_documents (purge_after) WHERE NOT legal_hold;

-- ---------------------------------------------------------------------------
-- Turnover tracking
--
-- Two distinct regimes read this table:
--   * GST: services suppliers below the aggregate-turnover threshold are
--     relieved from compulsory ECO registration (Notification 65/2017 as
--     amended), so the platform must know each seller's running total.
--   * Income tax: s.194-O carries a threshold for resident Individual/HUF
--     sellers, below which no TDS is deducted for the financial year.
--
-- Indian financial years run April to March, which fy_start encodes.
-- ---------------------------------------------------------------------------

CREATE TABLE seller_turnover (
  seller_id        UUID NOT NULL REFERENCES sellers (id) ON DELETE CASCADE,
  fy_start         DATE NOT NULL,
  currency         currency_code NOT NULL DEFAULT 'INR',
  gross_supply     money_minor NOT NULL DEFAULT 0 CHECK (gross_supply >= 0),
  taxable_supply   money_minor NOT NULL DEFAULT 0 CHECK (taxable_supply >= 0),
  tds_deducted     money_minor NOT NULL DEFAULT 0 CHECK (tds_deducted >= 0),
  tcs_collected    money_minor NOT NULL DEFAULT 0 CHECK (tcs_collected >= 0),
  order_count      INTEGER NOT NULL DEFAULT 0 CHECK (order_count >= 0),
  refunded_amount  money_minor NOT NULL DEFAULT 0 CHECK (refunded_amount >= 0),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (seller_id, fy_start, currency),
  CONSTRAINT seller_turnover_fy_starts_in_april CHECK (EXTRACT(MONTH FROM fy_start) = 4 AND EXTRACT(DAY FROM fy_start) = 1)
);

CREATE INDEX seller_turnover_fy_idx ON seller_turnover (fy_start, gross_supply DESC);

-- ---------------------------------------------------------------------------
-- Platform turnover
--
-- Route activation requires evidence of domestic turnover above a threshold in
-- the current or preceding financial year. The platform tracks its own figure
-- so that the payment adapter can be switched on the basis of data rather than
-- of someone remembering to check.
-- ---------------------------------------------------------------------------

CREATE TABLE platform_turnover (
  fy_start        DATE PRIMARY KEY,
  currency        currency_code NOT NULL DEFAULT 'INR',
  domestic_gmv    money_minor NOT NULL DEFAULT 0 CHECK (domestic_gmv >= 0),
  export_gmv      money_minor NOT NULL DEFAULT 0 CHECK (export_gmv >= 0),
  commission_income money_minor NOT NULL DEFAULT 0 CHECK (commission_income >= 0),
  order_count     INTEGER NOT NULL DEFAULT 0,
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT platform_turnover_fy_starts_in_april CHECK (EXTRACT(MONTH FROM fy_start) = 4 AND EXTRACT(DAY FROM fy_start) = 1)
);
