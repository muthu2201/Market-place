-- 0008_compliance_ranking.sql
-- Grievance redressal, data-subject rights, takedowns, cross-border reporting,
-- the published ranking state, and notification delivery.

-- ---------------------------------------------------------------------------
-- Grievance redressal
--
-- Consumer Protection (E-Commerce) Rules 2020 and the IT Rules 2021 both impose
-- hard clocks: acknowledge within 24 hours, resolve within 15 days. The clocks
-- are stored as columns so that a breach is a query, not a discovery.
-- ---------------------------------------------------------------------------

CREATE TABLE grievances (
  id              UUID PRIMARY KEY,
  public_id       public_id NOT NULL UNIQUE,
  ticket_number   TEXT NOT NULL UNIQUE,
  complainant_id  UUID REFERENCES users (id) ON DELETE SET NULL,
  complainant_email_ciphertext BYTEA,
  category        TEXT NOT NULL CHECK (category IN
                    ('order','delivery','refund','seller_conduct','content','privacy','copyright','accessibility','other')),
  subject         TEXT NOT NULL CHECK (length(subject) BETWEEN 3 AND 200),
  body            TEXT NOT NULL CHECK (length(body) BETWEEN 10 AND 10000),
  related_order_id UUID REFERENCES orders (id) ON DELETE SET NULL,
  related_product_id UUID REFERENCES products (id) ON DELETE SET NULL,

  status          TEXT NOT NULL DEFAULT 'received'
                    CHECK (status IN ('received','acknowledged','in_progress','resolved','closed','escalated')),
  received_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  acknowledge_by  TIMESTAMPTZ NOT NULL,
  acknowledged_at TIMESTAMPTZ,
  resolve_by      TIMESTAMPTZ NOT NULL,
  resolved_at     TIMESTAMPTZ,
  resolution      TEXT,
  assigned_to     UUID REFERENCES users (id),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX grievances_open_idx ON grievances (status, acknowledge_by)
  WHERE status IN ('received','acknowledged','in_progress','escalated');
CREATE INDEX grievances_breach_idx ON grievances (resolve_by)
  WHERE resolved_at IS NULL;
CREATE INDEX grievances_user_idx ON grievances (complainant_id, created_at DESC);

CREATE TRIGGER grievances_set_updated_at BEFORE UPDATE ON grievances
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE OR REPLACE VIEW grievance_sla_breaches AS
SELECT id, public_id, ticket_number, status, received_at,
       acknowledge_by, acknowledged_at, resolve_by,
       (acknowledged_at IS NULL AND now() > acknowledge_by) AS ack_breached,
       (resolved_at IS NULL AND now() > resolve_by)         AS resolution_breached
FROM grievances
WHERE (acknowledged_at IS NULL AND now() > acknowledge_by)
   OR (resolved_at IS NULL AND now() > resolve_by);

-- ---------------------------------------------------------------------------
-- Data-subject rights (DPDP Act 2023 / GDPR where applicable)
-- ---------------------------------------------------------------------------

CREATE TABLE dsar_requests (
  id             UUID PRIMARY KEY,
  public_id      public_id NOT NULL UNIQUE,
  user_id        UUID NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
  kind           TEXT NOT NULL CHECK (kind IN ('access','correction','erasure','portability','consent_withdrawal','grievance')),
  status         TEXT NOT NULL DEFAULT 'received'
                   CHECK (status IN ('received','identity_verified','in_progress','completed','rejected','partially_completed')),
  -- Erasure cannot be unconditional: tax law requires financial records to be
  -- retained. The response is crypto-shredding plus a documented explanation of
  -- exactly what survives and why.
  retention_basis TEXT,
  requested_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  respond_by     TIMESTAMPTZ NOT NULL,
  completed_at   TIMESTAMPTZ,
  export_object_key TEXT,
  rejection_reason TEXT,
  handled_by     UUID REFERENCES users (id),
  notes          TEXT
);

CREATE INDEX dsar_requests_open_idx ON dsar_requests (respond_by) WHERE completed_at IS NULL;
CREATE INDEX dsar_requests_user_idx ON dsar_requests (user_id, requested_at DESC);

-- ---------------------------------------------------------------------------
-- Copyright takedown (Copyright Rules 2013 / DMCA-style for global phase)
-- ---------------------------------------------------------------------------

CREATE TABLE takedown_notices (
  id               UUID PRIMARY KEY,
  public_id        public_id NOT NULL UNIQUE,
  regime           TEXT NOT NULL DEFAULT 'in_copyright_rules_2013'
                     CHECK (regime IN ('in_copyright_rules_2013','us_dmca','eu_dsa','other')),
  product_id       UUID REFERENCES products (id) ON DELETE SET NULL,
  asset_id         UUID REFERENCES product_assets (id) ON DELETE SET NULL,
  complainant_name TEXT NOT NULL,
  complainant_email_ciphertext BYTEA NOT NULL,
  work_description TEXT NOT NULL CHECK (length(work_description) BETWEEN 10 AND 5000),
  -- Rule 75 of the Copyright Rules requires the notice to describe the work,
  -- assert ownership and undertake to pursue the matter; without those the
  -- notice is not actionable and the flag records that decision.
  sworn_statement  BOOLEAN NOT NULL DEFAULT FALSE,
  status           TEXT NOT NULL DEFAULT 'received'
                     CHECK (status IN ('received','valid','invalid','content_disabled','counter_notice_received','restored','escalated')),
  -- Copyright Rules 2013 disable access for 21 days pending a court order.
  disable_until    TIMESTAMPTZ,
  received_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  actioned_at      TIMESTAMPTZ,
  counter_notice   TEXT,
  counter_notice_at TIMESTAMPTZ,
  decided_by       UUID REFERENCES users (id),
  notes            TEXT
);

CREATE INDEX takedown_notices_status_idx  ON takedown_notices (status, received_at DESC);
CREATE INDEX takedown_notices_product_idx ON takedown_notices (product_id);
CREATE INDEX takedown_notices_expiry_idx  ON takedown_notices (disable_until) WHERE status = 'content_disabled';

-- ---------------------------------------------------------------------------
-- Cross-border seller reporting (DAC7) and trader traceability (DSA Art. 30)
-- ---------------------------------------------------------------------------

CREATE TABLE dac7_reports (
  id            UUID PRIMARY KEY,
  reporting_year SMALLINT NOT NULL,
  member_state  CHAR(2) NOT NULL,
  status        TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','submitted','accepted','corrected')),
  seller_count  INTEGER NOT NULL DEFAULT 0,
  submitted_at  TIMESTAMPTZ,
  due_on        DATE NOT NULL,
  reference     TEXT,
  UNIQUE (reporting_year, member_state)
);

CREATE TABLE dac7_report_lines (
  id             UUID PRIMARY KEY,
  report_id      UUID NOT NULL REFERENCES dac7_reports (id) ON DELETE CASCADE,
  seller_id      UUID NOT NULL REFERENCES sellers (id) ON DELETE RESTRICT,
  residence      CHAR(2) NOT NULL,
  tin_ciphertext BYTEA,
  consideration_minor money_minor NOT NULL DEFAULT 0,
  fees_minor     money_minor NOT NULL DEFAULT 0,
  transaction_count INTEGER NOT NULL DEFAULT 0,
  currency       currency_code NOT NULL DEFAULT 'EUR',
  UNIQUE (report_id, seller_id)
);

-- ---------------------------------------------------------------------------
-- Ranking
--
-- The formula is published verbatim and the inputs are stored, so any listing's
-- position can be explained to its seller. That satisfies EU P2B Article 5, the
-- DSA and the Indian CP (E-Commerce) Rules prohibition on manipulating search
-- results, and it is also simply the honest thing to do.
-- ---------------------------------------------------------------------------

CREATE TABLE ranking_state (
  product_id          UUID PRIMARY KEY REFERENCES products (id) ON DELETE CASCADE,
  seller_id           UUID NOT NULL REFERENCES sellers (id) ON DELETE CASCADE,
  -- Component inputs, each independently explainable.
  age_hours           INTEGER NOT NULL DEFAULT 0,
  recency_score       INTEGER NOT NULL DEFAULT 0 CHECK (recency_score BETWEEN 0 AND 1000000),
  quality_gate_passed BOOLEAN NOT NULL DEFAULT FALSE,
  quality_failures    TEXT[] NOT NULL DEFAULT '{}',
  exposure_rank       SMALLINT NOT NULL DEFAULT 1 CHECK (exposure_rank >= 1),
  exposure_factor_bps basis_points NOT NULL DEFAULT 10000,
  band                SMALLINT NOT NULL DEFAULT 0,
  final_score         INTEGER NOT NULL DEFAULT 0,
  computed_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  formula_version     TEXT NOT NULL DEFAULT 'v1'
);

CREATE INDEX ranking_state_score_idx  ON ranking_state (final_score DESC, product_id);
CREATE INDEX ranking_state_seller_idx ON ranking_state (seller_id, final_score DESC);

-- The rotating seed used for within-band shuffling. It is published so that
-- ordering is reproducible by anyone, which is the point: a random tie-break
-- that nobody can verify is indistinguishable from a thumb on the scale.
CREATE TABLE ranking_seeds (
  effective_from TIMESTAMPTZ PRIMARY KEY,
  seed           BIGINT NOT NULL,
  published_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Notifications
-- ---------------------------------------------------------------------------

CREATE TABLE notifications (
  id            UUID PRIMARY KEY,
  public_id     public_id NOT NULL UNIQUE,
  user_id       UUID REFERENCES users (id) ON DELETE CASCADE,
  channel       TEXT NOT NULL CHECK (channel IN ('email','in_app')),
  template      TEXT NOT NULL,
  -- The rendered subject and body are not stored; only the variables needed to
  -- re-render are, and those are already PII-minimal.
  variables     JSONB NOT NULL DEFAULT '{}'::jsonb,
  to_ciphertext BYTEA,
  status        TEXT NOT NULL DEFAULT 'queued'
                  CHECK (status IN ('queued','sent','delivered','bounced','complained','failed','suppressed')),
  provider_message_id TEXT,
  attempts      INTEGER NOT NULL DEFAULT 0,
  last_error    TEXT,
  -- Transactional mail is never subject to marketing consent; marketing mail
  -- always is. The column makes that distinction enforceable.
  category      TEXT NOT NULL DEFAULT 'transactional' CHECK (category IN ('transactional','marketing')),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  sent_at       TIMESTAMPTZ
);

CREATE INDEX notifications_user_idx    ON notifications (user_id, created_at DESC);
CREATE INDEX notifications_pending_idx ON notifications (created_at) WHERE status = 'queued';

CREATE TABLE email_suppressions (
  email_index  email_blind_index PRIMARY KEY,
  reason       TEXT NOT NULL CHECK (reason IN ('hard_bounce','complaint','manual','unsubscribed')),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Fee schedule and the public fee covenant
--
-- The commission a seller is charged is the one that was in force when they
-- joined, unless they opt into a newer schedule. Grandfathering is implemented
-- in data so that the published covenant is a property of the system rather
-- than a promise on a marketing page.
-- ---------------------------------------------------------------------------

CREATE TABLE fee_schedules (
  id              UUID PRIMARY KEY,
  code            TEXT NOT NULL UNIQUE,
  commission_bps  basis_points NOT NULL,
  fixed_fee_minor money_minor NOT NULL DEFAULT 0 CHECK (fixed_fee_minor >= 0),
  currency        currency_code NOT NULL DEFAULT 'INR',
  description     TEXT NOT NULL,
  effective_from  TIMESTAMPTZ NOT NULL,
  -- 90 days' notice is the covenant. A schedule cannot become effective sooner
  -- than that after being announced.
  announced_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  superseded_at   TIMESTAMPTZ,
  CONSTRAINT fee_schedules_ninety_day_notice
    CHECK (effective_from >= announced_at + INTERVAL '90 days' OR code = 'launch')
);

CREATE TABLE seller_fee_assignments (
  seller_id       UUID NOT NULL REFERENCES sellers (id) ON DELETE CASCADE,
  fee_schedule_id UUID NOT NULL REFERENCES fee_schedules (id) ON DELETE RESTRICT,
  assigned_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  effective_from  TIMESTAMPTZ NOT NULL DEFAULT now(),
  effective_to    TIMESTAMPTZ,
  opted_in        BOOLEAN NOT NULL DEFAULT FALSE,
  PRIMARY KEY (seller_id, fee_schedule_id, effective_from)
);

CREATE INDEX seller_fee_assignments_active_idx
  ON seller_fee_assignments (seller_id, effective_from DESC);

INSERT INTO fee_schedules (id, code, commission_bps, description, effective_from, announced_at)
VALUES (gen_random_uuid(), 'launch', 900,
        'Launch schedule: a flat all-in 9.00% commission. Payment-processing cost and statutory tax are itemised separately and passed through at cost.',
        now(), now());
