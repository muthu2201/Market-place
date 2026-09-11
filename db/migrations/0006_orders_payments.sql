-- 0006_orders_payments.sql
-- Orders, the order state machine, payments, transfers, refunds, chargebacks
-- and provider webhook de-duplication.

-- ---------------------------------------------------------------------------
-- Orders
--
-- Every monetary figure is stored as a snapshot taken at checkout. A later
-- change to a price, a commission rate or a tax rate must never retroactively
-- alter an order that has already been placed.
-- ---------------------------------------------------------------------------

CREATE TABLE orders (
  id                   UUID PRIMARY KEY,
  public_id            public_id NOT NULL UNIQUE,
  order_number         TEXT NOT NULL UNIQUE,
  buyer_id             UUID NOT NULL REFERENCES users (id) ON DELETE RESTRICT,

  status               TEXT NOT NULL DEFAULT 'draft' CHECK (status IN (
                         'draft','awaiting_payment','payment_failed','paid','fulfilled',
                         'completed','cancelled','expired','refund_pending','partially_refunded',
                         'refunded','disputed','chargeback_lost')),

  currency             currency_code NOT NULL,
  -- The buyer-facing total, and the components that make it up. gross =
  -- items + tax collected from the buyer.
  items_subtotal_minor money_minor NOT NULL DEFAULT 0 CHECK (items_subtotal_minor >= 0),
  tax_total_minor      money_minor NOT NULL DEFAULT 0 CHECK (tax_total_minor >= 0),
  grand_total_minor    money_minor NOT NULL DEFAULT 0 CHECK (grand_total_minor >= 0),
  refunded_total_minor money_minor NOT NULL DEFAULT 0 CHECK (refunded_total_minor >= 0),

  -- Place of supply decides CGST+SGST versus IGST, and for a non-resident
  -- buyer decides whether the supply is an export of services.
  place_of_supply_country CHAR(2) NOT NULL DEFAULT 'IN' CHECK (place_of_supply_country ~ '^[A-Z]{2}$'),
  place_of_supply_state   SMALLINT CHECK (place_of_supply_state IS NULL OR place_of_supply_state BETWEEN 1 AND 99),
  buyer_gstin          CHAR(15),
  is_b2b               BOOLEAN NOT NULL DEFAULT FALSE,

  buyer_ip             INET,
  buyer_country_signal CHAR(2),

  placed_at            TIMESTAMPTZ,
  paid_at              TIMESTAMPTZ,
  fulfilled_at         TIMESTAMPTZ,
  completed_at         TIMESTAMPTZ,
  cancelled_at         TIMESTAMPTZ,
  expires_at           TIMESTAMPTZ,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT orders_total_is_consistent
    CHECK (grand_total_minor = items_subtotal_minor + tax_total_minor),
  CONSTRAINT orders_refund_within_total
    CHECK (refunded_total_minor <= grand_total_minor),
  CONSTRAINT orders_paid_has_timestamp
    CHECK (status NOT IN ('paid','fulfilled','completed') OR paid_at IS NOT NULL),
  CONSTRAINT orders_b2b_has_gstin
    CHECK (NOT is_b2b OR buyer_gstin IS NOT NULL),
  CONSTRAINT orders_domestic_has_state
    CHECK (place_of_supply_country <> 'IN' OR place_of_supply_state IS NOT NULL)
);

CREATE INDEX orders_buyer_idx   ON orders (buyer_id, created_at DESC);
CREATE INDEX orders_status_idx  ON orders (status, created_at DESC);
CREATE INDEX orders_paid_idx    ON orders (paid_at DESC) WHERE paid_at IS NOT NULL;
CREATE INDEX orders_expiry_idx  ON orders (expires_at) WHERE status IN ('draft','awaiting_payment');

CREATE TRIGGER orders_set_updated_at BEFORE UPDATE ON orders
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER orders_immutable_core BEFORE UPDATE ON orders
  FOR EACH ROW EXECUTE FUNCTION forbid_update_of_columns('id','public_id','order_number','buyer_id','currency','created_at');

-- The state machine, expressed as data rather than as scattered application
-- conditionals, and enforced by the database so that no code path can skip it.
CREATE TABLE order_transitions_allowed (
  from_status TEXT NOT NULL,
  to_status   TEXT NOT NULL,
  note        TEXT NOT NULL,
  PRIMARY KEY (from_status, to_status)
);

INSERT INTO order_transitions_allowed (from_status, to_status, note) VALUES
  ('draft','awaiting_payment','Checkout created a payment intent.'),
  ('draft','cancelled','Buyer abandoned before payment.'),
  ('draft','expired','Draft aged out.'),
  ('awaiting_payment','paid','Provider confirmed capture and the signature verified.'),
  ('awaiting_payment','payment_failed','Provider reported failure.'),
  ('awaiting_payment','cancelled','Buyer cancelled before capture.'),
  ('awaiting_payment','expired','Payment window elapsed.'),
  ('payment_failed','awaiting_payment','Buyer retried payment.'),
  ('payment_failed','cancelled','Buyer gave up.'),
  ('paid','fulfilled','Entitlements were issued.'),
  ('paid','refund_pending','Refund requested before fulfilment.'),
  ('paid','disputed','Provider raised a dispute or chargeback.'),
  ('fulfilled','completed','Protection window elapsed with no dispute.'),
  ('fulfilled','refund_pending','Refund requested after fulfilment.'),
  ('fulfilled','disputed','Provider raised a dispute or chargeback.'),
  ('completed','refund_pending','Goodwill refund after completion.'),
  ('completed','disputed','Late chargeback.'),
  ('refund_pending','refunded','Full refund settled.'),
  ('refund_pending','partially_refunded','Partial refund settled.'),
  ('refund_pending','fulfilled','Refund request withdrawn or declined.'),
  ('partially_refunded','refund_pending','A further refund was requested.'),
  ('partially_refunded','refunded','Remaining balance refunded.'),
  ('partially_refunded','disputed','Dispute raised after a partial refund.'),
  ('disputed','chargeback_lost','Representment failed; the acquirer debited the payment.'),
  ('disputed','fulfilled','Representment succeeded; the order stands.'),
  ('disputed','refunded','Settled by refunding the buyer.');

CREATE OR REPLACE FUNCTION orders_enforce_state_machine() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.status = OLD.status THEN
    RETURN NEW;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM order_transitions_allowed
    WHERE from_status = OLD.status AND to_status = NEW.status
  ) THEN
    RAISE EXCEPTION 'order % cannot move from % to %', NEW.id, OLD.status, NEW.status
      USING ERRCODE = 'P0001',
            HINT = 'Permitted transitions are listed in order_transitions_allowed.';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER orders_state_machine
  BEFORE UPDATE OF status ON orders
  FOR EACH ROW EXECUTE FUNCTION orders_enforce_state_machine();

CREATE TABLE order_events (
  id          BIGSERIAL PRIMARY KEY,
  order_id    UUID NOT NULL REFERENCES orders (id) ON DELETE CASCADE,
  from_status TEXT,
  to_status   TEXT NOT NULL,
  actor_kind  TEXT NOT NULL CHECK (actor_kind IN ('user','seller','admin','system','provider')),
  actor_id    UUID,
  reason      TEXT,
  metadata    JSONB NOT NULL DEFAULT '{}'::jsonb,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX order_events_order_idx ON order_events (order_id, id);

CREATE TRIGGER order_events_append_only
  BEFORE UPDATE OR DELETE ON order_events
  FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

-- ---------------------------------------------------------------------------
-- Order items: the per-seller, per-product economics
--
-- This is where the money actually decomposes. Every figure is a snapshot and
-- the row is frozen the moment the order is paid.
-- ---------------------------------------------------------------------------

CREATE TABLE order_items (
  id                    UUID PRIMARY KEY,
  public_id             public_id NOT NULL UNIQUE,
  order_id              UUID NOT NULL REFERENCES orders (id) ON DELETE CASCADE,
  product_id            UUID NOT NULL REFERENCES products (id) ON DELETE RESTRICT,
  variant_id            UUID NOT NULL REFERENCES product_variants (id) ON DELETE RESTRICT,
  seller_id             UUID NOT NULL REFERENCES sellers (id) ON DELETE RESTRICT,

  -- Snapshots taken at checkout so the record survives catalogue edits.
  title_snapshot        TEXT NOT NULL,
  license_type_snapshot TEXT NOT NULL,
  license_terms_snapshot TEXT NOT NULL,
  refund_policy_snapshot TEXT NOT NULL,
  seller_gstin_snapshot  CHAR(15),
  seller_pan_snapshot    CHAR(10),
  seller_state_snapshot  SMALLINT,

  currency              currency_code NOT NULL,
  quantity              SMALLINT NOT NULL DEFAULT 1 CHECK (quantity = 1),

  -- Buyer-facing
  unit_price_minor      money_minor NOT NULL CHECK (unit_price_minor >= 0),
  line_total_minor      money_minor NOT NULL CHECK (line_total_minor >= 0),
  gst_rate_bps          basis_points NOT NULL DEFAULT 1800,
  cgst_minor            money_minor NOT NULL DEFAULT 0 CHECK (cgst_minor >= 0),
  sgst_minor            money_minor NOT NULL DEFAULT 0 CHECK (sgst_minor >= 0),
  igst_minor            money_minor NOT NULL DEFAULT 0 CHECK (igst_minor >= 0),
  tax_total_minor       money_minor NOT NULL DEFAULT 0 CHECK (tax_total_minor >= 0),
  buyer_total_minor     money_minor NOT NULL CHECK (buyer_total_minor >= 0),

  -- Platform economics
  commission_bps        basis_points NOT NULL,
  commission_minor      money_minor NOT NULL DEFAULT 0 CHECK (commission_minor >= 0),
  commission_gst_minor  money_minor NOT NULL DEFAULT 0 CHECK (commission_gst_minor >= 0),

  -- Statutory collections. TCS under s.52 CGST and TDS under s.194-O apply to
  -- the same transaction through different ledgers and are never netted.
  tcs_bps               basis_points NOT NULL DEFAULT 0,
  tcs_minor             money_minor NOT NULL DEFAULT 0 CHECK (tcs_minor >= 0),
  tds_bps               basis_points NOT NULL DEFAULT 0,
  tds_minor             money_minor NOT NULL DEFAULT 0 CHECK (tds_minor >= 0),

  -- Payment processing cost attributed to this line.
  psp_fee_minor         money_minor NOT NULL DEFAULT 0 CHECK (psp_fee_minor >= 0),
  psp_fee_gst_minor     money_minor NOT NULL DEFAULT 0 CHECK (psp_fee_gst_minor >= 0),

  -- What the seller is owed, after everything above.
  seller_net_minor      money_minor NOT NULL DEFAULT 0,

  refunded_minor        money_minor NOT NULL DEFAULT 0 CHECK (refunded_minor >= 0),
  status                TEXT NOT NULL DEFAULT 'pending'
                          CHECK (status IN ('pending','paid','fulfilled','refunded','partially_refunded','cancelled','charged_back')),
  fulfilled_at          TIMESTAMPTZ,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT order_items_tax_split_is_exclusive
    CHECK ((igst_minor = 0) OR (cgst_minor = 0 AND sgst_minor = 0)),
  CONSTRAINT order_items_tax_total_matches_components
    CHECK (tax_total_minor = cgst_minor + sgst_minor + igst_minor),
  CONSTRAINT order_items_intra_state_split_is_even
    CHECK (igst_minor > 0 OR cgst_minor = sgst_minor),
  CONSTRAINT order_items_buyer_total_matches
    CHECK (buyer_total_minor = line_total_minor + tax_total_minor),
  CONSTRAINT order_items_refund_within_total
    CHECK (refunded_minor <= buyer_total_minor)
);

CREATE INDEX order_items_order_idx   ON order_items (order_id);
CREATE INDEX order_items_seller_idx  ON order_items (seller_id, created_at DESC);
CREATE INDEX order_items_product_idx ON order_items (product_id, created_at DESC);

CREATE TRIGGER order_items_set_updated_at BEFORE UPDATE ON order_items
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Once money has moved, the economics of a line are history.
CREATE TRIGGER order_items_freeze_economics BEFORE UPDATE ON order_items
  FOR EACH ROW EXECUTE FUNCTION forbid_update_of_columns(
    'id','public_id','order_id','product_id','variant_id','seller_id','currency',
    'unit_price_minor','line_total_minor','tax_total_minor','buyer_total_minor',
    'commission_bps','commission_minor','commission_gst_minor',
    'tcs_bps','tcs_minor','tds_bps','tds_minor','seller_net_minor','created_at');

-- ---------------------------------------------------------------------------
-- Payments
-- ---------------------------------------------------------------------------

CREATE TABLE payment_intents (
  id                 UUID PRIMARY KEY,
  public_id          public_id NOT NULL UNIQUE,
  order_id           UUID NOT NULL REFERENCES orders (id) ON DELETE RESTRICT,
  provider           TEXT NOT NULL CHECK (provider IN ('razorpay_route','bridge','mor')),
  provider_intent_id TEXT,
  amount_minor       money_minor NOT NULL CHECK (amount_minor > 0),
  currency           currency_code NOT NULL,
  status             TEXT NOT NULL DEFAULT 'created'
                       CHECK (status IN ('created','requires_action','processing','succeeded','failed','cancelled','expired')),
  -- The split instruction sent to the provider, kept verbatim for reconciliation.
  split_instruction  JSONB NOT NULL DEFAULT '[]'::jsonb,
  client_secret_hash sha256_digest,
  failure_code       TEXT,
  failure_message    TEXT,
  expires_at         TIMESTAMPTZ,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX payment_intents_provider_uq ON payment_intents (provider, provider_intent_id)
  WHERE provider_intent_id IS NOT NULL;
CREATE INDEX payment_intents_order_idx ON payment_intents (order_id, created_at DESC);

CREATE TRIGGER payment_intents_set_updated_at BEFORE UPDATE ON payment_intents
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE payments (
  id                  UUID PRIMARY KEY,
  public_id           public_id NOT NULL UNIQUE,
  order_id            UUID NOT NULL REFERENCES orders (id) ON DELETE RESTRICT,
  intent_id           UUID REFERENCES payment_intents (id) ON DELETE RESTRICT,
  provider            TEXT NOT NULL,
  provider_payment_id TEXT NOT NULL,
  method              TEXT CHECK (method IN ('upi','card','netbanking','wallet','emi','paylater','international_card','unknown')),
  card_network        TEXT,
  amount_minor        money_minor NOT NULL CHECK (amount_minor > 0),
  currency            currency_code NOT NULL,
  -- The fee the provider actually charged, learned from settlement data rather
  -- than assumed. Until then it is NULL and reconciliation flags the gap.
  provider_fee_minor  money_minor CHECK (provider_fee_minor IS NULL OR provider_fee_minor >= 0),
  provider_tax_minor  money_minor CHECK (provider_tax_minor IS NULL OR provider_tax_minor >= 0),
  status              TEXT NOT NULL CHECK (status IN ('authorized','captured','failed','refunded','partially_refunded','disputed')),
  captured_at         TIMESTAMPTZ,
  -- Verified means: we recomputed the provider's HMAC over the documented
  -- payload and it matched. No payment is honoured without this.
  signature_verified  BOOLEAN NOT NULL DEFAULT FALSE,
  raw_provider_status TEXT,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT payments_captured_must_be_verified
    CHECK (status <> 'captured' OR signature_verified)
);

CREATE UNIQUE INDEX payments_provider_uq ON payments (provider, provider_payment_id);
CREATE INDEX payments_order_idx ON payments (order_id);
CREATE INDEX payments_captured_idx ON payments (captured_at DESC) WHERE status = 'captured';

CREATE TRIGGER payments_set_updated_at BEFORE UPDATE ON payments
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER payments_immutable_core BEFORE UPDATE ON payments
  FOR EACH ROW EXECUTE FUNCTION forbid_update_of_columns(
    'id','public_id','order_id','provider','provider_payment_id','amount_minor','currency','created_at');

-- ---------------------------------------------------------------------------
-- Transfers to sellers (split settlement)
-- ---------------------------------------------------------------------------

CREATE TABLE payment_transfers (
  id                   UUID PRIMARY KEY,
  public_id            public_id NOT NULL UNIQUE,
  payment_id           UUID NOT NULL REFERENCES payments (id) ON DELETE RESTRICT,
  order_item_id        UUID NOT NULL REFERENCES order_items (id) ON DELETE RESTRICT,
  seller_id            UUID NOT NULL REFERENCES sellers (id) ON DELETE RESTRICT,
  provider             TEXT NOT NULL,
  provider_transfer_id TEXT,
  provider_account_id  TEXT NOT NULL,
  amount_minor         money_minor NOT NULL CHECK (amount_minor > 0),
  currency             currency_code NOT NULL,
  status               TEXT NOT NULL DEFAULT 'pending'
                         CHECK (status IN ('pending','on_hold','created','processed','reversed','failed','cancelled')),
  -- Settlement is deliberately deferred. The hold is the wallet-free answer to
  -- "settled seller, then chargeback": funds simply have not moved yet.
  hold_until           TIMESTAMPTZ,
  released_at          TIMESTAMPTZ,
  reversed_amount_minor money_minor NOT NULL DEFAULT 0 CHECK (reversed_amount_minor >= 0),
  failure_code         TEXT,
  failure_message      TEXT,
  attempts             INTEGER NOT NULL DEFAULT 0,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT payment_transfers_reversal_within_amount
    CHECK (reversed_amount_minor <= amount_minor)
);

CREATE UNIQUE INDEX payment_transfers_provider_uq ON payment_transfers (provider, provider_transfer_id)
  WHERE provider_transfer_id IS NOT NULL;
CREATE UNIQUE INDEX payment_transfers_item_uq ON payment_transfers (order_item_id);
CREATE INDEX payment_transfers_seller_idx  ON payment_transfers (seller_id, created_at DESC);
CREATE INDEX payment_transfers_release_idx ON payment_transfers (hold_until) WHERE status = 'on_hold';

CREATE TRIGGER payment_transfers_set_updated_at BEFORE UPDATE ON payment_transfers
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- Refunds
-- ---------------------------------------------------------------------------

CREATE TABLE refunds (
  id                 UUID PRIMARY KEY,
  public_id          public_id NOT NULL UNIQUE,
  order_id           UUID NOT NULL REFERENCES orders (id) ON DELETE RESTRICT,
  order_item_id      UUID REFERENCES order_items (id) ON DELETE RESTRICT,
  payment_id         UUID NOT NULL REFERENCES payments (id) ON DELETE RESTRICT,
  provider           TEXT NOT NULL,
  provider_refund_id TEXT,
  amount_minor       money_minor NOT NULL CHECK (amount_minor > 0),
  currency           currency_code NOT NULL,
  reason             TEXT NOT NULL CHECK (reason IN
                       ('buyer_request','not_as_described','duplicate','fraud','seller_request',
                        'dispute_resolution','goodwill','failed_delivery','chargeback_preempt')),
  status             TEXT NOT NULL DEFAULT 'requested'
                       CHECK (status IN ('requested','approved','processing','succeeded','failed','rejected')),
  -- The processing fee is NOT returned by the network on a refund. The platform
  -- absorbs it, and recording it is what keeps unit economics honest.
  psp_fee_retained_minor money_minor NOT NULL DEFAULT 0 CHECK (psp_fee_retained_minor >= 0),
  -- Where the seller has already been settled, the reversal is taken from
  -- future settlement rather than by creating an internal debit balance.
  seller_recovery_mode TEXT NOT NULL DEFAULT 'transfer_reversal'
                       CHECK (seller_recovery_mode IN ('transfer_reversal','future_settlement_offset','platform_absorbed')),
  requested_by       UUID REFERENCES users (id),
  approved_by        UUID REFERENCES users (id),
  note               TEXT,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  settled_at         TIMESTAMPTZ
);

CREATE UNIQUE INDEX refunds_provider_uq ON refunds (provider, provider_refund_id) WHERE provider_refund_id IS NOT NULL;
CREATE INDEX refunds_order_idx  ON refunds (order_id, created_at DESC);
CREATE INDEX refunds_status_idx ON refunds (status) WHERE status IN ('requested','approved','processing');

CREATE TRIGGER refunds_set_updated_at BEFORE UPDATE ON refunds
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- Chargebacks
--
-- A card-network chargeback is NOT an in-app dispute: it has an externally
-- imposed representment deadline, it debits us whether or not we agree, and the
-- processing fee is not returned. It therefore gets its own table.
-- ---------------------------------------------------------------------------

CREATE TABLE chargebacks (
  id                    UUID PRIMARY KEY,
  public_id             public_id NOT NULL UNIQUE,
  order_id              UUID NOT NULL REFERENCES orders (id) ON DELETE RESTRICT,
  payment_id            UUID NOT NULL REFERENCES payments (id) ON DELETE RESTRICT,
  provider              TEXT NOT NULL,
  provider_dispute_id   TEXT NOT NULL,
  network               TEXT NOT NULL CHECK (network IN ('visa','mastercard','rupay','amex','diners','upi','other')),
  reason_code           TEXT,
  amount_minor          money_minor NOT NULL CHECK (amount_minor > 0),
  currency              currency_code NOT NULL,
  fee_minor             money_minor NOT NULL DEFAULT 0 CHECK (fee_minor >= 0),
  status                TEXT NOT NULL DEFAULT 'received'
                          CHECK (status IN ('received','evidence_required','evidence_submitted','won','lost','accepted','expired')),
  -- Representment windows tightened from 2026: Visa/Mastercard 10-14 calendar
  -- days in India, RuPay (NPCI RGCS) 7 working days. The deadline is stored
  -- per case because it is set by the network, not by us.
  respond_by            TIMESTAMPTZ NOT NULL,
  evidence_submitted_at TIMESTAMPTZ,
  evidence              JSONB NOT NULL DEFAULT '{}'::jsonb,
  resolved_at           TIMESTAMPTZ,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX chargebacks_provider_uq ON chargebacks (provider, provider_dispute_id);
CREATE INDEX chargebacks_deadline_idx ON chargebacks (respond_by) WHERE status IN ('received','evidence_required');
CREATE INDEX chargebacks_order_idx    ON chargebacks (order_id);

CREATE TRIGGER chargebacks_set_updated_at BEFORE UPDATE ON chargebacks
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- In-app disputes (buyer <-> seller, mediated by the platform)
-- ---------------------------------------------------------------------------

CREATE TABLE disputes (
  id            UUID PRIMARY KEY,
  public_id     public_id NOT NULL UNIQUE,
  order_item_id UUID NOT NULL REFERENCES order_items (id) ON DELETE RESTRICT,
  opened_by     UUID NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
  category      TEXT NOT NULL CHECK (category IN
                  ('not_as_described','corrupt_file','missing_file','licence_dispute','copyright_claim','other')),
  description   TEXT NOT NULL CHECK (length(description) BETWEEN 10 AND 5000),
  status        TEXT NOT NULL DEFAULT 'open'
                  CHECK (status IN ('open','awaiting_seller','awaiting_buyer','under_review','resolved_refund','resolved_no_refund','withdrawn')),
  resolution    TEXT,
  resolved_by   UUID REFERENCES users (id),
  resolved_at   TIMESTAMPTZ,
  -- Seller response SLA; breach escalates automatically.
  seller_due_at TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX disputes_status_idx ON disputes (status, seller_due_at) WHERE status IN ('open','awaiting_seller');
CREATE INDEX disputes_item_idx   ON disputes (order_item_id);

CREATE TRIGGER disputes_set_updated_at BEFORE UPDATE ON disputes
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE dispute_messages (
  id          UUID PRIMARY KEY,
  dispute_id  UUID NOT NULL REFERENCES disputes (id) ON DELETE CASCADE,
  author_id   UUID NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
  author_role TEXT NOT NULL CHECK (author_role IN ('buyer','seller','support')),
  body        TEXT NOT NULL CHECK (length(body) BETWEEN 1 AND 5000),
  internal    BOOLEAN NOT NULL DEFAULT FALSE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX dispute_messages_dispute_idx ON dispute_messages (dispute_id, created_at);

-- ---------------------------------------------------------------------------
-- Provider webhook de-duplication
--
-- Providers retry. Networks duplicate. The unique key on (provider, event_id)
-- is what makes "process exactly once" true rather than hoped for, and the
-- stored payload digest detects a replay carrying altered content.
-- ---------------------------------------------------------------------------

CREATE TABLE provider_webhook_events (
  id              UUID PRIMARY KEY,
  provider        TEXT NOT NULL,
  event_id        TEXT NOT NULL,
  event_type      TEXT NOT NULL,
  payload_digest  sha256_digest NOT NULL,
  payload         JSONB NOT NULL,
  signature_valid BOOLEAN NOT NULL,
  received_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  processed_at    TIMESTAMPTZ,
  process_status  TEXT NOT NULL DEFAULT 'received'
                    CHECK (process_status IN ('received','processed','ignored','failed','replay_detected')),
  attempts        INTEGER NOT NULL DEFAULT 0,
  last_error      TEXT
);

CREATE UNIQUE INDEX provider_webhook_events_uq ON provider_webhook_events (provider, event_id);
CREATE INDEX provider_webhook_events_pending_idx ON provider_webhook_events (received_at)
  WHERE process_status IN ('received','failed');
CREATE INDEX provider_webhook_events_type_idx ON provider_webhook_events (provider, event_type, received_at DESC);
