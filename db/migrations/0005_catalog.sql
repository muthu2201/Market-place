-- 0005_catalog.sql
-- Products, assets, the curated-folksonomy taxonomy, provenance and moderation.

-- ---------------------------------------------------------------------------
-- Taxonomy: a small curated spine plus seller-proposed tags
--
-- The AO3 model: sellers tag freely, and a wrangling pipeline maps synonyms and
-- misspellings onto canonical tags behind the scenes. Faceted search runs on
-- canonical tags; the seller's own wording is still displayed.
-- ---------------------------------------------------------------------------

CREATE TABLE categories (
  id           UUID PRIMARY KEY,
  public_id    public_id NOT NULL UNIQUE,
  parent_id    UUID REFERENCES categories (id) ON DELETE RESTRICT,
  slug         TEXT NOT NULL CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
  name         TEXT NOT NULL CHECK (length(name) BETWEEN 2 AND 80),
  description  TEXT,
  -- Materialised path makes "everything under Design" a prefix scan.
  path         TEXT NOT NULL,
  depth        SMALLINT NOT NULL CHECK (depth BETWEEN 0 AND 3),
  position     INTEGER NOT NULL DEFAULT 0,
  -- Digital goods are services for GST; the HSN/SAC code is per category.
  sac_code     TEXT CHECK (sac_code IS NULL OR sac_code ~ '^[0-9]{4,8}$'),
  active       BOOLEAN NOT NULL DEFAULT TRUE,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (parent_id, slug)
);

CREATE UNIQUE INDEX categories_path_uq ON categories (path);
CREATE INDEX categories_parent_idx ON categories (parent_id, position);

CREATE TABLE tags (
  id             UUID PRIMARY KEY,
  public_id      public_id NOT NULL UNIQUE,
  slug           TEXT NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
  label          TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 40),
  -- A canonical tag stands on its own. A synonym points at one and is never
  -- shown as a facet; its uses are attributed to its canonical parent.
  status         TEXT NOT NULL DEFAULT 'proposed'
                   CHECK (status IN ('proposed','canonical','synonym','rejected','banned')),
  canonical_id   UUID REFERENCES tags (id) ON DELETE RESTRICT,
  usage_count    INTEGER NOT NULL DEFAULT 0 CHECK (usage_count >= 0),
  wrangled_by    UUID REFERENCES users (id),
  wrangled_at    TIMESTAMPTZ,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT tags_synonym_points_at_canonical CHECK (
    (status = 'synonym' AND canonical_id IS NOT NULL) OR
    (status <> 'synonym' AND canonical_id IS NULL)
  )
);

CREATE INDEX tags_status_idx    ON tags (status, usage_count DESC);
CREATE INDEX tags_canonical_idx ON tags (canonical_id) WHERE canonical_id IS NOT NULL;
CREATE INDEX tags_label_trgm_idx ON tags USING GIN (label gin_trgm_ops);

-- resolve_tag follows a synonym chain to its canonical tag, with a depth guard
-- so that a mis-wrangled cycle cannot loop forever.
CREATE OR REPLACE FUNCTION resolve_tag(p_tag UUID)
RETURNS UUID LANGUAGE plpgsql STABLE AS $$
DECLARE
  cur   UUID := p_tag;
  nxt   UUID;
  hops  INTEGER := 0;
BEGIN
  LOOP
    SELECT canonical_id INTO nxt FROM tags WHERE id = cur;
    IF nxt IS NULL THEN RETURN cur; END IF;
    cur := nxt;
    hops := hops + 1;
    IF hops > 8 THEN
      RAISE EXCEPTION 'tag synonym chain from % exceeds 8 hops (probable cycle)', p_tag
        USING ERRCODE = 'P0001';
    END IF;
  END LOOP;
END;
$$;

-- ---------------------------------------------------------------------------
-- Products
-- ---------------------------------------------------------------------------

CREATE TABLE products (
  id                 UUID PRIMARY KEY,
  public_id          public_id NOT NULL UNIQUE,
  seller_id          UUID NOT NULL REFERENCES sellers (id) ON DELETE RESTRICT,
  category_id        UUID NOT NULL REFERENCES categories (id) ON DELETE RESTRICT,
  slug               TEXT NOT NULL CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
  title              TEXT NOT NULL CHECK (length(title) BETWEEN 3 AND 140),
  summary            TEXT NOT NULL CHECK (length(summary) BETWEEN 10 AND 300),
  description        TEXT NOT NULL CHECK (length(description) BETWEEN 10 AND 20000),

  -- Delivery shape. "rental" is deliberately absent: once a file is downloaded
  -- access cannot be revoked, so a time-limited grant is modelled honestly as a
  -- licence with an expiry on further downloads, not as a rental.
  delivery_type      TEXT NOT NULL CHECK (delivery_type IN ('download','streamed_access','license_key','hosted_access')),
  license_type       TEXT NOT NULL CHECK (license_type IN ('personal','commercial','extended','editorial','open_source')),
  license_terms      TEXT NOT NULL CHECK (length(license_terms) BETWEEN 10 AND 20000),
  license_duration_days INTEGER CHECK (license_duration_days IS NULL OR license_duration_days > 0),

  status             TEXT NOT NULL DEFAULT 'draft'
                       CHECK (status IN ('draft','pending_review','published','rejected','suspended','archived')),
  rejection_reason   TEXT,

  -- Disclosure-first provenance. The declaration is mandatory and is the
  -- primary signal; detector output never overrides it on its own.
  ai_disclosure      TEXT NOT NULL DEFAULT 'undeclared'
                       CHECK (ai_disclosure IN ('undeclared','no_ai','ai_assisted','ai_generated','ai_generated_edited')),
  ai_disclosure_note TEXT CHECK (ai_disclosure_note IS NULL OR length(ai_disclosure_note) <= 2000),
  provenance_score   SMALLINT NOT NULL DEFAULT 0 CHECK (provenance_score BETWEEN 0 AND 100),
  risk_score         SMALLINT NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
  requires_human_review BOOLEAN NOT NULL DEFAULT FALSE,

  -- Refund posture is declared up front, which is what makes "no refund after
  -- download" fair and enforceable under the Consumer Protection rules.
  refund_policy      TEXT NOT NULL DEFAULT 'no_refund_after_download'
                       CHECK (refund_policy IN ('no_refund_after_download','refundable_14_days','no_refund','case_by_case')),

  published_at       TIMESTAMPTZ,
  first_published_at TIMESTAMPTZ,
  -- Republishing does not reset ranking recency; that is the anti-bump control.
  ranking_anchor_at  TIMESTAMPTZ,

  view_count         BIGINT NOT NULL DEFAULT 0,
  sales_count        INTEGER NOT NULL DEFAULT 0,
  refund_count       INTEGER NOT NULL DEFAULT 0,
  rating_sum         INTEGER NOT NULL DEFAULT 0,
  rating_count       INTEGER NOT NULL DEFAULT 0,

  search_vector      TSVECTOR,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),

  UNIQUE (seller_id, slug),
  CONSTRAINT products_published_has_timestamp CHECK (status <> 'published' OR published_at IS NOT NULL),
  CONSTRAINT products_rejected_has_reason CHECK (status <> 'rejected' OR rejection_reason IS NOT NULL)
);

CREATE INDEX products_seller_idx     ON products (seller_id, status, created_at DESC);
CREATE INDEX products_category_idx   ON products (category_id, status) WHERE status = 'published';
CREATE INDEX products_published_idx  ON products (ranking_anchor_at DESC) WHERE status = 'published';
CREATE INDEX products_review_idx     ON products (status, created_at) WHERE status = 'pending_review';
CREATE INDEX products_search_idx     ON products USING GIN (search_vector);
CREATE INDEX products_title_trgm_idx ON products USING GIN (title gin_trgm_ops);
CREATE INDEX products_risk_idx       ON products (risk_score DESC) WHERE requires_human_review;

CREATE TRIGGER products_set_updated_at BEFORE UPDATE ON products
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER products_immutable_core BEFORE UPDATE ON products
  FOR EACH ROW EXECUTE FUNCTION forbid_update_of_columns('id','public_id','seller_id','created_at');

-- The search vector is maintained by the database so it can never drift from
-- the row. Weights: title > summary > description.
CREATE OR REPLACE FUNCTION products_refresh_search_vector() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
  NEW.search_vector :=
      setweight(to_tsvector('simple', coalesce(NEW.title, '')), 'A')
   || setweight(to_tsvector('english', coalesce(NEW.title, '')), 'A')
   || setweight(to_tsvector('english', coalesce(NEW.summary, '')), 'B')
   || setweight(to_tsvector('english', coalesce(NEW.description, '')), 'C');
  RETURN NEW;
END;
$$;

CREATE TRIGGER products_search_vector
  BEFORE INSERT OR UPDATE OF title, summary, description ON products
  FOR EACH ROW EXECUTE FUNCTION products_refresh_search_vector();

-- ranking_anchor_at is set once, on first publication, and never moves. An
-- unpublish/republish cycle therefore buys no ranking advantage.
CREATE OR REPLACE FUNCTION products_set_ranking_anchor() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.status = 'published' THEN
    IF NEW.first_published_at IS NULL THEN
      NEW.first_published_at := COALESCE(NEW.published_at, now());
    END IF;
    IF NEW.ranking_anchor_at IS NULL THEN
      NEW.ranking_anchor_at := NEW.first_published_at;
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER products_ranking_anchor
  BEFORE INSERT OR UPDATE OF status ON products
  FOR EACH ROW EXECUTE FUNCTION products_set_ranking_anchor();

CREATE TRIGGER products_anchor_immutable BEFORE UPDATE ON products
  FOR EACH ROW EXECUTE FUNCTION forbid_update_of_columns('first_published_at');

-- ---------------------------------------------------------------------------
-- Variants: the priced, purchasable unit
-- ---------------------------------------------------------------------------

CREATE TABLE product_variants (
  id              UUID PRIMARY KEY,
  public_id       public_id NOT NULL UNIQUE,
  product_id      UUID NOT NULL REFERENCES products (id) ON DELETE CASCADE,
  name            TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
  price_minor     money_minor NOT NULL CHECK (price_minor >= 0),
  currency        currency_code NOT NULL,
  compare_at_minor money_minor CHECK (compare_at_minor IS NULL OR compare_at_minor >= 0),
  -- A variant may cap total sales (limited editions) without inventory
  -- semantics leaking into the rest of the system.
  max_sales       INTEGER CHECK (max_sales IS NULL OR max_sales > 0),
  sales_count     INTEGER NOT NULL DEFAULT 0 CHECK (sales_count >= 0),
  position        SMALLINT NOT NULL DEFAULT 0,
  active          BOOLEAN NOT NULL DEFAULT TRUE,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT product_variants_compare_at_is_higher
    CHECK (compare_at_minor IS NULL OR compare_at_minor > price_minor),
  CONSTRAINT product_variants_within_max_sales
    CHECK (max_sales IS NULL OR sales_count <= max_sales)
);

CREATE INDEX product_variants_product_idx ON product_variants (product_id, position);

CREATE TRIGGER product_variants_set_updated_at BEFORE UPDATE ON product_variants
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- Assets: the files a buyer receives
--
-- No asset is ever served from a path the client supplies. Delivery resolves an
-- entitlement to an object key server-side; object_key is not a URL and is not
-- exposed to buyers.
-- ---------------------------------------------------------------------------

CREATE TABLE product_assets (
  id              UUID PRIMARY KEY,
  public_id       public_id NOT NULL UNIQUE,
  product_id      UUID NOT NULL REFERENCES products (id) ON DELETE CASCADE,
  variant_id      UUID REFERENCES product_variants (id) ON DELETE CASCADE,
  filename        TEXT NOT NULL CHECK (length(filename) BETWEEN 1 AND 255),
  object_key      TEXT NOT NULL UNIQUE,
  content_type    TEXT NOT NULL CHECK (length(content_type) BETWEEN 3 AND 255),
  -- The type the bytes actually are, from magic-number sniffing. A mismatch
  -- with content_type is a rejection, not a warning.
  detected_type   TEXT,
  size_bytes      BIGINT NOT NULL CHECK (size_bytes > 0 AND size_bytes <= 21474836480),
  checksum        sha256_digest NOT NULL,

  scan_status     TEXT NOT NULL DEFAULT 'pending'
                    CHECK (scan_status IN ('pending','scanning','clean','infected','suspicious','error','skipped')),
  scan_engine     TEXT,
  scan_signature  TEXT,
  scanned_at      TIMESTAMPTZ,

  -- Provenance signals, all cheap and all advisory.
  c2pa_present    BOOLEAN NOT NULL DEFAULT FALSE,
  c2pa_valid      BOOLEAN,
  c2pa_issuer     TEXT,
  generator_hint  TEXT,
  perceptual_hash BIGINT,
  simhash         BIGINT,
  has_source_project BOOLEAN NOT NULL DEFAULT FALSE,

  is_preview      BOOLEAN NOT NULL DEFAULT FALSE,
  watermarked     BOOLEAN NOT NULL DEFAULT FALSE,
  position        SMALLINT NOT NULL DEFAULT 0,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX product_assets_product_idx ON product_assets (product_id, position);
CREATE INDEX product_assets_scan_idx    ON product_assets (scan_status) WHERE scan_status IN ('pending','scanning');
CREATE INDEX product_assets_phash_idx   ON product_assets (perceptual_hash) WHERE perceptual_hash IS NOT NULL;
CREATE INDEX product_assets_checksum_idx ON product_assets (checksum);

CREATE TRIGGER product_assets_immutable_bytes BEFORE UPDATE ON product_assets
  FOR EACH ROW EXECUTE FUNCTION forbid_update_of_columns('id','product_id','object_key','checksum','size_bytes');

-- A published product must have at least one clean, non-preview asset. This is
-- the control that stops "pay and receive nothing" and "pay and receive malware".
CREATE OR REPLACE FUNCTION products_publish_guard() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
DECLARE
  deliverable INTEGER;
  unscanned   INTEGER;
  seller_ok   BOOLEAN;
BEGIN
  IF NEW.status <> 'published' OR (TG_OP = 'UPDATE' AND OLD.status = 'published') THEN
    RETURN NEW;
  END IF;

  SELECT count(*) FILTER (WHERE NOT is_preview AND scan_status = 'clean'),
         count(*) FILTER (WHERE NOT is_preview AND scan_status IN ('pending','scanning','infected','suspicious','error'))
    INTO deliverable, unscanned
  FROM product_assets WHERE product_id = NEW.id;

  IF NEW.delivery_type = 'download' AND deliverable = 0 THEN
    RAISE EXCEPTION 'product % cannot be published: it has no clean deliverable asset', NEW.id
      USING ERRCODE = 'P0001';
  END IF;
  IF unscanned > 0 THEN
    RAISE EXCEPTION 'product % cannot be published: % asset(s) are not scanned clean', NEW.id, unscanned
      USING ERRCODE = 'P0001';
  END IF;
  IF NEW.ai_disclosure = 'undeclared' THEN
    RAISE EXCEPTION 'product % cannot be published: an AI-content declaration is mandatory', NEW.id
      USING ERRCODE = 'P0001';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM product_variants WHERE product_id = NEW.id AND active) THEN
    RAISE EXCEPTION 'product % cannot be published: it has no active priced variant', NEW.id
      USING ERRCODE = 'P0001';
  END IF;

  SELECT s.status = 'active' AND s.kyc_status = 'verified'
    INTO seller_ok FROM sellers s WHERE s.id = NEW.seller_id;
  IF NOT COALESCE(seller_ok, FALSE) THEN
    RAISE EXCEPTION 'product % cannot be published: seller is not active with verified KYC', NEW.id
      USING ERRCODE = 'P0001';
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER products_publish_guard
  BEFORE INSERT OR UPDATE OF status ON products
  FOR EACH ROW EXECUTE FUNCTION products_publish_guard();

-- ---------------------------------------------------------------------------
-- Product tags and moderation
-- ---------------------------------------------------------------------------

CREATE TABLE product_tags (
  product_id      UUID NOT NULL REFERENCES products (id) ON DELETE CASCADE,
  tag_id          UUID NOT NULL REFERENCES tags (id) ON DELETE RESTRICT,
  canonical_tag_id UUID NOT NULL REFERENCES tags (id) ON DELETE RESTRICT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (product_id, tag_id)
);

CREATE INDEX product_tags_canonical_idx ON product_tags (canonical_tag_id);

CREATE TABLE moderation_cases (
  id            UUID PRIMARY KEY,
  public_id     public_id NOT NULL UNIQUE,
  subject_type  TEXT NOT NULL CHECK (subject_type IN ('product','asset','review','seller','user')),
  subject_id    UUID NOT NULL,
  reason        TEXT NOT NULL CHECK (reason IN
                  ('provenance_risk','malware','copyright','counterfeit','prohibited_content',
                   'spam','tag_abuse','pricing_abuse','user_report','duplicate_content','sanctions')),
  severity      SMALLINT NOT NULL DEFAULT 50 CHECK (severity BETWEEN 0 AND 100),
  status        TEXT NOT NULL DEFAULT 'open'
                  CHECK (status IN ('open','in_review','action_taken','dismissed','escalated')),
  -- Signals are recorded, but a single detector never decides. The blueprint's
  -- rule (false positives systematically punish non-native writers) is encoded
  -- as a schema-level requirement for a human decision on any enforcement.
  signals       JSONB NOT NULL DEFAULT '{}'::jsonb,
  opened_by     UUID REFERENCES users (id),
  assigned_to   UUID REFERENCES users (id),
  decided_by    UUID REFERENCES users (id),
  decided_at    TIMESTAMPTZ,
  decision      TEXT,
  decision_note TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT moderation_enforcement_requires_a_human
    CHECK (status <> 'action_taken' OR (decided_by IS NOT NULL AND decided_at IS NOT NULL))
);

CREATE INDEX moderation_cases_open_idx    ON moderation_cases (status, severity DESC, created_at) WHERE status IN ('open','in_review','escalated');
CREATE INDEX moderation_cases_subject_idx ON moderation_cases (subject_type, subject_id, created_at DESC);

CREATE TRIGGER moderation_cases_set_updated_at BEFORE UPDATE ON moderation_cases
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- Reviews: only from verified purchasers
-- ---------------------------------------------------------------------------

CREATE TABLE reviews (
  id           UUID PRIMARY KEY,
  public_id    public_id NOT NULL UNIQUE,
  product_id   UUID NOT NULL REFERENCES products (id) ON DELETE CASCADE,
  user_id      UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  order_item_id UUID NOT NULL,
  rating       SMALLINT NOT NULL CHECK (rating BETWEEN 1 AND 5),
  title        TEXT CHECK (title IS NULL OR length(title) <= 140),
  body         TEXT CHECK (body IS NULL OR length(body) <= 5000),
  status       TEXT NOT NULL DEFAULT 'published' CHECK (status IN ('published','hidden','removed')),
  seller_reply TEXT CHECK (seller_reply IS NULL OR length(seller_reply) <= 2000),
  seller_replied_at TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (order_item_id)
);

CREATE INDEX reviews_product_idx ON reviews (product_id, created_at DESC) WHERE status = 'published';
CREATE INDEX reviews_user_idx    ON reviews (user_id, created_at DESC);

CREATE TRIGGER reviews_set_updated_at BEFORE UPDATE ON reviews
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();
