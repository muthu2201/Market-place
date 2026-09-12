-- 0002_identity.sql
-- Accounts, credentials, sessions, RBAC, and the per-subject key material that
-- makes DPDP/GDPR erasure possible without destroying financial history.

-- ---------------------------------------------------------------------------
-- Crypto-shredding key registry
--
-- Every data subject gets a data-encryption key (DEK). The DEK is stored only
-- in wrapped form, sealed under the deployment's key-encryption key (KEK).
-- Erasure destroys the wrapped DEK, which renders every ciphertext encrypted
-- under it permanently unreadable while leaving the rows - and therefore the
-- ledger, the invoices and the tax returns that reference them - structurally
-- intact. This is the reconciliation of "right to erasure" with "immutable
-- financial record" that the blueprint identified as an unresolved tension.
-- ---------------------------------------------------------------------------

CREATE TABLE subject_keys (
  subject_id     UUID PRIMARY KEY,
  wrapped_dek    BYTEA,                     -- NULL once shredded
  kek_version    INTEGER NOT NULL DEFAULT 1,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  shredded_at    TIMESTAMPTZ,
  shred_reason   TEXT,
  CONSTRAINT subject_keys_shred_consistency CHECK (
    (shredded_at IS NULL AND wrapped_dek IS NOT NULL) OR
    (shredded_at IS NOT NULL AND wrapped_dek IS NULL)
  )
);

COMMENT ON TABLE subject_keys IS
  'Per-data-subject wrapped DEKs. Deleting wrapped_dek is the erasure primitive (crypto-shredding).';

-- ---------------------------------------------------------------------------
-- Users
--
-- The e-mail address is never stored in the clear. Lookup uses a keyed blind
-- index (HMAC under a server-side pepper) so equality search still works while
-- a database dump yields no addresses. The display copy is AEAD-encrypted under
-- the subject DEK, so erasure removes it.
-- ---------------------------------------------------------------------------

CREATE TABLE users (
  id                  UUID PRIMARY KEY,
  public_id           public_id NOT NULL UNIQUE,
  email_index         email_blind_index NOT NULL,
  email_ciphertext    BYTEA,
  email_domain        TEXT NOT NULL CHECK (length(email_domain) BETWEEN 3 AND 253),
  email_verified_at   TIMESTAMPTZ,
  password_hash       TEXT NOT NULL CHECK (password_hash LIKE '$argon2id$%'),
  password_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  display_name_ciphertext BYTEA,
  status              TEXT NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active','suspended','closed','erased')),
  locale              TEXT NOT NULL DEFAULT 'en-IN' CHECK (length(locale) <= 16),
  country             CHAR(2) NOT NULL DEFAULT 'IN' CHECK (country ~ '^[A-Z]{2}$'),
  -- Residence drives place-of-supply and which tax regime applies.
  tax_residence       CHAR(2) NOT NULL DEFAULT 'IN' CHECK (tax_residence ~ '^[A-Z]{2}$'),
  state_code          SMALLINT CHECK (state_code IS NULL OR state_code BETWEEN 1 AND 99),
  failed_login_count  INTEGER NOT NULL DEFAULT 0 CHECK (failed_login_count >= 0),
  locked_until        TIMESTAMPTZ,
  last_login_at       TIMESTAMPTZ,
  totp_secret_ciphertext BYTEA,
  totp_enabled_at     TIMESTAMPTZ,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  erased_at           TIMESTAMPTZ,
  CONSTRAINT users_subject_key_fk FOREIGN KEY (id) REFERENCES subject_keys (subject_id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX users_email_index_uq ON users (email_index) WHERE erased_at IS NULL;
CREATE INDEX users_status_idx  ON users (status) WHERE status <> 'active';
CREATE INDEX users_created_idx ON users (created_at DESC);
CREATE INDEX users_domain_idx  ON users (email_domain);

CREATE TRIGGER users_set_updated_at BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER users_immutable_core BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION forbid_update_of_columns('id', 'public_id', 'created_at');

-- ---------------------------------------------------------------------------
-- Roles (RBAC)
--
-- Authorisation is a server-side join, never a claim in a token the client
-- holds. A stolen session cannot escalate because the role set is re-read from
-- the database on every privileged check.
-- ---------------------------------------------------------------------------

CREATE TABLE roles (
  code        TEXT PRIMARY KEY CHECK (code ~ '^[a-z_]{3,40}$'),
  description TEXT NOT NULL
);

INSERT INTO roles (code, description) VALUES
  ('buyer',            'Can purchase and download entitled products.'),
  ('seller',           'Can list products and receive settlements.'),
  ('support_agent',    'Can read orders and respond to grievances; cannot move money.'),
  ('finance_operator', 'Can run reconciliation and release settlements.'),
  ('moderator',        'Can review listings, provenance flags and takedown notices.'),
  ('admin',            'Full administrative access including role assignment.');

CREATE TABLE user_roles (
  user_id     UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  role_code   TEXT NOT NULL REFERENCES roles (code) ON DELETE RESTRICT,
  granted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  granted_by  UUID REFERENCES users (id),
  expires_at  TIMESTAMPTZ,
  PRIMARY KEY (user_id, role_code)
);

CREATE INDEX user_roles_role_idx ON user_roles (role_code);

-- ---------------------------------------------------------------------------
-- Sessions
--
-- Only the SHA-256 of the session token is stored. A database leak therefore
-- yields no usable sessions. Rotation on privilege change defeats fixation.
-- ---------------------------------------------------------------------------

CREATE TABLE sessions (
  id              UUID PRIMARY KEY,
  user_id         UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  token_hash      sha256_digest NOT NULL UNIQUE,
  -- A session is only "fully authenticated" once any required second factor
  -- has been satisfied; until then it may access the 2FA challenge and nothing else.
  auth_level      TEXT NOT NULL DEFAULT 'full' CHECK (auth_level IN ('pending_mfa','full')),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  absolute_expiry TIMESTAMPTZ NOT NULL,
  idle_expiry     TIMESTAMPTZ NOT NULL,
  revoked_at      TIMESTAMPTZ,
  revoked_reason  TEXT,
  ip              INET,
  user_agent_hash sha256_digest,
  CONSTRAINT sessions_expiry_order CHECK (idle_expiry <= absolute_expiry)
);

CREATE INDEX sessions_user_idx    ON sessions (user_id, created_at DESC);
CREATE INDEX sessions_cleanup_idx ON sessions (absolute_expiry) WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- Credentials: recovery codes, resets, verification, API keys
-- ---------------------------------------------------------------------------

CREATE TABLE recovery_codes (
  id         UUID PRIMARY KEY,
  user_id    UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  code_hash  sha256_digest NOT NULL,
  used_at    TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX recovery_codes_hash_uq ON recovery_codes (user_id, code_hash);
CREATE INDEX recovery_codes_unused_idx ON recovery_codes (user_id) WHERE used_at IS NULL;

CREATE TABLE credential_tokens (
  id           UUID PRIMARY KEY,
  user_id      UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  purpose      TEXT NOT NULL CHECK (purpose IN ('password_reset','email_verification','email_change','seller_invite')),
  token_hash   sha256_digest NOT NULL UNIQUE,
  payload      JSONB NOT NULL DEFAULT '{}'::jsonb,
  expires_at   TIMESTAMPTZ NOT NULL,
  consumed_at  TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_ip   INET
);

CREATE INDEX credential_tokens_user_idx ON credential_tokens (user_id, purpose, created_at DESC);
CREATE INDEX credential_tokens_expiry_idx ON credential_tokens (expires_at) WHERE consumed_at IS NULL;

CREATE TABLE api_keys (
  id           UUID PRIMARY KEY,
  public_id    public_id NOT NULL UNIQUE,
  user_id      UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  name         TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
  key_hash     sha256_digest NOT NULL UNIQUE,
  prefix       TEXT NOT NULL,
  scopes       TEXT[] NOT NULL DEFAULT '{}',
  last_used_at TIMESTAMPTZ,
  expires_at   TIMESTAMPTZ,
  revoked_at   TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX api_keys_user_idx ON api_keys (user_id) WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- Login attempt history
--
-- Retained for lockout decisions and abuse investigation. The identifier is the
-- blind index, never the address, so this table is not a harvesting target.
-- ---------------------------------------------------------------------------

CREATE TABLE login_attempts (
  id           BIGSERIAL PRIMARY KEY,
  email_index  email_blind_index,
  user_id      UUID REFERENCES users (id) ON DELETE SET NULL,
  ip           INET,
  outcome      TEXT NOT NULL CHECK (outcome IN
                 ('success','bad_password','unknown_account','locked','mfa_required','mfa_failed','rate_limited','suspended')),
  attempted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  user_agent_hash sha256_digest
);

CREATE INDEX login_attempts_email_idx ON login_attempts (email_index, attempted_at DESC);
CREATE INDEX login_attempts_ip_idx    ON login_attempts (ip, attempted_at DESC);
CREATE INDEX login_attempts_time_idx  ON login_attempts (attempted_at DESC);

-- ---------------------------------------------------------------------------
-- Consent records (DPDP Act 2023 / DPDP Rules 2025)
--
-- Consent must be demonstrable: what was asked, in which language, when, and
-- how it was withdrawn. An append-only table is the only honest shape for that.
-- ---------------------------------------------------------------------------

CREATE TABLE consent_records (
  id            UUID PRIMARY KEY,
  user_id       UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  purpose       TEXT NOT NULL CHECK (purpose IN
                  ('account','transactional_email','marketing_email','analytics','provenance_review','tax_reporting')),
  granted       BOOLEAN NOT NULL,
  notice_version TEXT NOT NULL,
  notice_language TEXT NOT NULL DEFAULT 'en',
  recorded_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  ip            INET,
  evidence      JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX consent_records_user_idx ON consent_records (user_id, purpose, recorded_at DESC);

CREATE TRIGGER consent_records_append_only
  BEFORE UPDATE OR DELETE ON consent_records
  FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
