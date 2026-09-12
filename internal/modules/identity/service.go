package identity

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/muthu2201/market-place/internal/modules/audit"
	"github.com/muthu2201/market-place/internal/platform/clock"
	"github.com/muthu2201/market-place/internal/platform/config"
	"github.com/muthu2201/market-place/internal/platform/cryptox"
	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/ids"
	"github.com/muthu2201/market-place/internal/platform/metrics"
	"github.com/muthu2201/market-place/internal/platform/problem"
	"github.com/muthu2201/market-place/internal/platform/ratelimit"
)

// Role codes mirror the roles table.
const (
	RoleBuyer           = "buyer"
	RoleSeller          = "seller"
	RoleSupportAgent    = "support_agent"
	RoleFinanceOperator = "finance_operator"
	RoleModerator       = "moderator"
	RoleAdmin           = "admin"
)

// Service is the identity module's public surface.
type Service struct {
	db      *db.DB
	vault   *Vault
	clk     clock.Clock
	cfg     config.SecurityConfig
	argon   cryptox.Argon2idParams
	limiter *ratelimit.Local
	audit   *audit.Service
	m       *metrics.App
}

// Options configures the service.
type Options struct {
	DB       *db.DB
	Vault    *Vault
	Clock    clock.Clock
	Security config.SecurityConfig
	// Argon lets integration suites use cheaper parameters without changing the
	// code path under test. Production passes the default.
	Argon   cryptox.Argon2idParams
	Limiter *ratelimit.Local
	Audit   *audit.Service
	Metrics *metrics.App
}

func NewService(o Options) (*Service, error) {
	if o.DB == nil || o.Vault == nil {
		return nil, errors.New("identity: database and vault are required")
	}
	if o.Clock == nil {
		o.Clock = clock.System()
	}
	if o.Argon.Memory == 0 {
		o.Argon = cryptox.DefaultArgon2idParams
	}
	if o.Limiter == nil {
		o.Limiter = ratelimit.NewLocal(o.Clock)
	}
	if o.Audit == nil {
		o.Audit = audit.New()
	}
	return &Service{
		db: o.DB, vault: o.Vault, clk: o.Clock, cfg: o.Security,
		argon: o.Argon, limiter: o.Limiter, audit: o.Audit, m: o.Metrics,
	}, nil
}

// Vault exposes the encryption vault to sibling modules that must store PII
// under the same subject key (sellers, invoices, grievances).
func (s *Service) Vault() *Vault { return s.vault }

// User is the in-memory view of an account. The e-mail is decrypted on demand
// and is absent for an erased subject.
type User struct {
	ID              ids.UUID
	PublicID        string
	Email           string
	EmailDomain     string
	EmailVerified   bool
	DisplayName     string
	Status          string
	Country         string
	TaxResidence    string
	StateCode       int
	TwoFactorOn     bool
	Roles           []string
	CreatedAt       time.Time
	PasswordChanged time.Time
}

// HasRole reports membership. Callers must use this rather than comparing
// strings, so role naming stays in one place.
func (u *User) HasRole(role string) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// IsStaff reports any role that grants access to other people's data.
func (u *User) IsStaff() bool {
	return u.HasRole(RoleAdmin) || u.HasRole(RoleSupportAgent) ||
		u.HasRole(RoleFinanceOperator) || u.HasRole(RoleModerator)
}

// ---- registration -----------------------------------------------------------

// RegisterInput is a validated registration request.
type RegisterInput struct {
	Email       string
	Password    string
	DisplayName string
	Country     string
	StateCode   int
	IP          string
	// AcceptedNoticeVersion records which privacy notice the user was shown,
	// which is what makes consent demonstrable under the DPDP Rules.
	AcceptedNoticeVersion string
	NoticeLanguage        string
}

// Register creates an account.
//
// It returns the same generic success to the caller whether or not the address
// was already registered, and sends a different e-mail in each case. That is
// the standard defence against account enumeration through the signup form.
func (s *Service) Register(ctx context.Context, in RegisterInput) (*User, bool, error) {
	if err := cryptox.CheckPasswordLength(in.Password); err != nil {
		return nil, false, problem.Validation(problem.FieldError{
			Field: "password", Code: "too_short",
			Detail: fmt.Sprintf("Passwords must be at least %d characters. Length is the control that matters; there are no composition rules.", cryptox.MinPasswordLength),
		})
	}
	if weak, why := IsWeakPassword(in.Password, in.Email, in.DisplayName); weak {
		return nil, false, problem.Validation(problem.FieldError{
			Field: "password", Code: "too_weak", Detail: why,
		})
	}

	index := s.vault.BlindIndex(in.Email)
	domain := EmailDomain(in.Email)
	hash, err := cryptox.HashPassword(in.Password, s.argon)
	if err != nil {
		return nil, false, fmt.Errorf("identity: hash password: %w", err)
	}

	var created bool
	var user *User
	err = s.db.InTx(ctx, db.TxOptions{Name: "identity_register"}, func(ctx context.Context, tx db.Tx) error {
		created = false
		var existing ids.UUID
		err := tx.QueryRow(ctx,
			`SELECT id FROM users WHERE email_index = $1 AND erased_at IS NULL`, index).Scan(&existing)
		if err == nil {
			// Already registered. Nothing is written and nothing is disclosed.
			user = &User{ID: existing}
			return nil
		}
		if !db.IsNoRows(err) {
			return fmt.Errorf("identity: lookup: %w", err)
		}

		id := ids.NewUUIDv7()
		dek, err := s.vault.IssueSubjectKey(ctx, tx, id)
		if err != nil {
			return err
		}
		emailCT, err := s.vault.Encrypt(dek, id, "email", NormaliseEmail(in.Email))
		if err != nil {
			return err
		}
		nameCT, err := s.vault.Encrypt(dek, id, "display_name", in.DisplayName)
		if err != nil {
			return err
		}

		publicID := ids.NewPublic(ids.PrefixUser)
		country := in.Country
		if country == "" {
			country = "IN"
		}
		var state any
		if in.StateCode > 0 {
			state = in.StateCode
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO users (id, public_id, email_index, email_ciphertext, email_domain,
			                   password_hash, display_name_ciphertext, country, tax_residence, state_code)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$8,$9)`,
			id, publicID, index, emailCT, domain, hash, nameCT, country, state); err != nil {
			return fmt.Errorf("identity: insert user: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO user_roles (user_id, role_code) VALUES ($1, $2)`, id, RoleBuyer); err != nil {
			return fmt.Errorf("identity: grant buyer role: %w", err)
		}

		notice := in.AcceptedNoticeVersion
		if notice == "" {
			notice = "unrecorded"
		}
		lang := in.NoticeLanguage
		if lang == "" {
			lang = "en"
		}
		for _, purpose := range []string{"account", "transactional_email"} {
			if _, err := tx.Exec(ctx, `
				INSERT INTO consent_records (id, user_id, purpose, granted, notice_version, notice_language, ip)
				VALUES ($1,$2,$3,TRUE,$4,$5,$6)`,
				ids.NewUUIDv7(), id, purpose, notice, lang, nullIfEmpty(in.IP)); err != nil {
				return fmt.Errorf("identity: record consent: %w", err)
			}
		}

		if err := s.audit.Record(ctx, tx, audit.Event{
			ActorKind: audit.ActorUser, ActorID: &id, ActorIP: in.IP,
			Action: "user.registered", SubjectType: "user", SubjectID: publicID,
			Metadata: map[string]any{"email_domain": domain, "country": country},
		}); err != nil {
			return err
		}

		created = true
		user = &User{
			ID: id, PublicID: publicID, Email: NormaliseEmail(in.Email), EmailDomain: domain,
			DisplayName: in.DisplayName, Status: "active", Country: country,
			TaxResidence: country, StateCode: in.StateCode, Roles: []string{RoleBuyer},
			CreatedAt: s.clk.Now(),
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	if s.m != nil {
		outcome := "duplicate"
		if created {
			outcome = "created"
		}
		s.m.AuthEvents.Inc("register", outcome)
	}
	return user, created, nil
}

// ---- login ------------------------------------------------------------------

// LoginInput carries a credential attempt.
type LoginInput struct {
	Email        string
	Password     string
	IP           string
	UserAgent    string
	TOTPCode     string
	RecoveryCode string
}

// LoginResult describes the outcome.
type LoginResult struct {
	User *User
	// SessionToken is shown to the caller exactly once; only its digest is stored.
	SessionToken string
	SessionID    ids.UUID
	ExpiresAt    time.Time
	// TwoFactorRequired means the session exists but is limited to completing
	// the second factor.
	TwoFactorRequired bool
}

var (
	// ErrInvalidCredentials is deliberately indistinguishable between "no such
	// account" and "wrong password".
	ErrInvalidCredentials = problem.Unauthenticated("The e-mail address or password is incorrect.")
	ErrAccountLocked      = problem.New(http.StatusLocked, problem.TypeAccountLocked,
		"Account temporarily locked", "Too many failed sign-in attempts. Try again later or reset your password.")
	ErrAccountSuspended = problem.Forbidden("This account is suspended. Contact support.")
	ErrTwoFactorNeeded  = problem.New(http.StatusUnauthorized, problem.TypeTwoFactorRequired,
		"Two-factor authentication required", "Enter the six-digit code from your authenticator app.")
)

// Login authenticates and issues a session.
//
// The timing of a failure is equalised: when no account exists we still perform
// an Argon2id hash, so response time cannot be used to enumerate registered
// addresses.
func (s *Service) Login(ctx context.Context, in LoginInput) (*LoginResult, error) {
	index := s.vault.BlindIndex(in.Email)

	if d := s.limiter.Allow(in.IP, ratelimit.RuleLoginPerIP); !d.Allowed {
		s.recordAttempt(ctx, index, nil, in, "rate_limited")
		return nil, problem.RateLimited(int(d.RetryAfter.Seconds()) + 1)
	}

	var row struct {
		id          ids.UUID
		publicID    string
		hash        string
		status      string
		failedCount int
		lockedUntil *time.Time
		totpCT      []byte
		totpEnabled *time.Time
		emailCT     []byte
		nameCT      []byte
		domain      string
		verifiedAt  *time.Time
		country     string
		stateCode   *int
		passwordAt  time.Time
		createdAt   time.Time
	}
	err := s.db.QueryRow(ctx, `
		SELECT id, public_id, password_hash, status, failed_login_count, locked_until,
		       totp_secret_ciphertext, totp_enabled_at, email_ciphertext, display_name_ciphertext,
		       email_domain, email_verified_at, country, state_code, password_changed_at, created_at
		  FROM users WHERE email_index = $1 AND erased_at IS NULL`, index,
	).Scan(&row.id, &row.publicID, &row.hash, &row.status, &row.failedCount, &row.lockedUntil,
		&row.totpCT, &row.totpEnabled, &row.emailCT, &row.nameCT, &row.domain,
		&row.verifiedAt, &row.country, &row.stateCode, &row.passwordAt, &row.createdAt)

	if db.IsNoRows(err) {
		// Equalise timing against the no-such-account path.
		cryptox.DummyVerify(in.Password, s.argon)
		s.recordAttempt(ctx, index, nil, in, "unknown_account")
		if s.m != nil {
			s.m.AuthEvents.Inc("login", "unknown_account")
		}
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, fmt.Errorf("identity: login lookup: %w", err)
	}

	if row.lockedUntil != nil && row.lockedUntil.After(s.clk.Now()) {
		s.recordAttempt(ctx, index, &row.id, in, "locked")
		if s.m != nil {
			s.m.AuthEvents.Inc("login", "locked")
		}
		return nil, ErrAccountLocked
	}
	if d := s.limiter.Allow(row.publicID, ratelimit.RuleLoginPerAccount); !d.Allowed {
		s.recordAttempt(ctx, index, &row.id, in, "rate_limited")
		return nil, problem.RateLimited(int(d.RetryAfter.Seconds()) + 1)
	}

	ok, needsRehash, err := cryptox.VerifyPassword(in.Password, row.hash)
	if err != nil {
		return nil, fmt.Errorf("identity: verify password: %w", err)
	}
	if !ok {
		s.onFailedPassword(ctx, row.id, row.failedCount, index, in)
		if s.m != nil {
			s.m.AuthEvents.Inc("login", "bad_password")
		}
		return nil, ErrInvalidCredentials
	}
	if row.status != "active" {
		s.recordAttempt(ctx, index, &row.id, in, "suspended")
		return nil, ErrAccountSuspended
	}

	user := &User{
		ID: row.id, PublicID: row.publicID, EmailDomain: row.domain,
		EmailVerified: row.verifiedAt != nil, Status: row.status, Country: row.country,
		TaxResidence: row.country, TwoFactorOn: row.totpEnabled != nil,
		CreatedAt: row.createdAt, PasswordChanged: row.passwordAt,
	}
	if row.stateCode != nil {
		user.StateCode = *row.stateCode
	}
	if dek, err := s.vault.SubjectKey(ctx, s.db, row.id); err == nil {
		user.Email, _ = s.vault.Decrypt(dek, row.id, "email", row.emailCT)
		user.DisplayName, _ = s.vault.Decrypt(dek, row.id, "display_name", row.nameCT)
	}
	if user.Roles, err = s.rolesOf(ctx, s.db, row.id); err != nil {
		return nil, err
	}

	// Second factor.
	twoFactorSatisfied := true
	if user.TwoFactorOn {
		twoFactorSatisfied = false
		switch {
		case in.TOTPCode != "":
			if d := s.limiter.Allow(row.publicID, ratelimit.RuleTOTPVerify); !d.Allowed {
				return nil, problem.RateLimited(int(d.RetryAfter.Seconds()) + 1)
			}
			secret, err := s.vault.DecryptFor(ctx, s.db, row.id, "totp_secret", row.totpCT)
			if err != nil {
				return nil, fmt.Errorf("identity: read totp secret: %w", err)
			}
			valid, err := cryptox.VerifyTOTP(secret, in.TOTPCode, s.clk.Now())
			if err != nil || !valid {
				s.recordAttempt(ctx, index, &row.id, in, "mfa_failed")
				if s.m != nil {
					s.m.AuthEvents.Inc("login", "mfa_failed")
				}
				return nil, ErrInvalidCredentials
			}
			twoFactorSatisfied = true
		case in.RecoveryCode != "":
			used, err := s.consumeRecoveryCode(ctx, row.id, in.RecoveryCode)
			if err != nil {
				return nil, err
			}
			if !used {
				s.recordAttempt(ctx, index, &row.id, in, "mfa_failed")
				return nil, ErrInvalidCredentials
			}
			twoFactorSatisfied = true
		}
	}

	if !twoFactorSatisfied {
		res, err := s.issueSession(ctx, user, in.IP, in.UserAgent, "pending_mfa")
		if err != nil {
			return nil, err
		}
		s.recordAttempt(ctx, index, &row.id, in, "mfa_required")
		res.TwoFactorRequired = true
		res.User = user
		return res, nil
	}

	if needsRehash {
		// Upgrade the stored hash opportunistically; the user never notices.
		if newHash, err := cryptox.HashPassword(in.Password, s.argon); err == nil {
			_, _ = s.db.Exec(ctx, `UPDATE users SET password_hash = $2 WHERE id = $1`, row.id, newHash)
		}
	}

	res, err := s.issueSession(ctx, user, in.IP, in.UserAgent, "full")
	if err != nil {
		return nil, err
	}
	res.User = user

	if err := s.db.InTx(ctx, db.TxOptions{Name: "identity_login_success"}, func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx,
			`UPDATE users SET failed_login_count = 0, locked_until = NULL, last_login_at = now() WHERE id = $1`,
			row.id); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, audit.Event{
			ActorKind: audit.ActorUser, ActorID: &row.id, ActorIP: in.IP,
			Action: "user.login", SubjectType: "user", SubjectID: row.publicID,
			Metadata: map[string]any{"two_factor": user.TwoFactorOn},
		})
	}); err != nil {
		return nil, err
	}
	s.recordAttempt(ctx, index, &row.id, in, "success")
	if s.m != nil {
		s.m.AuthEvents.Inc("login", "success")
	}
	return res, nil
}

func (s *Service) onFailedPassword(ctx context.Context, id ids.UUID, failed int, index []byte, in LoginInput) {
	next := failed + 1
	var lockUntil any
	if next >= s.cfg.LoginMaxAttempts && s.cfg.LoginMaxAttempts > 0 {
		lockUntil = s.clk.Now().Add(s.cfg.LoginLockout)
	}
	_, _ = s.db.Exec(ctx,
		`UPDATE users SET failed_login_count = $2, locked_until = COALESCE($3, locked_until) WHERE id = $1`,
		id, next, lockUntil)
	s.recordAttempt(ctx, index, &id, in, "bad_password")
}

func (s *Service) recordAttempt(ctx context.Context, index []byte, userID *ids.UUID, in LoginInput, outcome string) {
	var uid any
	if userID != nil {
		uid = *userID
	}
	var uaHash any
	if in.UserAgent != "" {
		uaHash = cryptox.HashToken(in.UserAgent)
	}
	// A failure to write the attempt log must not mask the authentication
	// outcome, so the error is deliberately dropped after being surfaced in
	// metrics by the caller.
	_, _ = s.db.Exec(ctx, `
		INSERT INTO login_attempts (email_index, user_id, ip, outcome, user_agent_hash)
		VALUES ($1,$2,$3,$4,$5)`, index, uid, nullIfEmpty(in.IP), outcome, uaHash)
}

// ---- sessions ---------------------------------------------------------------

func (s *Service) issueSession(ctx context.Context, u *User, ip, userAgent, level string) (*LoginResult, error) {
	token, err := cryptox.NewToken(32)
	if err != nil {
		return nil, fmt.Errorf("identity: mint session token: %w", err)
	}
	now := s.clk.Now()
	absolute := now.Add(s.cfg.SessionTTL)
	idle := now.Add(s.cfg.SessionIdleTTL)
	if idle.After(absolute) {
		idle = absolute
	}
	sessionID := ids.NewUUIDv7()
	var uaHash any
	if userAgent != "" {
		uaHash = cryptox.HashToken(userAgent)
	}

	if _, err := s.db.Exec(ctx, `
		INSERT INTO sessions (id, user_id, token_hash, auth_level, absolute_expiry, idle_expiry, ip, user_agent_hash)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		sessionID, u.ID, cryptox.HashToken(token), level, absolute, idle, nullIfEmpty(ip), uaHash); err != nil {
		return nil, fmt.Errorf("identity: create session: %w", err)
	}
	return &LoginResult{SessionToken: token, SessionID: sessionID, ExpiresAt: absolute}, nil
}

// Session is a resolved, still-valid session.
type Session struct {
	ID        ids.UUID
	User      *User
	AuthLevel string
	ExpiresAt time.Time
}

// ResolveSession validates a bearer token and loads the user with fresh roles.
//
// Roles are re-read on every request rather than cached in the token, so a
// revocation takes effect immediately.
func (s *Service) ResolveSession(ctx context.Context, token string) (*Session, error) {
	if len(token) < 32 || len(token) > 128 {
		return nil, ErrInvalidCredentials
	}
	hash := cryptox.HashToken(token)
	now := s.clk.Now()

	var sess Session
	var userID ids.UUID
	var publicID, status, country, domain string
	var stateCode *int
	var emailCT, nameCT []byte
	var verifiedAt, totpEnabled *time.Time
	var createdAt, passwordAt time.Time

	err := s.db.QueryRow(ctx, `
		SELECT s.id, s.auth_level, s.absolute_expiry,
		       u.id, u.public_id, u.status, u.country, u.state_code, u.email_domain,
		       u.email_ciphertext, u.display_name_ciphertext, u.email_verified_at,
		       u.totp_enabled_at, u.created_at, u.password_changed_at
		  FROM sessions s
		  JOIN users u ON u.id = s.user_id
		 WHERE s.token_hash = $1
		   AND s.revoked_at IS NULL
		   AND s.absolute_expiry > $2
		   AND s.idle_expiry > $2
		   AND u.erased_at IS NULL`, hash, now,
	).Scan(&sess.ID, &sess.AuthLevel, &sess.ExpiresAt,
		&userID, &publicID, &status, &country, &stateCode, &domain,
		&emailCT, &nameCT, &verifiedAt, &totpEnabled, &createdAt, &passwordAt)
	if db.IsNoRows(err) {
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, fmt.Errorf("identity: resolve session: %w", err)
	}
	if status != "active" {
		return nil, ErrAccountSuspended
	}

	u := &User{
		ID: userID, PublicID: publicID, EmailDomain: domain, Status: status,
		EmailVerified: verifiedAt != nil, Country: country, TaxResidence: country,
		TwoFactorOn: totpEnabled != nil, CreatedAt: createdAt, PasswordChanged: passwordAt,
	}
	if stateCode != nil {
		u.StateCode = *stateCode
	}
	if dek, err := s.vault.SubjectKey(ctx, s.db, userID); err == nil {
		u.Email, _ = s.vault.Decrypt(dek, userID, "email", emailCT)
		u.DisplayName, _ = s.vault.Decrypt(dek, userID, "display_name", nameCT)
	}
	if u.Roles, err = s.rolesOf(ctx, s.db, userID); err != nil {
		return nil, err
	}
	sess.User = u

	// Sliding idle window, written without blocking the request path's result.
	newIdle := now.Add(s.cfg.SessionIdleTTL)
	if newIdle.After(sess.ExpiresAt) {
		newIdle = sess.ExpiresAt
	}
	_, _ = s.db.Exec(ctx,
		`UPDATE sessions SET last_seen_at = $2, idle_expiry = $3 WHERE id = $1`, sess.ID, now, newIdle)

	return &sess, nil
}

// RotateSession issues a new token for an existing session and invalidates the
// old one. It is called whenever privilege changes (completing 2FA, becoming a
// seller, a password change), which is what defeats session fixation.
func (s *Service) RotateSession(ctx context.Context, sessionID ids.UUID, level string) (string, error) {
	token, err := cryptox.NewToken(32)
	if err != nil {
		return "", err
	}
	tag, err := s.db.Exec(ctx, `
		UPDATE sessions SET token_hash = $2, auth_level = $3, last_seen_at = now()
		 WHERE id = $1 AND revoked_at IS NULL`,
		sessionID, cryptox.HashToken(token), level)
	if err != nil {
		return "", fmt.Errorf("identity: rotate session: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return "", ErrInvalidCredentials
	}
	return token, nil
}

// RevokeSession signs one session out.
func (s *Service) RevokeSession(ctx context.Context, sessionID ids.UUID, reason string) error {
	_, err := s.db.Exec(ctx,
		`UPDATE sessions SET revoked_at = now(), revoked_reason = $2 WHERE id = $1 AND revoked_at IS NULL`,
		sessionID, reason)
	return err
}

// RevokeAllSessions signs a user out everywhere. Called on password change, on
// a discovered compromise, and on suspension.
func (s *Service) RevokeAllSessions(ctx context.Context, q db.Querier, userID ids.UUID, reason string) error {
	_, err := q.Exec(ctx,
		`UPDATE sessions SET revoked_at = now(), revoked_reason = $2 WHERE user_id = $1 AND revoked_at IS NULL`,
		userID, reason)
	return err
}

func (s *Service) rolesOf(ctx context.Context, q db.Querier, userID ids.UUID) ([]string, error) {
	rows, err := q.Query(ctx, `
		SELECT role_code FROM user_roles
		 WHERE user_id = $1 AND (expires_at IS NULL OR expires_at > $2)
		 ORDER BY role_code`, userID, s.clk.Now())
	if err != nil {
		return nil, fmt.Errorf("identity: read roles: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GrantRole assigns a role. Role assignment is always audited because it is the
// primary privilege-escalation path in any system.
func (s *Service) GrantRole(ctx context.Context, q db.Tx, userID ids.UUID, role string, grantedBy *ids.UUID) error {
	var by any
	if grantedBy != nil {
		by = *grantedBy
	}
	if _, err := q.Exec(ctx, `
		INSERT INTO user_roles (user_id, role_code, granted_by) VALUES ($1,$2,$3)
		ON CONFLICT (user_id, role_code) DO NOTHING`, userID, role, by); err != nil {
		return fmt.Errorf("identity: grant %s: %w", role, err)
	}
	return s.audit.Record(ctx, q, audit.Event{
		ActorKind: audit.ActorAdmin, ActorID: grantedBy,
		Action: "role.granted", SubjectType: "user", SubjectID: userID.String(),
		Metadata: map[string]any{"role": role},
	})
}

// RevokeRole removes a role.
func (s *Service) RevokeRole(ctx context.Context, q db.Tx, userID ids.UUID, role string, by *ids.UUID) error {
	if _, err := q.Exec(ctx, `DELETE FROM user_roles WHERE user_id = $1 AND role_code = $2`, userID, role); err != nil {
		return fmt.Errorf("identity: revoke %s: %w", role, err)
	}
	return s.audit.Record(ctx, q, audit.Event{
		ActorKind: audit.ActorAdmin, ActorID: by,
		Action: "role.revoked", SubjectType: "user", SubjectID: userID.String(),
		Metadata: map[string]any{"role": role},
	})
}

// ---- two-factor -------------------------------------------------------------

// BeginTOTPEnrolment returns a secret and its provisioning URI. The secret is
// stored encrypted but two-factor is not enabled until a code is confirmed, so
// a user cannot lock themselves out by abandoning enrolment.
func (s *Service) BeginTOTPEnrolment(ctx context.Context, userID ids.UUID, accountLabel, issuer string) (secret, uri string, err error) {
	secret, err = cryptox.NewTOTPSecret()
	if err != nil {
		return "", "", err
	}
	err = s.db.InTx(ctx, db.TxOptions{Name: "totp_begin"}, func(ctx context.Context, tx db.Tx) error {
		dek, err := s.vault.SubjectKey(ctx, tx, userID)
		if err != nil {
			return err
		}
		ct, err := s.vault.Encrypt(dek, userID, "totp_secret", secret)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx,
			`UPDATE users SET totp_secret_ciphertext = $2, totp_enabled_at = NULL WHERE id = $1`, userID, ct)
		return err
	})
	if err != nil {
		return "", "", err
	}
	return secret, cryptox.TOTPProvisioningURI(issuer, accountLabel, secret), nil
}

// ConfirmTOTPEnrolment enables two-factor once a code verifies, and returns
// single-use recovery codes.
func (s *Service) ConfirmTOTPEnrolment(ctx context.Context, userID ids.UUID, code string) ([]string, error) {
	var plain []string
	err := s.db.InTx(ctx, db.TxOptions{Name: "totp_confirm"}, func(ctx context.Context, tx db.Tx) error {
		var ct []byte
		if err := tx.QueryRow(ctx, `SELECT totp_secret_ciphertext FROM users WHERE id = $1`, userID).Scan(&ct); err != nil {
			return fmt.Errorf("identity: read totp secret: %w", err)
		}
		if len(ct) == 0 {
			return problem.Conflict("", "Start two-factor enrolment before confirming it.")
		}
		dek, err := s.vault.SubjectKey(ctx, tx, userID)
		if err != nil {
			return err
		}
		secret, err := s.vault.Decrypt(dek, userID, "totp_secret", ct)
		if err != nil {
			return err
		}
		valid, err := cryptox.VerifyTOTP(secret, code, s.clk.Now())
		if err != nil || !valid {
			return problem.Validation(problem.FieldError{
				Field: "code", Code: "invalid", Detail: "That code is not valid. Check your device's clock and try the current code."})
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET totp_enabled_at = now() WHERE id = $1`, userID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM recovery_codes WHERE user_id = $1`, userID); err != nil {
			return err
		}
		codes, digests, err := cryptox.NewRecoveryCodes(10)
		if err != nil {
			return err
		}
		for _, d := range digests {
			if _, err := tx.Exec(ctx,
				`INSERT INTO recovery_codes (id, user_id, code_hash) VALUES ($1,$2,$3)`,
				ids.NewUUIDv7(), userID, d); err != nil {
				return err
			}
		}
		plain = codes
		return s.audit.Record(ctx, tx, audit.Event{
			ActorKind: audit.ActorUser, ActorID: &userID,
			Action: "user.two_factor_enabled", SubjectType: "user", SubjectID: userID.String(),
		})
	})
	if err != nil {
		return nil, err
	}
	return plain, nil
}

func (s *Service) consumeRecoveryCode(ctx context.Context, userID ids.UUID, code string) (bool, error) {
	tag, err := s.db.Exec(ctx, `
		UPDATE recovery_codes SET used_at = now()
		 WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL`,
		userID, cryptox.HashToken(normaliseRecoveryCode(code)))
	if err != nil {
		return false, fmt.Errorf("identity: consume recovery code: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func normaliseRecoveryCode(c string) string {
	out := make([]byte, 0, len(c))
	for i := 0; i < len(c); i++ {
		ch := c[i]
		switch {
		case ch >= 'a' && ch <= 'z':
			out = append(out, ch-32)
		case (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-':
			out = append(out, ch)
		}
	}
	return string(out)
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
