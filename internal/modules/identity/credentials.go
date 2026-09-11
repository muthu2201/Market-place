package identity

import (
	"context"
	"fmt"
	"time"

	"github.com/muthu2201/market-place/internal/modules/audit"
	"github.com/muthu2201/market-place/internal/platform/cryptox"
	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/ids"
	"github.com/muthu2201/market-place/internal/platform/problem"
	"github.com/muthu2201/market-place/internal/platform/ratelimit"
)

// Token lifetimes. Short windows are the cheapest mitigation for a token that
// leaks through a forwarded e-mail, a shared screenshot or a mail archive.
const (
	PasswordResetTTL     = 30 * time.Minute
	EmailVerificationTTL = 24 * time.Hour
)

// IssuedToken is returned once; only its digest is stored.
type IssuedToken struct {
	Token     string
	ExpiresAt time.Time
	// Delivered is false when no account matched. The caller must still report
	// success to the user so the form cannot be used to enumerate accounts.
	Delivered bool
	UserID    ids.UUID
	Email     string
}

// BeginPasswordReset issues a reset token when the address is registered.
//
// It always reports success to the caller. Whether an e-mail is actually sent
// is carried in Delivered, which the HTTP layer ignores and the mailer honours.
func (s *Service) BeginPasswordReset(ctx context.Context, email, ip string) (IssuedToken, error) {
	if d := s.limiter.Allow(ip, ratelimit.RulePasswordResetIP); !d.Allowed {
		return IssuedToken{}, problem.RateLimited(int(d.RetryAfter.Seconds()) + 1)
	}
	index := s.vault.BlindIndex(email)

	var userID ids.UUID
	var publicID string
	var emailCT []byte
	err := s.db.QueryRow(ctx,
		`SELECT id, public_id, email_ciphertext FROM users
		  WHERE email_index = $1 AND erased_at IS NULL AND status = 'active'`, index,
	).Scan(&userID, &publicID, &emailCT)
	if db.IsNoRows(err) {
		return IssuedToken{Delivered: false}, nil
	}
	if err != nil {
		return IssuedToken{}, fmt.Errorf("identity: reset lookup: %w", err)
	}
	if d := s.limiter.Allow(publicID, ratelimit.RulePasswordResetUser); !d.Allowed {
		return IssuedToken{}, problem.RateLimited(int(d.RetryAfter.Seconds()) + 1)
	}

	token, err := cryptox.NewToken(32)
	if err != nil {
		return IssuedToken{}, err
	}
	expires := s.clk.Now().Add(PasswordResetTTL)

	err = s.db.InTx(ctx, db.TxOptions{Name: "password_reset_begin"}, func(ctx context.Context, tx db.Tx) error {
		// Any outstanding reset is consumed: issuing a second link must not
		// leave the first one live.
		if _, err := tx.Exec(ctx, `
			UPDATE credential_tokens SET consumed_at = now()
			 WHERE user_id = $1 AND purpose = 'password_reset' AND consumed_at IS NULL`, userID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO credential_tokens (id, user_id, purpose, token_hash, expires_at, created_ip)
			VALUES ($1,$2,'password_reset',$3,$4,$5)`,
			ids.NewUUIDv7(), userID, cryptox.HashToken(token), expires, nullIfEmpty(ip)); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, audit.Event{
			ActorKind: audit.ActorUser, ActorID: &userID, ActorIP: ip,
			Action: "user.password_reset_requested", SubjectType: "user", SubjectID: publicID,
		})
	})
	if err != nil {
		return IssuedToken{}, err
	}

	out := IssuedToken{Token: token, ExpiresAt: expires, Delivered: true, UserID: userID}
	if dek, err := s.vault.SubjectKey(ctx, s.db, userID); err == nil {
		out.Email, _ = s.vault.Decrypt(dek, userID, "email", emailCT)
	}
	return out, nil
}

// CompletePasswordReset consumes a token and sets a new password.
//
// Every session is revoked: if the reset was triggered by a compromise, leaving
// the attacker's session alive would defeat the point of the reset.
func (s *Service) CompletePasswordReset(ctx context.Context, token, newPassword, ip string) error {
	if err := cryptox.CheckPasswordLength(newPassword); err != nil {
		return problem.Validation(problem.FieldError{
			Field: "password", Code: "too_short",
			Detail: fmt.Sprintf("Passwords must be at least %d characters.", cryptox.MinPasswordLength)})
	}
	hash, err := cryptox.HashPassword(newPassword, s.argon)
	if err != nil {
		return err
	}

	return s.db.InTx(ctx, db.TxOptions{Name: "password_reset_complete"}, func(ctx context.Context, tx db.Tx) error {
		var userID ids.UUID
		var emailCT, nameCT []byte
		err := tx.QueryRow(ctx, `
			SELECT t.user_id, u.email_ciphertext, u.display_name_ciphertext
			  FROM credential_tokens t
			  JOIN users u ON u.id = t.user_id
			 WHERE t.token_hash = $1 AND t.purpose = 'password_reset'
			   AND t.consumed_at IS NULL AND t.expires_at > now()
			   AND u.erased_at IS NULL
			 FOR UPDATE OF t`, cryptox.HashToken(token)).Scan(&userID, &emailCT, &nameCT)
		if db.IsNoRows(err) {
			return problem.Unauthenticated("That reset link is invalid or has expired. Request a new one.")
		}
		if err != nil {
			return fmt.Errorf("identity: reset lookup: %w", err)
		}

		// Re-run the weak-password check with this user's own context.
		var email, name string
		if dek, err := s.vault.SubjectKey(ctx, tx, userID); err == nil {
			email, _ = s.vault.Decrypt(dek, userID, "email", emailCT)
			name, _ = s.vault.Decrypt(dek, userID, "display_name", nameCT)
		}
		if weak, why := IsWeakPassword(newPassword, email, name); weak {
			return problem.Validation(problem.FieldError{Field: "password", Code: "too_weak", Detail: why})
		}

		if _, err := tx.Exec(ctx,
			`UPDATE credential_tokens SET consumed_at = now() WHERE token_hash = $1`,
			cryptox.HashToken(token)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE users
			   SET password_hash = $2, password_changed_at = now(),
			       failed_login_count = 0, locked_until = NULL
			 WHERE id = $1`, userID, hash); err != nil {
			return err
		}
		if err := s.RevokeAllSessions(ctx, tx, userID, "password_reset"); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, audit.Event{
			ActorKind: audit.ActorUser, ActorID: &userID, ActorIP: ip,
			Action: "user.password_reset_completed", SubjectType: "user", SubjectID: userID.String(),
		})
	})
}

// ChangePassword updates a password for a signed-in user, requiring the current
// one. Other sessions are revoked; the caller's own session is rotated by the
// HTTP layer.
func (s *Service) ChangePassword(ctx context.Context, userID ids.UUID, current, next, ip string, keepSessionID ids.UUID) error {
	if err := cryptox.CheckPasswordLength(next); err != nil {
		return problem.Validation(problem.FieldError{Field: "new_password", Code: "too_short",
			Detail: fmt.Sprintf("Passwords must be at least %d characters.", cryptox.MinPasswordLength)})
	}
	return s.db.InTx(ctx, db.TxOptions{Name: "password_change"}, func(ctx context.Context, tx db.Tx) error {
		var hash string
		var emailCT, nameCT []byte
		if err := tx.QueryRow(ctx,
			`SELECT password_hash, email_ciphertext, display_name_ciphertext FROM users WHERE id = $1`,
			userID).Scan(&hash, &emailCT, &nameCT); err != nil {
			return fmt.Errorf("identity: change password lookup: %w", err)
		}
		ok, _, err := cryptox.VerifyPassword(current, hash)
		if err != nil {
			return err
		}
		if !ok {
			return problem.Unauthenticated("Your current password is not correct.")
		}
		var email, name string
		if dek, err := s.vault.SubjectKey(ctx, tx, userID); err == nil {
			email, _ = s.vault.Decrypt(dek, userID, "email", emailCT)
			name, _ = s.vault.Decrypt(dek, userID, "display_name", nameCT)
		}
		if weak, why := IsWeakPassword(next, email, name); weak {
			return problem.Validation(problem.FieldError{Field: "new_password", Code: "too_weak", Detail: why})
		}
		newHash, err := cryptox.HashPassword(next, s.argon)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE users SET password_hash = $2, password_changed_at = now() WHERE id = $1`,
			userID, newHash); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE sessions SET revoked_at = now(), revoked_reason = 'password_changed'
			 WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL`, userID, keepSessionID); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, audit.Event{
			ActorKind: audit.ActorUser, ActorID: &userID, ActorIP: ip,
			Action: "user.password_changed", SubjectType: "user", SubjectID: userID.String(),
		})
	})
}

// BeginEmailVerification issues a verification token.
func (s *Service) BeginEmailVerification(ctx context.Context, userID ids.UUID) (IssuedToken, error) {
	token, err := cryptox.NewToken(32)
	if err != nil {
		return IssuedToken{}, err
	}
	expires := s.clk.Now().Add(EmailVerificationTTL)
	if _, err := s.db.Exec(ctx, `
		INSERT INTO credential_tokens (id, user_id, purpose, token_hash, expires_at)
		VALUES ($1,$2,'email_verification',$3,$4)`,
		ids.NewUUIDv7(), userID, cryptox.HashToken(token), expires); err != nil {
		return IssuedToken{}, fmt.Errorf("identity: issue verification token: %w", err)
	}
	out := IssuedToken{Token: token, ExpiresAt: expires, Delivered: true, UserID: userID}
	var ct []byte
	if err := s.db.QueryRow(ctx, `SELECT email_ciphertext FROM users WHERE id = $1`, userID).Scan(&ct); err == nil {
		out.Email, _ = s.vault.DecryptFor(ctx, s.db, userID, "email", ct)
	}
	return out, nil
}

// CompleteEmailVerification consumes a verification token.
func (s *Service) CompleteEmailVerification(ctx context.Context, token string) (ids.UUID, error) {
	var userID ids.UUID
	err := s.db.InTx(ctx, db.TxOptions{Name: "email_verify"}, func(ctx context.Context, tx db.Tx) error {
		err := tx.QueryRow(ctx, `
			UPDATE credential_tokens SET consumed_at = now()
			 WHERE token_hash = $1 AND purpose = 'email_verification'
			   AND consumed_at IS NULL AND expires_at > now()
			 RETURNING user_id`, cryptox.HashToken(token)).Scan(&userID)
		if db.IsNoRows(err) {
			return problem.Unauthenticated("That verification link is invalid or has expired.")
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE users SET email_verified_at = COALESCE(email_verified_at, now()) WHERE id = $1`, userID); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, audit.Event{
			ActorKind: audit.ActorUser, ActorID: &userID,
			Action: "user.email_verified", SubjectType: "user", SubjectID: userID.String(),
		})
	})
	return userID, err
}

// ---- erasure ----------------------------------------------------------------

// ErasureResult describes what an erasure actually did, which the data subject
// is entitled to be told.
type ErasureResult struct {
	Shredded        bool
	SessionsRevoked bool
	// RetainedRecords names what survives and on what legal basis. Erasure is
	// never unconditional: tax law requires the financial record to be kept.
	RetainedRecords []string
	RetentionBasis  string
}

// EraseSubject performs crypto-shredding.
//
// Ciphertext rows are left in place so that orders, invoices, the ledger and the
// statutory returns remain structurally intact and internally consistent; the
// personal data inside them simply becomes permanently unreadable. The user row
// is marked erased and every session is revoked.
func (s *Service) EraseSubject(ctx context.Context, userID ids.UUID, reason string, actor *ids.UUID) (ErasureResult, error) {
	var res ErasureResult
	err := s.db.InTx(ctx, db.TxOptions{Name: "erase_subject"}, func(ctx context.Context, tx db.Tx) error {
		if err := s.vault.Shred(ctx, tx, userID, reason); err != nil {
			return err
		}
		res.Shredded = true
		if _, err := tx.Exec(ctx, `
			UPDATE users
			   SET status = 'erased', erased_at = now(),
			       email_ciphertext = NULL, display_name_ciphertext = NULL,
			       totp_secret_ciphertext = NULL
			 WHERE id = $1`, userID); err != nil {
			return err
		}
		if err := s.RevokeAllSessions(ctx, tx, userID, "erasure"); err != nil {
			return err
		}
		res.SessionsRevoked = true
		if _, err := tx.Exec(ctx, `DELETE FROM recovery_codes WHERE user_id = $1`, userID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE credential_tokens SET consumed_at = now() WHERE user_id = $1 AND consumed_at IS NULL`, userID); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, audit.Event{
			ActorKind: audit.ActorAdmin, ActorID: actor,
			Action: "user.erased", SubjectType: "user", SubjectID: userID.String(),
			Metadata: map[string]any{"reason": reason, "method": "crypto_shredding"},
		})
	})
	if err != nil {
		return res, err
	}
	res.RetainedRecords = []string{
		"order and invoice records, with personal data rendered unreadable",
		"double-entry ledger postings, which reference opaque identifiers only",
		"GST and income-tax return aggregates",
		"the tamper-evident audit log, which records actions rather than personal data",
	}
	res.RetentionBasis = "Retained to comply with tax and accounting obligations, including section 52 CGST reporting and section 194-O deposit and reporting. Personal data within those records has been rendered permanently unreadable by destroying the subject's encryption key."
	return res, nil
}
