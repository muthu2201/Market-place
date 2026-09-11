package identity_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/muthu2201/market-place/internal/modules/identity"
	"github.com/muthu2201/market-place/internal/platform/clock"
	"github.com/muthu2201/market-place/internal/platform/config"
	"github.com/muthu2201/market-place/internal/platform/cryptox"
	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/dbtest"
	"github.com/muthu2201/market-place/internal/platform/ids"
	"github.com/muthu2201/market-place/internal/platform/problem"
)

func newService(t *testing.T) (*identity.Service, *db.DB, *clock.Fixed) {
	t.Helper()
	d := dbtest.Fresh(t)
	kek := make([]byte, 32)
	copy(kek, "test-kek-0123456789abcdef0123456789")
	vault, err := identity.NewVault(kek)
	if err != nil {
		t.Fatal(err)
	}
	clk := clock.NewFixed(time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC))
	s, err := identity.NewService(identity.Options{
		DB: d, Vault: vault, Clock: clk,
		Security: config.SecurityConfig{
			SessionTTL: 30 * 24 * time.Hour, SessionIdleTTL: 14 * 24 * time.Hour,
			LoginMaxAttempts: 5, LoginLockout: 15 * time.Minute,
		},
		Argon:   cryptox.TestArgon2idParams,
		Metrics: dbtest.Metrics(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, d, clk
}

func register(t *testing.T, s *identity.Service, email, password string) *identity.User {
	t.Helper()
	u, created, err := s.Register(context.Background(), identity.RegisterInput{
		Email: email, Password: password, DisplayName: "Test Person",
		Country: "IN", StateCode: 33, IP: "203.0.113.10",
		AcceptedNoticeVersion: "2026-01-01", NoticeLanguage: "en",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !created {
		t.Fatal("expected a new account")
	}
	return u
}

func TestRegisterAndLogin(t *testing.T) {
	s, d, _ := newService(t)
	ctx := context.Background()

	u := register(t, s, "kavitha@example.com", "correct-horse-battery-99")
	if u.PublicID == "" || !strings.HasPrefix(u.PublicID, "usr_") {
		t.Fatalf("public id = %q", u.PublicID)
	}

	// The address must not be stored in the clear anywhere.
	var clear int
	if err := d.QueryRow(ctx,
		`SELECT count(*) FROM users WHERE email_ciphertext::text LIKE '%kavitha%'`).Scan(&clear); err != nil {
		t.Fatal(err)
	}
	if clear != 0 {
		t.Fatal("the e-mail address appears in the clear in the database")
	}

	res, err := s.Login(ctx, identity.LoginInput{
		Email: "kavitha@example.com", Password: "correct-horse-battery-99", IP: "203.0.113.10",
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if res.SessionToken == "" || res.TwoFactorRequired {
		t.Fatalf("unexpected login result %+v", res)
	}
	if res.User.Email != "kavitha@example.com" {
		t.Fatalf("decrypted email = %q", res.User.Email)
	}
	if !res.User.HasRole(identity.RoleBuyer) {
		t.Fatal("a new account should hold the buyer role")
	}

	// Only the digest is stored, so the raw token must not appear in sessions.
	var raw int
	if err := d.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE encode(token_hash,'hex') = $1`,
		res.SessionToken).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if raw != 0 {
		t.Fatal("the session token itself must never be stored")
	}

	sess, err := s.ResolveSession(ctx, res.SessionToken)
	if err != nil {
		t.Fatalf("ResolveSession: %v", err)
	}
	if sess.User.ID != u.ID {
		t.Fatal("resolved the wrong user")
	}
}

func TestRegisterDoesNotDiscloseExistingAccounts(t *testing.T) {
	s, _, _ := newService(t)
	ctx := context.Background()
	register(t, s, "dup@example.com", "correct-horse-battery-99")

	_, created, err := s.Register(ctx, identity.RegisterInput{
		Email: "dup@example.com", Password: "a-different-password-42", DisplayName: "Other",
	})
	if err != nil {
		t.Fatalf("a duplicate registration must not error: %v", err)
	}
	if created {
		t.Fatal("a duplicate must not create a second account")
	}
	// And the original password must still work, i.e. nothing was overwritten.
	if _, err := s.Login(ctx, identity.LoginInput{
		Email: "dup@example.com", Password: "correct-horse-battery-99",
	}); err != nil {
		t.Fatalf("the original credentials must survive a duplicate registration: %v", err)
	}
}

func TestLoginFailuresAreIndistinguishable(t *testing.T) {
	s, _, _ := newService(t)
	ctx := context.Background()
	register(t, s, "real@example.com", "correct-horse-battery-99")

	_, errUnknown := s.Login(ctx, identity.LoginInput{Email: "nobody@example.com", Password: "whatever-long-enough"})
	_, errWrong := s.Login(ctx, identity.LoginInput{Email: "real@example.com", Password: "wrong-password-here"})

	pu, pw := problem.As(errUnknown), problem.As(errWrong)
	if pu == nil || pw == nil {
		t.Fatalf("both should be problem documents: %v / %v", errUnknown, errWrong)
	}
	if pu.Status != pw.Status || pu.Detail != pw.Detail || pu.Type != pw.Type {
		t.Fatalf("responses differ and therefore enumerate accounts:\n  unknown: %+v\n  wrong:   %+v", pu, pw)
	}
}

func TestAccountLocksAfterRepeatedFailures(t *testing.T) {
	s, _, _ := newService(t)
	ctx := context.Background()
	register(t, s, "lock@example.com", "correct-horse-battery-99")

	for i := 0; i < 5; i++ {
		if _, err := s.Login(ctx, identity.LoginInput{
			Email: "lock@example.com", Password: "definitely-wrong-pass", IP: "198.51.100.7",
		}); err == nil {
			t.Fatal("a wrong password must fail")
		}
	}
	// Even the CORRECT password must now be refused while locked.
	_, err := s.Login(ctx, identity.LoginInput{
		Email: "lock@example.com", Password: "correct-horse-battery-99", IP: "198.51.100.7",
	})
	p := problem.As(err)
	if p == nil || p.Type != problem.TypeAccountLocked {
		t.Fatalf("expected a lockout, got %v", err)
	}
}

func TestWeakPasswordsAreRefused(t *testing.T) {
	s, _, _ := newService(t)
	ctx := context.Background()
	cases := []struct{ pw, why string }{
		{"short", "below the minimum length"},
		{"password1234", "a common password with digits appended"},
		{"p4ssw0rd1234", "leet substitution of a common password"},
		{"aaaaaaaaaaaa", "too few distinct characters"},
		{"abcdefghijkl", "a long ascending run"},
		{"qwertyuiop12", "a keyboard pattern"},
		{"weakuser12345", "contains the user's own e-mail local part"},
	}
	for _, c := range cases {
		_, _, err := s.Register(ctx, identity.RegisterInput{
			Email: "weakuser@example.com", Password: c.pw, DisplayName: "Weak User",
		})
		if err == nil {
			t.Errorf("%q should be refused (%s)", c.pw, c.why)
			continue
		}
		if p := problem.As(err); p == nil || p.Status != 422 {
			t.Errorf("%q: expected a 422 validation problem, got %v", c.pw, err)
		}
	}
	// A long, unpredictable passphrase must be accepted.
	if _, _, err := s.Register(ctx, identity.RegisterInput{
		Email: "strong@example.com", Password: "seven lamps beside the quiet river", DisplayName: "Strong",
	}); err != nil {
		t.Fatalf("a good passphrase must be accepted: %v", err)
	}
}

func TestTwoFactorGatesTheSession(t *testing.T) {
	s, _, clk := newService(t)
	ctx := context.Background()
	u := register(t, s, "mfa@example.com", "correct-horse-battery-99")

	secret, uri, err := s.BeginTOTPEnrolment(ctx, u.ID, "mfa@example.com", "Marketplace")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Fatalf("provisioning uri = %q", uri)
	}
	// Two-factor is not enabled until a code is confirmed.
	res, err := s.Login(ctx, identity.LoginInput{Email: "mfa@example.com", Password: "correct-horse-battery-99"})
	if err != nil || res.TwoFactorRequired {
		t.Fatalf("enrolment alone must not lock the user out: %v %+v", err, res)
	}

	code, err := cryptox.TOTPCodeAt(secret, clk.Now())
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := s.ConfirmTOTPEnrolment(ctx, u.ID, code)
	if err != nil {
		t.Fatalf("ConfirmTOTPEnrolment: %v", err)
	}
	if len(recovery) != 10 {
		t.Fatalf("expected 10 recovery codes, got %d", len(recovery))
	}

	// Password alone now yields a limited session.
	res, err = s.Login(ctx, identity.LoginInput{Email: "mfa@example.com", Password: "correct-horse-battery-99"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.TwoFactorRequired {
		t.Fatal("two-factor must be required once enabled")
	}
	sess, err := s.ResolveSession(ctx, res.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if sess.AuthLevel != "pending_mfa" {
		t.Fatalf("auth level = %q, want pending_mfa", sess.AuthLevel)
	}

	// A wrong code fails.
	if _, err := s.Login(ctx, identity.LoginInput{
		Email: "mfa@example.com", Password: "correct-horse-battery-99", TOTPCode: "000000",
	}); err == nil {
		t.Fatal("a wrong TOTP code must fail")
	}

	// The right code yields a full session.
	code, _ = cryptox.TOTPCodeAt(secret, clk.Now())
	res, err = s.Login(ctx, identity.LoginInput{
		Email: "mfa@example.com", Password: "correct-horse-battery-99", TOTPCode: code,
	})
	if err != nil || res.TwoFactorRequired {
		t.Fatalf("a valid code must complete login: %v %+v", err, res)
	}

	// A recovery code works once and only once.
	res, err = s.Login(ctx, identity.LoginInput{
		Email: "mfa@example.com", Password: "correct-horse-battery-99", RecoveryCode: recovery[0],
	})
	if err != nil || res.TwoFactorRequired {
		t.Fatalf("a recovery code must complete login: %v", err)
	}
	if _, err := s.Login(ctx, identity.LoginInput{
		Email: "mfa@example.com", Password: "correct-horse-battery-99", RecoveryCode: recovery[0],
	}); err == nil {
		t.Fatal("a recovery code must not be reusable")
	}
}

func TestPasswordResetRevokesEverySession(t *testing.T) {
	s, d, _ := newService(t)
	ctx := context.Background()
	register(t, s, "reset@example.com", "correct-horse-battery-99")

	first, err := s.Login(ctx, identity.LoginInput{Email: "reset@example.com", Password: "correct-horse-battery-99"})
	if err != nil {
		t.Fatal(err)
	}

	tok, err := s.BeginPasswordReset(ctx, "reset@example.com", "203.0.113.1")
	if err != nil {
		t.Fatal(err)
	}
	if !tok.Delivered || tok.Token == "" {
		t.Fatalf("reset token: %+v", tok)
	}
	if err := s.CompletePasswordReset(ctx, tok.Token, "another good long phrase", "203.0.113.1"); err != nil {
		t.Fatalf("CompletePasswordReset: %v", err)
	}

	// The pre-existing session, which may belong to an attacker, is dead.
	if _, err := s.ResolveSession(ctx, first.SessionToken); err == nil {
		t.Fatal("a password reset must revoke existing sessions")
	}
	// The token cannot be replayed.
	if err := s.CompletePasswordReset(ctx, tok.Token, "yet another long phrase", ""); err == nil {
		t.Fatal("a reset token must be single use")
	}
	// The new password works.
	if _, err := s.Login(ctx, identity.LoginInput{Email: "reset@example.com", Password: "another good long phrase"}); err != nil {
		t.Fatalf("the new password must work: %v", err)
	}

	var revoked int
	if err := d.QueryRow(ctx,
		`SELECT count(*) FROM sessions WHERE revoked_reason = 'password_reset'`).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if revoked == 0 {
		t.Fatal("expected revocations to be recorded with a reason")
	}
}

func TestPasswordResetForUnknownAddressLooksIdentical(t *testing.T) {
	s, _, _ := newService(t)
	tok, err := s.BeginPasswordReset(context.Background(), "ghost@example.com", "203.0.113.2")
	if err != nil {
		t.Fatalf("an unknown address must not error: %v", err)
	}
	if tok.Delivered {
		t.Fatal("nothing should be delivered for an unknown address")
	}
}

// Crypto-shredding is the mechanism that reconciles the right to erasure with
// the duty to retain financial records. Both halves are asserted here.
func TestErasureShredsKeyButKeepsRecords(t *testing.T) {
	s, d, _ := newService(t)
	ctx := context.Background()
	u := register(t, s, "erase@example.com", "correct-horse-battery-99")

	login, err := s.Login(ctx, identity.LoginInput{Email: "erase@example.com", Password: "correct-horse-battery-99"})
	if err != nil {
		t.Fatal(err)
	}

	res, err := s.EraseSubject(ctx, u.ID, "data subject request", nil)
	if err != nil {
		t.Fatalf("EraseSubject: %v", err)
	}
	if !res.Shredded || !res.SessionsRevoked {
		t.Fatalf("erasure result: %+v", res)
	}
	if len(res.RetainedRecords) == 0 || res.RetentionBasis == "" {
		t.Fatal("a data subject must be told what survives and why")
	}

	// The key is gone and the data is unreadable.
	if _, err := s.Vault().SubjectKey(ctx, d, u.ID); !errors.Is(err, identity.ErrShredded) {
		t.Fatalf("the subject key must be shredded, got %v", err)
	}
	var wrapped []byte
	if err := d.QueryRow(ctx, `SELECT wrapped_dek FROM subject_keys WHERE subject_id = $1`, u.ID).Scan(&wrapped); err != nil {
		t.Fatal(err)
	}
	if wrapped != nil {
		t.Fatal("the wrapped key must be destroyed, not merely flagged")
	}
	// The row survives so foreign keys from financial records still resolve.
	var status string
	if err := d.QueryRow(ctx, `SELECT status FROM users WHERE id = $1`, u.ID).Scan(&status); err != nil {
		t.Fatalf("the user row must survive erasure so the ledger stays intact: %v", err)
	}
	if status != "erased" {
		t.Fatalf("status = %q", status)
	}
	if _, err := s.ResolveSession(ctx, login.SessionToken); err == nil {
		t.Fatal("erasure must revoke sessions")
	}
	// Logging in again must not resurrect the account.
	if _, err := s.Login(ctx, identity.LoginInput{Email: "erase@example.com", Password: "correct-horse-battery-99"}); err == nil {
		t.Fatal("an erased account must not authenticate")
	}
}

func TestSessionRotationInvalidatesTheOldToken(t *testing.T) {
	s, _, _ := newService(t)
	ctx := context.Background()
	register(t, s, "rotate@example.com", "correct-horse-battery-99")
	res, err := s.Login(ctx, identity.LoginInput{Email: "rotate@example.com", Password: "correct-horse-battery-99"})
	if err != nil {
		t.Fatal(err)
	}
	newToken, err := s.RotateSession(ctx, res.SessionID, "full")
	if err != nil {
		t.Fatal(err)
	}
	if newToken == res.SessionToken {
		t.Fatal("rotation must produce a different token")
	}
	if _, err := s.ResolveSession(ctx, res.SessionToken); err == nil {
		t.Fatal("the pre-rotation token must stop working, which is what defeats fixation")
	}
	if _, err := s.ResolveSession(ctx, newToken); err != nil {
		t.Fatalf("the rotated token must work: %v", err)
	}
}

func TestExpiredSessionIsRefused(t *testing.T) {
	s, _, clk := newService(t)
	ctx := context.Background()
	register(t, s, "expire@example.com", "correct-horse-battery-99")
	res, err := s.Login(ctx, identity.LoginInput{Email: "expire@example.com", Password: "correct-horse-battery-99"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveSession(ctx, res.SessionToken); err != nil {
		t.Fatal(err)
	}
	clk.Advance(31 * 24 * time.Hour)
	if _, err := s.ResolveSession(ctx, res.SessionToken); err == nil {
		t.Fatal("a session past its absolute expiry must be refused")
	}
}

func TestRolesAreReReadNotCached(t *testing.T) {
	s, d, _ := newService(t)
	ctx := context.Background()
	u := register(t, s, "role@example.com", "correct-horse-battery-99")
	res, err := s.Login(ctx, identity.LoginInput{Email: "role@example.com", Password: "correct-horse-battery-99"})
	if err != nil {
		t.Fatal(err)
	}
	sess, _ := s.ResolveSession(ctx, res.SessionToken)
	if sess.User.HasRole(identity.RoleAdmin) {
		t.Fatal("a new user must not be an admin")
	}

	if err := d.InTx(ctx, db.TxOptions{Name: "grant"}, func(ctx context.Context, tx db.Tx) error {
		return s.GrantRole(ctx, tx, u.ID, identity.RoleAdmin, nil)
	}); err != nil {
		t.Fatal(err)
	}
	// The SAME session token must now reflect the new role: authorisation is a
	// live lookup, not a claim baked into the token.
	sess, _ = s.ResolveSession(ctx, res.SessionToken)
	if !sess.User.HasRole(identity.RoleAdmin) {
		t.Fatal("a granted role must be visible on the existing session")
	}

	if err := d.InTx(ctx, db.TxOptions{Name: "revoke"}, func(ctx context.Context, tx db.Tx) error {
		return s.RevokeRole(ctx, tx, u.ID, identity.RoleAdmin, nil)
	}); err != nil {
		t.Fatal(err)
	}
	sess, _ = s.ResolveSession(ctx, res.SessionToken)
	if sess.User.HasRole(identity.RoleAdmin) {
		t.Fatal("a revoked role must take effect immediately")
	}
}

func TestVaultRefusesCrossFieldAndCrossSubjectCiphertext(t *testing.T) {
	_, d, _ := newService(t)
	ctx := context.Background()
	kek := make([]byte, 32)
	copy(kek, "test-kek-0123456789abcdef0123456789")
	v, _ := identity.NewVault(kek)

	subjectA := ids.NewUUIDv7()
	subjectB := ids.NewUUIDv7()
	var dekA, dekB []byte
	if err := d.InTx(ctx, db.TxOptions{Name: "keys"}, func(ctx context.Context, tx db.Tx) error {
		var err error
		if dekA, err = v.IssueSubjectKey(ctx, tx, subjectA); err != nil {
			return err
		}
		dekB, err = v.IssueSubjectKey(ctx, tx, subjectB)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	ct, err := v.Encrypt(dekA, subjectA, "email", "a@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Decrypt(dekA, subjectA, "email", ct); err != nil {
		t.Fatalf("the correct key, subject and field must decrypt: %v", err)
	}
	if _, err := v.Decrypt(dekA, subjectA, "display_name", ct); err == nil {
		t.Fatal("a ciphertext must not be movable between fields")
	}
	if _, err := v.Decrypt(dekA, subjectB, "email", ct); err == nil {
		t.Fatal("a ciphertext must not be movable between subjects")
	}
	if _, err := v.Decrypt(dekB, subjectA, "email", ct); err == nil {
		t.Fatal("another subject's key must not decrypt this ciphertext")
	}
}

func TestBlindIndexNormalisesDomainButNotLocalPart(t *testing.T) {
	kek := make([]byte, 32)
	copy(kek, "test-kek-0123456789abcdef0123456789")
	v, _ := identity.NewVault(kek)

	same := v.BlindIndex("Kavitha@Example.COM")
	alsoSame := v.BlindIndex("Kavitha@example.com")
	if string(same) != string(alsoSame) {
		t.Fatal("the domain must be case-insensitive")
	}
	different := v.BlindIndex("kavitha@example.com")
	if string(same) == string(different) {
		t.Fatal("the local part is case-sensitive per RFC 5321 and must not be folded")
	}
}
