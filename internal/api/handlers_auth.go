package api

import (
	"net/http"
	"strings"

	"github.com/muthu2201/market-place/internal/modules/identity"
	"github.com/muthu2201/market-place/internal/platform/httpx"
	"github.com/muthu2201/market-place/internal/platform/problem"
	"github.com/muthu2201/market-place/internal/platform/ratelimit"
	"github.com/muthu2201/market-place/internal/platform/validate"
)

type registerRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
	Country     string `json:"country"`
	StateCode   int    `json:"state_code"`
	// AcceptNotice records which privacy notice the user was shown, which is
	// what makes consent demonstrable under the DPDP Rules.
	AcceptNotice   string `json:"accept_notice_version"`
	NoticeLanguage string `json:"notice_language"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	ip := httpx.ClientIP(r.Context())
	if d := s.limiter.Allow(ip, ratelimit.RuleSignupPerIP); !d.Allowed {
		httpx.Fail(w, r, problem.RateLimited(int(d.RetryAfter.Seconds())+1))
		return
	}

	var req registerRequest
	if !decode(w, r, &req) {
		return
	}
	var v validate.Errors
	email := v.Email("email", req.Email)
	name := v.Required("display_name", req.DisplayName, validate.MaxNameLength)
	country := "IN"
	if req.Country != "" {
		country = strings.ToUpper(v.OneOf("country", strings.ToUpper(req.Country),
			"IN", "US", "GB", "AE", "SG", "AU", "CA", "DE", "FR", "NL", "JP"))
	}
	if country == "IN" && req.StateCode != 0 {
		v.IntRange("state_code", int64(req.StateCode), 1, 99)
	}
	if p := v.Problem(); p != nil {
		httpx.Fail(w, r, p)
		return
	}

	user, created, err := s.identity.Register(r.Context(), identity.RegisterInput{
		Email: email, Password: req.Password, DisplayName: name,
		Country: country, StateCode: req.StateCode, IP: ip,
		AcceptedNoticeVersion: req.AcceptNotice, NoticeLanguage: req.NoticeLanguage,
	})
	if err != nil {
		httpx.Fail(w, r, err)
		return
	}

	if created {
		if tok, err := s.identity.BeginEmailVerification(r.Context(), user.ID); err == nil {
			s.queueVerificationEmail(r, tok)
		}
	}
	// The response is identical whether or not the address was already
	// registered. Anything else turns this endpoint into an account oracle.
	httpx.NoStore(w)
	httpx.JSON(w, r, http.StatusAccepted, map[string]any{
		"status":  "pending_verification",
		"message": "If that address can be registered, we have sent a verification link to it.",
	})
}

type loginRequest struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	TOTPCode     string `json:"totp_code"`
	RecoveryCode string `json:"recovery_code"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Email == "" || req.Password == "" {
		httpx.Fail(w, r, problem.Validation(
			problem.FieldError{Field: "email", Code: "required", Detail: "An e-mail address and password are required."}))
		return
	}

	res, err := s.identity.Login(r.Context(), identity.LoginInput{
		Email: req.Email, Password: req.Password,
		TOTPCode: req.TOTPCode, RecoveryCode: req.RecoveryCode,
		IP:        httpx.ClientIP(r.Context()),
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		httpx.Fail(w, r, err)
		return
	}

	s.setSessionCookie(w, res.SessionToken, res.ExpiresAt)
	httpx.NoStore(w)

	if res.TwoFactorRequired {
		httpx.JSON(w, r, http.StatusOK, map[string]any{
			"status":  "two_factor_required",
			"message": "Enter the six-digit code from your authenticator app to finish signing in.",
		})
		return
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{
		"status": "signed_in",
		"user":   publicUser(res.User),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if sess := SessionOf(r.Context()); sess != nil {
		_ = s.identity.RevokeSession(r.Context(), sess.ID, "signed out")
	}
	s.clearSessionCookie(w)
	httpx.NoStore(w)
	httpx.JSON(w, r, http.StatusOK, map[string]any{"status": "signed_out"})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	httpx.NoStore(w)
	sess := SessionOf(r.Context())
	if sess == nil {
		httpx.JSON(w, r, http.StatusOK, map[string]any{
			"authenticated": false,
			"csrf_token":    httpx.CSRFToken(r.Context()),
		})
		return
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{
		"authenticated": true,
		"auth_level":    sess.AuthLevel,
		"user":          publicUser(sess.User),
		"csrf_token":    httpx.CSRFToken(r.Context()),
	})
}

type passwordResetRequest struct {
	Email string `json:"email"`
}

func (s *Server) handleBeginPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req passwordResetRequest
	if !decode(w, r, &req) {
		return
	}
	tok, err := s.identity.BeginPasswordReset(r.Context(), req.Email, httpx.ClientIP(r.Context()))
	if err != nil {
		httpx.Fail(w, r, err)
		return
	}
	if tok.Delivered {
		s.queueResetEmail(r, tok)
	}
	// Identical response either way: the form must not reveal whether an
	// account exists.
	httpx.NoStore(w)
	httpx.JSON(w, r, http.StatusAccepted, map[string]any{
		"status":  "accepted",
		"message": "If that address has an account, we have sent a reset link to it.",
	})
}

type completeResetRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

func (s *Server) handleCompletePasswordReset(w http.ResponseWriter, r *http.Request) {
	var req completeResetRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Token == "" {
		httpx.Fail(w, r, problem.Validation(
			problem.FieldError{Field: "token", Code: "required", Detail: "A reset token is required."}))
		return
	}
	if err := s.identity.CompletePasswordReset(r.Context(), req.Token, req.Password, httpx.ClientIP(r.Context())); err != nil {
		httpx.Fail(w, r, err)
		return
	}
	s.clearSessionCookie(w)
	httpx.NoStore(w)
	httpx.JSON(w, r, http.StatusOK, map[string]any{
		"status":  "password_changed",
		"message": "Your password has been changed and every other session has been signed out.",
	})
}

// publicUser is the only shape a user is ever serialised in. Keeping it in one
// place is how a new internal field avoids accidentally becoming public.
func publicUser(u *identity.User) map[string]any {
	if u == nil {
		return nil
	}
	return map[string]any{
		"id":             u.PublicID,
		"display_name":   u.DisplayName,
		"email_verified": u.EmailVerified,
		"country":        u.Country,
		"roles":          u.Roles,
		"two_factor":     u.TwoFactorOn,
	}
}
