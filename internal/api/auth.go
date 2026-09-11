// Package api is the HTTP composition root: routing, authentication,
// authorisation and request/response translation.
//
// Business rules do not live here. Every handler is a thin translation between
// HTTP and a module service, which is what keeps the rules testable without a
// server and keeps this layer reviewable as a security boundary rather than as
// a second implementation.
package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/muthu2201/market-place/internal/modules/identity"
	"github.com/muthu2201/market-place/internal/platform/httpx"
	"github.com/muthu2201/market-place/internal/platform/problem"
)

type ctxKey int

const ctxKeySession ctxKey = iota

// SessionCookieName uses the __Host- prefix, which binds the cookie to this
// exact origin: it cannot be set by a subdomain, cannot carry a Domain
// attribute, and is refused over plain HTTP.
const (
	SessionCookieName    = "__Host-session"
	SessionCookieNameDev = "session_dev"
)

func (s *Server) sessionCookieName() string {
	if s.cfg.Security.SecureCookies {
		return SessionCookieName
	}
	// __Host- requires Secure, so local HTTP development uses a plain name
	// rather than silently emitting a cookie the browser will drop.
	return SessionCookieNameDev
}

// setSessionCookie issues the session cookie with the full hardening set.
func (s *Server) setSessionCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.sessionCookieName(),
		Value:    token,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		Secure:   s.cfg.Security.SecureCookies,
		HttpOnly: true, // script must never be able to read the session
		// Lax rather than Strict: Strict breaks the return journey from the
		// payment provider, and every state-changing request is separately
		// protected by the CSRF token and an Origin check.
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.sessionCookieName(),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   s.cfg.Security.SecureCookies,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// authenticate resolves a session from the cookie, or from a bearer token for
// API clients. It never fails the request: it simply leaves the context
// unauthenticated, and the authorisation middleware decides what that means.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := ""
		if c, err := r.Cookie(s.sessionCookieName()); err == nil {
			token = c.Value
		}
		if token == "" {
			if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
				token = strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
			}
		}
		if token == "" {
			next.ServeHTTP(w, r)
			return
		}
		sess, err := s.identity.ResolveSession(r.Context(), token)
		if err != nil {
			// An invalid or expired cookie is cleared so the browser stops
			// sending it, then treated as anonymous.
			s.clearSessionCookie(w)
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeySession, sess)))
	})
}

// SessionOf returns the authenticated session, or nil.
func SessionOf(ctx context.Context) *identity.Session {
	if s, ok := ctx.Value(ctxKeySession).(*identity.Session); ok {
		return s
	}
	return nil
}

// requireAuth refuses anonymous requests and requests whose second factor is
// still outstanding.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := SessionOf(r.Context())
		if sess == nil {
			httpx.Fail(w, r, problem.Unauthenticated("Sign in to continue."))
			return
		}
		if sess.AuthLevel != "full" {
			httpx.Fail(w, r, problem.New(http.StatusUnauthorized, problem.TypeTwoFactorRequired,
				"Two-factor authentication required",
				"Finish signing in by entering the code from your authenticator app."))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requirePartialAuth allows a session that has not yet completed its second
// factor. Used only by the 2FA challenge endpoints.
func (s *Server) requirePartialAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if SessionOf(r.Context()) == nil {
			httpx.Fail(w, r, problem.Unauthenticated("Sign in to continue."))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireRole enforces role membership.
//
// The role set is re-read from the database on every request by
// ResolveSession, so a revocation takes effect immediately rather than when a
// token happens to expire.
func (s *Server) requireRole(roles ...string) httpx.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess := SessionOf(r.Context())
			if sess == nil {
				httpx.Fail(w, r, problem.Unauthenticated("Sign in to continue."))
				return
			}
			if sess.AuthLevel != "full" {
				httpx.Fail(w, r, problem.New(http.StatusUnauthorized, problem.TypeTwoFactorRequired,
					"Two-factor authentication required", "Finish signing in first."))
				return
			}
			for _, role := range roles {
				if sess.User.HasRole(role) {
					next.ServeHTTP(w, r)
					return
				}
			}
			// A 403 here confirms the resource exists. Handlers that must not
			// confirm existence return 404 from inside the service instead.
			httpx.Fail(w, r, problem.Forbidden("Your account does not have access to this area."))
		})
	}
}

// requireVerifiedEmail gates actions that send mail or move money.
func (s *Server) requireVerifiedEmail(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := SessionOf(r.Context())
		if sess == nil {
			httpx.Fail(w, r, problem.Unauthenticated("Sign in to continue."))
			return
		}
		if !sess.User.EmailVerified {
			httpx.Fail(w, r, problem.Forbidden(
				"Verify your e-mail address before continuing. We have sent you a link."))
			return
		}
		next.ServeHTTP(w, r)
	})
}
