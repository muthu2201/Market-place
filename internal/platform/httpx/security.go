package httpx

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/muthu2201/market-place/internal/platform/cryptox"
	"github.com/muthu2201/market-place/internal/platform/logx"
	"github.com/muthu2201/market-place/internal/platform/problem"
)

// SecurityHeaderOptions configures the response hardening middleware.
type SecurityHeaderOptions struct {
	HSTSMaxAge time.Duration
	// Enable HSTS only behind TLS; sending it over plain HTTP is ignored by
	// browsers but signals a misconfiguration.
	EnableHSTS bool
	// ExtraConnectSrc allows an analytics or error endpoint without loosening
	// the rest of the policy.
	ExtraConnectSrc []string
	// FrameAncestors is 'none' by default. Only a deliberate embed use case
	// should change it.
	FrameAncestors string
	// ReportURI receives CSP violation reports when set.
	ReportURI string
}

// SecurityHeaders applies a strict, nonce-based Content-Security-Policy plus the
// rest of the modern header set.
//
// The policy deliberately contains no 'unsafe-inline' and no 'unsafe-eval'. Every
// inline script must carry the per-response nonce, which templates read from the
// request context. That is what makes a stored-XSS payload inert even if output
// encoding were ever missed somewhere.
func SecurityHeaders(o SecurityHeaderOptions) Middleware {
	if o.FrameAncestors == "" {
		o.FrameAncestors = "'none'"
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nonce := newNonce()
			ctx := context.WithValue(r.Context(), ctxKeyCSPNonce, nonce)

			connect := "'self'"
			if len(o.ExtraConnectSrc) > 0 {
				connect += " " + strings.Join(o.ExtraConnectSrc, " ")
			}

			csp := strings.Join([]string{
				"default-src 'self'",
				"base-uri 'none'",
				"object-src 'none'",
				"script-src 'self' 'nonce-" + nonce + "'",
				"style-src 'self' 'nonce-" + nonce + "'",
				// Buyer-visible previews come from our own origin or the CDN,
				// never from arbitrary remote hosts a seller could point at.
				"img-src 'self' data: blob:",
				"media-src 'self' blob:",
				"font-src 'self'",
				"connect-src " + connect,
				"form-action 'self'",
				"frame-ancestors " + o.FrameAncestors,
				"frame-src 'none'",
				"worker-src 'self' blob:",
				"manifest-src 'self'",
				"upgrade-insecure-requests",
			}, "; ")
			if o.ReportURI != "" {
				csp += "; report-uri " + o.ReportURI
			}

			h := w.Header()
			h.Set("Content-Security-Policy", csp)
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
			h.Set("Cross-Origin-Resource-Policy", "same-origin")
			h.Set("Cross-Origin-Embedder-Policy", "credentialless")
			h.Set("Permissions-Policy", strings.Join([]string{
				"accelerometer=()", "autoplay=()", "camera=()", "geolocation=()",
				"gyroscope=()", "magnetometer=()", "microphone=()", "payment=()",
				"usb=()", "interest-cohort=()", "browsing-topics=()",
			}, ", "))
			h.Set("X-Permitted-Cross-Domain-Policies", "none")
			// Remove the header Go sets for us that discloses nothing useful to
			// a user but does help an attacker fingerprint the stack.
			h.Del("X-Powered-By")

			if o.EnableHSTS && o.HSTSMaxAge > 0 {
				h.Set("Strict-Transport-Security",
					"max-age="+strconv.Itoa(int(o.HSTSMaxAge.Seconds()))+"; includeSubDomains; preload")
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func newNonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("httpx: crypto/rand unavailable: " + err.Error())
	}
	return base64.RawStdEncoding.EncodeToString(b[:])
}

// CSPNonce returns the per-response nonce for templates.
func CSPNonce(ctx context.Context) string {
	if s, ok := ctx.Value(ctxKeyCSPNonce).(string); ok {
		return s
	}
	return ""
}

// ---- CSRF -------------------------------------------------------------------

const (
	// CSRFCookieName uses the __Host- prefix so the cookie is locked to this
	// exact origin: it cannot be set by a subdomain or over plain HTTP.
	CSRFCookieName    = "__Host-csrf"
	CSRFCookieNameDev = "csrf_dev"
	CSRFHeaderName    = "X-CSRF-Token"
	CSRFFormField     = "csrf_token"
	csrfTokenBytes    = 32
)

// CSRFOptions configures the CSRF middleware.
type CSRFOptions struct {
	Key            []byte
	Secure         bool
	Domain         string
	TTL            time.Duration
	TrustedOrigins []string
}

// CSRF implements defence in depth: a signed double-submit cookie AND an
// Origin/Sec-Fetch-Site check.
//
// The double-submit token defeats classic forgery. The Origin check additionally
// defeats the cookie-injection variant where a network attacker or a
// compromised sibling subdomain plants a cookie value it also knows.
func CSRF(o CSRFOptions) Middleware {
	if o.TTL == 0 {
		o.TTL = 12 * time.Hour
	}
	cookieName := CSRFCookieName
	if !o.Secure {
		// __Host- requires Secure; in local HTTP development use a plain name
		// rather than silently emitting a cookie browsers will drop.
		cookieName = CSRFCookieNameDev
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := ensureCSRFCookie(w, r, o, cookieName)
			ctx := context.WithValue(r.Context(), ctxKeyCSRFToken, token)
			r = r.WithContext(ctx)

			if safeMethod(r.Method) {
				next.ServeHTTP(w, r)
				return
			}

			if err := checkOrigin(r, o.TrustedOrigins); err != nil {
				problem.New(http.StatusForbidden, problem.TypeCSRF, "Cross-origin request refused", err.Error()).
					Write(w, logx.RequestID(r.Context()))
				return
			}

			sent := r.Header.Get(CSRFHeaderName)
			if sent == "" {
				// Only touch the form when the content type says there is one:
				// ParseForm on a JSON body would consume it.
				if isFormContentType(r.Header.Get("Content-Type")) {
					if err := r.ParseForm(); err == nil {
						sent = r.PostFormValue(CSRFFormField)
					}
				}
			}
			if sent == "" || !verifyCSRFToken(o.Key, sent) || !cryptox.ConstantTimeEqualString(sent, token) {
				problem.New(http.StatusForbidden, problem.TypeCSRF, "CSRF check failed",
					"The anti-forgery token was missing, stale or did not match. Reload the page and try again.").
					Write(w, logx.RequestID(r.Context()))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

const ctxKeyCSRFToken ctxKey = 100

// CSRFToken returns the token templates must embed in forms.
func CSRFToken(ctx context.Context) string {
	if s, ok := ctx.Value(ctxKeyCSRFToken).(string); ok {
		return s
	}
	return ""
}

func safeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	return false
}

func isFormContentType(ct string) bool {
	mt := strings.TrimSpace(strings.ToLower(strings.Split(ct, ";")[0]))
	return mt == "application/x-www-form-urlencoded" || mt == "multipart/form-data"
}

// checkOrigin prefers Sec-Fetch-Site (which a page cannot forge) and falls back
// to Origin, then to Referer for the small set of clients that send neither.
func checkOrigin(r *http.Request, trusted []string) error {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return nil
	case "cross-site", "same-site":
		// same-site still means a different origin (another subdomain), which
		// we do not accept for state-changing requests.
		if !originAllowed(r.Header.Get("Origin"), trusted) {
			return errCrossOrigin
		}
		return nil
	}
	if o := r.Header.Get("Origin"); o != "" {
		if originAllowed(o, trusted) {
			return nil
		}
		return errCrossOrigin
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		u, err := url.Parse(ref)
		if err != nil {
			return errCrossOrigin
		}
		if originAllowed(u.Scheme+"://"+u.Host, trusted) {
			return nil
		}
		return errCrossOrigin
	}
	// Neither Sec-Fetch-Site, Origin nor Referer: refuse rather than assume.
	return errNoOrigin
}

type csrfError string

func (e csrfError) Error() string { return string(e) }

const (
	errCrossOrigin = csrfError("The request originated from an origin this server does not trust.")
	errNoOrigin    = csrfError("The request carried no Origin, Referer or Sec-Fetch-Site header.")
)

func originAllowed(origin string, trusted []string) bool {
	if origin == "" || origin == "null" {
		return false
	}
	for _, t := range trusted {
		if strings.EqualFold(strings.TrimSuffix(t, "/"), strings.TrimSuffix(origin, "/")) {
			return true
		}
	}
	return false
}

// ensureCSRFCookie returns the current token, minting one when absent or invalid.
func ensureCSRFCookie(w http.ResponseWriter, r *http.Request, o CSRFOptions, name string) string {
	if c, err := r.Cookie(name); err == nil && verifyCSRFToken(o.Key, c.Value) {
		return c.Value
	}
	tok := newCSRFToken(o.Key)
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    tok,
		Path:     "/",
		Domain:   o.Domain,
		MaxAge:   int(o.TTL.Seconds()),
		Secure:   o.Secure,
		HttpOnly: false, // the page must read it to set the header
		SameSite: http.SameSiteLaxMode,
	})
	return tok
}

// newCSRFToken is random||hmac(random). Signing means a forged cookie value is
// rejected before any comparison against the submitted token.
func newCSRFToken(key []byte) string {
	var raw [csrfTokenBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic("httpx: crypto/rand unavailable: " + err.Error())
	}
	body := base64.RawURLEncoding.EncodeToString(raw[:])
	mac := cryptox.Sign(key, []byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(mac)
}

func verifyCSRFToken(key []byte, tok string) bool {
	i := strings.LastIndexByte(tok, '.')
	if i <= 0 || len(tok) > 256 {
		return false
	}
	mac, err := base64.RawURLEncoding.DecodeString(tok[i+1:])
	if err != nil {
		return false
	}
	return cryptox.VerifyHMAC(key, []byte(tok[:i]), mac)
}

// ---- CORS -------------------------------------------------------------------

// CORS answers preflights for an explicit allow-list. There is no wildcard and
// no origin reflection: reflecting Origin with credentials enabled is the
// single most common CORS vulnerability.
func CORS(allowed []string) Middleware {
	allowSet := make(map[string]struct{}, len(allowed))
	for _, a := range allowed {
		allowSet[strings.ToLower(strings.TrimSuffix(a, "/"))] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" {
				if _, ok := allowSet[strings.ToLower(strings.TrimSuffix(origin, "/"))]; ok {
					h := w.Header()
					h.Set("Access-Control-Allow-Origin", origin)
					h.Set("Access-Control-Allow-Credentials", "true")
					h.Add("Vary", "Origin")
					if r.Method == http.MethodOptions {
						h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
						h.Set("Access-Control-Allow-Headers", "Content-Type, "+CSRFHeaderName+", X-Request-Id, Idempotency-Key, Authorization")
						h.Set("Access-Control-Max-Age", "600")
						w.WriteHeader(http.StatusNoContent)
						return
					}
				} else if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusForbidden)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
