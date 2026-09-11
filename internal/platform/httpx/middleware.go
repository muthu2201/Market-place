// Package httpx holds the HTTP edge: middleware, security headers, CSRF, client
// IP resolution and response helpers.
//
// The middleware order in Chain() is itself a security control and is asserted
// by a test: recovery must be outermost so a panic in any later layer still
// produces a correlated 500; body limiting must precede anything that reads a
// body; rate limiting must precede authentication so an unauthenticated flood
// cannot force password hashing.
package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/muthu2201/market-place/internal/platform/ids"
	"github.com/muthu2201/market-place/internal/platform/logx"
	"github.com/muthu2201/market-place/internal/platform/metrics"
	"github.com/muthu2201/market-place/internal/platform/problem"
	"github.com/muthu2201/market-place/internal/platform/ratelimit"
)

type ctxKey int

const (
	ctxKeyRoute ctxKey = iota
	ctxKeyClientIP
	ctxKeyCSPNonce
	ctxKeyStart
)

// Middleware decorates a handler.
type Middleware func(http.Handler) http.Handler

// Chain applies middleware so that the first argument is the outermost layer.
func Chain(h http.Handler, mw ...Middleware) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}

// responseWriter captures status and byte count, and refuses a second
// WriteHeader (a common source of "superfluous WriteHeader" log noise that
// masks real double-write bugs).
type responseWriter struct {
	http.ResponseWriter
	status      int
	bytes       int64
	wroteHeader bool
}

func (w *responseWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *responseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

func (w *responseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *responseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// RequestID assigns or adopts a correlation id and echoes it to the client.
func RequestID() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get("X-Request-Id")
			// An inbound id is only adopted if it is safely shaped; otherwise a
			// caller could inject newlines or unbounded data into our logs.
			if !validCorrelation(id) {
				id = ids.Correlation()
			}
			ctx := logx.WithRequestID(r.Context(), id)
			ctx = context.WithValue(ctx, ctxKeyStart, time.Now())
			w.Header().Set("X-Request-Id", id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func validCorrelation(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			continue
		}
		return false
	}
	return true
}

// Recover converts a panic into a correlated 500 and keeps the process alive.
func Recover(log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				rec := recover()
				if rec == nil {
					return
				}
				if err, ok := rec.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					panic(rec) // the server handles this one itself
				}
				rid := logx.RequestID(r.Context())
				log.ErrorContext(r.Context(), "panic recovered",
					slog.Any("panic", rec),
					slog.String("request_id", rid),
					slog.String("route", RouteOf(r.Context())),
					slog.String("stack", string(debug.Stack())),
				)
				problem.Internal(fmt.Errorf("panic: %v", rec)).Write(w, rid)
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// Logging emits one structured line per request. It never logs the body, the
// query string or any header, because all three routinely carry secrets.
func Logging(log *slog.Logger, m *metrics.App) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
			if m != nil {
				m.HTTPInFlight.Set(1)
			}
			rid := logx.RequestID(r.Context())
			reqLog := log.With(slog.String("request_id", rid))
			ctx := logx.Into(r.Context(), reqLog)

			next.ServeHTTP(rw, r.WithContext(ctx))

			route := RouteOf(ctx)
			if route == "" {
				route = "unmatched"
			}
			dur := time.Since(start)
			level := slog.LevelInfo
			switch {
			case rw.status >= 500:
				level = slog.LevelError
			case rw.status >= 400:
				level = slog.LevelWarn
			}
			reqLog.LogAttrs(ctx, level, "http request",
				slog.String("method", r.Method),
				slog.String("route", route),
				slog.Int("status", rw.status),
				slog.Int64("bytes", rw.bytes),
				slog.Float64("duration_ms", float64(dur.Microseconds())/1000),
				slog.String("client_ip", ClientIP(ctx)),
			)
			if m != nil {
				m.HTTPRequests.Inc(route, r.Method, statusClass(rw.status))
				m.HTTPDuration.Observe(dur.Seconds(), route, r.Method)
				m.HTTPResponseBytes.Add(uint64(rw.bytes), route)
			}
		})
	}
}

func statusClass(code int) string {
	switch {
	case code < 200:
		return "1xx"
	case code < 300:
		return "2xx"
	case code < 400:
		return "3xx"
	case code < 500:
		return "4xx"
	}
	return "5xx"
}

// Route records the route template for metrics and logs. Handlers call it (or
// the router does) so that cardinality stays bounded by the number of routes
// rather than by the number of distinct URLs an attacker can invent.
func Route(ctx context.Context, template string) context.Context {
	return context.WithValue(ctx, ctxKeyRoute, template)
}

func RouteOf(ctx context.Context) string {
	if s, ok := ctx.Value(ctxKeyRoute).(string); ok {
		return s
	}
	return ""
}

// WithRoute wraps a handler so that its template is attached before it runs.
func WithRoute(template string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(Route(r.Context(), template)))
	})
}

// MaxBytes caps the request body. Beyond the limit the body reader returns an
// error, which handlers translate into 413.
func MaxBytes(limit int64) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, limit)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Timeout bounds total handler time. It is separate from the server's
// WriteTimeout so that a slow handler produces a 503 with a request id rather
// than a silently dropped connection.
func Timeout(d time.Duration) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), d)
			defer cancel()
			done := make(chan struct{})
			rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
			go func() {
				defer func() {
					if rec := recover(); rec != nil {
						// Re-raise on the original goroutine's behalf via the
						// response so Recover's contract is preserved.
						logx.From(ctx).Error("panic in timed handler", slog.Any("panic", rec), slog.String("stack", string(debug.Stack())))
						if !rw.wroteHeader {
							problem.Internal(fmt.Errorf("panic: %v", rec)).Write(rw, logx.RequestID(ctx))
						}
					}
					close(done)
				}()
				next.ServeHTTP(rw, r.WithContext(ctx))
			}()
			select {
			case <-done:
			case <-ctx.Done():
				if !rw.wroteHeader {
					problem.Unavailable("The request took too long to process.", 5).Write(w, logx.RequestID(ctx))
				}
			}
		})
	}
}

// RealIP resolves the client address, honouring X-Forwarded-For only when the
// immediate peer is inside a configured trusted CIDR. Without that check any
// client can forge its own IP and defeat every per-IP limit.
func RealIP(trustedCIDRs []string) Middleware {
	nets := make([]*net.IPNet, 0, len(trustedCIDRs))
	for _, c := range trustedCIDRs {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil {
			nets = append(nets, n)
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := peerIP(r.RemoteAddr)
			if trusted(nets, ip) {
				if fwd := clientFromForwarded(r, nets); fwd != "" {
					ip = fwd
				}
			}
			ctx := context.WithValue(r.Context(), ctxKeyClientIP, ip)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func peerIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func trusted(nets []*net.IPNet, ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// clientFromForwarded walks X-Forwarded-For from right to left and returns the
// right-most address that is NOT one of our own proxies. Taking the left-most
// entry (the common mistake) trusts whatever the client sent.
func clientFromForwarded(r *http.Request, nets []*net.IPNet) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		// Cloudflare's header is single-valued and set by the edge.
		if cf := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cf != "" && net.ParseIP(cf) != nil {
			return cf
		}
		return ""
	}
	parts := strings.Split(xff, ",")
	if len(parts) > 32 {
		parts = parts[len(parts)-32:] // bound the work an attacker can force
	}
	for i := len(parts) - 1; i >= 0; i-- {
		cand := strings.TrimSpace(parts[i])
		if net.ParseIP(cand) == nil {
			return ""
		}
		if !trusted(nets, cand) {
			return cand
		}
	}
	return ""
}

// ClientIP returns the resolved client address.
func ClientIP(ctx context.Context) string {
	if s, ok := ctx.Value(ctxKeyClientIP).(string); ok {
		return s
	}
	return ""
}

// RateLimit applies a local GCRA limit keyed by client IP.
func RateLimit(l *ratelimit.Local, rule ratelimit.Rule, m *metrics.App) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := ClientIP(r.Context())
			d := l.Allow(key, rule)
			h := w.Header()
			h.Set("RateLimit-Limit", strconv.Itoa(rule.Burst))
			h.Set("RateLimit-Remaining", strconv.Itoa(d.Remaining))
			h.Set("RateLimit-Reset", strconv.Itoa(int(d.ResetAfter.Seconds()+0.999)))
			if !d.Allowed {
				if m != nil {
					m.RateLimitDecisions.Inc(rule.Name, "blocked")
				}
				problem.RateLimited(int(d.RetryAfter.Seconds()+0.999)).Write(w, logx.RequestID(r.Context()))
				return
			}
			if m != nil {
				m.RateLimitDecisions.Inc(rule.Name, "allowed")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// NoStore marks a response as never cacheable. Applied to everything that
// depends on the session.
func NoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
	w.Header().Set("Pragma", "no-cache")
}

// ---- response helpers -------------------------------------------------------

// JSON writes a JSON response with the correct headers.
func JSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	buf, err := json.Marshal(v)
	if err != nil {
		problem.Internal(err).Write(w, logx.RequestID(r.Context()))
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(buf)
}

// Fail writes an error as a problem document, logging the internal cause.
func Fail(w http.ResponseWriter, r *http.Request, err error) {
	rid := logx.RequestID(r.Context())
	p := problem.As(err)
	if p == nil {
		p = problem.Internal(err)
	}
	if p.Status >= 500 {
		logx.From(r.Context()).Error("request failed",
			slog.String("error", err.Error()),
			slog.String("route", RouteOf(r.Context())),
			slog.Int("status", p.Status),
		)
	}
	p.Write(w, rid)
}

// DecodeJSON reads a JSON body with strict semantics: unknown fields are
// rejected, trailing data is rejected, and the size is already capped by
// MaxBytes upstream.
func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	ct := r.Header.Get("Content-Type")
	if ct != "" {
		mt := strings.TrimSpace(strings.Split(ct, ";")[0])
		if !strings.EqualFold(mt, "application/json") {
			return problem.New(http.StatusUnsupportedMediaType, problem.TypeUnsupportedMedia,
				"Unsupported media type", "This endpoint accepts application/json.")
		}
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return problem.New(http.StatusRequestEntityTooLarge, problem.TypePayloadTooLarge,
				"Request body too large", "The request body exceeded the permitted size.")
		}
		var syn *json.SyntaxError
		var typ *json.UnmarshalTypeError
		switch {
		case errors.As(err, &syn):
			return problem.Validation(problem.FieldError{Field: "body", Code: "malformed_json",
				Detail: fmt.Sprintf("Invalid JSON at byte offset %d.", syn.Offset)})
		case errors.As(err, &typ):
			return problem.Validation(problem.FieldError{Field: typ.Field, Code: "wrong_type",
				Detail: fmt.Sprintf("Expected %s.", typ.Type.String())})
		case errors.Is(err, io.EOF):
			return problem.Validation(problem.FieldError{Field: "body", Code: "required", Detail: "A JSON body is required."})
		case strings.HasPrefix(err.Error(), "json: unknown field "):
			name := strings.TrimPrefix(err.Error(), "json: unknown field ")
			return problem.Validation(problem.FieldError{Field: strings.Trim(name, `"`), Code: "unknown_field",
				Detail: "This field is not accepted by this endpoint."})
		}
		return problem.Validation(problem.FieldError{Field: "body", Code: "malformed_json", Detail: "The request body could not be parsed."})
	}
	if dec.More() {
		return problem.Validation(problem.FieldError{Field: "body", Code: "trailing_data",
			Detail: "The request body must contain exactly one JSON value."})
	}
	return nil
}
