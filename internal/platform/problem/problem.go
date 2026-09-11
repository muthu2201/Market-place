// Package problem implements RFC 9457 "Problem Details for HTTP APIs".
//
// Every non-2xx API response in this system is a problem document. Two rules
// keep it safe: the "detail" field is written for a human operator but is
// scrubbed of internals, and a correlation id is always returned so that a user
// report can be tied to a server log without exposing a stack trace.
package problem

import (
	"encoding/json"
	"errors"
	"net/http"
)

// Type URIs are stable, documented and versioned. They are the machine-readable
// contract; HTTP status alone is not specific enough for clients.
const base = "https://errors.marketplace.in/v1/"

const (
	TypeValidation        = base + "validation-failed"
	TypeUnauthenticated   = base + "unauthenticated"
	TypeForbidden         = base + "forbidden"
	TypeNotFound          = base + "not-found"
	TypeConflict          = base + "conflict"
	TypeRateLimited       = base + "rate-limited"
	TypePayloadTooLarge   = base + "payload-too-large"
	TypeUnsupportedMedia  = base + "unsupported-media-type"
	TypeInternal          = base + "internal-error"
	TypeUnavailable       = base + "service-unavailable"
	TypeIdempotencyReuse  = base + "idempotency-key-reuse"
	TypePaymentFailed     = base + "payment-failed"
	TypeSettlementBlocked = base + "settlement-blocked"
	TypeKYCRequired       = base + "kyc-required"
	TypeEntitlement       = base + "entitlement-required"
	TypeDownloadExhausted = base + "download-limit-reached"
	TypeStateTransition   = base + "invalid-state-transition"
	TypeCSRF              = base + "csrf-check-failed"
	TypeAccountLocked     = base + "account-locked"
	TypeTwoFactorRequired = base + "two-factor-required"
)

// FieldError names one invalid input.
type FieldError struct {
	Field  string `json:"field"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// Problem is the wire representation.
type Problem struct {
	Type       string       `json:"type"`
	Title      string       `json:"title"`
	Status     int          `json:"status"`
	Detail     string       `json:"detail,omitempty"`
	Instance   string       `json:"instance,omitempty"`
	RequestID  string       `json:"request_id,omitempty"`
	Errors     []FieldError `json:"errors,omitempty"`
	RetryAfter int          `json:"retry_after_seconds,omitempty"`

	// cause is never serialised; it is what the server logs.
	cause error
}

func (p *Problem) Error() string {
	if p.Detail != "" {
		return p.Title + ": " + p.Detail
	}
	return p.Title
}

func (p *Problem) Unwrap() error { return p.cause }

// WithCause attaches the underlying error for logging only.
func (p *Problem) WithCause(err error) *Problem { p.cause = err; return p }

// WithInstance records which resource the failure concerned.
func (p *Problem) WithInstance(s string) *Problem { p.Instance = s; return p }

// New builds a problem document.
func New(status int, typ, title, detail string) *Problem {
	return &Problem{Type: typ, Title: title, Status: status, Detail: detail}
}

func Validation(errs ...FieldError) *Problem {
	return &Problem{
		Type: TypeValidation, Title: "The request failed validation",
		Status: http.StatusUnprocessableEntity, Errors: errs,
	}
}

func Unauthenticated(detail string) *Problem {
	return New(http.StatusUnauthorized, TypeUnauthenticated, "Authentication is required", detail)
}

func Forbidden(detail string) *Problem {
	return New(http.StatusForbidden, TypeForbidden, "You do not have access to this resource", detail)
}

func NotFound(detail string) *Problem {
	return New(http.StatusNotFound, TypeNotFound, "Resource not found", detail)
}

func Conflict(typ, detail string) *Problem {
	if typ == "" {
		typ = TypeConflict
	}
	return New(http.StatusConflict, typ, "The request conflicts with the current state", detail)
}

func RateLimited(retryAfterSeconds int) *Problem {
	p := New(http.StatusTooManyRequests, TypeRateLimited, "Too many requests", "Slow down and retry after the indicated interval.")
	p.RetryAfter = retryAfterSeconds
	return p
}

func Internal(cause error) *Problem {
	// The detail is deliberately generic: internal errors never describe
	// themselves to a caller.
	return (&Problem{
		Type: TypeInternal, Title: "Internal server error",
		Status: http.StatusInternalServerError,
		Detail: "The request could not be completed. Quote the request id when reporting this.",
	}).WithCause(cause)
}

func Unavailable(detail string, retryAfterSeconds int) *Problem {
	p := New(http.StatusServiceUnavailable, TypeUnavailable, "Service temporarily unavailable", detail)
	p.RetryAfter = retryAfterSeconds
	return p
}

// As extracts a *Problem from an error chain, or nil.
func As(err error) *Problem {
	var p *Problem
	if errors.As(err, &p) {
		return p
	}
	return nil
}

// Write renders the problem as application/problem+json.
func (p *Problem) Write(w http.ResponseWriter, requestID string) {
	p.RequestID = requestID
	body, err := json.Marshal(p)
	if err != nil {
		http.Error(w, `{"type":"`+TypeInternal+`","title":"Internal server error","status":500}`, http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/problem+json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	if p.RetryAfter > 0 {
		h.Set("Retry-After", itoa(p.RetryAfter))
	}
	if p.Status == http.StatusUnauthorized {
		h.Set("WWW-Authenticate", `Bearer realm="marketplace", charset="UTF-8"`)
	}
	w.WriteHeader(p.Status)
	_, _ = w.Write(body)
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := v < 0
	if neg {
		v = -v
	}
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
