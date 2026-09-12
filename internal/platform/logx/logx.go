// Package logx provides structured JSON logging with automatic redaction.
//
// Every log line is JSON so that it can be shipped to Loki/SigNoz without a
// parsing layer. Any attribute whose key looks like a secret is replaced before
// it reaches an io.Writer, which means an accidental log.Info("req", "body",
// body) cannot leak a card number or an API key.
package logx

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
)

type ctxKey int

const (
	ctxKeyLogger ctxKey = iota
	ctxKeyRequestID
)

// sensitiveKeys are matched case-insensitively as substrings of an attribute key.
var sensitiveKeys = []string{
	"password", "passwd", "secret", "token", "authorization", "cookie",
	"api_key", "apikey", "private_key", "signature", "otp", "totp",
	"card", "cvv", "pan_number", "aadhaar", "account_number", "ifsc",
	"session", "csrf", "webhook_secret", "dek", "kek", "credential",
}

const redacted = "[REDACTED]"

// Redact returns a ReplaceAttr function that masks sensitive values at any depth.
func Redact() func([]string, slog.Attr) slog.Attr {
	return func(_ []string, a slog.Attr) slog.Attr {
		lk := strings.ToLower(a.Key)
		for _, s := range sensitiveKeys {
			if strings.Contains(lk, s) {
				return slog.String(a.Key, redacted)
			}
		}
		return a
	}
}

// Options configures the root logger.
type Options struct {
	Level     slog.Level
	Writer    io.Writer
	Service   string
	Version   string
	Env       string
	AddSource bool
}

// New builds the root logger. It always emits JSON; human-friendly rendering is
// the job of the log viewer, not of production processes.
func New(o Options) *slog.Logger {
	w := o.Writer
	if w == nil {
		w = os.Stdout
	}
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level:       o.Level,
		AddSource:   o.AddSource,
		ReplaceAttr: Redact(),
	})
	return slog.New(h).With(
		slog.String("service", o.Service),
		slog.String("version", o.Version),
		slog.String("env", o.Env),
	)
}

// Into stores a logger on the context.
func Into(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, ctxKeyLogger, l)
}

// From retrieves the request-scoped logger, falling back to the default.
func From(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(ctxKeyLogger).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.Default()
}

// WithRequestID tags the context so every downstream line correlates.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKeyRequestID, id)
}

// RequestID reads the correlation id, or "" when absent.
func RequestID(ctx context.Context) string {
	if s, ok := ctx.Value(ctxKeyRequestID).(string); ok {
		return s
	}
	return ""
}

// ParseLevel maps a configuration string to a slog level, defaulting to info.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
