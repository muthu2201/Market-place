package api

import (
	"context"
	"net/http"
	"time"

	"github.com/muthu2201/market-place/internal/modules/identity"
	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/ids"
)

// queueVerificationEmail and queueResetEmail write a notification row rather
// than sending inline.
//
// Sending inside the request would make sign-up latency depend on an SMTP
// handshake and would lose the message entirely if delivery failed. The worker
// sends it, retries it, and records the outcome.
func (s *Server) queueVerificationEmail(r *http.Request, tok identity.IssuedToken) {
	s.queueMail(r, tok, "email_verification", map[string]any{
		"verify_url": s.cfg.HTTP.PublicBaseURL.String() + "/verify?token=" + tok.Token,
		"expires_in": "24 hours",
	})
}

func (s *Server) queueResetEmail(r *http.Request, tok identity.IssuedToken) {
	s.queueMail(r, tok, "password_reset", map[string]any{
		"reset_url":  s.cfg.HTTP.PublicBaseURL.String() + "/reset?token=" + tok.Token,
		"expires_in": "30 minutes",
	})
}

func (s *Server) queueMail(r *http.Request, tok identity.IssuedToken, template string, vars map[string]any) {
	// Detached from the request context so a client disconnect does not lose a
	// transactional message the user is waiting for.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer cancel()

	var toCT []byte
	if tok.Email != "" {
		if dek, err := s.identity.Vault().SubjectKey(ctx, s.db, tok.UserID); err == nil {
			toCT, _ = s.identity.Vault().Encrypt(dek, tok.UserID, "notification_to", tok.Email)
		}
	}
	if _, err := s.db.Exec(ctx, `
		INSERT INTO notifications (id, public_id, user_id, channel, template, variables, to_ciphertext, category)
		VALUES ($1,$2,$3,'email',$4,$5,$6,'transactional')`,
		ids.NewUUIDv7(), ids.NewPublic(ids.PrefixNotification), tok.UserID, template, vars, toCT,
	); err != nil {
		logFrom(r).Error("could not queue transactional mail",
			"template", template, "error", err.Error())
	}
}

var _ = db.IsNoRows
