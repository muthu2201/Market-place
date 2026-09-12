// Package audit writes the tamper-evident activity log.
//
// The chain itself lives in the database (db/migrations/0001_infrastructure.sql):
// each row carries the digest of the previous one, so altering or removing any
// historical entry breaks verification. This package is the only sanctioned way
// to append, and it is deliberately narrow: an action name, a subject, and a
// metadata map that has already been stripped of personal data.
package audit

import (
	"context"
	"fmt"

	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/ids"
	"github.com/muthu2201/market-place/internal/platform/logx"
)

// ActorKind says who performed the action.
type ActorKind string

const (
	ActorUser      ActorKind = "user"
	ActorSeller    ActorKind = "seller"
	ActorAdmin     ActorKind = "admin"
	ActorSystem    ActorKind = "system"
	ActorProvider  ActorKind = "provider"
	ActorAnonymous ActorKind = "anonymous"
)

// Event is one audit record.
type Event struct {
	ActorKind   ActorKind
	ActorID     *ids.UUID
	ActorIP     string
	Action      string
	SubjectType string
	SubjectID   string
	Metadata    map[string]any
}

// Service appends to the log.
type Service struct{}

func New() *Service { return &Service{} }

// Record appends one event. It takes the caller's Querier so the audit row is
// written in the same transaction as the action it describes: an action that
// rolls back leaves no audit entry claiming it happened.
func (s *Service) Record(ctx context.Context, q db.Querier, e Event) error {
	if e.Action == "" || e.SubjectType == "" {
		return fmt.Errorf("audit: action and subject type are required")
	}
	if e.ActorKind == "" {
		e.ActorKind = ActorSystem
	}
	meta := e.Metadata
	if meta == nil {
		meta = map[string]any{}
	}
	var actorID any
	if e.ActorID != nil && !e.ActorID.IsZero() {
		actorID = *e.ActorID
	}
	var ip any
	if e.ActorIP != "" {
		ip = e.ActorIP
	}
	var reqID any
	if r := logx.RequestID(ctx); r != "" {
		reqID = r
	}

	_, err := q.Exec(ctx, `
		INSERT INTO audit_log (actor_kind, actor_id, actor_ip, action, subject_type, subject_id, request_id, metadata)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		string(e.ActorKind), actorID, ip, e.Action, e.SubjectType, nullIfEmpty(e.SubjectID), reqID, meta)
	if err != nil {
		return fmt.Errorf("audit: record %s: %w", e.Action, err)
	}
	return nil
}

// Break describes a detected tampering point.
type Break struct {
	Seq    int64
	Reason string
}

// Verify walks the chain and returns the first break, or nil when intact.
// The operations runbook schedules this; a break is a security incident.
func (s *Service) Verify(ctx context.Context, q db.Querier, fromSeq int64) (*Break, error) {
	rows, err := q.Query(ctx, `SELECT broken_at, reason FROM verify_audit_chain($1)`, fromSeq)
	if err != nil {
		return nil, fmt.Errorf("audit: verify: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		var b Break
		if err := rows.Scan(&b.Seq, &b.Reason); err != nil {
			return nil, err
		}
		return &b, nil
	}
	return nil, rows.Err()
}

// Entry is a record as read back for an investigation.
type Entry struct {
	Seq         int64
	Action      string
	ActorKind   ActorKind
	ActorID     *ids.UUID
	SubjectType string
	SubjectID   string
	RequestID   string
	Metadata    map[string]any
	OccurredAt  string
}

// ForSubject returns the most recent entries about one subject.
func (s *Service) ForSubject(ctx context.Context, q db.Querier, subjectType, subjectID string, limit int) ([]Entry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := q.Query(ctx, `
		SELECT seq, action, actor_kind, actor_id, subject_type, COALESCE(subject_id,''),
		       COALESCE(request_id,''), metadata, occurred_at::text
		  FROM audit_log
		 WHERE subject_type = $1 AND subject_id = $2
		 ORDER BY seq DESC LIMIT $3`, subjectType, subjectID, limit)
	if err != nil {
		return nil, fmt.Errorf("audit: for subject: %w", err)
	}
	defer rows.Close()

	var out []Entry
	for rows.Next() {
		var e Entry
		var kind string
		var actor *ids.UUID
		if err := rows.Scan(&e.Seq, &e.Action, &kind, &actor, &e.SubjectType, &e.SubjectID,
			&e.RequestID, &e.Metadata, &e.OccurredAt); err != nil {
			return nil, err
		}
		e.ActorKind = ActorKind(kind)
		e.ActorID = actor
		out = append(out, e)
	}
	return out, rows.Err()
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
