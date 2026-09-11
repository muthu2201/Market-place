// Package delivery serves entitled downloads.
//
// The rule that governs every line here: the client is never trusted with a
// delivery decision. A request names a licence and an asset; the server
// re-resolves the entitlement from the session, re-checks expiry and quota, and
// only then issues a ticket. There is no parameter a client can send that
// grants access it does not already have.
//
// A signed URL is a bearer token, so three things bound the damage if one
// leaks: it is short-lived, it is single-use, and consuming it is counted
// against the licence's download quota.
package delivery

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/muthu2201/market-place/internal/modules/audit"
	"github.com/muthu2201/market-place/internal/platform/clock"
	"github.com/muthu2201/market-place/internal/platform/config"
	"github.com/muthu2201/market-place/internal/platform/cryptox"
	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/ids"
	"github.com/muthu2201/market-place/internal/platform/metrics"
	"github.com/muthu2201/market-place/internal/platform/problem"
	"github.com/muthu2201/market-place/internal/platform/ratelimit"
	"github.com/muthu2201/market-place/internal/storage"
)

// Service issues and redeems download tickets.
type Service struct {
	db      *db.DB
	store   storage.Store
	clk     clock.Clock
	cfg     config.PlatformConfig
	signKey []byte
	limiter *ratelimit.Local
	audit   *audit.Service
	m       *metrics.App
}

// Options configures the service.
type Options struct {
	DB       *db.DB
	Store    storage.Store
	Clock    clock.Clock
	Platform config.PlatformConfig
	SignKey  []byte
	Limiter  *ratelimit.Local
	Audit    *audit.Service
	Metrics  *metrics.App
}

func NewService(o Options) (*Service, error) {
	if o.DB == nil || o.Store == nil {
		return nil, errors.New("delivery: database and object store are required")
	}
	if len(o.SignKey) != cryptox.KeySize {
		return nil, fmt.Errorf("delivery: DOWNLOAD_SIGN_KEY must be %d bytes", cryptox.KeySize)
	}
	if o.Clock == nil {
		o.Clock = clock.System()
	}
	if o.Limiter == nil {
		o.Limiter = ratelimit.NewLocal(o.Clock)
	}
	if o.Audit == nil {
		o.Audit = audit.New()
	}
	if o.Platform.DownloadURLTTL <= 0 {
		o.Platform.DownloadURLTTL = 10 * time.Minute
	}
	return &Service{
		db: o.DB, store: o.Store, clk: o.Clock, cfg: o.Platform,
		signKey: o.SignKey, limiter: o.Limiter, audit: o.Audit, m: o.Metrics,
	}, nil
}

// Entitlement is a buyer's view of what they own.
type Entitlement struct {
	LicensePublicID string
	ProductTitle    string
	LicenseType     string
	Terms           string
	DownloadsUsed   int
	DownloadLimit   int
	ExpiresAt       *time.Time
	Revoked         bool
	Assets          []AssetSummary
}

// AssetSummary describes one downloadable file. The object key is deliberately
// absent: a buyer never learns where a file physically lives.
type AssetSummary struct {
	AssetPublicID string
	Filename      string
	SizeBytes     int64
	ContentType   string
	Checksum      string
}

// Ticket is a single-use grant.
type Ticket struct {
	// URL is either a redirect to presigned object storage, or a path this
	// application serves itself when the adapter cannot presign.
	URL       string
	Direct    bool
	ExpiresAt time.Time
	Filename  string
	SizeBytes int64
}

var (
	ErrNoEntitlement = problem.New(http.StatusForbidden, problem.TypeEntitlement,
		"You do not have a licence for this file",
		"Downloads are available only to the account that purchased them.")
	ErrLicenseExpired = problem.New(http.StatusForbidden, problem.TypeEntitlement,
		"This licence has expired",
		"The access period for this licence has ended. Files already downloaded remain yours under the licence terms.")
	ErrLicenseRevoked = problem.New(http.StatusForbidden, problem.TypeEntitlement,
		"This licence is no longer active",
		"This purchase was refunded or the licence was withdrawn.")
	ErrDownloadsExhausted = problem.New(http.StatusForbidden, problem.TypeDownloadExhausted,
		"Download limit reached",
		"This licence's download allowance is used up. Contact support if you need it raised.")
)

// ListEntitlements returns everything a buyer owns.
func (s *Service) ListEntitlements(ctx context.Context, userID ids.UUID, limit, offset int) ([]Entitlement, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := s.db.Query(ctx, `
		SELECT l.id, l.public_id, i.title_snapshot, l.license_type, l.terms_snapshot,
		       l.download_count, l.download_limit, l.access_expires_at, l.status
		  FROM licenses l
		  JOIN order_items i ON i.id = l.order_item_id
		 WHERE l.user_id = $1
		 ORDER BY l.issued_at DESC
		 LIMIT $2 OFFSET $3`, userID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("delivery: list entitlements: %w", err)
	}
	defer rows.Close()

	type row struct {
		id ids.UUID
		e  Entitlement
	}
	var collected []row
	for rows.Next() {
		var r row
		var status string
		if err := rows.Scan(&r.id, &r.e.LicensePublicID, &r.e.ProductTitle, &r.e.LicenseType,
			&r.e.Terms, &r.e.DownloadsUsed, &r.e.DownloadLimit, &r.e.ExpiresAt, &status); err != nil {
			return nil, err
		}
		r.e.Revoked = status != "active"
		collected = append(collected, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]Entitlement, 0, len(collected))
	for _, r := range collected {
		assets, err := s.assetsFor(ctx, r.id)
		if err != nil {
			return nil, err
		}
		r.e.Assets = assets
		out = append(out, r.e)
	}
	return out, nil
}

func (s *Service) assetsFor(ctx context.Context, licenseID ids.UUID) ([]AssetSummary, error) {
	rows, err := s.db.Query(ctx, `
		SELECT a.public_id, a.filename, a.size_bytes, a.content_type, encode(a.checksum, 'hex')
		  FROM product_assets a
		  JOIN licenses l ON l.product_id = a.product_id
		 WHERE l.id = $1
		   AND NOT a.is_preview
		   AND a.scan_status = 'clean'
		   AND (a.variant_id IS NULL OR a.variant_id = l.variant_id)
		 ORDER BY a.position, a.filename`, licenseID)
	if err != nil {
		return nil, fmt.Errorf("delivery: list assets: %w", err)
	}
	defer rows.Close()
	var out []AssetSummary
	for rows.Next() {
		var a AssetSummary
		if err := rows.Scan(&a.AssetPublicID, &a.Filename, &a.SizeBytes, &a.ContentType, &a.Checksum); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// IssueTicket authorises one download.
//
// Every check is a fresh server-side read. The quota is incremented in the same
// transaction that creates the grant, so two concurrent requests cannot both
// consume the last allowance.
func (s *Service) IssueTicket(ctx context.Context, userID ids.UUID, licensePublicID, assetPublicID, ip string) (*Ticket, error) {
	if d := s.limiter.Allow(userID.String(), ratelimit.RuleDownloadPerUser); !d.Allowed {
		return nil, problem.RateLimited(int(d.RetryAfter.Seconds()) + 1)
	}

	var ticket *Ticket
	// A refusal rolls the transaction back, so denial evidence cannot be
	// written inside it. It is captured here and recorded afterwards: a denied
	// download is exactly the sort of event an investigation needs.
	var denial *denialRecord
	err := s.db.InTx(ctx, db.TxOptions{Name: "issue_download_ticket"}, func(ctx context.Context, tx db.Tx) error {
		denial = nil
		var licenseID, assetID ids.UUID
		var status, objectKey, filename, contentType string
		var sizeBytes int64
		var used, limit int
		var expiresAt *time.Time

		// One query establishes ownership, licence state, quota and the asset's
		// membership of the licensed product. Splitting it would open a window
		// between the checks.
		err := tx.QueryRow(ctx, `
			SELECT l.id, l.status, l.download_count, l.download_limit, l.access_expires_at,
			       a.id, a.object_key, a.filename, a.content_type, a.size_bytes
			  FROM licenses l
			  JOIN product_assets a
			    ON a.product_id = l.product_id
			   AND (a.variant_id IS NULL OR a.variant_id = l.variant_id)
			 WHERE l.public_id = $1
			   AND l.user_id  = $2
			   AND a.public_id = $3
			   AND NOT a.is_preview
			   AND a.scan_status = 'clean'
			 FOR UPDATE OF l`,
			licensePublicID, userID, assetPublicID,
		).Scan(&licenseID, &status, &used, &limit, &expiresAt,
			&assetID, &objectKey, &filename, &contentType, &sizeBytes)

		if db.IsNoRows(err) {
			// Indistinguishable whether the licence is someone else's, the
			// asset belongs to another product, or neither exists. An attacker
			// learns nothing from probing.
			denial = &denialRecord{outcome: "denied_entitlement"}
			return ErrNoEntitlement
		}
		if err != nil {
			return fmt.Errorf("delivery: resolve entitlement: %w", err)
		}

		now := s.clk.Now()
		switch {
		case status != "active":
			denial = &denialRecord{licenseID: licenseID, assetID: assetID, outcome: "denied_revoked"}
			return ErrLicenseRevoked
		case expiresAt != nil && now.After(*expiresAt):
			denial = &denialRecord{licenseID: licenseID, assetID: assetID, outcome: "denied_expired"}
			return ErrLicenseExpired
		case used >= limit:
			denial = &denialRecord{licenseID: licenseID, assetID: assetID, outcome: "denied_limit"}
			return ErrDownloadsExhausted
		}

		nonce, err := cryptox.NewToken(32)
		if err != nil {
			return err
		}
		grantID := ids.NewUUIDv7()
		expires := now.Add(s.cfg.DownloadURLTTL)

		// issued_at is written from the service clock rather than left to the
		// column default. Mixing an injected clock with the database's now()
		// gives two sources of truth for the same window, which is how a
		// grant can be born already expired.
		if _, err := tx.Exec(ctx, `
			INSERT INTO download_grants (id, license_id, asset_id, user_id, nonce_hash, issued_at, expires_at, issued_ip)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			grantID, licenseID, assetID, userID, cryptox.HashToken(nonce), now, expires, nullIfEmpty(ip)); err != nil {
			return fmt.Errorf("delivery: create grant: %w", err)
		}
		// The quota is spent at issue, not at redemption. Spending it later
		// would let an attacker mint unlimited tickets and redeem them
		// afterwards at leisure.
		if _, err := tx.Exec(ctx,
			`UPDATE licenses SET download_count = download_count + 1 WHERE id = $1`, licenseID); err != nil {
			return err
		}

		presigned, err := s.store.PresignGet(ctx, objectKey, s.cfg.DownloadURLTTL, filename)
		switch {
		case err == nil:
			ticket = &Ticket{URL: presigned, Direct: true, ExpiresAt: expires, Filename: filename, SizeBytes: sizeBytes}
		case errors.Is(err, storage.ErrPresignUnsupported):
			// Served by this application instead. The signed path carries the
			// grant nonce, which is verified and consumed on redemption.
			ticket = &Ticket{
				URL:    "/downloads/" + grantID.String() + "?t=" + nonce,
				Direct: false, ExpiresAt: expires, Filename: filename, SizeBytes: sizeBytes,
			}
		default:
			return fmt.Errorf("delivery: presign: %w", err)
		}

		return s.audit.Record(ctx, tx, audit.Event{
			ActorKind: audit.ActorUser, ActorID: &userID, ActorIP: ip,
			Action: "download.ticket_issued", SubjectType: "license", SubjectID: licensePublicID,
			Metadata: map[string]any{
				"asset": assetPublicID, "direct": ticket.Direct,
				"downloads_used": used + 1, "download_limit": limit,
			},
		})
	})
	if err != nil {
		if denial != nil {
			if s.m != nil {
				s.m.DownloadsServed.Inc(denial.outcome)
			}
			s.recordOutside(ctx, denial.licenseID, denial.assetID, userID, nil, 0, denial.outcome, ip)
			_ = s.audit.Record(context.WithoutCancel(ctx), s.db, audit.Event{
				ActorKind: audit.ActorUser, ActorID: &userID, ActorIP: ip,
				Action: "download.denied", SubjectType: "license", SubjectID: licensePublicID,
				Metadata: map[string]any{"reason": denial.outcome, "asset": assetPublicID},
			})
		}
		return nil, err
	}
	if s.m != nil {
		s.m.DownloadsServed.Inc("ticket_issued")
	}
	return ticket, nil
}

// denialRecord carries what a refused attempt needs to record once the
// transaction that refused it has rolled back.
type denialRecord struct {
	licenseID ids.UUID
	assetID   ids.UUID
	outcome   string
}

// Redeem consumes a single-use grant and streams the object.
//
// Used only when the storage adapter cannot presign. The nonce is compared
// against a stored digest, the grant is marked consumed inside the same
// transaction that authorises the read, and a replay finds it already spent.
func (s *Service) Redeem(ctx context.Context, w http.ResponseWriter, r *http.Request, grantIDRaw, nonce string) error {
	grantID, err := ids.ParseUUID(grantIDRaw)
	if err != nil {
		return ErrNoEntitlement
	}
	if len(nonce) < 32 || len(nonce) > 128 {
		return ErrNoEntitlement
	}

	var objectKey, filename, contentType string
	var sizeBytes int64
	var licenseID, assetID, userID ids.UUID

	err = s.db.InTx(ctx, db.TxOptions{Name: "redeem_download"}, func(ctx context.Context, tx db.Tx) error {
		err := tx.QueryRow(ctx, `
			UPDATE download_grants g
			   SET consumed_at = $3, consumed_ip = $4
			  FROM product_assets a
			 WHERE g.id = $1
			   AND g.nonce_hash = $2
			   AND g.consumed_at IS NULL
			   AND g.expires_at > $3
			   AND a.id = g.asset_id
			 RETURNING g.license_id, g.asset_id, g.user_id, a.object_key, a.filename, a.content_type, a.size_bytes`,
			grantID, cryptox.HashToken(nonce), s.clk.Now(), nullIfEmpty(clientIP(r)),
		).Scan(&licenseID, &assetID, &userID, &objectKey, &filename, &contentType, &sizeBytes)
		if db.IsNoRows(err) {
			// Expired, already consumed, or a forged nonce. All three are the
			// same answer to the caller.
			return ErrNoEntitlement
		}
		if err != nil {
			return fmt.Errorf("delivery: redeem grant: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}

	body, info, err := s.store.Get(ctx, objectKey)
	if err != nil {
		s.recordOutside(ctx, licenseID, assetID, userID, &grantID, 0, "error", clientIP(r))
		if errors.Is(err, storage.ErrNotFound) {
			return problem.Internal(fmt.Errorf("delivery: entitled object %s is missing from storage", objectKey))
		}
		return problem.Internal(err)
	}
	defer body.Close()

	// The response is forced to a download with a safe filename. An uploaded
	// HTML or SVG file must never render in the buyer's browser on our origin.
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Disposition", `attachment; filename="`+safeFilename(filename)+`"`)
	h.Set("Cache-Control", "private, no-store, max-age=0")
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	if info.Size > 0 {
		h.Set("Content-Length", strconv.FormatInt(info.Size, 10))
	}
	w.WriteHeader(http.StatusOK)

	sent, copyErr := io.Copy(w, body)
	outcome := "served"
	if copyErr != nil {
		outcome = "aborted"
	}
	s.recordOutside(ctx, licenseID, assetID, userID, &grantID, sent, outcome, clientIP(r))
	if s.m != nil {
		s.m.DownloadsServed.Inc(outcome)
		if sent > 0 {
			s.m.DownloadBytes.Add(uint64(sent))
		}
	}
	return nil
}

// RecordDirectDelivery is called after a redirect to presigned storage. The
// bytes do not pass through this application, so the count is what the ticket
// promised rather than what was actually transferred; the distinction is
// recorded honestly rather than papered over.
func (s *Service) RecordDirectDelivery(ctx context.Context, userID ids.UUID, licensePublicID, assetPublicID string, size int64, ip string) {
	var licenseID, assetID ids.UUID
	if err := s.db.QueryRow(ctx, `
		SELECT l.id, a.id FROM licenses l
		  JOIN product_assets a ON a.product_id = l.product_id
		 WHERE l.public_id = $1 AND a.public_id = $2 AND l.user_id = $3`,
		licensePublicID, assetPublicID, userID).Scan(&licenseID, &assetID); err != nil {
		return
	}
	s.recordOutside(ctx, licenseID, assetID, userID, nil, size, "served", ip)
}

func (s *Service) record(ctx context.Context, q db.Querier, licenseID, assetID, userID ids.UUID, grantID *ids.UUID, bytes int64, outcome, ip string) {
	if licenseID.IsZero() || assetID.IsZero() {
		// A denied probe has no licence to attribute; the audit log carries it.
		return
	}
	var grant any
	if grantID != nil {
		grant = *grantID
	}
	_, _ = q.Exec(ctx, `
		INSERT INTO download_events (license_id, asset_id, user_id, grant_id, bytes_sent, outcome, ip)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		licenseID, assetID, userID, grant, bytes, outcome, nullIfEmpty(ip))
}

func (s *Service) recordOutside(ctx context.Context, licenseID, assetID, userID ids.UUID, grantID *ids.UUID, bytes int64, outcome, ip string) {
	// Written with a detached context so a client disconnect still leaves
	// evidence: download_events is the primary exhibit in a chargeback.
	s.record(context.WithoutCancel(ctx), s.db, licenseID, assetID, userID, grantID, bytes, outcome, ip)
}

// ExpireGrants clears consumed and expired grants. Run by the worker.
func (s *Service) ExpireGrants(ctx context.Context, olderThan time.Duration) (int, error) {
	tag, err := s.db.Exec(ctx,
		`DELETE FROM download_grants WHERE expires_at < now() - $1::interval`, olderThan.String())
	if err != nil {
		return 0, fmt.Errorf("delivery: expire grants: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func safeFilename(name string) string {
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r < 0x20 || r == 0x7f:
		case r == '"' || r == '\\' || r == ';' || r == ',' || r > 0x7f:
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
		if b.Len() >= 200 {
			break
		}
	}
	out := strings.TrimSpace(b.String())
	if out == "" || out == "." || out == ".." {
		return "download"
	}
	return out
}

func clientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if v := r.Context().Value(clientIPKey{}); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	return host
}

// clientIPKey mirrors the httpx context key so delivery can read the resolved
// address without importing the HTTP layer, which would invert the dependency.
type clientIPKey struct{}

// WithClientIP lets the HTTP layer pass the trusted-proxy-resolved address in.
func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPKey{}, ip)
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
