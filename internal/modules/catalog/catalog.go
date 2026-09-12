// Package catalog owns the seller's side of a listing: drafting a product,
// pricing it, uploading the files a buyer receives, tagging it, and getting it
// published.
//
// The publish transition is the centre of gravity. Four things must be true
// before a product can be sold, and all four are enforced by a database trigger
// rather than by this package:
//
//  1. Every deliverable asset is scanned clean.
//  2. An AI-content declaration has been made.
//  3. At least one active priced variant exists.
//  4. The seller is active with verified KYC.
//
// They live in `products_publish_guard` because a control a direct UPDATE can
// bypass is not a control. This package's job is to make the failure
// *legible* — to tell the seller which of the four is missing, in words,
// before the database has to refuse them.
//
// Uploads never touch the application's request path. A seller uploads
// straight to a quarantine prefix that delivery never reads from, and the
// worker reads it back, scans it, gathers provenance signals, and promotes it.
// The safety property is the prefix rather than a flag: an object that has not
// been scanned cannot be served even by a bug in the delivery code, because
// delivery never constructs a quarantine key.
package catalog

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/muthu2201/market-place/internal/antivirus"
	"github.com/muthu2201/market-place/internal/modules/audit"
	"github.com/muthu2201/market-place/internal/modules/provenance"
	"github.com/muthu2201/market-place/internal/platform/clock"
	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/ids"
	"github.com/muthu2201/market-place/internal/platform/problem"
	"github.com/muthu2201/market-place/internal/storage"
)

// Status values, matching the products CHECK constraint.
const (
	StatusDraft         = "draft"
	StatusPendingReview = "pending_review"
	StatusPublished     = "published"
	StatusRejected      = "rejected"
	StatusSuspended     = "suspended"
	StatusArchived      = "archived"
)

// Scan status values, matching the product_assets CHECK constraint.
const (
	ScanPending  = "pending"
	ScanScanning = "scanning"
	ScanClean    = "clean"
	ScanInfected = "infected"
	ScanSuspect  = "suspicious"
	ScanError    = "error"
	ScanSkipped  = "skipped"
)

// Object-key prefixes. These two strings are a security boundary: delivery
// resolves entitlements only under deliverablePrefix, and never constructs a
// key under quarantinePrefix.
const (
	quarantinePrefix  = "quarantine"
	deliverablePrefix = "assets"
)

// Service is the catalogue write path.
type Service struct {
	db      *db.DB
	store   storage.Store
	scanner antivirus.Scanner
	audit   *audit.Service
	clk     clock.Clock
	log     *slog.Logger

	// uploadTTL bounds a presigned upload URL.
	uploadTTL time.Duration
	// maxAssetBytes bounds one upload, independently of the schema's own cap.
	maxAssetBytes int64
}

// Options configure the service.
type Options struct {
	DB            *db.DB
	Store         storage.Store
	Scanner       antivirus.Scanner
	Audit         *audit.Service
	Clock         clock.Clock
	Log           *slog.Logger
	UploadTTL     time.Duration
	MaxAssetBytes int64
}

// New builds the service.
func New(o Options) (*Service, error) {
	if o.DB == nil {
		return nil, errors.New("catalog: a database is required")
	}
	if o.Store == nil {
		return nil, errors.New("catalog: an object store is required")
	}
	if o.Scanner == nil {
		return nil, errors.New("catalog: a scanner is required; the disabled driver is explicit, nil is not")
	}
	if o.Clock == nil {
		o.Clock = clock.System()
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Audit == nil {
		o.Audit = audit.New()
	}
	if o.UploadTTL <= 0 {
		o.UploadTTL = 2 * time.Hour
	}
	if o.MaxAssetBytes <= 0 {
		o.MaxAssetBytes = 20 << 30 // matches the schema's ceiling
	}
	return &Service{
		db: o.DB, store: o.Store, scanner: o.Scanner, audit: o.Audit,
		clk: o.Clock, log: o.Log,
		uploadTTL: o.UploadTTL, maxAssetBytes: o.MaxAssetBytes,
	}, nil
}

// Errors callers branch on.
var (
	// ErrNotFound covers both "no such product" and "not this seller's
	// product", deliberately, so the endpoint cannot be used to probe for the
	// existence of other sellers' drafts.
	ErrNotFound = errors.New("catalog: product not found")
	// ErrNotEditable means the product is in a state where this change is not
	// allowed.
	ErrNotEditable = errors.New("catalog: product is not editable in its current state")
)

// PublishBlocker is one unmet precondition, phrased for the seller.
type PublishBlocker struct {
	Code   string
	Detail string
	// Fixable says whether the seller can resolve it themselves. KYC and a
	// suspended account are not things a seller fixes from the listing screen,
	// and telling them to try is worse than telling them to wait.
	Fixable bool
}

// PublishReadiness is the answer to "can this go live, and if not, why not".
type PublishReadiness struct {
	Ready    bool
	Blockers []PublishBlocker
}

// problemFor turns a database publish-guard rejection into a problem document.
//
// The guard raises P0001 with a message naming the reason. Mapping it here
// means the seller gets the same explanation whether the check was caught early
// by ReadyToPublish or late by the trigger, and it means a future constraint
// added to the trigger still produces something a person can read.
func problemFor(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "no clean deliverable asset"):
		return problem.Conflict("", "This product has no file a buyer could download. Upload at least one file and wait for it to finish scanning.")
	case strings.Contains(msg, "not scanned clean"):
		return problem.Conflict("", "One or more files are still being scanned, or did not pass the scan. A product cannot be published until every file is clean.")
	case strings.Contains(msg, "declaration is mandatory"):
		return problem.Conflict("", "Tell us whether AI was involved in making this. The declaration is required before anything can be published.")
	case strings.Contains(msg, "no active priced variant"):
		return problem.Conflict("", "This product has no price. Add at least one option with a price before publishing.")
	case strings.Contains(msg, "seller is not active with verified KYC"):
		return problem.Conflict("", "Your seller account is not yet verified. Publishing opens up once verification is complete.")
	}
	return err
}

// quarantineKey is where an upload lands before it is trusted.
func quarantineKey(sellerID ids.UUID, assetID ids.UUID) string {
	return fmt.Sprintf("%s/%s/%s", quarantinePrefix, sellerID.String(), assetID.String())
}

// deliverableKey is where a scanned-clean asset lives.
//
// Both keys derive entirely from server-generated identifiers. The seller's
// filename never reaches a key: it is metadata, used for the download's
// Content-Disposition header and nothing else.
func deliverableKey(sellerID ids.UUID, assetID ids.UUID) string {
	return fmt.Sprintf("%s/%s/%s", deliverablePrefix, sellerID.String(), assetID.String())
}

// assessment bundles what the two analysers found, so one row update carries
// both and a partial write cannot leave them disagreeing.
type assessment struct {
	scan       antivirus.Result
	signals    provenance.Signals
	provenance provenance.Assessment
}
