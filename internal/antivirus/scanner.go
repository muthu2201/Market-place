// Package antivirus scans uploaded bytes before they can ever be sold.
//
// A marketplace for downloadable files is a malware distribution channel that
// happens to take payments. The distinguishing feature of that threat is that
// the platform's own reputation signs the delivery: a buyer who would never run
// an executable from a stranger will run one they paid for.
//
// Two defences run here, and they answer different questions:
//
//   - The scanner answers "is this known-bad?". It catches what a signature
//     database knows about, which is most commodity malware and none of a
//     targeted attack.
//   - Magic-byte detection answers "are these bytes what the uploader says they
//     are?". It catches the far more common case of an executable or a script
//     dressed as a font, and it does not depend on anybody's signature feed
//     being current.
//
// Neither is sufficient alone, and the database enforces the outcome: a product
// with any asset that is not scanned clean cannot be published. That constraint
// is a trigger rather than application code, because a control a direct INSERT
// can bypass is not a control.
package antivirus

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

// Status is the outcome of a scan. The values match the scan_status CHECK
// constraint on product_assets exactly; a value that does not round-trip
// through the database is a bug, not a new state.
type Status string

const (
	// StatusClean means the scanner examined the bytes and found nothing.
	StatusClean Status = "clean"
	// StatusInfected means a signature matched. The asset is never published.
	StatusInfected Status = "infected"
	// StatusSuspicious means a heuristic fired without a definite match, or the
	// declared and detected types disagree. Routed to human review.
	StatusSuspicious Status = "suspicious"
	// StatusError means the scan could not be completed. This is NOT clean:
	// an asset that could not be scanned stays unpublishable, so a scanner
	// outage degrades into a backlog rather than into unscanned downloads.
	StatusError Status = "error"
	// StatusSkipped is for deployments that have deliberately disabled
	// scanning. Production configuration refuses it.
	StatusSkipped Status = "skipped"
)

// Result is what a scan produced.
type Result struct {
	Status Status
	// Engine identifies the scanner and its signature database version, so a
	// result can be re-evaluated when a false positive is later corrected.
	Engine string
	// Signature is the matched threat name, empty unless Status is infected.
	Signature string
	// DetectedType is what the bytes actually are, from magic-number sniffing.
	DetectedType string
	// DeclaredType is what the uploader claimed.
	DeclaredType string
	// Reason explains a suspicious or error status in words a moderator can act
	// on without reading code.
	Reason string
	// ScannedAt is from the injected clock, never from the wall.
	ScannedAt time.Time
	// Bytes is how much was examined, which is how a truncated scan is spotted.
	Bytes int64
}

// Publishable reports whether an asset with this result may be sold.
//
// Only clean qualifies. Error and suspicious both hold the asset, which is the
// safe direction: the cost of a delayed listing is a seller waiting, and the
// cost of the other mistake is a buyer infected by something they paid us for.
func (r Result) Publishable() bool { return r.Status == StatusClean }

// Scanner is the port.
type Scanner interface {
	// Name identifies the implementation in logs, metrics and the scan record.
	Name() string

	// Scan reads the whole of r and reports what it found. It must not retain
	// the reader, and it must not require the caller to buffer the file: an
	// implementation that reads everything into memory cannot scan the 20 GB
	// upload the schema permits.
	Scan(ctx context.Context, r io.Reader, opts ScanOptions) (Result, error)

	// Ping reports whether the scanner is reachable and ready. Used by /readyz
	// and by the worker before claiming scan jobs.
	Ping(ctx context.Context) error
}

// ScanOptions carries what the scanner needs beyond the bytes.
type ScanOptions struct {
	// Filename is used for logging and for extension-versus-content checks. It
	// is never used to construct a path.
	Filename string
	// DeclaredType is the content type the uploader claimed.
	DeclaredType string
	// Size, when known, lets the scanner reject an oversized stream before
	// transferring it.
	Size int64
}

// Errors a caller may branch on.
var (
	// ErrUnavailable means the scanner could not be reached. Callers must treat
	// this as "not yet scanned", never as "clean".
	ErrUnavailable = errors.New("antivirus: scanner unavailable")
	// ErrTooLarge means the stream exceeded the scanner's configured limit.
	ErrTooLarge = errors.New("antivirus: stream exceeds the scanner size limit")
	// ErrProtocol means the scanner answered something unparseable, which is a
	// version mismatch or a corrupted connection rather than a verdict.
	ErrProtocol = errors.New("antivirus: unexpected scanner response")
)

// Config configures a scanner built by New.
type Config struct {
	// Driver is "clamav" or "disabled".
	Driver string
	// Address is host:port, or unix:/path/to/clamd.ctl.
	Address string
	// Timeout bounds one scan end to end.
	Timeout time.Duration
	// MaxBytes bounds what will be sent. It must not exceed clamd's own
	// StreamMaxLength, or clamd terminates the connection mid-transfer and the
	// result is an error rather than a verdict.
	MaxBytes int64
	// ChunkSize is the INSTREAM chunk size. 64 KiB keeps memory flat while
	// staying well inside clamd's per-chunk limit.
	ChunkSize int
}

// Defaults, applied to any zero field.
const (
	DefaultTimeout   = 5 * time.Minute
	DefaultMaxBytes  = 2 << 30 // 2 GiB — clamd's own default StreamMaxLength is lower; align them.
	DefaultChunkSize = 64 << 10
)

func (c *Config) applyDefaults() {
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}
	if c.MaxBytes <= 0 {
		c.MaxBytes = DefaultMaxBytes
	}
	if c.ChunkSize <= 0 || c.ChunkSize > 1<<20 {
		c.ChunkSize = DefaultChunkSize
	}
}

// New builds the configured scanner.
func New(cfg Config, now func() time.Time) (Scanner, error) {
	cfg.applyDefaults()
	switch cfg.Driver {
	case "clamav":
		return NewClamAV(cfg, now)
	case "disabled":
		return disabled{now: now}, nil
	default:
		return nil, fmt.Errorf("antivirus: unknown driver %q (want clamav|disabled)", cfg.Driver)
	}
}

// disabled records that no scan happened, honestly.
//
// It exists so a developer without clamd can still exercise the upload path. It
// returns StatusSkipped, which is not publishable, so the absence of a scanner
// cannot be mistaken for a passing scan. Production configuration refuses this
// driver outright.
type disabled struct{ now func() time.Time }

func (disabled) Name() string               { return "disabled" }
func (disabled) Ping(context.Context) error { return nil }
func (d disabled) Scan(_ context.Context, r io.Reader, opts ScanOptions) (Result, error) {
	n, err := io.Copy(io.Discard, r)
	if err != nil {
		return Result{}, err
	}
	detected, _ := DetectType(nil, opts.Filename)
	return Result{
		Status: StatusSkipped, Engine: "disabled", Bytes: n,
		DeclaredType: opts.DeclaredType, DetectedType: detected,
		Reason:    "scanning is disabled in this deployment; the asset is not publishable",
		ScannedAt: d.now(),
	}, nil
}
