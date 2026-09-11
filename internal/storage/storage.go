// Package storage abstracts object storage behind a port with two real
// adapters: S3-compatible (Cloudflare R2, AWS S3, Backblaze B2) and a local
// filesystem for single-node and development deployments.
//
// R2 is the default for delivery because egress is the dominant cost of a
// download marketplace and R2 charges nothing for it, where S3 charges per
// gigabyte. That single choice is the difference between a bandwidth bill that
// scales with success and one that does not.
//
// The SigV4 signer is implemented here rather than pulled from an SDK: it is
// about 150 lines against a stable, published specification, and it keeps the
// dependency surface of a security-critical system small enough to audit.
package storage

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"
)

// ObjectInfo describes a stored object.
type ObjectInfo struct {
	Key          string
	Size         int64
	ETag         string
	ContentType  string
	LastModified time.Time
}

// PutRequest uploads one object.
type PutRequest struct {
	Key         string
	Body        io.Reader
	Size        int64
	ContentType string
	// ChecksumSHA256 is verified by the adapter after the write, so a truncated
	// or corrupted upload is detected at ingest rather than at first download.
	ChecksumSHA256 []byte
	Metadata       map[string]string
	// CacheControl is set on public preview objects only. Deliverable assets
	// are never cacheable by a shared cache.
	CacheControl string
}

// Store is the object-storage port.
type Store interface {
	// Name identifies the adapter for logs and metrics.
	Name() string

	// Put writes an object and returns what was stored.
	Put(ctx context.Context, req PutRequest) (ObjectInfo, error)

	// Get opens an object for reading. The caller must close the reader.
	Get(ctx context.Context, key string) (io.ReadCloser, ObjectInfo, error)

	// GetRange opens a byte range, which is what makes resumable downloads work.
	GetRange(ctx context.Context, key string, offset, length int64) (io.ReadCloser, ObjectInfo, error)

	// Stat returns metadata without transferring the body.
	Stat(ctx context.Context, key string) (ObjectInfo, error)

	// Delete removes an object. Deleting an absent object is not an error.
	Delete(ctx context.Context, key string) error

	// PresignGet returns a time-limited URL the client can fetch directly,
	// which is how delivery avoids proxying bytes through the application.
	// Returns ErrPresignUnsupported when the adapter cannot do this.
	PresignGet(ctx context.Context, key string, ttl time.Duration, downloadFilename string) (string, error)
}

var (
	// ErrNotFound means no object exists at that key.
	ErrNotFound = errors.New("storage: object not found")
	// ErrChecksumMismatch means the stored bytes are not what was offered.
	ErrChecksumMismatch = errors.New("storage: checksum did not match the uploaded bytes")
	// ErrPresignUnsupported means this adapter cannot issue direct URLs.
	ErrPresignUnsupported = errors.New("storage: this adapter cannot presign URLs")
	// ErrInvalidKey means the key is unsafe or malformed.
	ErrInvalidKey = errors.New("storage: invalid object key")
)

// ValidateKey rejects any key that could escape its prefix or confuse a
// filesystem adapter. It is applied by every adapter, not just the filesystem
// one, so a single rule governs all of them.
//
// This is the control that prevents a path-traversal write: an attacker who can
// influence a key cannot reach "../../etc/passwd" or an absolute path.
func ValidateKey(key string) error {
	switch {
	case key == "":
		return ErrInvalidKey
	case len(key) > 1024:
		return ErrInvalidKey
	case strings.HasPrefix(key, "/"), strings.HasPrefix(key, "\\"):
		return ErrInvalidKey
	case strings.Contains(key, ".."):
		return ErrInvalidKey
	case strings.Contains(key, "//"):
		return ErrInvalidKey
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '/' || c == '-' || c == '_' || c == '.' || c == '=':
		default:
			// Anything outside this set, including control characters, spaces,
			// backslashes and every non-ASCII byte, is refused.
			return ErrInvalidKey
		}
	}
	// A Windows device name in any segment would be a problem for a filesystem
	// adapter on that platform; refusing it everywhere keeps adapters
	// interchangeable.
	for _, seg := range strings.Split(key, "/") {
		if seg == "" || seg == "." {
			return ErrInvalidKey
		}
		base := seg
		if dot := strings.IndexByte(seg, '.'); dot > 0 {
			base = seg[:dot]
		}
		if reservedNames[strings.ToUpper(base)] {
			return ErrInvalidKey
		}
	}
	return nil
}

var reservedNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true,
}
