package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/muthu2201/market-place/internal/platform/clock"
)

// Filesystem stores objects on local disk.
//
// It is a real adapter, not a stub: it is the correct choice for a single-node
// self-hosted deployment and for development, and it enforces the same key
// rules as the S3 adapter so code cannot accidentally depend on one or the
// other's laxity. Production configuration refuses it, because a local disk
// cannot serve two application replicas.
type Filesystem struct {
	root string
	clk  clock.Clock
}

// NewFilesystem prepares the root directory.
func NewFilesystem(root string, clk nilableClock) (*Filesystem, error) {
	if root == "" {
		return nil, errors.New("storage: a filesystem root is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("storage: resolve root: %w", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("storage: create root: %w", err)
	}
	c := clock.Clock(clk)
	if c == nil {
		c = clock.System()
	}
	return &Filesystem{root: abs, clk: c}, nil
}

type nilableClock = clock.Clock

func (f *Filesystem) Name() string { return "filesystem" }

// path resolves a key and then verifies the result is still inside the root.
// ValidateKey already refuses traversal, but checking the resolved path as well
// means a future change to the key rules cannot silently open an escape.
func (f *Filesystem) path(key string) (string, error) {
	if err := ValidateKey(key); err != nil {
		return "", err
	}
	p := filepath.Join(f.root, filepath.FromSlash(key))
	rel, err := filepath.Rel(f.root, p)
	if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return "", ErrInvalidKey
	}
	return p, nil
}

type sidecar struct {
	ContentType  string            `json:"content_type"`
	Size         int64             `json:"size"`
	ETag         string            `json:"etag"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	LastModified time.Time         `json:"last_modified"`
}

func (f *Filesystem) Put(ctx context.Context, req PutRequest) (ObjectInfo, error) {
	p, err := f.path(req.Key)
	if err != nil {
		return ObjectInfo{}, err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return ObjectInfo{}, fmt.Errorf("storage: create directory: %w", err)
	}

	// Write to a temporary file and rename, so a crash mid-write never leaves a
	// truncated object that later reads as valid.
	tmp, err := os.CreateTemp(filepath.Dir(p), ".upload-*")
	if err != nil {
		return ObjectInfo{}, fmt.Errorf("storage: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	h := sha256.New()
	written, err := io.Copy(io.MultiWriter(tmp, h), req.Body)
	if err != nil {
		tmp.Close()
		return ObjectInfo{}, fmt.Errorf("storage: write object: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return ObjectInfo{}, fmt.Errorf("storage: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return ObjectInfo{}, fmt.Errorf("storage: close: %w", err)
	}

	sum := h.Sum(nil)
	if len(req.ChecksumSHA256) > 0 && string(sum) != string(req.ChecksumSHA256) {
		return ObjectInfo{}, ErrChecksumMismatch
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return ObjectInfo{}, fmt.Errorf("storage: chmod: %w", err)
	}
	if err := os.Rename(tmpName, p); err != nil {
		return ObjectInfo{}, fmt.Errorf("storage: commit object: %w", err)
	}

	info := ObjectInfo{
		Key: req.Key, Size: written, ETag: hex.EncodeToString(sum),
		ContentType: req.ContentType, LastModified: f.clk.Now(),
	}
	meta, err := json.Marshal(sidecar{
		ContentType: req.ContentType, Size: written, ETag: info.ETag,
		Metadata: req.Metadata, LastModified: info.LastModified,
	})
	if err == nil {
		_ = os.WriteFile(p+".meta.json", meta, 0o600)
	}
	return info, nil
}

func (f *Filesystem) Get(ctx context.Context, key string) (io.ReadCloser, ObjectInfo, error) {
	p, err := f.path(key)
	if err != nil {
		return nil, ObjectInfo{}, err
	}
	file, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ObjectInfo{}, ErrNotFound
		}
		return nil, ObjectInfo{}, fmt.Errorf("storage: open: %w", err)
	}
	info, err := f.statFile(key, p)
	if err != nil {
		file.Close()
		return nil, ObjectInfo{}, err
	}
	return file, info, nil
}

func (f *Filesystem) GetRange(ctx context.Context, key string, offset, length int64) (io.ReadCloser, ObjectInfo, error) {
	rc, info, err := f.Get(ctx, key)
	if err != nil {
		return nil, ObjectInfo{}, err
	}
	file, ok := rc.(*os.File)
	if !ok {
		rc.Close()
		return nil, ObjectInfo{}, errors.New("storage: range read is unavailable")
	}
	if offset > 0 {
		if _, err := file.Seek(offset, io.SeekStart); err != nil {
			file.Close()
			return nil, ObjectInfo{}, fmt.Errorf("storage: seek: %w", err)
		}
	}
	if length <= 0 {
		return file, info, nil
	}
	return struct {
		io.Reader
		io.Closer
	}{io.LimitReader(file, length), file}, info, nil
}

func (f *Filesystem) Stat(ctx context.Context, key string) (ObjectInfo, error) {
	p, err := f.path(key)
	if err != nil {
		return ObjectInfo{}, err
	}
	return f.statFile(key, p)
}

func (f *Filesystem) statFile(key, p string) (ObjectInfo, error) {
	st, err := os.Stat(p)
	if err != nil {
		if os.IsNotExist(err) {
			return ObjectInfo{}, ErrNotFound
		}
		return ObjectInfo{}, fmt.Errorf("storage: stat: %w", err)
	}
	info := ObjectInfo{Key: key, Size: st.Size(), LastModified: st.ModTime()}
	if raw, err := os.ReadFile(p + ".meta.json"); err == nil {
		var side sidecar
		if json.Unmarshal(raw, &side) == nil {
			info.ContentType = side.ContentType
			info.ETag = side.ETag
		}
	}
	return info, nil
}

func (f *Filesystem) Delete(ctx context.Context, key string) error {
	p, err := f.path(key)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("storage: delete: %w", err)
	}
	_ = os.Remove(p + ".meta.json")
	return nil
}

// PresignGet is unsupported: a local disk has no edge to redirect to, so the
// application streams the bytes itself under an entitlement check.
func (f *Filesystem) PresignGet(context.Context, string, time.Duration, string) (string, error) {
	return "", ErrPresignUnsupported
}

var _ Store = (*Filesystem)(nil)
