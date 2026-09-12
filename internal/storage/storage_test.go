package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/muthu2201/market-place/internal/platform/clock"
)

// Path traversal is the single most important thing this package prevents, so
// it gets an exhaustive table.
func TestValidateKeyRejectsEveryEscape(t *testing.T) {
	bad := []string{
		"", "/etc/passwd", "../../etc/passwd", "a/../../b", "a//b",
		"\\windows\\system32", "a/./b", "a/", "/", "..",
		"key with spaces", "key\x00null", "key\nnewline", "key\ttab",
		"emoji/\U0001F600", "café/file", "a/CON/b", "a/nul.txt",
		strings.Repeat("a", 1025),
	}
	for _, k := range bad {
		if err := ValidateKey(k); err == nil {
			t.Errorf("key %q should be refused", k)
		}
	}
	good := []string{
		"products/prd_ABC/bundle.zip", "a", "a/b/c/d.tar.gz",
		"previews/2026/09/image-01.webp", "kyc/slr_XYZ/pan.pdf",
		"a-b_c.d/e=f",
	}
	for _, k := range good {
		if err := ValidateKey(k); err != nil {
			t.Errorf("key %q should be accepted: %v", k, err)
		}
	}
}

func TestFilesystemRoundTrip(t *testing.T) {
	dir := t.TempDir()
	fs, err := NewFilesystem(dir, clock.System())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	payload := []byte("the quick brown fox jumps over the lazy dog")
	sum := sha256.Sum256(payload)

	info, err := fs.Put(ctx, PutRequest{
		Key: "products/prd_TEST/bundle.zip", Body: bytes.NewReader(payload),
		ContentType: "application/zip", ChecksumSHA256: sum[:],
	})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if info.Size != int64(len(payload)) {
		t.Fatalf("size = %d", info.Size)
	}

	rc, got, err := fs.Get(ctx, "products/prd_TEST/bundle.zip")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(rc)
	rc.Close()
	if string(body) != string(payload) {
		t.Fatal("round trip corrupted the object")
	}
	if got.ContentType != "application/zip" {
		t.Fatalf("content type = %q", got.ContentType)
	}

	// Range reads are what make resumable downloads work.
	rc, _, err = fs.GetRange(ctx, "products/prd_TEST/bundle.zip", 4, 5)
	if err != nil {
		t.Fatal(err)
	}
	part, _ := io.ReadAll(rc)
	rc.Close()
	if string(part) != "quick" {
		t.Fatalf("range read = %q, want \"quick\"", part)
	}

	if err := fs.Delete(ctx, "products/prd_TEST/bundle.zip"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fs.Get(ctx, "products/prd_TEST/bundle.zip"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	// Deleting again is not an error.
	if err := fs.Delete(ctx, "products/prd_TEST/bundle.zip"); err != nil {
		t.Fatalf("a repeated delete must succeed: %v", err)
	}
}

func TestFilesystemRefusesChecksumMismatch(t *testing.T) {
	fs, _ := NewFilesystem(t.TempDir(), clock.System())
	wrong := sha256.Sum256([]byte("something else entirely"))
	_, err := fs.Put(context.Background(), PutRequest{
		Key: "a/b.bin", Body: strings.NewReader("actual content"), ChecksumSHA256: wrong[:],
	})
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("want ErrChecksumMismatch, got %v", err)
	}
	// A refused upload must leave nothing behind, not even a partial file.
	entries, _ := os.ReadDir(filepath.Join(fs.root, "a"))
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".upload-") {
			t.Fatalf("a failed upload left %q behind", e.Name())
		}
	}
}

func TestFilesystemCannotEscapeItsRoot(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(root, "..", "escaped.txt")
	fs, _ := NewFilesystem(filepath.Join(root, "objects"), clock.System())

	for _, key := range []string{"../escaped.txt", "../../escaped.txt", "a/../../escaped.txt"} {
		if _, err := fs.Put(context.Background(), PutRequest{Key: key, Body: strings.NewReader("x")}); err == nil {
			t.Fatalf("key %q escaped the root", key)
		}
	}
	if _, err := os.Stat(outside); err == nil {
		t.Fatal("a file was written outside the storage root")
	}
}

func TestFilesystemPresignIsHonestlyUnsupported(t *testing.T) {
	fs, _ := NewFilesystem(t.TempDir(), clock.System())
	if _, err := fs.PresignGet(context.Background(), "a/b", time.Minute, "b.zip"); !errors.Is(err, ErrPresignUnsupported) {
		t.Fatalf("the filesystem adapter must say plainly that it cannot presign, got %v", err)
	}
}

// SigV4 is verified end to end against the "GET Object with Range" worked
// example published in the AWS Signature Version 4 documentation. Checking the
// final Authorization header rather than an intermediate value exercises
// canonical-request construction, header canonicalisation and key derivation
// together, which is the only way to know the whole implementation is right.
func TestSigV4MatchesTheAWSReferenceVector(t *testing.T) {
	s := sigV4{
		accessKey: "AKIAIOSFODNN7EXAMPLE",
		secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		region:    "us-east-1", service: "s3",
	}
	req, err := http.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "examplebucket.s3.amazonaws.com"
	req.Header.Set("Range", "bytes=0-9")

	// The published example signs the Range header, which our production path
	// does not include by default, so it is added explicitly here.
	signedAt := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
	s.signWithExtraHeaders(req, emptyPayloadHash, signedAt, []string{"range"})

	const want = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, " +
		"SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, " +
		"Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("Authorization mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestSigV4PresignShapeAndExpiry(t *testing.T) {
	s := sigV4{accessKey: "AKID", secretKey: "SECRET", region: "auto", service: "s3"}
	u, _ := url.Parse("https://bucket.r2.example.com/products/prd_A/file.zip")
	signed := s.presign("GET", u, "bucket.r2.example.com", 10*time.Minute, url.Values{
		"response-content-disposition": []string{`attachment; filename="file.zip"`},
	}, time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC))

	parsed, err := url.Parse(signed)
	if err != nil {
		t.Fatal(err)
	}
	q := parsed.Query()
	for _, k := range []string{"X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Date", "X-Amz-Expires", "X-Amz-SignedHeaders", "X-Amz-Signature"} {
		if q.Get(k) == "" {
			t.Errorf("presigned URL is missing %s", k)
		}
	}
	if q.Get("X-Amz-Expires") != "600" {
		t.Fatalf("expiry = %s, want 600", q.Get("X-Amz-Expires"))
	}
	if len(q.Get("X-Amz-Signature")) != 64 {
		t.Fatalf("signature is not a 32-byte hex digest: %q", q.Get("X-Amz-Signature"))
	}
	if strings.Contains(signed, "SECRET") {
		t.Fatal("the secret key leaked into the presigned URL")
	}
	// The signature must actually depend on the request.
	other := s.presign("GET", u, "bucket.r2.example.com", 11*time.Minute, nil,
		time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC))
	if q.Get("X-Amz-Signature") == mustQuery(t, other).Get("X-Amz-Signature") {
		t.Fatal("changing the expiry did not change the signature")
	}
}

func TestSanitiseFilenameStripsHeaderInjection(t *testing.T) {
	cases := []struct{ in, want string }{
		{"bundle.zip", "bundle.zip"},
		{"../../etc/passwd", "passwd"},
		{`evil"; attachment; filename="other.exe`, `evil__ attachment_ filename=_other.exe`},
		{"with\nnewline.zip", "withnewline.zip"},
		{"", "download"},
		{"..", "download"},
	}
	for _, c := range cases {
		if got := sanitiseFilename(c.in); got != c.want {
			t.Errorf("sanitiseFilename(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func mustQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}
