package storage

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/muthu2201/market-place/internal/platform/clock"
	"github.com/muthu2201/market-place/internal/platform/config"
)

// S3 talks to any S3-compatible service: Cloudflare R2, AWS S3, Backblaze B2,
// MinIO. R2 is the intended production target because its egress is free.
type S3 struct {
	hc             *http.Client
	endpoint       *url.URL
	bucket         string
	signer         sigV4
	forcePathStyle bool
	clk            clock.Clock
}

// NewS3 builds the adapter from validated configuration.
func NewS3(cfg config.StorageConfig, clk clock.Clock) (*S3, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("storage: STORAGE_BUCKET is required")
	}
	if cfg.AccessKeyID == "" || cfg.SecretAccessKey == "" {
		return nil, fmt.Errorf("storage: object-storage credentials are required")
	}
	ep := cfg.Endpoint
	if ep == "" {
		ep = "https://s3." + cfg.Region + ".amazonaws.com"
	}
	u, err := url.Parse(strings.TrimSuffix(ep, "/"))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("storage: STORAGE_ENDPOINT %q is not a valid URL", ep)
	}
	if u.Scheme != "https" && !isLoopbackHost(u.Hostname()) {
		// Plaintext object storage would expose both credentials and content.
		// A loopback endpoint is allowed so a local MinIO can be used in
		// development without weakening the production rule.
		return nil, fmt.Errorf("storage: STORAGE_ENDPOINT must be https")
	}
	if clk == nil {
		clk = clock.System()
	}
	region := cfg.Region
	if region == "" {
		region = "auto"
	}

	return &S3{
		hc: &http.Client{
			Timeout: 10 * time.Minute, // large assets legitimately take a while
			Transport: &http.Transport{
				TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
				MaxIdleConns:          64,
				MaxIdleConnsPerHost:   16,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: time.Second,
				ForceAttemptHTTP2:     true,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return fmt.Errorf("storage: refusing to follow a redirect; signed credentials must not leave the configured host")
			},
		},
		endpoint:       u,
		bucket:         cfg.Bucket,
		signer:         sigV4{accessKey: cfg.AccessKeyID, secretKey: cfg.SecretAccessKey, region: region, service: "s3"},
		forcePathStyle: cfg.ForcePathStyle,
		clk:            clk,
	}, nil
}

func (s *S3) Name() string { return "s3" }

func (s *S3) objectURL(key string) (*url.URL, string) {
	u := *s.endpoint
	host := u.Host
	if s.forcePathStyle {
		u.Path = "/" + s.bucket + "/" + key
	} else {
		host = s.bucket + "." + u.Host
		u.Host = host
		u.Path = "/" + key
	}
	return &u, host
}

func (s *S3) Put(ctx context.Context, req PutRequest) (ObjectInfo, error) {
	if err := ValidateKey(req.Key); err != nil {
		return ObjectInfo{}, err
	}
	// The body is buffered so the payload can be hashed for signing and the
	// checksum verified before anything is accepted. Assets above the buffer
	// threshold should use multipart upload, which the runbook documents.
	body, err := io.ReadAll(io.LimitReader(req.Body, maxBufferedUpload+1))
	if err != nil {
		return ObjectInfo{}, fmt.Errorf("storage: read upload: %w", err)
	}
	if int64(len(body)) > maxBufferedUpload {
		return ObjectInfo{}, fmt.Errorf("storage: object exceeds the %d byte single-part limit; use multipart upload", maxBufferedUpload)
	}
	sum := sha256.Sum256(body)
	if len(req.ChecksumSHA256) > 0 && string(sum[:]) != string(req.ChecksumSHA256) {
		return ObjectInfo{}, ErrChecksumMismatch
	}

	u, host := s.objectURL(req.Key)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), strings.NewReader(string(body)))
	if err != nil {
		return ObjectInfo{}, err
	}
	httpReq.Host = host
	httpReq.ContentLength = int64(len(body))
	if req.ContentType != "" {
		httpReq.Header.Set("Content-Type", req.ContentType)
	}
	if req.CacheControl != "" {
		httpReq.Header.Set("Cache-Control", req.CacheControl)
	} else {
		// Deliverable assets must never sit in a shared cache: the URL is
		// short-lived and single-use, and a cached copy would outlive both.
		httpReq.Header.Set("Cache-Control", "private, no-store")
	}
	for k, v := range req.Metadata {
		httpReq.Header.Set("x-amz-meta-"+k, v)
	}
	s.signer.sign(httpReq, hex.EncodeToString(sum[:]), s.clk.Now())

	resp, err := s.hc.Do(httpReq)
	if err != nil {
		return ObjectInfo{}, fmt.Errorf("storage: put %s: %w", req.Key, err)
	}
	defer drain(resp)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ObjectInfo{}, s3Error("put", req.Key, resp)
	}

	return ObjectInfo{
		Key: req.Key, Size: int64(len(body)),
		ETag:        strings.Trim(resp.Header.Get("ETag"), `"`),
		ContentType: req.ContentType, LastModified: s.clk.Now(),
	}, nil
}

const maxBufferedUpload = 256 << 20

func (s *S3) Get(ctx context.Context, key string) (io.ReadCloser, ObjectInfo, error) {
	return s.get(ctx, key, "")
}

func (s *S3) GetRange(ctx context.Context, key string, offset, length int64) (io.ReadCloser, ObjectInfo, error) {
	rng := "bytes=" + strconv.FormatInt(offset, 10) + "-"
	if length > 0 {
		rng += strconv.FormatInt(offset+length-1, 10)
	}
	return s.get(ctx, key, rng)
}

func (s *S3) get(ctx context.Context, key, rangeHeader string) (io.ReadCloser, ObjectInfo, error) {
	if err := ValidateKey(key); err != nil {
		return nil, ObjectInfo{}, err
	}
	u, host := s.objectURL(key)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, ObjectInfo{}, err
	}
	req.Host = host
	if rangeHeader != "" {
		req.Header.Set("Range", rangeHeader)
	}
	s.signer.sign(req, emptyPayloadHash, s.clk.Now())

	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, ObjectInfo{}, fmt.Errorf("storage: get %s: %w", key, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		drain(resp)
		return nil, ObjectInfo{}, ErrNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err := s3Error("get", key, resp)
		drain(resp)
		return nil, ObjectInfo{}, err
	}
	return resp.Body, infoFromResponse(key, resp), nil
}

func (s *S3) Stat(ctx context.Context, key string) (ObjectInfo, error) {
	if err := ValidateKey(key); err != nil {
		return ObjectInfo{}, err
	}
	u, host := s.objectURL(key)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.String(), nil)
	if err != nil {
		return ObjectInfo{}, err
	}
	req.Host = host
	s.signer.sign(req, emptyPayloadHash, s.clk.Now())

	resp, err := s.hc.Do(req)
	if err != nil {
		return ObjectInfo{}, fmt.Errorf("storage: stat %s: %w", key, err)
	}
	defer drain(resp)
	if resp.StatusCode == http.StatusNotFound {
		return ObjectInfo{}, ErrNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ObjectInfo{}, s3Error("stat", key, resp)
	}
	return infoFromResponse(key, resp), nil
}

func (s *S3) Delete(ctx context.Context, key string) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	u, host := s.objectURL(key)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u.String(), nil)
	if err != nil {
		return err
	}
	req.Host = host
	s.signer.sign(req, emptyPayloadHash, s.clk.Now())

	resp, err := s.hc.Do(req)
	if err != nil {
		return fmt.Errorf("storage: delete %s: %w", key, err)
	}
	defer drain(resp)
	if resp.StatusCode == http.StatusNotFound || (resp.StatusCode >= 200 && resp.StatusCode < 300) {
		return nil
	}
	return s3Error("delete", key, resp)
}

// PresignGet issues a short-lived URL so the object is served by the storage
// edge rather than proxied through the application. The response-content-
// disposition parameter forces a download with a safe filename, which also
// prevents an uploaded HTML or SVG file from executing on the storage origin.
func (s *S3) PresignGet(_ context.Context, key string, ttl time.Duration, filename string) (string, error) {
	if err := ValidateKey(key); err != nil {
		return "", err
	}
	if ttl <= 0 || ttl > time.Hour {
		// A delivery URL is a bearer token. Long lifetimes turn a leaked
		// referrer or a shared screenshot into unlimited access.
		return "", fmt.Errorf("storage: presigned lifetime must be between 1 second and 1 hour")
	}
	u, host := s.objectURL(key)
	extra := url.Values{}
	if filename != "" {
		extra.Set("response-content-disposition", `attachment; filename="`+sanitiseFilename(filename)+`"`)
		extra.Set("response-content-type", "application/octet-stream")
	}
	return s.signer.presign(http.MethodGet, u, host, ttl, extra, s.clk.Now()), nil
}

func infoFromResponse(key string, resp *http.Response) ObjectInfo {
	size, _ := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	lm, _ := http.ParseTime(resp.Header.Get("Last-Modified"))
	return ObjectInfo{
		Key: key, Size: size,
		ETag:         strings.Trim(resp.Header.Get("ETag"), `"`),
		ContentType:  resp.Header.Get("Content-Type"),
		LastModified: lm,
	}
}

type s3ErrorBody struct {
	XMLName xml.Name `xml:"Error"`
	Code    string   `xml:"Code"`
	Message string   `xml:"Message"`
}

func s3Error(op, key string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	var e s3ErrorBody
	_ = xml.Unmarshal(body, &e)
	if e.Code == "NoSuchKey" || e.Code == "NotFound" {
		return ErrNotFound
	}
	msg := e.Message
	if msg == "" {
		msg = http.StatusText(resp.StatusCode)
	}
	return fmt.Errorf("storage: %s %s: %s (%s, HTTP %d)", op, key, msg, e.Code, resp.StatusCode)
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
}

// sanitiseFilename strips everything that could break a Content-Disposition
// header or smuggle a path.
func sanitiseFilename(name string) string {
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r < 0x20 || r == 0x7f:
		case r == '"' || r == '\\' || r == ';' || r == ',':
			b.WriteByte('_')
		case r > 0x7f:
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
		if b.Len() > 200 {
			break
		}
	}
	out := strings.TrimSpace(b.String())
	if out == "" || out == "." || out == ".." {
		return "download"
	}
	return out
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

var _ Store = (*S3)(nil)
