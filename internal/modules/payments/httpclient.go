package payments

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/muthu2201/market-place/internal/platform/metrics"
)

// maxResponseBytes bounds what a provider can make us buffer. A compromised or
// misbehaving upstream should not be able to exhaust our memory.
const maxResponseBytes = 4 << 20

// client is the shared, hardened HTTP client for provider calls.
//
// Hardening, in order of what it prevents:
//   - a dialler that refuses private, loopback and link-local addresses, so a
//     provider base URL or a redirect cannot be turned into an SSRF probe of
//     the internal network;
//   - redirects refused outright, because a redirect carries our Authorization
//     header to a host we never chose to trust;
//   - TLS 1.2 minimum with verification always on;
//   - a response size cap and a per-attempt timeout;
//   - retries only on idempotent failures, with backoff.
type client struct {
	hc         *http.Client
	baseURL    string
	userAgent  string
	maxRetries int
	metrics    *metrics.App
	provider   string
	// allowPrivateHosts is enabled ONLY by tests that point the adapter at a
	// loopback gateway simulator. Production configuration cannot set it.
	allowPrivateHosts bool
}

type clientOptions struct {
	BaseURL           string
	Timeout           time.Duration
	MaxRetries        int
	Metrics           *metrics.App
	Provider          string
	AllowPrivateHosts bool
}

func newClient(o clientOptions) (*client, error) {
	if o.Timeout <= 0 {
		o.Timeout = 20 * time.Second
	}
	if o.MaxRetries < 0 {
		o.MaxRetries = 0
	}
	u, err := url.Parse(strings.TrimSuffix(o.BaseURL, "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("payments: provider base URL %q is not an absolute http(s) URL", o.BaseURL)
	}
	if u.Scheme == "http" && !o.AllowPrivateHosts {
		return nil, fmt.Errorf("payments: provider base URL must be https")
	}

	dialer := &net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if !o.AllowPrivateHosts {
				ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
				if err != nil {
					return nil, err
				}
				for _, ip := range ips {
					if isDisallowedIP(ip.IP) {
						return nil, fmt.Errorf("payments: refusing to connect to non-public address %s", ip.IP)
					}
				}
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   8 * time.Second,
		ExpectContinueTimeout: time.Second,
		ForceAttemptHTTP2:     true,
	}

	return &client{
		hc: &http.Client{
			Transport: transport,
			Timeout:   o.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return errors.New("payments: refusing to follow a redirect; credentials must not leave the configured host")
			},
		},
		baseURL:           u.String(),
		userAgent:         "marketplace-payments/1.0",
		maxRetries:        o.MaxRetries,
		metrics:           o.Metrics,
		provider:          o.Provider,
		allowPrivateHosts: o.AllowPrivateHosts,
	}, nil
}

// isDisallowedIP blocks every range that could reach infrastructure rather than
// the public internet.
func isDisallowedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	// Carrier-grade NAT, used by some cloud metadata and internal fabrics.
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
		if ip4[0] == 169 && ip4[1] == 254 { // metadata service
			return true
		}
	}
	return false
}

type request struct {
	Method         string
	Path           string
	Body           any
	Query          url.Values
	IdempotencyKey string
	// BasicAuth carries the provider key pair. It never appears in a log line:
	// logx redacts anything whose key looks like a credential, and this struct
	// is never logged as a whole.
	BasicUser string
	BasicPass string
	Bearer    string
	// Idempotent marks a request safe to retry after a transport error.
	Idempotent bool
	Headers    map[string]string
}

func (c *client) do(ctx context.Context, op string, r request, out any) (int, []byte, error) {
	//archcheck:allow wall-clock time -- measures elapsed duration for a latency histogram, which needs the real monotonic clock rather than a controllable one.
	start := time.Now()
	defer func() {
		if c.metrics != nil {
			c.metrics.PaymentDuration.Observe(time.Since(start).Seconds(), c.provider, op)
		}
	}()

	var bodyBytes []byte
	if r.Body != nil {
		var err error
		bodyBytes, err = json.Marshal(r.Body)
		if err != nil {
			return 0, nil, fmt.Errorf("payments: %s: encode request: %w", op, err)
		}
	}

	endpoint := c.baseURL + r.Path
	if len(r.Query) > 0 {
		endpoint += "?" + r.Query.Encode()
	}

	attempts := 1
	if r.Idempotent {
		attempts = c.maxRetries + 1
	}

	var lastErr error
	backoff := 200 * time.Millisecond
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return 0, nil, ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > 4*time.Second {
				backoff = 4 * time.Second
			}
		}

		req, err := http.NewRequestWithContext(ctx, r.Method, endpoint, bytes.NewReader(bodyBytes))
		if err != nil {
			return 0, nil, fmt.Errorf("payments: %s: build request: %w", op, err)
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", c.userAgent)
		if bodyBytes != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if r.IdempotencyKey != "" {
			req.Header.Set("X-Idempotency-Key", r.IdempotencyKey)
			req.Header.Set("Idempotency-Key", r.IdempotencyKey)
		}
		for k, v := range r.Headers {
			req.Header.Set(k, v)
		}
		if r.BasicUser != "" {
			req.SetBasicAuth(r.BasicUser, r.BasicPass)
		}
		if r.Bearer != "" {
			req.Header.Set("Authorization", "Bearer "+r.Bearer)
		}

		resp, err := c.hc.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
			continue
		}

		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
		resp.Body.Close()
		if readErr != nil {
			lastErr = fmt.Errorf("%w: reading response: %v", ErrProviderUnavailable, readErr)
			continue
		}
		if len(raw) > maxResponseBytes {
			return resp.StatusCode, nil, fmt.Errorf("payments: %s: provider response exceeded %d bytes", op, maxResponseBytes)
		}

		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			if c.metrics != nil {
				c.metrics.PaymentOperations.Inc(c.provider, op, "success")
			}
			if out != nil && len(raw) > 0 {
				if err := json.Unmarshal(raw, out); err != nil {
					return resp.StatusCode, raw, fmt.Errorf("payments: %s: decode response: %w", op, err)
				}
			}
			return resp.StatusCode, raw, nil

		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			lastErr = classifyHTTP(op, resp.StatusCode, raw, ErrProviderUnavailable)
			if !r.Idempotent {
				if c.metrics != nil {
					c.metrics.PaymentOperations.Inc(c.provider, op, "unavailable")
				}
				return resp.StatusCode, raw, lastErr
			}
			continue

		case resp.StatusCode == http.StatusNotFound:
			if c.metrics != nil {
				c.metrics.PaymentOperations.Inc(c.provider, op, "not_found")
			}
			return resp.StatusCode, raw, classifyHTTP(op, resp.StatusCode, raw, ErrNotFound)

		default:
			if c.metrics != nil {
				c.metrics.PaymentOperations.Inc(c.provider, op, "rejected")
			}
			return resp.StatusCode, raw, classifyHTTP(op, resp.StatusCode, raw, ErrProviderRejected)
		}
	}
	if c.metrics != nil {
		c.metrics.PaymentOperations.Inc(c.provider, op, "unavailable")
	}
	return 0, nil, lastErr
}

// providerErrorBody covers the shape Razorpay and most Indian PSPs use.
type providerErrorBody struct {
	Error struct {
		Code        string `json:"code"`
		Description string `json:"description"`
		Reason      string `json:"reason"`
		Source      string `json:"source"`
		Step        string `json:"step"`
	} `json:"error"`
	Message string `json:"message"`
	Detail  string `json:"detail"`
}

func classifyHTTP(op string, status int, raw []byte, class error) error {
	var body providerErrorBody
	_ = json.Unmarshal(raw, &body)
	code := body.Error.Code
	msg := body.Error.Description
	if msg == "" {
		msg = body.Message
	}
	if msg == "" {
		msg = body.Detail
	}
	if msg == "" {
		msg = http.StatusText(status)
	}
	if code == "" {
		code = fmt.Sprintf("http_%d", status)
	}
	// The provider's message is echoed into our logs but never into a buyer or
	// seller response; an upstream error string is not ours to render.
	return &ProviderError{Op: op, Code: code, Message: truncate(msg, 400), Status: status, Class: class}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
