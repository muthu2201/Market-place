package storage

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// sigV4 implements AWS Signature Version 4 for S3-compatible services.
//
// It is written out rather than imported because the specification is stable,
// the implementation is small, and a payments-adjacent system benefits more
// from an auditable 150 lines than from a large SDK dependency tree.
type sigV4 struct {
	accessKey string
	secretKey string
	region    string
	service   string
}

const (
	iso8601          = "20060102T150405Z"
	yyyymmdd         = "20060102"
	unsignedPayload  = "UNSIGNED-PAYLOAD"
	emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// sign adds an Authorization header to a request. payloadHash is the hex
// SHA-256 of the body, or UNSIGNED-PAYLOAD for a streaming upload.
func (s sigV4) sign(req *http.Request, payloadHash string, now time.Time) {
	s.signWithExtraHeaders(req, payloadHash, now, nil)
}

// signWithExtraHeaders signs additional headers beyond the default set. The
// default set is deliberately narrow so that a proxy adding a header cannot
// invalidate a signature; a caller that genuinely needs a header covered names
// it here.
func (s sigV4) signWithExtraHeaders(req *http.Request, payloadHash string, now time.Time, extra []string) {
	now = now.UTC()
	amzDate := now.Format(iso8601)
	dateStamp := now.Format(yyyymmdd)

	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if req.Host != "" {
		req.Header.Set("Host", req.Host)
	}

	signedHeaders, canonicalHeaders := canonicalHeaders(req, extra)
	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI(req.URL),
		canonicalQuery(req.URL.Query()),
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	scope := dateStamp + "/" + s.region + "/" + s.service + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		hex.EncodeToString(sha256sum([]byte(canonicalRequest))),
	}, "\n")

	signature := hex.EncodeToString(hmacSHA256(s.signingKey(dateStamp), []byte(stringToSign)))
	req.Header.Set("Authorization",
		"AWS4-HMAC-SHA256 Credential="+s.accessKey+"/"+scope+
			", SignedHeaders="+signedHeaders+", Signature="+signature)
}

// presign returns a URL carrying the signature in the query string, so a client
// can fetch the object directly without our credentials ever reaching it.
func (s sigV4) presign(method string, u *url.URL, host string, ttl time.Duration, extraQuery url.Values, now time.Time) string {
	now = now.UTC()
	amzDate := now.Format(iso8601)
	dateStamp := now.Format(yyyymmdd)
	scope := dateStamp + "/" + s.region + "/" + s.service + "/aws4_request"

	q := u.Query()
	for k, vs := range extraQuery {
		for _, v := range vs {
			q.Set(k, v)
		}
	}
	q.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	q.Set("X-Amz-Credential", s.accessKey+"/"+scope)
	q.Set("X-Amz-Date", amzDate)
	q.Set("X-Amz-Expires", itoa(int(ttl.Seconds())))
	q.Set("X-Amz-SignedHeaders", "host")

	canonicalRequest := strings.Join([]string{
		method,
		canonicalURI(u),
		canonicalQuery(q),
		"host:" + strings.ToLower(host) + "\n",
		"host",
		unsignedPayload,
	}, "\n")

	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, scope,
		hex.EncodeToString(sha256sum([]byte(canonicalRequest))),
	}, "\n")

	q.Set("X-Amz-Signature", hex.EncodeToString(hmacSHA256(s.signingKey(dateStamp), []byte(stringToSign))))

	out := *u
	out.RawQuery = canonicalQuery(q)
	return out.String()
}

func (s sigV4) signingKey(dateStamp string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+s.secretKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(s.region))
	kService := hmacSHA256(kRegion, []byte(s.service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

func canonicalURI(u *url.URL) string {
	p := u.EscapedPath()
	if p == "" {
		return "/"
	}
	return p
}

// canonicalQuery sorts and re-encodes query parameters per the SigV4 rules,
// which differ from Go's default encoding for a few characters.
func canonicalQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		vs := append([]string(nil), q[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			if b.Len() > 0 {
				b.WriteByte('&')
			}
			b.WriteString(uriEncode(k, true))
			b.WriteByte('=')
			b.WriteString(uriEncode(v, true))
		}
	}
	return b.String()
}

func canonicalHeaders(req *http.Request, extra []string) (signed, canonical string) {
	include := map[string]bool{"host": true, "content-type": true, "content-length": true}
	for _, e := range extra {
		include[strings.ToLower(e)] = true
	}
	names := make([]string, 0, len(req.Header)+1)
	values := map[string]string{}
	for k, v := range req.Header {
		lk := strings.ToLower(k)
		// Only headers that matter to the service are signed; signing
		// everything makes a proxy that adds a header break the request.
		if !include[lk] && !strings.HasPrefix(lk, "x-amz-") {
			continue
		}
		names = append(names, lk)
		values[lk] = strings.TrimSpace(strings.Join(v, ","))
	}
	if _, ok := values["host"]; !ok {
		names = append(names, "host")
		values["host"] = req.Host
	}
	sort.Strings(names)

	var b strings.Builder
	for _, n := range names {
		b.WriteString(n)
		b.WriteByte(':')
		b.WriteString(values[n])
		b.WriteByte('\n')
	}
	return strings.Join(names, ";"), b.String()
}

// uriEncode implements the AWS rules: unreserved characters pass through,
// everything else is percent-encoded, and '/' is preserved only in a path.
func uriEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte('/')
		default:
			b.WriteByte('%')
			b.WriteByte(hexUpper[c>>4])
			b.WriteByte(hexUpper[c&0x0F])
		}
	}
	return b.String()
}

const hexUpper = "0123456789ABCDEF"

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func sha256sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := v < 0
	if neg {
		v = -v
	}
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
