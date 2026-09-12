package cryptox

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP implements RFC 6238 with the parameters every mainstream authenticator
// app assumes: SHA-1, 6 digits, 30-second steps.
const (
	totpDigits = 6
	totpPeriod = 30 * time.Second
	// TOTPSkew accepts one step either side of now, covering clock drift
	// without meaningfully widening the guessing window.
	TOTPSkew = 1
)

var (
	ErrBadTOTPSecret = errors.New("cryptox: malformed TOTP secret")
	ErrBadTOTPCode   = errors.New("cryptox: malformed TOTP code")
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a 160-bit secret in the base32 form authenticator apps expect.
func NewTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("cryptox: totp secret: %w", err)
	}
	return b32.EncodeToString(b), nil
}

// TOTPProvisioningURI builds the otpauth:// URI rendered as an enrolment QR code.
func TOTPProvisioningURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", "30")
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// TOTPCodeAt derives the code for a specific instant; exported for tests and
// for the enrolment confirmation step.
func TOTPCodeAt(secret string, t time.Time) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil || len(key) < 10 {
		return "", ErrBadTOTPSecret
	}
	counter := uint64(t.Unix()) / uint64(totpPeriod.Seconds())
	return hotp(key, counter), nil
}

// VerifyTOTP checks code against the secret at time t, allowing TOTPSkew steps
// of drift. Comparison is constant time.
func VerifyTOTP(secret, code string, t time.Time) (bool, error) {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false, ErrBadTOTPCode
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return false, ErrBadTOTPCode
		}
	}
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil || len(key) < 10 {
		return false, ErrBadTOTPSecret
	}
	base := uint64(t.Unix()) / uint64(totpPeriod.Seconds())
	match := 0
	for d := -TOTPSkew; d <= TOTPSkew; d++ {
		c := base
		if d < 0 {
			c -= uint64(-d)
		} else {
			c += uint64(d)
		}
		// Accumulate rather than return early so the loop is timing-flat.
		match |= subtle.ConstantTimeCompare([]byte(hotp(key, c)), []byte(code))
	}
	return match == 1, nil
}

func hotp(key []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	m := hmac.New(sha1.New, key)
	m.Write(buf[:])
	sum := m.Sum(nil)
	offset := sum[len(sum)-1] & 0x0F
	trunc := (uint32(sum[offset])&0x7F)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	return fmt.Sprintf("%0*d", totpDigits, trunc%1_000_000)
}

// NewRecoveryCodes returns n single-use backup codes in a human-transcribable
// form, together with their digests for storage.
func NewRecoveryCodes(n int) (plain []string, digests [][]byte, err error) {
	plain = make([]string, n)
	digests = make([][]byte, n)
	for i := 0; i < n; i++ {
		var raw [10]byte
		if _, err = rand.Read(raw[:]); err != nil {
			return nil, nil, fmt.Errorf("cryptox: recovery code: %w", err)
		}
		s := b32.EncodeToString(raw[:])
		code := s[0:4] + "-" + s[4:8] + "-" + s[8:12] + "-" + s[12:16]
		plain[i] = code
		digests[i] = HashToken(code)
	}
	return plain, digests, nil
}
