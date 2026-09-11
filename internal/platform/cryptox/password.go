// Package cryptox holds every cryptographic primitive the platform uses.
//
// Nothing outside this package may call crypto/* directly for password
// hashing, token minting, AEAD or signing; cmd/archcheck enforces that rule so
// that a security review only ever has to read one package.
package cryptox

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2idParams are the cost parameters baked into every new hash.
//
// Defaults follow OWASP's 2024 Password Storage Cheat Sheet minimum for
// Argon2id (19 MiB, t=2, p=1) raised to 64 MiB because our login path is not
// throughput-critical and memory hardness is the property that actually
// defeats GPU cracking.
type Argon2idParams struct {
	Memory      uint32 // KiB
	Time        uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultArgon2idParams is used for all new passwords.
var DefaultArgon2idParams = Argon2idParams{
	Memory:      64 * 1024,
	Time:        3,
	Parallelism: uint8(min(4, runtime.NumCPU())),
	SaltLength:  16,
	KeyLength:   32,
}

// TestArgon2idParams keeps integration suites fast without changing the code
// path under test. Never assign this outside of tests; config refuses it when
// APP_ENV=production.
var TestArgon2idParams = Argon2idParams{Memory: 8 * 1024, Time: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}

var (
	ErrInvalidHash      = errors.New("cryptox: malformed password hash")
	ErrIncompatibleHash = errors.New("cryptox: unsupported password hash algorithm")
	ErrPasswordMismatch = errors.New("cryptox: password does not match")
	ErrPasswordTooShort = errors.New("cryptox: password is shorter than the minimum length")
	ErrPasswordTooLong  = errors.New("cryptox: password exceeds the maximum length")
)

const (
	// MinPasswordLength follows NIST SP 800-63B: length is the control that
	// matters; composition rules are not enforced.
	MinPasswordLength = 12
	// MaxPasswordLength bounds the work an unauthenticated caller can force us
	// to do. Argon2 cost is dominated by memory, but hashing a 10 MB "password"
	// is still free CPU for an attacker.
	MaxPasswordLength = 1024
)

// HashPassword returns a PHC-format string: $argon2id$v=19$m=...,t=...,p=...$salt$hash
func HashPassword(plaintext string, p Argon2idParams) (string, error) {
	if err := CheckPasswordLength(plaintext); err != nil {
		return "", err
	}
	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("cryptox: salt generation failed: %w", err)
	}
	key := argon2.IDKey([]byte(plaintext), salt, p.Time, p.Memory, p.Parallelism, p.KeyLength)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Time, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// CheckPasswordLength validates bounds before any expensive work happens.
func CheckPasswordLength(plaintext string) error {
	if len(plaintext) < MinPasswordLength {
		return ErrPasswordTooShort
	}
	if len(plaintext) > MaxPasswordLength {
		return ErrPasswordTooLong
	}
	return nil
}

// VerifyPassword compares a candidate against an encoded hash in constant time
// and reports whether the stored hash should be upgraded to current parameters.
func VerifyPassword(plaintext, encoded string) (ok bool, needsRehash bool, err error) {
	p, salt, want, err := decodeArgon2idHash(encoded)
	if err != nil {
		return false, false, err
	}
	if len(plaintext) > MaxPasswordLength {
		return false, false, ErrPasswordTooLong
	}
	got := argon2.IDKey([]byte(plaintext), salt, p.Time, p.Memory, p.Parallelism, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, false, nil
	}
	d := DefaultArgon2idParams
	needsRehash = p.Memory < d.Memory || p.Time < d.Time || uint32(len(want)) < d.KeyLength
	return true, needsRehash, nil
}

func decodeArgon2idHash(encoded string) (p Argon2idParams, salt, key []byte, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" {
		return p, nil, nil, ErrInvalidHash
	}
	if parts[1] != "argon2id" {
		return p, nil, nil, ErrIncompatibleHash
	}
	var version int
	if _, err = fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return p, nil, nil, ErrInvalidHash
	}
	if version != argon2.Version {
		return p, nil, nil, ErrIncompatibleHash
	}
	if _, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Parallelism); err != nil {
		return p, nil, nil, ErrInvalidHash
	}
	if p.Memory == 0 || p.Time == 0 || p.Parallelism == 0 {
		return p, nil, nil, ErrInvalidHash
	}
	if salt, err = base64.RawStdEncoding.Strict().DecodeString(parts[4]); err != nil {
		return p, nil, nil, ErrInvalidHash
	}
	if key, err = base64.RawStdEncoding.Strict().DecodeString(parts[5]); err != nil {
		return p, nil, nil, ErrInvalidHash
	}
	if len(salt) < 8 || len(key) < 16 {
		return p, nil, nil, ErrInvalidHash
	}
	p.SaltLength = uint32(len(salt))
	p.KeyLength = uint32(len(key))
	return p, salt, key, nil
}

// DummyVerify burns the same work as a real verification. The login handler
// calls it when the account does not exist so that response time cannot be used
// to enumerate registered e-mail addresses.
func DummyVerify(plaintext string, p Argon2idParams) {
	salt := []byte("marketplace-timing-equaliser")
	_ = argon2.IDKey([]byte(plaintext), salt, p.Time, p.Memory, p.Parallelism, p.KeyLength)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
