package cryptox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// KeySize is the AES-256 key length in bytes.
	KeySize = 32
	// NonceSize is the AES-GCM standard nonce length.
	NonceSize = 12
)

var (
	ErrKeySize     = errors.New("cryptox: key must be exactly 32 bytes")
	ErrCiphertext  = errors.New("cryptox: ciphertext is too short or corrupt")
	ErrDecryptFail = errors.New("cryptox: decryption failed (wrong key, tampered data, or shredded)")
	ErrNoKey       = errors.New("cryptox: no key available for this key id")
)

// NewKey returns a fresh 256-bit key from the system CSPRNG.
func NewKey() ([]byte, error) {
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("cryptox: key generation failed: %w", err)
	}
	return k, nil
}

// Seal encrypts plaintext with AES-256-GCM, binding aad into the tag.
// The returned blob is nonce||ciphertext||tag.
//
// aad must include a stable identifier of what is being encrypted (for example
// the subject id and the field name) so a ciphertext cannot be moved between
// rows or columns.
func Seal(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("cryptox: nonce generation failed: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// Open reverses Seal. A wrong key, tampered bytes or mismatched aad are all
// reported as ErrDecryptFail with no further detail, on purpose.
func Open(key, blob, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < NonceSize+gcm.Overhead() {
		return nil, ErrCiphertext
	}
	out, err := gcm.Open(nil, blob[:NonceSize], blob[NonceSize:], aad)
	if err != nil {
		return nil, ErrDecryptFail
	}
	return out, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, ErrKeySize
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cryptox: cipher init: %w", err)
	}
	return cipher.NewGCM(block)
}

// DeriveKey expands a master key into a purpose-bound subkey via HKDF-SHA256.
// Different purposes therefore never share key material.
func DeriveKey(master []byte, purpose string, salt []byte) ([]byte, error) {
	if len(master) < KeySize {
		return nil, ErrKeySize
	}
	out := make([]byte, KeySize)
	r := hkdf.New(sha256.New, master, salt, []byte("marketplace/v1/"+purpose))
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("cryptox: hkdf: %w", err)
	}
	return out, nil
}

// Sign returns the HMAC-SHA256 of msg under key.
func Sign(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// SignHex returns Sign rendered as lowercase hex, matching the encoding that
// Razorpay and most webhook providers use.
func SignHex(key, msg []byte) string {
	return hexEncode(Sign(key, msg))
}

// VerifyHMAC compares a received MAC against the expected one in constant time.
func VerifyHMAC(key, msg, mac []byte) bool {
	return hmac.Equal(Sign(key, msg), mac)
}

// ConstantTimeEqualString compares two strings without leaking length-prefix
// information through early exit.
func ConstantTimeEqualString(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// HashToken returns the SHA-256 of a bearer token. Only the digest is stored,
// so a database leak does not yield usable session or API credentials.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// NewToken returns n bytes of CSPRNG entropy in URL-safe base64.
func NewToken(n int) (string, error) {
	if n < 16 {
		return "", errors.New("cryptox: tokens must carry at least 128 bits")
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("cryptox: token generation failed: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

const hexDigits = "0123456789abcdef"

func hexEncode(b []byte) string {
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexDigits[c>>4]
		out[i*2+1] = hexDigits[c&0x0F]
	}
	return string(out)
}

// HexDecode is a strict lowercase-or-uppercase hex decoder used for provider
// signature comparison. It never allocates on the failure path.
func HexDecode(s string) ([]byte, bool) {
	if len(s)%2 != 0 {
		return nil, false
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi, ok1 := hexVal(s[i*2])
		lo, ok2 := hexVal(s[i*2+1])
		if !ok1 || !ok2 {
			return nil, false
		}
		out[i] = hi<<4 | lo
	}
	return out, true
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
