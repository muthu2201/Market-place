// Package ids issues identifiers.
//
// Two kinds exist and they are deliberately different:
//
//   - UUIDv7 (RFC 9562) is the primary key type for every table. It is
//     time-ordered, so B-tree inserts stay at the right edge of the index and
//     we avoid the write amplification of UUIDv4 without leaking a sequence.
//   - Public IDs are what appear in URLs and API payloads. They carry a type
//     prefix and 128 bits of CSPRNG entropy encoded in Crockford base32, so an
//     attacker cannot enumerate resources or infer volume from an ID.
package ids

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// UUID is a raw 16-byte RFC 9562 identifier.
type UUID [16]byte

var (
	seqMu   sync.Mutex
	lastMS  int64
	lastSeq uint16
)

// NewUUIDv7 returns a time-ordered UUID. Within the same millisecond a
// monotonic 12-bit counter preserves ordering; if that counter saturates we
// borrow from the next millisecond rather than emit an out-of-order value.
func NewUUIDv7() UUID {
	var u UUID
	if _, err := rand.Read(u[6:]); err != nil {
		panic("ids: crypto/rand unavailable: " + err.Error())
	}

	seqMu.Lock()
	ms := time.Now().UnixMilli()
	switch {
	case ms > lastMS:
		lastMS, lastSeq = ms, 0
	case ms == lastMS:
		lastSeq++
		if lastSeq > 0x0FFF {
			lastMS++
			ms = lastMS
			lastSeq = 0
		}
	default:
		lastSeq++
		if lastSeq > 0x0FFF {
			lastMS++
			lastSeq = 0
		}
		ms = lastMS
	}
	seq := lastSeq
	seqMu.Unlock()

	u[0] = byte(ms >> 40)
	u[1] = byte(ms >> 32)
	u[2] = byte(ms >> 24)
	u[3] = byte(ms >> 16)
	u[4] = byte(ms >> 8)
	u[5] = byte(ms)
	u[6] = 0x70 | byte(seq>>8) // version 7
	u[7] = byte(seq)
	u[8] = (u[8] & 0x3F) | 0x80 // RFC 4122 variant
	return u
}

// Time recovers the millisecond timestamp embedded in a v7 UUID.
func (u UUID) Time() time.Time {
	ms := int64(u[0])<<40 | int64(u[1])<<32 | int64(u[2])<<24 |
		int64(u[3])<<16 | int64(u[4])<<8 | int64(u[5])
	return time.UnixMilli(ms).UTC()
}

func (u UUID) String() string {
	b := make([]byte, 36)
	hex.Encode(b[0:8], u[0:4])
	b[8] = '-'
	hex.Encode(b[9:13], u[4:6])
	b[13] = '-'
	hex.Encode(b[14:18], u[6:8])
	b[18] = '-'
	hex.Encode(b[19:23], u[8:10])
	b[23] = '-'
	hex.Encode(b[24:36], u[10:16])
	return string(b)
}

func (u UUID) Bytes() []byte { c := u; return c[:] }

func (u UUID) IsZero() bool { return u == UUID{} }

// ParseUUID accepts the canonical hyphenated form.
func ParseUUID(s string) (UUID, error) {
	var u UUID
	s = strings.TrimSpace(s)
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return u, fmt.Errorf("ids: %q is not a UUID", s)
	}
	clean := s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:36]
	b, err := hex.DecodeString(clean)
	if err != nil {
		return u, fmt.Errorf("ids: %q is not a UUID", s)
	}
	copy(u[:], b)
	return u, nil
}

// ---- public (external) identifiers -----------------------------------------

// crockford omits I, L, O and U so that transcription mistakes are impossible.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var crockfordRev = func() [256]int8 {
	var t [256]int8
	for i := range t {
		t[i] = -1
	}
	for i, c := range crockford {
		t[c] = int8(i)
		t[c|0x20] = int8(i) // lowercase
	}
	// Forgiving aliases for the omitted letters.
	t['o'], t['O'] = 0, 0
	t['i'], t['I'], t['l'], t['L'] = 1, 1, 1, 1
	t['u'], t['U'] = 27, 27 // same slot as V
	return t
}()

// Prefix names the resource type a public ID refers to.
type Prefix string

const (
	PrefixUser         Prefix = "usr"
	PrefixSeller       Prefix = "slr"
	PrefixProduct      Prefix = "prd"
	PrefixVariant      Prefix = "var"
	PrefixAsset        Prefix = "ast"
	PrefixOrder        Prefix = "ord"
	PrefixOrderItem    Prefix = "oit"
	PrefixPayment      Prefix = "pay"
	PrefixRefund       Prefix = "ref"
	PrefixTransfer     Prefix = "trf"
	PrefixLicense      Prefix = "lic"
	PrefixDownload     Prefix = "dnl"
	PrefixDispute      Prefix = "dsp"
	PrefixChargeback   Prefix = "cbk"
	PrefixPayout       Prefix = "pot"
	PrefixJournal      Prefix = "jrn"
	PrefixSession      Prefix = "ses"
	PrefixAPIKey       Prefix = "key"
	PrefixWebhook      Prefix = "whk"
	PrefixTag          Prefix = "tag"
	PrefixCategory     Prefix = "cat"
	PrefixReview       Prefix = "rev"
	PrefixGrievance    Prefix = "grv"
	PrefixIdempotency  Prefix = "idm"
	PrefixInvoice      Prefix = "inv"
	PrefixNotification Prefix = "ntf"
)

// NewPublic returns a prefixed, non-enumerable external identifier such as
// "prd_7ZK3QF1M8N2PXAB4CDEFGH0JKM".
func NewPublic(p Prefix) string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic("ids: crypto/rand unavailable: " + err.Error())
	}
	return string(p) + "_" + encodeCrockford(raw[:])
}

var ErrBadPublicID = errors.New("ids: malformed public identifier")

// ParsePublic validates shape and prefix, returning the encoded body.
func ParsePublic(want Prefix, s string) (string, error) {
	i := strings.IndexByte(s, '_')
	if i <= 0 || i == len(s)-1 {
		return "", ErrBadPublicID
	}
	if Prefix(s[:i]) != want {
		return "", fmt.Errorf("%w: expected prefix %q", ErrBadPublicID, want)
	}
	body := s[i+1:]
	if len(body) != 26 {
		return "", ErrBadPublicID
	}
	for j := 0; j < len(body); j++ {
		if crockfordRev[body[j]] < 0 {
			return "", ErrBadPublicID
		}
	}
	return body, nil
}

// ValidPublic reports whether s is a well-formed public ID of any known prefix.
func ValidPublic(s string) bool {
	i := strings.IndexByte(s, '_')
	if i <= 0 || i > 4 || len(s)-i-1 != 26 {
		return false
	}
	for j := i + 1; j < len(s); j++ {
		if crockfordRev[s[j]] < 0 {
			return false
		}
	}
	return true
}

func encodeCrockford(b []byte) string {
	// 16 bytes -> 128 bits -> 26 base32 symbols (130 bits, top 2 bits zero).
	out := make([]byte, 26)
	hi := binary.BigEndian.Uint64(b[0:8])
	lo := binary.BigEndian.Uint64(b[8:16])
	for i := 25; i >= 0; i-- {
		out[i] = crockford[lo&0x1F]
		lo = lo>>5 | (hi&0x1F)<<59
		hi >>= 5
	}
	return string(out)
}

// Correlation returns a short, non-secret identifier for log correlation.
func Correlation() string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic("ids: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(raw[:])
}
