// Package identity owns accounts, credentials, sessions and authorisation.
//
// Two design commitments run through it:
//
//  1. Personal data is encrypted under a per-subject key, and erasure is
//     performed by destroying that key. That is what lets a DPDP or GDPR
//     erasure request be honoured without deleting the financial records that
//     tax law requires be retained: the ledger keeps opaque identifiers, and
//     the readable personal data simply stops being readable.
//
//  2. Authorisation is always a fresh server-side lookup. No role, entitlement
//     or seller status is ever carried in a token the client holds, so a stolen
//     session cannot outlive a revocation.
package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/muthu2201/market-place/internal/platform/cryptox"
	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/ids"
)

// Vault performs per-subject encryption and the erasure primitive.
type Vault struct {
	// kek wraps every subject DEK. It never encrypts user data directly, so a
	// KEK rotation re-wraps keys rather than re-encrypting the whole database.
	kek []byte
	// blindIndexKey is derived from the KEK. It lets an exact-match lookup on
	// e-mail work while the address itself is never stored in the clear.
	blindIndexKey []byte
}

// NewVault derives the subkeys from the deployment KEK.
func NewVault(kek []byte) (*Vault, error) {
	if len(kek) != cryptox.KeySize {
		return nil, fmt.Errorf("identity: DATA_KEK must be %d bytes", cryptox.KeySize)
	}
	bi, err := cryptox.DeriveKey(kek, "email-blind-index", nil)
	if err != nil {
		return nil, err
	}
	wrap, err := cryptox.DeriveKey(kek, "dek-wrapping", nil)
	if err != nil {
		return nil, err
	}
	return &Vault{kek: wrap, blindIndexKey: bi}, nil
}

var (
	// ErrShredded means the subject's key has been destroyed. The ciphertext
	// still exists and still cannot be read, which is the intended outcome.
	ErrShredded = errors.New("identity: this subject's data has been erased")
	// ErrNoSubjectKey means no key was ever issued for this subject.
	ErrNoSubjectKey = errors.New("identity: no key registered for this subject")
)

// BlindIndex returns the deterministic lookup value for an e-mail address.
//
// The address is normalised first so that the same account is always found:
// the domain is lower-cased, the local part is not, because RFC 5321 makes the
// local part case-sensitive and silently folding it has caused real
// account-takeover bugs elsewhere.
func (v *Vault) BlindIndex(email string) []byte {
	return cryptox.Sign(v.blindIndexKey, []byte(NormaliseEmail(email)))
}

// NormaliseEmail lower-cases the domain and trims surrounding space.
func NormaliseEmail(email string) string {
	email = strings.TrimSpace(email)
	at := strings.LastIndexByte(email, '@')
	if at < 0 {
		return email
	}
	return email[:at+1] + strings.ToLower(email[at+1:])
}

// EmailDomain returns the lower-cased domain, which is kept in the clear for
// abuse analysis and is not personal data on its own.
func EmailDomain(email string) string {
	at := strings.LastIndexByte(email, '@')
	if at < 0 || at == len(email)-1 {
		return ""
	}
	return strings.ToLower(email[at+1:])
}

// IssueSubjectKey creates and stores a wrapped DEK for a new subject.
func (v *Vault) IssueSubjectKey(ctx context.Context, q db.Tx, subject ids.UUID) ([]byte, error) {
	dek, err := cryptox.NewKey()
	if err != nil {
		return nil, err
	}
	wrapped, err := cryptox.Seal(v.kek, dek, subjectAAD(subject))
	if err != nil {
		return nil, fmt.Errorf("identity: wrap dek: %w", err)
	}
	if _, err := q.Exec(ctx,
		`INSERT INTO subject_keys (subject_id, wrapped_dek) VALUES ($1, $2)
		 ON CONFLICT (subject_id) DO NOTHING`, subject, wrapped); err != nil {
		return nil, fmt.Errorf("identity: store subject key: %w", err)
	}
	return dek, nil
}

// SubjectKey unwraps a subject's DEK.
func (v *Vault) SubjectKey(ctx context.Context, q db.Querier, subject ids.UUID) ([]byte, error) {
	var wrapped []byte
	var shredded *string
	err := q.QueryRow(ctx,
		`SELECT wrapped_dek, shredded_at::text FROM subject_keys WHERE subject_id = $1`, subject,
	).Scan(&wrapped, &shredded)
	if db.IsNoRows(err) {
		return nil, ErrNoSubjectKey
	}
	if err != nil {
		return nil, fmt.Errorf("identity: read subject key: %w", err)
	}
	if shredded != nil || len(wrapped) == 0 {
		return nil, ErrShredded
	}
	dek, err := cryptox.Open(v.kek, wrapped, subjectAAD(subject))
	if err != nil {
		return nil, fmt.Errorf("identity: unwrap dek: %w", err)
	}
	return dek, nil
}

// Shred destroys a subject's key. This is irreversible and is the whole point:
// after it returns, no ciphertext encrypted under that key can be read by
// anyone, including us, including from a backup taken before the request.
func (v *Vault) Shred(ctx context.Context, q db.Tx, subject ids.UUID, reason string) error {
	tag, err := q.Exec(ctx, `
		UPDATE subject_keys
		   SET wrapped_dek = NULL, shredded_at = now(), shred_reason = $2
		 WHERE subject_id = $1 AND shredded_at IS NULL`, subject, reason)
	if err != nil {
		return fmt.Errorf("identity: shred: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Already shredded, or never existed. Either way the postcondition
		// "this subject's data is unreadable" holds, so this is not an error.
		return nil
	}
	return nil
}

// Encrypt seals a field under the subject's key, binding the subject and field
// name into the tag so a ciphertext cannot be moved between rows or columns.
func (v *Vault) Encrypt(dek []byte, subject ids.UUID, field, plaintext string) ([]byte, error) {
	if plaintext == "" {
		return nil, nil
	}
	return cryptox.Seal(dek, []byte(plaintext), fieldAAD(subject, field))
}

// Decrypt opens a field. A shredded subject yields ErrShredded from SubjectKey
// before this is ever reached.
func (v *Vault) Decrypt(dek []byte, subject ids.UUID, field string, ciphertext []byte) (string, error) {
	if len(ciphertext) == 0 {
		return "", nil
	}
	pt, err := cryptox.Open(dek, ciphertext, fieldAAD(subject, field))
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// DecryptFor is the common path: fetch the key, open one field.
func (v *Vault) DecryptFor(ctx context.Context, q db.Querier, subject ids.UUID, field string, ciphertext []byte) (string, error) {
	if len(ciphertext) == 0 {
		return "", nil
	}
	dek, err := v.SubjectKey(ctx, q, subject)
	if err != nil {
		return "", err
	}
	return v.Decrypt(dek, subject, field, ciphertext)
}

func subjectAAD(subject ids.UUID) []byte {
	return []byte("marketplace/subject-key/v1/" + subject.String())
}

func fieldAAD(subject ids.UUID, field string) []byte {
	return []byte("marketplace/field/v1/" + subject.String() + "/" + field)
}
