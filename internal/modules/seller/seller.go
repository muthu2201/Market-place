// Package seller owns onboarding: becoming a seller, submitting KYC, linking a
// provider account, and registering where money should go.
//
// Two controls in here matter more than the rest of the package put together,
// and both are about the same attack: somebody takes over a seller's account
// and redirects their earnings.
//
//  1. **Settlement is gated on the PROVIDER's view of KYC, never on ours.** A
//     seller may list while verification is pending; they cannot be paid until
//     the provider reports the linked account activated. Our own record of that
//     is a cache, and a cache is not an authorisation.
//
//  2. **A new or changed payout destination is quarantined for 48 hours.** The
//     schema defaults `active_from` to `now() + 48 hours`, and settlement reads
//     that column. An attacker who gets in at 2am cannot have the next
//     settlement run land in their account — there is a window in which the
//     real seller is notified and can intervene.
//
// Neither control stops an account takeover. Both convert it from an
// irreversible loss into a recoverable incident, which is the realistic goal.
package seller

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/muthu2201/market-place/internal/modules/audit"
	"github.com/muthu2201/market-place/internal/modules/identity"
	"github.com/muthu2201/market-place/internal/modules/payments"
	"github.com/muthu2201/market-place/internal/platform/clock"
	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/ids"
	"github.com/muthu2201/market-place/internal/platform/problem"
	"github.com/muthu2201/market-place/internal/platform/validate"
)

// Status values, matching the sellers CHECK constraint.
const (
	StatusPending    = "pending"
	StatusActive     = "active"
	StatusRestricted = "restricted"
	StatusSuspended  = "suspended"
	StatusClosed     = "closed"
)

// KYC status values, matching the sellers CHECK constraint.
const (
	KYCUnverified  = "unverified"
	KYCSubmitted   = "submitted"
	KYCUnderReview = "under_review"
	KYCVerified    = "verified"
	KYCRejected    = "rejected"
	KYCExpired     = "expired"
)

// PayoutCoolOff is how long a new or changed destination is quarantined.
//
// It matches the schema default, and it is stated here so the notification the
// seller receives can name the same number the database enforces.
const PayoutCoolOff = 48 * time.Hour

// Service is seller onboarding.
type Service struct {
	db       *db.DB
	vault    *identity.Vault
	provider payments.Provider
	audit    *audit.Service
	clk      clock.Clock
	log      *slog.Logger
	// payoutPepper keys the destination fingerprint, so the fingerprint index
	// cannot be used to test guesses at an account number.
	payoutPepper []byte
}

// Options configure the service.
type Options struct {
	DB           *db.DB
	Vault        *identity.Vault
	Provider     payments.Provider
	Audit        *audit.Service
	Clock        clock.Clock
	Log          *slog.Logger
	PayoutPepper []byte
}

// New builds the service.
func New(o Options) (*Service, error) {
	switch {
	case o.DB == nil:
		return nil, errors.New("seller: a database is required")
	case o.Vault == nil:
		return nil, errors.New("seller: a vault is required; legal identity is never stored in the clear")
	case len(o.PayoutPepper) < 32:
		return nil, errors.New("seller: a payout fingerprint pepper of at least 32 bytes is required")
	}
	if o.Clock == nil {
		o.Clock = clock.System()
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Audit == nil {
		o.Audit = audit.New()
	}
	return &Service{
		db: o.DB, vault: o.Vault, provider: o.Provider, audit: o.Audit,
		clk: o.Clock, log: o.Log, payoutPepper: o.PayoutPepper,
	}, nil
}

// Errors callers branch on.
var (
	ErrNotFound      = errors.New("seller: not found")
	ErrAlreadySeller = errors.New("seller: this account is already a seller")
	// ErrNotPayable means settlement cannot run: KYC, provider activation or
	// the payout cool-off is not satisfied.
	ErrNotPayable = errors.New("seller: not yet eligible for settlement")
)

// OnboardRequest is an application to sell.
type OnboardRequest struct {
	UserID      ids.UUID
	Handle      string
	DisplayName string
	Bio         string
	LegalName   string
	EntityType  string
	Country     string
	StateCode   int
	PAN         string
	GSTIN       string
	IP          string
}

// Seller is the seller-facing view.
type Seller struct {
	ID          ids.UUID
	PublicID    string
	Handle      string
	DisplayName string
	Status      string
	KYCStatus   string
}

// Onboard creates a seller profile in pending state.
//
// The legal name is encrypted under the user's own subject key before it
// touches a column, so an erasure request later destroys it along with
// everything else about that person, while the financial record survives.
func (s *Service) Onboard(ctx context.Context, req OnboardRequest) (*Seller, error) {
	if err := validateOnboard(&req); err != nil {
		return nil, err
	}

	id := ids.NewUUIDv7()
	publicID := ids.NewPublic(ids.PrefixSeller)
	var out *Seller

	err := s.db.InTx(ctx, db.TxOptions{Name: "seller_onboard"}, func(ctx context.Context, tx db.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM sellers WHERE user_id = $1)`, req.UserID).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return ErrAlreadySeller
		}

		dek, err := s.vault.SubjectKey(ctx, tx, req.UserID)
		if err != nil {
			return fmt.Errorf("seller: reading the subject key: %w", err)
		}
		legalName, err := s.vault.Encrypt(dek, req.UserID, "seller.legal_name", req.LegalName)
		if err != nil {
			return err
		}

		_, err = tx.Exec(ctx, `
			INSERT INTO sellers (
				id, public_id, user_id, handle, display_name, bio,
				legal_name_ciphertext, entity_type, country, state_code,
				pan, gstin, gst_registered, status, kyc_status
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'pending','unverified')`,
			id, publicID, req.UserID, req.Handle, req.DisplayName, nullIfEmpty(req.Bio),
			legalName, req.EntityType, req.Country, nullIfZero(req.StateCode),
			nullIfEmpty(req.PAN), nullIfEmpty(req.GSTIN), req.GSTIN != "")
		if err != nil {
			if isUniqueViolation(err, "sellers_handle_key") {
				return problem.Validation(problem.FieldError{
					Field: "handle", Code: "taken", Detail: "That handle is already in use."})
			}
			if isUniqueViolation(err, "sellers_gstin_uq") {
				// Two sellers cannot share a GSTIN. Saying so plainly is right:
				// it is a fact about a public register, not a private one.
				return problem.Validation(problem.FieldError{
					Field: "gstin", Code: "taken",
					Detail: "That GSTIN is already registered to another seller account."})
			}
			return fmt.Errorf("seller: creating the profile: %w", err)
		}

		// Granting the role is what makes the seller surfaces reachable. It is
		// granted at onboarding, not at verification, because a pending seller
		// must be able to build a listing while KYC runs — they simply cannot
		// publish it or be paid.
		if _, err := tx.Exec(ctx, `
			INSERT INTO user_roles (user_id, role_code) VALUES ($1, $2)
			ON CONFLICT (user_id, role_code) DO NOTHING`, req.UserID, identity.RoleSeller); err != nil {
			return fmt.Errorf("seller: granting the seller role: %w", err)
		}

		if err := s.audit.Record(ctx, tx, audit.Event{
			ActorKind: audit.ActorUser, ActorID: &req.UserID, ActorIP: req.IP,
			Action: "seller.onboarded", SubjectType: "seller", SubjectID: publicID,
			Metadata: map[string]any{"handle": req.Handle, "entity_type": req.EntityType},
		}); err != nil {
			return err
		}

		out = &Seller{
			ID: id, PublicID: publicID, Handle: req.Handle, DisplayName: req.DisplayName,
			Status: StatusPending, KYCStatus: KYCUnverified,
		}
		return nil
	})
	return out, err
}

// SubmitKYC moves a seller into the review queue.
func (s *Service) SubmitKYC(ctx context.Context, sellerID, actorID ids.UUID, ip string) error {
	return s.db.InTx(ctx, db.TxOptions{Name: "seller_submit_kyc"}, func(ctx context.Context, tx db.Tx) error {
		var status, kyc, publicID string
		var pan, gstin *string
		var docs int
		err := tx.QueryRow(ctx, `
			SELECT s.public_id, s.status, s.kyc_status, s.pan, s.gstin,
			       (SELECT count(*) FROM seller_documents d
			          WHERE d.seller_id = s.id AND d.scan_status = 'clean')
			  FROM sellers s WHERE s.id = $1 FOR UPDATE`, sellerID,
		).Scan(&publicID, &status, &kyc, &pan, &gstin, &docs)
		if err != nil {
			return ErrNotFound
		}
		switch kyc {
		case KYCVerified:
			return nil // already done; resubmitting is not an error
		case KYCSubmitted, KYCUnderReview:
			return problem.Conflict("", "Your documents are already with us. We will e-mail you when the review is complete.")
		}
		if pan == nil || *pan == "" {
			return problem.Conflict("", "A PAN is required before verification can start.")
		}
		if docs == 0 {
			return problem.Conflict("", "Upload at least one identity document before submitting for verification.")
		}

		if _, err := tx.Exec(ctx,
			`UPDATE sellers SET kyc_status = 'submitted', kyc_rejected_reason = NULL WHERE id = $1`,
			sellerID); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, audit.Event{
			ActorKind: audit.ActorSeller, ActorID: &actorID, ActorIP: ip,
			Action: "seller.kyc.submitted", SubjectType: "seller", SubjectID: publicID,
		})
	})
}

// PayoutEligibility answers "can this seller be paid, and if not, why not".
//
// It is the single place that question is answered, so settlement, the seller
// dashboard and support all get the same answer from the same rules.
type PayoutEligibility struct {
	Payable bool
	// Reasons are phrased for the seller, because this is what their dashboard
	// shows when money has not arrived.
	Reasons []string
	// PayoutActiveFrom is when the current destination leaves its cool-off.
	PayoutActiveFrom *time.Time
}

// PayoutEligibility reports whether settlement may run for this seller.
func (s *Service) PayoutEligibility(ctx context.Context, sellerID ids.UUID) (PayoutEligibility, error) {
	var e PayoutEligibility
	var (
		status, kyc, providerStatus string
		providerAccount             *string
		activeFrom                  *time.Time
		validation                  *string
	)
	err := s.db.QueryRow(ctx, `
		SELECT s.status, s.kyc_status, s.provider_account_status, s.provider_account_id,
		       pa.active_from, pa.validation_status
		  FROM sellers s
		  LEFT JOIN seller_payout_accounts pa
		    ON pa.seller_id = s.id AND pa.is_default AND pa.disabled_at IS NULL
		 WHERE s.id = $1`, sellerID,
	).Scan(&status, &kyc, &providerStatus, &providerAccount, &activeFrom, &validation)
	if err != nil {
		return e, ErrNotFound
	}

	if status != StatusActive {
		e.Reasons = append(e.Reasons, "Your seller account is "+status+".")
	}
	if kyc != KYCVerified {
		e.Reasons = append(e.Reasons, "Identity verification is not complete.")
	}
	// The provider's view, not ours. Their record is the one that decides
	// whether a transfer succeeds or silently holds.
	if providerStatus != "activated" || providerAccount == nil {
		e.Reasons = append(e.Reasons,
			"Your payment account is not yet activated by our payment provider.")
	}
	switch {
	case activeFrom == nil:
		e.Reasons = append(e.Reasons, "No payout destination has been added.")
	case validation == nil || *validation != "validated":
		e.Reasons = append(e.Reasons, "Your payout destination has not been verified yet.")
	case activeFrom.After(s.clk.Now()):
		e.PayoutActiveFrom = activeFrom
		e.Reasons = append(e.Reasons, fmt.Sprintf(
			"Your payout destination was added or changed recently and becomes active on %s. "+
				"This %s wait applies to every change, and it exists so that if someone else "+
				"changed it, you have time to tell us.",
			activeFrom.UTC().Format("2 January 2006 at 15:04 UTC"), PayoutCoolOff))
	}

	e.Payable = len(e.Reasons) == 0
	return e, nil
}

// ---- helpers ----------------------------------------------------------------

// payoutFingerprint identifies a destination without storing it in the clear.
//
// Keyed with a deployment pepper: an unkeyed hash of an account number is
// reversible by anyone willing to enumerate, and account numbers are a small
// enough space to enumerate. The fingerprint's only jobs are to spot a
// re-added destination and to enforce the per-seller uniqueness index.
func (s *Service) payoutFingerprint(method, account, ifsc string) []byte {
	mac := hmac.New(sha256.New, s.payoutPepper)
	mac.Write([]byte(method))
	mac.Write([]byte{0})
	mac.Write([]byte(strings.ToUpper(strings.TrimSpace(account))))
	mac.Write([]byte{0})
	mac.Write([]byte(strings.ToUpper(strings.TrimSpace(ifsc))))
	return mac.Sum(nil)
}

func validateOnboard(req *OnboardRequest) error {
	var v validate.Errors

	req.Handle = strings.ToLower(strings.TrimSpace(req.Handle))
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	req.LegalName = strings.TrimSpace(req.LegalName)
	req.PAN = strings.ToUpper(strings.TrimSpace(req.PAN))
	req.GSTIN = strings.ToUpper(strings.TrimSpace(req.GSTIN))
	req.Country = strings.ToUpper(strings.TrimSpace(req.Country))
	if req.Country == "" {
		req.Country = "IN"
	}
	if req.EntityType == "" {
		req.EntityType = "individual"
	}

	v.Handle("handle", req.Handle)
	v.Text("display_name", req.DisplayName, 2, 120)
	v.Text("legal_name", req.LegalName, 2, 200)
	if req.Bio != "" {
		v.Text("bio", req.Bio, 1, 2000)
	}
	v.OneOf("entity_type", req.EntityType,
		"individual", "huf", "proprietorship", "partnership", "llp",
		"private_limited", "public_limited", "trust", "society", "foreign")

	if req.PAN != "" && !validPAN(req.PAN) {
		v.Add("pan", "invalid", "That is not a valid PAN.")
	}
	if req.GSTIN != "" {
		if !validGSTIN(req.GSTIN) {
			v.Add("gstin", "invalid", "That is not a valid GSTIN.")
		} else if req.PAN != "" && req.GSTIN[2:12] != req.PAN {
			// A GSTIN embeds the holder's PAN. A mismatch is either a typo or
			// somebody else's registration number, and both are worth catching
			// before a TCS return is filed against the wrong party.
			v.Add("gstin", "pan_mismatch",
				"This GSTIN does not belong to the PAN you gave. Characters 3 to 12 of a GSTIN are the holder's PAN.")
		}
	}
	if req.Country == "IN" && (req.StateCode < 1 || req.StateCode > 99) {
		v.Add("state_code", "required", "A GST state code is required for sellers in India.")
	}

	if p := v.Problem(); p != nil {
		return p
	}
	return nil
}

func validPAN(s string) bool {
	if len(s) != 10 {
		return false
	}
	for i, c := range s {
		switch {
		case i < 5 || i == 9:
			if c < 'A' || c > 'Z' {
				return false
			}
		default:
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// validGSTIN checks the format and the check digit.
//
// The checksum is worth computing rather than trusting the shape: a
// transposed digit produces a well-formed GSTIN that belongs to nobody, and
// discovering that when a GSTR-8 return is rejected is expensive.
func validGSTIN(s string) bool {
	if len(s) != 15 || s[13] != 'Z' {
		return false
	}
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	sum := 0
	for i := 0; i < 14; i++ {
		idx := strings.IndexByte(alphabet, s[i])
		if idx < 0 {
			return false
		}
		factor := 1
		if i%2 == 1 {
			factor = 2
		}
		product := idx * factor
		sum += product/36 + product%36
	}
	check := (36 - sum%36) % 36
	return s[14] == alphabet[check]
}

func nullIfEmpty(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func nullIfZero(v int) any {
	if v == 0 {
		return nil
	}
	return v
}

func isUniqueViolation(err error, constraint string) bool {
	return err != nil && strings.Contains(err.Error(), constraint)
}
