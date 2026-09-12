package seller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/muthu2201/market-place/internal/modules/audit"
	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/ids"
	"github.com/muthu2201/market-place/internal/platform/problem"
	"github.com/muthu2201/market-place/internal/platform/validate"
)

// PayoutAccountRequest registers where a seller's money should go.
type PayoutAccountRequest struct {
	SellerID ids.UUID
	UserID   ids.UUID
	// Method is "bank_account" or "vpa".
	Method string
	// AccountNumber is the bank account, or the VPA for a UPI destination.
	AccountNumber string
	IFSC          string
	// BeneficiaryName is what the bank has on file. It is checked against the
	// penny-drop result, which is the control that catches a typo'd account
	// number belonging to a real stranger.
	BeneficiaryName string
	MakeDefault     bool
	IP              string
}

// PayoutAccount is the seller-facing view. It never carries the account number.
type PayoutAccount struct {
	ID         ids.UUID
	Method     string
	Last4      string
	IFSC       string
	Validation string
	IsDefault  bool
	ActiveFrom time.Time
	// Quarantined says whether the cool-off is still running.
	Quarantined bool
}

// AddPayoutAccount registers a destination, quarantined for the cool-off.
//
// Three things happen here, and the order matters:
//
//  1. The account details are encrypted under the seller's subject key. The
//     clear columns are the last four digits and the IFSC — enough for the
//     seller to recognise which account they picked, and not enough to pay it.
//  2. A keyed fingerprint is stored so the same destination cannot be added
//     twice and so re-adding a previously-used one is recognisable.
//  3. `active_from` is left at the schema's default of now() + 48 hours.
//
// The third is the anti-takeover control, and it applies to *every* addition,
// including the first. A seller onboarding today waits two days for their first
// settlement — which is inside the settlement hold anyway, so it costs them
// nothing, while an attacker gets no exception for being first.
func (s *Service) AddPayoutAccount(ctx context.Context, req PayoutAccountRequest) (*PayoutAccount, error) {
	if err := validatePayoutRequest(&req); err != nil {
		return nil, err
	}

	id := ids.NewUUIDv7()
	fingerprint := s.payoutFingerprint(req.Method, req.AccountNumber, req.IFSC)
	last4 := lastFour(req.AccountNumber)
	activeFrom := s.clk.Now().Add(PayoutCoolOff)
	var out *PayoutAccount

	err := s.db.InTx(ctx, db.TxOptions{Name: "seller_add_payout"}, func(ctx context.Context, tx db.Tx) error {
		var sellerPublicID, status string
		if err := tx.QueryRow(ctx,
			`SELECT public_id, status FROM sellers WHERE id = $1 AND user_id = $2 FOR UPDATE`,
			req.SellerID, req.UserID).Scan(&sellerPublicID, &status); err != nil {
			return ErrNotFound
		}
		if status == StatusSuspended || status == StatusClosed {
			return problem.Conflict("", "Payout destinations cannot be changed while the account is "+status+".")
		}

		dek, err := s.vault.SubjectKey(ctx, tx, req.UserID)
		if err != nil {
			return fmt.Errorf("seller: reading the subject key: %w", err)
		}
		accountCipher, err := s.vault.Encrypt(dek, req.UserID, "payout.account", req.AccountNumber)
		if err != nil {
			return err
		}
		nameCipher, err := s.vault.Encrypt(dek, req.UserID, "payout.beneficiary_name", req.BeneficiaryName)
		if err != nil {
			return err
		}

		// The previous default is NOT disabled here. It keeps receiving
		// settlement until the new destination leaves quarantine, which is the
		// whole point: an attacker who adds an account must also survive 48
		// hours of the real seller seeing the notification.
		_, err = tx.Exec(ctx, `
			INSERT INTO seller_payout_accounts (
				id, seller_id, method, account_ciphertext, ifsc, account_last4,
				beneficiary_name_ciphertext, fingerprint, validation_status, active_from
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9)`,
			id, req.SellerID, req.Method, accountCipher, nullIfEmpty(req.IFSC), last4,
			nameCipher, fingerprint, activeFrom)
		if err != nil {
			if isUniqueViolation(err, "seller_payout_accounts_fingerprint_uq") {
				return problem.Conflict("", "That destination is already on your account.")
			}
			return fmt.Errorf("seller: adding the payout destination: %w", err)
		}

		if err := s.audit.Record(ctx, tx, audit.Event{
			ActorKind: audit.ActorSeller, ActorID: &req.UserID, ActorIP: req.IP,
			Action: "seller.payout_account.added", SubjectType: "seller", SubjectID: sellerPublicID,
			Metadata: map[string]any{
				"method": req.Method, "last4": last4, "ifsc": req.IFSC,
				"active_from": activeFrom.UTC().Format(time.RFC3339),
			},
		}); err != nil {
			return err
		}

		// The notification is the control. A cool-off nobody is told about
		// protects nothing, so this is queued in the same transaction as the
		// change: if the change commits, the warning is owed.
		if err := s.queuePayoutChangeNotice(ctx, tx, req.SellerID, last4, activeFrom); err != nil {
			return err
		}

		out = &PayoutAccount{
			ID: id, Method: req.Method, Last4: last4, IFSC: req.IFSC,
			Validation: "pending", ActiveFrom: activeFrom, Quarantined: true,
		}
		return nil
	})
	return out, err
}

// RecordValidation stores the outcome of a penny-drop or provider verification.
//
// The name-match score is what catches the dangerous case: an account number
// that is valid, belongs to somebody, and is not the seller. A mistyped digit
// almost always lands on a real account.
func (s *Service) RecordValidation(ctx context.Context, accountID ids.UUID, method, reference string, nameMatch int, failure string) error {
	if nameMatch < 0 || nameMatch > 100 {
		return errors.New("seller: a name-match score must be between 0 and 100")
	}
	return s.db.InTx(ctx, db.TxOptions{Name: "seller_record_validation"}, func(ctx context.Context, tx db.Tx) error {
		status := "validated"
		if failure != "" || nameMatch < minimumNameMatch {
			status = "failed"
			if failure == "" {
				failure = fmt.Sprintf(
					"the name on the account did not match the registered seller closely enough (%d%%)", nameMatch)
			}
		}

		tag, err := tx.Exec(ctx, `
			UPDATE seller_payout_accounts
			   SET validation_status = $2, validation_method = $3, validation_reference = $4,
			       name_match_score = $5, validation_failure = $6,
			       validated_at = CASE WHEN $2 = 'validated' THEN $7::timestamptz END
			 WHERE id = $1 AND disabled_at IS NULL`,
			accountID, status, method, nullIfEmpty(reference), nameMatch, nullIfEmpty(failure), s.clk.Now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}

		// A validated destination becomes the default. It still cannot receive
		// anything until active_from passes — validation and quarantine are
		// independent gates, and passing one does not shorten the other.
		if status == "validated" {
			if _, err := tx.Exec(ctx, `
				UPDATE seller_payout_accounts SET is_default = FALSE
				 WHERE seller_id = (SELECT seller_id FROM seller_payout_accounts WHERE id = $1)
				   AND id <> $1 AND disabled_at IS NULL`, accountID); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx,
				`UPDATE seller_payout_accounts SET is_default = TRUE WHERE id = $1`, accountID); err != nil {
				return err
			}
		}

		return s.audit.Record(ctx, tx, audit.Event{
			ActorKind: audit.ActorSystem, Action: "seller.payout_account.validated",
			SubjectType: "payout_account", SubjectID: accountID.String(),
			Metadata: map[string]any{
				"status": status, "method": method, "name_match_score": nameMatch,
			},
		})
	})
}

// minimumNameMatch is how close the bank's beneficiary name must be.
//
// Not 100: banks abbreviate, drop middle names, and render company suffixes
// inconsistently, so an exact-match rule would reject a large share of genuine
// accounts and teach support to override it — which is worse than a threshold.
const minimumNameMatch = 80

// ListPayoutAccounts returns a seller's destinations, never their numbers.
func (s *Service) ListPayoutAccounts(ctx context.Context, sellerID ids.UUID) ([]PayoutAccount, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id, method, COALESCE(account_last4, ''), COALESCE(ifsc, ''),
		       validation_status, is_default, active_from
		  FROM seller_payout_accounts
		 WHERE seller_id = $1 AND disabled_at IS NULL
		 ORDER BY is_default DESC, created_at DESC`, sellerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	now := s.clk.Now()
	var out []PayoutAccount
	for rows.Next() {
		var a PayoutAccount
		if err := rows.Scan(&a.ID, &a.Method, &a.Last4, &a.IFSC,
			&a.Validation, &a.IsDefault, &a.ActiveFrom); err != nil {
			return nil, err
		}
		a.Quarantined = a.ActiveFrom.After(now)
		out = append(out, a)
	}
	return out, rows.Err()
}

// DisablePayoutAccount removes a destination.
//
// Disabling is immediate and needs no cool-off: stopping money going somewhere
// is the safe direction, and an attacker gains nothing by turning off an
// account they do not control.
func (s *Service) DisablePayoutAccount(ctx context.Context, sellerID, userID, accountID ids.UUID, ip string) error {
	return s.db.InTx(ctx, db.TxOptions{Name: "seller_disable_payout"}, func(ctx context.Context, tx db.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE seller_payout_accounts SET disabled_at = $3, is_default = FALSE
			 WHERE id = $1 AND seller_id = $2 AND disabled_at IS NULL`,
			accountID, sellerID, s.clk.Now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return s.audit.Record(ctx, tx, audit.Event{
			ActorKind: audit.ActorSeller, ActorID: &userID, ActorIP: ip,
			Action: "seller.payout_account.disabled", SubjectType: "payout_account",
			SubjectID: accountID.String(),
		})
	})
}

// queuePayoutChangeNotice tells the seller their destination changed.
func (s *Service) queuePayoutChangeNotice(ctx context.Context, tx db.Tx, sellerID ids.UUID, last4 string, activeFrom time.Time) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO jobs (id, kind, unique_key, payload, run_at)
		VALUES ($1, 'notify_payout_change', $2, $3::jsonb, now())
		ON CONFLICT (unique_key) WHERE unique_key IS NOT NULL
		  AND completed_at IS NULL AND failed_at IS NULL DO NOTHING`,
		ids.NewUUIDv7(), "notify_payout_change:"+sellerID.String()+":"+activeFrom.UTC().Format(time.RFC3339),
		fmt.Sprintf(`{"seller_id":%q,"last4":%q,"active_from":%q}`,
			sellerID.String(), last4, activeFrom.UTC().Format(time.RFC3339)))
	return err
}

func validatePayoutRequest(req *PayoutAccountRequest) error {
	var v validate.Errors

	req.Method = strings.TrimSpace(req.Method)
	if req.Method == "" {
		req.Method = "bank_account"
	}
	req.AccountNumber = strings.TrimSpace(req.AccountNumber)
	req.IFSC = strings.ToUpper(strings.TrimSpace(req.IFSC))
	req.BeneficiaryName = strings.TrimSpace(req.BeneficiaryName)

	v.OneOf("method", req.Method, "bank_account", "vpa")
	v.Text("beneficiary_name", req.BeneficiaryName, 2, 200)

	switch req.Method {
	case "bank_account":
		if len(req.AccountNumber) < 6 || len(req.AccountNumber) > 20 || !isAlphanumeric(req.AccountNumber) {
			v.Add("account_number", "invalid", "That is not a valid bank account number.")
		}
		if !validIFSC(req.IFSC) {
			v.Add("ifsc", "invalid", "That is not a valid IFSC code.")
		}
	case "vpa":
		if !validVPA(req.AccountNumber) {
			v.Add("account_number", "invalid", "That is not a valid UPI ID.")
		}
		if req.IFSC != "" {
			v.Add("ifsc", "not_applicable", "A UPI ID does not take an IFSC code.")
		}
	}

	if p := v.Problem(); p != nil {
		return p
	}
	return nil
}

// validIFSC checks the published format: four letters, a zero, then six
// alphanumerics.
func validIFSC(s string) bool {
	if len(s) != 11 || s[4] != '0' {
		return false
	}
	for i := 0; i < 4; i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return false
		}
	}
	for i := 5; i < 11; i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func validVPA(s string) bool {
	at := strings.IndexByte(s, '@')
	if at <= 0 || at == len(s)-1 || len(s) > 255 {
		return false
	}
	if strings.Count(s, "@") != 1 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '-' || c == '_' || c == '@':
		default:
			return false
		}
	}
	return true
}

func isAlphanumeric(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// lastFour is what the seller sees to recognise which account they chose.
func lastFour(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 4 {
		return s
	}
	return s[len(s)-4:]
}
