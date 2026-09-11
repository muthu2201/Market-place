// Package fixtures seeds realistic data for integration and load tests.
//
// It writes through the same tables and constraints production uses, so a
// fixture that violates a business rule fails here rather than producing a test
// that passes against data the real system would never have allowed.
package fixtures

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/muthu2201/market-place/internal/modules/identity"
	"github.com/muthu2201/market-place/internal/platform/cryptox"
	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/ids"
)

// Seller is a seeded, fully onboarded seller.
type Seller struct {
	ID              ids.UUID
	PublicID        string
	UserID          ids.UUID
	Handle          string
	GSTIN           string
	PAN             string
	StateCode       int
	ProviderAccount string
}

// Product is a seeded, published product with one priced variant.
type Product struct {
	ID              ids.UUID
	PublicID        string
	VariantID       ids.UUID
	VariantPublicID string
	AssetID         ids.UUID
	SellerID        ids.UUID
	Title           string
	PriceMinor      int64
	Currency        string
}

// SellerSpec controls how a seeded seller is configured.
type SellerSpec struct {
	Handle          string
	GSTRegistered   bool
	GSTIN           string
	PAN             string
	StateCode       int
	EntityType      string
	KYCVerified     bool
	ProviderAccount string
	ProviderStatus  string
	HoldDays        int
	CommissionBps   int64
}

// DefaultSellerSpec is a GST-registered private limited company in Tamil Nadu
// with an activated linked account: the fully happy path.
//
// The PAN and GSTIN are derived from the handle so that every seeded seller is
// distinct, and the GSTIN carries a real checksum so it survives the same
// validation a live registration would.
func DefaultSellerSpec(handle string) SellerSpec {
	pan := PANFor(handle)
	return SellerSpec{
		Handle: handle, GSTRegistered: true, GSTIN: GSTINFor(33, pan),
		PAN: pan, StateCode: 33, EntityType: "private_limited",
		KYCVerified: true, ProviderAccount: "acc_seeded_" + handle,
		ProviderStatus: "activated", HoldDays: 14, CommissionBps: 900,
	}
}

const b36 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

// PANFor derives a well-formed, deterministic PAN (AAAAA9999A) from a handle.
func PANFor(handle string) string {
	h := sha256.Sum256([]byte("pan:" + handle))
	letters := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	out := make([]byte, 0, 10)
	for i := 0; i < 5; i++ {
		out = append(out, letters[int(h[i])%26])
	}
	for i := 5; i < 9; i++ {
		out = append(out, byte('0'+int(h[i])%10))
	}
	out = append(out, letters[int(h[9])%26])
	return string(out)
}

// GSTINFor builds a GSTIN with a correct check character, so fixtures exercise
// the same validation path a real registration would.
func GSTINFor(stateCode int, pan string) string {
	body := fmt.Sprintf("%02d%s1Z", stateCode, pan)
	sum := 0
	for i := 0; i < 14; i++ {
		idx := strings.IndexByte(b36, body[i])
		factor := 1
		if i%2 == 1 {
			factor = 2
		}
		p := idx * factor
		sum += p/36 + p%36
	}
	check := (36 - (sum % 36)) % 36
	return body + string(b36[check])
}

// NewSeller seeds a user, a seller profile and a validated payout account.
func NewSeller(t *testing.T, ctx context.Context, d *db.DB, vault *identity.Vault, spec SellerSpec) Seller {
	t.Helper()
	if spec.EntityType == "" {
		spec.EntityType = "individual"
	}
	if spec.StateCode == 0 {
		spec.StateCode = 33
	}
	if spec.CommissionBps == 0 {
		spec.CommissionBps = 900
	}

	userID := ids.NewUUIDv7()
	sellerID := ids.NewUUIDv7()
	sellerPublic := ids.NewPublic(ids.PrefixSeller)
	email := spec.Handle + "@sellers.example.com"

	err := d.InTx(ctx, db.TxOptions{Name: "fixture_seller"}, func(ctx context.Context, tx db.Tx) error {
		dek, err := vault.IssueSubjectKey(ctx, tx, userID)
		if err != nil {
			return err
		}
		emailCT, err := vault.Encrypt(dek, userID, "email", email)
		if err != nil {
			return err
		}
		hash, err := cryptox.HashPassword("fixture-password-not-real", cryptox.TestArgon2idParams)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO users (id, public_id, email_index, email_ciphertext, email_domain,
			                   password_hash, country, tax_residence, state_code, email_verified_at)
			VALUES ($1,$2,$3,$4,'sellers.example.com',$5,'IN','IN',$6, now())`,
			userID, ids.NewPublic(ids.PrefixUser), vault.BlindIndex(email), emailCT, hash, spec.StateCode); err != nil {
			return err
		}
		for _, role := range []string{"buyer", "seller"} {
			if _, err := tx.Exec(ctx,
				`INSERT INTO user_roles (user_id, role_code) VALUES ($1,$2)`, userID, role); err != nil {
				return err
			}
		}

		kyc := "unverified"
		var verifiedAt any
		if spec.KYCVerified {
			kyc = "verified"
			verifiedAt = time.Now().UTC()
		}
		providerStatus := spec.ProviderStatus
		if providerStatus == "" {
			providerStatus = "none"
		}
		var provider, providerAccount any
		if providerStatus != "none" {
			provider = "razorpay_route"
			providerAccount = spec.ProviderAccount
		}
		var gstin, pan any
		if spec.GSTIN != "" {
			gstin = spec.GSTIN
		}
		if spec.PAN != "" {
			pan = spec.PAN
		}
		status := "pending"
		if spec.KYCVerified {
			status = "active"
		}
		holdDays := spec.HoldDays
		if holdDays == 0 {
			holdDays = 14
		}

		if _, err := tx.Exec(ctx, `
			INSERT INTO sellers (id, public_id, user_id, handle, display_name, entity_type,
			                     country, state_code, pan, gstin, gst_registered,
			                     kyc_status, kyc_verified_at, provider, provider_account_id,
			                     provider_account_status, provider_account_activated_at,
			                     settlement_hold_days, status)
			VALUES ($1,$2,$3,$4,$5,$6,'IN',$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
			sellerID, sellerPublic, userID, spec.Handle, "Seller "+spec.Handle, spec.EntityType,
			spec.StateCode, pan, gstin, spec.GSTRegistered,
			kyc, verifiedAt, provider, providerAccount, providerStatus, verifiedAt,
			holdDays, status); err != nil {
			return err
		}

		// Payout destination, validated and past its change cool-off so a
		// payout is permitted.
		if _, err := tx.Exec(ctx, `
			INSERT INTO seller_payout_accounts (id, seller_id, account_ciphertext, ifsc, account_last4,
			                                    fingerprint, validation_status, validation_method,
			                                    validated_at, name_match_score, is_default, active_from)
			VALUES ($1,$2,$3,'HDFC0001234','7890',$4,'validated','penny_drop',now(),100,TRUE, now() - INTERVAL '3 days')`,
			ids.NewUUIDv7(), sellerID, []byte("encrypted-account-details"),
			cryptox.HashToken("fixture-account-"+spec.Handle)); err != nil {
			return err
		}

		// Fee assignment, so the contracted commission is honoured.
		var scheduleID ids.UUID
		if err := tx.QueryRow(ctx,
			`SELECT id FROM fee_schedules WHERE commission_bps = $1 ORDER BY effective_from LIMIT 1`,
			spec.CommissionBps).Scan(&scheduleID); err != nil {
			if !db.IsNoRows(err) {
				return err
			}
			scheduleID = ids.NewUUIDv7()
			if _, err := tx.Exec(ctx, `
				INSERT INTO fee_schedules (id, code, commission_bps, description, effective_from, announced_at)
				VALUES ($1,$2,$3,'Fixture schedule', now(), now())`,
				scheduleID, fmt.Sprintf("fixture_%d", spec.CommissionBps), spec.CommissionBps); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO seller_fee_assignments (seller_id, fee_schedule_id, effective_from)
			VALUES ($1,$2, now() - INTERVAL '1 day')`, sellerID, scheduleID)
		return err
	})
	if err != nil {
		t.Fatalf("fixtures: seed seller %s: %v", spec.Handle, err)
	}

	return Seller{
		ID: sellerID, PublicID: sellerPublic, UserID: userID, Handle: spec.Handle,
		GSTIN: spec.GSTIN, PAN: spec.PAN, StateCode: spec.StateCode,
		ProviderAccount: spec.ProviderAccount,
	}
}

// Category returns (creating once) the seeded top-level category.
func Category(t *testing.T, ctx context.Context, d *db.DB) ids.UUID {
	t.Helper()
	var id ids.UUID
	err := d.QueryRow(ctx, `SELECT id FROM categories WHERE slug = 'digital-assets'`).Scan(&id)
	if err == nil {
		return id
	}
	if !db.IsNoRows(err) {
		t.Fatalf("fixtures: read category: %v", err)
	}
	id = ids.NewUUIDv7()
	if _, err := d.Exec(ctx, `
		INSERT INTO categories (id, public_id, slug, name, path, depth, sac_code)
		VALUES ($1,$2,'digital-assets','Digital assets','digital-assets',0,'998434')`,
		id, ids.NewPublic(ids.PrefixCategory)); err != nil {
		t.Fatalf("fixtures: seed category: %v", err)
	}
	return id
}

// ProductSpec controls a seeded product.
type ProductSpec struct {
	Title        string
	Slug         string
	PriceMinor   int64
	Currency     string
	AIDisclosure string
	LicenseDays  *int
	MaxSales     *int
	Publish      bool
}

// NewProduct seeds a product with one clean, scanned asset and one variant.
func NewProduct(t *testing.T, ctx context.Context, d *db.DB, seller Seller, spec ProductSpec) Product {
	t.Helper()
	if spec.Currency == "" {
		spec.Currency = "INR"
	}
	if spec.PriceMinor == 0 {
		spec.PriceMinor = 200000
	}
	if spec.AIDisclosure == "" {
		spec.AIDisclosure = "no_ai"
	}
	if spec.Slug == "" {
		spec.Slug = "fixture-" + ids.Correlation()
	}
	if spec.Title == "" {
		spec.Title = "Fixture product " + spec.Slug
	}

	categoryID := Category(t, ctx, d)
	p := Product{
		ID: ids.NewUUIDv7(), PublicID: ids.NewPublic(ids.PrefixProduct),
		VariantID: ids.NewUUIDv7(), VariantPublicID: ids.NewPublic(ids.PrefixVariant),
		AssetID: ids.NewUUIDv7(), SellerID: seller.ID, Title: spec.Title,
		PriceMinor: spec.PriceMinor, Currency: spec.Currency,
	}

	err := d.InTx(ctx, db.TxOptions{Name: "fixture_product"}, func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO products (id, public_id, seller_id, category_id, slug, title, summary, description,
			                      delivery_type, license_type, license_terms, license_duration_days,
			                      status, ai_disclosure)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'download','commercial',$9,$10,'draft',$11)`,
			p.ID, p.PublicID, seller.ID, categoryID, spec.Slug, spec.Title,
			"A seeded product used by the integration suite.",
			"A longer description of the seeded product, used to exercise search indexing and rendering.",
			"Commercial use permitted. Redistribution of the source files is not permitted.",
			spec.LicenseDays, spec.AIDisclosure); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO product_variants (id, public_id, product_id, name, price_minor, currency, max_sales)
			VALUES ($1,$2,$3,'Standard',$4,$5,$6)`,
			p.VariantID, p.VariantPublicID, p.ID, spec.PriceMinor, spec.Currency, spec.MaxSales); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO product_assets (id, public_id, product_id, variant_id, filename, object_key,
			                            content_type, detected_type, size_bytes, checksum,
			                            scan_status, scan_engine, scanned_at)
			VALUES ($1,$2,$3,$4,'bundle.zip',$5,'application/zip','application/zip',1048576,$6,
			        'clean','clamav', now())`,
			p.AssetID, ids.NewPublic(ids.PrefixAsset), p.ID, p.VariantID,
			"products/"+p.PublicID+"/bundle.zip", cryptox.HashToken(p.PublicID)); err != nil {
			return err
		}
		if spec.Publish {
			if _, err := tx.Exec(ctx,
				`UPDATE products SET status = 'published', published_at = now() WHERE id = $1`, p.ID); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("fixtures: seed product: %v", err)
	}
	return p
}

// NewBuyer seeds a buyer account.
func NewBuyer(t *testing.T, ctx context.Context, d *db.DB, vault *identity.Vault, email string, stateCode int) ids.UUID {
	t.Helper()
	userID := ids.NewUUIDv7()
	// state_code is CHECKed to 1..99, so "unspecified" must be NULL rather
	// than zero. A buyer with no state is a real case: it is exactly what the
	// checkout path must refuse for a domestic order.
	var state any
	if stateCode > 0 {
		state = stateCode
	}
	err := d.InTx(ctx, db.TxOptions{Name: "fixture_buyer"}, func(ctx context.Context, tx db.Tx) error {
		dek, err := vault.IssueSubjectKey(ctx, tx, userID)
		if err != nil {
			return err
		}
		emailCT, err := vault.Encrypt(dek, userID, "email", email)
		if err != nil {
			return err
		}
		hash, err := cryptox.HashPassword("fixture-password-not-real", cryptox.TestArgon2idParams)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO users (id, public_id, email_index, email_ciphertext, email_domain,
			                   password_hash, country, tax_residence, state_code, email_verified_at)
			VALUES ($1,$2,$3,$4,'buyers.example.com',$5,'IN','IN',$6, now())`,
			userID, ids.NewPublic(ids.PrefixUser), vault.BlindIndex(email), emailCT, hash, state); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO user_roles (user_id, role_code) VALUES ($1,'buyer')`, userID)
		return err
	})
	if err != nil {
		t.Fatalf("fixtures: seed buyer: %v", err)
	}
	return userID
}

// TestVault builds a vault with a deterministic, obviously-test key.
func TestVault(t *testing.T) *identity.Vault {
	t.Helper()
	kek := make([]byte, 32)
	copy(kek, "test-kek-0123456789abcdef0123456789")
	v, err := identity.NewVault(kek)
	if err != nil {
		t.Fatalf("fixtures: vault: %v", err)
	}
	return v
}
