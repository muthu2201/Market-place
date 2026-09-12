// Command seed populates a database with realistic catalogue data.
//
// It is used to bring up a demonstration environment and to give the load
// harness something to buy. It writes through the same constraints production
// uses, so seeded data is data the real system would have accepted.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/muthu2201/market-place/internal/modules/identity"
	"github.com/muthu2201/market-place/internal/platform/clock"
	"github.com/muthu2201/market-place/internal/platform/config"
	"github.com/muthu2201/market-place/internal/platform/cryptox"
	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/ids"
	"github.com/muthu2201/market-place/internal/platform/metrics"
	"github.com/muthu2201/market-place/internal/storage"
)

func main() {
	sellers := flag.Int("sellers", 5, "number of sellers to create")
	products := flag.Int("products", 40, "number of products to create")
	providerPrefix := flag.String("provider-account-prefix", "acc_seed_", "prefix for simulated linked-account ids")
	writeAssets := flag.Bool("write-assets", true, "write placeholder asset bytes to object storage")
	flag.Parse()

	if err := run(*sellers, *products, *providerPrefix, *writeAssets); err != nil {
		fmt.Fprintln(os.Stderr, "seed:", err)
		os.Exit(1)
	}
}

func run(sellerCount, productCount int, providerPrefix string, writeAssets bool) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if cfg.Env.IsProduction() {
		// Seeding a production database with synthetic sellers would corrupt
		// tax returns and settlement. There is no flag to override this.
		return fmt.Errorf("refusing to seed a production environment")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	registry := metrics.NewRegistry()
	database, err := db.Open(ctx, cfg.Database, metrics.NewApp(registry))
	if err != nil {
		return err
	}
	defer database.Close()

	vault, err := identity.NewVault(cfg.Security.DataKEK)
	if err != nil {
		return err
	}

	var store storage.Store
	if writeAssets {
		if cfg.Storage.Driver == "s3" {
			store, err = storage.NewS3(cfg.Storage, clock.System())
		} else {
			store, err = storage.NewFilesystem(cfg.Storage.LocalRoot, clock.System())
		}
		if err != nil {
			return err
		}
	}

	categoryID, err := ensureCategory(ctx, database)
	if err != nil {
		return err
	}

	type seeded struct {
		id     ids.UUID
		handle string
	}
	var sellers []seeded

	for i := 0; i < sellerCount; i++ {
		handle := fmt.Sprintf("studio%02d", i+1)
		id, err := ensureSeller(ctx, database, vault, handle, providerPrefix+handle, 33+(i%5))
		if err != nil {
			return fmt.Errorf("seller %s: %w", handle, err)
		}
		sellers = append(sellers, seeded{id: id, handle: handle})
		fmt.Printf("seller  %s\n", handle)
	}

	titles := []string{
		"Vector icon pack", "Lightroom preset bundle", "Notion productivity template",
		"Figma design system", "Lo-fi sample pack", "Blender material library",
		"Tamil typography set", "Invoice template for freelancers", "3D product mockups",
		"Stock photo collection", "After Effects title pack", "GST filing spreadsheet",
	}
	prices := []int64{19900, 49900, 99900, 149900, 249900, 499900, 999900}

	for i := 0; i < productCount; i++ {
		seller := sellers[i%len(sellers)]
		title := fmt.Sprintf("%s %02d", titles[i%len(titles)], i+1)
		slug := strings.ToLower(strings.ReplaceAll(title, " ", "-"))
		price := prices[i%len(prices)]

		key, err := ensureProduct(ctx, database, seller.id, categoryID, slug, title, price)
		if err != nil {
			return fmt.Errorf("product %s: %w", slug, err)
		}
		if writeAssets && store != nil && key != "" {
			content := bytes.Repeat([]byte(title+" payload. "), 512)
			sum := sha256.Sum256(content)
			if _, err := store.Put(ctx, storage.PutRequest{
				Key: key, Body: bytes.NewReader(content), ContentType: "application/zip",
				Size: int64(len(content)), ChecksumSHA256: sum[:],
			}); err != nil {
				return fmt.Errorf("write asset %s: %w", key, err)
			}
		}
	}
	fmt.Printf("\nseeded %d sellers and %d products\n", len(sellers), productCount)
	return nil
}

func ensureCategory(ctx context.Context, database *db.DB) (ids.UUID, error) {
	var id ids.UUID
	err := database.QueryRow(ctx, `SELECT id FROM categories WHERE slug = 'digital-assets'`).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !db.IsNoRows(err) {
		return id, err
	}
	id = ids.NewUUIDv7()
	_, err = database.Exec(ctx, `
		INSERT INTO categories (id, public_id, slug, name, description, path, depth, sac_code)
		VALUES ($1,$2,'digital-assets','Digital assets',
		        'Downloadable design, audio, video and document assets.','digital-assets',0,'998434')`,
		id, ids.NewPublic(ids.PrefixCategory))
	return id, err
}

func ensureSeller(ctx context.Context, database *db.DB, vault *identity.Vault, handle, providerAccount string, stateCode int) (ids.UUID, error) {
	var existing ids.UUID
	err := database.QueryRow(ctx, `SELECT id FROM sellers WHERE handle = $1`, handle).Scan(&existing)
	if err == nil {
		return existing, nil
	}
	if !db.IsNoRows(err) {
		return existing, err
	}

	userID := ids.NewUUIDv7()
	sellerID := ids.NewUUIDv7()
	email := handle + "@sellers.example.com"
	pan := panFor(handle)
	gstin := gstinFor(stateCode, pan)

	err = database.InTx(ctx, db.TxOptions{Name: "seed_seller"}, func(ctx context.Context, tx db.Tx) error {
		dek, err := vault.IssueSubjectKey(ctx, tx, userID)
		if err != nil {
			return err
		}
		emailCT, err := vault.Encrypt(dek, userID, "email", email)
		if err != nil {
			return err
		}
		hash, err := cryptox.HashPassword("seed-account-not-for-production", cryptox.TestArgon2idParams)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO users (id, public_id, email_index, email_ciphertext, email_domain,
			                   password_hash, country, tax_residence, state_code, email_verified_at)
			VALUES ($1,$2,$3,$4,'sellers.example.com',$5,'IN','IN',$6, now())`,
			userID, ids.NewPublic(ids.PrefixUser), vault.BlindIndex(email), emailCT, hash, stateCode); err != nil {
			return err
		}
		for _, role := range []string{"buyer", "seller"} {
			if _, err := tx.Exec(ctx,
				`INSERT INTO user_roles (user_id, role_code) VALUES ($1,$2)`, userID, role); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO sellers (id, public_id, user_id, handle, display_name, entity_type,
			                     country, state_code, pan, gstin, gst_registered,
			                     kyc_status, kyc_verified_at, provider, provider_account_id,
			                     provider_account_status, provider_account_activated_at,
			                     settlement_hold_days, status)
			VALUES ($1,$2,$3,$4,$5,'private_limited','IN',$6,$7,$8,TRUE,'verified',now(),
			        'razorpay_route',$9,'activated',now(),14,'active')`,
			sellerID, ids.NewPublic(ids.PrefixSeller), userID, handle,
			"Studio "+strings.ToUpper(handle[:1])+handle[1:], stateCode, pan, gstin, providerAccount); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO seller_payout_accounts (id, seller_id, account_ciphertext, ifsc, account_last4,
			                                    fingerprint, validation_status, validation_method,
			                                    validated_at, name_match_score, is_default, active_from)
			VALUES ($1,$2,$3,'HDFC0001234','7890',$4,'validated','penny_drop',now(),100,TRUE,
			        now() - INTERVAL '3 days')`,
			ids.NewUUIDv7(), sellerID, []byte("seeded-account"), cryptox.HashToken("seed:"+handle)); err != nil {
			return err
		}
		var scheduleID ids.UUID
		if err := tx.QueryRow(ctx,
			`SELECT id FROM fee_schedules ORDER BY effective_from LIMIT 1`).Scan(&scheduleID); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO seller_fee_assignments (seller_id, fee_schedule_id, effective_from)
			VALUES ($1,$2, now() - INTERVAL '1 day')`, sellerID, scheduleID)
		return err
	})
	return sellerID, err
}

func ensureProduct(ctx context.Context, database *db.DB, sellerID, categoryID ids.UUID, slug, title string, priceMinor int64) (objectKey string, err error) {
	var existing ids.UUID
	err = database.QueryRow(ctx,
		`SELECT id FROM products WHERE seller_id = $1 AND slug = $2`, sellerID, slug).Scan(&existing)
	if err == nil {
		return "", nil
	}
	if !db.IsNoRows(err) {
		return "", err
	}

	productID := ids.NewUUIDv7()
	productPublic := ids.NewPublic(ids.PrefixProduct)
	objectKey = "products/" + productPublic + "/bundle.zip"

	err = database.InTx(ctx, db.TxOptions{Name: "seed_product"}, func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO products (id, public_id, seller_id, category_id, slug, title, summary, description,
			                      delivery_type, license_type, license_terms, status, ai_disclosure,
			                      refund_policy)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'download','commercial',$9,'draft','no_ai',
			        'no_refund_after_download')`,
			productID, productPublic, sellerID, categoryID, slug, title,
			"A professionally produced "+strings.ToLower(title)+" for commercial use.",
			"This bundle contains layered source files, exported assets in common formats, "+
				"and a short guide to using them. Commercial use is permitted under the licence terms; "+
				"redistribution of the source files is not.",
			"Commercial use permitted, including in client work. Redistribution or resale of the "+
				"source files, on their own or as part of a competing bundle, is not permitted."); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO product_variants (id, public_id, product_id, name, price_minor, currency)
			VALUES ($1,$2,$3,'Standard licence',$4,'INR')`,
			ids.NewUUIDv7(), ids.NewPublic(ids.PrefixVariant), productID, priceMinor); err != nil {
			return err
		}
		// A preview satisfies the ranking quality gate and lets a buyer inspect
		// before purchase.
		if _, err := tx.Exec(ctx, `
			INSERT INTO product_assets (id, public_id, product_id, filename, object_key, content_type,
			                            detected_type, size_bytes, checksum, scan_status, scan_engine,
			                            scanned_at, is_preview)
			VALUES ($1,$2,$3,'preview.webp',$4,'image/webp','image/webp',20480,$5,'clean','clamav',now(),TRUE)`,
			ids.NewUUIDv7(), ids.NewPublic(ids.PrefixAsset), productID,
			"previews/"+productPublic+"/preview.webp", cryptox.HashToken("preview:"+productPublic)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO product_assets (id, public_id, product_id, filename, object_key, content_type,
			                            detected_type, size_bytes, checksum, scan_status, scan_engine, scanned_at)
			VALUES ($1,$2,$3,'bundle.zip',$4,'application/zip','application/zip',5242880,$5,'clean','clamav',now())`,
			ids.NewUUIDv7(), ids.NewPublic(ids.PrefixAsset), productID, objectKey,
			cryptox.HashToken("bundle:"+productPublic)); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`UPDATE products SET status = 'published', published_at = now() WHERE id = $1`, productID)
		return err
	})
	if err != nil {
		return "", err
	}
	return objectKey, nil
}

const b36 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

func panFor(handle string) string {
	h := sha256.Sum256([]byte("pan:" + handle))
	letters := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
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

// gstinFor produces a GSTIN with a correct check character, so seeded sellers
// survive the same validation a live registration would.
func gstinFor(stateCode int, pan string) string {
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
	return body + string(b36[(36-(sum%36))%36])
}
