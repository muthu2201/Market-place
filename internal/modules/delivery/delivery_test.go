package delivery_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/muthu2201/market-place/internal/modules/delivery"
	"github.com/muthu2201/market-place/internal/platform/clock"
	"github.com/muthu2201/market-place/internal/platform/config"
	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/dbtest"
	"github.com/muthu2201/market-place/internal/platform/ids"
	"github.com/muthu2201/market-place/internal/platform/problem"
	"github.com/muthu2201/market-place/internal/storage"
	"github.com/muthu2201/market-place/internal/testsupport/fixtures"
)

type harness struct {
	db    *db.DB
	svc   *delivery.Service
	store storage.Store
	clk   *clock.Fixed
	ctx   context.Context
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	d := dbtest.Fresh(t)
	ctx := dbtest.Ctx(t)
	store, err := storage.NewFilesystem(t.TempDir(), clock.System())
	if err != nil {
		t.Fatal(err)
	}
	clk := clock.NewFixed(time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC))
	key := make([]byte, 32)
	copy(key, "download-sign-key-for-tests-0123")
	svc, err := delivery.NewService(delivery.Options{
		DB: d, Store: store, Clock: clk, SignKey: key,
		Platform: config.PlatformConfig{DownloadURLTTL: 10 * time.Minute, DownloadsPerLicense: 3},
		Metrics:  dbtest.Metrics(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{db: d, svc: svc, store: store, clk: clk, ctx: ctx}
}

// seedPurchase creates a seller, a product with a real stored file, a buyer and
// an issued licence, so the delivery path is exercised against real bytes.
func (h *harness) seedPurchase(t *testing.T, limit int) (licensePublicID, assetPublicID string, buyer ids.UUID, content []byte) {
	t.Helper()
	vault := fixtures.TestVault(t)
	seller := fixtures.NewSeller(t, h.ctx, h.db, vault, fixtures.DefaultSellerSpec("deliveryseller"))
	product := fixtures.NewProduct(t, h.ctx, h.db, seller, fixtures.ProductSpec{PriceMinor: 100000, Publish: true})
	buyer = fixtures.NewBuyer(t, h.ctx, h.db, vault, "dl@example.com", 33)

	content = bytes.Repeat([]byte("digital-asset-bytes-"), 64)
	var objectKey string
	if err := h.db.QueryRow(h.ctx,
		`SELECT object_key FROM product_assets WHERE id = $1`, product.AssetID).Scan(&objectKey); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.Put(h.ctx, storage.PutRequest{
		Key: objectKey, Body: bytes.NewReader(content), ContentType: "application/zip",
	}); err != nil {
		t.Fatal(err)
	}

	orderID := ids.NewUUIDv7()
	itemID := ids.NewUUIDv7()
	licenseID := ids.NewUUIDv7()
	licensePublicID = ids.NewPublic(ids.PrefixLicense)

	if err := h.db.InTx(h.ctx, db.TxOptions{Name: "seed_license"}, func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO orders (id, public_id, order_number, buyer_id, status, currency,
			                    items_subtotal_minor, tax_total_minor, grand_total_minor,
			                    place_of_supply_country, place_of_supply_state, paid_at)
			VALUES ($1,$2,$3,$4,'fulfilled','INR',100000,18000,118000,'IN',33, now())`,
			orderID, ids.NewPublic(ids.PrefixOrder), "ORD/2627/"+ids.Correlation(), buyer); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO order_items (id, public_id, order_id, product_id, variant_id, seller_id,
			                         title_snapshot, license_type_snapshot, license_terms_snapshot,
			                         refund_policy_snapshot, currency, unit_price_minor, line_total_minor,
			                         cgst_minor, sgst_minor, tax_total_minor, buyer_total_minor,
			                         commission_bps, commission_minor, commission_gst_minor, seller_net_minor, status)
			VALUES ($1,$2,$3,$4,$5,$6,'Test asset','commercial','Commercial licence.',
			        'no_refund_after_download','INR',100000,100000,9000,9000,18000,118000,900,9000,1620,106280,'fulfilled')`,
			itemID, ids.NewPublic(ids.PrefixOrderItem), orderID, product.ID, product.VariantID, seller.ID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO licenses (id, public_id, order_item_id, user_id, product_id, variant_id,
			                      license_type, terms_snapshot, download_limit)
			VALUES ($1,$2,$3,$4,$5,$6,'commercial','Commercial licence.',$7)`,
			licenseID, licensePublicID, itemID, buyer, product.ID, product.VariantID, limit)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	if err := h.db.QueryRow(h.ctx,
		`SELECT public_id FROM product_assets WHERE id = $1`, product.AssetID).Scan(&assetPublicID); err != nil {
		t.Fatal(err)
	}
	return licensePublicID, assetPublicID, buyer, content
}

func TestEntitledDownloadSucceedsAndCountsAgainstQuota(t *testing.T) {
	h := newHarness(t)
	lic, asset, buyer, content := h.seedPurchase(t, 3)

	ticket, err := h.svc.IssueTicket(h.ctx, buyer, lic, asset, "203.0.113.5")
	if err != nil {
		t.Fatalf("IssueTicket: %v", err)
	}
	if ticket.Direct {
		t.Fatal("the filesystem adapter cannot presign, so delivery must be served by the application")
	}
	if !strings.HasPrefix(ticket.URL, "/downloads/") || !strings.Contains(ticket.URL, "?t=") {
		t.Fatalf("unexpected ticket URL %q", ticket.URL)
	}

	grantID, nonce := splitTicket(t, ticket.URL)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, ticket.URL, nil)
	if err := h.svc.Redeem(h.ctx, rec, req, grantID, nonce); err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !bytes.Equal(rec.Body.Bytes(), content) {
		t.Fatal("the delivered bytes do not match what was stored")
	}
	// An uploaded HTML or SVG must never render on our origin.
	if ct := rec.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("Content-Type = %q; deliverables must always be forced to a download", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment;") {
		t.Fatalf("Content-Disposition = %q", cd)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("nosniff is required so a browser cannot re-interpret the bytes")
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("Cache-Control = %q; a short-lived single-use delivery must not be cached", cc)
	}

	var used int
	if err := h.db.QueryRow(h.ctx,
		`SELECT download_count FROM licenses WHERE public_id = $1`, lic).Scan(&used); err != nil {
		t.Fatal(err)
	}
	if used != 1 {
		t.Fatalf("download count = %d, want 1", used)
	}
	var outcome string
	var sent int64
	if err := h.db.QueryRow(h.ctx,
		`SELECT outcome, bytes_sent FROM download_events ORDER BY id DESC LIMIT 1`).Scan(&outcome, &sent); err != nil {
		t.Fatal(err)
	}
	if outcome != "served" || sent != int64(len(content)) {
		t.Fatalf("download evidence: outcome=%s bytes=%d", outcome, sent)
	}
}

// A ticket is a bearer token, so it must work exactly once.
func TestTicketIsSingleUse(t *testing.T) {
	h := newHarness(t)
	lic, asset, buyer, _ := h.seedPurchase(t, 5)

	ticket, err := h.svc.IssueTicket(h.ctx, buyer, lic, asset, "")
	if err != nil {
		t.Fatal(err)
	}
	grantID, nonce := splitTicket(t, ticket.URL)

	rec := httptest.NewRecorder()
	if err := h.svc.Redeem(h.ctx, rec, httptest.NewRequest(http.MethodGet, "/", nil), grantID, nonce); err != nil {
		t.Fatal(err)
	}
	rec2 := httptest.NewRecorder()
	if err := h.svc.Redeem(h.ctx, rec2, httptest.NewRequest(http.MethodGet, "/", nil), grantID, nonce); err == nil {
		t.Fatal("a leaked ticket must not be replayable")
	}
}

func TestTicketExpires(t *testing.T) {
	h := newHarness(t)
	lic, asset, buyer, _ := h.seedPurchase(t, 5)
	ticket, err := h.svc.IssueTicket(h.ctx, buyer, lic, asset, "")
	if err != nil {
		t.Fatal(err)
	}
	grantID, nonce := splitTicket(t, ticket.URL)

	h.clk.Advance(11 * time.Minute)
	rec := httptest.NewRecorder()
	if err := h.svc.Redeem(h.ctx, rec, httptest.NewRequest(http.MethodGet, "/", nil), grantID, nonce); err == nil {
		t.Fatal("an expired ticket must be refused")
	}
}

func TestForgedNonceIsRefused(t *testing.T) {
	h := newHarness(t)
	lic, asset, buyer, _ := h.seedPurchase(t, 5)
	ticket, err := h.svc.IssueTicket(h.ctx, buyer, lic, asset, "")
	if err != nil {
		t.Fatal(err)
	}
	grantID, _ := splitTicket(t, ticket.URL)

	for _, bad := range []string{
		strings.Repeat("A", 43),
		"", "short",
		"' OR 1=1 --" + strings.Repeat("x", 40),
	} {
		rec := httptest.NewRecorder()
		if err := h.svc.Redeem(h.ctx, rec, httptest.NewRequest(http.MethodGet, "/", nil), grantID, bad); err == nil {
			t.Fatalf("nonce %q must be refused", bad)
		}
	}
}

// The central authorisation test: another account must not be able to download
// someone else's purchase, however the request is shaped.
func TestAnotherAccountCannotDownload(t *testing.T) {
	h := newHarness(t)
	lic, asset, _, _ := h.seedPurchase(t, 5)
	attacker := fixtures.NewBuyer(t, h.ctx, h.db, fixtures.TestVault(t), "thief@example.com", 33)

	_, err := h.svc.IssueTicket(h.ctx, attacker, lic, asset, "198.51.100.9")
	if err == nil {
		t.Fatal("another account must not be able to obtain a ticket")
	}
	p := problem.As(err)
	if p == nil || p.Status != http.StatusForbidden {
		t.Fatalf("unexpected error: %v", err)
	}
	// The refusal must not reveal whether the licence exists.
	_, errUnknown := h.svc.IssueTicket(h.ctx, attacker, "lic_0000000000000000000000000", asset, "")
	pu := problem.As(errUnknown)
	if pu == nil || pu.Detail != p.Detail || pu.Status != p.Status {
		t.Fatalf("a probe for a non-existent licence must look identical:\n  %+v\n  %+v", p, pu)
	}
}

func TestAssetFromAnotherProductCannotBeReached(t *testing.T) {
	h := newHarness(t)
	lic, _, buyer, _ := h.seedPurchase(t, 5)

	// A second product the buyer has NOT purchased.
	vault := fixtures.TestVault(t)
	other := fixtures.NewSeller(t, h.ctx, h.db, vault, fixtures.DefaultSellerSpec("otherseller"))
	otherProduct := fixtures.NewProduct(t, h.ctx, h.db, other, fixtures.ProductSpec{PriceMinor: 500000, Publish: true})
	var otherAsset string
	if err := h.db.QueryRow(h.ctx,
		`SELECT public_id FROM product_assets WHERE id = $1`, otherProduct.AssetID).Scan(&otherAsset); err != nil {
		t.Fatal(err)
	}

	// A valid licence paired with an asset from a different product must fail.
	if _, err := h.svc.IssueTicket(h.ctx, buyer, lic, otherAsset, ""); err == nil {
		t.Fatal("a licence must not unlock an asset from a product it does not cover")
	}
}

func TestQuotaIsEnforced(t *testing.T) {
	h := newHarness(t)
	lic, asset, buyer, _ := h.seedPurchase(t, 2)

	for i := 0; i < 2; i++ {
		if _, err := h.svc.IssueTicket(h.ctx, buyer, lic, asset, ""); err != nil {
			t.Fatalf("download %d: %v", i+1, err)
		}
	}
	_, err := h.svc.IssueTicket(h.ctx, buyer, lic, asset, "")
	if err == nil {
		t.Fatal("the download allowance must be enforced")
	}
	if p := problem.As(err); p == nil || p.Type != problem.TypeDownloadExhausted {
		t.Fatalf("unexpected error: %v", err)
	}
	var denied int
	if err := h.db.QueryRow(h.ctx,
		`SELECT count(*) FROM download_events WHERE outcome = 'denied_limit'`).Scan(&denied); err != nil {
		t.Fatal(err)
	}
	if denied != 1 {
		t.Fatalf("a denial must be evidenced, found %d", denied)
	}
}

func TestRevokedLicenceCannotDownload(t *testing.T) {
	h := newHarness(t)
	lic, asset, buyer, _ := h.seedPurchase(t, 5)
	if _, err := h.db.Exec(h.ctx,
		`UPDATE licenses SET status = 'refunded' WHERE public_id = $1`, lic); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.IssueTicket(h.ctx, buyer, lic, asset, ""); err == nil {
		t.Fatal("a refunded licence must not download")
	}
}

func TestExpiredLicenceCannotDownload(t *testing.T) {
	h := newHarness(t)
	lic, asset, buyer, _ := h.seedPurchase(t, 5)
	if _, err := h.db.Exec(h.ctx,
		`UPDATE licenses SET access_expires_at = now() - INTERVAL '1 day' WHERE public_id = $1`, lic); err != nil {
		t.Fatal(err)
	}
	_, err := h.svc.IssueTicket(h.ctx, buyer, lic, asset, "")
	if err == nil {
		t.Fatal("an expired licence must not download")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("the message should explain the expiry: %v", err)
	}
}

// Two concurrent requests must not both consume the last allowance.
func TestQuotaIsRaceFree(t *testing.T) {
	h := newHarness(t)
	lic, asset, buyer, _ := h.seedPurchase(t, 5)

	const workers = 16
	results := make(chan error, workers)
	for i := 0; i < workers; i++ {
		go func() {
			_, err := h.svc.IssueTicket(h.ctx, buyer, lic, asset, "")
			results <- err
		}()
	}
	granted := 0
	for i := 0; i < workers; i++ {
		if err := <-results; err == nil {
			granted++
		}
	}
	if granted != 5 {
		t.Fatalf("%d tickets issued against an allowance of 5", granted)
	}
	var used int
	if err := h.db.QueryRow(h.ctx,
		`SELECT download_count FROM licenses WHERE public_id = $1`, lic).Scan(&used); err != nil {
		t.Fatal(err)
	}
	if used != 5 {
		t.Fatalf("download count = %d, want exactly 5", used)
	}
}

func TestListEntitlementsShowsOnlyYourOwn(t *testing.T) {
	h := newHarness(t)
	lic, _, buyer, _ := h.seedPurchase(t, 5)
	stranger := fixtures.NewBuyer(t, h.ctx, h.db, fixtures.TestVault(t), "stranger@example.com", 33)

	mine, err := h.svc.ListEntitlements(h.ctx, buyer, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(mine) != 1 || mine[0].LicensePublicID != lic {
		t.Fatalf("expected one entitlement, got %+v", mine)
	}
	if len(mine[0].Assets) != 1 {
		t.Fatalf("expected one downloadable asset, got %d", len(mine[0].Assets))
	}
	theirs, err := h.svc.ListEntitlements(h.ctx, stranger, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(theirs) != 0 {
		t.Fatal("another account must see nothing")
	}
}

func TestGrantCleanup(t *testing.T) {
	h := newHarness(t)
	lic, asset, buyer, _ := h.seedPurchase(t, 5)
	if _, err := h.svc.IssueTicket(h.ctx, buyer, lic, asset, ""); err != nil {
		t.Fatal(err)
	}
	// Age the whole grant, not just its expiry: the row constraint requires
	// expires_at to stay after issued_at.
	if _, err := h.db.Exec(h.ctx, `
		UPDATE download_grants
		   SET issued_at  = now() - INTERVAL '2 days' - INTERVAL '10 minutes',
		       expires_at = now() - INTERVAL '2 days'`); err != nil {
		t.Fatal(err)
	}
	n, err := h.svc.ExpireGrants(h.ctx, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("cleaned %d grants, want 1", n)
	}
}

func splitTicket(t *testing.T, url string) (grantID, nonce string) {
	t.Helper()
	path, query, ok := strings.Cut(url, "?t=")
	if !ok {
		t.Fatalf("malformed ticket URL %q", url)
	}
	return strings.TrimPrefix(path, "/downloads/"), query
}
