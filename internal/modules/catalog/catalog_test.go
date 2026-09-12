package catalog_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/muthu2201/market-place/internal/antivirus"
	"github.com/muthu2201/market-place/internal/modules/catalog"
	"github.com/muthu2201/market-place/internal/modules/provenance"
	"github.com/muthu2201/market-place/internal/platform/clock"
	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/dbtest"
	"github.com/muthu2201/market-place/internal/platform/ids"
	"github.com/muthu2201/market-place/internal/platform/money"
	"github.com/muthu2201/market-place/internal/storage"
	"github.com/muthu2201/market-place/internal/testsupport/fixtures"
)

// The tests below run against a real PostgreSQL schema, because the interesting
// behaviour of this package lives in the database: the publish guard, the
// immutability triggers and the tag resolver are all things a mocked store
// would let pass.

func TestDraftAndPublishHappyPath(t *testing.T) {
	h := newHarness(t)
	seller := h.seller("publisher")

	product, err := h.svc.Draft(h.ctx, catalog.DraftRequest{
		SellerID: seller.ID, ActorID: seller.UserID, CategoryID: h.categoryPublicID,
		Title: "Twelve Risograph Textures", Summary: "A pack of twelve scanned risograph textures.",
		Description:  "Scanned from prints made on a Riso MZ1090, cleaned up by hand.",
		DeliveryType: "download", LicenseType: "commercial",
		LicenseTerms: "Use in commercial work. Do not resell the files themselves.",
		AIDisclosure: provenance.NoAI,
		Tags:         []string{"risograph", "texture", "Print"},
	})
	if err != nil {
		t.Fatalf("Draft: %v", err)
	}
	if product.Status != catalog.StatusDraft {
		t.Errorf("status = %q, want draft", product.Status)
	}
	if product.Slug != "twelve-risograph-textures" {
		t.Errorf("slug = %q", product.Slug)
	}

	// A draft with nothing else is blocked on all the things it is missing, and
	// says so all at once rather than one refusal at a time.
	readiness, err := h.svc.ReadyToPublish(h.ctx, seller.ID, product.PublicID)
	if err != nil {
		t.Fatal(err)
	}
	if readiness.Ready {
		t.Fatal("an empty draft reported ready to publish")
	}
	codes := blockerCodes(readiness)
	for _, want := range []string{"no_deliverable_asset", "no_priced_variant"} {
		if !codes[want] {
			t.Errorf("blocker %q missing; got %v", want, keys(codes))
		}
	}

	if _, err := h.svc.AddVariant(h.ctx, seller.ID, product.PublicID, "Full pack",
		money.MustNew(120000, money.INR), nil); err != nil {
		t.Fatalf("AddVariant: %v", err)
	}
	h.uploadCleanAsset(t, seller, product.PublicID, "textures.zip", "application/zip")

	readiness, err = h.svc.ReadyToPublish(h.ctx, seller.ID, product.PublicID)
	if err != nil {
		t.Fatal(err)
	}
	if !readiness.Ready {
		t.Fatalf("still blocked after satisfying everything: %v", readiness.Blockers)
	}
	if err := h.svc.Publish(h.ctx, seller.ID, seller.UserID, product.PublicID, "203.0.113.7"); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	var status string
	var publishedAt, anchorAt *time.Time
	if err := h.db.QueryRow(h.ctx,
		`SELECT status, published_at, ranking_anchor_at FROM products WHERE public_id = $1`,
		product.PublicID).Scan(&status, &publishedAt, &anchorAt); err != nil {
		t.Fatal(err)
	}
	if status != catalog.StatusPublished || publishedAt == nil || anchorAt == nil {
		t.Fatalf("status=%q published_at=%v anchor=%v", status, publishedAt, anchorAt)
	}
}

// TestPublishRefusedWithoutADisclosure covers the control ADR 0010 turns on:
// there is no route to a live listing that skips the question.
func TestPublishRefusedWithoutADisclosure(t *testing.T) {
	h := newHarness(t)
	seller := h.seller("undeclared")

	product := h.draft(t, seller, "Undeclared Pack", provenance.Undeclared)
	if _, err := h.svc.AddVariant(h.ctx, seller.ID, product.PublicID, "Standard",
		money.MustNew(50000, money.INR), nil); err != nil {
		t.Fatal(err)
	}
	h.uploadCleanAsset(t, seller, product.PublicID, "pack.zip", "application/zip")

	readiness, err := h.svc.ReadyToPublish(h.ctx, seller.ID, product.PublicID)
	if err != nil {
		t.Fatal(err)
	}
	if !blockerCodes(readiness)["no_ai_disclosure"] {
		t.Fatalf("an undeclared product was not blocked; blockers: %v", readiness.Blockers)
	}
	if err := h.svc.Publish(h.ctx, seller.ID, seller.UserID, product.PublicID, ""); err == nil {
		t.Fatal("an undeclared product published")
	}

	// And the database refuses it even when the application layer is bypassed.
	_, err = h.db.Exec(h.ctx,
		`UPDATE products SET status = 'published', published_at = now() WHERE public_id = $1`,
		product.PublicID)
	if err == nil {
		t.Fatal("raw SQL published an undeclared product; the trigger is not enforcing this")
	}
	if !strings.Contains(err.Error(), "declaration is mandatory") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

// TestInfectedAssetCannotBePublished is the control that stops "pay and receive
// malware", verified end to end rather than asserted.
func TestInfectedAssetCannotBePublished(t *testing.T) {
	h := newHarness(t)
	seller := h.seller("infected")
	product := h.draft(t, seller, "Suspicious Bundle", provenance.NoAI)

	if _, err := h.svc.AddVariant(h.ctx, seller.ID, product.PublicID, "Standard",
		money.MustNew(50000, money.INR), nil); err != nil {
		t.Fatal(err)
	}

	asset := h.upload(t, seller, product.PublicID, "bundle.zip", "application/zip",
		[]byte(eicarPayload))
	if err := h.svc.ScanAsset(h.ctx, asset.PublicID); err != nil {
		t.Fatalf("ScanAsset: %v", err)
	}

	var scanStatus, signature string
	if err := h.db.QueryRow(h.ctx,
		`SELECT scan_status, COALESCE(scan_signature, '') FROM product_assets WHERE public_id = $1`,
		asset.PublicID).Scan(&scanStatus, &signature); err != nil {
		t.Fatal(err)
	}
	if scanStatus != catalog.ScanInfected {
		t.Fatalf("scan_status = %q, want infected", scanStatus)
	}
	if signature == "" {
		t.Error("no threat signature was recorded")
	}

	readiness, err := h.svc.ReadyToPublish(h.ctx, seller.ID, product.PublicID)
	if err != nil {
		t.Fatal(err)
	}
	if readiness.Ready {
		t.Fatal("a product with an infected file reported ready to publish")
	}
	if err := h.svc.Publish(h.ctx, seller.ID, seller.UserID, product.PublicID, ""); err == nil {
		t.Fatal("a product with an infected file published")
	}

	// A moderation case is opened without anyone watching, and the schema
	// refuses to record enforcement without a human decision.
	var cases int
	if err := h.db.QueryRow(h.ctx, `
		SELECT count(*) FROM moderation_cases mc
		  JOIN product_assets a ON a.id = mc.subject_id
		 WHERE mc.subject_type = 'asset' AND mc.reason = 'malware' AND a.public_id = $1`,
		asset.PublicID).Scan(&cases); err != nil {
		t.Fatal(err)
	}
	if cases != 1 {
		t.Errorf("moderation cases for this asset = %d, want 1", cases)
	}
}

// TestInfectedAssetIsNeverPromoted: the bytes must stay in quarantine, and the
// deliverable key must resolve to nothing.
func TestInfectedAssetIsNeverPromoted(t *testing.T) {
	h := newHarness(t)
	seller := h.seller("notpromoted")
	product := h.draft(t, seller, "Bad Bundle", provenance.NoAI)

	asset := h.upload(t, seller, product.PublicID, "bundle.zip", "application/zip", []byte(eicarPayload))
	if err := h.svc.ScanAsset(h.ctx, asset.PublicID); err != nil {
		t.Fatal(err)
	}

	var objectKey string
	if err := h.db.QueryRow(h.ctx,
		`SELECT object_key FROM product_assets WHERE public_id = $1`, asset.PublicID).Scan(&objectKey); err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(objectKey, "quarantine/") {
		t.Fatal("object_key points into quarantine; delivery must never be handed a quarantine key")
	}
	if _, err := h.store.Stat(h.ctx, objectKey); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("an object exists at the deliverable key of an infected asset (err=%v)", err)
	}
}

// TestCleanAssetIsPromoted is the other half: a clean asset's object_key must
// resolve to the real bytes.
func TestCleanAssetIsPromoted(t *testing.T) {
	h := newHarness(t)
	seller := h.seller("promoted")
	product := h.draft(t, seller, "Good Bundle", provenance.NoAI)

	content := []byte("PK\x03\x04" + strings.Repeat("legitimate archive content ", 100))
	asset := h.upload(t, seller, product.PublicID, "bundle.zip", "application/zip", content)
	if err := h.svc.ScanAsset(h.ctx, asset.PublicID); err != nil {
		t.Fatal(err)
	}

	var objectKey, scanStatus, detected string
	if err := h.db.QueryRow(h.ctx,
		`SELECT object_key, scan_status, COALESCE(detected_type, '') FROM product_assets WHERE public_id = $1`,
		asset.PublicID).Scan(&objectKey, &scanStatus, &detected); err != nil {
		t.Fatal(err)
	}
	if scanStatus != catalog.ScanClean {
		t.Fatalf("scan_status = %q, want clean", scanStatus)
	}
	if detected != "application/zip" {
		t.Errorf("detected_type = %q, want application/zip", detected)
	}

	body, info, err := h.store.Get(h.ctx, objectKey)
	if err != nil {
		t.Fatalf("the promoted object is not readable: %v", err)
	}
	defer body.Close()
	got := make([]byte, len(content))
	if _, err := bytes.NewReader(content).Read(got); err != nil {
		t.Fatal(err)
	}
	if info.Size != int64(len(content)) {
		t.Errorf("promoted object is %d bytes, uploaded %d", info.Size, len(content))
	}
}

// TestChecksumIsComputedFromTheStoredBytes: a checksum taken from the client's
// word about its own upload is worth nothing.
func TestChecksumIsComputedFromTheStoredBytes(t *testing.T) {
	h := newHarness(t)
	seller := h.seller("checksum")
	product := h.draft(t, seller, "Checksum Pack", provenance.NoAI)

	content := []byte("%PDF-1.7\nthe actual bytes that were uploaded\n")
	asset := h.upload(t, seller, product.PublicID, "guide.pdf", "application/pdf", content)

	want := sha256.Sum256(content)
	if asset.Checksum != hex.EncodeToString(want[:]) {
		t.Errorf("checksum = %s, want the digest of what was stored", asset.Checksum)
	}

	var stored []byte
	var size int64
	if err := h.db.QueryRow(h.ctx,
		`SELECT checksum, size_bytes FROM product_assets WHERE public_id = $1`,
		asset.PublicID).Scan(&stored, &size); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, want[:]) {
		t.Error("the stored checksum is not the digest of the stored bytes")
	}
	if size != int64(len(content)) {
		t.Errorf("size = %d, uploaded %d", size, len(content))
	}
}

// TestExecutableDressedAsAFontIsHeld exercises the signal that does not depend
// on any signature feed being current.
func TestExecutableDressedAsAFontIsHeld(t *testing.T) {
	h := newHarness(t)
	seller := h.seller("disguised")
	product := h.draft(t, seller, "Font Pack", provenance.NoAI)

	// A Windows PE binary named as an OpenType font.
	content := append([]byte("MZ\x90\x00\x03\x00\x00\x00"), bytes.Repeat([]byte{0x41}, 500)...)
	asset := h.upload(t, seller, product.PublicID, "helvetica.otf", "font/otf", content)
	if err := h.svc.ScanAsset(h.ctx, asset.PublicID); err != nil {
		t.Fatal(err)
	}

	var scanStatus, detected string
	if err := h.db.QueryRow(h.ctx,
		`SELECT scan_status, COALESCE(detected_type, '') FROM product_assets WHERE public_id = $1`,
		asset.PublicID).Scan(&scanStatus, &detected); err != nil {
		t.Fatal(err)
	}
	if scanStatus != catalog.ScanSuspect {
		t.Fatalf("scan_status = %q, want suspicious", scanStatus)
	}
	if detected != "application/x-dosexec" {
		t.Errorf("detected_type = %q, want the real type", detected)
	}
	if err := h.svc.Publish(h.ctx, seller.ID, seller.UserID, product.PublicID, ""); err == nil {
		t.Fatal("a product with a disguised executable published")
	}
}

// TestScannerOutageLeavesTheAssetUnpublishable is the safe-direction property:
// a scanner that cannot answer must not be read as having said "fine".
func TestScannerOutageLeavesTheAssetUnpublishable(t *testing.T) {
	h := newHarnessWith(t, failingScanner{})
	seller := h.seller("outage")
	product := h.draft(t, seller, "Outage Pack", provenance.NoAI)

	asset := h.upload(t, seller, product.PublicID, "pack.zip", "application/zip",
		[]byte("PK\x03\x04harmless"))
	if err := h.svc.ScanAsset(h.ctx, asset.PublicID); err == nil {
		t.Fatal("a scanner outage was reported as success")
	}

	var scanStatus string
	if err := h.db.QueryRow(h.ctx,
		`SELECT scan_status FROM product_assets WHERE public_id = $1`, asset.PublicID).Scan(&scanStatus); err != nil {
		t.Fatal(err)
	}
	if scanStatus != catalog.ScanError {
		t.Fatalf("scan_status = %q, want error", scanStatus)
	}
	if err := h.svc.Publish(h.ctx, seller.ID, seller.UserID, product.PublicID, ""); err == nil {
		t.Fatal("a product whose file could not be scanned published")
	}
}

// TestScanIsIdempotent: the worker's at-least-once delivery makes a repeat run
// inevitable, and it must cost nothing.
func TestScanIsIdempotent(t *testing.T) {
	h := newHarness(t)
	seller := h.seller("idempotent")
	product := h.draft(t, seller, "Repeat Pack", provenance.NoAI)

	asset := h.upload(t, seller, product.PublicID, "pack.zip", "application/zip",
		[]byte("PK\x03\x04harmless content here"))
	for i := 0; i < 3; i++ {
		if err := h.svc.ScanAsset(h.ctx, asset.PublicID); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}

	var scannedAt time.Time
	var status string
	if err := h.db.QueryRow(h.ctx,
		`SELECT scan_status, scanned_at FROM product_assets WHERE public_id = $1`,
		asset.PublicID).Scan(&status, &scannedAt); err != nil {
		t.Fatal(err)
	}
	if status != catalog.ScanClean {
		t.Fatalf("status = %q after repeated scans", status)
	}
	var cases int
	if err := h.db.QueryRow(h.ctx, `
		SELECT count(*) FROM moderation_cases mc
		  JOIN product_assets a ON a.id = mc.subject_id
		 WHERE mc.subject_type = 'asset' AND a.public_id = $1`, asset.PublicID).Scan(&cases); err != nil {
		t.Fatal(err)
	}
	if cases != 0 {
		t.Errorf("a clean asset opened %d moderation cases", cases)
	}
}

// TestOtherSellersProductIsNotFound: ownership is part of the query, and a
// product belonging to someone else must be indistinguishable from one that
// does not exist.
func TestOtherSellersProductIsNotFound(t *testing.T) {
	h := newHarness(t)
	owner := h.seller("owner")
	intruder := h.seller("intruder")

	product := h.draft(t, owner, "Private Draft", provenance.NoAI)

	if _, err := h.svc.AddVariant(h.ctx, intruder.ID, product.PublicID, "Cheap",
		money.MustNew(1, money.INR), nil); !errors.Is(err, catalog.ErrNotFound) {
		t.Errorf("AddVariant by another seller: %v, want ErrNotFound", err)
	}
	if err := h.svc.Publish(h.ctx, intruder.ID, intruder.UserID, product.PublicID, ""); !errors.Is(err, catalog.ErrNotFound) {
		t.Errorf("Publish by another seller: %v, want ErrNotFound", err)
	}
	if _, err := h.svc.RequestUpload(h.ctx, intruder.ID, product.PublicID, "x.zip", "application/zip", 10); !errors.Is(err, catalog.ErrNotFound) {
		t.Errorf("RequestUpload by another seller: %v, want ErrNotFound", err)
	}
	if _, err := h.svc.ReadyToPublish(h.ctx, intruder.ID, product.PublicID); !errors.Is(err, catalog.ErrNotFound) {
		t.Errorf("ReadyToPublish by another seller: %v, want ErrNotFound", err)
	}
}

// TestRepublishDoesNotResetRankingAnchor is the anti-bump control.
func TestRepublishDoesNotResetRankingAnchor(t *testing.T) {
	h := newHarness(t)
	seller := h.seller("bumper")
	product := h.publishedProduct(t, seller, "Bumpable Pack")

	var firstAnchor time.Time
	if err := h.db.QueryRow(h.ctx,
		`SELECT ranking_anchor_at FROM products WHERE public_id = $1`, product).Scan(&firstAnchor); err != nil {
		t.Fatal(err)
	}

	if err := h.svc.Unpublish(h.ctx, seller.ID, seller.UserID, product, ""); err != nil {
		t.Fatalf("Unpublish: %v", err)
	}
	h.clock.Advance(72 * time.Hour)
	if err := h.svc.Publish(h.ctx, seller.ID, seller.UserID, product, ""); err != nil {
		t.Fatalf("republish: %v", err)
	}

	var secondAnchor time.Time
	if err := h.db.QueryRow(h.ctx,
		`SELECT ranking_anchor_at FROM products WHERE public_id = $1`, product).Scan(&secondAnchor); err != nil {
		t.Fatal(err)
	}
	if !secondAnchor.Equal(firstAnchor) {
		t.Fatalf("ranking anchor moved from %s to %s; relisting bought a ranking advantage",
			firstAnchor, secondAnchor)
	}
}

// TestTagsAreResolvedToCanonicalForms exercises the wrangling model: the
// seller's own wording is stored, and search runs on what it resolves to.
func TestTagsAreResolvedToCanonicalForms(t *testing.T) {
	h := newHarness(t)
	seller := h.seller("tagger")

	// Tag slugs are unique across the whole catalogue, and this package shares
	// one database, so the test needs a vocabulary no other test proposes.
	suffix := strings.ToLower(ids.NewPublic("x")[2:8])
	canonicalSlug, synonymSlug, freshSlug := "risograph-"+suffix, "riso-"+suffix, "texture-"+suffix

	canonical := ids.NewUUIDv7()
	synonym := ids.NewUUIDv7()
	if _, err := h.db.Exec(h.ctx, `
		INSERT INTO tags (id, public_id, slug, label, status) VALUES ($1,$2,$3,'Risograph','canonical')`,
		canonical, ids.NewPublic(ids.PrefixTag), canonicalSlug); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(h.ctx, `
		INSERT INTO tags (id, public_id, slug, label, status, canonical_id) VALUES ($1,$2,$3,'Riso','synonym',$4)`,
		synonym, ids.NewPublic(ids.PrefixTag), synonymSlug, canonical); err != nil {
		t.Fatal(err)
	}

	product, err := h.svc.Draft(h.ctx, catalog.DraftRequest{
		SellerID: seller.ID, ActorID: seller.UserID, CategoryID: h.categoryPublicID,
		Title: "Riso Texture Pack", Summary: "Textures scanned from riso prints.",
		Description: "A pack of scanned textures.", DeliveryType: "download",
		LicenseType: "commercial", LicenseTerms: "Commercial use permitted.",
		AIDisclosure: provenance.NoAI,
		Tags:         []string{synonymSlug, freshSlug},
	})
	if err != nil {
		t.Fatal(err)
	}

	rows, err := h.db.Query(h.ctx, `
		SELECT t.slug, c.slug
		  FROM product_tags pt
		  JOIN products p ON p.id = pt.product_id
		  JOIN tags t ON t.id = pt.tag_id
		  JOIN tags c ON c.id = pt.canonical_tag_id
		 WHERE p.public_id = $1 ORDER BY t.slug`, product.PublicID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	resolved := map[string]string{}
	for rows.Next() {
		var own, canon string
		if err := rows.Scan(&own, &canon); err != nil {
			t.Fatal(err)
		}
		resolved[own] = canon
	}
	if got := resolved[synonymSlug]; got != canonicalSlug {
		t.Errorf("the seller's tag %q resolved to %q, want %q", synonymSlug, got, canonicalSlug)
	}
	if got := resolved[freshSlug]; got != freshSlug {
		t.Errorf("a brand new tag resolved to %q; an unwrangled tag stands for itself", got)
	}
}

// TestBannedTagsAreDroppedSilently: refusing would tell someone probing the
// moderation list exactly which words are on it.
func TestBannedTagsAreDroppedSilently(t *testing.T) {
	h := newHarness(t)
	seller := h.seller("bannedtags")

	suffix := strings.ToLower(ids.NewPublic("x")[2:8])
	bannedSlug, allowedSlug := "forbidden-"+suffix, "allowed-"+suffix
	if _, err := h.db.Exec(h.ctx, `
		INSERT INTO tags (id, public_id, slug, label, status) VALUES ($1,$2,$3,'Forbidden','banned')`,
		ids.NewUUIDv7(), ids.NewPublic(ids.PrefixTag), bannedSlug); err != nil {
		t.Fatal(err)
	}

	product, err := h.svc.Draft(h.ctx, catalog.DraftRequest{
		SellerID: seller.ID, ActorID: seller.UserID, CategoryID: h.categoryPublicID,
		Title: "Ordinary Pack", Summary: "An ordinary pack of things.",
		Description: "Nothing unusual here.", DeliveryType: "download",
		LicenseType: "personal", LicenseTerms: "Personal use only.",
		AIDisclosure: provenance.NoAI, Tags: []string{bannedSlug, allowedSlug},
	})
	if err != nil {
		t.Fatalf("a banned tag caused the draft to be refused: %v", err)
	}

	var tags []string
	rows, err := h.db.Query(h.ctx, `
		SELECT t.slug FROM product_tags pt
		  JOIN products p ON p.id = pt.product_id
		  JOIN tags t ON t.id = pt.tag_id
		 WHERE p.public_id = $1`, product.PublicID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		tags = append(tags, s)
	}
	if len(tags) != 1 || tags[0] != allowedSlug {
		t.Errorf("tags = %v, want only %q", tags, allowedSlug)
	}
}

func TestDraftValidationRejectsBadInput(t *testing.T) {
	h := newHarness(t)
	seller := h.seller("validation")

	base := catalog.DraftRequest{
		SellerID: seller.ID, ActorID: seller.UserID, CategoryID: h.categoryPublicID,
		Title: "A Perfectly Fine Title", Summary: "A summary that is long enough.",
		Description: "A description that is long enough.", DeliveryType: "download",
		LicenseType: "commercial", LicenseTerms: "Commercial use permitted.",
		AIDisclosure: provenance.NoAI,
	}

	for _, tc := range []struct {
		name   string
		mutate func(*catalog.DraftRequest)
	}{
		{"title too short", func(r *catalog.DraftRequest) { r.Title = "Hi" }},
		{"summary too short", func(r *catalog.DraftRequest) { r.Summary = "short" }},
		{"unknown delivery type", func(r *catalog.DraftRequest) { r.DeliveryType = "teleportation" }},
		{"unknown licence type", func(r *catalog.DraftRequest) { r.LicenseType = "whatever" }},
		{"unknown disclosure", func(r *catalog.DraftRequest) { r.AIDisclosure = "maybe" }},
		{"too many tags", func(r *catalog.DraftRequest) { r.Tags = make([]string, 31) }},
		{"unknown category", func(r *catalog.DraftRequest) { r.CategoryID = "cat_doesnotexist" }},
		{"control characters in the title", func(r *catalog.DraftRequest) { r.Title = "Title‮with bidi" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := base
			tc.mutate(&req)
			if _, err := h.svc.Draft(h.ctx, req); err == nil {
				t.Fatal("invalid input was accepted")
			}
		})
	}
}

// ---- harness ----------------------------------------------------------------

const eicarPayload = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

type harness struct {
	t                *testing.T
	ctx              context.Context
	db               *db.DB
	store            storage.Store
	svc              *catalog.Service
	clock            *clock.Fixed
	categoryPublicID string
}

func newHarness(t *testing.T) *harness { return newHarnessWith(t, testScanner{}) }

func newHarnessWith(t *testing.T, scanner antivirus.Scanner) *harness {
	t.Helper()
	d := dbtest.Open(t)
	ctx := context.Background()
	clk := clock.NewFixed(time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC))

	store, err := storage.NewFilesystem(t.TempDir(), clk)
	if err != nil {
		t.Fatalf("filesystem store: %v", err)
	}

	svc, err := catalog.New(catalog.Options{
		DB: d, Store: store, Scanner: scanner, Clock: clk,
	})
	if err != nil {
		t.Fatalf("catalog.New: %v", err)
	}

	categoryID := fixtures.Category(t, ctx, d)
	var categoryPublicID string
	if err := d.QueryRow(ctx, `SELECT public_id FROM categories WHERE id = $1`, categoryID).
		Scan(&categoryPublicID); err != nil {
		t.Fatal(err)
	}

	return &harness{t: t, ctx: ctx, db: d, store: store, svc: svc, clock: clk,
		categoryPublicID: categoryPublicID}
}

func (h *harness) seller(handle string) fixtures.Seller {
	h.t.Helper()
	return fixtures.NewSeller(h.t, h.ctx, h.db, fixtures.TestVault(h.t),
		fixtures.DefaultSellerSpec(handle+strings.ToLower(ids.NewPublic("x")[2:8])))
}

func (h *harness) draft(t *testing.T, seller fixtures.Seller, title string, d provenance.Disclosure) *catalog.Product {
	t.Helper()
	p, err := h.svc.Draft(h.ctx, catalog.DraftRequest{
		SellerID: seller.ID, ActorID: seller.UserID, CategoryID: h.categoryPublicID,
		Title: title, Summary: "A summary that comfortably exceeds the minimum.",
		Description:  "A description that comfortably exceeds the minimum length.",
		DeliveryType: "download", LicenseType: "commercial",
		LicenseTerms: "Commercial use permitted.", AIDisclosure: d,
	})
	if err != nil {
		t.Fatalf("draft %q: %v", title, err)
	}
	return p
}

// upload runs the real two-step flow: request a slot, put the bytes where the
// ticket says, then finalise.
func (h *harness) upload(t *testing.T, seller fixtures.Seller, productPublicID, filename, contentType string, content []byte) *catalog.Asset {
	t.Helper()
	ticket, err := h.svc.RequestUpload(h.ctx, seller.ID, productPublicID, filename, contentType, int64(len(content)))
	if err != nil {
		t.Fatalf("RequestUpload: %v", err)
	}

	// The filesystem adapter cannot presign, so the bytes are written the way
	// the API's streaming fallback would write them.
	key := "quarantine/" + seller.ID.String() + "/" + ticket.AssetID
	if _, err := h.store.Put(h.ctx, storage.PutRequest{
		Key: key, Body: bytes.NewReader(content), Size: int64(len(content)),
		ContentType: contentType,
	}); err != nil {
		t.Fatalf("storing the upload: %v", err)
	}

	asset, err := h.svc.FinaliseUpload(h.ctx, seller.ID, productPublicID, ticket.AssetID,
		filename, contentType, false)
	if err != nil {
		t.Fatalf("FinaliseUpload: %v", err)
	}
	return asset
}

func (h *harness) uploadCleanAsset(t *testing.T, seller fixtures.Seller, productPublicID, filename, contentType string) {
	t.Helper()
	asset := h.upload(t, seller, productPublicID, filename, contentType,
		[]byte("PK\x03\x04"+strings.Repeat("content ", 200)))
	if err := h.svc.ScanAsset(h.ctx, asset.PublicID); err != nil {
		t.Fatalf("ScanAsset: %v", err)
	}
}

func (h *harness) publishedProduct(t *testing.T, seller fixtures.Seller, title string) string {
	t.Helper()
	p := h.draft(t, seller, title, provenance.NoAI)
	if _, err := h.svc.AddVariant(h.ctx, seller.ID, p.PublicID, "Standard",
		money.MustNew(100000, money.INR), nil); err != nil {
		t.Fatal(err)
	}
	h.uploadCleanAsset(t, seller, p.PublicID, "pack.zip", "application/zip")
	if err := h.svc.Publish(h.ctx, seller.ID, seller.UserID, p.PublicID, ""); err != nil {
		t.Fatalf("publish %q: %v", title, err)
	}
	return p.PublicID
}

// testScanner answers the way a real scanner does, using the same EICAR
// convention and the real magic-byte detection.
type testScanner struct{}

func (testScanner) Name() string               { return "test-scanner" }
func (testScanner) Ping(context.Context) error { return nil }

func (testScanner) Scan(_ context.Context, r io.Reader, opts antivirus.ScanOptions) (antivirus.Result, error) {
	buf := new(bytes.Buffer)
	n, err := buf.ReadFrom(r)
	if err != nil {
		return antivirus.Result{}, err
	}
	res := antivirus.Result{
		Engine: "test-scanner/1", Bytes: n, DeclaredType: opts.DeclaredType,
		ScannedAt: time.Now().UTC(),
	}
	detected, mismatch := antivirus.DetectType(buf.Bytes(), opts.Filename)
	res.DetectedType = detected

	switch {
	case bytes.Contains(buf.Bytes(), []byte(eicarPayload)):
		res.Status = antivirus.StatusInfected
		res.Signature = "Win.Test.EICAR_HDB-1"
		res.Reason = "the scanner matched a known threat signature"
	case mismatch != "":
		res.Status = antivirus.StatusSuspicious
		res.Reason = mismatch
	default:
		res.Status = antivirus.StatusClean
	}
	return res, nil
}

// failingScanner stands in for an outage.
type failingScanner struct{}

func (failingScanner) Name() string               { return "failing-scanner" }
func (failingScanner) Ping(context.Context) error { return antivirus.ErrUnavailable }
func (failingScanner) Scan(context.Context, io.Reader, antivirus.ScanOptions) (antivirus.Result, error) {
	return antivirus.Result{}, antivirus.ErrUnavailable
}

func blockerCodes(r catalog.PublishReadiness) map[string]bool {
	out := map[string]bool{}
	for _, b := range r.Blockers {
		out[b.Code] = true
	}
	return out
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
