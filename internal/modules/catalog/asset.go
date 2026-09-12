package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/muthu2201/market-place/internal/antivirus"
	"github.com/muthu2201/market-place/internal/modules/audit"
	"github.com/muthu2201/market-place/internal/modules/provenance"
	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/ids"
	"github.com/muthu2201/market-place/internal/platform/problem"
	"github.com/muthu2201/market-place/internal/storage"
)

// Asset is one file a buyer receives.
type Asset struct {
	ID           ids.UUID
	PublicID     string
	Filename     string
	ContentType  string
	DetectedType string
	SizeBytes    int64
	Checksum     string
	ScanStatus   string
	ScanEngine   string
	ScanDetail   string
	IsPreview    bool
}

// UploadTicket is what a seller needs to put bytes somewhere.
type UploadTicket struct {
	AssetID   string
	URL       string
	Method    string
	ExpiresAt time.Time
	MaxBytes  int64
	// Direct is false when the adapter cannot presign, in which case the seller
	// uploads through the API instead.
	Direct bool
	// Headers the client must send for the signature to match.
	Headers map[string]string
}

// RequestUpload returns somewhere for a seller to put bytes.
//
// It deliberately creates no database row. `product_assets` freezes
// `object_key`, `checksum` and `size_bytes` on UPDATE — correctly, since those
// three are what identify the bytes a buyer paid for — so none of them may be
// written as a placeholder and corrected later. The row is created at
// finalisation, from what actually arrived.
//
// The upload lands under the quarantine prefix, and the row's `object_key` will
// name the *deliverable* key, which nothing writes to until the asset scans
// clean. So an unscanned asset does not merely carry an unsafe flag: its object
// key points at nothing, and delivery would fail to find an object rather than
// serve one that was never scanned.
func (s *Service) RequestUpload(ctx context.Context, sellerID ids.UUID, productPublicID, filename, contentType string, size int64) (*UploadTicket, error) {
	if err := validateUploadRequest(filename, contentType, size, s.maxAssetBytes); err != nil {
		return nil, err
	}

	// Ownership is established before a URL is issued, so an upload slot can
	// never be obtained for somebody else's product.
	var status string
	err := s.db.QueryRow(ctx,
		`SELECT status FROM products WHERE public_id = $1 AND seller_id = $2`,
		productPublicID, sellerID).Scan(&status)
	if err != nil {
		return nil, ErrNotFound
	}
	if status == StatusArchived || status == StatusSuspended {
		return nil, fmt.Errorf("%w: a %s product cannot take new files", ErrNotEditable, status)
	}

	assetID := ids.NewUUIDv7()
	key := quarantineKey(sellerID, assetID)

	ticket := &UploadTicket{
		AssetID: assetID.String(), Method: "PUT",
		ExpiresAt: s.clk.Now().Add(s.uploadTTL), MaxBytes: s.maxAssetBytes,
		Headers: map[string]string{"Content-Type": contentType},
	}
	url, err := s.store.PresignPut(ctx, key, s.uploadTTL, contentType, s.maxAssetBytes)
	switch {
	case err == nil:
		ticket.URL, ticket.Direct = url, true
	case errors.Is(err, storage.ErrPresignUnsupported):
		// The single-node development adapter. The API streams the body
		// through instead, which is why this is not an error.
		ticket.URL = "/api/v1/seller/uploads/" + assetID.String()
	default:
		return nil, err
	}
	return ticket, nil
}

// FinaliseUpload creates the asset row from the bytes that actually arrived,
// and queues them for scanning.
//
// The size and the checksum are read back from the object store rather than
// taken from the client. A row that recorded what the client *said* it uploaded
// would be a row that says nothing: the whole value of the checksum is that a
// buyer can verify the download against it.
func (s *Service) FinaliseUpload(ctx context.Context, sellerID ids.UUID, productPublicID, assetID, filename, contentType string, isPreview bool) (*Asset, error) {
	if err := validateUploadRequest(filename, contentType, 1, s.maxAssetBytes); err != nil {
		return nil, err
	}
	uploadID, err := ids.ParseUUID(assetID)
	if err != nil {
		return nil, ErrNotFound
	}

	// The key is derived from THIS seller's ID, so a seller cannot finalise an
	// upload made under another seller's prefix: the key they would have to
	// name does not exist under theirs.
	key := quarantineKey(sellerID, uploadID)

	info, err := s.store.Stat(ctx, key)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, problem.Conflict("", "We have not received this file yet. Complete the upload, then try again.")
		}
		return nil, err
	}
	switch {
	case info.Size <= 0:
		return nil, problem.Conflict("", "The uploaded file is empty.")
	case info.Size > s.maxAssetBytes:
		return nil, problem.Conflict("", fmt.Sprintf("The uploaded file is larger than the %d byte limit.", s.maxAssetBytes))
	}

	// The checksum is computed over the stored bytes. Streaming rather than
	// buffering, so the digest of a 2 GiB asset costs one 32 KiB window.
	checksum, err := s.checksumObject(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("catalog: checksumming the upload: %w", err)
	}

	publicID := ids.NewPublic(ids.PrefixAsset)
	out := &Asset{
		ID: uploadID, PublicID: publicID, Filename: filename, ContentType: contentType,
		SizeBytes: info.Size, Checksum: hex.EncodeToString(checksum),
		ScanStatus: ScanPending, IsPreview: isPreview,
	}

	err = s.db.InTx(ctx, db.TxOptions{Name: "catalog_finalise_upload"}, func(ctx context.Context, tx db.Tx) error {
		productID, status, err := s.ownedProduct(ctx, tx, sellerID, productPublicID)
		if err != nil {
			return err
		}
		if status == StatusArchived || status == StatusSuspended {
			return fmt.Errorf("%w: a %s product cannot take new files", ErrNotEditable, status)
		}

		// object_key names the DELIVERABLE location, which nothing writes to
		// until this asset scans clean. Until then the key resolves to no
		// object at all, so an unscanned asset cannot be served even if every
		// other control were bypassed.
		_, err = tx.Exec(ctx, `
			INSERT INTO product_assets (
				id, public_id, product_id, filename, object_key, content_type,
				size_bytes, checksum, scan_status, is_preview, position
			)
			SELECT $1, $2, $3, $4, $5, $6, $7, $8, 'pending', $9,
			       COALESCE((SELECT MAX(position) + 1 FROM product_assets WHERE product_id = $3), 0)`,
			uploadID, publicID, productID, filename, deliverableKey(sellerID, uploadID), contentType,
			info.Size, checksum, isPreview)
		if err != nil {
			return fmt.Errorf("catalog: recording the asset: %w", err)
		}

		// Enqueue rather than scan inline. Scanning a large asset takes
		// minutes, and a seller's HTTP request is not the place to spend them.
		// The partial unique index makes a duplicate enqueue a no-op.
		_, err = tx.Exec(ctx, `
			INSERT INTO jobs (id, kind, unique_key, payload, run_at)
			VALUES ($1, 'scan_asset', $2, $3::jsonb, now())
			ON CONFLICT (unique_key) WHERE unique_key IS NOT NULL
			  AND completed_at IS NULL AND failed_at IS NULL DO NOTHING`,
			ids.NewUUIDv7(), "scan_asset:"+publicID,
			fmt.Sprintf(`{"asset_public_id":%q}`, publicID))
		if err != nil {
			return fmt.Errorf("catalog: queueing the scan: %w", err)
		}

		return s.audit.Record(ctx, tx, audit.Event{
			ActorKind: audit.ActorSeller, Action: "catalog.asset.uploaded",
			SubjectType: "asset", SubjectID: publicID,
			Metadata: map[string]any{
				"filename": filename, "size_bytes": info.Size,
				"checksum": hex.EncodeToString(checksum),
			},
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// checksumObject streams the stored object through SHA-256.
func (s *Service) checksumObject(ctx context.Context, key string) ([]byte, error) {
	body, _, err := s.store.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	defer func() { _ = body.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(body, s.maxAssetBytes+1)); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// ScanAsset reads an asset back from quarantine, scans it, gathers provenance
// signals, and promotes it if it is clean.
//
// Called by the worker. It is idempotent: an asset already in a terminal state
// is left alone, so a duplicated job or a retried one costs a no-op.
func (s *Service) ScanAsset(ctx context.Context, assetPublicID string) error {
	var (
		assetID     ids.UUID
		productID   ids.UUID
		sellerID    ids.UUID
		filename    string
		contentType string
		size        int64
		disclosure  string
		status      string
	)
	err := s.db.QueryRow(ctx, `
		SELECT a.id, a.product_id, p.seller_id, a.filename,
		       a.content_type, a.size_bytes, p.ai_disclosure, a.scan_status
		  FROM product_assets a JOIN products p ON p.id = a.product_id
		 WHERE a.public_id = $1`, assetPublicID,
	).Scan(&assetID, &productID, &sellerID, &filename, &contentType, &size, &disclosure, &status)
	if err != nil {
		return fmt.Errorf("catalog: asset %s not found: %w", assetPublicID, err)
	}
	if status != ScanPending && status != ScanScanning && status != ScanError {
		return nil // already decided
	}

	if _, err := s.db.Exec(ctx,
		`UPDATE product_assets SET scan_status = 'scanning' WHERE id = $1 AND scan_status IN ('pending','error')`,
		assetID); err != nil {
		return err
	}

	// The bytes are read from quarantine. The row's object_key names where they
	// will live once clean, and nothing has written there yet.
	source := quarantineKey(sellerID, assetID)
	a, err := s.analyse(ctx, source, filename, contentType, size)
	if err != nil {
		// The scan could not be completed. Recording 'error' leaves the asset
		// unpublishable, which is the safe direction: a scanner outage becomes
		// a backlog rather than a stream of unscanned downloads.
		s.log.Warn("asset scan failed", "asset", assetPublicID, "error", err)
		_, updateErr := s.db.Exec(ctx, `
			UPDATE product_assets SET scan_status = 'error', scan_engine = $2, scanned_at = $3
			 WHERE id = $1`, assetID, s.scanner.Name(), s.clk.Now())
		return errors.Join(err, updateErr)
	}

	if a.scan.Status == antivirus.StatusClean {
		// Promote out of quarantine BEFORE marking clean. If the copy fails,
		// the asset stays unpublishable and the job retries; the other order
		// would leave a row claiming to be deliverable with nothing behind it.
		if err := s.store.Copy(ctx, source, deliverableKey(sellerID, assetID)); err != nil {
			return fmt.Errorf("catalog: promoting %s out of quarantine: %w", assetPublicID, err)
		}
	}

	return s.db.InTx(ctx, db.TxOptions{Name: "catalog_record_scan"}, func(ctx context.Context, tx db.Tx) error {
		if err := s.recordAnalysis(ctx, tx, assetID, a); err != nil {
			return err
		}
		if err := s.refreshProductProvenance(ctx, tx, productID, provenance.Disclosure(disclosure)); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, audit.Event{
			ActorKind: audit.ActorSystem, Action: "catalog.asset.scanned",
			SubjectType: "asset", SubjectID: assetPublicID,
			Metadata: map[string]any{
				"status": string(a.scan.Status), "engine": a.scan.Engine,
				"signature": a.scan.Signature, "detected_type": a.scan.DetectedType,
			},
		}); err != nil {
			return err
		}
		// An infected upload is a trust-and-safety matter, not a validation
		// error, and the case is opened whether or not anyone is watching.
		if a.scan.Status == antivirus.StatusInfected || a.scan.Status == antivirus.StatusSuspicious {
			return s.openModerationCase(ctx, tx, assetID, a)
		}
		return nil
	})
}

// analyse runs the scanner and the provenance extractors over one object.
//
// The object is read twice, deliberately. Scanning streams it so a 2 GiB asset
// never lands in memory; provenance needs the leading bytes in one piece and the
// whole file only for the C2PA hard binding, which is capped. Two bounded reads
// beat one unbounded buffer.
func (s *Service) analyse(ctx context.Context, key, filename, contentType string, size int64) (assessment, error) {
	var a assessment

	body, _, err := s.store.Get(ctx, key)
	if err != nil {
		return a, fmt.Errorf("reading the uploaded object: %w", err)
	}
	a.scan, err = s.scanner.Scan(ctx, body, antivirus.ScanOptions{
		Filename: filename, DeclaredType: contentType, Size: size,
	})
	_ = body.Close()
	if err != nil {
		return a, err
	}

	// Provenance is only gathered for an asset that is not malware. Parsing
	// containers inside a known-infected file is work with no upside.
	if a.scan.Status == antivirus.StatusInfected {
		return a, nil
	}

	head, err := s.readBounded(ctx, key, maxProvenanceBytes)
	if err != nil {
		a.signals.Notes = append(a.signals.Notes,
			"provenance signals could not be gathered: "+err.Error())
		return a, nil
	}

	a.signals.C2PAPresent, a.signals.C2PAIntact, a.signals.C2PABindingValid,
		a.signals.C2PAIssuer, a.signals.C2PAGenerator = c2paFields(head)
	a.signals.GeneratorHint, a.signals.GeneratorHintIndicatesAI = provenance.GeneratorHint(head)

	switch {
	case strings.HasPrefix(a.scan.DetectedType, "image/"):
		if h, err := provenance.PerceptualHash(strings.NewReader(string(head))); err == nil {
			a.signals.PerceptualHash = h
		}
	case strings.HasPrefix(a.scan.DetectedType, "text/"), a.scan.DetectedType == "application/xml":
		if h, err := provenance.SimHash(strings.NewReader(string(head))); err == nil {
			a.signals.SimHash = h
		}
	}
	return a, nil
}

// maxProvenanceBytes bounds what provenance extraction reads into memory.
//
// C2PA manifests live at the head of a file and perceptual hashing needs a
// decodable image; neither benefits from the tail of a 2 GiB archive, and
// reading one would turn every upload into a memory incident.
const maxProvenanceBytes = 32 << 20

func (s *Service) readBounded(ctx context.Context, key string, limit int64) ([]byte, error) {
	body, _, err := s.store.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	defer func() { _ = body.Close() }()
	return io.ReadAll(io.LimitReader(body, limit))
}

func c2paFields(head []byte) (present, intact, binding bool, issuer, generator string) {
	r := provenance.ExtractC2PA(head)
	return r.Present, r.Intact, r.BindingValid, r.Issuer, r.Generator
}

// recordAnalysis writes both results in one statement, so a partial write
// cannot leave the scan verdict and the provenance signals disagreeing.
func (s *Service) recordAnalysis(ctx context.Context, tx db.Tx, assetID ids.UUID, a assessment) error {
	_, err := tx.Exec(ctx, `
		UPDATE product_assets SET
			scan_status = $2, scan_engine = $3, scan_signature = $4, scanned_at = $5,
			detected_type = $6,
			c2pa_present = $7, c2pa_valid = $8, c2pa_issuer = $9, generator_hint = $10,
			perceptual_hash = $11, simhash = $12
		 WHERE id = $1`,
		assetID, string(a.scan.Status), a.scan.Engine, nullIfEmpty(a.scan.Signature), s.clk.Now(),
		nullIfEmpty(a.scan.DetectedType),
		a.signals.C2PAPresent, c2paValidity(a.signals), nullIfEmpty(a.signals.C2PAIssuer),
		nullIfEmpty(a.signals.GeneratorHint),
		nullableHash(a.signals.PerceptualHash), nullableHash(a.signals.SimHash))
	return err
}

// c2paValidity maps to the nullable c2pa_valid column.
//
// NULL means "present but not evaluated", which is a genuinely different state
// from "evaluated and failed", and the schema models it that way for a reason.
func c2paValidity(s provenance.Signals) any {
	if !s.C2PAPresent {
		return nil
	}
	return s.C2PAIntact && s.C2PABindingValid
}

func nullableHash(h uint64) any {
	if h == 0 {
		return nil
	}
	// The column is BIGINT; the top bit is preserved by the two's-complement
	// reinterpretation and comparisons are on equality and Hamming distance,
	// both of which are bit operations that do not care about the sign.
	return int64(h)
}

// refreshProductProvenance recomputes the product's routing from its assets.
func (s *Service) refreshProductProvenance(ctx context.Context, tx db.Tx, productID ids.UUID, disclosure provenance.Disclosure) error {
	var sig provenance.Signals
	rows, err := tx.Query(ctx, `
		SELECT c2pa_present, COALESCE(c2pa_valid, FALSE), COALESCE(generator_hint, '')
		  FROM product_assets WHERE product_id = $1 AND NOT is_preview`, productID)
	if err != nil {
		return err
	}
	var filenames []string
	for rows.Next() {
		var present, valid bool
		var hint string
		if err := rows.Scan(&present, &valid, &hint); err != nil {
			rows.Close()
			return err
		}
		// Across a multi-file upload, the strongest evidence on any one file
		// speaks for the product: a layered source file beside a flattened
		// export is evidence about the work, not about that one export.
		sig.C2PAPresent = sig.C2PAPresent || present
		sig.C2PAIntact = sig.C2PAIntact || valid
		sig.C2PABindingValid = sig.C2PABindingValid || valid
		if hint != "" && sig.GeneratorHint == "" {
			sig.GeneratorHint, sig.GeneratorHintIndicatesAI = hint, false
		}
		if hint != "" {
			if _, ai := provenance.GeneratorHint([]byte("<xmp:CreatorTool>" + hint + "</xmp:CreatorTool>")); ai {
				sig.GeneratorHintIndicatesAI = true
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	nameRows, err := tx.Query(ctx, `SELECT filename FROM product_assets WHERE product_id = $1`, productID)
	if err != nil {
		return err
	}
	for nameRows.Next() {
		var f string
		if err := nameRows.Scan(&f); err != nil {
			nameRows.Close()
			return err
		}
		filenames = append(filenames, f)
	}
	nameRows.Close()
	if err := nameRows.Err(); err != nil {
		return err
	}
	sig.HasSourceProject, sig.SourceProjectKinds = provenance.DetectSourceProjects(filenames)

	a := provenance.Assess(disclosure, sig)
	_, err = tx.Exec(ctx, `
		UPDATE products SET provenance_score = $2, requires_human_review = $3
		 WHERE id = $1`,
		productID, a.Score, a.Routing != provenance.RoutePublish)
	return err
}

// openModerationCase records a case for a human.
//
// The schema requires a human decision before any enforcement — `status =
// action_taken` demands a decided_by and a decided_at — so this opens a case
// and nothing more. That constraint is the reason a detector here can never
// become a ban by itself.
func (s *Service) openModerationCase(ctx context.Context, tx db.Tx, assetID ids.UUID, a assessment) error {
	reason, severity := "provenance_risk", 50
	if a.scan.Status == antivirus.StatusInfected {
		reason, severity = "malware", 100
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO moderation_cases (id, public_id, subject_type, subject_id, reason, severity, signals)
		VALUES ($1, $2, 'asset', $3, $4, $5, $6::jsonb)`,
		ids.NewUUIDv7(), ids.NewPublic("mod"), assetID, reason, severity,
		fmt.Sprintf(`{"scan_status":%q,"signature":%q,"detected_type":%q,"reason":%q}`,
			a.scan.Status, a.scan.Signature, a.scan.DetectedType, a.scan.Reason))
	return err
}

func validateUploadRequest(filename, contentType string, size, maxBytes int64) error {
	switch {
	case strings.TrimSpace(filename) == "":
		return problem.Validation(problem.FieldError{
			Field: "filename", Code: "required", Detail: "A filename is required."})
	case len(filename) > 255:
		return problem.Validation(problem.FieldError{
			Field: "filename", Code: "too_long", Detail: "Filenames are limited to 255 characters."})
	case strings.ContainsAny(filename, "/\\\x00"):
		// The filename never reaches an object key — keys derive entirely from
		// server-generated identifiers — but it does reach a Content-Disposition
		// header, and a separator there is a header-injection primitive.
		return problem.Validation(problem.FieldError{
			Field: "filename", Code: "invalid", Detail: "A filename cannot contain slashes."})
	case len(contentType) < 3 || len(contentType) > 255:
		return problem.Validation(problem.FieldError{
			Field: "content_type", Code: "invalid", Detail: "Declare the file's content type."})
	case size <= 0:
		return problem.Validation(problem.FieldError{
			Field: "size", Code: "invalid", Detail: "Declare the file's size in bytes."})
	case size > maxBytes:
		return problem.Validation(problem.FieldError{
			Field: "size", Code: "too_large",
			Detail: fmt.Sprintf("Files are limited to %d bytes.", maxBytes)})
	}
	return nil
}
