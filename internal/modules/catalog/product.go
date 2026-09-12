package catalog

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/muthu2201/market-place/internal/modules/audit"
	"github.com/muthu2201/market-place/internal/modules/provenance"
	"github.com/muthu2201/market-place/internal/outbox"
	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/ids"
	"github.com/muthu2201/market-place/internal/platform/money"
	"github.com/muthu2201/market-place/internal/platform/problem"
	"github.com/muthu2201/market-place/internal/platform/validate"
)

// DraftRequest is a new product.
type DraftRequest struct {
	SellerID    ids.UUID
	ActorID     ids.UUID
	CategoryID  string // public ID
	Title       string
	Summary     string
	Description string

	DeliveryType        string
	LicenseType         string
	LicenseTerms        string
	LicenseDurationDays *int

	AIDisclosure     provenance.Disclosure
	AIDisclosureNote string
	RefundPolicy     string

	Tags []string
	IP   string
}

// Product is a seller-facing view of a listing.
type Product struct {
	ID         ids.UUID
	PublicID   string
	SellerID   ids.UUID
	Slug       string
	Title      string
	Status     string
	Disclosure provenance.Disclosure
	CreatedAt  string
	Variants   []Variant
	Assets     []Asset
	Tags       []string
}

// Variant is a priced, purchasable option.
type Variant struct {
	ID       ids.UUID
	PublicID string
	Name     string
	Price    money.Money
	MaxSales *int
	Active   bool
	Position int
}

// Draft creates a product in draft state.
//
// Nothing here is published, priced or deliverable yet: a draft is a place to
// put the description while the files upload. The four publish preconditions
// are checked at publication, not here, so a seller can build a listing in the
// order that suits them rather than the order the constraints happen to be in.
func (s *Service) Draft(ctx context.Context, req DraftRequest) (*Product, error) {
	if err := validateDraft(&req); err != nil {
		return nil, err
	}

	id := ids.NewUUIDv7()
	publicID := ids.NewPublic(ids.PrefixProduct)
	var out *Product

	err := s.db.InTx(ctx, db.TxOptions{Name: "catalog_draft"}, func(ctx context.Context, tx db.Tx) error {
		var categoryID ids.UUID
		err := tx.QueryRow(ctx,
			`SELECT id FROM categories WHERE public_id = $1 AND active`, req.CategoryID).Scan(&categoryID)
		if err != nil {
			return problem.Validation(problem.FieldError{
				Field: "category_id", Code: "unknown",
				Detail: "That is not a category products can be listed in.",
			})
		}

		slug, err := s.uniqueSlug(ctx, tx, req.SellerID, req.Title)
		if err != nil {
			return err
		}

		_, err = tx.Exec(ctx, `
			INSERT INTO products (
				id, public_id, seller_id, category_id, slug, title, summary, description,
				delivery_type, license_type, license_terms, license_duration_days,
				ai_disclosure, ai_disclosure_note, refund_policy, status
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'draft')`,
			id, publicID, req.SellerID, categoryID, slug, req.Title, req.Summary, req.Description,
			req.DeliveryType, req.LicenseType, req.LicenseTerms, req.LicenseDurationDays,
			string(req.AIDisclosure), nullIfEmpty(req.AIDisclosureNote), req.RefundPolicy)
		if err != nil {
			return fmt.Errorf("catalog: inserting the product: %w", err)
		}

		if err := s.applyTags(ctx, tx, id, req.Tags); err != nil {
			return err
		}

		if err := s.audit.Record(ctx, tx, audit.Event{
			Action: "catalog.product.drafted", ActorID: &req.ActorID,
			SubjectType: "product", SubjectID: publicID, ActorIP: req.IP,
			ActorKind: audit.ActorSeller,
			Metadata:  map[string]any{"title": req.Title, "disclosure": string(req.AIDisclosure)},
		}); err != nil {
			return err
		}

		out = &Product{
			ID: id, PublicID: publicID, SellerID: req.SellerID, Slug: slug,
			Title: req.Title, Status: StatusDraft, Disclosure: req.AIDisclosure,
		}
		return nil
	})
	return out, err
}

// AddVariant prices an option on a draft.
func (s *Service) AddVariant(ctx context.Context, sellerID ids.UUID, productPublicID, name string, price money.Money, maxSales *int) (*Variant, error) {
	if strings.TrimSpace(name) == "" {
		return nil, problem.Validation(problem.FieldError{
			Field: "name", Code: "required", Detail: "Give this option a name buyers will understand."})
	}
	if price.IsNegative() {
		return nil, problem.Validation(problem.FieldError{
			Field: "price", Code: "invalid", Detail: "A price cannot be negative."})
	}
	if maxSales != nil && *maxSales <= 0 {
		return nil, problem.Validation(problem.FieldError{
			Field: "max_sales", Code: "invalid", Detail: "A sales limit must be at least one."})
	}

	id := ids.NewUUIDv7()
	publicID := ids.NewPublic(ids.PrefixVariant)
	var out *Variant

	err := s.db.InTx(ctx, db.TxOptions{Name: "catalog_add_variant"}, func(ctx context.Context, tx db.Tx) error {
		productID, status, err := s.ownedProduct(ctx, tx, sellerID, productPublicID)
		if err != nil {
			return err
		}
		if status != StatusDraft && status != StatusPublished {
			return fmt.Errorf("%w: a %s product cannot be repriced", ErrNotEditable, status)
		}

		// Position is allocated from the existing rows in the same statement,
		// so two options added concurrently cannot take the same slot.
		_, err = tx.Exec(ctx, `
			INSERT INTO product_variants (id, public_id, product_id, name, price_minor, currency, max_sales, position)
			SELECT $1, $2, $3, $4, $5, $6, $7, COALESCE(MAX(position) + 1, 0)
			  FROM product_variants WHERE product_id = $3`,
			id, publicID, productID, name, price.Minor(), string(price.Currency()), maxSales)
		if err != nil {
			return fmt.Errorf("catalog: inserting the variant: %w", err)
		}

		out = &Variant{ID: id, PublicID: publicID, Name: name, Price: price, MaxSales: maxSales, Active: true}
		return nil
	})
	return out, err
}

// ReadyToPublish reports whether a product can go live, and what is missing.
//
// This exists so the seller sees every unmet condition at once, before they
// press publish, rather than discovering them one refusal at a time. The
// database trigger remains the authority — this is a courtesy, and it is
// written to stay in step with the trigger's four checks.
func (s *Service) ReadyToPublish(ctx context.Context, sellerID ids.UUID, productPublicID string) (PublishReadiness, error) {
	var r PublishReadiness

	var (
		disclosure                   string
		deliveryType                 string
		cleanAssets, unscannedAssets int
		activeVariants               int
		sellerActive, kycVerified    bool
		status                       string
	)
	err := s.db.QueryRow(ctx, `
		SELECT p.ai_disclosure, p.delivery_type, p.status,
		       (SELECT count(*) FROM product_assets a
		          WHERE a.product_id = p.id AND NOT a.is_preview AND a.scan_status = 'clean'),
		       (SELECT count(*) FROM product_assets a
		          WHERE a.product_id = p.id AND NOT a.is_preview
		            AND a.scan_status IN ('pending','scanning','infected','suspicious','error')),
		       (SELECT count(*) FROM product_variants v WHERE v.product_id = p.id AND v.active),
		       s.status = 'active', s.kyc_status = 'verified'
		  FROM products p JOIN sellers s ON s.id = p.seller_id
		 WHERE p.public_id = $1 AND p.seller_id = $2`,
		productPublicID, sellerID,
	).Scan(&disclosure, &deliveryType, &status, &cleanAssets, &unscannedAssets,
		&activeVariants, &sellerActive, &kycVerified)
	if err != nil {
		return r, ErrNotFound
	}

	if deliveryType == "download" && cleanAssets == 0 {
		r.Blockers = append(r.Blockers, PublishBlocker{
			Code: "no_deliverable_asset", Fixable: true,
			Detail: "Upload at least one file for buyers to download.",
		})
	}
	if unscannedAssets > 0 {
		r.Blockers = append(r.Blockers, PublishBlocker{
			Code: "assets_not_clean", Fixable: true,
			Detail: fmt.Sprintf(
				"%d file(s) are still being scanned or did not pass. Scanning usually takes a few minutes; "+
					"a file that fails is listed with the reason on the files tab.", unscannedAssets),
		})
	}
	if provenance.Disclosure(disclosure) == provenance.Undeclared {
		r.Blockers = append(r.Blockers, PublishBlocker{
			Code: "no_ai_disclosure", Fixable: true,
			Detail: "Tell buyers whether AI was involved in making this. The declaration is required, and it is yours to make — we corroborate it, we do not override it.",
		})
	}
	if activeVariants == 0 {
		r.Blockers = append(r.Blockers, PublishBlocker{
			Code: "no_priced_variant", Fixable: true,
			Detail: "Add at least one option with a price.",
		})
	}
	if !sellerActive || !kycVerified {
		r.Blockers = append(r.Blockers, PublishBlocker{
			Code: "seller_not_verified", Fixable: false,
			Detail: "Your seller account is not yet verified. We will e-mail you when it is; there is nothing to do in the meantime.",
		})
	}

	r.Ready = len(r.Blockers) == 0
	return r, nil
}

// Publish takes a product live.
//
// The database trigger is the authority on whether this is allowed. This method
// checks first only so the seller gets every reason at once, and it maps a
// trigger rejection back into the same language if the state changed in between.
func (s *Service) Publish(ctx context.Context, sellerID, actorID ids.UUID, productPublicID, ip string) error {
	readiness, err := s.ReadyToPublish(ctx, sellerID, productPublicID)
	if err != nil {
		return err
	}
	if !readiness.Ready {
		return publishBlocked(readiness)
	}

	return s.db.InTx(ctx, db.TxOptions{Name: "catalog_publish"}, func(ctx context.Context, tx db.Tx) error {
		productID, status, err := s.ownedProduct(ctx, tx, sellerID, productPublicID)
		if err != nil {
			return err
		}
		switch status {
		case StatusDraft, StatusRejected:
		case StatusPublished:
			return nil // already live; publishing twice is not an error
		default:
			return fmt.Errorf("%w: a %s product cannot be published", ErrNotEditable, status)
		}

		// Status and its timestamp move in one statement: the schema has a
		// CHECK that a published product carries a published_at, so two
		// statements would be transiently invalid.
		tag, err := tx.Exec(ctx, `
			UPDATE products SET status = 'published', published_at = $2, rejection_reason = NULL
			 WHERE id = $1 AND status IN ('draft','rejected')`,
			productID, s.clk.Now())
		if err != nil {
			return problemFor(err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotEditable
		}

		if err := s.audit.Record(ctx, tx, audit.Event{
			Action: "catalog.product.published", ActorID: &actorID,
			SubjectType: "product", SubjectID: productPublicID, ActorIP: ip,
			ActorKind: audit.ActorSeller,
		}); err != nil {
			return err
		}

		_, err = outbox.PublishJSON(ctx, tx, "catalog.product.published", "product", productPublicID,
			map[string]any{"product_id": productPublicID, "seller_id": sellerID.String()}, productPublicID)
		return err
	})
}

// Unpublish takes a product off sale without deleting anything.
//
// Buyers who already own it keep their entitlement: a purchase is a completed
// transaction, and withdrawing a listing is not a reason to take back what
// someone paid for.
func (s *Service) Unpublish(ctx context.Context, sellerID, actorID ids.UUID, productPublicID, ip string) error {
	return s.db.InTx(ctx, db.TxOptions{Name: "catalog_unpublish"}, func(ctx context.Context, tx db.Tx) error {
		productID, status, err := s.ownedProduct(ctx, tx, sellerID, productPublicID)
		if err != nil {
			return err
		}
		if status != StatusPublished {
			return nil
		}
		// ranking_anchor_at is immutable by trigger, so an unpublish and
		// republish cycle buys no ranking advantage. That is the anti-bump
		// control, and it is why this method does not need to defend itself.
		if _, err := tx.Exec(ctx,
			`UPDATE products SET status = 'draft' WHERE id = $1`, productID); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, audit.Event{
			Action: "catalog.product.unpublished", ActorID: &actorID,
			SubjectType: "product", SubjectID: productPublicID, ActorIP: ip,
			ActorKind: audit.ActorSeller,
		})
	})
}

// ---- helpers ----------------------------------------------------------------

func publishBlocked(r PublishReadiness) error {
	var details []string
	for _, b := range r.Blockers {
		details = append(details, b.Detail)
	}
	return problem.Conflict("", strings.Join(details, " "))
}

// ownedProduct resolves a public ID to this seller's product.
//
// Ownership is part of the query rather than a check after the fetch, and a
// product belonging to someone else is reported as not found — so this cannot
// be used to discover that another seller has a draft by that name.
func (s *Service) ownedProduct(ctx context.Context, q db.Querier, sellerID ids.UUID, publicID string) (ids.UUID, string, error) {
	var id ids.UUID
	var status string
	err := q.QueryRow(ctx,
		`SELECT id, status FROM products WHERE public_id = $1 AND seller_id = $2 FOR UPDATE`,
		publicID, sellerID).Scan(&id, &status)
	if err != nil {
		return ids.UUID{}, "", ErrNotFound
	}
	return id, status, nil
}

// uniqueSlug derives a URL slug from the title, appending a discriminator only
// when the seller already has that slug.
func (s *Service) uniqueSlug(ctx context.Context, q db.Querier, sellerID ids.UUID, title string) (string, error) {
	base := slugify(title)
	if base == "" {
		base = "listing"
	}
	candidate := base
	for attempt := 0; attempt < 8; attempt++ {
		var exists bool
		err := q.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM products WHERE seller_id = $1 AND slug = $2)`,
			sellerID, candidate).Scan(&exists)
		if err != nil {
			return "", err
		}
		if !exists {
			return candidate, nil
		}
		candidate = fmt.Sprintf("%s-%s", base, strings.ToLower(ids.NewPublic("x")[2:8]))
	}
	return "", errors.New("catalog: could not derive a unique slug")
}

// slugify produces a value matching the schema's slug pattern.
func slugify(s string) string {
	var b strings.Builder
	lastDash := true // suppress a leading dash
	for _, r := range strings.ToLower(s) {
		switch {
		case unicode.IsLetter(r) && r < unicode.MaxASCII, unicode.IsDigit(r) && r < unicode.MaxASCII:
			b.WriteRune(r)
			lastDash = false
		case !lastDash:
			b.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 60 {
		out = strings.Trim(out[:60], "-")
	}
	return out
}

func validateDraft(req *DraftRequest) error {
	var v validate.Errors

	req.Title = strings.TrimSpace(req.Title)
	req.Summary = strings.TrimSpace(req.Summary)
	req.Description = strings.TrimSpace(req.Description)
	req.LicenseTerms = strings.TrimSpace(req.LicenseTerms)

	v.Text("title", req.Title, 3, 140)
	v.Text("summary", req.Summary, 10, 300)
	v.Text("description", req.Description, 10, 20000)
	v.Text("license_terms", req.LicenseTerms, 10, 20000)

	if !oneOf(req.DeliveryType, "download", "streamed_access", "license_key", "hosted_access") {
		v.Add("delivery_type", "invalid", "Choose how buyers receive this.")
	}
	if !oneOf(req.LicenseType, "personal", "commercial", "extended", "editorial", "open_source") {
		v.Add("license_type", "invalid", "Choose the licence buyers receive.")
	}
	if req.RefundPolicy == "" {
		req.RefundPolicy = "no_refund_after_download"
	}
	if !oneOf(req.RefundPolicy, "no_refund_after_download", "refundable_14_days", "no_refund", "case_by_case") {
		v.Add("refund_policy", "invalid", "Choose a refund policy.")
	}
	if req.LicenseDurationDays != nil && *req.LicenseDurationDays <= 0 {
		v.Add("license_duration_days", "invalid", "A licence duration must be at least one day.")
	}

	// A draft may be saved undeclared — the declaration is required to publish,
	// not to start writing. Anything other than undeclared must be a real value.
	if req.AIDisclosure == "" {
		req.AIDisclosure = provenance.Undeclared
	}
	if req.AIDisclosure != provenance.Undeclared && !req.AIDisclosure.Valid() {
		v.Add("ai_disclosure", "invalid", "That is not one of the disclosure options.")
	}
	if len(req.AIDisclosureNote) > 2000 {
		v.Add("ai_disclosure_note", "too_long", "Keep the note under 2000 characters.")
	}
	if len(req.Tags) > 30 {
		v.Add("tags", "too_many", "Use at most 30 tags. Tags describe the work; they are not a keyword field.")
	}

	if p := v.Problem(); p != nil {
		return p
	}
	return nil
}

func oneOf(v string, allowed ...string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

func nullIfEmpty(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}
