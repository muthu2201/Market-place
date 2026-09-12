package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/muthu2201/market-place/internal/modules/catalog"
	"github.com/muthu2201/market-place/internal/modules/provenance"
	"github.com/muthu2201/market-place/internal/modules/seller"
	"github.com/muthu2201/market-place/internal/platform/httpx"
	"github.com/muthu2201/market-place/internal/platform/ids"
	"github.com/muthu2201/market-place/internal/platform/money"
	"github.com/muthu2201/market-place/internal/platform/problem"
)

// The seller surface. Every handler here resolves the caller's seller identity
// from the session and passes it down as a parameter, so a seller ID is never
// taken from the request body: an endpoint that accepted one would let any
// seller act as any other.

// sellerOf resolves the caller's seller row, or refuses.
func (s *Server) sellerOf(r *http.Request) (ids.UUID, error) {
	sess := SessionOf(r.Context())
	var sellerID ids.UUID
	err := s.db.QueryRow(r.Context(),
		`SELECT id FROM sellers WHERE user_id = $1`, sess.User.ID).Scan(&sellerID)
	if err != nil {
		return ids.UUID{}, problem.Forbidden("This account is not registered as a seller.")
	}
	return sellerID, nil
}

type onboardRequest struct {
	Handle      string `json:"handle"`
	DisplayName string `json:"display_name"`
	Bio         string `json:"bio"`
	LegalName   string `json:"legal_name"`
	EntityType  string `json:"entity_type"`
	Country     string `json:"country"`
	StateCode   int    `json:"state_code"`
	PAN         string `json:"pan"`
	GSTIN       string `json:"gstin"`
}

func (s *Server) handleSellerOnboard(w http.ResponseWriter, r *http.Request) {
	sess := SessionOf(r.Context())
	var req onboardRequest
	if !decode(w, r, &req) {
		return
	}

	out, err := s.seller.Onboard(r.Context(), seller.OnboardRequest{
		UserID: sess.User.ID, Handle: req.Handle, DisplayName: req.DisplayName,
		Bio: req.Bio, LegalName: req.LegalName, EntityType: req.EntityType,
		Country: req.Country, StateCode: req.StateCode, PAN: req.PAN, GSTIN: req.GSTIN,
		IP: httpx.ClientIP(r.Context()),
	})
	if err != nil {
		if errors.Is(err, seller.ErrAlreadySeller) {
			httpx.Fail(w, r, problem.Conflict("", "This account is already registered as a seller."))
			return
		}
		httpx.Fail(w, r, err)
		return
	}
	httpx.NoStore(w)
	httpx.JSON(w, r, http.StatusCreated, map[string]any{
		"seller_id": out.PublicID, "handle": out.Handle,
		"status": out.Status, "kyc_status": out.KYCStatus,
		"note": "You can start building listings now. Publishing and settlement open up once verification completes.",
	})
}

func (s *Server) handleSellerSubmitKYC(w http.ResponseWriter, r *http.Request) {
	sellerID, err := s.sellerOf(r)
	if err != nil {
		httpx.Fail(w, r, err)
		return
	}
	sess := SessionOf(r.Context())
	if err := s.seller.SubmitKYC(r.Context(), sellerID, sess.User.ID, httpx.ClientIP(r.Context())); err != nil {
		httpx.Fail(w, r, err)
		return
	}
	httpx.NoStore(w)
	httpx.JSON(w, r, http.StatusAccepted, map[string]any{"status": "submitted"})
}

// handleSellerPayoutStatus is what a seller's dashboard shows when money has
// not arrived. It is the same answer settlement uses, from the same rules.
func (s *Server) handleSellerPayoutStatus(w http.ResponseWriter, r *http.Request) {
	sellerID, err := s.sellerOf(r)
	if err != nil {
		httpx.Fail(w, r, err)
		return
	}
	eligibility, err := s.seller.PayoutEligibility(r.Context(), sellerID)
	if err != nil {
		httpx.Fail(w, r, err)
		return
	}
	accounts, err := s.seller.ListPayoutAccounts(r.Context(), sellerID)
	if err != nil {
		httpx.Fail(w, r, err)
		return
	}

	out := make([]map[string]any, 0, len(accounts))
	for _, a := range accounts {
		out = append(out, map[string]any{
			"id": a.ID.String(), "method": a.Method, "last4": a.Last4, "ifsc": a.IFSC,
			"validation": a.Validation, "is_default": a.IsDefault,
			"active_from": a.ActiveFrom, "quarantined": a.Quarantined,
		})
	}
	httpx.NoStore(w)
	httpx.JSON(w, r, http.StatusOK, map[string]any{
		"payable":  eligibility.Payable,
		"reasons":  eligibility.Reasons,
		"accounts": out,
	})
}

type payoutAccountRequest struct {
	Method          string `json:"method"`
	AccountNumber   string `json:"account_number"`
	IFSC            string `json:"ifsc"`
	BeneficiaryName string `json:"beneficiary_name"`
}

func (s *Server) handleSellerAddPayoutAccount(w http.ResponseWriter, r *http.Request) {
	sellerID, err := s.sellerOf(r)
	if err != nil {
		httpx.Fail(w, r, err)
		return
	}
	var req payoutAccountRequest
	if !decode(w, r, &req) {
		return
	}
	sess := SessionOf(r.Context())

	acct, err := s.seller.AddPayoutAccount(r.Context(), seller.PayoutAccountRequest{
		SellerID: sellerID, UserID: sess.User.ID, Method: req.Method,
		AccountNumber: req.AccountNumber, IFSC: req.IFSC,
		BeneficiaryName: req.BeneficiaryName, IP: httpx.ClientIP(r.Context()),
	})
	if err != nil {
		httpx.Fail(w, r, err)
		return
	}
	httpx.NoStore(w)
	httpx.JSON(w, r, http.StatusCreated, map[string]any{
		"id": acct.ID.String(), "method": acct.Method, "last4": acct.Last4,
		"active_from": acct.ActiveFrom, "quarantined": acct.Quarantined,
		"note": "For your protection every new or changed payout destination waits 48 hours " +
			"before it can receive money. Your existing destination is unaffected. " +
			"If you did not make this change, contact us now.",
	})
}

func (s *Server) handleSellerDisablePayoutAccount(w http.ResponseWriter, r *http.Request) {
	sellerID, err := s.sellerOf(r)
	if err != nil {
		httpx.Fail(w, r, err)
		return
	}
	accountID, err := ids.ParseUUID(r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, r, problem.NotFound("No such payout destination."))
		return
	}
	sess := SessionOf(r.Context())
	if err := s.seller.DisablePayoutAccount(r.Context(), sellerID, sess.User.ID, accountID,
		httpx.ClientIP(r.Context())); err != nil {
		httpx.Fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- catalogue --------------------------------------------------------------

type draftProductRequest struct {
	CategoryID          string   `json:"category_id"`
	Title               string   `json:"title"`
	Summary             string   `json:"summary"`
	Description         string   `json:"description"`
	DeliveryType        string   `json:"delivery_type"`
	LicenseType         string   `json:"license_type"`
	LicenseTerms        string   `json:"license_terms"`
	LicenseDurationDays *int     `json:"license_duration_days"`
	AIDisclosure        string   `json:"ai_disclosure"`
	AIDisclosureNote    string   `json:"ai_disclosure_note"`
	RefundPolicy        string   `json:"refund_policy"`
	Tags                []string `json:"tags"`
}

func (s *Server) handleDraftProduct(w http.ResponseWriter, r *http.Request) {
	sellerID, err := s.sellerOf(r)
	if err != nil {
		httpx.Fail(w, r, err)
		return
	}
	var req draftProductRequest
	if !decode(w, r, &req) {
		return
	}
	sess := SessionOf(r.Context())

	product, err := s.catalog.Draft(r.Context(), catalog.DraftRequest{
		SellerID: sellerID, ActorID: sess.User.ID, CategoryID: req.CategoryID,
		Title: req.Title, Summary: req.Summary, Description: req.Description,
		DeliveryType: req.DeliveryType, LicenseType: req.LicenseType,
		LicenseTerms: req.LicenseTerms, LicenseDurationDays: req.LicenseDurationDays,
		AIDisclosure:     provenance.Disclosure(req.AIDisclosure),
		AIDisclosureNote: req.AIDisclosureNote, RefundPolicy: req.RefundPolicy,
		Tags: req.Tags, IP: httpx.ClientIP(r.Context()),
	})
	if err != nil {
		httpx.Fail(w, r, catalogError(err))
		return
	}
	httpx.NoStore(w)
	httpx.JSON(w, r, http.StatusCreated, map[string]any{
		"product_id": product.PublicID, "slug": product.Slug,
		"status": product.Status, "title": product.Title,
	})
}

type addVariantRequest struct {
	Name       string `json:"name"`
	PriceMinor int64  `json:"price_minor"`
	Currency   string `json:"currency"`
	MaxSales   *int   `json:"max_sales"`
}

func (s *Server) handleAddVariant(w http.ResponseWriter, r *http.Request) {
	sellerID, err := s.sellerOf(r)
	if err != nil {
		httpx.Fail(w, r, err)
		return
	}
	var req addVariantRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Currency == "" {
		req.Currency = "INR"
	}
	price, err := money.New(req.PriceMinor, money.Currency(req.Currency))
	if err != nil {
		httpx.Fail(w, r, problem.Validation(problem.FieldError{
			Field: "price_minor", Code: "invalid", Detail: "That is not a valid price."}))
		return
	}

	variant, err := s.catalog.AddVariant(r.Context(), sellerID, r.PathValue("id"),
		req.Name, price, req.MaxSales)
	if err != nil {
		httpx.Fail(w, r, catalogError(err))
		return
	}
	httpx.NoStore(w)
	httpx.JSON(w, r, http.StatusCreated, map[string]any{
		"variant_id": variant.PublicID, "name": variant.Name, "price": variant.Price,
	})
}

type uploadRequest struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	SizeBytes   int64  `json:"size_bytes"`
}

func (s *Server) handleRequestUpload(w http.ResponseWriter, r *http.Request) {
	sellerID, err := s.sellerOf(r)
	if err != nil {
		httpx.Fail(w, r, err)
		return
	}
	var req uploadRequest
	if !decode(w, r, &req) {
		return
	}

	ticket, err := s.catalog.RequestUpload(r.Context(), sellerID, r.PathValue("id"),
		req.Filename, req.ContentType, req.SizeBytes)
	if err != nil {
		httpx.Fail(w, r, catalogError(err))
		return
	}
	httpx.NoStore(w)
	httpx.JSON(w, r, http.StatusOK, map[string]any{
		"upload_id": ticket.AssetID, "url": ticket.URL, "method": ticket.Method,
		"headers": ticket.Headers, "expires_at": ticket.ExpiresAt,
		"max_bytes": ticket.MaxBytes, "direct": ticket.Direct,
	})
}

type finaliseUploadRequest struct {
	UploadID    string `json:"upload_id"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	IsPreview   bool   `json:"is_preview"`
}

func (s *Server) handleFinaliseUpload(w http.ResponseWriter, r *http.Request) {
	sellerID, err := s.sellerOf(r)
	if err != nil {
		httpx.Fail(w, r, err)
		return
	}
	var req finaliseUploadRequest
	if !decode(w, r, &req) {
		return
	}

	asset, err := s.catalog.FinaliseUpload(r.Context(), sellerID, r.PathValue("id"),
		req.UploadID, req.Filename, req.ContentType, req.IsPreview)
	if err != nil {
		httpx.Fail(w, r, catalogError(err))
		return
	}
	httpx.NoStore(w)
	httpx.JSON(w, r, http.StatusCreated, map[string]any{
		"asset_id": asset.PublicID, "filename": asset.Filename,
		"size_bytes": asset.SizeBytes, "sha256": asset.Checksum,
		"scan_status": asset.ScanStatus,
		"note": "The file is being scanned. It becomes publishable once the scan completes, " +
			"usually within a few minutes.",
	})
}

func (s *Server) handleProductReadiness(w http.ResponseWriter, r *http.Request) {
	sellerID, err := s.sellerOf(r)
	if err != nil {
		httpx.Fail(w, r, err)
		return
	}
	readiness, err := s.catalog.ReadyToPublish(r.Context(), sellerID, r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, r, catalogError(err))
		return
	}

	blockers := make([]map[string]any, 0, len(readiness.Blockers))
	for _, b := range readiness.Blockers {
		blockers = append(blockers, map[string]any{
			"code": b.Code, "detail": b.Detail, "you_can_fix_this": b.Fixable,
		})
	}
	httpx.NoStore(w)
	httpx.JSON(w, r, http.StatusOK, map[string]any{
		"ready": readiness.Ready, "blockers": blockers,
	})
}

func (s *Server) handlePublishProduct(w http.ResponseWriter, r *http.Request) {
	sellerID, err := s.sellerOf(r)
	if err != nil {
		httpx.Fail(w, r, err)
		return
	}
	sess := SessionOf(r.Context())
	if err := s.catalog.Publish(r.Context(), sellerID, sess.User.ID, r.PathValue("id"),
		httpx.ClientIP(r.Context())); err != nil {
		httpx.Fail(w, r, catalogError(err))
		return
	}
	httpx.NoStore(w)
	httpx.JSON(w, r, http.StatusOK, map[string]any{"status": "published"})
}

func (s *Server) handleUnpublishProduct(w http.ResponseWriter, r *http.Request) {
	sellerID, err := s.sellerOf(r)
	if err != nil {
		httpx.Fail(w, r, err)
		return
	}
	sess := SessionOf(r.Context())
	if err := s.catalog.Unpublish(r.Context(), sellerID, sess.User.ID, r.PathValue("id"),
		httpx.ClientIP(r.Context())); err != nil {
		httpx.Fail(w, r, catalogError(err))
		return
	}
	httpx.NoStore(w)
	httpx.JSON(w, r, http.StatusOK, map[string]any{
		"status": "draft",
		"note": "Buyers who already own this keep their downloads. A purchase is a completed " +
			"transaction, and withdrawing a listing does not take it back.",
	})
}

type replaceTagsRequest struct {
	Tags []string `json:"tags"`
}

func (s *Server) handleReplaceTags(w http.ResponseWriter, r *http.Request) {
	sellerID, err := s.sellerOf(r)
	if err != nil {
		httpx.Fail(w, r, err)
		return
	}
	var req replaceTagsRequest
	if !decode(w, r, &req) {
		return
	}
	if len(req.Tags) > 30 {
		httpx.Fail(w, r, problem.Validation(problem.FieldError{
			Field: "tags", Code: "too_many",
			Detail: "Use at most 30 tags. Tags describe the work; they are not a keyword field."}))
		return
	}
	if err := s.catalog.ReplaceTags(r.Context(), sellerID, r.PathValue("id"), req.Tags); err != nil {
		httpx.Fail(w, r, catalogError(err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// catalogError maps the module's sentinel errors to problem documents.
//
// ErrNotFound covers "no such product" and "not yours" alike, so this endpoint
// cannot be used to discover that another seller has a draft by that name.
func catalogError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, catalog.ErrNotFound):
		return problem.NotFound("No such product.")
	case errors.Is(err, catalog.ErrNotEditable):
		return problem.Conflict("", strings.TrimPrefix(err.Error(), "catalog: "))
	}
	return err
}
