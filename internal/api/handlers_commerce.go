package api

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/muthu2201/market-place/internal/modules/delivery"
	"github.com/muthu2201/market-place/internal/modules/orders"
	"github.com/muthu2201/market-place/internal/modules/tax"
	"github.com/muthu2201/market-place/internal/platform/httpx"
	"github.com/muthu2201/market-place/internal/platform/ids"
	"github.com/muthu2201/market-place/internal/platform/money"
	"github.com/muthu2201/market-place/internal/platform/problem"
	"github.com/muthu2201/market-place/internal/platform/ratelimit"
	"github.com/muthu2201/market-place/internal/platform/validate"
)

type checkoutRequest struct {
	Items []struct {
		ProductID string `json:"product_id"`
		VariantID string `json:"variant_id"`
	} `json:"items"`
	StateCode int    `json:"state_code"`
	Country   string `json:"country"`
	GSTIN     string `json:"gstin"`
	IsB2B     bool   `json:"is_b2b"`
}

func (s *Server) handleCheckout(w http.ResponseWriter, r *http.Request) {
	sess := SessionOf(r.Context())
	if d := s.limiter.Allow(sess.User.PublicID, ratelimit.RuleCheckoutPerUser); !d.Allowed {
		httpx.Fail(w, r, problem.RateLimited(int(d.RetryAfter.Seconds())+1))
		return
	}

	var req checkoutRequest
	if !decode(w, r, &req) {
		return
	}
	var v validate.Errors
	if len(req.Items) == 0 {
		v.Add("items", "required", "Add at least one item before checking out.")
	}
	items := make([]orders.CheckoutItem, 0, len(req.Items))
	for i, it := range req.Items {
		field := "items[" + strconv.Itoa(i) + "]"
		if _, err := ids.ParsePublic(ids.PrefixProduct, it.ProductID); err != nil {
			v.Add(field+".product_id", "invalid", "That is not a valid product identifier.")
			continue
		}
		if _, err := ids.ParsePublic(ids.PrefixVariant, it.VariantID); err != nil {
			v.Add(field+".variant_id", "invalid", "That is not a valid option identifier.")
			continue
		}
		items = append(items, orders.CheckoutItem{ProductPublicID: it.ProductID, VariantPublicID: it.VariantID})
	}

	country := strings.ToUpper(strings.TrimSpace(req.Country))
	if country == "" {
		country = sess.User.Country
	}
	state := req.StateCode
	if state == 0 {
		state = sess.User.StateCode
	}
	gstin := ""
	if req.IsB2B || req.GSTIN != "" {
		gstin = v.GSTIN("gstin", req.GSTIN)
	}
	if p := v.Problem(); p != nil {
		httpx.Fail(w, r, p)
		return
	}

	order, err := s.orders.Checkout(r.Context(), orders.CheckoutRequest{
		BuyerID: sess.User.ID, Items: items,
		BuyerStateCode: state, BuyerCountry: country,
		BuyerGSTIN: gstin, IsB2B: req.IsB2B,
		IP:             httpx.ClientIP(r.Context()),
		IdempotencyKey: idempotencyKey(r),
	})
	if err != nil {
		httpx.Fail(w, r, err)
		return
	}
	httpx.NoStore(w)
	httpx.JSON(w, r, http.StatusCreated, orderResponse(order))
}

func (s *Server) handleBeginPayment(w http.ResponseWriter, r *http.Request) {
	sess := SessionOf(r.Context())
	orderID := r.PathValue("id")
	if _, err := ids.ParsePublic(ids.PrefixOrder, orderID); err != nil {
		httpx.Fail(w, r, problem.NotFound("Order not found."))
		return
	}
	handoff, err := s.orders.BeginPayment(r.Context(), orderID, sess.User.ID)
	if err != nil {
		httpx.Fail(w, r, err)
		return
	}
	httpx.NoStore(w)
	httpx.JSON(w, r, http.StatusOK, map[string]any{
		"order_id":   handoff.OrderPublicID,
		"provider":   handoff.Provider,
		"intent_id":  handoff.ProviderIntentID,
		"amount":     handoff.Amount,
		"checkout":   handoff.CheckoutParams,
		"expires_at": handoff.ExpiresAt,
	})
}

type confirmRequest struct {
	IntentID  string `json:"intent_id"`
	PaymentID string `json:"payment_id"`
	Signature string `json:"signature"`
}

func (s *Server) handleConfirmPayment(w http.ResponseWriter, r *http.Request) {
	sess := SessionOf(r.Context())
	orderID := r.PathValue("id")
	if _, err := ids.ParsePublic(ids.PrefixOrder, orderID); err != nil {
		httpx.Fail(w, r, problem.NotFound("Order not found."))
		return
	}
	var req confirmRequest
	if !decode(w, r, &req) {
		return
	}
	// Shape is checked here so an obviously malformed callback never reaches
	// the verification path or the database.
	if req.IntentID == "" || req.PaymentID == "" || len(req.Signature) < 32 || len(req.Signature) > 256 {
		httpx.Fail(w, r, problem.New(http.StatusPaymentRequired, problem.TypePaymentFailed,
			"Payment could not be verified", "The confirmation was incomplete."))
		return
	}

	res, err := s.orders.ConfirmPayment(r.Context(), orders.ConfirmRequest{
		OrderPublicID: orderID, ProviderIntentID: req.IntentID,
		ProviderPaymentID: req.PaymentID, Signature: req.Signature,
		BuyerID: sess.User.ID, IP: httpx.ClientIP(r.Context()),
	})
	if err != nil {
		httpx.Fail(w, r, err)
		return
	}
	licenses := make([]map[string]any, 0, len(res.Licenses))
	for _, l := range res.Licenses {
		licenses = append(licenses, map[string]any{
			"id": l.PublicID, "product": l.ProductTitle, "license_type": l.LicenseType,
			"download_limit": l.DownloadLimit, "expires_at": l.ExpiresAt,
		})
	}
	httpx.NoStore(w)
	httpx.JSON(w, r, http.StatusOK, map[string]any{
		"order":             orderResponse(res.Order),
		"licenses":          licenses,
		"already_confirmed": res.AlreadyConfirmed,
	})
}

func (s *Server) handleListOrders(w http.ResponseWriter, r *http.Request) {
	sess := SessionOf(r.Context())
	limit, offset := pagination(r, 25, 100)
	list, err := s.orders.ListOrdersForBuyer(r.Context(), s.db, sess.User.ID, limit, offset)
	if err != nil {
		httpx.Fail(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, o := range list {
		out = append(out, orderResponse(o))
	}
	httpx.NoStore(w)
	httpx.JSON(w, r, http.StatusOK, map[string]any{"orders": out, "limit": limit, "offset": offset})
}

func (s *Server) handleGetOrder(w http.ResponseWriter, r *http.Request) {
	sess := SessionOf(r.Context())
	order, err := s.orders.LoadOrderForBuyer(r.Context(), s.db, r.PathValue("id"), sess.User.ID)
	if err != nil {
		httpx.Fail(w, r, err)
		return
	}
	httpx.NoStore(w)
	httpx.JSON(w, r, http.StatusOK, orderResponse(order))
}

type refundRequest struct {
	ItemID      string `json:"item_id"`
	AmountMinor *int64 `json:"amount_minor"`
	Reason      string `json:"reason"`
	Note        string `json:"note"`
}

func (s *Server) handleRequestRefund(w http.ResponseWriter, r *http.Request) {
	sess := SessionOf(r.Context())
	var req refundRequest
	if !decode(w, r, &req) {
		return
	}
	var v validate.Errors
	reason := v.OneOf("reason", req.Reason,
		"buyer_request", "not_as_described", "duplicate", "failed_delivery")
	if p := v.Problem(); p != nil {
		httpx.Fail(w, r, p)
		return
	}

	var amount *money.Money
	if req.AmountMinor != nil {
		m, err := money.New(*req.AmountMinor, money.Currency(s.cfg.Platform.Currency))
		if err != nil {
			httpx.Fail(w, r, problem.Validation(
				problem.FieldError{Field: "amount_minor", Code: "invalid", Detail: "That amount is not valid."}))
			return
		}
		amount = &m
	}

	out, err := s.orders.Refund(r.Context(), orders.RefundRequest{
		OrderPublicID: r.PathValue("id"), ItemPublicID: req.ItemID,
		Amount: amount, Reason: reason, RequestedBy: sess.User.ID,
		// A buyer never gets the staff override; only the admin surface does.
		ActorIsStaff: false,
		Note:         req.Note, IdempotencyKey: idempotencyKey(r),
	})
	if err != nil {
		httpx.Fail(w, r, err)
		return
	}
	httpx.NoStore(w)
	httpx.JSON(w, r, http.StatusOK, map[string]any{
		"refund_id":    out.RefundPublicID,
		"amount":       out.Amount,
		"order_status": string(out.OrderStatus),
		"note": "The processing fee on the original payment is not returned by the card network. " +
			"We absorb it rather than pass it on to you or to the seller.",
	})
}

// ---- library and downloads --------------------------------------------------

func (s *Server) handleLibrary(w http.ResponseWriter, r *http.Request) {
	sess := SessionOf(r.Context())
	limit, offset := pagination(r, 50, 100)
	items, err := s.delivery.ListEntitlements(r.Context(), sess.User.ID, limit, offset)
	if err != nil {
		httpx.Fail(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(items))
	for _, e := range items {
		assets := make([]map[string]any, 0, len(e.Assets))
		for _, a := range e.Assets {
			assets = append(assets, map[string]any{
				"id": a.AssetPublicID, "filename": a.Filename,
				"size_bytes": a.SizeBytes, "content_type": a.ContentType,
				"sha256": a.Checksum,
			})
		}
		out = append(out, map[string]any{
			"license_id": e.LicensePublicID, "product": e.ProductTitle,
			"license_type": e.LicenseType, "terms": e.Terms,
			"downloads_used": e.DownloadsUsed, "download_limit": e.DownloadLimit,
			"expires_at": e.ExpiresAt, "revoked": e.Revoked, "assets": assets,
		})
	}
	httpx.NoStore(w)
	httpx.JSON(w, r, http.StatusOK, map[string]any{"library": out})
}

func (s *Server) handleIssueDownload(w http.ResponseWriter, r *http.Request) {
	sess := SessionOf(r.Context())
	license := r.PathValue("license")
	asset := r.PathValue("asset")
	// Shape validation only. Ownership is decided by the delivery service, which
	// re-resolves the entitlement from the session.
	if !ids.ValidPublic(license) || !ids.ValidPublic(asset) {
		httpx.Fail(w, r, delivery.ErrNoEntitlement)
		return
	}
	ticket, err := s.delivery.IssueTicket(r.Context(), sess.User.ID, license, asset, httpx.ClientIP(r.Context()))
	if err != nil {
		httpx.Fail(w, r, err)
		return
	}
	if ticket.Direct {
		s.delivery.RecordDirectDelivery(r.Context(), sess.User.ID, license, asset, ticket.SizeBytes, httpx.ClientIP(r.Context()))
	}
	httpx.NoStore(w)
	httpx.JSON(w, r, http.StatusOK, map[string]any{
		"url": ticket.URL, "direct": ticket.Direct,
		"expires_at": ticket.ExpiresAt, "filename": ticket.Filename,
		"size_bytes": ticket.SizeBytes,
		"note":       "This link is single use and expires shortly. Do not share it.",
	})
}

func (s *Server) handleRedeemDownload(w http.ResponseWriter, r *http.Request) {
	ctx := delivery.WithClientIP(r.Context(), httpx.ClientIP(r.Context()))
	err := s.delivery.Redeem(ctx, w, r.WithContext(ctx), r.PathValue("grant"), r.URL.Query().Get("t"))
	if err != nil {
		httpx.Fail(w, r, err)
	}
}

// ---- webhooks ---------------------------------------------------------------

func (s *Server) handlePaymentWebhook(w http.ResponseWriter, r *http.Request) {
	if d := s.limiter.Allow(httpx.ClientIP(r.Context()), ratelimit.RuleWebhookPerIP); !d.Allowed {
		httpx.Fail(w, r, problem.RateLimited(int(d.RetryAfter.Seconds())+1))
		return
	}
	// The raw bytes are what the signature covers, so the body is read exactly
	// once and never re-encoded before verification.
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		httpx.Fail(w, r, problem.Validation(
			problem.FieldError{Field: "body", Code: "unreadable", Detail: "The request body could not be read."}))
		return
	}

	out, err := s.orders.HandleWebhook(r.Context(), r.Header, body)
	if err != nil {
		p := problem.As(err)
		if p != nil && p.Status == http.StatusUnauthorized {
			// A bad signature is hostile input. It is refused, logged and NOT
			// retried; returning 5xx would invite the provider to hammer us.
			httpx.Fail(w, r, err)
			return
		}
		// A genuine processing failure returns 500 so the provider retries,
		// which is what the outbox and the de-duplication table exist to make
		// safe.
		logFrom(r).Error("webhook processing failed", "error", err.Error())
		httpx.JSON(w, r, http.StatusInternalServerError, map[string]any{"status": "retry"})
		return
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{
		"status": "accepted", "event_id": out.EventID,
		"duplicate": out.Duplicate, "processed": out.Processed,
	})
}

// ---- shared shaping ---------------------------------------------------------

func orderResponse(o *orders.Order) map[string]any {
	if o == nil {
		return nil
	}
	lines := make([]map[string]any, 0, len(o.Lines))
	for _, l := range o.Lines {
		lines = append(lines, map[string]any{
			"item_id": l.ItemPublicID, "title": l.Title, "seller_id": l.SellerPublicID,
			"price": l.Breakdown.ListPrice, "tax": l.Breakdown.TaxTotal,
			"total": l.Breakdown.BuyerTotal,
			"tax_breakdown": map[string]any{
				"cgst": l.Breakdown.CGST, "sgst": l.Breakdown.SGST, "igst": l.Breakdown.IGST,
				"rate_bps": l.Breakdown.GSTRateBps, "supply_type": string(l.Breakdown.Supply),
			},
			// The full explanation travels with the order so a buyer or seller
			// can see exactly how each figure was derived.
			"explanation": l.Breakdown.Explain,
		})
	}
	return map[string]any{
		"id": o.PublicID, "number": o.Number, "status": string(o.Status),
		"currency": string(o.Currency), "subtotal": o.ItemsTotal,
		"tax_total": o.TaxTotal, "total": o.GrandTotal, "refunded": o.Refunded,
		"place_of_supply": map[string]any{
			"country": o.PlaceOfSupplyCountry, "state_code": o.PlaceOfSupplyState,
		},
		"created_at": o.CreatedAt, "paid_at": o.PaidAt, "items": lines,
	}
}

// idempotencyKey reads the header, bounding its length so it cannot be used to
// store arbitrary data.
func idempotencyKey(r *http.Request) string {
	k := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if len(k) < 8 || len(k) > 255 {
		return ""
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == ':' || c == '.' {
			continue
		}
		return ""
	}
	return k
}

func pagination(r *http.Request, def, max int) (limit, offset int) {
	limit = def
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= max {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 100_000 {
			offset = n
		}
	}
	return limit, offset
}

var _ = errors.Is
var _ = tax.IntraState
