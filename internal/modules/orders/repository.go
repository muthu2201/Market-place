package orders

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/muthu2201/market-place/internal/modules/tax"
	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/ids"
	"github.com/muthu2201/market-place/internal/platform/money"
	"github.com/muthu2201/market-place/internal/platform/problem"
)

// LoadOrder reads an order and its lines, reconstructing the tax breakdown from
// the stored snapshot rather than recomputing it. A rate change must never
// retroactively alter an order that has already been placed.
func (s *Service) LoadOrder(ctx context.Context, q db.Querier, publicID string) (*Order, error) {
	var o Order
	var currency string
	var items, taxTotal, grand, refunded int64
	var placeState *int
	var paidAt, expiresAt *time.Time

	err := q.QueryRow(ctx, `
		SELECT id, public_id, order_number, buyer_id, status, currency,
		       items_subtotal_minor, tax_total_minor, grand_total_minor, refunded_total_minor,
		       place_of_supply_country, place_of_supply_state, created_at, paid_at, expires_at
		  FROM orders WHERE public_id = $1`, publicID,
	).Scan(&o.ID, &o.PublicID, &o.Number, &o.BuyerID, (*string)(&o.Status), &currency,
		&items, &taxTotal, &grand, &refunded, &o.PlaceOfSupplyCountry, &placeState,
		&o.CreatedAt, &paidAt, &expiresAt)
	if db.IsNoRows(err) {
		return nil, problem.NotFound("Order not found.")
	}
	if err != nil {
		return nil, fmt.Errorf("orders: load: %w", err)
	}

	cur := money.Currency(currency)
	o.Currency = cur
	if o.ItemsTotal, err = money.New(items, cur); err != nil {
		return nil, err
	}
	if o.TaxTotal, err = money.New(taxTotal, cur); err != nil {
		return nil, err
	}
	if o.GrandTotal, err = money.New(grand, cur); err != nil {
		return nil, err
	}
	if o.Refunded, err = money.New(refunded, cur); err != nil {
		return nil, err
	}
	if placeState != nil {
		o.PlaceOfSupplyState = *placeState
	}
	o.PaidAt, o.ExpiresAt = paidAt, expiresAt

	rows, err := q.Query(ctx, `
		SELECT i.id, i.public_id, i.product_id, i.variant_id, i.seller_id, s.public_id,
		       i.title_snapshot, i.currency,
		       i.unit_price_minor, i.cgst_minor, i.sgst_minor, i.igst_minor,
		       i.tax_total_minor, i.buyer_total_minor, i.gst_rate_bps,
		       i.commission_bps, i.commission_minor, i.commission_gst_minor,
		       i.tcs_bps, i.tcs_minor, i.tds_bps, i.tds_minor,
		       i.psp_fee_minor, i.psp_fee_gst_minor, i.seller_net_minor,
		       COALESCE(s.provider_account_id, ''), s.provider_account_status, s.kyc_status,
		       s.settlement_hold_days, i.status, i.refunded_minor
		  FROM order_items i
		  JOIN sellers s ON s.id = i.seller_id
		 WHERE i.order_id = $1
		 ORDER BY i.created_at, i.id`, o.ID)
	if err != nil {
		return nil, fmt.Errorf("orders: load items: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var l LineBreakdown
		var lineCur, providerAccount, providerStatus, kycStatus, itemStatus string
		var unit, cgst, sgst, igst, taxT, buyerT, comm, commGST, tcs, tds, psp, pspGST, net, refundedLine int64
		var gstBps, commBps, tcsBps, tdsBps int64
		var holdDays int

		if err := rows.Scan(&l.ItemID, &l.ItemPublicID, &l.ProductID, &l.VariantID, &l.SellerID,
			&l.SellerPublicID, &l.Title, &lineCur,
			&unit, &cgst, &sgst, &igst, &taxT, &buyerT, &gstBps,
			&commBps, &comm, &commGST, &tcsBps, &tcs, &tdsBps, &tds,
			&psp, &pspGST, &net, &providerAccount, &providerStatus, &kycStatus,
			&holdDays, &itemStatus, &refundedLine); err != nil {
			return nil, err
		}
		lc := money.Currency(lineCur)
		mk := func(v int64) money.Money { return money.MustNew(v, lc) }

		l.Breakdown = tax.Breakdown{
			Currency: lc, ListPrice: mk(unit),
			CGST: mk(cgst), SGST: mk(sgst), IGST: mk(igst),
			TaxTotal: mk(taxT), BuyerTotal: mk(buyerT), GSTRateBps: gstBps,
			CommissionBps: commBps, Commission: mk(comm), CommissionGST: mk(commGST),
			TCSBps: tcsBps, TCS: mk(tcs), TDSBps: tdsBps, TDS: mk(tds),
			PSPFee: mk(psp), PSPFeeGST: mk(pspGST), SellerNet: mk(net),
			PSPFeeBorne: s.tax.PSPFeeBearer,
		}
		if providerStatus == "activated" && kycStatus == "verified" {
			l.ProviderAccount = providerAccount
		}
		l.SettlementHoldUntil = o.CreatedAt.AddDate(0, 0, holdDays)
		o.Lines = append(o.Lines, l)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return &o, nil
}

// LoadOrderForBuyer enforces ownership. Staff read through a separate path so
// that a support view is an explicit, audited decision rather than a side
// effect of a missing check.
func (s *Service) LoadOrderForBuyer(ctx context.Context, q db.Querier, publicID string, buyerID ids.UUID) (*Order, error) {
	o, err := s.LoadOrder(ctx, q, publicID)
	if err != nil {
		return nil, err
	}
	if o.BuyerID != buyerID {
		return nil, problem.NotFound("Order not found.")
	}
	return o, nil
}

// ListOrdersForBuyer returns a buyer's order history, newest first.
func (s *Service) ListOrdersForBuyer(ctx context.Context, q db.Querier, buyerID ids.UUID, limit, offset int) ([]*Order, error) {
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	rows, err := q.Query(ctx,
		`SELECT public_id FROM orders WHERE buyer_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
		buyerID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("orders: list: %w", err)
	}
	var pubs []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			rows.Close()
			return nil, err
		}
		pubs = append(pubs, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]*Order, 0, len(pubs))
	for _, p := range pubs {
		o, err := s.LoadOrder(ctx, q, p)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, nil
}

// checkoutFingerprint binds an idempotency key to the exact request it was
// first used for, so the same key cannot be reused for different contents.
func checkoutFingerprint(req CheckoutRequest) []byte {
	parts := make([]string, 0, len(req.Items))
	for _, it := range req.Items {
		parts = append(parts, it.ProductPublicID+"/"+it.VariantPublicID)
	}
	sort.Strings(parts)
	h := sha256.New()
	fmt.Fprintf(h, "buyer=%s|country=%s|state=%d|b2b=%t|gstin=%s|items=%s",
		req.BuyerID, strings.ToUpper(req.BuyerCountry), req.BuyerStateCode,
		req.IsB2B, req.BuyerGSTIN, strings.Join(parts, ","))
	return h.Sum(nil)
}
