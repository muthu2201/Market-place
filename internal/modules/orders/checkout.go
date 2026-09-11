package orders

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/muthu2201/market-place/internal/modules/audit"
	"github.com/muthu2201/market-place/internal/modules/ledger"
	"github.com/muthu2201/market-place/internal/modules/payments"
	"github.com/muthu2201/market-place/internal/modules/tax"
	"github.com/muthu2201/market-place/internal/platform/clock"
	"github.com/muthu2201/market-place/internal/platform/config"
	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/ids"
	"github.com/muthu2201/market-place/internal/platform/metrics"
	"github.com/muthu2201/market-place/internal/platform/money"
	"github.com/muthu2201/market-place/internal/platform/problem"
)

// Service orchestrates the purchase lifecycle.
type Service struct {
	db       *db.DB
	ledger   *ledger.Service
	provider payments.Provider
	tax      tax.Policy
	cfg      config.PaymentsConfig
	platform config.PlatformConfig
	clk      clock.Clock
	audit    *audit.Service
	log      *slog.Logger
	m        *metrics.App
	// pspFeeBps and pspFeeGSTBps are the platform's current blended provider
	// cost, used to attribute processing cost per line. The authoritative
	// figure arrives with settlement data and reconciliation corrects any drift.
	pspFeeBps    int64
	pspFeeGSTBps int64
}

// Options configures the service.
type Options struct {
	DB           *db.DB
	Ledger       *ledger.Service
	Provider     payments.Provider
	TaxPolicy    tax.Policy
	Payments     config.PaymentsConfig
	Platform     config.PlatformConfig
	Clock        clock.Clock
	Audit        *audit.Service
	Log          *slog.Logger
	Metrics      *metrics.App
	PSPFeeBps    int64
	PSPFeeGSTBps int64
}

func NewService(o Options) (*Service, error) {
	if o.DB == nil || o.Ledger == nil || o.Provider == nil {
		return nil, errors.New("orders: database, ledger and payment provider are required")
	}
	if o.Clock == nil {
		o.Clock = clock.System()
	}
	if o.Audit == nil {
		o.Audit = audit.New()
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.PSPFeeBps == 0 {
		o.PSPFeeBps = 200 // 2%, the standard domestic rate
	}
	if o.PSPFeeGSTBps == 0 {
		o.PSPFeeGSTBps = 1800
	}
	return &Service{
		db: o.DB, ledger: o.Ledger, provider: o.Provider, tax: o.TaxPolicy,
		cfg: o.Payments, platform: o.Platform, clk: o.Clock, audit: o.Audit,
		log: o.Log, m: o.Metrics, pspFeeBps: o.PSPFeeBps, pspFeeGSTBps: o.PSPFeeGSTBps,
	}, nil
}

// catalogueLine is a product read fresh from the database at checkout.
type catalogueLine struct {
	productID      ids.UUID
	variantID      ids.UUID
	sellerID       ids.UUID
	sellerPublicID string
	title          string
	licenseType    string
	licenseTerms   string
	refundPolicy   string
	licenseDays    *int
	price          money.Money
	deliveryType   string
	// Seller tax attributes, snapshotted onto the order item.
	gstRegistered   bool
	gstin           string
	pan             string
	stateCode       int
	hasPAN          bool
	individual      bool
	fyGross         int64
	commissionBps   int64
	providerAccount string
	holdDays        int
	maxSales        *int
	salesCount      int
}

// Checkout prices an order and persists it.
//
// Prices, commission rates and seller tax attributes are all read server-side.
// The client supplies only which product it wants, so there is no field an
// attacker can tamper with to change what they pay or what a seller receives.
func (s *Service) Checkout(ctx context.Context, req CheckoutRequest) (*Order, error) {
	if len(req.Items) == 0 {
		return nil, problem.Validation(problem.FieldError{
			Field: "items", Code: "required", Detail: "An order must contain at least one item."})
	}
	if len(req.Items) > 50 {
		return nil, problem.Validation(problem.FieldError{
			Field: "items", Code: "too_many", Detail: "An order may contain at most 50 items."})
	}
	country := strings.ToUpper(strings.TrimSpace(req.BuyerCountry))
	if country == "" {
		country = "IN"
	}
	if country == "IN" && (req.BuyerStateCode < 1 || req.BuyerStateCode > 99) {
		return nil, problem.Validation(problem.FieldError{
			Field: "state_code", Code: "required",
			Detail: "A state is required for a domestic order: it fixes the place of supply and therefore whether CGST plus SGST or IGST applies."})
	}
	if req.IsB2B && req.BuyerGSTIN == "" {
		return nil, problem.Validation(problem.FieldError{
			Field: "buyer_gstin", Code: "required", Detail: "A business order requires the buyer's GSTIN."})
	}

	var order *Order
	err := s.db.InTx(ctx, db.TxOptions{Name: "checkout"}, func(ctx context.Context, tx db.Tx) error {
		// Idempotency: a retried checkout must return the original order rather
		// than charging the buyer twice.
		if req.IdempotencyKey != "" {
			existing, found, err := s.replayCheckout(ctx, tx, req)
			if err != nil {
				return err
			}
			if found {
				order = existing
				return nil
			}
		}

		lines, err := s.readCatalogue(ctx, tx, req.Items)
		if err != nil {
			return err
		}

		orderID := ids.NewUUIDv7()
		orderPublicID := ids.NewPublic(ids.PrefixOrder)
		now := s.clk.Now()
		number, err := s.nextOrderNumber(ctx, tx, now)
		if err != nil {
			return err
		}

		currency := lines[0].price.Currency()
		itemsTotal := money.Zero(currency)
		taxTotal := money.Zero(currency)
		grandTotal := money.Zero(currency)

		buyer := tax.Buyer{
			Country: country, StateCode: req.BuyerStateCode,
			GSTIN: req.BuyerGSTIN, IsB2B: req.IsB2B,
		}

		var state any
		if country == "IN" {
			state = req.BuyerStateCode
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO orders (id, public_id, order_number, buyer_id, status, currency,
			                    place_of_supply_country, place_of_supply_state, buyer_gstin, is_b2b,
			                    buyer_ip, expires_at)
			VALUES ($1,$2,$3,$4,'draft',$5,$6,$7,$8,$9,$10,$11)`,
			orderID, orderPublicID, number, req.BuyerID, string(currency),
			country, state, nullIfEmpty(req.BuyerGSTIN), req.IsB2B,
			nullIfEmpty(req.IP), now.Add(30*time.Minute),
		); err != nil {
			return fmt.Errorf("orders: insert order: %w", err)
		}

		out := make([]LineBreakdown, 0, len(lines))
		for _, cl := range lines {
			if cl.price.Currency() != currency {
				return problem.Validation(problem.FieldError{
					Field: "items", Code: "mixed_currency",
					Detail: "All items in one order must share a currency."})
			}
			seller := tax.Seller{
				GSTRegistered: cl.gstRegistered, GSTIN: cl.gstin, StateCode: cl.stateCode,
				HasPAN: cl.hasPAN, ResidentIndividualOrHUF: cl.individual,
				FYGrossSupplyMinor: cl.fyGross, Country: "IN",
			}
			bd, err := tax.Compute(s.tax, seller, buyer, tax.Line{
				ListPrice: cl.price, CommissionBps: cl.commissionBps,
				PSPFeeBps: s.pspFeeBps, PSPFeeGSTBps: s.pspFeeGSTBps,
			}, now)
			if err != nil {
				return fmt.Errorf("orders: price line %s: %w", cl.title, err)
			}

			itemID := ids.NewUUIDv7()
			itemPublicID := ids.NewPublic(ids.PrefixOrderItem)
			holdUntil := now.AddDate(0, 0, cl.holdDays)

			if _, err := tx.Exec(ctx, `
				INSERT INTO order_items (
					id, public_id, order_id, product_id, variant_id, seller_id,
					title_snapshot, license_type_snapshot, license_terms_snapshot, refund_policy_snapshot,
					seller_gstin_snapshot, seller_pan_snapshot, seller_state_snapshot,
					currency, unit_price_minor, line_total_minor, gst_rate_bps,
					cgst_minor, sgst_minor, igst_minor, tax_total_minor, buyer_total_minor,
					commission_bps, commission_minor, commission_gst_minor,
					tcs_bps, tcs_minor, tds_bps, tds_minor,
					psp_fee_minor, psp_fee_gst_minor, seller_net_minor, status)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,
				        $23,$24,$25,$26,$27,$28,$29,$30,$31,$32,'pending')`,
				itemID, itemPublicID, orderID, cl.productID, cl.variantID, cl.sellerID,
				cl.title, cl.licenseType, cl.licenseTerms, cl.refundPolicy,
				nullIfEmpty(cl.gstin), nullIfEmpty(cl.pan), nullIfZero(cl.stateCode),
				string(currency), bd.ListPrice.Minor(), bd.ListPrice.Minor(), bd.GSTRateBps,
				bd.CGST.Minor(), bd.SGST.Minor(), bd.IGST.Minor(), bd.TaxTotal.Minor(), bd.BuyerTotal.Minor(),
				bd.CommissionBps, bd.Commission.Minor(), bd.CommissionGST.Minor(),
				bd.TCSBps, bd.TCS.Minor(), bd.TDSBps, bd.TDS.Minor(),
				bd.PSPFee.Minor(), bd.PSPFeeGST.Minor(), bd.SellerNet.Minor(),
			); err != nil {
				return fmt.Errorf("orders: insert item: %w", err)
			}

			if itemsTotal, err = itemsTotal.Add(bd.ListPrice); err != nil {
				return err
			}
			if taxTotal, err = taxTotal.Add(bd.TaxTotal); err != nil {
				return err
			}
			if grandTotal, err = grandTotal.Add(bd.BuyerTotal); err != nil {
				return err
			}

			out = append(out, LineBreakdown{
				ItemID: itemID, ItemPublicID: itemPublicID, ProductID: cl.productID,
				VariantID: cl.variantID, SellerID: cl.sellerID, SellerPublicID: cl.sellerPublicID,
				Title: cl.title, Breakdown: bd, ProviderAccount: cl.providerAccount,
				SettlementHoldUntil: holdUntil,
			})
		}

		if _, err := tx.Exec(ctx, `
			UPDATE orders SET items_subtotal_minor = $2, tax_total_minor = $3, grand_total_minor = $4, placed_at = $5
			 WHERE id = $1`,
			orderID, itemsTotal.Minor(), taxTotal.Minor(), grandTotal.Minor(), now); err != nil {
			return fmt.Errorf("orders: set totals: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO order_events (order_id, from_status, to_status, actor_kind, actor_id, reason)
			VALUES ($1, NULL, 'draft', 'user', $2, 'checkout created')`, orderID, req.BuyerID); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, audit.Event{
			ActorKind: audit.ActorUser, ActorID: &req.BuyerID, ActorIP: req.IP,
			Action: "order.created", SubjectType: "order", SubjectID: orderPublicID,
			Metadata: map[string]any{
				"items": len(out), "total_minor": grandTotal.Minor(), "currency": string(currency),
			},
		}); err != nil {
			return err
		}
		if req.IdempotencyKey != "" {
			if err := s.claimIdempotency(ctx, tx, req, orderPublicID); err != nil {
				return err
			}
		}

		order = &Order{
			ID: orderID, PublicID: orderPublicID, Number: number, BuyerID: req.BuyerID,
			Status: StatusDraft, Currency: currency, ItemsTotal: itemsTotal,
			TaxTotal: taxTotal, GrandTotal: grandTotal, Refunded: money.Zero(currency),
			Lines: out, PlaceOfSupplyCountry: country, PlaceOfSupplyState: req.BuyerStateCode,
			CreatedAt: now,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return order, nil
}

// readCatalogue loads every requested line under a row lock, refusing anything
// that is not currently purchasable.
func (s *Service) readCatalogue(ctx context.Context, tx db.Tx, items []CheckoutItem) ([]catalogueLine, error) {
	out := make([]catalogueLine, 0, len(items))
	seen := make(map[string]struct{}, len(items))

	for _, it := range items {
		key := it.ProductPublicID + "/" + it.VariantPublicID
		if _, dup := seen[key]; dup {
			return nil, problem.Validation(problem.FieldError{
				Field: "items", Code: "duplicate",
				Detail: "A digital licence is issued once per order; remove the duplicate line."})
		}
		seen[key] = struct{}{}

		var cl catalogueLine
		var licenseDays *int
		var maxSales *int
		var sellerStatus, kycStatus, providerAccountStatus, entityType, currencyCode string
		var providerAccount *string
		var gstin, pan *string
		var stateCode *int
		var fyGross *int64
		var priceMinor int64
		var productStatus string
		var variantActive bool

		// FOR UPDATE on the variant serialises concurrent purchases of a
		// limited-edition item, so max_sales cannot be exceeded by a race.
		err := tx.QueryRow(ctx, `
			SELECT p.id, v.id, p.seller_id, s.public_id, p.title, p.license_type, p.license_terms,
			       p.refund_policy, p.license_duration_days, v.price_minor, v.currency, p.delivery_type,
			       p.status, v.active,
			       s.gst_registered, s.gstin, s.pan, s.state_code, s.entity_type,
			       s.status, s.kyc_status, s.provider_account_id, s.provider_account_status,
			       s.settlement_hold_days,
			       v.max_sales, v.sales_count,
			       COALESCE(fs.commission_bps, 900),
			       (SELECT t.gross_supply FROM seller_turnover t
			         WHERE t.seller_id = s.id AND t.fy_start = $3 AND t.currency = v.currency)
			  FROM products p
			  JOIN product_variants v ON v.product_id = p.id
			  JOIN sellers s ON s.id = p.seller_id
			  LEFT JOIN LATERAL (
			      SELECT f.commission_bps
			        FROM seller_fee_assignments a
			        JOIN fee_schedules f ON f.id = a.fee_schedule_id
			       WHERE a.seller_id = s.id
			         AND a.effective_from <= now()
			         AND (a.effective_to IS NULL OR a.effective_to > now())
			       ORDER BY a.effective_from DESC LIMIT 1
			  ) fs ON TRUE
			 WHERE p.public_id = $1 AND v.public_id = $2
			 FOR UPDATE OF v`,
			it.ProductPublicID, it.VariantPublicID, fyStart(s.clk.Now()),
		).Scan(&cl.productID, &cl.variantID, &cl.sellerID, &cl.sellerPublicID, &cl.title,
			&cl.licenseType, &cl.licenseTerms, &cl.refundPolicy, &licenseDays,
			&priceMinor, &currencyCode, &cl.deliveryType,
			&productStatus, &variantActive,
			&cl.gstRegistered, &gstin, &pan, &stateCode, &entityType,
			&sellerStatus, &kycStatus, &providerAccount, &providerAccountStatus,
			&cl.holdDays, &maxSales, &cl.salesCount, &cl.commissionBps, &fyGross)

		if db.IsNoRows(err) {
			return nil, problem.NotFound("That product is no longer available.")
		}
		if err != nil {
			return nil, fmt.Errorf("orders: read catalogue: %w", err)
		}

		if cl.price, err = money.New(priceMinor, money.Currency(currencyCode)); err != nil {
			return nil, fmt.Errorf("orders: variant %s has an unsupported currency: %w", cl.variantID, err)
		}
		// The s.194-O threshold applies only to a resident individual or HUF;
		// a company or firm has no threshold.
		cl.individual = entityType == "individual" || entityType == "huf" || entityType == "proprietorship"

		// Purchasability is re-checked here rather than trusted from a listing
		// page the buyer may have loaded hours ago.
		if productStatus != "published" {
			return nil, problem.Conflict("", "That product is not currently on sale.")
		}
		if !variantActive {
			return nil, problem.Conflict("", "That option is no longer on sale.")
		}
		if sellerStatus != "active" {
			return nil, problem.Conflict("", "That seller is not currently accepting orders.")
		}
		if maxSales != nil && cl.salesCount >= *maxSales {
			return nil, problem.Conflict("", "That limited edition has sold out.")
		}
		if cl.price.IsNegative() {
			return nil, fmt.Errorf("orders: negative price on variant %s", cl.variantID)
		}

		cl.licenseDays = licenseDays
		cl.maxSales = maxSales
		cl.hasPAN = pan != nil && *pan != ""
		if gstin != nil {
			cl.gstin = *gstin
		}
		if pan != nil {
			cl.pan = *pan
		}
		if stateCode != nil {
			cl.stateCode = *stateCode
		}
		if fyGross != nil {
			cl.fyGross = *fyGross
		}
		if providerAccount != nil {
			cl.providerAccount = *providerAccount
		}
		// Settlement eligibility is recorded but does NOT block the sale: a
		// buyer must not be turned away because a seller's KYC is pending. The
		// seller's share is simply held until the provider activates them.
		if kycStatus != "verified" || providerAccountStatus != "activated" {
			cl.providerAccount = ""
		}
		out = append(out, cl)
	}
	return out, nil
}

// nextOrderNumber allocates a gapless, per-financial-year order number under a
// row lock, so concurrent checkouts cannot collide or leave holes.
func (s *Service) nextOrderNumber(ctx context.Context, tx db.Tx, now time.Time) (string, error) {
	var number string
	if err := tx.QueryRow(ctx,
		`SELECT next_invoice_number('seller_supply', $1::date, 'ORD')`, fyStart(now)).Scan(&number); err != nil {
		return "", fmt.Errorf("orders: allocate order number: %w", err)
	}
	return number, nil
}

func (s *Service) replayCheckout(ctx context.Context, tx db.Tx, req CheckoutRequest) (*Order, bool, error) {
	fingerprint := checkoutFingerprint(req)
	var status, resourceID string
	var storedFP []byte
	err := tx.QueryRow(ctx, `
		SELECT status, COALESCE(resource_id,''), request_fingerprint
		  FROM idempotency_keys
		 WHERE scope = 'checkout' AND idempotency_key = $1 AND user_id = $2`,
		req.IdempotencyKey, req.BuyerID).Scan(&status, &resourceID, &storedFP)
	if db.IsNoRows(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("orders: idempotency lookup: %w", err)
	}
	if string(storedFP) != string(fingerprint) {
		// Same key, different request. Returning the first response here would
		// hand one caller another caller's order.
		return nil, false, problem.Conflict(problem.TypeIdempotencyReuse,
			"This idempotency key was already used for a different request. Use a fresh key.")
	}
	if status != "completed" || resourceID == "" {
		return nil, false, problem.Conflict(problem.TypeIdempotencyReuse,
			"An identical request is still being processed. Retry shortly.")
	}
	o, err := s.LoadOrder(ctx, tx, resourceID)
	if err != nil {
		return nil, false, err
	}
	return o, true, nil
}

func (s *Service) claimIdempotency(ctx context.Context, tx db.Tx, req CheckoutRequest, orderPublicID string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO idempotency_keys (id, scope, idempotency_key, user_id, request_fingerprint,
		                              status, resource_id, completed_at)
		VALUES ($1,'checkout',$2,$3,$4,'completed',$5,now())`,
		ids.NewUUIDv7(), req.IdempotencyKey, req.BuyerID, checkoutFingerprint(req), orderPublicID)
	if err != nil {
		return fmt.Errorf("orders: claim idempotency key: %w", err)
	}
	return nil
}

// BeginPayment creates the provider payment and moves the order to
// awaiting_payment, attaching the split instruction where Route is active.
func (s *Service) BeginPayment(ctx context.Context, orderPublicID string, buyerID ids.UUID) (*PaymentHandoff, error) {
	var handoff *PaymentHandoff

	err := s.db.InTx(ctx, db.TxOptions{Name: "begin_payment"}, func(ctx context.Context, tx db.Tx) error {
		o, err := s.LoadOrder(ctx, tx, orderPublicID)
		if err != nil {
			return err
		}
		if o.BuyerID != buyerID {
			// Reporting "not found" rather than "forbidden" avoids confirming
			// that an order with this id exists at all.
			return problem.NotFound("Order not found.")
		}
		if o.Status != StatusDraft && o.Status != StatusPaymentFailed {
			return problem.Conflict(problem.TypeStateTransition,
				"This order is not awaiting payment.")
		}

		// An existing, still-valid intent is reused rather than duplicated.
		var existingIntent string
		var existingStatus string
		err = tx.QueryRow(ctx, `
			SELECT COALESCE(provider_intent_id,''), status FROM payment_intents
			 WHERE order_id = $1 AND status IN ('created','requires_action','processing')
			 ORDER BY created_at DESC LIMIT 1`, o.ID).Scan(&existingIntent, &existingStatus)
		if err != nil && !db.IsNoRows(err) {
			return fmt.Errorf("orders: read intent: %w", err)
		}

		splits := make([]payments.SplitLine, 0, len(o.Lines))
		if s.provider.Capabilities().SplitSettlement {
			for _, l := range o.Lines {
				if l.ProviderAccount == "" {
					// The seller is not settleable yet. Their share simply stays
					// with the provider until they are activated, rather than
					// being routed to the platform, which would make us the
					// recipient of someone else's money.
					continue
				}
				splits = append(splits, payments.SplitLine{
					SellerReference:   l.SellerPublicID,
					ProviderAccountID: l.ProviderAccount,
					Amount:            l.Breakdown.SellerNet,
					OnHold:            true,
					HoldUntil:         l.SettlementHoldUntil,
					Notes: map[string]string{
						"order": o.PublicID, "item": l.ItemPublicID,
					},
				})
			}
		}

		res, err := s.provider.CreatePayment(ctx, payments.CreatePaymentRequest{
			OrderReference: o.PublicID,
			Amount:         o.GrandTotal,
			Splits:         splits,
			Description:    "Order " + o.Number,
			IdempotencyKey: "payment:" + o.PublicID,
			Notes:          map[string]string{"order": o.PublicID, "order_number": o.Number},
		})
		if err != nil {
			if s.m != nil {
				s.m.PaymentOperations.Inc(s.provider.Name(), "begin_payment", "error")
			}
			return mapProviderError(err)
		}

		intentID := ids.NewUUIDv7()
		splitJSON := splitsToJSON(splits)
		if _, err := tx.Exec(ctx, `
			INSERT INTO payment_intents (id, public_id, order_id, provider, provider_intent_id,
			                             amount_minor, currency, status, split_instruction, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,'created',$8,$9)`,
			intentID, ids.NewPublic(ids.PrefixPayment), o.ID, s.provider.Name(), res.ProviderIntentID,
			o.GrandTotal.Minor(), string(o.Currency), splitJSON, s.clk.Now().Add(30*time.Minute),
		); err != nil {
			return fmt.Errorf("orders: insert intent: %w", err)
		}

		if o.Status == StatusDraft || o.Status == StatusPaymentFailed {
			if err := s.transition(ctx, tx, o.ID, o.Status, StatusAwaitingPayment, "user", &buyerID, "payment started"); err != nil {
				return err
			}
		}

		handoff = &PaymentHandoff{
			OrderPublicID:    o.PublicID,
			ProviderIntentID: res.ProviderIntentID,
			Provider:         s.provider.Name(),
			Amount:           o.GrandTotal,
			CheckoutParams:   res.CheckoutParams,
			ExpiresAt:        s.clk.Now().Add(30 * time.Minute),
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return handoff, nil
}

// transition moves an order between states, guarded by the state machine in
// order_transitions_allowed.
//
// stampColumn, when given, is written in the SAME statement as the status. That
// is load-bearing: constraints such as "a paid order has a paid_at" are row
// checks, so setting the status first and the timestamp second would fail.
func (s *Service) transition(ctx context.Context, tx db.Tx, orderID ids.UUID, from, to Status, actorKind string, actorID *ids.UUID, reason string) error {
	return s.transitionStamped(ctx, tx, orderID, from, to, actorKind, actorID, reason, "", time.Time{})
}

func (s *Service) transitionStamped(ctx context.Context, tx db.Tx, orderID ids.UUID, from, to Status, actorKind string, actorID *ids.UUID, reason, stampColumn string, stamp time.Time) error {
	var actor any
	if actorID != nil {
		actor = *actorID
	}
	stmt := `UPDATE orders SET status = $2 WHERE id = $1 AND status = $3`
	args := []any{orderID, string(to), string(from)}
	if stampColumn != "" {
		// The column name is chosen from a closed set in this package; it is
		// never derived from input.
		switch stampColumn {
		case "paid_at", "fulfilled_at", "completed_at", "cancelled_at":
		default:
			return fmt.Errorf("orders: %q is not a stampable column", stampColumn)
		}
		//archcheck:allow SQL is parameterised -- stampColumn is matched against a closed set in the switch above and never derives from input; values still travel as bind parameters.
		stmt = `UPDATE orders SET status = $2, ` + stampColumn + ` = COALESCE(` + stampColumn + `, $4) WHERE id = $1 AND status = $3`
		args = append(args, stamp)
	}
	tag, err := tx.Exec(ctx, stmt, args...)
	if err != nil {
		if msg, ok := db.IsRaisedException(err); ok {
			return problem.Conflict(problem.TypeStateTransition, msg)
		}
		return fmt.Errorf("orders: transition %s -> %s: %w", from, to, err)
	}
	if tag.RowsAffected() == 0 {
		// Another writer moved the order first. This is normal under webhook
		// and callback racing; the caller decides whether that is an error.
		return errConcurrentTransition
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO order_events (order_id, from_status, to_status, actor_kind, actor_id, reason)
		VALUES ($1,$2,$3,$4,$5,$6)`, orderID, string(from), string(to), actorKind, actor, reason)
	return err
}

var errConcurrentTransition = errors.New("orders: the order was moved concurrently")

func mapProviderError(err error) error {
	switch {
	case errors.Is(err, payments.ErrProviderUnavailable):
		return problem.Unavailable("The payment provider is temporarily unavailable. Please try again in a moment.", 10)
	case errors.Is(err, payments.ErrCurrencyUnsupported):
		return problem.Validation(problem.FieldError{
			Field: "currency", Code: "unsupported", Detail: "That currency cannot be processed."})
	case errors.Is(err, payments.ErrAccountNotActivated):
		return problem.Conflict(problem.TypeSettlementBlocked,
			"This seller cannot receive settlement yet. Their payout account is still being verified.")
	case errors.Is(err, payments.ErrProviderRejected):
		return problem.New(402, problem.TypePaymentFailed, "Payment could not be started",
			"The payment provider declined this request. No money has been taken.").WithCause(err)
	}
	return problem.Internal(err)
}

func splitsToJSON(splits []payments.SplitLine) []map[string]any {
	out := make([]map[string]any, 0, len(splits))
	for _, s := range splits {
		out = append(out, map[string]any{
			"seller":     s.SellerReference,
			"account":    s.ProviderAccountID,
			"amount":     s.Amount.Minor(),
			"currency":   string(s.Amount.Currency()),
			"on_hold":    s.OnHold,
			"hold_until": s.HoldUntil.Format(time.RFC3339),
		})
	}
	return out
}

func fyStart(t time.Time) time.Time { return tax.FinancialYearStart(t) }

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullIfZero(v int) any {
	if v == 0 {
		return nil
	}
	return v
}
