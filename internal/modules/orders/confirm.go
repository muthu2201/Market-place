package orders

import (
	"context"
	"fmt"
	"time"

	"github.com/muthu2201/market-place/internal/modules/audit"
	"github.com/muthu2201/market-place/internal/modules/ledger"
	"github.com/muthu2201/market-place/internal/modules/payments"
	"github.com/muthu2201/market-place/internal/outbox"
	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/ids"
	"github.com/muthu2201/market-place/internal/platform/money"
	"github.com/muthu2201/market-place/internal/platform/problem"
)

// ConfirmPayment verifies the provider's signature and, if it holds, records
// the capture in one transaction: order status, payment row, ledger entries,
// licences, invoices, seller turnover and the outbox events.
//
// Everything happens together or not at all. That atomicity is why a buyer can
// never be charged without receiving an entitlement, and why the ledger can
// never disagree with the order table.
func (s *Service) ConfirmPayment(ctx context.Context, req ConfirmRequest) (*ConfirmResult, error) {
	// Signature verification happens BEFORE any database work, because an
	// unverified callback is untrusted input and must not be allowed to take
	// locks or create rows.
	verify, err := s.provider.VerifyPayment(ctx, payments.VerifyPaymentRequest{
		ProviderIntentID:  req.ProviderIntentID,
		ProviderPaymentID: req.ProviderPaymentID,
		Signature:         req.Signature,
	})
	if err != nil {
		return nil, problem.Internal(err)
	}
	if !verify.Valid {
		if s.m != nil {
			s.m.PaymentOperations.Inc(s.provider.Name(), "verify", "invalid_signature")
		}
		// Recorded as a security event: a failed signature on a payment
		// callback is an attempted forgery, not a user mistake.
		_ = s.audit.Record(ctx, s.db, audit.Event{
			ActorKind: audit.ActorUser, ActorID: &req.BuyerID, ActorIP: req.IP,
			Action: "payment.signature_rejected", SubjectType: "order", SubjectID: req.OrderPublicID,
			Metadata: map[string]any{"reason": verify.Reason, "provider_payment_id": req.ProviderPaymentID},
		})
		return nil, problem.New(402, problem.TypePaymentFailed, "Payment could not be verified",
			"The payment confirmation did not carry a valid signature and has been rejected.")
	}

	// The provider is the source of truth for what was actually captured. The
	// browser only tells us to go and look.
	record, err := s.provider.ReconcilePayment(ctx, req.ProviderPaymentID)
	if err != nil {
		return nil, mapProviderError(err)
	}

	var result ConfirmResult
	err = s.db.InTx(ctx, db.TxOptions{Name: "confirm_payment"}, func(ctx context.Context, tx db.Tx) error {
		result = ConfirmResult{}
		o, err := s.LoadOrder(ctx, tx, req.OrderPublicID)
		if err != nil {
			return err
		}
		if !req.BuyerID.IsZero() && o.BuyerID != req.BuyerID {
			return problem.NotFound("Order not found.")
		}

		// Replay: the callback posted twice, or the webhook arrived first.
		if o.Status == StatusPaid || o.Status == StatusFulfilled || o.Status == StatusCompleted {
			licenses, err := s.loadLicenses(ctx, tx, o.ID)
			if err != nil {
				return err
			}
			result = ConfirmResult{Order: o, Licenses: licenses, AlreadyConfirmed: true}
			return nil
		}
		if o.Status != StatusAwaitingPayment {
			return problem.Conflict(problem.TypeStateTransition,
				"This order is not awaiting payment.")
		}

		// The amount the provider captured must match the order exactly. A
		// mismatch is either a bug or an attack, and either way is refused.
		if !record.Amount.Equal(o.GrandTotal) {
			_ = s.audit.Record(ctx, tx, audit.Event{
				ActorKind: audit.ActorSystem, Action: "payment.amount_mismatch",
				SubjectType: "order", SubjectID: o.PublicID,
				Metadata: map[string]any{
					"expected_minor": o.GrandTotal.Minor(), "captured_minor": record.Amount.Minor(),
				},
			})
			return problem.Conflict(problem.TypePaymentFailed,
				"The captured amount does not match this order. The payment has not been accepted.")
		}
		if record.Status != payments.PaymentCaptured && record.Status != payments.PaymentAuthorized {
			return problem.New(402, problem.TypePaymentFailed, "Payment not completed",
				"The provider reports this payment as "+string(record.Status)+".")
		}

		// Capture if the provider left it authorised.
		if record.Status == payments.PaymentAuthorized {
			captured, err := s.provider.CapturePayment(ctx, payments.CaptureRequest{
				ProviderPaymentID: record.ProviderPaymentID,
				Amount:            o.GrandTotal,
				IdempotencyKey:    "capture:" + o.PublicID,
			})
			if err != nil {
				return mapProviderError(err)
			}
			record = captured
		}

		return s.recordCapture(ctx, tx, o, record, req.IP, &req.BuyerID, &result)
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// recordCapture performs the whole post-payment write. It is shared by the
// browser callback and the webhook path so the two can never diverge.
func (s *Service) recordCapture(ctx context.Context, tx db.Tx, o *Order, record payments.PaymentRecord, ip string, actor *ids.UUID, out *ConfirmResult) error {
	now := s.clk.Now()

	paymentID := ids.NewUUIDv7()
	var fee, feeTax any
	if record.Fee != nil {
		fee = record.Fee.Minor()
	}
	if record.Tax != nil {
		feeTax = record.Tax.Minor()
	}
	method := record.Method
	if method == "" {
		method = "unknown"
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO payments (id, public_id, order_id, provider, provider_payment_id, method,
		                      card_network, amount_minor, currency, provider_fee_minor, provider_tax_minor,
		                      status, captured_at, signature_verified, raw_provider_status)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'captured',$12,TRUE,$13)
		ON CONFLICT (provider, provider_payment_id) DO NOTHING`,
		paymentID, ids.NewPublic(ids.PrefixPayment), o.ID, s.provider.Name(), record.ProviderPaymentID,
		method, nullIfEmpty(record.CardNetwork), record.Amount.Minor(), string(record.Amount.Currency()),
		fee, feeTax, now, string(record.Status),
	); err != nil {
		return fmt.Errorf("orders: insert payment: %w", err)
	}
	// Resolve the real id: the insert may have been a no-op on replay.
	if err := tx.QueryRow(ctx,
		`SELECT id FROM payments WHERE provider = $1 AND provider_payment_id = $2`,
		s.provider.Name(), record.ProviderPaymentID).Scan(&paymentID); err != nil {
		return fmt.Errorf("orders: resolve payment: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		UPDATE payment_intents SET status = 'succeeded'
		 WHERE order_id = $1 AND provider_intent_id = $2`, o.ID, record.ProviderIntentID); err != nil {
		return fmt.Errorf("orders: settle intent: %w", err)
	}

	if err := s.postCaptureLedger(ctx, tx, o, record, paymentID); err != nil {
		return err
	}

	if err := s.transitionStamped(ctx, tx, o.ID, o.Status, StatusPaid, "provider", actor,
		"payment captured", "paid_at", now); err != nil {
		// A concurrent writer (typically the webhook racing the callback) wins
		// and does the work; this transaction rolls back and the caller sees
		// the replay path on retry.
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE order_items SET status = 'paid' WHERE order_id = $1`, o.ID); err != nil {
		return err
	}

	licenses, err := s.issueLicenses(ctx, tx, o, now)
	if err != nil {
		return err
	}
	if err := s.recordTransfers(ctx, tx, o, paymentID); err != nil {
		return err
	}
	if err := s.updateTurnover(ctx, tx, o, now); err != nil {
		return err
	}
	if err := s.issueInvoices(ctx, tx, o, now); err != nil {
		return err
	}

	if err := s.transitionStamped(ctx, tx, o.ID, StatusPaid, StatusFulfilled, "system", nil,
		"entitlements issued", "fulfilled_at", now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE order_items SET status = 'fulfilled', fulfilled_at = $2 WHERE order_id = $1`, o.ID, now); err != nil {
		return err
	}
	for _, l := range o.Lines {
		if _, err := tx.Exec(ctx,
			`UPDATE product_variants SET sales_count = sales_count + 1 WHERE id = $1`, l.VariantID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE products SET sales_count = sales_count + 1 WHERE id = $1`, l.ProductID); err != nil {
			return err
		}
	}

	if _, err := outbox.PublishJSON(ctx, tx, outbox.TopicOrderPaid, "order", o.PublicID, map[string]any{
		"order_public_id": o.PublicID, "order_number": o.Number,
		"buyer_id": o.BuyerID.String(), "total_minor": o.GrandTotal.Minor(),
		"currency": string(o.Currency), "paid_at": now.Format(time.RFC3339),
	}, o.PublicID); err != nil {
		return err
	}
	if _, err := outbox.PublishJSON(ctx, tx, outbox.TopicOrderFulfilled, "order", o.PublicID, map[string]any{
		"order_public_id": o.PublicID, "licenses": len(licenses),
	}, o.PublicID); err != nil {
		return err
	}

	if err := s.audit.Record(ctx, tx, audit.Event{
		ActorKind: audit.ActorProvider, ActorIP: ip,
		Action: "order.paid", SubjectType: "order", SubjectID: o.PublicID,
		Metadata: map[string]any{
			"provider": s.provider.Name(), "provider_payment_id": record.ProviderPaymentID,
			"amount_minor": record.Amount.Minor(), "method": method,
		},
	}); err != nil {
		return err
	}

	o.Status = StatusFulfilled
	o.PaidAt = &now
	out.Order = o
	out.Licenses = licenses
	return nil
}

// postCaptureLedger writes the two journal entries a capture produces.
//
// Entry one distributes what the buyer paid:
//
//	DR provider clearing        buyer total
//	  CR seller payable         seller net, per seller
//	  CR commission income      platform commission
//	  CR GST output payable     GST on that commission
//	  CR TCS payable            collected under s.52
//	  CR TDS payable            deducted under s.194-O
//
// Entry two records the processing cost the provider deducts:
//
//	DR processing fee expense   fee
//	DR GST input credit         GST on the fee
//	  CR provider clearing      fee plus its GST
func (s *Service) postCaptureLedger(ctx context.Context, tx db.Tx, o *Order, record payments.PaymentRecord, paymentID ids.UUID) error {
	cur := o.Currency
	clearing, err := s.ledger.AccountByCode(ctx, tx, s.clearingAccountCode())
	if err != nil {
		return err
	}
	commissionAcct, err := s.ledger.AccountByCode(ctx, tx, "platform.income.commission")
	if err != nil {
		return err
	}
	gstOutput, err := s.ledger.AccountByCode(ctx, tx, "platform.payable.gst_output")
	if err != nil {
		return err
	}
	tcsAcct, err := s.ledger.AccountByCode(ctx, tx, "platform.payable.tcs")
	if err != nil {
		return err
	}
	tdsAcct, err := s.ledger.AccountByCode(ctx, tx, "platform.payable.tds_194o")
	if err != nil {
		return err
	}

	lines := []ledger.Line{{
		AccountID: clearing, Direction: ledger.Debit, Amount: o.GrandTotal,
		Memo: "captured for order " + o.Number,
	}}

	totalCommission := money.Zero(cur)
	totalCommissionGST := money.Zero(cur)
	totalTCS := money.Zero(cur)
	totalTDS := money.Zero(cur)

	for _, l := range o.Lines {
		payable, err := s.ledger.SellerAccount(ctx, tx, l.SellerID, "payable", cur)
		if err != nil {
			return err
		}
		if l.Breakdown.SellerNet.IsPositive() {
			lines = append(lines, ledger.Line{
				AccountID: payable, Direction: ledger.Credit, Amount: l.Breakdown.SellerNet,
				Memo: "net due to seller for " + l.ItemPublicID,
			})
		}
		if totalCommission, err = totalCommission.Add(l.Breakdown.Commission); err != nil {
			return err
		}
		if totalCommissionGST, err = totalCommissionGST.Add(l.Breakdown.CommissionGST); err != nil {
			return err
		}
		if totalTCS, err = totalTCS.Add(l.Breakdown.TCS); err != nil {
			return err
		}
		if totalTDS, err = totalTDS.Add(l.Breakdown.TDS); err != nil {
			return err
		}
	}

	for _, e := range []struct {
		acct ids.UUID
		amt  money.Money
		memo string
	}{
		{commissionAcct, totalCommission, "platform commission"},
		{gstOutput, totalCommissionGST, "GST on commission"},
		{tcsAcct, totalTCS, "TCS collected under s.52 CGST"},
		{tdsAcct, totalTDS, "TDS deducted under s.194-O"},
	} {
		if e.amt.IsPositive() {
			lines = append(lines, ledger.Line{
				AccountID: e.acct, Direction: ledger.Credit, Amount: e.amt, Memo: e.memo,
			})
		}
	}

	if _, err := s.ledger.Post(ctx, tx, ledger.Entry{
		Kind: ledger.KindOrderCapture, Currency: cur, OccurredAt: s.clk.Now(),
		Description:   "Capture for order " + o.Number,
		ReferenceType: "order", ReferenceID: o.PublicID,
		IdempotencyKey: "capture:" + o.PublicID + ":" + record.ProviderPaymentID,
		Metadata: map[string]any{
			"provider": s.provider.Name(), "payment_id": paymentID.String(),
			"provider_payment_id": record.ProviderPaymentID,
		},
		Lines: lines,
	}); err != nil {
		return err
	}

	// Provider fee. Where the provider has not yet reported it, the platform's
	// configured blended rate is used and reconciliation corrects the drift.
	feeAmount := money.Zero(cur)
	feeTax := money.Zero(cur)
	if record.Fee != nil {
		feeAmount = *record.Fee
	} else {
		if feeAmount, err = o.GrandTotal.ApplyBasisPoints(s.pspFeeBps, money.HalfUp); err != nil {
			return err
		}
	}
	if record.Tax != nil {
		feeTax = *record.Tax
	} else {
		if feeTax, err = feeAmount.ApplyBasisPoints(s.pspFeeGSTBps, money.HalfUp); err != nil {
			return err
		}
	}
	if !feeAmount.IsPositive() && !feeTax.IsPositive() {
		return nil
	}

	feeExpense, err := s.ledger.AccountByCode(ctx, tx, "platform.expense.psp_fee")
	if err != nil {
		return err
	}
	inputCredit, err := s.ledger.AccountByCode(ctx, tx, "platform.input_credit.gst")
	if err != nil {
		return err
	}
	feeTotal, err := feeAmount.Add(feeTax)
	if err != nil {
		return err
	}
	feeLines := []ledger.Line{}
	if feeAmount.IsPositive() {
		feeLines = append(feeLines, ledger.Line{
			AccountID: feeExpense, Direction: ledger.Debit, Amount: feeAmount, Memo: "provider processing fee",
		})
	}
	if feeTax.IsPositive() {
		feeLines = append(feeLines, ledger.Line{
			AccountID: inputCredit, Direction: ledger.Debit, Amount: feeTax, Memo: "GST input credit on processing fee",
		})
	}
	feeLines = append(feeLines, ledger.Line{
		AccountID: clearing, Direction: ledger.Credit, Amount: feeTotal, Memo: "deducted by provider",
	})

	_, err = s.ledger.Post(ctx, tx, ledger.Entry{
		Kind: ledger.KindPSPFee, Currency: cur, OccurredAt: s.clk.Now(),
		Description:   "Processing fee for order " + o.Number,
		ReferenceType: "order", ReferenceID: o.PublicID,
		IdempotencyKey: "psp_fee:" + o.PublicID + ":" + record.ProviderPaymentID,
		Lines:          feeLines,
	})
	return err
}

func (s *Service) clearingAccountCode() string {
	switch s.provider.Name() {
	case "razorpay_route":
		return "platform.clearing.razorpay"
	case "mor":
		return "platform.clearing.mor"
	}
	return "platform.clearing.bridge"
}

// issueLicenses creates the entitlement rows. This is the ONLY thing that
// authorises a download, and it is written in the same transaction as the
// payment, so an entitlement cannot exist without a capture behind it.
func (s *Service) issueLicenses(ctx context.Context, tx db.Tx, o *Order, now time.Time) ([]IssuedLicense, error) {
	out := make([]IssuedLicense, 0, len(o.Lines))
	for _, l := range o.Lines {
		var licenseType, terms string
		var days *int
		if err := tx.QueryRow(ctx, `
			SELECT i.license_type_snapshot, i.license_terms_snapshot, p.license_duration_days
			  FROM order_items i JOIN products p ON p.id = i.product_id
			 WHERE i.id = $1`, l.ItemID).Scan(&licenseType, &terms, &days); err != nil {
			return nil, fmt.Errorf("orders: read licence terms: %w", err)
		}

		var expires any
		var expiresAt *time.Time
		if days != nil && *days > 0 {
			t := now.AddDate(0, 0, *days)
			expires, expiresAt = t, &t
		}
		publicID := ids.NewPublic(ids.PrefixLicense)
		limit := s.platform.DownloadsPerLicense
		if limit <= 0 {
			limit = 10
		}

		if _, err := tx.Exec(ctx, `
			INSERT INTO licenses (id, public_id, order_item_id, user_id, product_id, variant_id,
			                      license_type, terms_snapshot, access_expires_at, download_limit)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
			ON CONFLICT (order_item_id) DO NOTHING`,
			ids.NewUUIDv7(), publicID, l.ItemID, o.BuyerID, l.ProductID, l.VariantID,
			licenseType, terms, expires, limit,
		); err != nil {
			return nil, fmt.Errorf("orders: issue licence: %w", err)
		}
		if _, err := outbox.PublishJSON(ctx, tx, outbox.TopicLicenseIssued, "license", publicID, map[string]any{
			"license_public_id": publicID, "order_public_id": o.PublicID,
			"user_id": o.BuyerID.String(), "product_id": l.ProductID.String(),
		}, o.PublicID); err != nil {
			return nil, err
		}
		out = append(out, IssuedLicense{
			PublicID: publicID, ProductTitle: l.Title, LicenseType: licenseType,
			DownloadLimit: limit, ExpiresAt: expiresAt,
		})
	}
	return out, nil
}

func (s *Service) loadLicenses(ctx context.Context, q db.Querier, orderID ids.UUID) ([]IssuedLicense, error) {
	rows, err := q.Query(ctx, `
		SELECT l.public_id, i.title_snapshot, l.license_type, l.download_limit, l.access_expires_at
		  FROM licenses l JOIN order_items i ON i.id = l.order_item_id
		 WHERE i.order_id = $1 ORDER BY l.issued_at`, orderID)
	if err != nil {
		return nil, fmt.Errorf("orders: load licences: %w", err)
	}
	defer rows.Close()
	var out []IssuedLicense
	for rows.Next() {
		var l IssuedLicense
		if err := rows.Scan(&l.PublicID, &l.ProductTitle, &l.LicenseType, &l.DownloadLimit, &l.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// recordTransfers writes the settlement rows. Where split settlement is active
// the provider has already been instructed; where it is not, these rows are the
// instruction the payout batch will act on. Either way the seller's share is on
// hold until the protection window closes.
func (s *Service) recordTransfers(ctx context.Context, tx db.Tx, o *Order, paymentID ids.UUID) error {
	for _, l := range o.Lines {
		if !l.Breakdown.SellerNet.IsPositive() {
			continue
		}
		status := "on_hold"
		account := l.ProviderAccount
		if account == "" {
			// Not settleable yet: the seller's KYC or linked account is not
			// ready. The money stays with the provider and the row records
			// what is owed, so nothing is lost and nothing is misdirected.
			status = "pending"
			account = "pending_activation"
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO payment_transfers (id, public_id, payment_id, order_item_id, seller_id,
			                               provider, provider_account_id, amount_minor, currency,
			                               status, hold_until)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
			ON CONFLICT (order_item_id) DO NOTHING`,
			ids.NewUUIDv7(), ids.NewPublic(ids.PrefixTransfer), paymentID, l.ItemID, l.SellerID,
			s.provider.Name(), account, l.Breakdown.SellerNet.Minor(), string(o.Currency),
			status, l.SettlementHoldUntil,
		); err != nil {
			return fmt.Errorf("orders: record transfer: %w", err)
		}
	}
	return nil
}

// updateTurnover records the movements that drive the s.194-O threshold, the
// GST registration relief and Route eligibility.
//
// Writes are append-only deltas rather than updates to an aggregate row. A
// single platform-wide counter that every order touches is a guaranteed
// bottleneck: under load it either serialises every checkout or aborts them,
// and the load test showed it doing the latter. The worker folds deltas into
// the aggregates, and readers add the un-rolled tail, which is the same shape
// that already works for ledger balances.
func (s *Service) updateTurnover(ctx context.Context, tx db.Tx, o *Order, now time.Time) error {
	fy := fyStart(now)
	for _, l := range o.Lines {
		if _, err := tx.Exec(ctx, `
			INSERT INTO turnover_deltas (scope, seller_id, fy_start, currency,
			                             gross_supply, taxable_supply, tds_deducted,
			                             tcs_collected, order_count)
			VALUES ('seller',$1,$2,$3,$4,$4,$5,$6,1)`,
			l.SellerID, fy, string(o.Currency), l.Breakdown.ListPrice.Minor(),
			l.Breakdown.TDS.Minor(), l.Breakdown.TCS.Minor()); err != nil {
			return fmt.Errorf("orders: record seller turnover: %w", err)
		}
	}

	domestic := o.ItemsTotal.Minor()
	export := int64(0)
	if o.PlaceOfSupplyCountry != "IN" {
		domestic, export = 0, o.ItemsTotal.Minor()
	}
	var commission int64
	for _, l := range o.Lines {
		commission += l.Breakdown.Commission.Minor()
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO turnover_deltas (scope, fy_start, currency, gross_supply, export_supply,
		                             commission, order_count)
		VALUES ('platform',$1,$2,$3,$4,$5,1)`,
		fy, string(o.Currency), domestic, export, commission); err != nil {
		return fmt.Errorf("orders: record platform turnover: %w", err)
	}
	return nil
}

// issueInvoices writes the two documents a sale produces: the seller's tax
// invoice to the buyer, and the platform's commission invoice to the seller.
// They are separate supplies with separate GSTINs and are never combined.
func (s *Service) issueInvoices(ctx context.Context, tx db.Tx, o *Order, now time.Time) error {
	fy := fyStart(now)
	for _, l := range o.Lines {
		var sellerGSTIN *string
		var sellerName string
		var sellerState *int
		if err := tx.QueryRow(ctx,
			`SELECT gstin, display_name, state_code FROM sellers WHERE id = $1`, l.SellerID,
		).Scan(&sellerGSTIN, &sellerName, &sellerState); err != nil {
			return fmt.Errorf("orders: read seller for invoice: %w", err)
		}

		// The seller's supply to the buyer.
		if sellerGSTIN != nil {
			number, err := s.invoiceNumber(ctx, tx, "seller_supply", fy, "INV")
			if err != nil {
				return err
			}
			var state any
			if o.PlaceOfSupplyState > 0 {
				state = o.PlaceOfSupplyState
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO invoices (id, public_id, kind, invoice_number, fy_start, order_id, order_item_id,
				                      seller_id, buyer_id, supplier_gstin, supplier_name, supplier_state,
				                      recipient_gstin, place_of_supply_country, place_of_supply_state,
				                      currency, taxable_value_minor, cgst_minor, sgst_minor, igst_minor, total_minor)
				VALUES ($1,$2,'seller_supply',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,
				ids.NewUUIDv7(), ids.NewPublic(ids.PrefixInvoice), number, fy, o.ID, l.ItemID,
				l.SellerID, o.BuyerID, sellerGSTIN, sellerName, sellerState,
				nil, o.PlaceOfSupplyCountry, state, string(o.Currency),
				l.Breakdown.ListPrice.Minor(), l.Breakdown.CGST.Minor(),
				l.Breakdown.SGST.Minor(), l.Breakdown.IGST.Minor(), l.Breakdown.BuyerTotal.Minor(),
			); err != nil {
				return fmt.Errorf("orders: issue seller invoice: %w", err)
			}
		}

		// The platform's commission invoice to the seller. Place of supply is
		// the seller's state, and the split follows from that.
		if l.Breakdown.Commission.IsPositive() {
			number, err := s.invoiceNumber(ctx, tx, "platform_commission", fy, "COM")
			if err != nil {
				return err
			}
			cgst, sgst, igst := splitCommissionGST(l.Breakdown.CommissionGST, s.tax.PlatformStateCode, sellerState)
			total, err := l.Breakdown.Commission.Add(l.Breakdown.CommissionGST)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO invoices (id, public_id, kind, invoice_number, fy_start, order_id, order_item_id,
				                      seller_id, supplier_gstin, supplier_name, supplier_state,
				                      recipient_gstin, place_of_supply_country, place_of_supply_state,
				                      currency, taxable_value_minor, cgst_minor, sgst_minor, igst_minor,
				                      total_minor, sac_code)
				VALUES ($1,$2,'platform_commission',$3,$4,$5,$6,$7,$8,$9,$10,$11,'IN',$12,$13,$14,$15,$16,$17,$18,'998599')`,
				ids.NewUUIDv7(), ids.NewPublic(ids.PrefixInvoice), number, fy, o.ID, l.ItemID,
				l.SellerID, nullIfEmpty(s.tax.PlatformGSTINOrEmpty()), "Marketplace", s.tax.PlatformStateCode,
				sellerGSTIN, sellerState, string(o.Currency),
				l.Breakdown.Commission.Minor(), cgst.Minor(), sgst.Minor(), igst.Minor(), total.Minor(),
			); err != nil {
				return fmt.Errorf("orders: issue commission invoice: %w", err)
			}
		}
	}
	return nil
}

func (s *Service) invoiceNumber(ctx context.Context, tx db.Tx, kind string, fy time.Time, prefix string) (string, error) {
	var n string
	if err := tx.QueryRow(ctx, `SELECT next_invoice_number($1, $2::date, $3)`, kind, fy, prefix).Scan(&n); err != nil {
		return "", fmt.Errorf("orders: allocate %s invoice number: %w", kind, err)
	}
	return n, nil
}

// splitCommissionGST divides GST on the commission into CGST+SGST when the
// platform and the seller are in the same state, or IGST when they are not.
func splitCommissionGST(gst money.Money, platformState int, sellerState *int) (cgst, sgst, igst money.Money) {
	zero := money.Zero(gst.Currency())
	if sellerState != nil && *sellerState == platformState {
		half, err := gst.MulRatio(1, 2, money.Down)
		if err != nil {
			return zero, zero, gst
		}
		other, err := gst.Sub(half)
		if err != nil {
			return zero, zero, gst
		}
		// Halves can differ by one minor unit on an odd amount; the larger
		// share is assigned to CGST so the two always sum back to the whole.
		if other.Minor() > half.Minor() {
			return other, half, zero
		}
		return half, other, zero
	}
	return zero, zero, gst
}
