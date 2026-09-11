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

// RefundOutcome reports what a refund did, including who ends up bearing which
// cost. Being explicit about that is what keeps the unit economics honest.
type RefundOutcome struct {
	RefundPublicID string
	Amount         money.Money
	// ProcessingFeeRetained is the provider cost the network does NOT return on
	// a refund. The platform absorbs it; pretending it is zero is how a
	// marketplace discovers too late that its refund policy is loss-making.
	ProcessingFeeRetained money.Money
	// SellerRecovery says how the seller's share was recovered.
	//   transfer_reversal        - the settlement had not left yet
	//   future_settlement_offset - it had, so it is netted from the next payout
	SellerRecovery string
	OrderStatus    Status
}

// Refund reverses all or part of an order line.
//
// Three rules are enforced here because each has bitten real marketplaces:
//
//  1. A refund policy declared at purchase is honoured. "No refund once
//     downloaded" is enforceable precisely because it was disclosed and because
//     the download is evidenced; it is not applied retroactively.
//  2. The processing fee is not recoverable and is recorded as a platform cost.
//  3. If the seller has already been settled, the money is recovered from their
//     NEXT settlement rather than by creating an internal debit balance.
func (s *Service) Refund(ctx context.Context, req RefundRequest) (*RefundOutcome, error) {
	var out RefundOutcome

	err := s.db.InTx(ctx, db.TxOptions{Name: "refund"}, func(ctx context.Context, tx db.Tx) error {
		out = RefundOutcome{}
		o, err := s.LoadOrder(ctx, tx, req.OrderPublicID)
		if err != nil {
			return err
		}
		if !req.ActorIsStaff && o.BuyerID != req.RequestedBy {
			return problem.NotFound("Order not found.")
		}
		switch o.Status {
		case StatusPaid, StatusFulfilled, StatusCompleted, StatusPartiallyRefunded, StatusDisputed:
		default:
			return problem.Conflict(problem.TypeStateTransition,
				"This order is not in a state that can be refunded.")
		}

		line, err := s.pickRefundLine(o, req.ItemPublicID)
		if err != nil {
			return err
		}

		// Refund eligibility. A staff member can always override, and the
		// override is audited.
		if !req.ActorIsStaff {
			if err := s.checkRefundEligibility(ctx, tx, line); err != nil {
				return err
			}
		}

		amount := line.Breakdown.BuyerTotal
		if req.Amount != nil {
			amount = *req.Amount
			if amount.Currency() != o.Currency {
				return problem.Validation(problem.FieldError{
					Field: "amount", Code: "currency_mismatch", Detail: "The refund currency must match the order."})
			}
			if !amount.IsPositive() {
				return problem.Validation(problem.FieldError{
					Field: "amount", Code: "invalid", Detail: "A refund must be a positive amount."})
			}
			if cmp, _ := amount.Cmp(line.Breakdown.BuyerTotal); cmp > 0 {
				return problem.Validation(problem.FieldError{
					Field: "amount", Code: "too_large", Detail: "A refund cannot exceed what was paid for this item."})
			}
		}

		var alreadyRefunded int64
		if err := tx.QueryRow(ctx,
			`SELECT refunded_minor FROM order_items WHERE id = $1 FOR UPDATE`, line.ItemID).Scan(&alreadyRefunded); err != nil {
			return fmt.Errorf("orders: read refunded total: %w", err)
		}
		if alreadyRefunded+amount.Minor() > line.Breakdown.BuyerTotal.Minor() {
			return problem.Conflict("", "That would refund more than was paid for this item.")
		}

		var providerPaymentID string
		var paymentID ids.UUID
		var feeMinor *int64
		if err := tx.QueryRow(ctx, `
			SELECT id, provider_payment_id, provider_fee_minor FROM payments
			 WHERE order_id = $1 AND status IN ('captured','partially_refunded') LIMIT 1`, o.ID,
		).Scan(&paymentID, &providerPaymentID, &feeMinor); err != nil {
			if db.IsNoRows(err) {
				return problem.Conflict("", "No captured payment was found for this order.")
			}
			return fmt.Errorf("orders: read payment: %w", err)
		}

		// Is the seller's share still with the provider, or already gone?
		var transferStatus string
		var providerTransferID *string
		err = tx.QueryRow(ctx,
			`SELECT status, provider_transfer_id FROM payment_transfers WHERE order_item_id = $1 FOR UPDATE`,
			line.ItemID).Scan(&transferStatus, &providerTransferID)
		if err != nil && !db.IsNoRows(err) {
			return fmt.Errorf("orders: read transfer: %w", err)
		}
		settledAway := transferStatus == "processed"
		recovery := "transfer_reversal"
		if settledAway {
			recovery = "future_settlement_offset"
		}

		full := amount.Equal(line.Breakdown.BuyerTotal)
		providerRefund, err := s.provider.RequestRefund(ctx, payments.RefundRequest{
			ProviderPaymentID: providerPaymentID,
			Amount:            amount,
			Reason:            req.Reason,
			ReverseSplits:     full && !settledAway && s.provider.Capabilities().TransferReversal,
			IdempotencyKey:    "refund:" + line.ItemPublicID + ":" + amount.Decimal(),
			Notes:             map[string]string{"order": o.PublicID, "item": line.ItemPublicID},
		})
		if err != nil {
			return mapProviderError(err)
		}

		refundPublicID := ids.NewPublic(ids.PrefixRefund)
		retained := s.retainedProcessingFee(o, amount, feeMinor)

		if _, err := tx.Exec(ctx, `
			INSERT INTO refunds (id, public_id, order_id, order_item_id, payment_id, provider,
			                     provider_refund_id, amount_minor, currency, reason, status,
			                     psp_fee_retained_minor, seller_recovery_mode, requested_by, note, settled_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'succeeded',$11,$12,$13,$14, now())`,
			ids.NewUUIDv7(), refundPublicID, o.ID, line.ItemID, paymentID, s.provider.Name(),
			nullIfEmpty(providerRefund.ProviderRefundID), amount.Minor(), string(o.Currency),
			req.Reason, retained.Minor(), recovery, req.RequestedBy, nullIfEmpty(req.Note),
		); err != nil {
			return fmt.Errorf("orders: insert refund: %w", err)
		}

		// Proportion of the line being refunded, used to scale each component
		// so that a partial refund returns a proportionate share of tax,
		// commission and statutory collections rather than an arbitrary split.
		if err := s.postRefundLedger(ctx, tx, o, line, amount, settledAway, refundPublicID); err != nil {
			return err
		}

		if settledAway {
			sellerShare, err := scaleToRefund(line.Breakdown.SellerNet, amount, line.Breakdown.BuyerTotal)
			if err != nil {
				return err
			}
			if sellerShare.IsPositive() {
				if _, err := tx.Exec(ctx, `
					INSERT INTO settlement_offsets (id, public_id, seller_id, origin, origin_id,
					                                amount_minor, currency, note)
					VALUES ($1,$2,$3,'refund',$4,$5,$6,$7)`,
					ids.NewUUIDv7(), ids.NewPublic(ids.PrefixPayout), line.SellerID, line.ItemID,
					sellerShare.Minor(), string(o.Currency),
					"Recovered from the next settlement: refund on order "+o.Number); err != nil {
					return fmt.Errorf("orders: record settlement offset: %w", err)
				}
			}
		} else if providerTransferID != nil && *providerTransferID != "" && s.provider.Capabilities().TransferReversal {
			if _, err := tx.Exec(ctx,
				`UPDATE payment_transfers SET status = 'reversed', reversed_amount_minor = amount_minor
				  WHERE order_item_id = $1`, line.ItemID); err != nil {
				return err
			}
		} else {
			if _, err := tx.Exec(ctx,
				`UPDATE payment_transfers SET status = 'cancelled' WHERE order_item_id = $1 AND status IN ('pending','on_hold')`,
				line.ItemID); err != nil {
				return err
			}
		}

		if err := s.applyRefundStatuses(ctx, tx, o, line, amount, alreadyRefunded); err != nil {
			return err
		}

		if _, err := tx.Exec(ctx, `
			UPDATE licenses SET status = 'refunded', revoked_reason = 'order refunded'
			 WHERE order_item_id = $1 AND status = 'active'`, line.ItemID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE products SET refund_count = refund_count + 1 WHERE id = $1`, line.ProductID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE seller_turnover SET refunded_amount = refunded_amount + $3, updated_at = now()
			 WHERE seller_id = $1 AND fy_start = $2`,
			line.SellerID, fyStart(s.clk.Now()), amount.Minor()); err != nil {
			return err
		}

		if _, err := outbox.PublishJSON(ctx, tx, outbox.TopicOrderRefunded, "order", o.PublicID, map[string]any{
			"order_public_id": o.PublicID, "item_public_id": line.ItemPublicID,
			"amount_minor": amount.Minor(), "currency": string(o.Currency),
			"reason": req.Reason, "seller_recovery": recovery,
		}, o.PublicID); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, audit.Event{
			ActorKind: actorKindFor(req.ActorIsStaff), ActorID: &req.RequestedBy,
			Action: "order.refunded", SubjectType: "order", SubjectID: o.PublicID,
			Metadata: map[string]any{
				"item": line.ItemPublicID, "amount_minor": amount.Minor(),
				"reason": req.Reason, "seller_recovery": recovery,
				"staff_override": req.ActorIsStaff,
			},
		}); err != nil {
			return err
		}

		refreshed, err := s.LoadOrder(ctx, tx, o.PublicID)
		if err != nil {
			return err
		}
		out = RefundOutcome{
			RefundPublicID: refundPublicID, Amount: amount,
			ProcessingFeeRetained: retained, SellerRecovery: recovery,
			OrderStatus: refreshed.Status,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *Service) pickRefundLine(o *Order, itemPublicID string) (LineBreakdown, error) {
	if itemPublicID == "" {
		if len(o.Lines) != 1 {
			return LineBreakdown{}, problem.Validation(problem.FieldError{
				Field: "item_public_id", Code: "required",
				Detail: "This order has several items; name the one to refund."})
		}
		return o.Lines[0], nil
	}
	for _, l := range o.Lines {
		if l.ItemPublicID == itemPublicID {
			return l, nil
		}
	}
	return LineBreakdown{}, problem.NotFound("That item is not part of this order.")
}

// checkRefundEligibility applies the refund policy that was disclosed at
// purchase. Downloaded files cannot be recalled, so a "no refund once
// downloaded" policy is enforceable precisely because the download is evidenced.
func (s *Service) checkRefundEligibility(ctx context.Context, tx db.Tx, line LineBreakdown) error {
	var policy string
	var fulfilledAt *time.Time
	if err := tx.QueryRow(ctx,
		`SELECT refund_policy_snapshot, fulfilled_at FROM order_items WHERE id = $1`,
		line.ItemID).Scan(&policy, &fulfilledAt); err != nil {
		return fmt.Errorf("orders: read refund policy: %w", err)
	}

	var downloads int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM download_events de
		  JOIN licenses l ON l.id = de.license_id
		 WHERE l.order_item_id = $1 AND de.outcome = 'served'`, line.ItemID).Scan(&downloads); err != nil {
		return fmt.Errorf("orders: count downloads: %w", err)
	}

	switch policy {
	case "no_refund":
		return problem.Conflict("", "This item was sold without a refund option, which was disclosed before purchase.")
	case "no_refund_after_download":
		if downloads > 0 {
			return problem.Conflict("",
				"This item has already been downloaded. As disclosed before purchase, a downloaded file cannot be refunded because access cannot be withdrawn.")
		}
	case "refundable_14_days":
		if fulfilledAt != nil && s.clk.Now().Sub(*fulfilledAt) > 14*24*time.Hour {
			return problem.Conflict("", "The 14-day refund window for this item has closed.")
		}
	case "case_by_case":
		return problem.Conflict("",
			"This item is refunded case by case. Open a dispute and a person will review it.")
	}
	return nil
}

// retainedProcessingFee is the share of the provider's fee attributable to the
// refunded amount. The network does not return it, so the platform wears it.
func (s *Service) retainedProcessingFee(o *Order, refunded money.Money, paymentFee *int64) money.Money {
	zero := money.Zero(o.Currency)
	if o.GrandTotal.Minor() == 0 {
		return zero
	}
	total := money.Zero(o.Currency)
	if paymentFee != nil {
		total = money.MustNew(*paymentFee, o.Currency)
	} else {
		v, err := o.GrandTotal.ApplyBasisPoints(s.pspFeeBps, money.HalfUp)
		if err != nil {
			return zero
		}
		total = v
	}
	share, err := total.MulRatio(refunded.Minor(), o.GrandTotal.Minor(), money.HalfUp)
	if err != nil {
		return zero
	}
	return share
}

// postRefundLedger reverses the capture proportionally.
//
// Each component is scaled by the refunded fraction of the line, and the last
// component absorbs the rounding residue so the entry balances to the paise.
func (s *Service) postRefundLedger(ctx context.Context, tx db.Tx, o *Order, line LineBreakdown, amount money.Money, settledAway bool, refundPublicID string) error {
	cur := o.Currency
	clearing, err := s.ledger.AccountByCode(ctx, tx, s.clearingAccountCode())
	if err != nil {
		return err
	}

	components := []struct {
		code   string
		amount money.Money
		memo   string
	}{
		{"platform.income.commission", line.Breakdown.Commission, "commission reversed"},
		{"platform.payable.gst_output", line.Breakdown.CommissionGST, "GST on commission reversed"},
		{"platform.payable.tcs", line.Breakdown.TCS, "TCS reversed"},
		{"platform.payable.tds_194o", line.Breakdown.TDS, "TDS reversed"},
	}

	lines := make([]ledger.Line, 0, len(components)+2)
	allocated := money.Zero(cur)

	sellerShare, err := scaleToRefund(line.Breakdown.SellerNet, amount, line.Breakdown.BuyerTotal)
	if err != nil {
		return err
	}
	if sellerShare.IsPositive() {
		var acct ids.UUID
		var memo string
		if settledAway {
			// Already paid out: record a receivable from the seller, recovered
			// by netting against their next settlement.
			if acct, err = s.ledger.AccountByCode(ctx, tx, s.offsetAccountCode(cur)); err != nil {
				return err
			}
			memo = "recoverable from the seller's next settlement"
		} else {
			if acct, err = s.ledger.SellerAccount(ctx, tx, line.SellerID, "payable", cur); err != nil {
				return err
			}
			memo = "seller share reversed before settlement"
		}
		lines = append(lines, ledger.Line{AccountID: acct, Direction: ledger.Debit, Amount: sellerShare, Memo: memo})
		if allocated, err = allocated.Add(sellerShare); err != nil {
			return err
		}
	}

	for _, c := range components {
		share, err := scaleToRefund(c.amount, amount, line.Breakdown.BuyerTotal)
		if err != nil {
			return err
		}
		if !share.IsPositive() {
			continue
		}
		acct, err := s.ledger.AccountByCode(ctx, tx, c.code)
		if err != nil {
			return err
		}
		lines = append(lines, ledger.Line{AccountID: acct, Direction: ledger.Debit, Amount: share, Memo: c.memo})
		if allocated, err = allocated.Add(share); err != nil {
			return err
		}
	}

	// Proportional scaling rounds each component independently, so the parts
	// may miss the whole by a paise or two. The residue is absorbed by the
	// platform rather than left to unbalance the entry.
	residue, err := amount.Sub(allocated)
	if err != nil {
		return err
	}
	if !residue.IsZero() {
		absorb, err := s.ledger.AccountByCode(ctx, tx, "platform.expense.refund_absorbed")
		if err != nil {
			return err
		}
		dir := ledger.Debit
		abs := residue
		if residue.IsNegative() {
			dir = ledger.Credit
			if abs, err = residue.Abs(); err != nil {
				return err
			}
		}
		lines = append(lines, ledger.Line{
			AccountID: absorb, Direction: dir, Amount: abs,
			Memo: "rounding residue on a proportional refund, absorbed by the platform",
		})
	}

	lines = append(lines, ledger.Line{
		AccountID: clearing, Direction: ledger.Credit, Amount: amount, Memo: "returned to the buyer",
	})

	_, err = s.ledger.Post(ctx, tx, ledger.Entry{
		Kind: ledger.KindRefund, Currency: cur, OccurredAt: s.clk.Now(),
		Description:   "Refund on order " + o.Number,
		ReferenceType: "order", ReferenceID: o.PublicID,
		IdempotencyKey: "refund:" + refundPublicID,
		Metadata: map[string]any{
			"item": line.ItemPublicID, "settled_away": settledAway,
		},
		Lines: lines,
	})
	return err
}

func (s *Service) offsetAccountCode(cur money.Currency) string {
	if cur == money.INR {
		return "platform.receivable.seller_offset"
	}
	return "platform.receivable.seller_offset." + lower(string(cur))
}

func (s *Service) applyRefundStatuses(ctx context.Context, tx db.Tx, o *Order, line LineBreakdown, amount money.Money, alreadyRefunded int64) error {
	newItemRefunded := alreadyRefunded + amount.Minor()
	itemStatus := "partially_refunded"
	if newItemRefunded >= line.Breakdown.BuyerTotal.Minor() {
		itemStatus = "refunded"
	}
	if _, err := tx.Exec(ctx,
		`UPDATE order_items SET refunded_minor = $2, status = $3 WHERE id = $1`,
		line.ItemID, newItemRefunded, itemStatus); err != nil {
		return err
	}

	newOrderRefunded := o.Refunded.Minor() + amount.Minor()
	if _, err := tx.Exec(ctx,
		`UPDATE orders SET refunded_total_minor = $2 WHERE id = $1`, o.ID, newOrderRefunded); err != nil {
		return err
	}

	target := StatusPartiallyRefunded
	if newOrderRefunded >= o.GrandTotal.Minor() {
		target = StatusRefunded
	}
	// The state machine requires passing through refund_pending, which keeps
	// the transition table a complete description of reality.
	if o.Status != StatusRefundPending {
		if err := s.transition(ctx, tx, o.ID, o.Status, StatusRefundPending, "system", nil, "refund requested"); err != nil {
			return err
		}
	}
	return s.transition(ctx, tx, o.ID, StatusRefundPending, target, "system", nil, "refund settled")
}

// scaleToRefund returns component * refunded / lineTotal, rounded half-up.
func scaleToRefund(component, refunded, lineTotal money.Money) (money.Money, error) {
	if lineTotal.Minor() == 0 {
		return money.Zero(component.Currency()), nil
	}
	if refunded.Equal(lineTotal) {
		return component, nil
	}
	return component.MulRatio(refunded.Minor(), lineTotal.Minor(), money.HalfUp)
}

func actorKindFor(staff bool) audit.ActorKind {
	if staff {
		return audit.ActorAdmin
	}
	return audit.ActorUser
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 32
		}
	}
	return string(b)
}
