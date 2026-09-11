package orders

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
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

// WebhookOutcome describes how an inbound provider event was handled.
type WebhookOutcome struct {
	EventID   string
	Type      string
	Processed bool
	// Duplicate is true when this exact event was seen before. Providers retry
	// and networks duplicate, so this is the normal case, not an error.
	Duplicate bool
	// ReplayMismatch is true when a previously-seen event id arrived with
	// different content, which is a tampering signal rather than a retry.
	ReplayMismatch bool
	Note           string
}

// HandleWebhook verifies, de-duplicates and applies a provider event.
//
// The ordering here is deliberate and is the whole security model of this
// endpoint: verify the signature over the exact raw bytes FIRST, then
// de-duplicate on the provider's event id, then act. Nothing unverified is
// allowed to reach the database.
func (s *Service) HandleWebhook(ctx context.Context, header http.Header, rawBody []byte) (*WebhookOutcome, error) {
	ev, err := s.provider.ParseWebhook(ctx, header, rawBody)
	if err != nil {
		if errors.Is(err, payments.ErrInvalidSignature) {
			if s.m != nil {
				s.m.WebhookRejections.Inc(s.provider.Name(), "invalid_signature")
			}
			// Deliberately recorded, deliberately not retried, deliberately not
			// described to the caller in any detail.
			_ = s.audit.Record(ctx, s.db, audit.Event{
				ActorKind: audit.ActorProvider, Action: "webhook.signature_rejected",
				SubjectType: "webhook", SubjectID: s.provider.Name(),
				Metadata: map[string]any{"bytes": len(rawBody)},
			})
			return nil, problem.Unauthenticated("The webhook signature did not verify.")
		}
		if s.m != nil {
			s.m.WebhookRejections.Inc(s.provider.Name(), "malformed")
		}
		return nil, problem.Validation(problem.FieldError{
			Field: "body", Code: "unparseable", Detail: "The webhook payload could not be interpreted."})
	}
	if s.m != nil {
		s.m.WebhookEvents.Inc(s.provider.Name(), ev.Type)
	}

	digest := sha256.Sum256(rawBody)
	out := &WebhookOutcome{EventID: ev.EventID, Type: ev.Type}

	err = s.db.InTx(ctx, db.TxOptions{Name: "webhook_claim"}, func(ctx context.Context, tx db.Tx) error {
		var existingDigest []byte
		var existingStatus string
		err := tx.QueryRow(ctx,
			`SELECT payload_digest, process_status FROM provider_webhook_events
			  WHERE provider = $1 AND event_id = $2 FOR UPDATE`,
			s.provider.Name(), ev.EventID).Scan(&existingDigest, &existingStatus)

		switch {
		case err == nil:
			if string(existingDigest) != string(digest[:]) {
				// Same event id, different bytes. A genuine retry is
				// byte-identical, so this is an attempt to replay an id with
				// altered content.
				out.Duplicate, out.ReplayMismatch = true, true
				out.Note = "an event with this id was already received with different content"
				if _, err := tx.Exec(ctx, `
					UPDATE provider_webhook_events SET process_status = 'replay_detected', attempts = attempts + 1
					 WHERE provider = $1 AND event_id = $2`, s.provider.Name(), ev.EventID); err != nil {
					return err
				}
				if s.m != nil {
					s.m.WebhookRejections.Inc(s.provider.Name(), "replay_mismatch")
				}
				return s.audit.Record(ctx, tx, audit.Event{
					ActorKind: audit.ActorProvider, Action: "webhook.replay_mismatch",
					SubjectType: "webhook", SubjectID: ev.EventID,
					Metadata: map[string]any{"event_type": ev.Type},
				})
			}
			if existingStatus == "processed" || existingStatus == "ignored" {
				out.Duplicate, out.Processed = true, true
				out.Note = "already processed"
				return nil
			}
			// Previously failed; fall through and try again.

		case db.IsNoRows(err):
			payload, mErr := json.Marshal(ev.Raw)
			if mErr != nil {
				payload = []byte(`{}`)
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO provider_webhook_events (id, provider, event_id, event_type,
				                                     payload_digest, payload, signature_valid, attempts)
				VALUES ($1,$2,$3,$4,$5,$6,TRUE,0)`,
				ids.NewUUIDv7(), s.provider.Name(), ev.EventID, ev.Type, digest[:], payload); err != nil {
				return fmt.Errorf("orders: record webhook: %w", err)
			}

		default:
			return fmt.Errorf("orders: webhook lookup: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if out.Duplicate {
		return out, nil
	}

	applyErr := s.applyWebhook(ctx, ev)

	status, note := "processed", ""
	if applyErr != nil {
		status = "failed"
		note = applyErr.Error()
		s.log.ErrorContext(ctx, "webhook processing failed",
			slog.String("event", ev.Type), slog.String("event_id", ev.EventID),
			slog.String("error", applyErr.Error()))
	}
	if _, err := s.db.Exec(context.WithoutCancel(ctx), `
		UPDATE provider_webhook_events
		   SET process_status = $3, processed_at = now(), attempts = attempts + 1, last_error = $4
		 WHERE provider = $1 AND event_id = $2`,
		s.provider.Name(), ev.EventID, status, nullIfEmpty(note)); err != nil {
		s.log.ErrorContext(ctx, "webhook bookkeeping failed", slog.String("error", err.Error()))
	}
	if applyErr != nil {
		return out, applyErr
	}
	out.Processed = true
	return out, nil
}

// applyWebhook routes a verified event to its handler. Unknown event types are
// accepted and ignored rather than retried: a provider adding a new event must
// not create a permanent backlog.
func (s *Service) applyWebhook(ctx context.Context, ev payments.WebhookEvent) error {
	switch ev.Type {
	case "payment.captured", "order.paid":
		return s.onPaymentCaptured(ctx, ev)
	case "payment.failed":
		return s.onPaymentFailed(ctx, ev)
	case "refund.processed", "refund.created":
		return s.onRefundProcessed(ctx, ev)
	case "transfer.processed":
		return s.onTransferProcessed(ctx, ev)
	case "transfer.failed":
		return s.onTransferFailed(ctx, ev)
	case "payment.dispute.created", "payment.dispute.won", "payment.dispute.lost", "payment.dispute.closed":
		return s.onDispute(ctx, ev)
	case "account.activated", "account.under_review", "account.needs_clarification", "account.suspended":
		return s.onAccountStatus(ctx, ev)
	}
	s.log.InfoContext(ctx, "webhook event ignored", slog.String("event", ev.Type))
	return nil
}

// onPaymentCaptured is the authoritative confirmation path. The browser
// callback is a convenience; this is what makes an order paid even if the buyer
// closed the tab.
func (s *Service) onPaymentCaptured(ctx context.Context, ev payments.WebhookEvent) error {
	if ev.ProviderPaymentID == "" {
		return nil
	}
	record, err := s.provider.ReconcilePayment(ctx, ev.ProviderPaymentID)
	if err != nil {
		return fmt.Errorf("orders: reconcile webhook payment: %w", err)
	}
	if record.Status != payments.PaymentCaptured {
		return nil
	}

	return s.db.InTx(ctx, db.TxOptions{Name: "webhook_capture"}, func(ctx context.Context, tx db.Tx) error {
		var orderPublicID string
		err := tx.QueryRow(ctx, `
			SELECT o.public_id FROM orders o
			  JOIN payment_intents pi ON pi.order_id = o.id
			 WHERE pi.provider = $1 AND pi.provider_intent_id = $2`,
			s.provider.Name(), record.ProviderIntentID).Scan(&orderPublicID)
		if db.IsNoRows(err) {
			// A payment we have no order for is a reconciliation difference,
			// not a crash: it is recorded for a human rather than swallowed.
			return s.recordOrphanPayment(ctx, tx, record)
		}
		if err != nil {
			return fmt.Errorf("orders: resolve order from intent: %w", err)
		}

		o, err := s.LoadOrder(ctx, tx, orderPublicID)
		if err != nil {
			return err
		}
		if o.Status != StatusAwaitingPayment {
			return nil // the callback already did the work
		}
		if !record.Amount.Equal(o.GrandTotal) {
			return s.recordAmountMismatch(ctx, tx, o, record)
		}
		var res ConfirmResult
		return s.recordCapture(ctx, tx, o, record, "", nil, &res)
	})
}

func (s *Service) recordOrphanPayment(ctx context.Context, tx db.Tx, record payments.PaymentRecord) error {
	runID := ids.NewUUIDv7()
	if _, err := tx.Exec(ctx, `
		INSERT INTO reconciliation_runs (id, provider, period_start, period_end, status,
		                                 currency, difference_count, finished_at)
		VALUES ($1,$2,CURRENT_DATE,CURRENT_DATE,'completed',$3,1, now())`,
		runID, s.provider.Name(), string(record.Amount.Currency())); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO reconciliation_differences (id, run_id, kind, provider_ref, actual_minor, currency, detail)
		VALUES ($1,$2,'missing_in_ledger',$3,$4,$5,$6)`,
		ids.NewUUIDv7(), runID, record.ProviderPaymentID, record.Amount.Minor(),
		string(record.Amount.Currency()),
		map[string]any{"reason": "a captured payment arrived for an intent this system has no order for"})
	if err != nil {
		return err
	}
	if s.m != nil {
		s.m.ReconciliationDiffs.Set(1, "missing_in_ledger")
	}
	return nil
}

func (s *Service) recordAmountMismatch(ctx context.Context, tx db.Tx, o *Order, record payments.PaymentRecord) error {
	runID := ids.NewUUIDv7()
	if _, err := tx.Exec(ctx, `
		INSERT INTO reconciliation_runs (id, provider, period_start, period_end, status,
		                                 currency, difference_count, finished_at)
		VALUES ($1,$2,CURRENT_DATE,CURRENT_DATE,'completed',$3,1, now())`,
		runID, s.provider.Name(), string(o.Currency)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO reconciliation_differences (id, run_id, kind, provider_ref, ledger_ref,
		                                        expected_minor, actual_minor, currency, detail)
		VALUES ($1,$2,'amount_mismatch',$3,$4,$5,$6,$7,$8)`,
		ids.NewUUIDv7(), runID, record.ProviderPaymentID, o.PublicID,
		o.GrandTotal.Minor(), record.Amount.Minor(), string(o.Currency),
		map[string]any{"reason": "the captured amount does not match the order total"}); err != nil {
		return err
	}
	return s.audit.Record(ctx, tx, audit.Event{
		ActorKind: audit.ActorSystem, Action: "payment.amount_mismatch",
		SubjectType: "order", SubjectID: o.PublicID,
		Metadata: map[string]any{
			"expected_minor": o.GrandTotal.Minor(), "captured_minor": record.Amount.Minor(),
		},
	})
}

func (s *Service) onPaymentFailed(ctx context.Context, ev payments.WebhookEvent) error {
	if ev.ProviderIntentID == "" {
		return nil
	}
	return s.db.InTx(ctx, db.TxOptions{Name: "webhook_payment_failed"}, func(ctx context.Context, tx db.Tx) error {
		var orderID ids.UUID
		var status string
		err := tx.QueryRow(ctx, `
			SELECT o.id, o.status FROM orders o
			  JOIN payment_intents pi ON pi.order_id = o.id
			 WHERE pi.provider = $1 AND pi.provider_intent_id = $2`,
			s.provider.Name(), ev.ProviderIntentID).Scan(&orderID, &status)
		if db.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if status != string(StatusAwaitingPayment) {
			return nil
		}
		if _, err := tx.Exec(ctx,
			`UPDATE payment_intents SET status = 'failed' WHERE provider_intent_id = $1`, ev.ProviderIntentID); err != nil {
			return err
		}
		if err := s.transition(ctx, tx, orderID, StatusAwaitingPayment, StatusPaymentFailed,
			"provider", nil, "provider reported failure"); err != nil {
			return err
		}
		var pub string
		if err := tx.QueryRow(ctx, `SELECT public_id FROM orders WHERE id = $1`, orderID).Scan(&pub); err != nil {
			return err
		}
		_, err = outbox.PublishJSON(ctx, tx, outbox.TopicPaymentFailed, "order", pub,
			map[string]any{"order_public_id": pub, "reason": ev.Status}, pub)
		return err
	})
}

func (s *Service) onRefundProcessed(ctx context.Context, ev payments.WebhookEvent) error {
	if ev.ProviderRefundID == "" {
		return nil
	}
	_, err := s.db.Exec(ctx,
		`UPDATE refunds SET status = 'succeeded', settled_at = COALESCE(settled_at, now())
		  WHERE provider = $1 AND provider_refund_id = $2 AND status <> 'succeeded'`,
		s.provider.Name(), ev.ProviderRefundID)
	return err
}

func (s *Service) onTransferProcessed(ctx context.Context, ev payments.WebhookEvent) error {
	if ev.ProviderTransferID == "" {
		return nil
	}
	_, err := s.db.Exec(ctx, `
		UPDATE payment_transfers SET status = 'processed', released_at = COALESCE(released_at, now())
		 WHERE provider = $1 AND provider_transfer_id = $2 AND status <> 'processed'`,
		s.provider.Name(), ev.ProviderTransferID)
	return err
}

func (s *Service) onTransferFailed(ctx context.Context, ev payments.WebhookEvent) error {
	if ev.ProviderTransferID == "" {
		return nil
	}
	_, err := s.db.Exec(ctx, `
		UPDATE payment_transfers SET status = 'failed', failure_message = $3
		 WHERE provider = $1 AND provider_transfer_id = $2`,
		s.provider.Name(), ev.ProviderTransferID, "provider reported transfer failure")
	return err
}

// onDispute records a card-network chargeback.
//
// A chargeback is NOT an in-app dispute: the representment deadline is set by
// the network, the debit happens whether or not we agree, and the processing
// fee is not returned. It therefore gets its own table and its own clock.
func (s *Service) onDispute(ctx context.Context, ev payments.WebhookEvent) error {
	if ev.ProviderDisputeID == "" || ev.ProviderPaymentID == "" {
		return nil
	}
	return s.db.InTx(ctx, db.TxOptions{Name: "webhook_dispute"}, func(ctx context.Context, tx db.Tx) error {
		var orderID ids.UUID
		var paymentID ids.UUID
		var orderPublic, orderStatus, currency string
		err := tx.QueryRow(ctx, `
			SELECT p.id, o.id, o.public_id, o.status, o.currency
			  FROM payments p JOIN orders o ON o.id = p.order_id
			 WHERE p.provider = $1 AND p.provider_payment_id = $2`,
			s.provider.Name(), ev.ProviderPaymentID).Scan(&paymentID, &orderID, &orderPublic, &orderStatus, &currency)
		if db.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}

		amount := money.Zero(money.Currency(currency))
		if ev.Amount != nil {
			amount = *ev.Amount
		}
		network := networkFromRaw(ev.Raw)
		respondBy := s.clk.Now().Add(representmentWindow(network))

		switch ev.Type {
		case "payment.dispute.created":
			if _, err := tx.Exec(ctx, `
				INSERT INTO chargebacks (id, public_id, order_id, payment_id, provider, provider_dispute_id,
				                         network, reason_code, amount_minor, currency, status, respond_by)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'evidence_required',$11)
				ON CONFLICT (provider, provider_dispute_id) DO NOTHING`,
				ids.NewUUIDv7(), ids.NewPublic(ids.PrefixChargeback), orderID, paymentID,
				s.provider.Name(), ev.ProviderDisputeID, network,
				nullIfEmpty(reasonCodeFromRaw(ev.Raw)), amount.Minor(), currency, respondBy); err != nil {
				return fmt.Errorf("orders: record chargeback: %w", err)
			}
			if orderStatus != string(StatusDisputed) {
				if err := s.transition(ctx, tx, orderID, Status(orderStatus), StatusDisputed,
					"provider", nil, "chargeback received"); err != nil && !errors.Is(err, errConcurrentTransition) {
					return err
				}
			}
			// Settlement is frozen the instant a chargeback lands, which is the
			// point of the protection window existing at all.
			if _, err := tx.Exec(ctx, `
				UPDATE payment_transfers t SET status = 'on_hold',
				       hold_until = GREATEST(t.hold_until, $2)
				  FROM order_items i
				 WHERE i.id = t.order_item_id AND i.order_id = $1 AND t.status IN ('pending','on_hold')`,
				orderID, respondBy.Add(30*24*time.Hour)); err != nil {
				return err
			}
			if _, err := outbox.PublishJSON(ctx, tx, outbox.TopicChargebackOpened, "order", orderPublic, map[string]any{
				"order_public_id": orderPublic, "network": network,
				"amount_minor": amount.Minor(), "respond_by": respondBy.Format(time.RFC3339),
			}, orderPublic); err != nil {
				return err
			}

		case "payment.dispute.won":
			if _, err := tx.Exec(ctx,
				`UPDATE chargebacks SET status = 'won', resolved_at = now()
				  WHERE provider = $1 AND provider_dispute_id = $2`,
				s.provider.Name(), ev.ProviderDisputeID); err != nil {
				return err
			}
			if err := s.transition(ctx, tx, orderID, StatusDisputed, StatusFulfilled,
				"provider", nil, "representment succeeded"); err != nil && !errors.Is(err, errConcurrentTransition) {
				return err
			}

		case "payment.dispute.lost":
			if _, err := tx.Exec(ctx,
				`UPDATE chargebacks SET status = 'lost', resolved_at = now()
				  WHERE provider = $1 AND provider_dispute_id = $2`,
				s.provider.Name(), ev.ProviderDisputeID); err != nil {
				return err
			}
			if err := s.postChargebackLoss(ctx, tx, orderID, orderPublic, amount, ev.ProviderDisputeID); err != nil {
				return err
			}
			if err := s.transition(ctx, tx, orderID, StatusDisputed, StatusChargebackLost,
				"provider", nil, "representment failed"); err != nil && !errors.Is(err, errConcurrentTransition) {
				return err
			}
		}

		return s.audit.Record(ctx, tx, audit.Event{
			ActorKind: audit.ActorProvider, Action: "chargeback." + ev.Type,
			SubjectType: "order", SubjectID: orderPublic,
			Metadata: map[string]any{
				"dispute_id": ev.ProviderDisputeID, "network": network,
				"amount_minor": amount.Minor(),
			},
		})
	})
}

// postChargebackLoss books the loss. The seller's share becomes recoverable
// from their next settlement; the platform absorbs its own commission and the
// processing cost, which the network does not return.
func (s *Service) postChargebackLoss(ctx context.Context, tx db.Tx, orderID ids.UUID, orderPublic string, amount money.Money, disputeID string) error {
	cur := amount.Currency()
	clearing, err := s.ledger.AccountByCode(ctx, tx, s.clearingAccountCode())
	if err != nil {
		return err
	}
	lossAcct, err := s.ledger.AccountByCode(ctx, tx, "platform.expense.chargeback_loss")
	if err != nil {
		return err
	}

	rows, err := tx.Query(ctx, `
		SELECT i.id, i.public_id, i.seller_id, i.seller_net_minor, t.status
		  FROM order_items i
		  LEFT JOIN payment_transfers t ON t.order_item_id = i.id
		 WHERE i.order_id = $1`, orderID)
	if err != nil {
		return err
	}
	type line struct {
		itemID   ids.UUID
		itemPub  string
		sellerID ids.UUID
		net      int64
		status   *string
	}
	var lines []line
	for rows.Next() {
		var l line
		if err := rows.Scan(&l.itemID, &l.itemPub, &l.sellerID, &l.net, &l.status); err != nil {
			rows.Close()
			return err
		}
		lines = append(lines, l)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	entryLines := make([]ledger.Line, 0, len(lines)+2)
	recovered := money.Zero(cur)
	for _, l := range lines {
		net, err := money.New(l.net, cur)
		if err != nil || !net.IsPositive() {
			continue
		}
		settledAway := l.status != nil && *l.status == "processed"
		var acct ids.UUID
		var memo string
		if settledAway {
			if acct, err = s.ledger.AccountByCode(ctx, tx, s.offsetAccountCode(cur)); err != nil {
				return err
			}
			memo = "recoverable from the seller's next settlement"
			if _, err := tx.Exec(ctx, `
				INSERT INTO settlement_offsets (id, public_id, seller_id, origin, origin_id,
				                                amount_minor, currency, note)
				VALUES ($1,$2,$3,'chargeback',$4,$5,$6,$7)`,
				ids.NewUUIDv7(), ids.NewPublic(ids.PrefixPayout), l.sellerID, l.itemID,
				net.Minor(), string(cur), "Chargeback lost on order "+orderPublic); err != nil {
				return err
			}
		} else {
			if acct, err = s.ledger.SellerAccount(ctx, tx, l.sellerID, "payable", cur); err != nil {
				return err
			}
			memo = "seller share reversed: chargeback lost before settlement"
			if _, err := tx.Exec(ctx,
				`UPDATE payment_transfers SET status = 'cancelled' WHERE order_item_id = $1`, l.itemID); err != nil {
				return err
			}
		}
		entryLines = append(entryLines, ledger.Line{
			AccountID: acct, Direction: ledger.Debit, Amount: net, Memo: memo,
		})
		if recovered, err = recovered.Add(net); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE order_items SET status = 'charged_back' WHERE id = $1`, l.itemID); err != nil {
			return err
		}
	}

	absorbed, err := amount.Sub(recovered)
	if err != nil {
		return err
	}
	if absorbed.IsPositive() {
		entryLines = append(entryLines, ledger.Line{
			AccountID: lossAcct, Direction: ledger.Debit, Amount: absorbed,
			Memo: "platform share of the charged-back amount, absorbed",
		})
	} else if absorbed.IsNegative() {
		abs, err := absorbed.Abs()
		if err != nil {
			return err
		}
		entryLines = append(entryLines, ledger.Line{
			AccountID: lossAcct, Direction: ledger.Credit, Amount: abs,
			Memo: "recovery in excess of the charged-back amount",
		})
	}
	entryLines = append(entryLines, ledger.Line{
		AccountID: clearing, Direction: ledger.Credit, Amount: amount,
		Memo: "debited by the acquirer",
	})

	_, err = s.ledger.Post(ctx, tx, ledger.Entry{
		Kind: ledger.KindChargeback, Currency: cur, OccurredAt: s.clk.Now(),
		Description:   "Chargeback lost on order " + orderPublic,
		ReferenceType: "order", ReferenceID: orderPublic,
		IdempotencyKey: "chargeback:" + disputeID,
		Lines:          entryLines,
	})
	return err
}

func (s *Service) onAccountStatus(ctx context.Context, ev payments.WebhookEvent) error {
	if ev.ProviderAccountID == "" {
		return nil
	}
	status := ev.Status
	if status == "" {
		return nil
	}
	var activatedAt any
	if status == "activated" {
		activatedAt = s.clk.Now()
	}
	allowed := map[string]bool{
		"created": true, "needs_clarification": true, "under_review": true,
		"activated": true, "suspended": true,
	}
	if !allowed[status] {
		return nil
	}
	return s.db.InTx(ctx, db.TxOptions{Name: "webhook_account"}, func(ctx context.Context, tx db.Tx) error {
		var sellerPublic string
		err := tx.QueryRow(ctx, `
			UPDATE sellers
			   SET provider_account_status = $2,
			       provider_account_activated_at = COALESCE(provider_account_activated_at, $3)
			 WHERE provider_account_id = $1
			 RETURNING public_id`, ev.ProviderAccountID, status, activatedAt).Scan(&sellerPublic)
		if db.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		_, err = outbox.PublishJSON(ctx, tx, outbox.TopicSellerKYCUpdated, "seller", sellerPublic,
			map[string]any{"seller_public_id": sellerPublic, "provider_account_status": status}, sellerPublic)
		return err
	})
}

// representmentWindow returns the time available to contest a chargeback.
//
// These windows tightened from 2026: Visa and Mastercard to 10-14 calendar days
// in India, RuPay under NPCI's RGCS to 7 working days. The shorter end of each
// range is used so an internal deadline is never later than the network's.
func representmentWindow(network string) time.Duration {
	switch network {
	case "rupay":
		return 7 * 24 * time.Hour
	case "visa", "mastercard":
		return 10 * 24 * time.Hour
	case "amex", "diners":
		return 20 * 24 * time.Hour
	}
	return 7 * 24 * time.Hour
}

func networkFromRaw(raw map[string]any) string {
	d, ok := raw["dispute"].(map[string]any)
	if !ok {
		return "other"
	}
	if n, ok := d["network"].(string); ok && n != "" {
		return normaliseNetwork(n)
	}
	if n, ok := d["card_network"].(string); ok && n != "" {
		return normaliseNetwork(n)
	}
	return "other"
}

func normaliseNetwork(n string) string {
	switch lower(n) {
	case "visa":
		return "visa"
	case "mastercard", "master card", "mc":
		return "mastercard"
	case "rupay":
		return "rupay"
	case "amex", "american express":
		return "amex"
	case "diners", "diners club":
		return "diners"
	case "upi":
		return "upi"
	}
	return "other"
}

func reasonCodeFromRaw(raw map[string]any) string {
	d, ok := raw["dispute"].(map[string]any)
	if !ok {
		return ""
	}
	if c, ok := d["reason_code"].(string); ok {
		return c
	}
	return ""
}
