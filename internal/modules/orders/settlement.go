package orders

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/muthu2201/market-place/internal/modules/audit"
	"github.com/muthu2201/market-place/internal/modules/ledger"
	"github.com/muthu2201/market-place/internal/modules/payments"
	"github.com/muthu2201/market-place/internal/outbox"
	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/ids"
	"github.com/muthu2201/market-place/internal/platform/money"
)

// ReleaseResult summarises one settlement-release pass.
type ReleaseResult struct {
	Considered int
	Released   int
	Held       int
	Failed     int
	// HeldReasons explains every deferral, so an operator answering "where is
	// my money" has the answer without reading code.
	HeldReasons map[string]int
}

// ReleaseDueSettlements releases every transfer whose protection window has
// closed and whose order is not under dispute.
//
// This is the wallet-free answer to the "settled seller, then chargeback"
// problem: the money simply has not moved yet, so there is nothing to claw back
// and no internal balance to go negative.
func (s *Service) ReleaseDueSettlements(ctx context.Context, limit int) (ReleaseResult, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	res := ReleaseResult{HeldReasons: map[string]int{}}

	type candidate struct {
		transferID    ids.UUID
		providerRef   string
		orderItemID   ids.UUID
		orderPublicID string
		orderStatus   string
		sellerID      ids.UUID
		amount        money.Money
		accountStatus string
		kycStatus     string
		sellerStatus  string
		reserveBps    int64
		disputes      int
	}

	var batch []candidate
	err := s.db.InTx(ctx, db.TxOptions{Name: "settlement_scan", ReadOnly: true}, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT t.id, COALESCE(t.provider_transfer_id,''), t.order_item_id, o.public_id, o.status,
			       t.seller_id, t.amount_minor, t.currency,
			       s.provider_account_status, s.kyc_status, s.status, s.rolling_reserve_bps,
			       (SELECT count(*) FROM disputes d
			         WHERE d.order_item_id = t.order_item_id
			           AND d.status IN ('open','awaiting_seller','awaiting_buyer','under_review'))
			  FROM payment_transfers t
			  JOIN order_items i ON i.id = t.order_item_id
			  JOIN orders o      ON o.id = i.order_id
			  JOIN sellers s     ON s.id = t.seller_id
			 WHERE t.status IN ('on_hold','pending')
			   AND t.hold_until <= now()
			 ORDER BY t.hold_until
			 LIMIT $1`, limit)
		if err != nil {
			return fmt.Errorf("orders: scan settlements: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var c candidate
			var minor int64
			var cur string
			if err := rows.Scan(&c.transferID, &c.providerRef, &c.orderItemID, &c.orderPublicID,
				&c.orderStatus, &c.sellerID, &minor, &cur, &c.accountStatus, &c.kycStatus,
				&c.sellerStatus, &c.reserveBps, &c.disputes); err != nil {
				return err
			}
			m, err := money.New(minor, money.Currency(cur))
			if err != nil {
				return err
			}
			c.amount = m
			batch = append(batch, c)
		}
		return rows.Err()
	})
	if err != nil {
		return res, err
	}

	for _, c := range batch {
		res.Considered++

		// Every reason a settlement is deferred, checked in order of severity.
		hold := ""
		switch {
		case c.orderStatus == "disputed" || c.orderStatus == "chargeback_lost":
			hold = "order is under dispute or was charged back"
		case c.orderStatus == "refunded" || c.orderStatus == "refund_pending":
			hold = "order is being refunded"
		case c.disputes > 0:
			hold = "an in-app dispute is open on this item"
		case c.kycStatus != "verified":
			hold = "seller KYC is not verified"
		case c.accountStatus != "activated":
			hold = "the provider has not activated the seller's linked account"
		case c.sellerStatus == "suspended" || c.sellerStatus == "closed":
			hold = "seller account is suspended"
		}
		if hold != "" {
			res.Held++
			res.HeldReasons[hold]++
			continue
		}

		if err := s.releaseOne(ctx, c.transferID, c.providerRef, c.orderItemID, c.orderPublicID,
			c.sellerID, c.amount, c.reserveBps); err != nil {
			res.Failed++
			s.log.ErrorContext(ctx, "settlement release failed",
				slog.String("transfer", c.transferID.String()),
				slog.String("order", c.orderPublicID),
				slog.String("error", err.Error()))
			continue
		}
		res.Released++
	}
	return res, nil
}

// releaseOne releases a single transfer, withholding the rolling reserve and
// applying any outstanding settlement offset first.
func (s *Service) releaseOne(ctx context.Context, transferID ids.UUID, providerRef string, itemID ids.UUID, orderPublicID string, sellerID ids.UUID, amount money.Money, reserveBps int64) error {
	return s.db.InTx(ctx, db.TxOptions{Name: "settlement_release"}, func(ctx context.Context, tx db.Tx) error {
		// Re-read under a lock: the scan was a read-only snapshot and the world
		// may have changed since.
		var status string
		if err := tx.QueryRow(ctx,
			`SELECT status FROM payment_transfers WHERE id = $1 FOR UPDATE`, transferID).Scan(&status); err != nil {
			return err
		}
		if status != "on_hold" && status != "pending" {
			return nil // someone else handled it
		}

		cur := amount.Currency()
		payable, err := s.ledger.SellerAccount(ctx, tx, sellerID, "payable", cur)
		if err != nil {
			return err
		}

		// A rolling reserve is withheld against future chargeback exposure. It
		// remains the seller's money and is released on a schedule; it is never
		// platform income.
		reserve := money.Zero(cur)
		if reserveBps > 0 {
			if reserve, err = amount.ApplyBasisPoints(reserveBps, money.Down); err != nil {
				return err
			}
		}
		if reserve.IsPositive() {
			reserveAcct, err := s.ledger.SellerAccount(ctx, tx, sellerID, "reserve", cur)
			if err != nil {
				return err
			}
			if _, err := s.ledger.Post(ctx, tx, ledger.Entry{
				Kind: ledger.KindRollingReserveHold, Currency: cur, OccurredAt: s.clk.Now(),
				Description:   "Rolling reserve withheld on settlement for " + orderPublicID,
				ReferenceType: "order_item", ReferenceID: itemID.String(),
				IdempotencyKey: "reserve:" + itemID.String(),
				Lines: []ledger.Line{
					{AccountID: payable, Direction: ledger.Debit, Amount: reserve, Memo: "moved to rolling reserve"},
					{AccountID: reserveAcct, Direction: ledger.Credit, Amount: reserve, Memo: "held against chargeback exposure"},
				},
			}); err != nil {
				return err
			}
		}

		net, err := amount.Sub(reserve)
		if err != nil {
			return err
		}

		// Outstanding offsets are netted before anything leaves, which is how a
		// post-settlement refund is recovered without an internal debit balance.
		applied, err := s.applyOffsets(ctx, tx, sellerID, net, payable)
		if err != nil {
			return err
		}
		if net, err = net.Sub(applied); err != nil {
			return err
		}

		if providerRef != "" && s.provider.Capabilities().SettlementHold {
			if err := s.provider.ReleaseSellerSettlement(ctx, providerRef); err != nil {
				if !errors.Is(err, payments.ErrNotSupported) {
					return fmt.Errorf("orders: release at provider: %w", err)
				}
			}
		}

		if _, err := tx.Exec(ctx, `
			UPDATE payment_transfers SET status = 'processed', released_at = now() WHERE id = $1`,
			transferID); err != nil {
			return err
		}

		if net.IsPositive() {
			clearing, err := s.ledger.AccountByCode(ctx, tx, s.clearingAccountCode())
			if err != nil {
				return err
			}
			if _, err := s.ledger.Post(ctx, tx, ledger.Entry{
				Kind: ledger.KindSettlementRelease, Currency: cur, OccurredAt: s.clk.Now(),
				Description:   "Settlement released for " + orderPublicID,
				ReferenceType: "order_item", ReferenceID: itemID.String(),
				IdempotencyKey: "settle:" + itemID.String(),
				Lines: []ledger.Line{
					{AccountID: payable, Direction: ledger.Debit, Amount: net, Memo: "paid to the seller"},
					{AccountID: clearing, Direction: ledger.Credit, Amount: net, Memo: "left provider clearing"},
				},
			}); err != nil {
				return err
			}
		}

		if _, err := outbox.PublishJSON(ctx, tx, outbox.TopicTransferReleased, "order", orderPublicID, map[string]any{
			"order_public_id": orderPublicID, "seller_id": sellerID.String(),
			"gross_minor": amount.Minor(), "reserve_minor": reserve.Minor(),
			"offset_applied_minor": applied.Minor(), "net_minor": net.Minor(),
			"currency": string(cur),
		}, orderPublicID); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, audit.Event{
			ActorKind: audit.ActorSystem, Action: "settlement.released",
			SubjectType: "order", SubjectID: orderPublicID,
			Metadata: map[string]any{
				"seller": sellerID.String(), "gross_minor": amount.Minor(),
				"reserve_minor": reserve.Minor(), "offset_minor": applied.Minor(),
				"net_minor": net.Minor(),
			},
		})
	})
}

// applyOffsets nets outstanding recoveries against an outgoing settlement,
// oldest first, up to the amount available.
func (s *Service) applyOffsets(ctx context.Context, tx db.Tx, sellerID ids.UUID, available money.Money, payableAcct ids.UUID) (money.Money, error) {
	cur := available.Currency()
	applied := money.Zero(cur)
	if !available.IsPositive() {
		return applied, nil
	}

	rows, err := tx.Query(ctx, `
		SELECT id, public_id, amount_minor, applied_minor
		  FROM settlement_offsets
		 WHERE seller_id = $1 AND currency = $2 AND status IN ('outstanding','partially_applied')
		 ORDER BY created_at
		 FOR UPDATE`, sellerID, string(cur))
	if err != nil {
		return applied, fmt.Errorf("orders: read offsets: %w", err)
	}
	type row struct {
		id        ids.UUID
		publicID  string
		amount    int64
		alreadyOn int64
	}
	var offsets []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.publicID, &r.amount, &r.alreadyOn); err != nil {
			rows.Close()
			return applied, err
		}
		offsets = append(offsets, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return applied, err
	}
	if len(offsets) == 0 {
		return applied, nil
	}

	offsetAcct, err := s.ledger.AccountByCode(ctx, tx, s.offsetAccountCode(cur))
	if err != nil {
		return applied, err
	}

	remaining := available
	for _, o := range offsets {
		outstanding := o.amount - o.alreadyOn
		if outstanding <= 0 {
			continue
		}
		take := outstanding
		if take > remaining.Minor() {
			take = remaining.Minor()
		}
		if take <= 0 {
			break
		}
		takeM, err := money.New(take, cur)
		if err != nil {
			return applied, err
		}

		newApplied := o.alreadyOn + take
		status := "partially_applied"
		if newApplied >= o.amount {
			status = "settled"
		}
		if _, err := tx.Exec(ctx,
			`UPDATE settlement_offsets SET applied_minor = $2, status = $3 WHERE id = $1`,
			o.id, newApplied, status); err != nil {
			return applied, err
		}
		if _, err := s.ledger.Post(ctx, tx, ledger.Entry{
			Kind: ledger.KindAdjustment, Currency: cur, OccurredAt: s.clk.Now(),
			Description:   "Settlement offset applied",
			ReferenceType: "settlement_offset", ReferenceID: o.publicID,
			IdempotencyKey: "offset:" + o.publicID + ":" + takeM.Decimal(),
			Lines: []ledger.Line{
				{AccountID: payableAcct, Direction: ledger.Debit, Amount: takeM, Memo: "netted against an outstanding recovery"},
				{AccountID: offsetAcct, Direction: ledger.Credit, Amount: takeM, Memo: "recovery collected"},
			},
		}); err != nil {
			return applied, err
		}
		if applied, err = applied.Add(takeM); err != nil {
			return applied, err
		}
		if remaining, err = remaining.Sub(takeM); err != nil {
			return applied, err
		}
	}
	return applied, nil
}

// CompleteProtectedOrders moves fulfilled orders to completed once their
// protection window has closed with no dispute, which is what finally takes
// them out of the settlement-hold population.
func (s *Service) CompleteProtectedOrders(ctx context.Context, window time.Duration, limit int) (int, error) {
	if limit <= 0 {
		limit = 500
	}
	var completed int
	err := s.db.InTx(ctx, db.TxOptions{Name: "complete_orders"}, func(ctx context.Context, tx db.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE orders o
			   SET status = 'completed', completed_at = now()
			 WHERE o.id IN (
			   SELECT id FROM orders
			    WHERE status = 'fulfilled'
			      AND fulfilled_at IS NOT NULL
			      AND fulfilled_at < now() - $1::interval
			      AND NOT EXISTS (
			        SELECT 1 FROM order_items i
			          JOIN disputes d ON d.order_item_id = i.id
			         WHERE i.order_id = orders.id
			           AND d.status IN ('open','awaiting_seller','awaiting_buyer','under_review'))
			      AND NOT EXISTS (
			        SELECT 1 FROM chargebacks c
			         WHERE c.order_id = orders.id
			           AND c.status NOT IN ('won','expired'))
			    ORDER BY fulfilled_at
			    LIMIT $2
			 )`, window.String(), limit)
		if err != nil {
			return fmt.Errorf("orders: complete protected: %w", err)
		}
		completed = int(tag.RowsAffected())
		return nil
	})
	return completed, err
}
