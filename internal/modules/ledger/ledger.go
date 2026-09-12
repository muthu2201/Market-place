// Package ledger is the Go face of the double-entry journal.
//
// Every economic event in the system is expressed here as a balanced set of
// debits and credits. The database enforces the balance rule and immutability
// (see db/migrations/0004_ledger.sql); this package makes the correct thing the
// easy thing and makes posting idempotent.
//
// Nothing outside this package may INSERT into journal_entries or journal_lines;
// cmd/archcheck enforces that.
package ledger

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/muthu2201/market-place/internal/platform/clock"
	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/ids"
	"github.com/muthu2201/market-place/internal/platform/metrics"
	"github.com/muthu2201/market-place/internal/platform/money"
)

// Kind classifies an entry. The set matches the CHECK constraint on
// journal_entries.kind; adding one requires a migration, deliberately.
type Kind string

const (
	KindOrderCapture          Kind = "order_capture"
	KindPlatformFee           Kind = "platform_fee"
	KindPSPFee                Kind = "psp_fee"
	KindTCSCollection         Kind = "tcs_collection"
	KindTDSDeduction          Kind = "tds_deduction"
	KindSellerTransfer        Kind = "seller_transfer"
	KindSettlementRelease     Kind = "settlement_release"
	KindRollingReserveHold    Kind = "rolling_reserve_hold"
	KindRollingReserveRelease Kind = "rolling_reserve_release"
	KindRefund                Kind = "refund"
	KindTransferReversal      Kind = "transfer_reversal"
	KindChargeback            Kind = "chargeback"
	KindChargebackWon         Kind = "chargeback_representment_won"
	KindPayout                Kind = "payout"
	KindTaxRemittance         Kind = "tax_remittance"
	KindAdjustment            Kind = "adjustment"
	KindOpeningBalance        Kind = "opening_balance"
	KindFXRevaluation         Kind = "fx_revaluation"
)

// Direction is which side of the journal a line sits on.
type Direction string

const (
	Debit  Direction = "debit"
	Credit Direction = "credit"
)

// Line is one posting.
type Line struct {
	AccountID ids.UUID
	Direction Direction
	Amount    money.Money
	Memo      string
}

// Entry is one balanced economic event.
type Entry struct {
	Kind       Kind
	Currency   money.Currency
	OccurredAt time.Time
	// Description is written for a human reading a statement, not for a machine.
	Description string
	// Reference ties the entry back to the thing that caused it.
	ReferenceType string
	ReferenceID   string
	// IdempotencyKey makes posting safe under webhook replay and at-least-once
	// outbox delivery. A repeat posts nothing and reports the original.
	IdempotencyKey string
	// ReversesEntryID is set when this entry corrects an earlier one. History is
	// never edited; it is compensated.
	ReversesEntryID *ids.UUID
	Metadata        map[string]any
	Lines           []Line
}

var (
	ErrUnbalanced      = errors.New("ledger: entry does not balance")
	ErrEmptyEntry      = errors.New("ledger: entry has fewer than two lines")
	ErrCurrencyMixed   = errors.New("ledger: entry mixes currencies")
	ErrNoIdempotency   = errors.New("ledger: entry has no idempotency key")
	ErrAccountNotFound = errors.New("ledger: account not found")
)

// Validate checks the entry in Go before it reaches the database. The database
// checks again; this layer exists so the error a developer sees names the field.
func (e Entry) Validate() error {
	switch {
	case e.Kind == "":
		return errors.New("ledger: entry kind is required")
	case e.Description == "":
		return errors.New("ledger: entry description is required")
	case e.ReferenceType == "" || e.ReferenceID == "":
		return errors.New("ledger: entry reference is required")
	case e.IdempotencyKey == "":
		return ErrNoIdempotency
	case len(e.Lines) < 2:
		return ErrEmptyEntry
	}

	var debits, credits int64
	for i, l := range e.Lines {
		if l.Amount.Currency() != e.Currency {
			return fmt.Errorf("%w: line %d is %s, entry is %s", ErrCurrencyMixed, i+1, l.Amount.Currency(), e.Currency)
		}
		if !l.Amount.IsPositive() {
			return fmt.Errorf("ledger: line %d amount must be positive (direction carries the sign)", i+1)
		}
		if l.AccountID.IsZero() {
			return fmt.Errorf("ledger: line %d has no account", i+1)
		}
		switch l.Direction {
		case Debit:
			debits += l.Amount.Minor()
		case Credit:
			credits += l.Amount.Minor()
		default:
			return fmt.Errorf("ledger: line %d has invalid direction %q", i+1, l.Direction)
		}
	}
	if debits != credits {
		return fmt.Errorf("%w: debits %d, credits %d, difference %d", ErrUnbalanced, debits, credits, debits-credits)
	}
	return nil
}

// Posted describes the result of Post.
type Posted struct {
	EntryID  ids.UUID
	PublicID string
	// Replayed is true when the idempotency key had already been used, in which
	// case nothing new was written and the identifiers are the originals.
	Replayed bool
}

// Service posts and queries the journal.
type Service struct {
	m   *metrics.App
	clk clock.Clock
}

// New builds the service. The clock is injected so that entry timestamps are
// controllable in tests and consistent with the rest of a unit of work.
func New(m *metrics.App) *Service { return &Service{m: m, clk: clock.System()} }

// NewWithClock is used where time must be controlled, chiefly in tests and in
// back-dated corrections.
func NewWithClock(m *metrics.App, clk clock.Clock) *Service {
	if clk == nil {
		clk = clock.System()
	}
	return &Service{m: m, clk: clk}
}

// Post writes a balanced entry.
//
// It takes a db.Tx, not a db.Querier, and that is load-bearing: an entry and
// its lines must land in one transaction or the deferred balance check fires
// against an entry that has no lines yet. Taking Tx also means the entry is
// written in the same transaction as the state change that caused it, which is
// what makes the ledger and the domain tables impossible to diverge.
func (s *Service) Post(ctx context.Context, q db.Tx, e Entry) (Posted, error) {
	if err := e.Validate(); err != nil {
		if s.m != nil && errors.Is(err, ErrUnbalanced) {
			s.m.LedgerImbalance.Inc(string(e.Kind))
		}
		return Posted{}, err
	}

	// Idempotent replay: if this key is already present, return the original.
	var existingID ids.UUID
	var existingPublic string
	err := q.QueryRow(ctx,
		`SELECT id, public_id FROM journal_entries WHERE idempotency_key = $1`,
		e.IdempotencyKey,
	).Scan(&existingID, &existingPublic)
	if err == nil {
		return Posted{EntryID: existingID, PublicID: existingPublic, Replayed: true}, nil
	}
	if !db.IsNoRows(err) {
		return Posted{}, fmt.Errorf("ledger: idempotency lookup: %w", err)
	}

	entryID := ids.NewUUIDv7()
	publicID := ids.NewPublic(ids.PrefixJournal)
	occurred := e.OccurredAt
	if occurred.IsZero() {
		occurred = s.clk.Now()
	}
	meta := e.Metadata
	if meta == nil {
		meta = map[string]any{}
	}

	var reverses any
	if e.ReversesEntryID != nil {
		reverses = *e.ReversesEntryID
	}

	if _, err := q.Exec(ctx, `
		INSERT INTO journal_entries
		  (id, public_id, kind, currency, occurred_at, description,
		   reference_type, reference_id, reverses_entry_id, idempotency_key, metadata)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		entryID, publicID, string(e.Kind), string(e.Currency), occurred, e.Description,
		e.ReferenceType, e.ReferenceID, reverses, e.IdempotencyKey, meta,
	); err != nil {
		// A concurrent poster may have claimed the key between our snapshot and
		// our insert. Recovering here is impossible: the failed statement has
		// already aborted the transaction, so no further query can run inside
		// it. db.InTx classifies this constraint as retryable, so the caller's
		// unit of work is replayed against a fresh snapshot, where the winner's
		// row is visible and the lookup above takes the replay path.
		return Posted{}, fmt.Errorf("ledger: insert entry: %w", err)
	}

	for i, l := range e.Lines {
		if _, err := q.Exec(ctx, `
			INSERT INTO journal_lines
			  (id, entry_id, line_no, account_id, direction, amount_minor, currency, memo)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			ids.NewUUIDv7(), entryID, i+1, l.AccountID, string(l.Direction),
			l.Amount.Minor(), string(l.Amount.Currency()), nullIfEmpty(l.Memo),
		); err != nil {
			return Posted{}, fmt.Errorf("ledger: insert line %d: %w", i+1, err)
		}
	}

	if s.m != nil {
		s.m.LedgerPostings.Add(uint64(len(e.Lines)), string(e.Kind))
	}
	return Posted{EntryID: entryID, PublicID: publicID}, nil
}

// AccountByCode resolves a chart-of-accounts code to its id.
func (s *Service) AccountByCode(ctx context.Context, q db.Querier, code string) (ids.UUID, error) {
	var id ids.UUID
	err := q.QueryRow(ctx, `SELECT id FROM ledger_accounts WHERE code = $1 AND closed_at IS NULL`, code).Scan(&id)
	if db.IsNoRows(err) {
		return ids.UUID{}, fmt.Errorf("%w: %s", ErrAccountNotFound, code)
	}
	if err != nil {
		return ids.UUID{}, fmt.Errorf("ledger: resolve %s: %w", code, err)
	}
	return id, nil
}

// SellerAccount returns (opening on first use) a seller's subsidiary account.
// purpose is "payable" or "reserve".
func (s *Service) SellerAccount(ctx context.Context, q db.Querier, sellerID ids.UUID, purpose string, cur money.Currency) (ids.UUID, error) {
	var id ids.UUID
	err := q.QueryRow(ctx, `SELECT seller_ledger_account($1, $2, $3)`, sellerID, purpose, string(cur)).Scan(&id)
	if err != nil {
		return ids.UUID{}, fmt.Errorf("ledger: seller account (%s/%s): %w", sellerID, purpose, err)
	}
	return id, nil
}

// Balance returns the signed balance in the account's natural direction.
func (s *Service) Balance(ctx context.Context, q db.Querier, accountID ids.UUID) (int64, error) {
	var v int64
	if err := q.QueryRow(ctx, `SELECT ledger_balance($1)`, accountID).Scan(&v); err != nil {
		return 0, fmt.Errorf("ledger: balance: %w", err)
	}
	return v, nil
}

// BalanceOf is Balance keyed by account code, for readable call sites.
func (s *Service) BalanceOf(ctx context.Context, q db.Querier, code string, cur money.Currency) (money.Money, error) {
	id, err := s.AccountByCode(ctx, q, code)
	if err != nil {
		return money.Money{}, err
	}
	v, err := s.Balance(ctx, q, id)
	if err != nil {
		return money.Money{}, err
	}
	return money.New(v, cur)
}

// TrialBalanceRow is one currency's totals.
type TrialBalanceRow struct {
	Currency   money.Currency
	Debits     int64
	Credits    int64
	Difference int64
}

// TrialBalance is the system's health check. Any non-zero Difference is an
// incident: it means a posting escaped the balance rule, which should be
// impossible, so it would indicate tampering or a disabled trigger.
func (s *Service) TrialBalance(ctx context.Context, q db.Querier) ([]TrialBalanceRow, error) {
	rows, err := q.Query(ctx, `SELECT currency, COALESCE(total_debits,0), COALESCE(total_credits,0), COALESCE(difference,0) FROM ledger_trial_balance ORDER BY currency`)
	if err != nil {
		return nil, fmt.Errorf("ledger: trial balance: %w", err)
	}
	defer rows.Close()

	var out []TrialBalanceRow
	for rows.Next() {
		var r TrialBalanceRow
		var cur string
		if err := rows.Scan(&cur, &r.Debits, &r.Credits, &r.Difference); err != nil {
			return nil, err
		}
		r.Currency = money.Currency(cur)
		out = append(out, r)
	}
	return out, rows.Err()
}

// AssertBalanced returns an error naming the first out-of-balance currency.
func (s *Service) AssertBalanced(ctx context.Context, q db.Querier) error {
	rows, err := s.TrialBalance(ctx, q)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if r.Difference != 0 {
			return fmt.Errorf("ledger: TRIAL BALANCE BROKEN for %s: debits %d, credits %d, difference %d",
				r.Currency, r.Debits, r.Credits, r.Difference)
		}
	}
	return nil
}

// Rollup advances the balance watermark. The worker calls it on a schedule.
func (s *Service) Rollup(ctx context.Context, q db.Querier) (int, error) {
	var n int
	if err := q.QueryRow(ctx, `SELECT ledger_rollup()`).Scan(&n); err != nil {
		return 0, fmt.Errorf("ledger: rollup: %w", err)
	}
	return n, nil
}

// EntryLine is a line as read back for a statement.
type EntryLine struct {
	AccountCode string
	AccountName string
	Direction   Direction
	Amount      money.Money
	Memo        string
}

// EntryDetail is an entry with its lines, for a seller statement or an audit.
type EntryDetail struct {
	PublicID      string
	Kind          Kind
	Description   string
	OccurredAt    time.Time
	ReferenceType string
	ReferenceID   string
	Lines         []EntryLine
}

// EntriesFor returns every entry touching a reference, oldest first.
func (s *Service) EntriesFor(ctx context.Context, q db.Querier, refType, refID string) ([]EntryDetail, error) {
	rows, err := q.Query(ctx, `
		SELECT e.public_id, e.kind, e.description, e.occurred_at, e.reference_type, e.reference_id,
		       a.code, a.name, l.direction, l.amount_minor, l.currency, COALESCE(l.memo,'')
		  FROM journal_entries e
		  JOIN journal_lines  l ON l.entry_id = e.id
		  JOIN ledger_accounts a ON a.id = l.account_id
		 WHERE e.reference_type = $1 AND e.reference_id = $2
		 ORDER BY e.occurred_at, e.id, l.line_no`,
		refType, refID)
	if err != nil {
		return nil, fmt.Errorf("ledger: entries for %s/%s: %w", refType, refID, err)
	}
	defer rows.Close()

	var out []EntryDetail
	var cur *EntryDetail
	for rows.Next() {
		var pub, kind, desc, rt, ri, code, name, dir, curr, memo string
		var at time.Time
		var amt int64
		if err := rows.Scan(&pub, &kind, &desc, &at, &rt, &ri, &code, &name, &dir, &amt, &curr, &memo); err != nil {
			return nil, err
		}
		if cur == nil || cur.PublicID != pub {
			out = append(out, EntryDetail{
				PublicID: pub, Kind: Kind(kind), Description: desc,
				OccurredAt: at, ReferenceType: rt, ReferenceID: ri,
			})
			cur = &out[len(out)-1]
		}
		m, err := money.New(amt, money.Currency(curr))
		if err != nil {
			return nil, err
		}
		cur.Lines = append(cur.Lines, EntryLine{
			AccountCode: code, AccountName: name, Direction: Direction(dir), Amount: m, Memo: memo,
		})
	}
	return out, rows.Err()
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
