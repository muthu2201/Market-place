package ledger_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/muthu2201/market-place/internal/modules/ledger"
	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/dbtest"
	"github.com/muthu2201/market-place/internal/platform/ids"
	"github.com/muthu2201/market-place/internal/platform/money"
)

func inr(minor int64) money.Money { return money.MustNew(minor, money.INR) }

func newService() *ledger.Service { return ledger.New(dbtest.Metrics()) }

// post is the shape every caller uses in production: a journal entry is always
// written inside the transaction that carries the state change causing it.
func post(t *testing.T, ctx context.Context, d *db.DB, s *ledger.Service, e ledger.Entry) (ledger.Posted, error) {
	t.Helper()
	var res ledger.Posted
	err := d.InTx(ctx, db.TxOptions{Name: "ledger_post"}, func(ctx context.Context, tx db.Tx) error {
		var err error
		res, err = s.Post(ctx, tx, e)
		return err
	})
	return res, err
}

func accounts(t *testing.T, ctx context.Context, d *db.DB, s *ledger.Service) (clearing, income ids.UUID) {
	t.Helper()
	var err error
	if clearing, err = s.AccountByCode(ctx, d, "platform.clearing.razorpay"); err != nil {
		t.Fatal(err)
	}
	if income, err = s.AccountByCode(ctx, d, "platform.income.commission"); err != nil {
		t.Fatal(err)
	}
	return
}

func TestPostBalancedEntry(t *testing.T) {
	d := dbtest.Fresh(t)
	ctx := dbtest.Ctx(t)
	s := newService()
	clearing, income := accounts(t, ctx, d, s)

	res, err := post(t, ctx, d, s, ledger.Entry{
		Kind: ledger.KindPlatformFee, Currency: money.INR, OccurredAt: time.Now().UTC(),
		Description: "commission on order 1", ReferenceType: "order", ReferenceID: "ord_1",
		IdempotencyKey: "fee:ord_1",
		Lines: []ledger.Line{
			{AccountID: clearing, Direction: ledger.Debit, Amount: inr(18000)},
			{AccountID: income, Direction: ledger.Credit, Amount: inr(18000)},
		},
	})
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	if res.Replayed {
		t.Fatal("a first post is not a replay")
	}

	bal, err := s.BalanceOf(ctx, d, "platform.income.commission", money.INR)
	if err != nil {
		t.Fatal(err)
	}
	if bal.Decimal() != "180.00" {
		t.Fatalf("commission balance = %s, want 180.00", bal.Decimal())
	}
	if err := s.AssertBalanced(ctx, d); err != nil {
		t.Fatal(err)
	}
}

func TestUnbalancedEntryRefusedInGoBeforeSQL(t *testing.T) {
	d := dbtest.Fresh(t)
	ctx := dbtest.Ctx(t)
	s := newService()
	clearing, income := accounts(t, ctx, d, s)

	_, err := post(t, ctx, d, s, ledger.Entry{
		Kind: ledger.KindAdjustment, Currency: money.INR,
		Description: "bad", ReferenceType: "test", ReferenceID: "x", IdempotencyKey: "bad:1",
		Lines: []ledger.Line{
			{AccountID: clearing, Direction: ledger.Debit, Amount: inr(100)},
			{AccountID: income, Direction: ledger.Credit, Amount: inr(99)},
		},
	})
	if !errors.Is(err, ledger.ErrUnbalanced) {
		t.Fatalf("want ErrUnbalanced, got %v", err)
	}
	var n int
	if err := d.QueryRow(ctx, `SELECT count(*) FROM journal_entries`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a refused entry must write nothing, found %d entries", n)
	}
}

// The Go check can be bypassed; the database check cannot. This proves the
// second line of defence is real by writing raw SQL that skips the package.
func TestDatabaseRefusesUnbalancedEntryEvenWhenGoIsBypassed(t *testing.T) {
	d := dbtest.Fresh(t)
	ctx := dbtest.Ctx(t)
	s := newService()
	clearing, income := accounts(t, ctx, d, s)

	err := d.InTx(ctx, db.TxOptions{Name: "bypass"}, func(ctx context.Context, tx db.Tx) error {
		entryID := ids.NewUUIDv7()
		if _, err := tx.Exec(ctx, `
			INSERT INTO journal_entries (id, public_id, kind, currency, occurred_at, description, reference_type, reference_id, idempotency_key)
			VALUES ($1,$2,'adjustment','INR',now(),'bypass attempt','test','x','bypass:1')`,
			entryID, ids.NewPublic(ids.PrefixJournal)); err != nil {
			return err
		}
		for i, l := range []struct {
			acct ids.UUID
			dir  string
			amt  int64
		}{{clearing, "debit", 100}, {income, "credit", 1}} {
			if _, err := tx.Exec(ctx, `
				INSERT INTO journal_lines (id, entry_id, line_no, account_id, direction, amount_minor, currency)
				VALUES ($1,$2,$3,$4,$5,$6,'INR')`,
				ids.NewUUIDv7(), entryID, i+1, l.acct, l.dir, l.amt); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil {
		t.Fatal("the database must refuse an unbalanced commit")
	}
	if msg, ok := db.IsRaisedException(err); !ok || !contains(msg, "does not balance") {
		t.Fatalf("expected a balance violation, got %v", err)
	}
}

func TestIdempotentReplayWritesNothingTwice(t *testing.T) {
	d := dbtest.Fresh(t)
	ctx := dbtest.Ctx(t)
	s := newService()
	clearing, income := accounts(t, ctx, d, s)

	entry := ledger.Entry{
		Kind: ledger.KindOrderCapture, Currency: money.INR,
		Description: "capture", ReferenceType: "order", ReferenceID: "ord_9",
		IdempotencyKey: "capture:ord_9",
		Lines: []ledger.Line{
			{AccountID: clearing, Direction: ledger.Debit, Amount: inr(50000)},
			{AccountID: income, Direction: ledger.Credit, Amount: inr(50000)},
		},
	}
	first, err := post(t, ctx, d, s, entry)
	if err != nil {
		t.Fatal(err)
	}
	second, err := post(t, ctx, d, s, entry)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Replayed || second.EntryID != first.EntryID {
		t.Fatalf("replay should return the original entry: %+v vs %+v", first, second)
	}
	bal, _ := s.BalanceOf(ctx, d, "platform.income.commission", money.INR)
	if bal.Decimal() != "500.00" {
		t.Fatalf("a replay must not double-post: balance = %s", bal.Decimal())
	}
}

// Webhook storms are concurrent, not sequential. Many goroutines posting the
// same idempotency key must produce exactly one entry.
func TestConcurrentReplayPostsExactlyOnce(t *testing.T) {
	d := dbtest.Fresh(t)
	ctx := dbtest.Ctx(t)
	s := newService()
	clearing, income := accounts(t, ctx, d, s)

	const workers = 24
	var wg sync.WaitGroup
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = post(t, ctx, d, s, ledger.Entry{
				Kind: ledger.KindOrderCapture, Currency: money.INR,
				Description: "race", ReferenceType: "order", ReferenceID: "ord_race",
				IdempotencyKey: "capture:ord_race",
				Lines: []ledger.Line{
					{AccountID: clearing, Direction: ledger.Debit, Amount: inr(12345)},
					{AccountID: income, Direction: ledger.Credit, Amount: inr(12345)},
				},
			})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d: %v", i, err)
		}
	}
	var n int
	if err := d.QueryRow(ctx, `SELECT count(*) FROM journal_entries WHERE idempotency_key = 'capture:ord_race'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("%d entries written for one idempotency key", n)
	}
	bal, _ := s.BalanceOf(ctx, d, "platform.income.commission", money.INR)
	if bal.Decimal() != "123.45" {
		t.Fatalf("balance = %s, want 123.45", bal.Decimal())
	}
}

func TestSellerSubsidiaryAccountsOpenOnDemand(t *testing.T) {
	d := dbtest.Fresh(t)
	ctx := dbtest.Ctx(t)
	s := newService()
	clearing, _ := accounts(t, ctx, d, s)
	sellerID := ids.NewUUIDv7()

	payable, err := s.SellerAccount(ctx, d, sellerID, "payable", money.INR)
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.SellerAccount(ctx, d, sellerID, "payable", money.INR)
	if err != nil {
		t.Fatal(err)
	}
	if payable != again {
		t.Fatal("opening the same account twice must return the same id")
	}
	reserve, err := s.SellerAccount(ctx, d, sellerID, "reserve", money.INR)
	if err != nil {
		t.Fatal(err)
	}
	if reserve == payable {
		t.Fatal("payable and reserve must be distinct accounts")
	}
	if _, err := s.SellerAccount(ctx, d, sellerID, "wallet", money.INR); err == nil {
		t.Fatal("an unknown purpose must be refused: this platform has no wallets")
	}

	if _, err := post(t, ctx, d, s, ledger.Entry{
		Kind: ledger.KindOrderCapture, Currency: money.INR,
		Description: "capture to seller", ReferenceType: "order", ReferenceID: "ord_s",
		IdempotencyKey: "capture:ord_s",
		Lines: []ledger.Line{
			{AccountID: clearing, Direction: ledger.Debit, Amount: inr(200000)},
			{AccountID: payable, Direction: ledger.Credit, Amount: inr(200000)},
		},
	}); err != nil {
		t.Fatal(err)
	}
	bal, err := s.Balance(ctx, d, payable)
	if err != nil {
		t.Fatal(err)
	}
	if bal != 200000 {
		t.Fatalf("seller payable = %d, want 200000", bal)
	}
}

func TestControlAccountsCannotBePostedTo(t *testing.T) {
	d := dbtest.Fresh(t)
	ctx := dbtest.Ctx(t)
	s := newService()
	clearing, _ := accounts(t, ctx, d, s)
	control, err := s.AccountByCode(ctx, d, "platform.payable.seller_control")
	if err != nil {
		t.Fatal(err)
	}
	_, err = post(t, ctx, d, s, ledger.Entry{
		Kind: ledger.KindAdjustment, Currency: money.INR,
		Description: "into a control account", ReferenceType: "test", ReferenceID: "c",
		IdempotencyKey: "control:1",
		Lines: []ledger.Line{
			{AccountID: clearing, Direction: ledger.Debit, Amount: inr(1)},
			{AccountID: control, Direction: ledger.Credit, Amount: inr(1)},
		},
	})
	if err == nil {
		t.Fatal("posting directly to a control account must be refused")
	}
}

func TestRollupMatchesOnTheFlyBalance(t *testing.T) {
	d := dbtest.Fresh(t)
	ctx := dbtest.Ctx(t)
	s := newService()
	clearing, income := accounts(t, ctx, d, s)

	for i := 0; i < 200; i++ {
		if _, err := post(t, ctx, d, s, ledger.Entry{
			Kind: ledger.KindPlatformFee, Currency: money.INR,
			Description: "fee", ReferenceType: "order", ReferenceID: "o",
			IdempotencyKey: "fee:" + ids.NewPublic(ids.PrefixJournal),
			Lines: []ledger.Line{
				{AccountID: clearing, Direction: ledger.Debit, Amount: inr(int64(i + 1))},
				{AccountID: income, Direction: ledger.Credit, Amount: inr(int64(i + 1))},
			},
		}); err != nil {
			t.Fatal(err)
		}
	}
	before, _ := s.Balance(ctx, d, income)
	if _, err := s.Rollup(ctx, d); err != nil {
		t.Fatal(err)
	}
	after, _ := s.Balance(ctx, d, income)
	if before != after {
		t.Fatalf("rollup changed the answer: %d -> %d", before, after)
	}
	// 1+2+...+200
	if after != 20100 {
		t.Fatalf("balance = %d, want 20100", after)
	}
	// A second rollup must be a no-op, not a double count.
	if _, err := s.Rollup(ctx, d); err != nil {
		t.Fatal(err)
	}
	if third, _ := s.Balance(ctx, d, income); third != after {
		t.Fatalf("second rollup double-counted: %d -> %d", after, third)
	}
}

func TestEntriesForBuildsAStatement(t *testing.T) {
	d := dbtest.Fresh(t)
	ctx := dbtest.Ctx(t)
	s := newService()
	clearing, income := accounts(t, ctx, d, s)

	if _, err := post(t, ctx, d, s, ledger.Entry{
		Kind: ledger.KindPlatformFee, Currency: money.INR,
		Description: "commission on ord_7", ReferenceType: "order", ReferenceID: "ord_7",
		IdempotencyKey: "fee:ord_7",
		Lines: []ledger.Line{
			{AccountID: clearing, Direction: ledger.Debit, Amount: inr(900), Memo: "from provider clearing"},
			{AccountID: income, Direction: ledger.Credit, Amount: inr(900), Memo: "platform commission"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	entries, err := s.EntriesFor(ctx, d, "order", "ord_7")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || len(entries[0].Lines) != 2 {
		t.Fatalf("got %d entries", len(entries))
	}
	if entries[0].Lines[0].AccountCode != "platform.clearing.razorpay" {
		t.Fatalf("unexpected first line %+v", entries[0].Lines[0])
	}
	if entries[0].Lines[1].Memo != "platform commission" {
		t.Fatalf("memo was not preserved: %q", entries[0].Lines[1].Memo)
	}
}

func TestMissingIdempotencyKeyRefused(t *testing.T) {
	d := dbtest.Fresh(t)
	ctx := dbtest.Ctx(t)
	s := newService()
	clearing, income := accounts(t, ctx, d, s)
	_, err := post(t, ctx, d, s, ledger.Entry{
		Kind: ledger.KindAdjustment, Currency: money.INR,
		Description: "no key", ReferenceType: "t", ReferenceID: "1",
		Lines: []ledger.Line{
			{AccountID: clearing, Direction: ledger.Debit, Amount: inr(1)},
			{AccountID: income, Direction: ledger.Credit, Amount: inr(1)},
		},
	})
	if !errors.Is(err, ledger.ErrNoIdempotency) {
		t.Fatalf("want ErrNoIdempotency, got %v", err)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		len(needle) == 0 || indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
