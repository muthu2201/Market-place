package audit_test

import (
	"context"
	"sync"
	"testing"

	"github.com/muthu2201/market-place/internal/modules/audit"
	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/dbtest"
	"github.com/muthu2201/market-place/internal/platform/ids"
)

func TestChainVerifiesAfterSequentialWrites(t *testing.T) {
	d := dbtest.Fresh(t)
	ctx := dbtest.Ctx(t)
	s := audit.New()

	for i := 0; i < 50; i++ {
		if err := s.Record(ctx, d, audit.Event{
			ActorKind: audit.ActorSystem, Action: "test.event",
			SubjectType: "test", SubjectID: ids.NewPublic(ids.PrefixOrder),
			Metadata: map[string]any{"i": i},
		}); err != nil {
			t.Fatal(err)
		}
	}
	brk, err := s.Verify(ctx, d, 0)
	if err != nil {
		t.Fatal(err)
	}
	if brk != nil {
		t.Fatalf("chain broken at %d: %s", brk.Seq, brk.Reason)
	}
}

// The chain must survive concurrent writers. A hash chain that forks under load
// provides no tamper evidence at all, and a load test found exactly that before
// the chain position was moved inside the serialised section.
func TestChainVerifiesAfterConcurrentWrites(t *testing.T) {
	d := dbtest.Fresh(t)
	ctx := dbtest.Ctx(t)
	s := audit.New()

	const workers, each = 16, 25
	var wg sync.WaitGroup
	errs := make([]error, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				if err := s.Record(ctx, d, audit.Event{
					ActorKind: audit.ActorSystem, Action: "concurrent.event",
					SubjectType: "test", SubjectID: ids.NewPublic(ids.PrefixOrder),
					Metadata: map[string]any{"worker": w, "i": i},
				}); err != nil {
					errs[w] = err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	for w, err := range errs {
		if err != nil {
			t.Fatalf("worker %d: %v", w, err)
		}
	}

	var n int
	if err := d.QueryRow(ctx, `SELECT count(*) FROM audit_log`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != workers*each {
		t.Fatalf("wrote %d entries, want %d", n, workers*each)
	}

	brk, err := s.Verify(ctx, d, 0)
	if err != nil {
		t.Fatal(err)
	}
	if brk != nil {
		t.Fatalf("the chain forked under concurrency: broken at %d (%s)", brk.Seq, brk.Reason)
	}

	// Chain positions must be a dense run with no gaps or duplicates.
	var minPos, maxPos, distinct int64
	if err := d.QueryRow(ctx,
		`SELECT MIN(chain_pos), MAX(chain_pos), COUNT(DISTINCT chain_pos) FROM audit_log`).Scan(&minPos, &maxPos, &distinct); err != nil {
		t.Fatal(err)
	}
	if distinct != int64(n) || maxPos-minPos+1 != int64(n) {
		t.Fatalf("chain positions are not a dense run: min=%d max=%d distinct=%d rows=%d",
			minPos, maxPos, distinct, n)
	}
}

// Tamper evidence is the whole point, so it is proved rather than assumed.
func TestTamperingIsDetected(t *testing.T) {
	d := dbtest.Fresh(t)
	ctx := dbtest.Ctx(t)
	s := audit.New()

	for i := 0; i < 10; i++ {
		if err := s.Record(ctx, d, audit.Event{
			ActorKind: audit.ActorAdmin, Action: "money.moved",
			SubjectType: "order", SubjectID: "ord_" + ids.Correlation(),
			Metadata: map[string]any{"amount_minor": 100000 + i},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if brk, _ := s.Verify(ctx, d, 0); brk != nil {
		t.Fatalf("chain should verify before tampering: %v", brk)
	}

	// Alter history the way an attacker with database access would: disable the
	// append-only guard, change one row, restore the guard.
	if _, err := d.Exec(ctx, `
		ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only;
		UPDATE audit_log SET metadata = jsonb_set(metadata, '{amount_minor}', '1')
		 WHERE chain_pos = (SELECT MIN(chain_pos) + 4 FROM audit_log);
		ALTER TABLE audit_log ENABLE TRIGGER audit_log_append_only;`); err != nil {
		t.Fatal(err)
	}

	brk, err := s.Verify(ctx, d, 0)
	if err != nil {
		t.Fatal(err)
	}
	if brk == nil {
		t.Fatal("an altered entry must break the chain; the log provides no evidence otherwise")
	}
	if brk.Reason == "" {
		t.Fatal("a detected break must say what is wrong")
	}

	// Deleting a row must also be detected.
	if _, err := d.Exec(ctx, `
		ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only;
		DELETE FROM audit_log WHERE chain_pos = (SELECT MIN(chain_pos) + 2 FROM audit_log);
		ALTER TABLE audit_log ENABLE TRIGGER audit_log_append_only;`); err != nil {
		t.Fatal(err)
	}
	if brk, _ := s.Verify(ctx, d, 0); brk == nil {
		t.Fatal("a deleted entry must break the chain")
	}
}

func TestAppendOnlyGuardRefusesOrdinaryMutation(t *testing.T) {
	d := dbtest.Fresh(t)
	ctx := dbtest.Ctx(t)
	s := audit.New()
	if err := s.Record(ctx, d, audit.Event{
		ActorKind: audit.ActorSystem, Action: "test", SubjectType: "test", SubjectID: "1",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(ctx, `UPDATE audit_log SET action = 'rewritten'`); err == nil {
		t.Fatal("the audit log must refuse an UPDATE")
	}
	if _, err := d.Exec(ctx, `DELETE FROM audit_log`); err == nil {
		t.Fatal("the audit log must refuse a DELETE")
	}
}

func TestRecordIsAtomicWithItsTransaction(t *testing.T) {
	d := dbtest.Fresh(t)
	ctx := dbtest.Ctx(t)
	s := audit.New()

	sentinel := context.Canceled
	err := d.InTx(ctx, db.TxOptions{Name: "rollback"}, func(ctx context.Context, tx db.Tx) error {
		if err := s.Record(ctx, tx, audit.Event{
			ActorKind: audit.ActorSystem, Action: "should.not.survive",
			SubjectType: "test", SubjectID: "1",
		}); err != nil {
			return err
		}
		return sentinel
	})
	if err != sentinel {
		t.Fatalf("expected the sentinel, got %v", err)
	}
	var n int
	if err := d.QueryRow(ctx,
		`SELECT count(*) FROM audit_log WHERE action = 'should.not.survive'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("an audit entry must not survive a rolled-back transaction: it would claim something happened that did not")
	}
}
