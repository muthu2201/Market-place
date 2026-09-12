package api

import (
	"context"
	"net/http"

	"github.com/muthu2201/market-place/internal/platform/httpx"
	"github.com/muthu2201/market-place/internal/platform/problem"
)

// The /internal/verify endpoints run the system's own correctness audit.
//
// They exist for three audiences and are worth having for all three: the load
// harness asserts them after a run, the monitoring system polls them
// continuously, and an operator reaches for them first during an incident.
// They are gated by the same token as metrics, because they disclose volume.

// requireInternalToken protects the verification surface.
func (s *Server) requireInternalToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearer(r)
		if s.cfg.Observe.MetricsToken == "" || !constantTimeEqual(token, s.cfg.Observe.MetricsToken) {
			// A staff session is the alternative credential, so an operator does
			// not need the token to hand during an incident.
			sess := SessionOf(r.Context())
			if sess == nil || !sess.User.IsStaff() {
				httpx.Fail(w, r, problem.Unauthenticated("This endpoint requires an operations credential."))
				return
			}
		}
		next(w, r)
	}
}

func bearer(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) > len(prefix) && h[:len(prefix)] == prefix {
		return h[len(prefix):]
	}
	return ""
}

func (s *Server) handleVerifyTrialBalance(w http.ResponseWriter, r *http.Request) {
	s.handleTrialBalance(w, r)
}

func (s *Server) handleVerifyAudit(w http.ResponseWriter, r *http.Request) {
	s.handleVerifyAuditChain(w, r)
}

// consistencyFinding is one detected discrepancy.
type consistencyFinding struct {
	Check  string `json:"check"`
	Count  int    `json:"count"`
	Detail string `json:"detail"`
	Sample string `json:"sample,omitempty"`
}

// handleVerifyConsistency cross-checks the domain tables against the ledger.
//
// Each query below answers a question that, if answered wrongly, means someone
// has lost money or received something they did not pay for.
func (s *Server) handleVerifyConsistency(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	checks := []struct {
		name   string
		detail string
		query  string
	}{
		{
			"paid_orders_have_capture_postings",
			"every paid order must have a balanced capture entry in the journal",
			`SELECT count(*), COALESCE(min(o.public_id), '')
			   FROM orders o
			  WHERE o.status IN ('paid','fulfilled','completed')
			    AND NOT EXISTS (
			      SELECT 1 FROM journal_entries e
			       WHERE e.reference_type = 'order' AND e.reference_id = o.public_id
			         AND e.kind = 'order_capture')`,
		},
		{
			"capture_postings_match_order_totals",
			"the amount posted for each capture must equal the order total",
			`SELECT count(*), COALESCE(min(o.public_id), '')
			   FROM orders o
			   JOIN journal_entries e ON e.reference_type = 'order' AND e.reference_id = o.public_id
			                         AND e.kind = 'order_capture'
			   JOIN LATERAL (
			     SELECT COALESCE(SUM(amount_minor) FILTER (WHERE direction = 'debit'), 0) AS debits
			       FROM journal_lines WHERE entry_id = e.id
			   ) t ON TRUE
			  WHERE o.status IN ('paid','fulfilled','completed')
			    AND t.debits <> o.grand_total_minor`,
		},
		{
			"fulfilled_items_have_exactly_one_licence",
			"a fulfilled item must issue exactly one entitlement, never zero and never two",
			`SELECT count(*), COALESCE(min(i.public_id), '')
			   FROM order_items i
			  WHERE i.status IN ('fulfilled','refunded','partially_refunded')
			    AND (SELECT count(*) FROM licenses l WHERE l.order_item_id = i.id) <> 1`,
		},
		{
			"no_licence_without_a_paid_order",
			"an entitlement must never exist without a captured payment behind it",
			`SELECT count(*), COALESCE(min(l.public_id), '')
			   FROM licenses l
			   JOIN order_items i ON i.id = l.order_item_id
			   JOIN orders o ON o.id = i.order_id
			  WHERE o.status NOT IN ('paid','fulfilled','completed','refund_pending',
			                         'partially_refunded','refunded','disputed','chargeback_lost')`,
		},
		{
			"no_negative_seller_payable",
			"the platform must never run an internal debit balance for a seller",
			`SELECT count(*), COALESCE(min(a.code), '')
			   FROM ledger_accounts a
			  WHERE a.owner_type = 'seller' AND ledger_balance(a.id) < 0`,
		},
		{
			"no_duplicate_capture_for_a_payment",
			"a provider payment must be captured into the ledger exactly once",
			`SELECT count(*), COALESCE(min(provider_payment_id), '') FROM (
			   SELECT p.provider_payment_id, count(DISTINCT e.id) AS entries
			     FROM payments p
			     JOIN orders o ON o.id = p.order_id
			     JOIN journal_entries e ON e.reference_type = 'order' AND e.reference_id = o.public_id
			                           AND e.kind = 'order_capture'
			    GROUP BY p.provider_payment_id
			   HAVING count(DISTINCT e.id) > 1
			 ) d`,
		},
		{
			"order_totals_match_their_items",
			"an order's total must equal the sum of its item totals",
			`SELECT count(*), COALESCE(min(o.public_id), '')
			   FROM orders o
			  WHERE o.status <> 'draft'
			    AND o.grand_total_minor <> (
			      SELECT COALESCE(SUM(i.buyer_total_minor), 0) FROM order_items i WHERE i.order_id = o.id)`,
		},
		{
			"settled_transfers_are_not_still_on_hold",
			"a released settlement must not remain flagged as held",
			`SELECT count(*), COALESCE(min(t.public_id), '')
			   FROM payment_transfers t
			  WHERE t.status = 'processed' AND t.released_at IS NULL AND t.hold_until > now()`,
		},
		{
			"downloads_have_an_entitlement",
			"every served download must reference a licence held by that user",
			`SELECT count(*), ''
			   FROM download_events de
			   JOIN licenses l ON l.id = de.license_id
			  WHERE de.outcome = 'served' AND l.user_id <> de.user_id`,
		},
	}

	findings := make([]consistencyFinding, 0)
	for _, c := range checks {
		var count int
		var sample string
		if err := s.db.QueryRow(ctx, c.query).Scan(&count, &sample); err != nil {
			httpx.Fail(w, r, problem.Internal(err))
			return
		}
		if count > 0 {
			findings = append(findings, consistencyFinding{
				Check: c.name, Count: count, Detail: c.detail, Sample: sample,
			})
		}
	}

	// The trial balance is checked here too, so a single call answers "is the
	// system correct right now".
	balanceErr := s.ledger.AssertBalanced(ctx, s.db)
	if balanceErr != nil {
		findings = append(findings, consistencyFinding{
			Check: "trial_balance", Count: 1,
			Detail: "debits must equal credits in every currency",
			Sample: balanceErr.Error(),
		})
	}

	status := http.StatusOK
	if len(findings) > 0 {
		// A monitor can alert on the status code alone.
		status = http.StatusInternalServerError
	}
	httpx.NoStore(w)
	httpx.JSON(w, r, status, map[string]any{
		"consistent": len(findings) == 0,
		"checks_run": len(checks) + 1,
		"findings":   findings,
		"checked_at": s.clk.Now(),
	})
}

var _ = context.Background
