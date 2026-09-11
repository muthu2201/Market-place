package metrics

// App holds the metric handles the application actually emits. Keeping them in
// one struct means the full observable surface is reviewable at a glance and
// label cardinality stays deliberate: route templates, never raw paths.
type App struct {
	HTTPRequests        *CounterVec
	HTTPDuration        *HistogramVec
	HTTPInFlight        *GaugeVec
	HTTPResponseBytes   *CounterVec
	DBQueryDuration     *HistogramVec
	DBTxRetries         *CounterVec
	DBPoolConns         *GaugeVec
	OutboxPending       *GaugeVec
	OutboxDispatched    *CounterVec
	OutboxFailures      *CounterVec
	JobDuration         *HistogramVec
	JobOutcomes         *CounterVec
	LedgerPostings      *CounterVec
	LedgerImbalance     *CounterVec
	PaymentOperations   *CounterVec
	PaymentDuration     *HistogramVec
	WebhookEvents       *CounterVec
	WebhookRejections   *CounterVec
	RateLimitDecisions  *CounterVec
	AuthEvents          *CounterVec
	DownloadsServed     *CounterVec
	DownloadBytes       *CounterVec
	ScanResults         *CounterVec
	SearchDuration      *HistogramVec
	ReconciliationDiffs *GaugeVec
}

// NewApp registers every application metric on r.
func NewApp(r *Registry) *App {
	return &App{
		HTTPRequests:      NewCounter(r, "http_requests_total", "HTTP requests by route template, method and status class.", "route", "method", "status"),
		HTTPDuration:      NewHistogram(r, "http_request_duration_seconds", "HTTP request latency by route template.", DefaultBuckets, "route", "method"),
		HTTPInFlight:      NewGauge(r, "http_requests_in_flight", "Requests currently being served."),
		HTTPResponseBytes: NewCounter(r, "http_response_bytes_total", "Bytes written in HTTP response bodies.", "route"),

		DBQueryDuration: NewHistogram(r, "db_query_duration_seconds", "Database query latency by operation name.", []float64{0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5}, "op"),
		DBTxRetries:     NewCounter(r, "db_tx_retries_total", "Transactions retried after a serialization or deadlock failure.", "op"),
		DBPoolConns:     NewGauge(r, "db_pool_connections", "Connection pool occupancy.", "state"),

		OutboxPending:    NewGauge(r, "outbox_pending_messages", "Messages awaiting dispatch, by topic."),
		OutboxDispatched: NewCounter(r, "outbox_dispatched_total", "Outbox messages successfully dispatched.", "topic"),
		OutboxFailures:   NewCounter(r, "outbox_failures_total", "Outbox dispatch attempts that failed.", "topic", "reason"),

		JobDuration: NewHistogram(r, "job_duration_seconds", "Background job execution time.", DefaultBuckets, "kind"),
		JobOutcomes: NewCounter(r, "job_outcomes_total", "Background job terminal outcomes.", "kind", "outcome"),

		LedgerPostings:  NewCounter(r, "ledger_postings_total", "Ledger postings written, by journal kind.", "kind"),
		LedgerImbalance: NewCounter(r, "ledger_imbalance_rejected_total", "Journal entries rejected because debits did not equal credits.", "kind"),

		PaymentOperations: NewCounter(r, "payment_operations_total", "Payment port operations by provider, operation and outcome.", "provider", "operation", "outcome"),
		PaymentDuration:   NewHistogram(r, "payment_operation_duration_seconds", "Payment provider call latency.", DefaultBuckets, "provider", "operation"),

		WebhookEvents:     NewCounter(r, "webhook_events_total", "Provider webhooks accepted, by provider and event type.", "provider", "event"),
		WebhookRejections: NewCounter(r, "webhook_rejections_total", "Provider webhooks rejected, by reason.", "provider", "reason"),

		RateLimitDecisions: NewCounter(r, "rate_limit_decisions_total", "Rate limiter verdicts by bucket.", "bucket", "decision"),
		AuthEvents:         NewCounter(r, "auth_events_total", "Authentication lifecycle events.", "event", "outcome"),

		DownloadsServed: NewCounter(r, "downloads_served_total", "Entitled downloads served.", "outcome"),
		DownloadBytes:   NewCounter(r, "download_bytes_total", "Bytes delivered to buyers."),

		ScanResults: NewCounter(r, "asset_scan_results_total", "Uploaded asset scan verdicts.", "scanner", "verdict"),

		SearchDuration: NewHistogram(r, "search_duration_seconds", "Catalog search latency.", DefaultBuckets, "mode"),

		ReconciliationDiffs: NewGauge(r, "reconciliation_open_differences", "Unresolved differences between the ledger and provider records.", "kind"),
	}
}
