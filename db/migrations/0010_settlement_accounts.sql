-- 0010_settlement_accounts.sql
-- Accounts for the post-settlement recovery path.
--
-- When a refund or a lost chargeback lands AFTER a seller has already been
-- paid, the money has left the system and cannot be clawed back from a balance
-- we do not hold. The honest model is an ordinary trade receivable from the
-- seller, recovered by netting against their next settlement. That is a
-- receivable in our own books, not a customer-funds balance, which is what
-- keeps the platform clear of payment-aggregator territory.

SELECT open_ledger_account('platform.receivable.seller_offset',
                           'Recoverable from sellers (settlement offsets)', 'asset', 'INR');
SELECT open_ledger_account('platform.receivable.seller_offset.usd',
                           'Recoverable from sellers (settlement offsets, USD)', 'asset', 'USD');
SELECT open_ledger_account('platform.expense.chargeback_fee',
                           'Chargeback and representment fees', 'expense', 'INR');
SELECT open_ledger_account('platform.payable.reserve_control.usd',
                           'Rolling reserve held (control, USD)', 'liability', 'USD');

UPDATE ledger_accounts SET is_control = TRUE WHERE code = 'platform.payable.reserve_control.usd';

-- Chargeback exposure, tracked per seller over a rolling window. Card networks
-- monitor a merchant's chargeback ratio; crossing a network threshold is an
-- existential event for a marketplace, so it is measured continuously rather
-- than discovered in a monthly report.
CREATE OR REPLACE VIEW seller_chargeback_exposure AS
SELECT
  s.id                AS seller_id,
  s.handle,
  s.status,
  count(DISTINCT oi.id) FILTER (WHERE oi.created_at > now() - INTERVAL '90 days')  AS orders_90d,
  count(DISTINCT cb.id) FILTER (WHERE cb.created_at > now() - INTERVAL '90 days')  AS chargebacks_90d,
  CASE
    WHEN count(DISTINCT oi.id) FILTER (WHERE oi.created_at > now() - INTERVAL '90 days') = 0 THEN 0
    ELSE round(
      100.0 * count(DISTINCT cb.id) FILTER (WHERE cb.created_at > now() - INTERVAL '90 days')
      / count(DISTINCT oi.id) FILTER (WHERE oi.created_at > now() - INTERVAL '90 days'), 4)
  END                 AS chargeback_rate_pct,
  COALESCE(sum(o.amount_minor) FILTER (WHERE o.status IN ('outstanding','partially_applied')), 0)
                      AS outstanding_offset_minor
FROM sellers s
LEFT JOIN order_items oi ON oi.seller_id = s.id
LEFT JOIN chargebacks cb ON cb.order_id = oi.order_id
LEFT JOIN settlement_offsets o ON o.seller_id = s.id
GROUP BY s.id, s.handle, s.status;

COMMENT ON VIEW seller_chargeback_exposure IS
  'Rolling 90-day chargeback ratio per seller. Card networks monitor this; tighten holds and reserves well before a network threshold.';
