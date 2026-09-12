# Payment provider outage — SEV-2

**Symptom:** payment creation failing, webhooks stopped, or transfers erroring.

**What it means:** buyers cannot complete purchases. Nothing is corrupted — an
order only advances on a *verified capture*, so a failed payment leaves a
`pending` order and nothing else.

## First: which way is it failing

| Failing | Effect | Urgency |
|---|---|---|
| Payment creation | New purchases fail cleanly | SEV-2 |
| Webhook delivery | Captures land late, via the browser callback | SEV-2 |
| **Both** | Money may have been taken with no record here | **SEV-1** |
| Transfers / settlement release | Sellers are paid late | SEV-3 |

The third row is the dangerous one. If the provider took money and neither the
callback nor the webhook reached us, buyers have paid for orders that read
`pending`.

## Verify the direction of the failure

```bash
curl -sS -o /dev/null -w '%{http_code}\n' "$RAZORPAY_BASE_URL/v1/payments?count=1" -u "$RAZORPAY_KEY_ID:$RAZORPAY_KEY_SECRET"
```

Then check the provider's own status page before assuming it is us. A
configuration change on our side looks identical from the inside.

```sql
-- Orders that are pending longer than they should be.
SELECT count(*), min(created_at) FROM orders
 WHERE status = 'pending' AND created_at < now() - INTERVAL '15 minutes';
```

## If money was taken with no capture recorded

1. Pull the provider's payment list for the window.
2. For each provider payment with no local `payments` row, reconcile by hand
   against `orders` using the provider's `notes`/reference field.
3. Replay the capture through the normal path rather than posting to the ledger
   directly — the idempotency key makes a replay safe, and it produces exactly
   the postings a capture should produce.
4. Do not hand-post to the ledger. The capture path exists so that the ledger,
   the entitlement, the audit line and the outbox all happen together.

## Expiry is on your side

`expire_stale_orders` releases `pending` orders after five minutes, so a short
outage self-cleans. For a long outage, consider pausing that task so orders are
still reconcilable by reference — and write down that you did, because it is
easy to forget to re-enable.

## Webhook secret rotation looks like an attack

A spike in signature failures after a deploy is almost always a rotated secret
that was not deployed. Check `RAZORPAY_WEBHOOK_SECRET` against the provider
dashboard before escalating it as an attack — but check, do not assume.

## Communicating

Buyers whose payment failed have not been charged. Say exactly that. Buyers
whose payment succeeded but whose order reads `pending` have been charged and
must be told their order is being reconciled — that is the group that generates
chargebacks if they hear nothing.
