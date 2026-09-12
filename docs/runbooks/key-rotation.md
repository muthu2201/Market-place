# Key rotation — planned, or SEV-1 on suspected compromise

The platform holds several keys. They rotate differently, and confusing them is
how a rotation becomes an outage.

| Key | Rotating it costs | Losing it costs |
|---|---|---|
| `DATA_KEK` | Re-wrapping one row per subject | **Every subject's personal data, permanently** |
| `SESSION_SIGNING_KEY` | Every session logged out | Sessions can be forged |
| `CSRF_SIGNING_KEY` | In-flight forms rejected once | CSRF tokens can be forged |
| `RAZORPAY_KEY_SECRET` | A brief window of failing callbacks | Payments can be forged |
| `RAZORPAY_WEBHOOK_SECRET` | A brief window of failing webhooks | Webhooks can be forged |
| `METRICS_TOKEN` | Scraper reconfiguration | Metrics are world-readable |

## Rotating the KEK

The KEK never encrypts user data directly — it wraps per-subject DEKs. A
rotation therefore re-wraps keys rather than re-encrypting the database, which is
the whole reason the indirection exists
(ADR [0008](../adr/0008-crypto-shredding-for-erasure.md)).

**Before you start:** confirm the current KEK is backed up and that the backup has
been tested by decrypting a known ciphertext. A rotation that goes wrong with no
recoverable old KEK is unrecoverable, full stop.

1. Generate the new KEK from a CSPRNG. 32 bytes. Store it in the KMS alongside
   the old one — both must be readable during the rotation.
2. Deploy with both configured: the new one for wrapping, the old one retained
   for unwrapping.
3. Run the re-wrap. It is resumable: each subject's DEK is unwrapped with the old
   KEK and re-wrapped with the new one, in its own transaction, so an interruption
   costs nothing.
4. **Re-derive the blind-index pepper.** The pepper is derived from the KEK, so
   every e-mail blind index must be recomputed or login breaks for everyone. This
   is the step that gets forgotten. Recompute in the same pass as the re-wrap.
5. Verify: pick several subjects across the range and confirm their data decrypts
   and their blind index resolves.
6. Only then retire the old KEK — and archive it rather than destroying it until
   a full backup cycle has passed under the new one.

## On suspected KEK compromise — SEV-1

An attacker with the KEK and a database copy has everything. Rotation does not
undo that: the copy they hold remains decryptable with the key they hold.

1. Rotate immediately, as above, so *future* data is protected.
2. Treat it as a personal-data breach and start the disclosure clock. This is a
   legal determination, not an engineering one — escalate now.
3. Investigate how it was obtained. A KEK in an environment variable on a
   compromised host, in a log, or in a repository are the three usual answers.

## Rotating session and CSRF keys

Both are single-step: deploy the new key. Sessions signed with the old key stop
validating, so every user is logged out — which is exactly what you want on a
suspected compromise, and what you should schedule for a quiet hour otherwise.

## Rotating provider secrets

The two Razorpay secrets serve different schemes and must be rotated
independently:

- `RAZORPAY_KEY_SECRET` signs the checkout callback and authenticates API calls.
- `RAZORPAY_WEBHOOK_SECRET` signs webhook bodies.

Rotate in the provider dashboard and deploy in the same change window. Expect a
brief spike in signature failures; a *sustained* spike means one side did not
take. Verify with one real transaction before considering it done.

## Never

- Never derive one key from another "to simplify". The separation is what
  contains a single compromise.
- Never store the KEK in the same system as the database backups. That
  combination is the entire threat.
- Never skip step 4 of the KEK rotation.
