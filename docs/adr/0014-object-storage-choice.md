# 0014. Cloudflare R2 for delivery, egress being the real cost

Status: Accepted
Date: 2026-09-11

## Context

The product is digital files, so bandwidth *is* cost of goods sold. It is worth
doing the arithmetic before choosing a bucket.

Take a modest month: 10 TB of downloads.

| | Storage (1 TB) | Egress (10 TB) | Monthly |
|---|---|---|---|
| AWS S3 (ap-south-1) | ~$25 | ~$0.09/GB ≈ $920 | **~$945** |
| Cloudflare R2 | ~$15 | **$0** | **~$15** |

At a 9% commission, $920 of egress consumes the platform's entire revenue on
roughly $10,200 of GMV per month. Egress is not an infrastructure line item; it
is the margin.

The second consideration is jurisdictional. Both offer Indian or
Asia-Pacific-region placement, which matters for DPDP data-localisation posture
and for latency to the primary market.

## Decision

Cloudflare R2 in production, addressed through an S3-compatible API.

Delivery is by **presigned URL with a short expiry**, generated only after an
entitlement check that establishes ownership, licence validity, remaining quota
and asset membership in a single query. Bytes never pass through the
application, so download traffic does not consume application capacity and a
large file does not occupy a request goroutine for its duration.

SigV4 signing is implemented directly rather than pulled in with an SDK. The AWS
SDK for Go is a large dependency tree for one algorithm, and the algorithm is
small and fully specified. The implementation is verified against the official
AWS reference test vector, including the "GET Object with Range" case with
extra signed headers — the case that catches canonical-header ordering bugs.
Implementing a signing algorithm from memory is exactly how signature bugs are
introduced; the reference vector is what makes it safe.

The storage port has two adapters: `s3` (R2, or genuine S3, or MinIO — same
protocol) and `filesystem` for local development. Production configuration
refuses to boot with the filesystem driver.

## Object key discipline

`ValidateKey` rejects traversal sequences, absolute paths, control characters and
empty segments before any key reaches the provider. Keys are derived from
server-generated identifiers, never from user-supplied filenames — the original
filename is metadata, used for the `Content-Disposition` header and nothing else.

## Consequences

Vendor-neutral at the protocol level: R2, S3 and MinIO are the same adapter, so
the decision is reversible with a configuration change.

R2 has no equivalent of S3 Object Lock, so WORM retention for compliance
archives would need a different store. Nothing in the current design requires it;
if a retention obligation ever does, it applies to a small archive rather than to
the whole delivery corpus.

Presigned URLs are bearer credentials for their lifetime. The mitigations are a
short expiry, a per-grant download quota decremented inside the issuing
transaction, and every issuance and every denial recorded in the audit log —
denials written *after* the rollback that refused them, so evidence of an
attempted abuse is not lost with the transaction that caught it.
