# Architecture decision records

Every decision that a future maintainer would otherwise have to reverse-engineer
from the code is recorded here, in [MADR](https://adr.github.io/madr/) form.

A record is written **before** the code, and it is mandatory for any decision
that creates a module boundary, chooses a provider, or changes how money is
represented or moved. If you find yourself explaining "why is it like this" in a
pull-request comment, the answer belonged in an ADR.

Records are immutable once accepted. A decision that changes gets a new record
that supersedes the old one, and the old one stays, because the reasoning that
was wrong is as useful as the reasoning that was right.

| # | Decision | Status |
|---|---|---|
| [0001](0001-modular-monolith-in-go.md) | A modular monolith in Go, not microservices | Accepted |
| [0002](0002-postgresql-as-the-backbone.md) | PostgreSQL as queue, cache and search, not just storage | Accepted |
| [0003](0003-never-hold-customer-funds.md) | The platform never holds customer funds | Accepted |
| [0004](0004-money-as-integer-minor-units.md) | Money is an integer count of minor units | Accepted |
| [0005](0005-double-entry-ledger.md) | An immutable double-entry ledger, even holding no funds | Accepted |
| [0006](0006-payment-provider-port.md) | One payment port, three adapters | Accepted |
| [0007](0007-transactional-outbox.md) | A transactional outbox, and idempotent consumers | Accepted |
| [0008](0008-crypto-shredding-for-erasure.md) | Crypto-shredding reconciles erasure with retention | Accepted |
| [0009](0009-published-deterministic-ranking.md) | A published, reproducible ranking formula | Accepted |
| [0010](0010-disclosure-first-provenance.md) | Disclosure-first provenance, never detector-only | Accepted |
| [0011](0011-settlement-holds-not-wallets.md) | Settlement holds and offsets, never a wallet | Accepted |
| [0012](0012-read-committed-isolation.md) | READ COMMITTED with explicit locking | Accepted |
| [0013](0013-build-time-architecture-enforcement.md) | Architecture rules enforced at build time | Accepted |
| [0014](0014-object-storage-choice.md) | Cloudflare R2 for delivery, egress being the real cost | Accepted |
| [0015](0015-flat-all-in-commission.md) | A flat all-in commission with a published fee covenant | Accepted |
