# 0001. A modular monolith in Go, not microservices

Status: Accepted
Date: 2026-09-11

## Context

The blueprint recommends a modular monolith with build-time boundary
enforcement, naming Elixir/Phoenix as the primary choice, Java with Spring
Modulith as the runner-up, and Go or TypeScript third.

The operator is a single founder on a small VPS. Whatever is chosen has to be
something one person can reason about at 3am during an incident, deploy without
a control plane, and afford to run at roughly ten dollars a month at zero users.

## Decision

A modular monolith in Go, deployed as two binaries: an API process and a worker
process, sharing one PostgreSQL database.

Module boundaries are declared in a dependency table and enforced at build time
by `cmd/archcheck`, which fails the build on a violation.

## Why Go rather than the blueprint's first choice

Elixir's case is genuinely strong: the BEAM handles rental timers, background
work and real-time delivery beautifully, and its `Decimal` and `Money` ecosystem
handles the money-bug class well. Go was chosen over it for reasons specific to
this system rather than to language preference:

- **The dependency surface is the security surface.** This system handles
  payments, personal data and statutory tax. The whole build depends on five
  modules: pgx, x/crypto, and three transitives. Everything else, including the
  SigV4 signer, the metrics exposition, the rate limiter and the TOTP
  implementation, is written against a published specification and tested
  against its reference vectors. That is a supply chain one person can actually
  audit.
- **Compile-time enforcement.** The money type refuses cross-currency
  arithmetic, `db.Tx` makes "you must be in a transaction" a compile error rather
  than a runtime surprise, and `archcheck` turns the module map into a build
  failure. These are the properties the blueprint wanted ArchUnit for.
- **Deployment and footprint.** A static binary with no runtime, starting in
  milliseconds, on a box that also runs PostgreSQL. There is no BEAM to tune and
  no JVM heap to size.
- **The race detector.** It found a genuine data race in the transaction backoff
  on its first run against concurrent traffic.

## Consequences

**Accepted costs.** Go's error handling is verbose, and generics are limited
enough that some repository code repeats itself. There is no supervision tree:
resilience comes from explicit retries, the outbox and the job queue rather than
from the runtime. Go's standard library has no decimal type, which is why
`internal/platform/money` exists and why `archcheck` refuses floating point on
any money path.

**What we keep.** Extracting a module into its own service later means giving it
its own database and replacing in-process calls with the outbox events that
already exist. The boundaries are already enforced, so the extraction cost is
the data, not the untangling.

**What would change this decision.** Hiring. If the team becomes three or more
people with Elixir or Java experience, the argument from ecosystem depth starts
to outweigh the argument from small dependency surface, and this record should be
superseded rather than quietly ignored.
