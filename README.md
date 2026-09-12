# Digital Products Marketplace (India-first)

A marketplace for digital products — templates, presets, fonts, courses, code,
audio — built so that the platform **never holds customer funds**, every rupee is
traceable through an immutable double-entry journal, and the rules sellers are
judged by are published and reproducible.

Go 1.24, PostgreSQL 16, two binaries, five dependencies.

## Start here

| If you want to know | Read |
|---|---|
| Why it is built this way | [docs/adr](docs/adr) — fifteen decision records |
| How it fits together | [docs/arch](docs/arch) — arc42 and C4 |
| **Where every rupee goes** | [docs/arch/04-money-flow.md](docs/arch/04-money-flow.md) |
| What the API does | [docs/api/openapi.yaml](docs/api/openapi.yaml) |
| What could go wrong | [docs/security/threat-model.md](docs/security/threat-model.md) |
| What to do at 3am | [docs/runbooks](docs/runbooks) |
| Whether it is fast enough | [docs/operations/capacity.md](docs/operations/capacity.md) |
| What law applies to what code | [docs/legal/compliance-map.md](docs/legal/compliance-map.md) |

## The four decisions everything else follows from

**The platform is never in the flow of funds.** Money goes buyer → payment
provider → seller. Under the RBI PA Directions 2025, being in that flow would
make this a payment aggregator: ₹15–25 crore of net worth, escrow with a
scheduled commercial bank, and a prohibition on operating a marketplace at all.
So there is no wallet — and `seller_ledger_account` accepts only `payable` and
`reserve` account types, so one cannot be added by accident.
([ADR 0003](docs/adr/0003-never-hold-customer-funds.md))

**Money is an integer count of minor units.** Never a float, anywhere.
Multiplication goes through 128-bit intermediates, rounding mode is always
explicit, and splitting an amount uses largest-remainder allocation that
conserves the total to the paise. 70,000 property-test iterations; 6.2 ns per
operation, zero allocations.
([ADR 0004](docs/adr/0004-money-as-integer-minor-units.md))

**Every economic event is a balanced journal entry.** Append-only —
`UPDATE` and `DELETE` raise. A deferred constraint trigger refuses an unbalanced
commit, proven by a test that writes raw SQL to bypass the Go layer entirely. A
correction is a compensating entry, never a mutation.
([ADR 0005](docs/adr/0005-double-entry-ledger.md))

**Rules that affect sellers are published and reproducible.** The ranking formula
is a pure function with published constants at `/legal/ranking`; a seller can
recompute their own position. The fee covenant — 90 days' notice, grandfathered
schedules — is a `CHECK` constraint, so abandoning it requires dropping a named
constraint in a visible migration.
([ADR 0009](docs/adr/0009-published-deterministic-ranking.md),
[ADR 0015](docs/adr/0015-flat-all-in-commission.md))

## What is enforced rather than intended

| Guarantee | Mechanism |
|---|---|
| Ledger entries balance | Deferred constraint trigger in PostgreSQL |
| History cannot be rewritten | `forbid_mutation()` on UPDATE/DELETE |
| You cannot post to the ledger outside a transaction | `db.Tx` has an unexported method — it is a **compile error** |
| You cannot mix currencies | The currency travels with the amount; checked again in the database |
| No `float64` near money | `archcheck` rule 6 fails the build |
| No `time.Now()` in business logic | `archcheck` rule 5 — every service takes a clock |
| No SQL built with `fmt.Sprintf` | `archcheck` rule 7 |
| Module boundaries hold | A declared dependency matrix; an undeclared import fails the build |
| A published product is deliverable | Trigger: no clean, scanned, non-preview asset, no publication |
| A fee change gives 90 days' notice | `CHECK (effective_from >= announced_at + INTERVAL '90 days')` |
| An unsafe production setting | 18 of them are **fatal at boot** |
| The API matches its specification | `TestOpenAPIMatchesRoutes` compares the file to the router |
| The documented worked example | `TestWorkedExampleMatchesDocs` computes it from the real code |
| All of the above, on every push | [CI](.github/workflows/ci.yml) — including the race detector against a real database |

## Measured

On four shared cores running the API, the worker, PostgreSQL and a gateway
simulator *simultaneously*:

- Read path: **2,885 req/s**, p99 55 ms, **0 errors**
- Commerce path: **53.9 completed purchases/s**, **0 errors**
- Ledger balanced, audit chain intact, orders reconciled — all **PASS**

The stress test is the highest-value thing in this repository. It found six
concurrency defects that were invisible to review and to single-threaded tests,
including an audit hash chain that forked because `BIGSERIAL` defaults are
evaluated before `BEFORE` triggers fire.
([docs/operations/capacity.md](docs/operations/capacity.md))

## Layout

```
cmd/          api · worker · migrate · archcheck · loadgen · gatewaysim · seed
internal/
  platform/   money · ids · cryptox · db · httpx · config · mail · metrics
              ratelimit · problem · validate · logx · clock · migrate
  modules/    orders · payments · tax · ledger · identity · delivery
              ranking · audit
  outbox/     transactional outbox + dispatcher
  storage/    S3-protocol object storage, SigV4 implemented directly
  api/        HTTP surface and middleware chain
  worker/     dispatcher + 13 scheduled tasks
db/migrations/  12 migrations, embedded
test/e2e/     end-to-end suite against the real payment adapter
ops/          stress-test.sh
docs/         adr · arch · api · security · runbooks · legal · operations
```

## Running it

```bash
go test ./...                  # unit, integration and end-to-end
go run ./cmd/archcheck         # architecture fitness functions
go run ./cmd/migrate up        # apply migrations
ops/stress-test.sh             # full load test with invariant verification
```

`APP_ENV=production` makes eighteen unsafe settings fatal at boot — a non-HTTPS
base URL, insecure cookies, `sslmode=disable`, a missing `PLATFORM_GSTIN`,
`SETTLEMENT_HOLD_DAYS` under 7, disabled seller 2FA, and so on. The full list is
in [docs/security/threat-model.md](docs/security/threat-model.md).

## Not yet built

Stated plainly rather than implied by an empty directory. The schema, the
dependency matrix and the publish-time constraints for these already exist; what
is missing is the Go and the surfaces:

- Provenance signal extraction (C2PA verification, pHash/SimHash, metadata
  forensics) — until it lands, every listing routes to human review rather than
  auto-publishing, so the unfinished state fails toward more scrutiny, not less
- Antivirus scanning client — the publish trigger already refuses unscanned assets
- Catalogue write path, seller onboarding and payout-account surfaces
- Moderation, disputes, grievance and DSAR workflows
- The SSR web surface (`web/templates`, `web/static`)
- Deployment manifests

The [compliance map](docs/legal/compliance-map.md) lists which regulatory
obligations each of these discharges, and marks them pending there too.
