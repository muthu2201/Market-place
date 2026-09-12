# Deployment

Two stateless binaries, one PostgreSQL primary, one object-storage bucket.
Everything here assumes the architecture in
[../docs/arch/README.md](../docs/arch/README.md), and nothing here is a
substitute for working through
[../docs/runbooks/go-live-checklist.md](../docs/runbooks/go-live-checklist.md).

## What is in this directory

| File | Purpose |
|---|---|
| [`../Dockerfile`](../Dockerfile) | Builds `api`, `worker` and `migrate` into one distroless image |
| [`compose.yaml`](compose.yaml) | The whole stack locally: database, ClamAV, API, worker |
| [`k8s/`](k8s) | Reference manifests for a Kubernetes deployment |

**Not verified by CI.** The Dockerfile's build commands are the same ones CI
runs, and they are verified; the image build itself is not, because no Docker
daemon is available in the environment this was developed in. Build it once
yourself before relying on it.

## The image

One image, three binaries, three entrypoints. `api` is the default; `worker`
and `migrate` are selected by overriding the command.

It is built on `distroless/static`: no shell, no package manager, no libc.
There is nothing for an attacker who achieves code execution to pivot with, and
nothing to patch on a CVE treadmill. The cost is real — you cannot `exec` into a
running container to look around — and it is the right trade for a process that
moves money. Debugging happens through logs, metrics and
`/internal/verify/*`, which is what those exist for.

`archcheck` runs inside the build, so an image cannot be produced from source
that violates the architecture rules.

## Order of operations on a deploy

1. **Migrate first, separately.** `migrate up` is a distinct step, not
   something the API does at boot. An API replica that migrated on startup
   would have N replicas racing to migrate, and a rollback would be ambiguous.
2. **Then roll the workers.** They are idempotent and safe to run old and new
   simultaneously.
3. **Then roll the API.**

Migrations must therefore be backwards-compatible with the running version for
the length of the rollout. That constrains what a migration may do — a column
drop is two deploys, never one — and the constraint is the price of not having
downtime.

## Configuration

Every setting comes from the environment;
[`../docs/security/threat-model.md`](../docs/security/threat-model.md) lists the
nineteen that are **fatal at boot** under `APP_ENV=production`.

Four pieces of key material must come from a secret manager, never from a
manifest committed to a repository:

| Secret | Consequence of loss |
|---|---|
| `DATA_KEK` | **Every subject's personal data, permanently.** Back it up separately from the database, and test the restore |
| `SESSION_SIGNING_KEY` | Sessions can be forged |
| `CSRF_SIGNING_KEY` | CSRF tokens can be forged |
| `RAZORPAY_KEY_SECRET`, `RAZORPAY_WEBHOOK_SECRET` | Payments and webhooks can be forged |

See [../docs/runbooks/key-rotation.md](../docs/runbooks/key-rotation.md) before
rotating any of them — the KEK rotation has a step that is easy to miss and
breaks every login when it is.

## Health checks

| Probe | Endpoint | Why |
|---|---|---|
| Liveness | `/healthz` | Does **not** touch the database. A database blip must not make an orchestrator kill healthy replicas and turn a degradation into an outage |
| Readiness | `/readyz` | **Does** check the database, so an instance that lost it leaves the pool instead of serving errors |

Both are exempt from rate limiting: load shedding must never blind monitoring at
the moment it is most needed.
