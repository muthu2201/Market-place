# Kubernetes reference manifests

These are a **starting point**, not a drop-in deployment. They encode the
decisions that are easy to get wrong and expensive to get wrong; they do not
encode your ingress, your certificate issuer, your secret manager or your
storage class, because those are yours.

Read [../README.md](../README.md) first for the deploy order, which matters:
migrate, then workers, then API.

| File | What it is |
|---|---|
| `secret.example.yaml` | The shape of the secret. **Do not apply it** — it is an example, and the values are placeholders |
| `configmap.yaml` | Non-secret configuration |
| `migrate-job.yaml` | The migration, as a Job that must complete before a rollout |
| `api.yaml` | Deployment, Service, PodDisruptionBudget, HPA |
| `worker.yaml` | Deployment |

## The decisions worth knowing about

**Liveness does not touch the database.** `/healthz` answers "is this process
able to serve". If liveness checked the database, a database blip would make
the kubelet kill every healthy replica at once and turn a degradation into an
outage. Readiness (`/readyz`) does check it, so an instance that lost its
database leaves the Service and stops receiving traffic.

**The API probe is an exec probe, not an HTTP probe.** Both work; the exec form
is used because it exercises the same path a Docker healthcheck would and keeps
one mechanism rather than two. The image is distroless, so the binary probes
itself with `-healthcheck`.

**`terminationGracePeriodSeconds` exceeds the application's shutdown grace.**
If the kubelet's SIGKILL arrives before the application finishes draining, a
checkout mid-capture is cut off. The application's grace is
`HTTP_SHUTDOWN_GRACE`; the pod's must be longer, with room for the preStop
sleep that lets endpoints propagate.

**There is no preStop hook, and that is deliberate.** Endpoint removal and
SIGTERM race: without a pause, the pod stops accepting while the Service still
lists it, and those requests fail. The usual fix is a preStop `sleep`, which a
distroless image has no shell to run — and adding one would hand an attacker
with code execution something to pivot with, which is what distroless exists to
prevent. The application does it instead: on SIGTERM it reports not-ready for
`HTTP_DRAIN_DELAY` while continuing to serve, then shuts down gracefully.
Liveness still passes throughout, because the instance is healthy, just
leaving — a failing liveness probe would have the kubelet kill it mid-drain.

**Workers do not need a PodDisruptionBudget for correctness.** Every task is
idempotent and claims with `SKIP LOCKED`, so zero running workers means work
waits, not work lost. One is set anyway so a drain does not silently stop all
background processing.

**The HPA scales on CPU, and that is a deliberate under-specification.** The
real signal is request latency or queue depth, which needs a metrics adapter
this file cannot assume. CPU is the honest default until you have one.

## What is not here

- **Ingress and TLS.** Cluster-specific. HSTS is set by the application; the
  ingress must terminate TLS and set `X-Forwarded-For`, and the ranges it sends
  from must appear in `HTTP_TRUSTED_PROXY_CIDRS` or client IPs can be spoofed.
- **PostgreSQL.** Run it as a managed service or with an operator. A
  StatefulSet you maintain yourself is a database you are now responsible for,
  and this system's entire consistency story rests on it.
- **The secret manager.** `secret.example.yaml` shows the shape. Wire it to
  External Secrets, the Secrets Store CSI driver, or whatever your cluster
  uses. `DATA_KEK` in particular must be backed up **separately from the
  database** and its restore tested — losing it loses every subject's personal
  data, permanently.
