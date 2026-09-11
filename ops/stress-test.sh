#!/usr/bin/env bash
# Runs the end-to-end load and correctness test against a freshly built stack.
#
# It brings up a dedicated database, a payment-gateway simulator, a seeded
# catalogue, the API and the worker, drives sustained concurrent load, and then
# asserts that the books still balance. It exits non-zero if any invariant broke
# or if the error rate exceeded one percent.
set -euo pipefail

WORKERS="${WORKERS:-64}"
DURATION="${DURATION:-30s}"
SCENARIO="${SCENARIO:-mixed}"
SELLERS="${SELLERS:-8}"
PRODUCTS="${PRODUCTS:-60}"
PGHOST="${PGHOST:-127.0.0.1}"
PGPORT="${PGPORT:-5432}"
DBNAME="${DBNAME:-marketplace_load}"
DBUSER="${DBUSER:-marketplace}"
DBPASS="${DBPASS:-dev_local_only_pw}"
API_ADDR="${API_ADDR:-127.0.0.1:8099}"
METRICS_TOKEN="stress-test-token"
RUNDIR="$(mktemp -d)"

cleanup() {
  set +e
  [[ -n "${API_PID:-}" ]]     && kill "$API_PID" 2>/dev/null
  [[ -n "${WORKER_PID:-}" ]]  && kill "$WORKER_PID" 2>/dev/null
  [[ -n "${GATEWAY_PID:-}" ]] && kill "$GATEWAY_PID" 2>/dev/null
  wait 2>/dev/null
  echo "logs kept in $RUNDIR"
}
trap cleanup EXIT

echo "==> building"
go build -o "$RUNDIR/api"      ./cmd/api
go build -o "$RUNDIR/worker"   ./cmd/worker
go build -o "$RUNDIR/seed"     ./cmd/seed
go build -o "$RUNDIR/loadgen"  ./cmd/loadgen
go build -o "$RUNDIR/gateway"  ./cmd/gatewaysim

echo "==> preparing database $DBNAME"
export PGPASSWORD="$DBPASS"
psql -h "$PGHOST" -p "$PGPORT" -U "$DBUSER" -d postgres -q \
  -c "DROP DATABASE IF EXISTS $DBNAME" \
  -c "CREATE DATABASE $DBNAME"
psql -h "$PGHOST" -p "$PGPORT" -U "$DBUSER" -d "$DBNAME" -q \
  -c "CREATE EXTENSION IF NOT EXISTS pg_trgm; CREATE EXTENSION IF NOT EXISTS pgcrypto; CREATE EXTENSION IF NOT EXISTS btree_gist;"

echo "==> starting payment gateway simulator"
"$RUNDIR/gateway" -addr 127.0.0.1:0 -port-file "$RUNDIR/gateway.port" > "$RUNDIR/gateway.log" 2>&1 &
GATEWAY_PID=$!
for _ in $(seq 1 50); do [[ -s "$RUNDIR/gateway.port" ]] && break; sleep 0.1; done
GATEWAY_ADDR="$(cat "$RUNDIR/gateway.port")"
GATEWAY_URL="http://$GATEWAY_ADDR"
echo "    gateway on $GATEWAY_URL"

export APP_ENV=development
export APP_PUBLIC_BASE_URL="http://$API_ADDR"
export HTTP_ADDR="$API_ADDR"
export DATABASE_URL="postgres://$DBUSER:$DBPASS@$PGHOST:$PGPORT/$DBNAME?sslmode=disable"
export DB_MAX_CONNS=40
# The harness runs on this host and presents a distinct address per virtual
# user, so the host must be trusted as a proxy for the run to be realistic.
export HTTP_TRUSTED_PROXY_CIDRS=127.0.0.0/8
# The bridge adapter is the launch configuration: split settlement requires
# turnover the platform does not have on day one.
export PAYMENTS_PROVIDER=bridge
export RAZORPAY_BASE_URL="$GATEWAY_URL"
# The simulator speaks the provider protocol over loopback HTTP. Production
# configuration refuses this setting outright.
export PAYMENTS_ALLOW_LOOPBACK_PROVIDER=true
export RAZORPAY_KEY_ID=rzp_test_simulated
export RAZORPAY_KEY_SECRET=simulated_key_secret
export RAZORPAY_WEBHOOK_SECRET=simulated_webhook_secret
export STORAGE_DRIVER=filesystem
export STORAGE_LOCAL_ROOT="$RUNDIR/objects"
export MAIL_DRIVER=log
export PLATFORM_GSTIN=33AAAAA0000A1Z5
export PLATFORM_STATE_CODE=33
export COMMISSION_BPS=900
export METRICS_TOKEN="$METRICS_TOKEN"
export LOG_LEVEL=warn
export OUTBOX_POLL_INTERVAL=500ms
# The default limits are abuse controls sized so one client cannot monopolise
# the service. A capacity measurement must not be measuring them, so the run
# raises them deliberately. Production keeps the defaults.
export RATE_LIMIT_API_BURST="${RATE_LIMIT_API_BURST:-200000}"
export RATE_LIMIT_SEARCH_BURST="${RATE_LIMIT_SEARCH_BURST:-200000}"
export RATE_LIMIT_CHECKOUT_BURST="${RATE_LIMIT_CHECKOUT_BURST:-200000}"

echo "==> migrating and seeding"
go run ./cmd/migrate up | tail -1
"$RUNDIR/seed" -sellers "$SELLERS" -products "$PRODUCTS" | tail -1

echo "==> starting api"
"$RUNDIR/api" > "$RUNDIR/api.log" 2>&1 &
API_PID=$!
for _ in $(seq 1 80); do
  curl -fsS "http://$API_ADDR/readyz" >/dev/null 2>&1 && break
  sleep 0.15
done
curl -fsS "http://$API_ADDR/readyz" >/dev/null || { echo "api never became ready"; tail -30 "$RUNDIR/api.log"; exit 1; }

echo "==> starting worker"
"$RUNDIR/worker" > "$RUNDIR/worker.log" 2>&1 &
WORKER_PID=$!

echo "==> running load: $SCENARIO, $WORKERS workers, $DURATION"
"$RUNDIR/loadgen" \
  -url "http://$API_ADDR" \
  -gateway "$GATEWAY_URL" \
  -workers "$WORKERS" \
  -duration "$DURATION" \
  -scenario "$SCENARIO" \
  -metrics-token "$METRICS_TOKEN"
RESULT=$?

echo "==> api error lines (if any)"
grep -c '"level":"ERROR"' "$RUNDIR/api.log" 2>/dev/null || echo 0
grep '"level":"ERROR"' "$RUNDIR/api.log" 2>/dev/null | head -5 || true

exit $RESULT
