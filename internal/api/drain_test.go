package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestDrainingReportsNotReadyWhileStillServing covers the shutdown sequence the
// deployment manifests depend on: readiness must fail, liveness must not.
//
// Getting this backwards is subtle and expensive. A drain exists so the load
// balancer stops sending before the process stops accepting; if liveness failed
// too, the orchestrator would kill the instance mid-drain and cut off exactly
// the in-flight requests the drain was protecting.
func TestDrainingReportsNotReadyWhileStillServing(t *testing.T) {
	s := testServer(t)

	s.BeginDraining()

	rec := httptest.NewRecorder()
	s.handleReady(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness = %d while draining, want 503 so the load balancer stops sending",
			rec.Code)
	}

	rec = httptest.NewRecorder()
	s.handleHealth(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("liveness = %d while draining, want 200 — a failing liveness probe would "+
			"have the orchestrator kill this instance before it finished serving", rec.Code)
	}
}

// TestReadinessDoesNotReportDrainingBeforeSIGTERM guards the other direction: a
// server that reported draining from the start would never join the pool.
func TestReadinessDoesNotReportDrainingBeforeSIGTERM(t *testing.T) {
	s := testServer(t)
	if s.draining.Load() {
		t.Fatal("a freshly constructed server reports itself draining")
	}
}
