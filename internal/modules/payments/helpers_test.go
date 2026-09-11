package payments_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newRecorder(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func readAll(t *testing.T, r *http.Request) []byte {
	t.Helper()
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		t.Fatalf("read webhook body: %v", err)
	}
	return b
}
