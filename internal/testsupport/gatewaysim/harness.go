package gatewaysim

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Harness runs the simulator on a loopback listener for the duration of a test.
type Harness struct {
	Server *httptest.Server
	Cfg    Config
}

// Start brings up a simulator and tears it down when the test ends.
func Start(t *testing.T) *Harness {
	t.Helper()
	cfg := DefaultConfig()
	srv := httptest.NewServer(New(cfg))
	t.Cleanup(srv.Close)
	return &Harness{Server: srv, Cfg: cfg}
}

// URL is the simulator's base address.
func (h *Harness) URL() string { return h.Server.URL }

// PayResult is what the checkout callback would carry back from the browser.
type PayResult struct {
	OrderID   string `json:"razorpay_order_id"`
	PaymentID string `json:"razorpay_payment_id"`
	Signature string `json:"razorpay_signature"`
	Status    string `json:"status"`
}

// Pay plays the customer against an order.
func (h *Harness) Pay(t *testing.T, orderID string, capture bool) PayResult {
	t.Helper()
	var out PayResult
	h.post(t, "/_sim/pay", map[string]any{"order_id": orderID, "capture": capture, "method": "upi"}, &out)
	return out
}

// PayWith gives a test control over the method, network and failure outcome.
func (h *Harness) PayWith(t *testing.T, body map[string]any) PayResult {
	t.Helper()
	var out PayResult
	h.post(t, "/_sim/pay", body, &out)
	return out
}

// Activate flips a linked account to the given provider-side status.
func (h *Harness) Activate(t *testing.T, accountID, status string) {
	t.Helper()
	h.post(t, "/_sim/activate", map[string]any{"account_id": accountID, "status": status}, nil)
}

// SendWebhook signs a payload with the webhook secret and delivers it to target.
func (h *Harness) SendWebhook(t *testing.T, target, event, eventID string, payload map[string]any, badSignature bool) (int, string) {
	t.Helper()
	var out struct {
		DeliveredStatus int    `json:"delivered_status"`
		Response        string `json:"response"`
	}
	h.post(t, "/_sim/webhook", map[string]any{
		"target_url": target, "event": event, "event_id": eventID,
		"payload": payload, "bad_signature": badSignature,
	}, &out)
	return out.DeliveredStatus, out.Response
}

// FailNext makes the next n calls to op fail with a 503, so retry and
// classification behaviour can be exercised.
func (h *Harness) FailNext(t *testing.T, op string, times int) {
	t.Helper()
	h.post(t, "/_sim/fail-next", map[string]any{"op": op, "times": times}, nil)
}

func (h *Harness) post(t *testing.T, path string, body any, out any) {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("gatewaysim: encode %s: %v", path, err)
	}
	req, err := http.NewRequest(http.MethodPost, h.Server.URL+path, bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("gatewaysim: build %s: %v", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("gatewaysim: %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("gatewaysim: %s returned %d: %s", path, resp.StatusCode, raw)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("gatewaysim: decode %s: %v (%s)", path, err, raw)
		}
	}
}

// WebhookBody builds the payload envelope for a given entity kind.
func WebhookBody(kind string, entity map[string]any) map[string]any {
	return map[string]any{kind: map[string]any{"entity": entity}}
}

var _ = fmt.Sprint
