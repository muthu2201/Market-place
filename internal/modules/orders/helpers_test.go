package orders_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/muthu2201/market-place/internal/platform/cryptox"
)

// marshalWebhook builds the exact envelope the provider sends.
func marshalWebhook(t *testing.T, event string, payload map[string]any) []byte {
	t.Helper()
	contains := make([]string, 0, len(payload))
	for k := range payload {
		contains = append(contains, k)
	}
	body, err := json.Marshal(map[string]any{
		"entity": "event", "account_id": "acc_sim", "event": event,
		"contains": contains, "created_at": time.Now().Unix(), "payload": payload,
	})
	if err != nil {
		t.Fatalf("marshal webhook: %v", err)
	}
	return body
}

// signedHeader signs a body with the simulator's webhook secret, exactly as the
// provider would.
func signedHeader(t *testing.T, h *harness, body []byte) http.Header {
	t.Helper()
	hdr := http.Header{}
	hdr.Set("X-Razorpay-Signature", cryptox.SignHex([]byte(h.gateway.Cfg.WebhookSecret), body))
	return hdr
}
