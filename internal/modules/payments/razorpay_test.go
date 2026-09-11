package payments_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/muthu2201/market-place/internal/modules/payments"
	"github.com/muthu2201/market-place/internal/platform/cryptox"
	"github.com/muthu2201/market-place/internal/platform/money"
	"github.com/muthu2201/market-place/internal/testsupport/gatewaysim"
)

func inr(minor int64) money.Money { return money.MustNew(minor, money.INR) }

// adapter builds the REAL Razorpay adapter pointed at a local server speaking
// the provider's wire protocol. The code under test is production code.
func adapter(t *testing.T, route bool) (*payments.Razorpay, *gatewaysim.Harness) {
	t.Helper()
	h := gatewaysim.Start(t)
	a, err := payments.NewRazorpay(payments.RazorpayConfig{
		BaseURL: h.URL(), KeyID: h.Cfg.KeyID, KeySecret: h.Cfg.KeySecret,
		WebhookSecret: h.Cfg.WebhookSecret, RouteMode: route,
		Timeout: 10 * time.Second, MaxRetries: 2, AllowPrivateHosts: true,
	})
	if err != nil {
		t.Fatalf("NewRazorpay: %v", err)
	}
	return a, h
}

func TestAdapterRefusesToStartWithoutSecrets(t *testing.T) {
	if _, err := payments.NewRazorpay(payments.RazorpayConfig{KeyID: "k"}); err == nil {
		t.Fatal("an adapter without a key secret must not start")
	}
	if _, err := payments.NewRazorpay(payments.RazorpayConfig{KeyID: "k", KeySecret: "s"}); err == nil {
		t.Fatal("an adapter without a webhook secret must not start: an unverified webhook is an open door")
	}
	// A non-https base URL must be refused unless a test explicitly opts in.
	if _, err := payments.NewRazorpay(payments.RazorpayConfig{
		KeyID: "k", KeySecret: "s", WebhookSecret: "w", BaseURL: "http://api.example.com",
	}); err == nil {
		t.Fatal("a plaintext provider base URL must be refused")
	}
}

func TestCreateAndCapturePayment(t *testing.T) {
	a, h := adapter(t, false)
	ctx := context.Background()

	res, err := a.CreatePayment(ctx, payments.CreatePaymentRequest{
		OrderReference: "ord_TEST", Amount: inr(236000),
		Description: "Test order", IdempotencyKey: "create:ord_TEST",
	})
	if err != nil {
		t.Fatalf("CreatePayment: %v", err)
	}
	if !strings.HasPrefix(res.ProviderIntentID, "order_") {
		t.Fatalf("unexpected intent id %q", res.ProviderIntentID)
	}
	if res.CheckoutParams["key"] != h.Cfg.KeyID {
		t.Fatalf("checkout params must carry the publishable key id")
	}
	if _, leaked := res.CheckoutParams["key_secret"]; leaked {
		t.Fatal("the key secret must never reach the client")
	}

	pay := h.Pay(t, res.ProviderIntentID, false)
	if pay.Status != "authorized" {
		t.Fatalf("status = %s", pay.Status)
	}

	rec, err := a.CapturePayment(ctx, payments.CaptureRequest{
		ProviderPaymentID: pay.PaymentID, Amount: inr(236000), IdempotencyKey: "capture:" + pay.PaymentID,
	})
	if err != nil {
		t.Fatalf("CapturePayment: %v", err)
	}
	if rec.Status != payments.PaymentCaptured {
		t.Fatalf("status = %s", rec.Status)
	}
	if rec.Amount.Decimal() != "2360.00" {
		t.Fatalf("amount = %s", rec.Amount.Decimal())
	}
	if rec.Fee == nil || rec.Fee.Decimal() != "47.20" {
		t.Fatalf("provider fee not captured: %+v", rec.Fee)
	}
	if rec.Tax == nil || rec.Tax.Decimal() != "8.49" {
		t.Fatalf("provider fee tax = %+v", rec.Tax)
	}
}

// Signature verification is the single control standing between a captured
// payment and an attacker claiming one. It gets an exhaustive test.
func TestVerifyPaymentSignature(t *testing.T) {
	a, h := adapter(t, false)
	ctx := context.Background()

	res, err := a.CreatePayment(ctx, payments.CreatePaymentRequest{
		OrderReference: "ord_SIG", Amount: inr(100000), IdempotencyKey: "create:ord_SIG",
	})
	if err != nil {
		t.Fatal(err)
	}
	pay := h.Pay(t, res.ProviderIntentID, true)

	ok, err := a.VerifyPayment(ctx, payments.VerifyPaymentRequest{
		ProviderIntentID: pay.OrderID, ProviderPaymentID: pay.PaymentID, Signature: pay.Signature,
	})
	if err != nil || !ok.Valid {
		t.Fatalf("a genuine signature must verify: %v %+v", err, ok)
	}

	forged := cryptox.SignHex([]byte("the-wrong-secret"), []byte(pay.OrderID+"|"+pay.PaymentID))
	cases := []struct {
		name string
		req  payments.VerifyPaymentRequest
	}{
		{"forged signature", payments.VerifyPaymentRequest{ProviderIntentID: pay.OrderID, ProviderPaymentID: pay.PaymentID, Signature: forged}},
		{"swapped order id", payments.VerifyPaymentRequest{ProviderIntentID: "order_OTHER", ProviderPaymentID: pay.PaymentID, Signature: pay.Signature}},
		{"swapped payment id", payments.VerifyPaymentRequest{ProviderIntentID: pay.OrderID, ProviderPaymentID: "pay_OTHER", Signature: pay.Signature}},
		{"empty signature", payments.VerifyPaymentRequest{ProviderIntentID: pay.OrderID, ProviderPaymentID: pay.PaymentID}},
		{"non-hex signature", payments.VerifyPaymentRequest{ProviderIntentID: pay.OrderID, ProviderPaymentID: pay.PaymentID, Signature: "not-hex-at-all"}},
		{"truncated signature", payments.VerifyPaymentRequest{ProviderIntentID: pay.OrderID, ProviderPaymentID: pay.PaymentID, Signature: pay.Signature[:40]}},
		{"signature with trailing data", payments.VerifyPaymentRequest{ProviderIntentID: pay.OrderID, ProviderPaymentID: pay.PaymentID, Signature: pay.Signature + "00"}},
		{"delimiter shifted", payments.VerifyPaymentRequest{
			ProviderIntentID:  pay.OrderID + "|" + pay.PaymentID,
			ProviderPaymentID: "",
			Signature:         pay.Signature,
		}},
	}
	for _, c := range cases {
		got, err := a.VerifyPayment(ctx, c.req)
		if err != nil {
			t.Fatalf("%s: unexpected error %v", c.name, err)
		}
		if got.Valid {
			t.Fatalf("%s: must NOT verify", c.name)
		}
	}
}

func TestSplitSettlementRequiresRoute(t *testing.T) {
	bridge, h := adapter(t, false)
	ctx := context.Background()

	acct, err := bridge.CreateLinkedAccount(ctx, payments.LinkedAccountRequest{
		SellerReference: "slr_1", LegalName: "Test Seller", Email: "s@example.com",
		IdempotencyKey: "acct:slr_1",
	})
	if err != nil {
		t.Fatal(err)
	}

	// A bridge-mode adapter must REFUSE a split rather than silently drop it:
	// dropping it would settle the seller's money to the platform.
	_, err = bridge.CreatePayment(ctx, payments.CreatePaymentRequest{
		OrderReference: "ord_SPLIT", Amount: inr(100000), IdempotencyKey: "create:ord_SPLIT",
		Splits: []payments.SplitLine{{SellerReference: "slr_1", ProviderAccountID: acct.ProviderAccountID, Amount: inr(90000)}},
	})
	if !errors.Is(err, payments.ErrNotSupported) {
		t.Fatalf("bridge mode must refuse a split instruction, got %v", err)
	}
	_ = h
}

func TestRouteSplitSettlementEndToEnd(t *testing.T) {
	a, h := adapter(t, true)
	ctx := context.Background()

	acct, err := a.CreateLinkedAccount(ctx, payments.LinkedAccountRequest{
		SellerReference: "slr_route", LegalName: "Route Seller", Email: "r@example.com",
		IdempotencyKey: "acct:slr_route",
	})
	if err != nil {
		t.Fatal(err)
	}
	if acct.CanReceiveTransfer {
		t.Fatal("a freshly created linked account must not be transferable to")
	}
	h.Activate(t, acct.ProviderAccountID, "activated")

	fetched, err := a.FetchLinkedAccount(ctx, acct.ProviderAccountID)
	if err != nil {
		t.Fatal(err)
	}
	if !fetched.CanReceiveTransfer {
		t.Fatal("an activated account should be transferable to")
	}

	hold := time.Now().Add(14 * 24 * time.Hour).Truncate(time.Second)
	res, err := a.CreatePayment(ctx, payments.CreatePaymentRequest{
		OrderReference: "ord_ROUTE", Amount: inr(236000), IdempotencyKey: "create:ord_ROUTE",
		Splits: []payments.SplitLine{{
			SellerReference: "slr_route", ProviderAccountID: acct.ProviderAccountID,
			Amount: inr(212560), OnHold: true, HoldUntil: hold,
		}},
	})
	if err != nil {
		t.Fatalf("CreatePayment with split: %v", err)
	}

	pay := h.Pay(t, res.ProviderIntentID, true)
	if pay.Status != "captured" {
		t.Fatalf("status = %s", pay.Status)
	}

	rec, err := a.ReconcilePayment(ctx, pay.PaymentID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != payments.PaymentCaptured || rec.Amount.Decimal() != "2360.00" {
		t.Fatalf("reconciled payment: %+v", rec)
	}
}

func TestTransferToInactiveAccountIsRefused(t *testing.T) {
	a, h := adapter(t, true)
	ctx := context.Background()

	acct, err := a.CreateLinkedAccount(ctx, payments.LinkedAccountRequest{
		SellerReference: "slr_cold", LegalName: "Cold", Email: "c@example.com", IdempotencyKey: "acct:cold",
	})
	if err != nil {
		t.Fatal(err)
	}
	res, _ := a.CreatePayment(ctx, payments.CreatePaymentRequest{
		OrderReference: "ord_COLD", Amount: inr(100000), IdempotencyKey: "create:cold",
	})
	pay := h.Pay(t, res.ProviderIntentID, true)

	// This is the documented real-world trap: splitting to a non-activated
	// account can fail or hold funds.
	_, err = a.CreateSellerTransfer(ctx, payments.TransferRequest{
		ProviderPaymentID: pay.PaymentID, ProviderAccountID: acct.ProviderAccountID,
		SellerReference: "slr_cold", Amount: inr(90000), IdempotencyKey: "trf:cold",
	})
	if err == nil {
		t.Fatal("a transfer to a non-activated linked account must fail")
	}
	if !errors.Is(err, payments.ErrProviderRejected) {
		t.Fatalf("expected a definite rejection, got %v", err)
	}
}

func TestHoldReleaseAndReverseTransfer(t *testing.T) {
	a, h := adapter(t, true)
	ctx := context.Background()

	acct, _ := a.CreateLinkedAccount(ctx, payments.LinkedAccountRequest{
		SellerReference: "slr_hold", LegalName: "Hold", Email: "h@example.com", IdempotencyKey: "acct:hold",
	})
	h.Activate(t, acct.ProviderAccountID, "activated")
	res, _ := a.CreatePayment(ctx, payments.CreatePaymentRequest{
		OrderReference: "ord_HOLD", Amount: inr(200000), IdempotencyKey: "create:hold",
	})
	pay := h.Pay(t, res.ProviderIntentID, true)

	until := time.Now().Add(14 * 24 * time.Hour)
	tr, err := a.CreateSellerTransfer(ctx, payments.TransferRequest{
		ProviderPaymentID: pay.PaymentID, ProviderAccountID: acct.ProviderAccountID,
		SellerReference: "slr_hold", Amount: inr(180000),
		OnHold: true, HoldUntil: until, IdempotencyKey: "trf:hold",
	})
	if err != nil {
		t.Fatalf("CreateSellerTransfer: %v", err)
	}
	if tr.Status != payments.TransferOnHold {
		t.Fatalf("a held transfer should report on_hold, got %s", tr.Status)
	}

	if err := a.ReleaseSellerSettlement(ctx, tr.ProviderTransferID); err != nil {
		t.Fatalf("ReleaseSellerSettlement: %v", err)
	}
	after, err := a.ReconcileTransfer(ctx, tr.ProviderTransferID)
	if err != nil {
		t.Fatal(err)
	}
	if after.OnHold || after.Status != payments.TransferProcessed {
		t.Fatalf("after release: %+v", after)
	}

	rev, err := a.ReverseTransfer(ctx, payments.ReversalRequest{
		ProviderTransferID: tr.ProviderTransferID, Amount: inr(180000), IdempotencyKey: "rev:hold",
	})
	if err != nil {
		t.Fatalf("ReverseTransfer: %v", err)
	}
	if rev.Amount.Decimal() != "1800.00" {
		t.Fatalf("reversal amount = %s", rev.Amount.Decimal())
	}
	reversed, _ := a.ReconcileTransfer(ctx, tr.ProviderTransferID)
	if reversed.Status != payments.TransferReversed {
		t.Fatalf("transfer should be reversed, got %s", reversed.Status)
	}
}

func TestRefundWithSplitReversal(t *testing.T) {
	a, h := adapter(t, true)
	ctx := context.Background()

	acct, _ := a.CreateLinkedAccount(ctx, payments.LinkedAccountRequest{
		SellerReference: "slr_ref", LegalName: "Ref", Email: "r2@example.com", IdempotencyKey: "acct:ref",
	})
	h.Activate(t, acct.ProviderAccountID, "activated")
	res, _ := a.CreatePayment(ctx, payments.CreatePaymentRequest{
		OrderReference: "ord_REF", Amount: inr(236000), IdempotencyKey: "create:ref",
		Splits: []payments.SplitLine{{SellerReference: "slr_ref", ProviderAccountID: acct.ProviderAccountID, Amount: inr(212560)}},
	})
	pay := h.Pay(t, res.ProviderIntentID, true)

	ref, err := a.RequestRefund(ctx, payments.RefundRequest{
		ProviderPaymentID: pay.PaymentID, Amount: inr(236000),
		Reason: "buyer_request", ReverseSplits: true, IdempotencyKey: "rfnd:ref",
	})
	if err != nil {
		t.Fatalf("RequestRefund: %v", err)
	}
	if ref.Status != payments.RefundProcessed || ref.Amount.Decimal() != "2360.00" {
		t.Fatalf("refund: %+v", ref)
	}
	// Over-refunding must be refused by the provider, and classified as a
	// definite rejection rather than a transient failure.
	_, err = a.RequestRefund(ctx, payments.RefundRequest{
		ProviderPaymentID: pay.PaymentID, Amount: inr(100), Reason: "buyer_request", IdempotencyKey: "rfnd:over",
	})
	if !errors.Is(err, payments.ErrProviderRejected) {
		t.Fatalf("over-refund must be rejected, got %v", err)
	}
}

func TestPartialRefundsAccumulate(t *testing.T) {
	a, h := adapter(t, false)
	ctx := context.Background()
	res, _ := a.CreatePayment(ctx, payments.CreatePaymentRequest{
		OrderReference: "ord_PART", Amount: inr(100000), IdempotencyKey: "create:part",
	})
	pay := h.Pay(t, res.ProviderIntentID, true)

	for i := 0; i < 4; i++ {
		if _, err := a.RequestRefund(ctx, payments.RefundRequest{
			ProviderPaymentID: pay.PaymentID, Amount: inr(25000),
			Reason: "buyer_request", IdempotencyKey: "rfnd:part:" + string(rune('a'+i)),
		}); err != nil {
			t.Fatalf("partial refund %d: %v", i+1, err)
		}
	}
	if _, err := a.RequestRefund(ctx, payments.RefundRequest{
		ProviderPaymentID: pay.PaymentID, Amount: inr(1), Reason: "buyer_request", IdempotencyKey: "rfnd:part:e",
	}); err == nil {
		t.Fatal("refunding beyond the captured amount must fail")
	}
}

// ---- webhooks ---------------------------------------------------------------

func TestWebhookSignatureVerification(t *testing.T) {
	a, h := adapter(t, false)
	ctx := context.Background()

	captured := make(chan []byte, 4)
	recv := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		body := readAll(t, r)
		ev, err := a.ParseWebhook(ctx, r.Header, body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(err.Error()))
			return
		}
		captured <- []byte(ev.Type + "|" + ev.ProviderPaymentID + "|" + ev.EventID)
		w.WriteHeader(http.StatusOK)
	})

	payload := gatewaysim.WebhookBody("payment", map[string]any{
		"id": "pay_ABC", "order_id": "order_ABC", "status": "captured",
		"amount": float64(236000), "currency": "INR",
	})

	status, _ := h.SendWebhook(t, recv.URL, "payment.captured", "evt_1", payload, false)
	if status != http.StatusOK {
		t.Fatalf("a correctly signed webhook must be accepted, got %d", status)
	}
	got := <-captured
	if string(got) != "payment.captured|pay_ABC|evt_1" {
		t.Fatalf("normalised event = %s", got)
	}

	status, body := h.SendWebhook(t, recv.URL, "payment.captured", "evt_2", payload, true)
	if status != http.StatusBadRequest {
		t.Fatalf("a forged webhook must be refused, got %d", status)
	}
	if !strings.Contains(body, "signature") {
		t.Fatalf("refusal should name the signature: %s", body)
	}
}

func TestWebhookRejectsTamperedBody(t *testing.T) {
	a, _ := adapter(t, false)
	ctx := context.Background()

	body := []byte(`{"entity":"event","event":"payment.captured","created_at":1,"payload":{"payment":{"entity":{"id":"pay_1","amount":100}}}}`)
	sig := cryptox.SignHex([]byte(gatewaysim.DefaultConfig().WebhookSecret), body)

	hdr := http.Header{}
	hdr.Set("X-Razorpay-Signature", sig)
	if _, err := a.ParseWebhook(ctx, hdr, body); err != nil {
		t.Fatalf("the untouched body must verify: %v", err)
	}

	// One byte changed: the amount is now 100000 paise instead of 100.
	tampered := []byte(`{"entity":"event","event":"payment.captured","created_at":1,"payload":{"payment":{"entity":{"id":"pay_1","amount":100000}}}}`)
	if _, err := a.ParseWebhook(ctx, hdr, tampered); !errors.Is(err, payments.ErrInvalidSignature) {
		t.Fatalf("a tampered body must fail verification, got %v", err)
	}

	// Re-encoded but semantically identical JSON must also fail: verification
	// is over exact bytes, which is what stops a canonicalisation attack.
	reencoded := []byte(`{"event":"payment.captured","entity":"event","created_at":1,"payload":{"payment":{"entity":{"amount":100,"id":"pay_1"}}}}`)
	if _, err := a.ParseWebhook(ctx, hdr, reencoded); !errors.Is(err, payments.ErrInvalidSignature) {
		t.Fatalf("re-encoded JSON must fail verification, got %v", err)
	}

	if _, err := a.ParseWebhook(ctx, http.Header{}, body); !errors.Is(err, payments.ErrInvalidSignature) {
		t.Fatalf("a webhook with no signature header must fail, got %v", err)
	}
}

func TestWebhookNormalisesEveryEntityKind(t *testing.T) {
	a, _ := adapter(t, true)
	ctx := context.Background()
	secret := []byte(gatewaysim.DefaultConfig().WebhookSecret)

	cases := []struct {
		event string
		body  string
		check func(payments.WebhookEvent) error
	}{
		{"transfer.processed",
			`{"entity":"event","event":"transfer.processed","created_at":1,"payload":{"transfer":{"entity":{"id":"trf_1","status":"processed","amount":1000,"currency":"INR"}}}}`,
			func(e payments.WebhookEvent) error {
				if e.ProviderTransferID != "trf_1" || e.Amount == nil || e.Amount.Decimal() != "10.00" {
					return errors.New("transfer not normalised")
				}
				return nil
			}},
		{"refund.processed",
			`{"entity":"event","event":"refund.processed","created_at":1,"payload":{"refund":{"entity":{"id":"rfnd_1","payment_id":"pay_9","amount":500,"currency":"INR"}}}}`,
			func(e payments.WebhookEvent) error {
				if e.ProviderRefundID != "rfnd_1" || e.ProviderPaymentID != "pay_9" {
					return errors.New("refund not normalised")
				}
				return nil
			}},
		{"payment.dispute.created",
			`{"entity":"event","event":"payment.dispute.created","created_at":1,"payload":{"dispute":{"entity":{"id":"disp_1","payment_id":"pay_8","amount":2000,"currency":"INR"}}}}`,
			func(e payments.WebhookEvent) error {
				if e.ProviderDisputeID != "disp_1" || e.ProviderPaymentID != "pay_8" {
					return errors.New("dispute not normalised")
				}
				return nil
			}},
		{"account.activated",
			`{"entity":"event","event":"account.activated","created_at":1,"payload":{"account":{"entity":{"id":"acc_1","status":"activated"}}}}`,
			func(e payments.WebhookEvent) error {
				if e.ProviderAccountID != "acc_1" || e.Status != "activated" {
					return errors.New("account not normalised")
				}
				return nil
			}},
	}
	for _, c := range cases {
		hdr := http.Header{}
		hdr.Set("X-Razorpay-Signature", cryptox.SignHex(secret, []byte(c.body)))
		ev, err := a.ParseWebhook(ctx, hdr, []byte(c.body))
		if err != nil {
			t.Fatalf("%s: %v", c.event, err)
		}
		if err := c.check(ev); err != nil {
			t.Fatalf("%s: %v", c.event, err)
		}
		if ev.EventID == "" {
			t.Fatalf("%s: every event needs a de-duplication key", c.event)
		}
	}
}

// ---- resilience -------------------------------------------------------------

func TestTransientProviderFailureIsRetried(t *testing.T) {
	a, h := adapter(t, false)
	ctx := context.Background()

	h.FailNext(t, "create_order", 2) // MaxRetries is 2, so 3 attempts in total
	res, err := a.CreatePayment(ctx, payments.CreatePaymentRequest{
		OrderReference: "ord_RETRY", Amount: inr(100000), IdempotencyKey: "create:retry",
	})
	if err != nil {
		t.Fatalf("two transient failures should be absorbed by retries: %v", err)
	}
	if res.ProviderIntentID == "" {
		t.Fatal("no intent returned")
	}

	h.FailNext(t, "create_order", 5) // beyond the retry budget
	if _, err := a.CreatePayment(ctx, payments.CreatePaymentRequest{
		OrderReference: "ord_RETRY2", Amount: inr(100000), IdempotencyKey: "create:retry2",
	}); !errors.Is(err, payments.ErrProviderUnavailable) {
		t.Fatalf("exhausted retries should surface as unavailable, got %v", err)
	}
}

func TestProviderIdempotencyKeyPreventsDuplicateOrders(t *testing.T) {
	a, _ := adapter(t, false)
	ctx := context.Background()
	req := payments.CreatePaymentRequest{
		OrderReference: "ord_IDEM", Amount: inr(100000), IdempotencyKey: "create:idem",
	}
	first, err := a.CreatePayment(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.CreatePayment(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if first.ProviderIntentID != second.ProviderIntentID {
		t.Fatalf("the same idempotency key produced two orders: %s vs %s",
			first.ProviderIntentID, second.ProviderIntentID)
	}
}

func TestSplitsExceedingPaymentAreRefused(t *testing.T) {
	a, h := adapter(t, true)
	ctx := context.Background()
	acct, _ := a.CreateLinkedAccount(ctx, payments.LinkedAccountRequest{
		SellerReference: "slr_big", LegalName: "Big", Email: "b@example.com", IdempotencyKey: "acct:big",
	})
	h.Activate(t, acct.ProviderAccountID, "activated")

	_, err := a.CreatePayment(ctx, payments.CreatePaymentRequest{
		OrderReference: "ord_BIG", Amount: inr(100000), IdempotencyKey: "create:big",
		Splits: []payments.SplitLine{{SellerReference: "slr_big", ProviderAccountID: acct.ProviderAccountID, Amount: inr(200000)}},
	})
	if err == nil {
		t.Fatal("a split larger than the payment must be refused")
	}
}

func TestBeneficiaryValidationAndNameMatching(t *testing.T) {
	a, _ := adapter(t, false)
	ctx := context.Background()

	ok, err := a.ValidateBeneficiary(ctx, payments.BeneficiaryRequest{
		SellerReference: "slr_pd", AccountNumber: "123456789012", IFSC: "HDFC0001234",
		BeneficiaryName: "Kavitha Raman", IdempotencyKey: "pd:1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ok.Valid || ok.NameMatchScore != 100 {
		t.Fatalf("penny drop: %+v", ok)
	}

	bad, err := a.ValidateBeneficiary(ctx, payments.BeneficiaryRequest{
		SellerReference: "slr_pd2", AccountNumber: "123456780000", IFSC: "HDFC0001234",
		BeneficiaryName: "Kavitha Raman", IdempotencyKey: "pd:2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if bad.Valid {
		t.Fatal("a closed account must not validate")
	}
	if bad.Reason == "" {
		t.Fatal("a failed validation must say why")
	}
}

func TestNameMatchScoreBehaviour(t *testing.T) {
	cases := []struct {
		claimed, registered string
		min, max            int
	}{
		{"Kavitha Raman", "Kavitha Raman", 100, 100},
		{"Kavitha Raman", "KAVITHA RAMAN", 100, 100},
		{"Kavitha Raman", "Raman Kavitha", 100, 100},
		{"Mr Kavitha Raman", "Kavitha Raman", 100, 100},
		{"Kavitha Raman", "Kavitha R", 30, 60},
		{"Kavitha Raman", "Arjun Mehta", 0, 10},
		{"Acme Studios Pvt Ltd", "Acme Studios", 100, 100},
		{"", "Kavitha Raman", 0, 0},
	}
	for _, c := range cases {
		got := payments.NameMatchScore(c.claimed, c.registered)
		if got < c.min || got > c.max {
			t.Errorf("NameMatchScore(%q,%q) = %d, want %d..%d", c.claimed, c.registered, got, c.min, c.max)
		}
	}
}

// ---- SSRF ------------------------------------------------------------------

func TestAdapterRefusesPrivateHostsWhenNotOptedIn(t *testing.T) {
	// AllowPrivateHosts defaults to false, so https to a loopback address must
	// be refused at dial time rather than probing internal infrastructure.
	a, err := payments.NewRazorpay(payments.RazorpayConfig{
		BaseURL: "https://127.0.0.1:9", KeyID: "k", KeySecret: "s", WebhookSecret: "w",
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("construction should succeed; the refusal happens at dial: %v", err)
	}
	_, err = a.CreatePayment(context.Background(), payments.CreatePaymentRequest{
		OrderReference: "ord_SSRF", Amount: inr(100), IdempotencyKey: "ssrf:1",
	})
	if err == nil {
		t.Fatal("connecting to a loopback provider host must fail")
	}
	if !strings.Contains(err.Error(), "non-public address") && !errors.Is(err, payments.ErrProviderUnavailable) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCallbackURLMustBeHTTPS(t *testing.T) {
	a, err := payments.NewRazorpay(payments.RazorpayConfig{
		BaseURL: "https://api.razorpay.com", KeyID: "k", KeySecret: "s", WebhookSecret: "w",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.CreatePayment(context.Background(), payments.CreatePaymentRequest{
		OrderReference: "ord_CB", Amount: inr(100), IdempotencyKey: "cb:1",
		ReturnURL: "http://evil.example.com/steal",
	})
	if !errors.Is(err, payments.ErrProviderRejected) {
		t.Fatalf("a plaintext callback URL must be refused, got %v", err)
	}
}
