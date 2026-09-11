package payments

import (
	"fmt"

	"github.com/muthu2201/market-place/internal/platform/config"
	"github.com/muthu2201/market-place/internal/platform/metrics"
)

// Build constructs the configured provider.
//
// The adapter is chosen once, at boot, from validated configuration. There is
// deliberately no runtime switch: changing how money moves is a deployment, not
// a feature flag, and a flag would let a single compromised admin session
// redirect settlement.
func Build(cfg config.PaymentsConfig, m *metrics.App) (Provider, error) {
	switch cfg.Provider {
	case "bridge":
		return NewRazorpay(RazorpayConfig{
			BaseURL: cfg.RazorpayBaseURL, KeyID: cfg.RazorpayKeyID,
			KeySecret: cfg.RazorpayKeySecret, WebhookSecret: cfg.RazorpayWebhookSecret,
			Timeout: cfg.RequestTimeout, MaxRetries: cfg.MaxRetries,
			RouteMode: false, Metrics: m,
		})
	case "razorpay_route":
		return NewRazorpay(RazorpayConfig{
			BaseURL: cfg.RazorpayBaseURL, KeyID: cfg.RazorpayKeyID,
			KeySecret: cfg.RazorpayKeySecret, WebhookSecret: cfg.RazorpayWebhookSecret,
			Timeout: cfg.RequestTimeout, MaxRetries: cfg.MaxRetries,
			RouteMode: true, Metrics: m,
		})
	case "mor":
		return NewMerchantOfRecord(MoRConfig{
			Vendor: cfg.MoRProvider, BaseURL: cfg.MoRBaseURL, APIKey: cfg.MoRAPIKey,
			WebhookSecret: cfg.MoRWebhookSecret, Timeout: cfg.RequestTimeout,
			MaxRetries: cfg.MaxRetries, Metrics: m,
		})
	}
	return nil, fmt.Errorf("payments: unknown provider %q", cfg.Provider)
}

// RouteEligibility describes whether the platform's own turnover clears the bar
// for activating split settlement.
//
// Route activation requires evidenced domestic turnover above a threshold in
// the current or preceding financial year. A pre-revenue platform is ineligible,
// which is why the launch adapter is the bridge and why this check exists as
// code rather than as a note in a document someone has to remember to read.
type RouteEligibility struct {
	Eligible          bool
	DomesticTurnover  int64
	ExportTurnover    int64
	DomesticThreshold int64
	ExportThreshold   int64
	Reason            string
}

// DefaultRouteThresholds are the published bars, in paise: INR 40 lakh domestic
// or INR 5 lakh export. Confirm with the provider before relying on them.
const (
	DefaultRouteDomesticThresholdMinor int64 = 40_00_000 * 100
	DefaultRouteExportThresholdMinor   int64 = 5_00_000 * 100
)

// EvaluateRouteEligibility reports whether Route can be switched on, given the
// best of the current and preceding financial years.
func EvaluateRouteEligibility(domesticMinor, exportMinor int64) RouteEligibility {
	e := RouteEligibility{
		DomesticTurnover:  domesticMinor,
		ExportTurnover:    exportMinor,
		DomesticThreshold: DefaultRouteDomesticThresholdMinor,
		ExportThreshold:   DefaultRouteExportThresholdMinor,
	}
	switch {
	case domesticMinor > DefaultRouteDomesticThresholdMinor:
		e.Eligible = true
		e.Reason = "domestic turnover exceeds the threshold; GSTR-3B evidence for the relevant financial year is required at application"
	case exportMinor > DefaultRouteExportThresholdMinor:
		e.Eligible = true
		e.Reason = "export turnover exceeds the threshold; GSTR-3B evidence for the relevant financial year is required at application"
	default:
		e.Reason = "neither domestic nor export turnover clears the activation threshold; continue on the bridge adapter"
	}
	return e
}
