// Package ratelimit implements the GCRA (generic cell rate algorithm) leaky
// bucket, the same shape Stripe and Cloudflare use.
//
// GCRA is preferred over a fixed window because it has no boundary burst, and
// over a token bucket because a single timestamp per key is enough state, which
// keeps both the in-memory and the Postgres-backed implementations cheap.
//
// Two limiters exist:
//
//   - Local is per-process and lock-sharded. It is the first line of defence
//     and absorbs floods without touching the database.
//   - Shared is Postgres-backed and correct across replicas. It is used where a
//     limit must hold globally: login attempts, OTP sends, payout changes.
package ratelimit

import (
	"context"
	"hash/maphash"
	"sync"
	"time"

	"github.com/muthu2201/market-place/internal/platform/clock"
)

// Decision is the verdict for one request.
type Decision struct {
	Allowed    bool
	Remaining  int
	RetryAfter time.Duration
	ResetAfter time.Duration
}

// Rule describes a limit: Burst requests, refilling at Burst/Period.
type Rule struct {
	Name   string
	Burst  int
	Period time.Duration
}

// emissionInterval is the minimum spacing between two conforming requests.
func (r Rule) emissionInterval() time.Duration {
	if r.Burst <= 0 {
		return r.Period
	}
	return r.Period / time.Duration(r.Burst)
}

// delayTolerance is how far ahead of the theoretical arrival time we allow,
// which is what turns a strict rate into a burst allowance.
func (r Rule) delayTolerance() time.Duration { return r.Period }

const shardCount = 256

// Local is an in-process GCRA limiter.
type Local struct {
	clk    clock.Clock
	shards [shardCount]shard
	seed   maphash.Seed
}

type shard struct {
	mu   sync.Mutex
	tat  map[string]time.Time // theoretical arrival time
	last time.Time
}

func NewLocal(clk clock.Clock) *Local {
	l := &Local{clk: clk, seed: maphash.MakeSeed()}
	for i := range l.shards {
		l.shards[i].tat = make(map[string]time.Time)
	}
	return l
}

// Allow applies rule to key and records the request if it conforms.
func (l *Local) Allow(key string, rule Rule) Decision {
	return l.AllowN(key, rule, 1)
}

// AllowN charges n units at once, which is how an expensive operation (a large
// upload, a bulk export) can cost more than a cheap one.
func (l *Local) AllowN(key string, rule Rule, n int) Decision {
	if n < 1 {
		n = 1
	}
	now := l.clk.Now()
	ei := rule.emissionInterval()
	cost := time.Duration(n) * ei
	tol := rule.delayTolerance()

	var h maphash.Hash
	h.SetSeed(l.seed)
	_, _ = h.WriteString(rule.Name)
	_, _ = h.WriteString(key)
	s := &l.shards[h.Sum64()%shardCount]

	s.mu.Lock()
	defer s.mu.Unlock()

	tat, ok := s.tat[key+"\x00"+rule.Name]
	if !ok || tat.Before(now) {
		tat = now
	}
	newTAT := tat.Add(cost)
	allowAt := newTAT.Add(-tol)

	if allowAt.After(now) {
		return Decision{
			Allowed:    false,
			Remaining:  0,
			RetryAfter: allowAt.Sub(now),
			ResetAfter: tat.Sub(now),
		}
	}
	s.tat[key+"\x00"+rule.Name] = newTAT
	remaining := int((tol - newTAT.Sub(now)) / ei)
	if remaining < 0 {
		remaining = 0
	}
	return Decision{Allowed: true, Remaining: remaining, ResetAfter: newTAT.Sub(now)}
}

// Sweep removes entries whose theoretical arrival time is in the past, bounding
// memory against an attacker who cycles keys. Call it periodically.
func (l *Local) Sweep() int {
	now := l.clk.Now()
	removed := 0
	for i := range l.shards {
		s := &l.shards[i]
		s.mu.Lock()
		for k, tat := range s.tat {
			if tat.Before(now) {
				delete(s.tat, k)
				removed++
			}
		}
		s.mu.Unlock()
	}
	return removed
}

// Size reports the number of tracked keys (used by tests and metrics).
func (l *Local) Size() int {
	n := 0
	for i := range l.shards {
		l.shards[i].mu.Lock()
		n += len(l.shards[i].tat)
		l.shards[i].mu.Unlock()
	}
	return n
}

// Shared is implemented by the Postgres-backed limiter in the db package so
// that limits which must hold across replicas can be enforced transactionally.
type Shared interface {
	Allow(ctx context.Context, key string, rule Rule) (Decision, error)
}

// Standard rules used across the application. They live here so that a security
// review can read the entire rate-limit policy in one place.
var (
	RuleLoginPerIP        = Rule{Name: "login_ip", Burst: 20, Period: 15 * time.Minute}
	RuleLoginPerAccount   = Rule{Name: "login_account", Burst: 8, Period: 15 * time.Minute}
	RuleSignupPerIP       = Rule{Name: "signup_ip", Burst: 5, Period: time.Hour}
	RulePasswordResetIP   = Rule{Name: "pwreset_ip", Burst: 5, Period: time.Hour}
	RulePasswordResetUser = Rule{Name: "pwreset_user", Burst: 3, Period: time.Hour}
	RuleTOTPVerify        = Rule{Name: "totp_verify", Burst: 10, Period: 5 * time.Minute}
	RuleAPIPerIP          = Rule{Name: "api_ip", Burst: 300, Period: time.Minute}
	RuleAPIPerUser        = Rule{Name: "api_user", Burst: 600, Period: time.Minute}
	RuleSearchPerIP       = Rule{Name: "search_ip", Burst: 60, Period: time.Minute}
	RuleCheckoutPerUser   = Rule{Name: "checkout_user", Burst: 20, Period: 10 * time.Minute}
	RuleDownloadPerUser   = Rule{Name: "download_user", Burst: 60, Period: time.Hour}
	RuleUploadPerSeller   = Rule{Name: "upload_seller", Burst: 40, Period: time.Hour}
	RulePayoutChange      = Rule{Name: "payout_change", Burst: 3, Period: 24 * time.Hour}
	RuleWebhookPerIP      = Rule{Name: "webhook_ip", Burst: 600, Period: time.Minute}
	RuleGrievancePerUser  = Rule{Name: "grievance_user", Burst: 10, Period: 24 * time.Hour}
)
