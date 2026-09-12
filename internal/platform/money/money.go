// Package money implements exact monetary arithmetic on integer minor units.
//
// Non-negotiable rules enforced here (see ADR-0004):
//   - Money is ALWAYS stored and computed as int64 minor units (paise, cents).
//   - A currency travels with every amount; cross-currency arithmetic is refused.
//   - No float ever participates in a monetary computation. Ratios are applied
//     with a 128-bit intermediate so that (amount x numerator) cannot overflow
//     before the division happens.
//   - Rounding is always explicit. There is no default rounding mode.
//
// cmd/archcheck enforces at build time that this package contains no floating
// point types and that no module computes money outside of it.
package money

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"strconv"
	"strings"
)

// Currency is an ISO-4217 alphabetic code.
type Currency string

const (
	INR Currency = "INR"
	USD Currency = "USD"
	EUR Currency = "EUR"
	GBP Currency = "GBP"
	AUD Currency = "AUD"
	SGD Currency = "SGD"
	AED Currency = "AED"
	CAD Currency = "CAD"
	JPY Currency = "JPY"
)

// exponent is the number of minor units per major unit, expressed as a power of ten.
var exponent = map[Currency]int{
	INR: 2, USD: 2, EUR: 2, GBP: 2, AUD: 2, SGD: 2, AED: 2, CAD: 2,
	JPY: 0,
}

var (
	ErrCurrencyMismatch = errors.New("money: currency mismatch")
	ErrUnknownCurrency  = errors.New("money: unknown currency")
	ErrOverflow         = errors.New("money: arithmetic overflow")
	ErrDivideByZero     = errors.New("money: division by zero")
	ErrNegative         = errors.New("money: negative amount not permitted here")
	ErrParse            = errors.New("money: cannot parse amount")
)

// Rounding selects how a non-exact result is resolved to a whole minor unit.
type Rounding uint8

const (
	// HalfUp rounds .5 away from zero. This is the rounding mode prescribed for
	// Indian GST computation and is the default for tax and fee lines.
	HalfUp Rounding = iota
	// HalfEven (banker's rounding) minimises cumulative bias across many lines.
	HalfEven
	// Down truncates toward zero. Used when the platform must never over-collect.
	Down
	// Up rounds away from zero. Used when the platform must never under-remit.
	Up
)

func (r Rounding) String() string {
	switch r {
	case HalfUp:
		return "half_up"
	case HalfEven:
		return "half_even"
	case Down:
		return "down"
	case Up:
		return "up"
	}
	return "unknown"
}

// Money is an exact amount of a single currency held in minor units.
type Money struct {
	minor int64
	cur   Currency
}

// Valid reports whether c is a currency this system knows how to scale.
func Valid(c Currency) bool { _, ok := exponent[c]; return ok }

// Exponent returns the decimal exponent (minor units per major unit) for c.
func Exponent(c Currency) (int, error) {
	e, ok := exponent[c]
	if !ok {
		return 0, fmt.Errorf("%w: %q", ErrUnknownCurrency, c)
	}
	return e, nil
}

// New builds a Money from raw minor units.
func New(minor int64, c Currency) (Money, error) {
	if !Valid(c) {
		return Money{}, fmt.Errorf("%w: %q", ErrUnknownCurrency, c)
	}
	return Money{minor: minor, cur: c}, nil
}

// MustNew is New for compile-time-known constants; it panics on an unknown currency.
func MustNew(minor int64, c Currency) Money {
	m, err := New(minor, c)
	if err != nil {
		panic(err)
	}
	return m
}

// Zero returns the additive identity for c.
func Zero(c Currency) Money { return Money{minor: 0, cur: c} }

func (m Money) Minor() int64       { return m.minor }
func (m Money) Currency() Currency { return m.cur }
func (m Money) IsZero() bool       { return m.minor == 0 }
func (m Money) IsNegative() bool   { return m.minor < 0 }
func (m Money) IsPositive() bool   { return m.minor > 0 }
func (m Money) Sign() int {
	switch {
	case m.minor > 0:
		return 1
	case m.minor < 0:
		return -1
	}
	return 0
}

func (m Money) sameCurrency(o Money) error {
	if m.cur != o.cur {
		return fmt.Errorf("%w: %s vs %s", ErrCurrencyMismatch, m.cur, o.cur)
	}
	return nil
}

// Add returns m+o, refusing mixed currencies and int64 overflow.
func (m Money) Add(o Money) (Money, error) {
	if err := m.sameCurrency(o); err != nil {
		return Money{}, err
	}
	sum := m.minor + o.minor
	// Overflow iff both operands share a sign that the result does not.
	if (m.minor > 0 && o.minor > 0 && sum < 0) || (m.minor < 0 && o.minor < 0 && sum >= 0) {
		return Money{}, ErrOverflow
	}
	return Money{minor: sum, cur: m.cur}, nil
}

// Sub returns m-o.
func (m Money) Sub(o Money) (Money, error) {
	if err := m.sameCurrency(o); err != nil {
		return Money{}, err
	}
	neg, err := o.Neg()
	if err != nil {
		return Money{}, err
	}
	return m.Add(neg)
}

// Neg returns -m.
func (m Money) Neg() (Money, error) {
	if m.minor == math.MinInt64 {
		return Money{}, ErrOverflow
	}
	return Money{minor: -m.minor, cur: m.cur}, nil
}

// Abs returns |m|.
func (m Money) Abs() (Money, error) {
	if m.minor >= 0 {
		return m, nil
	}
	return m.Neg()
}

// MulInt returns m*n.
func (m Money) MulInt(n int64) (Money, error) {
	p, err := mulOverflowChecked(m.minor, n)
	if err != nil {
		return Money{}, err
	}
	return Money{minor: p, cur: m.cur}, nil
}

// MulRatio returns m * num / den rounded per mode, computed through a 128-bit
// intermediate so that the multiplication cannot overflow before the division.
//
// This is the only sanctioned way to apply a percentage, a tax rate or a
// commission rate to an amount.
func (m Money) MulRatio(num, den int64, mode Rounding) (Money, error) {
	if den == 0 {
		return Money{}, ErrDivideByZero
	}
	r, err := mulDivRound(m.minor, num, den, mode)
	if err != nil {
		return Money{}, err
	}
	return Money{minor: r, cur: m.cur}, nil
}

// ApplyBasisPoints returns m * bps / 10_000 rounded per mode.
// 100 bps == 1%. Rates such as GST 18% (1800 bps), TCS 1% (100 bps) and
// TDS 0.1% (10 bps) are all exactly representable.
func (m Money) ApplyBasisPoints(bps int64, mode Rounding) (Money, error) {
	return m.MulRatio(bps, 10_000, mode)
}

// Cmp returns -1, 0 or +1 comparing m to o.
func (m Money) Cmp(o Money) (int, error) {
	if err := m.sameCurrency(o); err != nil {
		return 0, err
	}
	switch {
	case m.minor < o.minor:
		return -1, nil
	case m.minor > o.minor:
		return 1, nil
	}
	return 0, nil
}

// Equal reports exact equality of both amount and currency.
func (m Money) Equal(o Money) bool { return m.cur == o.cur && m.minor == o.minor }

// Allocate splits m across len(weights) buckets in proportion to weights,
// distributing the indivisible remainder one minor unit at a time to the
// buckets with the largest fractional part (largest-remainder method).
//
// The sum of the returned parts is exactly m: no minor unit is created or lost.
func (m Money) Allocate(weights []int64) ([]Money, error) {
	if len(weights) == 0 {
		return nil, errors.New("money: allocate requires at least one weight")
	}
	var total int64
	for _, w := range weights {
		if w < 0 {
			return nil, fmt.Errorf("money: negative weight %d", w)
		}
		if total > math.MaxInt64-w {
			return nil, ErrOverflow
		}
		total += w
	}
	if total == 0 {
		return nil, ErrDivideByZero
	}

	parts := make([]Money, len(weights))
	remainders := make([]int64, len(weights))
	var allocated int64
	for i, w := range weights {
		q, r, err := mulDivRem(m.minor, w, total)
		if err != nil {
			return nil, err
		}
		parts[i] = Money{minor: q, cur: m.cur}
		remainders[i] = r
		allocated += q
	}

	left := m.minor - allocated
	step := int64(1)
	if left < 0 {
		step = -1
		left = -left
	}
	for ; left > 0; left-- {
		best, bestRem := -1, int64(-1)
		for i := range parts {
			if remainders[i] > bestRem {
				best, bestRem = i, remainders[i]
			}
		}
		if best < 0 {
			best = 0
		}
		parts[best].minor += step
		remainders[best] = -1
	}
	return parts, nil
}

// Sum adds every amount, requiring a non-empty, single-currency slice.
func Sum(ms ...Money) (Money, error) {
	if len(ms) == 0 {
		return Money{}, errors.New("money: sum of empty set has no currency")
	}
	acc := Money{minor: 0, cur: ms[0].cur}
	for _, m := range ms {
		var err error
		acc, err = acc.Add(m)
		if err != nil {
			return Money{}, err
		}
	}
	return acc, nil
}

// String renders the amount with its full minor-unit precision, e.g. "INR 1234.56".
func (m Money) String() string {
	return string(m.cur) + " " + m.Decimal()
}

// Decimal renders only the numeric part, e.g. "1234.56" or "-0.07".
func (m Money) Decimal() string {
	e, ok := exponent[m.cur]
	if !ok {
		e = 2
	}
	neg := m.minor < 0
	v := m.minor
	var u uint64
	if neg {
		u = uint64(-(v + 1)) + 1 // safe for MinInt64
	} else {
		u = uint64(v)
	}
	s := strconv.FormatUint(u, 10)
	if e == 0 {
		if neg {
			return "-" + s
		}
		return s
	}
	for len(s) <= e {
		s = "0" + s
	}
	out := s[:len(s)-e] + "." + s[len(s)-e:]
	if neg {
		out = "-" + out
	}
	return out
}

// Parse reads a decimal string ("1234.56", "-0.07", "1,234.56") as an exact
// amount in c. It never goes through a float.
func Parse(s string, c Currency) (Money, error) {
	e, err := Exponent(c)
	if err != nil {
		return Money{}, err
	}
	s = strings.TrimSpace(strings.ReplaceAll(s, ",", ""))
	s = strings.TrimPrefix(s, string(c))
	s = strings.TrimSpace(s)
	if s == "" {
		return Money{}, fmt.Errorf("%w: empty", ErrParse)
	}
	neg := false
	switch s[0] {
	case '-':
		neg, s = true, s[1:]
	case '+':
		s = s[1:]
	}
	intPart, fracPart := s, ""
	if i := strings.IndexByte(s, '.'); i >= 0 {
		intPart, fracPart = s[:i], s[i+1:]
	}
	if intPart == "" {
		intPart = "0"
	}
	if len(fracPart) > e {
		return Money{}, fmt.Errorf("%w: %q has more precision than %s supports", ErrParse, s, c)
	}
	for len(fracPart) < e {
		fracPart += "0"
	}
	digits := intPart + fracPart
	for _, r := range digits {
		if r < '0' || r > '9' {
			return Money{}, fmt.Errorf("%w: %q", ErrParse, s)
		}
	}
	v, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return Money{}, fmt.Errorf("%w: %v", ErrOverflow, err)
	}
	if neg {
		v = -v
	}
	return Money{minor: v, cur: c}, nil
}

// ---- database/driver + JSON -------------------------------------------------

// Value implements driver.Valuer so an amount can be bound directly as BIGINT.
func (m Money) Value() (driver.Value, error) { return m.minor, nil }

// MarshalJSON emits an object so that a currency can never be lost in transit.
func (m Money) MarshalJSON() ([]byte, error) {
	return []byte(`{"minor":` + strconv.FormatInt(m.minor, 10) +
		`,"currency":"` + string(m.cur) + `","display":"` + m.Decimal() + `"}`), nil
}

// ---- 128-bit helpers --------------------------------------------------------

func mulOverflowChecked(a, b int64) (int64, error) {
	if a == 0 || b == 0 {
		return 0, nil
	}
	p := a * b
	if p/b != a || (a == math.MinInt64 && b == -1) || (b == math.MinInt64 && a == -1) {
		return 0, ErrOverflow
	}
	return p, nil
}

// mulDivRem computes a*b/den exactly, returning the quotient and remainder.
func mulDivRem(a, b, den int64) (q int64, rem int64, err error) {
	if den == 0 {
		return 0, 0, ErrDivideByZero
	}
	neg := false
	ua, n1 := absU64(a)
	ub, n2 := absU64(b)
	ud, n3 := absU64(den)
	neg = n1 != n2
	if n3 {
		neg = !neg
	}

	hi, lo := bits.Mul64(ua, ub)
	if hi >= ud {
		return 0, 0, ErrOverflow // quotient cannot fit in 64 bits
	}
	uq, ur := bits.Div64(hi, lo, ud)
	if neg {
		if uq > uint64(math.MaxInt64)+1 {
			return 0, 0, ErrOverflow
		}
		if uq == uint64(math.MaxInt64)+1 {
			return math.MinInt64, -int64(ur), nil
		}
		return -int64(uq), -int64(ur), nil
	}
	if uq > uint64(math.MaxInt64) {
		return 0, 0, ErrOverflow
	}
	return int64(uq), int64(ur), nil
}

// mulDivRound computes round(a*b/den) under mode, exactly.
func mulDivRound(a, b, den int64, mode Rounding) (int64, error) {
	q, rem, err := mulDivRem(a, b, den)
	if err != nil {
		return 0, err
	}
	if rem == 0 {
		return q, nil
	}
	// resultNegative tells us which way "away from zero" points.
	resultNegative := (q < 0) || (q == 0 && rem < 0)

	absRem := rem
	if absRem < 0 {
		absRem = -absRem
	}
	absDen := den
	if absDen < 0 {
		absDen = -absDen
	}

	bump := false
	switch mode {
	case Down:
		bump = false
	case Up:
		bump = true
	case HalfUp:
		bump = absRem*2 >= absDen
	case HalfEven:
		twice := absRem * 2
		switch {
		case twice > absDen:
			bump = true
		case twice < absDen:
			bump = false
		default:
			bump = q%2 != 0
		}
	default:
		return 0, fmt.Errorf("money: unknown rounding mode %d", mode)
	}
	if !bump {
		return q, nil
	}
	if resultNegative {
		if q == math.MinInt64 {
			return 0, ErrOverflow
		}
		return q - 1, nil
	}
	if q == math.MaxInt64 {
		return 0, ErrOverflow
	}
	return q + 1, nil
}

func absU64(v int64) (uint64, bool) {
	if v < 0 {
		return uint64(-(v + 1)) + 1, true
	}
	return uint64(v), false
}
