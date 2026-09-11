# 0004. Money is an integer count of minor units

Status: Accepted
Date: 2026-09-11

## Context

Binary floating point cannot represent 0.01 exactly. In a system that applies an
18% tax, a 9% commission, a 1% collection and a 0.1% deduction to the same
amount and then requires the parts to sum back to the whole, floating point does
not merely lose precision: it loses money, in a direction nobody can predict.

## Decision

Every monetary amount is an `int64` count of minor units with its currency
attached. `internal/platform/money` is the only place arithmetic happens, and
`cmd/archcheck` fails the build if `float32` or `float64` appears anywhere on a
money path.

Four properties matter and each is tested:

- **Ratios cannot overflow before they divide.** Applying a rate goes through a
  128-bit intermediate, so `MaxInt64/2 × 1800 / 10000` is exact rather than
  wrapped.
- **Rounding is always explicit.** There is no default mode. Tax uses half-up,
  which is what GST computation prescribes; withholding a rolling reserve rounds
  down, so the platform never withholds more than it should.
- **Allocation conserves.** Splitting an amount across weights uses the
  largest-remainder method, so the parts sum back to the whole exactly. 20,000
  randomised allocations assert no minor unit is created or lost.
- **Currency travels with the amount.** Cross-currency arithmetic returns an
  error rather than a number.

Money is serialised as an object carrying `minor`, `currency` and a display
string, never as a bare number. A bare number becomes a float in most clients,
which reintroduces the bug at the API boundary. A test asserts this.

## Consequences

Call sites are more verbose: every operation returns an error. That is the
intended trade. A silent wrong answer in a payments system is worse than a noisy
one, and 200,000 randomised sales in the tax suite confirm the components always
reconcile to the buyer's total.

Rates are represented in basis points as integers, so 18% is 1800 and 0.1% is 10,
all exactly representable. The only floating point anywhere near money is in
rendering a rate into human-readable text, which carries an `//archcheck:allow`
directive with that reason.
