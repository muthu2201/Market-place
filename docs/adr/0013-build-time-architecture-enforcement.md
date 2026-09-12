# 0013. Architecture rules enforced at build time

Status: Accepted
Date: 2026-09-11

## Context

A modular monolith (ADR 0001) is only modular while its boundaries hold. They
erode the same way every time: a deadline, a reviewer who does not notice one
import among forty changed files, and six months later the "modules" are a
directory layout with no meaning behind it.

Documented conventions do not prevent this. Neither does code review, reliably —
reviewers are good at logic and bad at noticing an import that should not exist.

## Decision

Architecture rules are compiled and executed. `cmd/archcheck` runs in CI and
fails the build on violation.

Eight rules are enforced across the tree:

1. **Declared dependency matrix.** Each module names the modules it may import. An
   undeclared edge fails. Adding one is a deliberate edit to the matrix, which is
   a visible line in a diff that a reviewer will ask about.
2. **No module imports another module's internals**; only its public surface.
3. **Platform packages may not import modules.** Infrastructure never depends on
   business logic, which is what keeps `platform/` reusable and testable.
4. **No raw SQL outside repository layers.** A query in a handler is a boundary
   violation whether or not it works.
5. **No `time.Now()` in business logic.** Every service takes a clock. This is what
   makes deterministic tests of settlement windows, token expiry and rate limits
   possible at all.
6. **No `float64` in money or tax paths** (ADR 0004).
7. **No `fmt.Sprintf` building SQL.** Injection prevention as a structural rule
   rather than a habit.
8. **No `panic` in request paths.** A panic in a handler is a 500 with no problem
   document and no audit trail.

Exemptions are inline: `//archcheck:allow <fragment> -- <reason>`, scoped to the
enclosing statement, and the reason is mandatory. Across 86 files there are 12,
each with a written justification — a number small enough to read in full during
review, which is the point.

## Why a custom checker

The rules are specific to this system's invariants. "No `time.Now()` in a service"
and "no `float64` in `internal/modules/tax`" are not rules a generic linter ships
with, and expressing them in a general-purpose configuration language would be
more code than the checker itself. `archcheck` is a few hundred lines over
`go/ast` and `go/parser`, with no dependencies.

## Consequences

CI rejects architecturally-invalid code that compiles and passes tests. That is
occasionally annoying and always correct.

The rules themselves are the honest, executable statement of the architecture. If
someone wants to know what the boundaries are, the answer is a file that *fails
the build* when it is wrong, rather than a diagram that quietly goes stale.

The checker is a maintenance obligation: a rule that produces false positives
will be exempted into uselessness. Each rule earns its place by catching real
violations, and one that stops doing so should be deleted rather than kept for
appearances.
