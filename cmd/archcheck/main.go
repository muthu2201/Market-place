// Command archcheck enforces architecture rules at build time.
//
// A modular monolith only stays modular if something mechanical says so. This
// is that thing: the Go equivalent of ArchUnit fitness functions, run in CI and
// before every commit. A violation fails the build rather than being noticed in
// review, or not noticed at all.
//
// The rules below are not style preferences. Each one exists because breaking
// it has a specific, identifiable consequence, stated in its Why field and
// printed when it fires.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const modulePath = "github.com/muthu2201/market-place"

// Violation is one broken rule.
type Violation struct {
	Rule string
	File string
	Line int
	Why  string
	What string
}

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	files, err := collect(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "archcheck:", err)
		os.Exit(2)
	}

	var violations []Violation
	var exempted int
	for _, f := range files {
		for _, v := range checkFile(f) {
			if f.exempt(v.Line, v.Rule) {
				exempted++
				continue
			}
			violations = append(violations, v)
		}
	}
	violations = append(violations, checkLayering(files)...)

	sort.Slice(violations, func(i, j int) bool {
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		return violations[i].Line < violations[j].Line
	})

	if len(violations) == 0 {
		fmt.Printf("archcheck: %d files, all architecture rules hold (%d justified exemption(s))\n",
			len(files), exempted)
		return
	}
	fmt.Fprintf(os.Stderr, "archcheck: %d violation(s)\n\n", len(violations))
	for _, v := range violations {
		fmt.Fprintf(os.Stderr, "%s:%d\n  rule: %s\n  found: %s\n  why:  %s\n\n", v.File, v.Line, v.Rule, v.What, v.Why)
	}
	os.Exit(1)
}

type goFile struct {
	path    string
	pkgPath string // import path relative to the module, e.g. internal/modules/orders
	isTest  bool
	fset    *token.FileSet
	file    *ast.File
	src     string
	// allows maps a line number to the rule fragment exempted there.
	allows map[int]string
}

// allowDirective marks a deliberate, justified exception:
//
//	//archcheck:allow <rule fragment> -- <reason>
//
// The reason is mandatory and is printed by `archcheck --list-exemptions`, so
// every exception is visible in one place rather than buried in a diff.
const allowDirective = "//archcheck:allow "

func parseAllows(fset *token.FileSet, f *ast.File) map[int]string {
	out := map[int]string{}
	for _, group := range f.Comments {
		for _, c := range group.List {
			text := strings.TrimSpace(c.Text)
			if !strings.HasPrefix(text, allowDirective) {
				continue
			}
			body := strings.TrimPrefix(text, allowDirective)
			fragment, reason, ok := strings.Cut(body, "--")
			if !ok || strings.TrimSpace(reason) == "" {
				continue // an exemption without a reason is not an exemption
			}
			frag := strings.TrimSpace(fragment)
			start := fset.Position(c.Pos()).Line

			// The directive covers the whole statement it sits inside, found by
			// walking for the innermost statement spanning this line. Covering a
			// fixed number of lines instead would silently miss the tail of a
			// multi-line call, or silently exempt the statement after it.
			end := start + 1
			ast.Inspect(f, func(n ast.Node) bool {
				stmt, ok := n.(ast.Stmt)
				if !ok {
					return true
				}
				lo := fset.Position(stmt.Pos()).Line
				hi := fset.Position(stmt.End()).Line
				if lo <= start+1 && hi >= start && hi-lo < 40 {
					if hi > end {
						end = hi
					}
				}
				return true
			})
			for line := start; line <= end; line++ {
				out[line] = frag
			}
		}
	}
	return out
}

// exempt reports whether a violation at line is covered by a directive.
func (f goFile) exempt(line int, rule string) bool {
	frag, ok := f.allows[line]
	if !ok {
		return false
	}
	return strings.Contains(rule, frag)
}

func collect(root string) ([]goFile, error) {
	var out []goFile
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "node_modules", "vendor", "bin", "dist", "var", "tmp":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, path, src, parser.ParseComments)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		rel, _ := filepath.Rel(root, filepath.Dir(path))
		out = append(out, goFile{
			path: path, pkgPath: filepath.ToSlash(rel),
			isTest: strings.HasSuffix(path, "_test.go"),
			fset:   fset, file: parsed, src: string(src),
			allows: parseAllows(fset, parsed),
		})
		return nil
	})
	return out, err
}

func (f goFile) imports() []string {
	var out []string
	for _, imp := range f.file.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		out = append(out, p)
	}
	return out
}

func (f goFile) importLine(path string) int {
	for _, imp := range f.file.Imports {
		if p, err := strconv.Unquote(imp.Path.Value); err == nil && p == path {
			return f.fset.Position(imp.Pos()).Line
		}
	}
	return 1
}

// local strips the module prefix from an import path, or returns "" when the
// import is external.
func local(path string) string {
	if !strings.HasPrefix(path, modulePath+"/") {
		return ""
	}
	return strings.TrimPrefix(path, modulePath+"/")
}

// ---- rules ------------------------------------------------------------------

func checkFile(f goFile) []Violation {
	// The checker's own rule descriptions quote SQL and crypto names, so
	// analysing itself produces nothing but noise.
	if f.pkgPath == "cmd/archcheck" {
		return nil
	}
	var v []Violation
	v = append(v, ruleCryptoIsCentralised(f)...)
	v = append(v, ruleNoFloatInMoneyPaths(f)...)
	v = append(v, ruleJournalWritesGoThroughLedger(f)...)
	v = append(v, ruleNoDirectStdoutLogging(f)...)
	v = append(v, ruleNoSQLStringConcatenation(f)...)
	v = append(v, ruleTestSupportStaysInTests(f)...)
	v = append(v, ruleNoPanicInRequestPath(f)...)
	v = append(v, ruleTimeComesFromTheClock(f)...)
	return v
}

// Rule: only internal/platform/cryptox may call crypto primitives directly.
func ruleCryptoIsCentralised(f goFile) []Violation {
	if f.isTest || f.pkgPath == "internal/platform/cryptox" {
		return nil
	}
	// The storage SigV4 signer and the payment adapters verify provider
	// signatures; both are security-reviewed boundaries with their own tests.
	switch f.pkgPath {
	case "internal/storage", "internal/testsupport/gatewaysim", "cmd/gatewaysim":
		return nil
	}
	var v []Violation
	for _, imp := range f.imports() {
		switch imp {
		case "crypto/aes", "crypto/cipher", "crypto/des", "crypto/rc4",
			"golang.org/x/crypto/argon2", "golang.org/x/crypto/bcrypt",
			"golang.org/x/crypto/scrypt", "golang.org/x/crypto/hkdf":
			v = append(v, Violation{
				Rule: "cryptography is centralised in internal/platform/cryptox",
				File: f.path, Line: f.importLine(imp), What: "imports " + imp,
				Why: "A security review should have to read one package, not every package. " +
					"Add what you need to cryptox and call it from there.",
			})
		case "math/rand":
			v = append(v, Violation{
				Rule: "no math/rand outside tests",
				File: f.path, Line: f.importLine(imp), What: "imports math/rand",
				Why: "math/rand is predictable. Anything security-relevant must use crypto/rand via cryptox.",
			})
		}
	}
	return v
}

// Rule: no floating point in money, tax or ledger code.
func ruleNoFloatInMoneyPaths(f goFile) []Violation {
	moneyPaths := []string{
		"internal/platform/money", "internal/modules/tax",
		"internal/modules/ledger", "internal/modules/orders",
		"internal/modules/payouts",
	}
	matched := false
	for _, p := range moneyPaths {
		if f.pkgPath == p {
			matched = true
			break
		}
	}
	if !matched || f.isTest {
		return nil
	}

	var v []Violation
	ast.Inspect(f.file, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		if id.Name != "float32" && id.Name != "float64" {
			return true
		}
		v = append(v, Violation{
			Rule: "money is never a float",
			File: f.path, Line: f.fset.Position(id.Pos()).Line,
			What: "uses " + id.Name,
			Why: "Binary floating point cannot represent 0.01 exactly, so repeated arithmetic drifts. " +
				"Every amount in this system is an integer count of minor units carrying its currency.",
		})
		return true
	})
	return v
}

// Rule: only internal/modules/ledger writes the journal tables.
func ruleJournalWritesGoThroughLedger(f goFile) []Violation {
	if f.isTest || f.pkgPath == "internal/modules/ledger" {
		return nil
	}
	var v []Violation
	lower := strings.ToLower(f.src)
	for _, table := range []string{"journal_entries", "journal_lines"} {
		for _, verb := range []string{"insert into " + table, "update " + table, "delete from " + table} {
			if idx := strings.Index(lower, verb); idx >= 0 {
				v = append(v, Violation{
					Rule: "the journal is written only through internal/modules/ledger",
					File: f.path, Line: lineOf(f.src, idx),
					What: "contains SQL writing " + table,
					Why: "Ledger.Post enforces balance, idempotency and currency rules before the database " +
						"does. Bypassing it turns a compile-time guarantee into a runtime surprise.",
				})
			}
		}
	}
	return v
}

// Rule: production code logs through logx, not to stdout directly.
func ruleNoDirectStdoutLogging(f goFile) []Violation {
	if f.isTest || strings.HasPrefix(f.pkgPath, "cmd/") {
		return nil
	}
	var v []Violation
	ast.Inspect(f.file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		banned := map[string]map[string]bool{
			"fmt": {"Print": true, "Println": true, "Printf": true},
			"log": {"Print": true, "Println": true, "Printf": true, "Fatal": true, "Fatalf": true, "Fatalln": true},
		}
		if names, ok := banned[pkg.Name]; ok && names[sel.Sel.Name] {
			v = append(v, Violation{
				Rule: "structured logging only",
				File: f.path, Line: f.fset.Position(call.Pos()).Line,
				What: pkg.Name + "." + sel.Sel.Name,
				Why: "Unstructured output bypasses secret redaction and request correlation. " +
					"Use logx, which redacts anything that looks like a credential.",
			})
		}
		return true
	})
	return v
}

// Rule: SQL is never built by concatenating a variable.
func ruleNoSQLStringConcatenation(f goFile) []Violation {
	if f.isTest {
		return nil
	}
	var v []Violation
	ast.Inspect(f.file, func(n ast.Node) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if !ok || bin.Op != token.ADD {
			return true
		}
		lit, ok := bin.X.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		text := strings.ToLower(lit.Value)
		if !containsSQLVerb(text) {
			return true
		}
		// Concatenating another literal is fine; concatenating an expression
		// is how injection happens.
		if _, ok := bin.Y.(*ast.BasicLit); ok {
			return true
		}
		v = append(v, Violation{
			Rule: "SQL is parameterised, never concatenated",
			File: f.path, Line: f.fset.Position(bin.Pos()).Line,
			What: "builds a SQL string with +",
			Why: "Every value must travel as a bind parameter. If an identifier genuinely must vary, " +
				"choose it from a closed set in code and say so in a comment.",
		})
		return true
	})
	return v
}

func containsSQLVerb(lowerLit string) bool {
	for _, verb := range []string{"select ", "insert into", "update ", "delete from", " where ", " values("} {
		if strings.Contains(lowerLit, verb) {
			return true
		}
	}
	return false
}

// Rule: test support never reaches production code.
func ruleTestSupportStaysInTests(f goFile) []Violation {
	if f.isTest || strings.HasPrefix(f.pkgPath, "internal/testsupport") || f.pkgPath == "cmd/gatewaysim" {
		return nil
	}
	var v []Violation
	for _, imp := range f.imports() {
		l := local(imp)
		if strings.HasPrefix(l, "internal/testsupport") || l == "internal/platform/dbtest" {
			v = append(v, Violation{
				Rule: "test support is not reachable from production code",
				File: f.path, Line: f.importLine(imp), What: "imports " + l,
				Why: "The gateway simulator and fixtures exist so tests can run without a third party. " +
					"A production path that can reach them is a production path that can be faked.",
			})
		}
	}
	return v
}

// Rule: no panic in a request-handling package.
func ruleNoPanicInRequestPath(f goFile) []Violation {
	if f.isTest {
		return nil
	}
	if !strings.HasPrefix(f.pkgPath, "internal/modules") && !strings.HasPrefix(f.pkgPath, "internal/api") {
		return nil
	}
	var v []Violation
	ast.Inspect(f.file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok || id.Name != "panic" {
			return true
		}
		v = append(v, Violation{
			Rule: "request handling returns errors, it does not panic",
			File: f.path, Line: f.fset.Position(call.Pos()).Line, What: "calls panic",
			Why: "A panic in a handler is recovered into an opaque 500. Returning a problem document " +
				"tells the caller what went wrong and keeps the failure in the type system.",
		})
		return true
	})
	return v
}

// Rule: wall-clock time comes from the injected clock.
func ruleTimeComesFromTheClock(f goFile) []Violation {
	if f.isTest || f.pkgPath == "internal/platform/clock" {
		return nil
	}
	if !strings.HasPrefix(f.pkgPath, "internal/modules") {
		return nil
	}
	var v []Violation
	ast.Inspect(f.file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Now" {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "time" {
			return true
		}
		v = append(v, Violation{
			Rule: "wall-clock time comes from the injected clock",
			File: f.path, Line: f.fset.Position(sel.Pos()).Line, What: "calls time.Now",
			Why: "Expiry, decay, settlement windows and rate limits all depend on time. Reading it " +
				"directly makes those behaviours untestable without sleeping. Use the service's clock.",
		})
		return true
	})
	return v
}

// ---- layering ---------------------------------------------------------------

// allowedDeps declares, for each module, which other local modules it may
// import. Anything not listed is refused, so a new coupling has to be a
// deliberate edit to this table rather than an accident.
var allowedDeps = map[string][]string{
	"internal/platform":           {},
	"internal/outbox":             {"internal/platform"},
	"internal/storage":            {"internal/platform"},
	"internal/antivirus":          {"internal/platform"},
	"internal/modules/audit":      {"internal/platform"},
	"internal/modules/tax":        {"internal/platform"},
	"internal/modules/ranking":    {},
	"internal/modules/identity":   {"internal/platform", "internal/modules/audit"},
	"internal/modules/ledger":     {"internal/platform"},
	"internal/modules/payments":   {"internal/platform"},
	"internal/modules/provenance": {"internal/platform"},
	"internal/modules/catalog": {
		"internal/platform", "internal/modules/audit", "internal/modules/ranking",
		"internal/modules/provenance", "internal/storage", "internal/antivirus", "internal/outbox",
	},
	"internal/modules/delivery": {"internal/platform", "internal/modules/audit", "internal/storage"},
	"internal/modules/orders": {
		"internal/platform", "internal/modules/audit", "internal/modules/ledger",
		"internal/modules/payments", "internal/modules/tax", "internal/outbox",
	},
	"internal/modules/payouts": {
		"internal/platform", "internal/modules/audit", "internal/modules/ledger",
		"internal/modules/payments", "internal/outbox",
	},
	"internal/modules/compliance": {
		"internal/platform", "internal/modules/audit", "internal/modules/identity", "internal/outbox",
	},
	"internal/modules/notifications": {"internal/platform", "internal/modules/audit", "internal/outbox"},
	"internal/modules/search":        {"internal/platform", "internal/modules/ranking"},
	"internal/modules/disputes":      {"internal/platform", "internal/modules/audit", "internal/outbox"},
	"internal/modules/admin": {
		"internal/platform", "internal/modules/audit", "internal/modules/identity",
		"internal/modules/ledger", "internal/modules/orders",
	},
	"internal/modules/analytics": {"internal/platform"},
	"internal/modules/taxonomy":  {"internal/platform", "internal/modules/audit"},
	"internal/modules/seller":    {"internal/platform", "internal/modules/audit", "internal/modules/identity", "internal/modules/payments"},
}

func checkLayering(files []goFile) []Violation {
	var v []Violation
	for _, f := range files {
		if f.isTest || strings.HasPrefix(f.pkgPath, "cmd/") ||
			strings.HasPrefix(f.pkgPath, "internal/api") ||
			strings.HasPrefix(f.pkgPath, "internal/web") ||
			strings.HasPrefix(f.pkgPath, "internal/testsupport") ||
			strings.HasPrefix(f.pkgPath, "db/") {
			// Composition roots are allowed to see everything; that is what
			// makes them composition roots.
			continue
		}
		owner, allowed, known := ownerOf(f.pkgPath)
		if !known {
			continue
		}
		for _, imp := range f.imports() {
			l := local(imp)
			if l == "" || strings.HasPrefix(l, "db/migrations") {
				continue
			}
			target, _, targetKnown := ownerOf(l)
			if !targetKnown || target == owner {
				continue
			}
			if !contains(allowed, target) {
				v = append(v, Violation{
					Rule: "module boundaries are declared in cmd/archcheck",
					File: f.path, Line: f.importLine(imp),
					What: owner + " imports " + target,
					Why: "This coupling is not in the declared dependency table. If it is genuinely " +
						"needed, add it there so the architecture stays reviewable in one place.",
				})
			}
		}
	}
	return v
}

// ownerOf maps a package path to the module that owns it.
func ownerOf(pkgPath string) (owner string, allowed []string, known bool) {
	if strings.HasPrefix(pkgPath, "internal/platform") {
		return "internal/platform", allowedDeps["internal/platform"], true
	}
	if deps, ok := allowedDeps[pkgPath]; ok {
		return pkgPath, deps, true
	}
	// A module's sub-packages inherit its rules.
	for candidate, deps := range allowedDeps {
		if strings.HasPrefix(pkgPath, candidate+"/") {
			return candidate, deps, true
		}
	}
	return "", nil, false
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func lineOf(src string, offset int) int {
	return strings.Count(src[:offset], "\n") + 1
}
