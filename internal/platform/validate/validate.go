// Package validate holds input validation that is safe against the two classes
// of bug that validation code itself tends to introduce: catastrophic regex
// backtracking, and unbounded allocation from attacker-controlled length.
//
// Every validator here is linear time and bounds length before doing work.
package validate

import (
	"net/mail"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/muthu2201/market-place/internal/platform/problem"
)

// Errors accumulates field failures so a client gets every problem at once.
type Errors struct {
	list []problem.FieldError
}

func (e *Errors) Add(field, code, detail string) {
	e.list = append(e.list, problem.FieldError{Field: field, Code: code, Detail: detail})
}

func (e *Errors) Any() bool { return len(e.list) > 0 }

func (e *Errors) List() []problem.FieldError { return e.list }

// Problem converts accumulated errors into a 422 document, or nil if clean.
func (e *Errors) Problem() *problem.Problem {
	if !e.Any() {
		return nil
	}
	return problem.Validation(e.list...)
}

const (
	MaxEmailLength  = 254
	MaxNameLength   = 120
	MaxTitleLength  = 140
	MaxSlugLength   = 96
	MaxTextLength   = 20_000
	MaxTagLength    = 40
	MaxURLLength    = 2048
	MaxHandleLength = 32
)

// Email validates per RFC 5322 addr-spec via net/mail, then applies the extra
// rules that keep downstream systems safe (length, single address, no display
// name, no control characters).
func (e *Errors) Email(field, v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		e.Add(field, "required", "An e-mail address is required.")
		return ""
	}
	if len(v) > MaxEmailLength {
		e.Add(field, "too_long", "E-mail addresses may not exceed 254 characters.")
		return ""
	}
	if strings.ContainsAny(v, "\r\n\t") {
		e.Add(field, "invalid", "E-mail addresses may not contain control characters.")
		return ""
	}
	addr, err := mail.ParseAddress(v)
	if err != nil || addr.Name != "" || addr.Address != v {
		e.Add(field, "invalid", "That does not look like a valid e-mail address.")
		return ""
	}
	at := strings.LastIndexByte(v, '@')
	if at < 1 || at == len(v)-1 {
		e.Add(field, "invalid", "That does not look like a valid e-mail address.")
		return ""
	}
	domain := v[at+1:]
	if !strings.Contains(domain, ".") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		e.Add(field, "invalid", "The e-mail domain is not valid.")
		return ""
	}
	// Normalise the domain only. The local part is case-sensitive per RFC, and
	// silently lowercasing it has caused real account-takeover bugs elsewhere.
	return v[:at+1] + strings.ToLower(domain)
}

// Required trims and enforces presence plus a maximum rune count.
func (e *Errors) Required(field, v string, max int) string {
	v = strings.TrimSpace(v)
	if v == "" {
		e.Add(field, "required", "This field is required.")
		return ""
	}
	return e.Text(field, v, 1, max)
}

// Text enforces a rune-count range and rejects control characters other than
// newline and tab.
func (e *Errors) Text(field, v string, min, max int) string {
	if !utf8.ValidString(v) {
		e.Add(field, "invalid_encoding", "Input must be valid UTF-8.")
		return ""
	}
	n := utf8.RuneCountInString(v)
	if n < min {
		e.Add(field, "too_short", "This value is too short.")
		return ""
	}
	if n > max {
		e.Add(field, "too_long", "This value is too long.")
		return ""
	}
	for _, r := range v {
		if r == '\n' || r == '\t' || r == '\r' {
			continue
		}
		if unicode.IsControl(r) || r == '\ufeff' || (r >= '\u202a' && r <= '\u202e') || (r >= '\u2066' && r <= '\u2069') {
			// Bidi overrides are excluded: they enable homograph and
			// "Trojan Source" style display spoofing in listings.
			e.Add(field, "invalid_character", "This value contains characters that are not allowed.")
			return ""
		}
	}
	return v
}

// Slug validates a URL segment: lowercase alphanumerics and single hyphens.
func (e *Errors) Slug(field, v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		e.Add(field, "required", "A slug is required.")
		return ""
	}
	if len(v) > MaxSlugLength {
		e.Add(field, "too_long", "Slugs may not exceed 96 characters.")
		return ""
	}
	if strings.HasPrefix(v, "-") || strings.HasSuffix(v, "-") || strings.Contains(v, "--") {
		e.Add(field, "invalid", "Slugs may not start or end with a hyphen, nor contain a double hyphen.")
		return ""
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		e.Add(field, "invalid", "Slugs may contain only lowercase letters, digits and hyphens.")
		return ""
	}
	if reservedSlugs[v] {
		e.Add(field, "reserved", "That slug is reserved.")
		return ""
	}
	return v
}

var reservedSlugs = map[string]bool{
	"admin": true, "api": true, "auth": true, "login": true, "logout": true,
	"signup": true, "register": true, "static": true, "assets": true, "health": true,
	"healthz": true, "readyz": true, "metrics": true, "webhooks": true, "internal": true,
	"seller": true, "sellers": true, "orders": true, "checkout": true, "cart": true,
	"search": true, "download": true, "downloads": true, "legal": true, "docs": true,
	"about": true, "settings": true, "account": true, ".well-known": true, "robots.txt": true,
}

// Handle validates a public seller handle.
func (e *Errors) Handle(field, v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	if len(v) < 3 {
		e.Add(field, "too_short", "Handles must be at least 3 characters.")
		return ""
	}
	if len(v) > MaxHandleLength {
		e.Add(field, "too_long", "Handles may not exceed 32 characters.")
		return ""
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' {
			continue
		}
		e.Add(field, "invalid", "Handles may contain only lowercase letters, digits, hyphen and underscore.")
		return ""
	}
	if reservedSlugs[v] {
		e.Add(field, "reserved", "That handle is reserved.")
		return ""
	}
	return v
}

// OneOf constrains a value to a closed set.
func (e *Errors) OneOf(field, v string, allowed ...string) string {
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	e.Add(field, "invalid_choice", "This value is not one of the permitted options.")
	return ""
}

// IntRange enforces inclusive integer bounds.
func (e *Errors) IntRange(field string, v, min, max int64) int64 {
	if v < min || v > max {
		e.Add(field, "out_of_range", "This value is outside the permitted range.")
		return 0
	}
	return v
}

// GSTIN validates an Indian GST identification number including its checksum.
// The format is 2 state digits, a 10-character PAN, an entity digit, "Z", and a
// check character over base-36 with an alternating 1/2 weighting.
func (e *Errors) GSTIN(field, v string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	if v == "" {
		e.Add(field, "required", "A GSTIN is required.")
		return ""
	}
	if len(v) != 15 {
		e.Add(field, "invalid", "A GSTIN is exactly 15 characters.")
		return ""
	}
	if !isDigits(v[0:2]) {
		e.Add(field, "invalid", "The first two characters of a GSTIN are the state code.")
		return ""
	}
	state := (int(v[0]-'0') * 10) + int(v[1]-'0')
	if !validStateCodes[state] {
		e.Add(field, "invalid_state", "That GST state code does not exist.")
		return ""
	}
	if !panShape(v[2:12]) {
		e.Add(field, "invalid", "The embedded PAN is not well formed.")
		return ""
	}
	if v[13] != 'Z' {
		e.Add(field, "invalid", "The 14th character of a GSTIN must be Z.")
		return ""
	}
	if !gstinChecksumOK(v) {
		e.Add(field, "checksum", "The GSTIN checksum does not match.")
		return ""
	}
	return v
}

// PAN validates an Indian Permanent Account Number's shape (AAAAA9999A).
func (e *Errors) PAN(field, v string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	if !panShape(v) {
		e.Add(field, "invalid", "A PAN looks like ABCDE1234F.")
		return ""
	}
	return v
}

// IFSC validates an Indian bank branch code (4 letters, '0', 6 alphanumerics).
func (e *Errors) IFSC(field, v string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	if len(v) != 11 || !isAlpha(v[0:4]) || v[4] != '0' {
		e.Add(field, "invalid", "An IFSC looks like HDFC0001234.")
		return ""
	}
	for i := 5; i < 11; i++ {
		c := v[i]
		if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			e.Add(field, "invalid", "An IFSC looks like HDFC0001234.")
			return ""
		}
	}
	return v
}

// BankAccount validates the shape of an Indian account number.
func (e *Errors) BankAccount(field, v string) string {
	v = strings.TrimSpace(v)
	if len(v) < 6 || len(v) > 20 || !isDigits(v) {
		e.Add(field, "invalid", "Account numbers are 6 to 20 digits.")
		return ""
	}
	return v
}

const b36 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

func gstinChecksumOK(v string) bool {
	sum := 0
	for i := 0; i < 14; i++ {
		idx := strings.IndexByte(b36, v[i])
		if idx < 0 {
			return false
		}
		factor := 1
		if i%2 == 1 {
			factor = 2
		}
		p := idx * factor
		sum += p/36 + p%36
	}
	check := (36 - (sum % 36)) % 36
	return v[14] == b36[check]
}

func panShape(v string) bool {
	return len(v) == 10 && isAlpha(v[0:5]) && isDigits(v[5:9]) && isAlpha(v[9:10])
}

func isAlpha(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return false
		}
	}
	return len(s) > 0
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

// validStateCodes covers every GST state/UT code currently in issue,
// including 97 (Other Territory) and 99 (Centre Jurisdiction).
var validStateCodes = func() map[int]bool {
	m := map[int]bool{97: true, 99: true}
	for i := 1; i <= 38; i++ {
		m[i] = true
	}
	return m
}()
