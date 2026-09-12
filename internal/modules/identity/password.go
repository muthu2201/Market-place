package identity

import (
	"strings"
	"unicode"
)

// IsWeakPassword implements the NIST SP 800-63B posture: no composition rules,
// but a hard block on passwords that are known-common, derived from the user's
// own details, or structurally trivial.
//
// Composition rules ("one uppercase, one symbol") measurably push users toward
// predictable substitutions. Length plus a blocklist is both friendlier and
// stronger, so that is what is enforced here.
func IsWeakPassword(password, email, displayName string) (bool, string) {
	lower := strings.ToLower(password)

	// A blocklist is only as good as its normalisation: "P4ssw0rd123" and
	// "password" are the same guess to an attacker's wordlist. Every ordering
	// of de-leeting and digit-stripping is checked, because applying them in
	// one fixed order misses cases like "p4ssw0rd1234".
	for _, candidate := range normalisedCandidates(lower) {
		if len(candidate) >= 4 && commonPasswords[candidate] {
			if candidate == lower {
				return true, "That password appears on lists of the most commonly used passwords. Choose something unpredictable; a short phrase works well."
			}
			return true, "That is a common password with digits or letter substitutions added, which offers almost no additional protection against a wordlist attack."
		}
	}

	for _, ctx := range contextTokens(email, displayName) {
		if len(ctx) >= 4 && strings.Contains(lower, ctx) {
			return true, "Your password contains part of your own name or e-mail address, which is the first thing an attacker tries."
		}
	}

	if distinctRunes(password) <= 4 && len(password) < 20 {
		return true, "That password uses too few distinct characters. A longer phrase of ordinary words is stronger and easier to remember."
	}
	if hasRun(lower, 5) {
		return true, "That password is mostly a sequence or a repeated character. Choose something less predictable."
	}
	for _, pattern := range keyboardRuns {
		if len(pattern) >= 6 && strings.Contains(lower, pattern) {
			return true, "That password contains a keyboard pattern, which cracking tools try first."
		}
	}
	return false, ""
}

// normalisedCandidates expands a password into the forms a cracking wordlist
// would already cover.
func normalisedCandidates(lower string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	add(lower)
	stripped := stripTrailingDigits(lower)
	add(stripped)
	add(deLeet(lower))
	add(deLeet(stripped))
	add(stripTrailingDigits(deLeet(lower)))
	add(stripTrailingDigits(deLeet(stripped)))
	return out
}

func contextTokens(email, displayName string) []string {
	var out []string
	if at := strings.IndexByte(email, '@'); at > 0 {
		local := strings.ToLower(email[:at])
		out = append(out, local)
		for _, part := range strings.FieldsFunc(local, func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsDigit(r)
		}) {
			if len(part) >= 4 {
				out = append(out, part)
			}
		}
		if dot := strings.IndexByte(strings.ToLower(email[at+1:]), '.'); dot > 0 {
			out = append(out, strings.ToLower(email[at+1:at+1+dot]))
		}
	}
	for _, part := range strings.Fields(strings.ToLower(displayName)) {
		if len(part) >= 4 {
			out = append(out, part)
		}
	}
	out = append(out, "marketplace")
	return out
}

func distinctRunes(s string) int {
	seen := make(map[rune]struct{}, len(s))
	for _, r := range s {
		seen[r] = struct{}{}
	}
	return len(seen)
}

// hasRun reports a run of n identical, ascending or descending characters.
func hasRun(s string, n int) bool {
	if len(s) < n {
		return false
	}
	same, up, down := 1, 1, 1
	for i := 1; i < len(s); i++ {
		switch {
		case s[i] == s[i-1]:
			same++
		default:
			same = 1
		}
		switch {
		case s[i] == s[i-1]+1:
			up++
		default:
			up = 1
		}
		switch {
		case s[i] == s[i-1]-1:
			down++
		default:
			down = 1
		}
		if same >= n || up >= n || down >= n {
			return true
		}
	}
	return false
}

func stripTrailingDigits(s string) string {
	i := len(s)
	for i > 0 && s[i-1] >= '0' && s[i-1] <= '9' {
		i--
	}
	return s[:i]
}

var leetReplacer = strings.NewReplacer("0", "o", "1", "i", "3", "e", "4", "a", "5", "s", "7", "t", "@", "a", "$", "s", "!", "i")

func deLeet(s string) string { return leetReplacer.Replace(s) }

var keyboardRuns = []string{
	"qwerty", "qwertyui", "asdfgh", "asdfghjk", "zxcvbn", "zxcvbnm",
	"1qaz2wsx", "qazwsx", "123qwe", "qwe123", "poiuyt", "lkjhgf", "mnbvcx",
}

// commonPasswords is a blocklist of the passwords that dominate real breach
// corpora, including the India-specific entries that generic English lists miss.
// It is checked after normalisation (lower-cased, de-leeted, digits stripped),
// so it covers far more than its literal size.
var commonPasswords = func() map[string]bool {
	list := []string{
		"password", "123456", "123456789", "12345678", "12345", "1234567", "1234567890",
		"qwerty", "abc123", "111111", "123123", "000000", "iloveyou", "1234", "1q2w3e4r",
		"admin", "letmein", "welcome", "monkey", "login", "princess", "dragon", "passw0rd",
		"master", "hello", "freedom", "whatever", "qazwsx", "trustno1", "sunshine", "football",
		"baseball", "superman", "batman", "shadow", "michael", "jennifer", "jordan", "harley",
		"ranger", "buster", "soccer", "hockey", "killer", "george", "andrew", "charlie",
		"thomas", "robert", "computer", "internet", "samsung", "google", "facebook", "starwars",
		"password1", "password123", "admin123", "root", "toor", "guest", "test", "testing",
		"changeme", "secret", "default", "temporary", "temp", "pass", "passcode",
		// India-specific, from regional breach corpora.
		"india123", "bharat", "krishna", "ganesh", "shivam", "rahul", "priya", "sachin",
		"cricket", "bollywood", "namaste", "chennai", "mumbai", "delhi", "bangalore",
		"hyderabad", "kolkata", "indian", "hanuman", "jaishreeram", "omnamahshivaya",
		"maabharti", "ilovemyindia", "mypassword", "welcome123", "qwerty123", "abcd1234",
		"asdf1234", "zaq12wsx", "1qaz2wsx", "aaaaaa", "abcdef", "abcdefg", "abcdefgh",
		"letmein123", "iloveyou1", "sunshine1", "princess1", "dragon123",
		"the quick brown fox", "correcthorsebatterystaple", "correct horse battery staple",
		"loveyou", "lovely", "family", "friend", "forever", "angel", "jesus", "heaven",
		"money", "success", "winner", "happy", "smile", "flower", "butterfly", "chocolate",
	}
	m := make(map[string]bool, len(list)*2)
	for _, p := range list {
		m[p] = true
		m[deLeet(p)] = true
	}
	return m
}()
