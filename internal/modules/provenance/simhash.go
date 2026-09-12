package provenance

import (
	"bufio"
	"hash/fnv"
	"io"
	"strings"
	"unicode"
)

// SimHash computes a 64-bit SimHash over shingled tokens.
//
// This is the non-image half of near-duplicate detection. A marketplace sells a
// great deal that is not a picture — code, templates, copy decks, course
// scripts, prompt packs — and the same harm applies: somebody's work reappearing
// under somebody else's name, lightly edited.
//
// SimHash rather than a cryptographic digest because the whole point is that
// the hash must NOT change when the content barely does. Renaming a variable,
// reflowing a paragraph or changing a heading moves a handful of bits; rewriting
// the work moves most of them.
//
// Normalisation is deliberately aggressive — case folded, punctuation dropped,
// runs of whitespace collapsed — because every one of those is a free edit for
// someone republishing work that is not theirs.
func SimHash(r io.Reader) (uint64, error) {
	const shingleSize = 3

	var vector [64]int
	var window []string
	var tokens int

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxSimHashInput)
	sc.Split(bufio.ScanWords)

	for sc.Scan() {
		tok := normaliseToken(sc.Text())
		if tok == "" {
			continue
		}
		tokens++
		window = append(window, tok)
		if len(window) < shingleSize {
			continue
		}
		if len(window) > shingleSize {
			window = window[1:]
		}
		accumulate(&vector, strings.Join(window, " "))
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}

	// A document shorter than one shingle has no meaningful fingerprint.
	// Returning zero says "not computed", which is what the caller must treat
	// it as, rather than inventing a hash of nothing.
	if tokens < shingleSize {
		return 0, nil
	}

	var hash uint64
	for i, weight := range vector {
		if weight > 0 {
			hash |= 1 << uint(i)
		}
	}
	// Guarantee a non-zero result so it cannot be confused with "not computed".
	if hash == 0 {
		hash = 1
	}
	return hash, nil
}

// maxSimHashInput bounds one token, so a file with no whitespace cannot make
// the scanner allocate without limit.
const maxSimHashInput = 1 << 20

func accumulate(vector *[64]int, shingle string) {
	h := fnv.New64a()
	_, _ = h.Write([]byte(shingle))
	sum := h.Sum64()
	for i := 0; i < 64; i++ {
		if sum&(1<<uint(i)) != 0 {
			vector[i]++
		} else {
			vector[i]--
		}
	}
}

// normaliseToken folds away the edits that cost a plagiarist nothing.
func normaliseToken(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(unicode.ToLower(r))
		case r == '_' || r == '-':
			// Kept: they carry meaning in identifiers, where a rename is
			// exactly the edit we want to remain visible.
			b.WriteRune(r)
		}
	}
	return b.String()
}

// CompareText reports whether two SimHashes describe the same work.
//
// The threshold is tighter than the image one because text SimHash spreads more
// evenly: 3 of 64 bits is roughly "the same document with light edits", where
// independently written documents on the same topic sit far higher.
const NearDuplicateTextThreshold = 3

// CompareText reports how close two text fingerprints are.
func CompareText(a, b uint64) DuplicateVerdict {
	if a == 0 || b == 0 {
		return DuplicateVerdict{Distance: -1,
			Explanation: "one of the assets has no text fingerprint, so no comparison was made"}
	}
	d := HammingDistance(a, b)
	v := DuplicateVerdict{Distance: d, NearDuplicate: d <= NearDuplicateTextThreshold}
	switch {
	case d == 0:
		v.Explanation = "the two documents are identical after normalisation"
	case v.NearDuplicate:
		v.Explanation = "the two documents differ only by light editing"
	default:
		v.Explanation = "the two documents are not the same work"
	}
	return v
}
