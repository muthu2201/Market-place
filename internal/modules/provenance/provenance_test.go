package provenance

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	"image/png"
	"math"
	"math/rand"
	"strings"
	"testing"
)

// ---- perceptual hashing -----------------------------------------------------

// TestPerceptualHashSurvivesTheEditsAThiefWouldMake is the whole purpose of the
// hash. Someone reselling another seller's work re-compresses it, resizes it,
// adjusts levels or stamps a watermark on it. The hash has to survive all of
// those, because any one of them would otherwise be a free evasion.
func TestPerceptualHashSurvivesTheEditsAThiefWouldMake(t *testing.T) {
	original := syntheticArtwork(400, 300, 1)
	base := hashImage(t, original)

	for _, tc := range []struct {
		name    string
		altered image.Image
		maxDist int
	}{
		{"re-encoded as heavily compressed JPEG", reencodeJPEG(t, original, 30), 6},
		{"resized to half", resize(original, 200, 150), 8},
		{"resized to double", resize(original, 800, 600), 8},
		{"brightened by 20%", adjustBrightness(original, 1.2), 6},
		{"darkened by 20%", adjustBrightness(original, 0.8), 6},
		{"watermarked across the middle", watermark(original), 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := perceptualHashOf(tc.altered)
			if err != nil {
				t.Fatal(err)
			}
			d := HammingDistance(base, got)
			if d > tc.maxDist {
				t.Errorf("distance %d exceeds %d; this edit would evade duplicate detection", d, tc.maxDist)
			}
			if v := CompareImages(base, got); !v.NearDuplicate {
				t.Errorf("not flagged as a near-duplicate: %s", v.Explanation)
			}
		})
	}
}

// TestPerceptualHashSeparatesDifferentWorks guards the other direction. A hash
// that called everything a duplicate would bury the moderation queue and be
// worse than none.
func TestPerceptualHashSeparatesDifferentWorks(t *testing.T) {
	var hashes []uint64
	for seed := int64(1); seed <= 8; seed++ {
		hashes = append(hashes, hashImage(t, syntheticArtwork(400, 300, seed)))
	}
	for i := range hashes {
		for j := i + 1; j < len(hashes); j++ {
			if v := CompareImages(hashes[i], hashes[j]); v.NearDuplicate {
				t.Errorf("images %d and %d are unrelated but were flagged at distance %d", i, j, v.Distance)
			}
		}
	}
}

func TestPerceptualHashIsStableAndNeverZero(t *testing.T) {
	img := syntheticArtwork(256, 256, 42)
	first := hashImage(t, img)
	for i := 0; i < 5; i++ {
		if got := hashImage(t, img); got != first {
			t.Fatalf("hash is not deterministic: %016x then %016x", first, got)
		}
	}
	// Zero is the sentinel for "not computed". A real image must never collide
	// with it, or an unhashed asset would compare equal to a real one.
	if first == 0 {
		t.Fatal("a real image hashed to the zero sentinel")
	}
	for _, seed := range []int64{1, 2, 3, 99, 12345} {
		if h := hashImage(t, syntheticArtwork(64, 64, seed)); h == 0 {
			t.Fatalf("seed %d hashed to zero", seed)
		}
	}
}

func TestPerceptualHashDecodesRealContainers(t *testing.T) {
	img := syntheticArtwork(200, 200, 7)

	var pngBuf bytes.Buffer
	if err := png.Encode(&pngBuf, img); err != nil {
		t.Fatal(err)
	}
	var jpegBuf bytes.Buffer
	if err := jpeg.Encode(&jpegBuf, img, &jpeg.Options{Quality: 92}); err != nil {
		t.Fatal(err)
	}

	fromPNG, err := PerceptualHash(bytes.NewReader(pngBuf.Bytes()))
	if err != nil {
		t.Fatalf("PNG: %v", err)
	}
	fromJPEG, err := PerceptualHash(bytes.NewReader(jpegBuf.Bytes()))
	if err != nil {
		t.Fatalf("JPEG: %v", err)
	}
	if d := HammingDistance(fromPNG, fromJPEG); d > 6 {
		t.Errorf("the same image in two containers differs by %d bits", d)
	}
}

func TestPerceptualHashRejectsUnusableInput(t *testing.T) {
	if _, err := PerceptualHash(strings.NewReader("this is not an image")); err == nil {
		t.Error("non-image input was hashed")
	}
	if _, err := perceptualHashOf(image.NewRGBA(image.Rect(0, 0, 4, 4))); err != ErrImageTooSmall {
		t.Errorf("error = %v, want ErrImageTooSmall", err)
	}
}

// ---- SimHash ----------------------------------------------------------------

func TestSimHashSurvivesLightEditing(t *testing.T) {
	original := `The quick brown fox jumps over the lazy dog. Marketplace sellers
	deserve predictable economics and an explainable listing position. This
	paragraph exists so the fingerprint has enough tokens to be meaningful, and
	it continues for several more clauses to give the shingler something to work
	with across sentence boundaries.`

	base := simHashOf(t, original)

	for _, tc := range []struct {
		name  string
		edit  string
		close bool
	}{
		{"identical", original, true},
		{"reflowed whitespace", strings.Join(strings.Fields(original), " "), true},
		{"case changed", strings.ToUpper(original), true},
		{"punctuation stripped", strings.NewReplacer(".", "", ",", "").Replace(original), true},
		{"completely different work", strings.Repeat("entirely unrelated content about shipping containers and port logistics ", 8), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := simHashOf(t, tc.edit)
			v := CompareText(base, got)
			if v.NearDuplicate != tc.close {
				t.Errorf("nearDuplicate = %v at distance %d, want %v (%s)",
					v.NearDuplicate, v.Distance, tc.close, v.Explanation)
			}
		})
	}
}

func TestSimHashReportsNotComputedForTrivialInput(t *testing.T) {
	for _, s := range []string{"", "   ", "one", "one two"} {
		if h := simHashOf(t, s); h != 0 {
			t.Errorf("%q produced a fingerprint %016x; too little text must produce none", s, h)
		}
	}
	if v := CompareText(0, 12345); v.NearDuplicate || v.Distance != -1 {
		t.Error("comparing against a missing fingerprint must not produce a verdict")
	}
}

// ---- metadata ---------------------------------------------------------------

func TestGeneratorHintReadsRealMetadata(t *testing.T) {
	for _, tc := range []struct {
		name   string
		asset  []byte
		want   string
		wantAI bool
	}{
		{"PNG tEXt Software", pngWithText("Software", "Adobe Photoshop 26.0"), "Adobe Photoshop 26.0", false},
		{"PNG tEXt parameters", pngWithText("parameters", "masterpiece, Stable Diffusion XL"), "masterpiece, Stable Diffusion XL", true},
		{"PNG tEXt Creator", pngWithText("Creator", "Midjourney v6"), "Midjourney v6", true},
		{"XMP CreatorTool", xmpAsset("Affinity Designer 2"), "Affinity Designer 2", false},
		{"XMP naming a generator", xmpAsset("Adobe Firefly"), "Adobe Firefly", true},
		{"EXIF Software", jpegWithEXIFSoftware("Canon EOS R5"), "Canon EOS R5", false},
		{"no metadata at all", []byte("plain bytes with nothing embedded"), "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tool, ai := GeneratorHint(tc.asset)
			if tool != tc.want {
				t.Errorf("tool = %q, want %q", tool, tc.want)
			}
			if ai != tc.wantAI {
				t.Errorf("indicatesAI = %v, want %v", ai, tc.wantAI)
			}
		})
	}
}

// TestGeneratorHintSanitisesHostileValues: this string reaches a moderator's
// screen and a database column, and it came out of a stranger's file.
func TestGeneratorHintSanitisesHostileValues(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"control characters", "Tool\x00\x01\x02Name"},
		{"bidi override", "Tool\u202egnpX"},
		{"byte-order mark", "\ufeffTool"},
		{"very long", strings.Repeat("A", 5000)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := GeneratorHint(pngWithText("Software", tc.value))
			if len(got) > maxHintLen {
				t.Errorf("value was not bounded: %d characters", len(got))
			}
			for _, r := range got {
				if r < 0x20 && r != '\t' {
					t.Errorf("control character %U survived sanitisation", r)
				}
				if r == 0xfeff || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
					t.Errorf("bidirectional control %U survived sanitisation", r)
				}
			}
		})
	}
}

func TestDetectSourceProjects(t *testing.T) {
	present, kinds := DetectSourceProjects([]string{
		"final.png", "preview.jpg", "artwork.psd", "scene.blend", "notes.txt",
	})
	if !present {
		t.Fatal("source projects were present but not detected")
	}
	if len(kinds) != 2 {
		t.Errorf("kinds = %v, want the Photoshop document and the Blender scene", kinds)
	}
	if present, _ := DetectSourceProjects([]string{"final.png", "readme.txt"}); present {
		t.Error("a delivery with no project files reported source projects")
	}
}

// ---- assessment -------------------------------------------------------------

// TestAssessNeverRejects is the property ADR 0010 turns on. Nothing in this
// package may produce a decision that keeps a listing off the marketplace
// without a person having looked at it.
func TestAssessNeverRejects(t *testing.T) {
	disclosures := []Disclosure{Undeclared, NoAI, AIAssisted, AIGenerated, AIGeneratedEdited}
	rng := rand.New(rand.NewSource(7))

	for i := 0; i < 20000; i++ {
		s := Signals{
			C2PAPresent:              rng.Intn(2) == 0,
			C2PAIntact:               rng.Intn(2) == 0,
			C2PABindingValid:         rng.Intn(2) == 0,
			GeneratorHintIndicatesAI: rng.Intn(2) == 0,
			HasSourceProject:         rng.Intn(2) == 0,
		}
		if s.GeneratorHintIndicatesAI || rng.Intn(3) == 0 {
			s.GeneratorHint = "Some Tool"
		}
		a := Assess(disclosures[rng.Intn(len(disclosures))], s)

		switch a.Routing {
		case RoutePublish, RouteReview, RoutePriorityReview:
		default:
			t.Fatalf("routing %q is not one of the three permitted outcomes", a.Routing)
		}
		if a.Score < 0 || a.Score > 100 {
			t.Fatalf("score %d is outside 0..100", a.Score)
		}
		if len(a.Reasons) == 0 {
			t.Fatal("an assessment with no stated reason is not explainable")
		}
	}
}

// TestAssessRoutesConflictsToAPersonRegardlessOfScore: the score is a sort
// order for a queue, never an override on "the seller and the bytes disagree".
func TestAssessRoutesConflictsToAPersonRegardlessOfScore(t *testing.T) {
	// Every positive signal available, plus one conflict.
	a := Assess(NoAI, Signals{
		C2PAPresent: true, C2PAIntact: true, C2PABindingValid: true,
		HasSourceProject: true, SourceProjectKinds: []string{"Photoshop document"},
		GeneratorHint: "Midjourney v6", GeneratorHintIndicatesAI: true,
	})
	if a.Routing != RoutePriorityReview {
		t.Fatalf("routing = %q, want priority review: the seller declared no AI and the metadata says otherwise", a.Routing)
	}
	if len(a.Conflicts) == 0 {
		t.Fatal("the disagreement was not recorded as a conflict")
	}
	if !strings.Contains(a.Reasons[0], "Midjourney") {
		t.Errorf("the decisive reason is not stated first: %q", a.Reasons[0])
	}
}

func TestAssessTreatsAbsenceOfSignalsAsNeutral(t *testing.T) {
	// The common case: an honest seller whose tools emit nothing.
	a := Assess(NoAI, Signals{})
	if a.Score < 40 || a.Score > 60 {
		t.Errorf("score = %d; an asset with no signals must sit near neutral, not be punished", a.Score)
	}
	if len(a.Conflicts) != 0 {
		t.Errorf("absence of evidence was recorded as a conflict: %v", a.Conflicts)
	}
	if a.Routing == RoutePriorityReview {
		t.Error("an ordinary asset with no metadata was escalated")
	}
}

func TestAssessRewardsCorroboratedProcess(t *testing.T) {
	strong := Assess(NoAI, Signals{
		C2PAPresent: true, C2PAIntact: true, C2PABindingValid: true, C2PAIssuer: "Leica Camera AG",
		HasSourceProject: true, SourceProjectKinds: []string{"Photoshop document"},
		GeneratorHint: "Adobe Photoshop 26.0",
	})
	if strong.Routing != RoutePublish {
		t.Errorf("routing = %q, want publish for a well-corroborated asset", strong.Routing)
	}
	if strong.Score <= Assess(NoAI, Signals{}).Score {
		t.Error("corroborating evidence did not raise the score")
	}
	joined := strings.Join(strong.Reasons, " ")
	if !strings.Contains(joined, "Leica Camera AG") {
		t.Error("the signer is not named in the reasons")
	}
	if !strings.Contains(joined, "separate question") {
		t.Error("the reasons claim the signer is trustworthy; that is not what was checked")
	}
}

func TestAssessPenalisesABrokenManifest(t *testing.T) {
	broken := Assess(NoAI, Signals{C2PAPresent: true})
	absent := Assess(NoAI, Signals{})
	if broken.Score >= absent.Score {
		t.Error("a manifest that does not verify must score below no manifest at all: " +
			"an unaltered file would not carry a broken one")
	}
}

func TestUndeclaredAlwaysReachesAPerson(t *testing.T) {
	a := Assess(Undeclared, Signals{
		C2PAPresent: true, C2PAIntact: true, C2PABindingValid: true, HasSourceProject: true,
	})
	if a.Routing == RoutePublish {
		t.Fatal("an undeclared product was routed to publish; the database would refuse it anyway")
	}
}

// ---- helpers ----------------------------------------------------------------

func hashImage(t *testing.T, img image.Image) uint64 {
	t.Helper()
	h, err := perceptualHashOf(img)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func simHashOf(t *testing.T, s string) uint64 {
	t.Helper()
	h, err := SimHash(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// syntheticArtwork builds an image with real low-frequency structure, which is
// what a perceptual hash actually keys on. Random noise would be wrong: it has
// no structure to survive a resize, so it would make the test meaningless.
func syntheticArtwork(w, h int, seed int64) image.Image {
	rng := rand.New(rand.NewSource(seed))
	img := image.NewRGBA(image.Rect(0, 0, w, h))

	// A handful of smooth gradients at seed-dependent frequencies and phases.
	fx1, fy1 := 1+rng.Float64()*3, 1+rng.Float64()*3
	fx2, fy2 := 2+rng.Float64()*5, 2+rng.Float64()*5
	px, py := rng.Float64()*math.Pi, rng.Float64()*math.Pi

	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			u, v := float64(x)/float64(w), float64(y)/float64(h)
			value := 0.5 +
				0.25*math.Sin(2*math.Pi*fx1*u+px)*math.Cos(2*math.Pi*fy1*v) +
				0.15*math.Cos(2*math.Pi*fx2*u)*math.Sin(2*math.Pi*fy2*v+py)
			c := uint8(clampFloat(value, 0, 1) * 255)
			img.Set(x, y, color.RGBA{R: c, G: uint8(255 - int(c)/2), B: c / 2, A: 255})
		}
	}
	return img
}

func clampFloat(v, lo, hi float64) float64 { return math.Max(lo, math.Min(hi, v)) }

func reencodeJPEG(t *testing.T, img image.Image, quality int) image.Image {
	t.Helper()
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: quality}); err != nil {
		t.Fatal(err)
	}
	out, err := jpeg.Decode(&buf)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func resize(src image.Image, w, h int) image.Image {
	b := src.Bounds()
	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			sx := b.Min.X + x*b.Dx()/w
			sy := b.Min.Y + y*b.Dy()/h
			dst.Set(x, y, src.At(sx, sy))
		}
	}
	return dst
}

func adjustBrightness(src image.Image, factor float64) image.Image {
	b := src.Bounds()
	dst := image.NewRGBA(b)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, bl, a := src.At(x, y).RGBA()
			dst.Set(x, y, color.RGBA{
				R: scale8(r, factor), G: scale8(g, factor), B: scale8(bl, factor), A: uint8(a >> 8),
			})
		}
	}
	return dst
}

func scale8(v uint32, factor float64) uint8 {
	return uint8(clampFloat(float64(v>>8)*factor, 0, 255))
}

func watermark(src image.Image) image.Image {
	b := src.Bounds()
	dst := image.NewRGBA(b)
	draw.Draw(dst, b, src, b.Min, draw.Src)
	band := image.Rect(b.Min.X, b.Min.Y+b.Dy()*2/5, b.Max.X, b.Min.Y+b.Dy()*3/5)
	draw.Draw(dst, band, &image.Uniform{color.RGBA{255, 255, 255, 110}}, image.Point{}, draw.Over)
	return dst
}

func pngWithText(key, value string) []byte {
	var b bytes.Buffer
	b.Write([]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A})
	data := append([]byte(key), 0)
	data = append(data, value...)
	b.Write(pngChunk("tEXt", data))
	b.Write(pngChunk("IEND", nil))
	return b.Bytes()
}

func xmpAsset(tool string) []byte {
	return []byte(`<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>` +
		`<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF><rdf:Description>` +
		`<xmp:CreatorTool>` + tool + `</xmp:CreatorTool>` +
		`</rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>`)
}

// jpegWithEXIFSoftware builds a real APP1/EXIF segment with a Software tag.
func jpegWithEXIFSoftware(software string) []byte {
	value := append([]byte(software), 0)

	// TIFF header, one IFD entry, then the value.
	const headerLen, entryOffset = 8, 10 // 8-byte header + 2-byte entry count
	valueOffset := entryOffset + 12 + 4  // entry, then the next-IFD pointer

	tiff := make([]byte, valueOffset+len(value))
	copy(tiff, "MM\x00\x2a")
	binary.BigEndian.PutUint32(tiff[4:8], headerLen)
	binary.BigEndian.PutUint16(tiff[8:10], 1) // one entry

	e := tiff[entryOffset:]
	binary.BigEndian.PutUint16(e[0:2], 0x0131) // Software
	binary.BigEndian.PutUint16(e[2:4], 2)      // ASCII
	binary.BigEndian.PutUint32(e[4:8], uint32(len(value)))
	binary.BigEndian.PutUint32(e[8:12], uint32(valueOffset))
	copy(tiff[valueOffset:], value)

	body := append([]byte("Exif\x00\x00"), tiff...)
	var b bytes.Buffer
	b.Write([]byte{0xFF, 0xD8, 0xFF, 0xE1})
	_ = binary.Write(&b, binary.BigEndian, uint16(len(body)+2))
	b.Write(body)
	b.Write([]byte{0xFF, 0xD9})
	return b.Bytes()
}
