package provenance

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"
)

// These tests build real C2PA manifests: real CBOR, a real COSE_Sign1 over a
// correctly-reconstructed Sig_structure, signed by a real key, wrapped in real
// JUMBF boxes inside a real JPEG or PNG container.
//
// Nothing is mocked, because the only thing worth testing here is whether the
// parser and the verifier agree with the specification. A test that fed the
// verifier something the test itself invented would prove they agree with each
// other and nothing else.

func TestC2PAVerifiesAnIntactManifest(t *testing.T) {
	key, cert := testSigningCert(t, "Studio Camera CA", false)
	asset := jpegWithManifest(t, buildManifest(t, key, cert, manifestOpts{
		generator: "TestCam 2.1", bindTo: nil,
	}))

	res := ExtractC2PA(asset)
	if !res.Present {
		t.Fatalf("no manifest was found; notes: %v", res.Notes)
	}
	if !res.Intact {
		t.Fatalf("a correctly signed manifest did not verify; notes: %v", res.Notes)
	}
	if res.Issuer != "Studio Camera CA" {
		t.Errorf("issuer = %q, want the certificate subject", res.Issuer)
	}
	if res.Generator != "TestCam 2.1" {
		t.Errorf("generator = %q, want TestCam 2.1", res.Generator)
	}
	if res.SignatureAlg != "ES256" {
		t.Errorf("algorithm = %q, want ES256", res.SignatureAlg)
	}
}

// TestC2PADetectsTamperedManifest is the property the whole COSE
// implementation exists for. A manifest edited after signing must not verify.
func TestC2PADetectsTamperedManifest(t *testing.T) {
	key, cert := testSigningCert(t, "Studio Camera CA", false)
	manifest := buildManifest(t, key, cert, manifestOpts{generator: "TestCam 2.1"})

	// Flip the generator string inside the signed payload. Same length, so
	// every offset and box size stays valid — only the bytes differ.
	tampered := bytes.Replace(manifest, []byte("TestCam 2.1"), []byte("TestCam 9.9"), 1)
	if bytes.Equal(tampered, manifest) {
		t.Fatal("the test failed to tamper with anything")
	}

	res := ExtractC2PA(jpegWithManifest(t, tampered))
	if !res.Present {
		t.Fatal("the tampered manifest should still be found, just not trusted")
	}
	if res.Intact {
		t.Fatal("a manifest altered after signing verified; the signature is not being checked")
	}
	if len(res.Notes) == 0 {
		t.Error("a failed verification must explain itself")
	}
}

// TestC2PADetectsSignatureSubstitution covers the other half: swapping in a
// signature made by a different key must fail even though that signature is
// itself perfectly valid.
func TestC2PADetectsTamperedSignedPayload(t *testing.T) {
	key, cert := testSigningCert(t, "Studio Camera CA", false)
	manifest := buildManifest(t, key, cert, manifestOpts{generator: "TestCam 2.1"})

	// Change the generator in EVERY copy, including the one the signature
	// covers. This is the case the COSE verification itself has to catch — the
	// stored-versus-signed comparison cannot, because both copies agree.
	tampered := bytes.ReplaceAll(manifest, []byte("TestCam 2.1"), []byte("TestCam 9.9"))
	if bytes.Count(manifest, []byte("TestCam 2.1")) < 2 {
		t.Fatal("the manifest does not carry the claim twice; this test would not exercise the signature")
	}

	res := ExtractC2PA(jpegWithManifest(t, tampered))
	if !res.Present {
		t.Fatal("the tampered manifest should still be found, just not trusted")
	}
	if res.Intact {
		t.Fatal("a signed payload altered after signing verified; the COSE signature is not being checked")
	}
	if res.Generator == "TestCam 9.9" {
		t.Error("a value from an unverified payload was reported as a finding")
	}
}

// TestC2PARefusesClaimSubstitution pins a real flaw this suite caught: reading
// the generator and the assertions from a separately-stored claim box, rather
// than from the bytes the signature covers.
//
// An attacker who could do that would pair a genuine signature over a harmless
// claim with a completely different claim beside it, and every signature check
// would still pass while the platform reported the attacker's values.
func TestC2PARefusesClaimSubstitution(t *testing.T) {
	key, cert := testSigningCert(t, "Studio Camera CA", false)
	manifest := buildManifest(t, key, cert, manifestOpts{generator: "TestCam 2.1"})

	// Rewrite only the stored claim, leaving the signed payload untouched.
	first := bytes.Index(manifest, []byte("TestCam 2.1"))
	if first < 0 {
		t.Fatal("generator not found in the manifest")
	}
	substituted := append([]byte(nil), manifest...)
	copy(substituted[first:], []byte("Adobe Fire"))
	copy(substituted[first+10:], []byte("fy")) // same length, so all box sizes stay valid

	res := ExtractC2PA(jpegWithManifest(t, substituted))
	if res.Intact {
		t.Fatal("a manifest whose stored claim differs from the signed claim was accepted as intact")
	}
	if res.Generator != "" {
		t.Errorf("generator = %q; nothing may be reported from a manifest that failed verification", res.Generator)
	}
}

func TestC2PADetectsSignatureSubstitution(t *testing.T) {
	genuine, cert := testSigningCert(t, "Genuine Signer", false)
	attacker, attackerCert := testSigningCert(t, "Attacker", false)

	good := buildManifest(t, genuine, cert, manifestOpts{generator: "TestCam 2.1"})
	// The attacker signs their own claim correctly, then presents the genuine
	// certificate with it.
	forged := buildManifest(t, attacker, cert, manifestOpts{generator: "TestCam 2.1"})
	_ = attackerCert

	if bytes.Equal(good, forged) {
		t.Fatal("the two manifests are identical; the test proves nothing")
	}
	res := ExtractC2PA(jpegWithManifest(t, forged))
	if res.Intact {
		t.Fatal("a signature made by a different key verified against the presented certificate")
	}
}

func TestC2PAVerifiesHardBinding(t *testing.T) {
	key, cert := testSigningCert(t, "Studio Camera CA", false)

	// Build the asset first with a placeholder manifest so the excluded byte
	// range is known, then bind the manifest to what remains — which is what a
	// real producer does.
	placeholder := buildManifest(t, key, cert, manifestOpts{generator: "TestCam 2.1"})
	scaffold := jpegWithManifest(t, placeholder)
	_, exclusions, err := findManifestStore(scaffold)
	if err != nil {
		t.Fatal(err)
	}
	bound := sha256.Sum256(excludeRanges(scaffold, exclusions))

	real := buildManifest(t, key, cert, manifestOpts{generator: "TestCam 2.1", bindTo: bound[:]})
	if len(real) != len(placeholder) {
		t.Fatalf("manifest length changed (%d vs %d); the exclusion range would shift",
			len(real), len(placeholder))
	}
	asset := jpegWithManifest(t, real)

	res := ExtractC2PA(asset)
	if !res.Intact {
		t.Fatalf("the manifest did not verify; notes: %v", res.Notes)
	}
	if !res.BindingValid {
		t.Fatalf("the hard binding did not match its own asset; notes: %v", res.Notes)
	}

	// Now change a pixel. The manifest is untouched and still verifies, but it
	// no longer describes this file — which is exactly the case a signature
	// check alone would miss.
	altered := append([]byte(nil), asset...)
	altered[len(altered)-3] ^= 0xFF
	res2 := ExtractC2PA(altered)
	if !res2.Intact {
		t.Error("altering the image should not invalidate the manifest's own signature")
	}
	if res2.BindingValid {
		t.Fatal("a manifest copied onto different bytes passed the binding check")
	}
}

func TestC2PAWorksInPNGAndBMFF(t *testing.T) {
	key, cert := testSigningCert(t, "Studio Camera CA", false)
	manifest := buildManifest(t, key, cert, manifestOpts{generator: "TestCam 2.1"})

	for _, tc := range []struct {
		name  string
		asset []byte
	}{
		{"PNG caBX chunk", pngWithManifest(t, manifest)},
		{"BMFF uuid box", bmffWithManifest(t, manifest)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := ExtractC2PA(tc.asset)
			if !res.Present {
				t.Fatalf("no manifest found; notes: %v", res.Notes)
			}
			if !res.Intact {
				t.Fatalf("manifest did not verify; notes: %v", res.Notes)
			}
		})
	}
}

func TestC2PAVerifiesRSASignatures(t *testing.T) {
	key, cert := testSigningCert(t, "RSA Signer", true)
	asset := jpegWithManifest(t, buildManifest(t, key, cert, manifestOpts{
		generator: "RSATool 1.0", rsa: true,
	}))

	res := ExtractC2PA(asset)
	if !res.Intact {
		t.Fatalf("an RSA-signed manifest did not verify; notes: %v", res.Notes)
	}
	if res.SignatureAlg != "PS256" {
		t.Errorf("algorithm = %q, want PS256", res.SignatureAlg)
	}
}

func TestC2PAAbsenceIsNotAFinding(t *testing.T) {
	// A perfectly ordinary JPEG with no Content Credentials at all.
	res := ExtractC2PA(jpegWithManifest(t, nil))
	if res.Present || res.Intact || res.BindingValid {
		t.Fatalf("a file with no manifest reported %+v", res)
	}
	if len(res.Notes) != 0 {
		t.Errorf("absence generated notes %v; most honest tools emit no manifest and that is not a finding", res.Notes)
	}
}

// TestC2PASurvivesHostileInput is the property that matters for a parser fed
// attacker-controlled bytes: it may reject anything, but it must not panic,
// hang, or allocate without bound.
func TestC2PASurvivesHostileInput(t *testing.T) {
	cases := map[string][]byte{
		"empty":                      {},
		"JPEG marker only":           {0xFF, 0xD8, 0xFF},
		"PNG signature only":         {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A},
		"APP11 with no payload":      {0xFF, 0xD8, 0xFF, 0xEB, 0x00, 0x02},
		"segment length overruns":    {0xFF, 0xD8, 0xFF, 0xEB, 0xFF, 0xFF, 'J', 'P'},
		"PNG chunk length overruns":  append([]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}, 0x7F, 0xFF, 0xFF, 0xFF, 'c', 'a', 'B', 'X'),
		"CBOR array claims 2^32":     jpegWithManifest(t, []byte{0x9A, 0xFF, 0xFF, 0xFF, 0xFF}),
		"CBOR map claims 2^64":       jpegWithManifest(t, []byte{0xBB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}),
		"CBOR bytes claim 2^32":      jpegWithManifest(t, []byte{0x5A, 0xFF, 0xFF, 0xFF, 0xFF}),
		"deeply nested CBOR arrays":  jpegWithManifest(t, bytes.Repeat([]byte{0x81}, 5000)),
		"JUMBF box of size zero":     jpegWithManifest(t, []byte{0, 0, 0, 0, 'j', 'u', 'm', 'b'}),
		"JUMBF box larger than data": jpegWithManifest(t, []byte{0xFF, 0xFF, 0xFF, 0xFF, 'j', 'u', 'm', 'b'}),
	}

	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			done := make(chan C2PAResult, 1)
			go func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("panic on hostile input: %v", r)
						done <- C2PAResult{}
					}
				}()
				done <- ExtractC2PA(input)
			}()
			select {
			case res := <-done:
				if res.Intact || res.BindingValid {
					t.Fatalf("hostile input produced a positive verdict: %+v", res)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("parsing did not terminate")
			}
		})
	}
}

func TestCBORRejectsMalformedInput(t *testing.T) {
	for name, in := range map[string][]byte{
		"empty":                  {},
		"truncated uint64":       {0x1B, 0, 0},
		"byte string overruns":   {0x58, 0xFF, 'a'},
		"array element missing":  {0x82, 0x01},
		"map value missing":      {0xA1, 0x01},
		"indefinite length":      {0x9F, 0x01, 0xFF},
		"reserved additional 28": {0x1C},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := decodeCBOR(in); err == nil {
				t.Fatal("malformed CBOR was accepted")
			}
		})
	}
}

func TestCBORRoundTripsTheShapesCOSEUses(t *testing.T) {
	// A COSE protected header: {1: -7, 33: h'...'}
	encoded := append(encodeCBORHead(5, 2),
		append([]byte{0x01, 0x26, 0x18, 0x21}, encodeCBORBytes([]byte{0xDE, 0xAD})...)...)

	v, n, err := decodeCBOR(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if n != len(encoded) {
		t.Errorf("consumed %d of %d bytes", n, len(encoded))
	}
	alg, ok := v.lookup(coseHeaderAlg)
	if !ok {
		t.Fatal("algorithm header not found")
	}
	if got, _ := alg.asInt(); got != -7 {
		t.Errorf("alg = %d, want -7", got)
	}
	chain, ok := v.lookup(coseHeaderX5Chain)
	if !ok {
		t.Fatal("x5chain header not found")
	}
	if der, _ := chain.asBytes(); !bytes.Equal(der, []byte{0xDE, 0xAD}) {
		t.Errorf("x5chain = %x", der)
	}
}

// ---- builders ---------------------------------------------------------------

type manifestOpts struct {
	generator string
	bindTo    []byte
	rsa       bool
}

// buildManifest produces a JUMBF-wrapped, COSE_Sign1-signed C2PA manifest
// store, constructed the way the specification says rather than the way the
// parser happens to read.
func buildManifest(t *testing.T, key any, cert *x509.Certificate, opts manifestOpts) []byte {
	t.Helper()

	binding := opts.bindTo
	if binding == nil {
		binding = make([]byte, sha256.Size) // fixed length, so manifest size is stable
	}

	// assertions: [ { "url": "self#jumbf=c2pa.assertions/c2pa.hash.data", "hash": h'…' } ]
	assertion := append(encodeCBORHead(5, 2),
		append(
			append(encodeCBORText("url"), encodeCBORText("self#jumbf=c2pa.assertions/c2pa.hash.data")...),
			append(encodeCBORText("hash"), encodeCBORBytes(binding)...)...,
		)...)
	assertions := append(encodeCBORHead(4, 1), assertion...)

	// claim: { "claim_generator": "...", "assertions": [...] }
	claim := append(encodeCBORHead(5, 2),
		append(
			append(encodeCBORText("claim_generator"), encodeCBORText(opts.generator)...),
			append(encodeCBORText("assertions"), assertions...)...,
		)...)

	sig := signCOSE(t, key, cert, claim, opts.rsa)

	// manifest store: { "c2pa.claim": <claim>, "c2pa.signature": <cose> }
	store := append(encodeCBORHead(5, 2),
		append(
			append(encodeCBORText("c2pa.claim"), claim...),
			append(encodeCBORText("c2pa.signature"), encodeCBORBytes(sig)...)...,
		)...)

	return wrapJUMBF(store)
}

// signCOSE builds a COSE_Sign1 over the correct Sig_structure.
func signCOSE(t *testing.T, key any, cert *x509.Certificate, payload []byte, useRSA bool) []byte {
	t.Helper()

	algID := int64(-7) // ES256
	if useRSA {
		algID = -37 // PS256
	}
	// protected: { 1: <alg>, 33: <cert DER> }
	protected := append(encodeCBORHead(5, 2),
		append(
			append(encodeCBORHead(0, coseHeaderAlg), encodeCBORHead(1, uint64(-1-algID))...),
			append(encodeCBORHead(0, coseHeaderX5Chain), encodeCBORBytes(cert.Raw)...)...,
		)...)

	sigStructure := encodeCBORArray(
		encodeCBORText("Signature1"),
		encodeCBORBytes(protected),
		encodeCBORBytes(nil),
		encodeCBORBytes(payload),
	)

	var signature []byte
	digest := sha256.Sum256(sigStructure)
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, k, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		signature = append(padTo(r, 32), padTo(s, 32)...)
	case *rsa.PrivateKey:
		var err error
		signature, err = rsa.SignPSS(rand.Reader, k, 5 /* crypto.SHA256 */, digest[:],
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unsupported key type %T", key)
	}

	return encodeCBORArray(
		encodeCBORBytes(protected),
		encodeCBORHead(5, 0), // empty unprotected header map
		encodeCBORBytes(payload),
		encodeCBORBytes(signature),
	)
}

func padTo(v *big.Int, size int) []byte {
	b := v.Bytes()
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

func testSigningCert(t *testing.T, cn string, useRSA bool) (any, *x509.Certificate) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	var key any
	var pub any
	if useRSA {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		key, pub = k, &k.PublicKey
	} else {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key, pub = k, &k.PublicKey
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

// wrapJUMBF puts a CBOR payload inside the jumb/jumd/cbor box structure.
func wrapJUMBF(payload []byte) []byte {
	cbor := jumbfBox("cbor", payload)
	desc := jumbfBox("jumd", []byte("c2pa.manifest\x00"))
	return jumbfBox("jumb", append(desc, cbor...))
}

func jumbfBox(boxType string, content []byte) []byte {
	b := make([]byte, 8, 8+len(content))
	binary.BigEndian.PutUint32(b[:4], uint32(8+len(content)))
	copy(b[4:8], boxType)
	return append(b, content...)
}

// jpegWithManifest builds a minimal but structurally valid JPEG, embedding the
// manifest in APP11 segments the way the specification requires.
func jpegWithManifest(t *testing.T, manifest []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	b.Write([]byte{0xFF, 0xD8}) // SOI

	if len(manifest) > 0 {
		// APP11 body: "JP", 2-byte box instance, 4-byte packet sequence, payload.
		body := append([]byte("JP"), 0x00, 0x01, 0x00, 0x00, 0x00, 0x01)
		body = append(body, manifest...)
		if len(body)+2 > 0xFFFF {
			t.Fatalf("test manifest too large for one APP11 segment (%d bytes)", len(body))
		}
		b.Write([]byte{0xFF, 0xEB})
		_ = binary.Write(&b, binary.BigEndian, uint16(len(body)+2))
		b.Write(body)
	}

	// A minimal comment segment and an end-of-image, so the file has content
	// outside the manifest for the hard binding to cover.
	comment := []byte("test asset bytes")
	b.Write([]byte{0xFF, 0xFE})
	_ = binary.Write(&b, binary.BigEndian, uint16(len(comment)+2))
	b.Write(comment)
	b.Write([]byte{0xFF, 0xD9}) // EOI
	return b.Bytes()
}

func pngWithManifest(t *testing.T, manifest []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	b.Write([]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A})
	b.Write(pngChunk("caBX", manifest))
	b.Write(pngChunk("IEND", nil))
	return b.Bytes()
}

func pngChunk(chunkType string, data []byte) []byte {
	b := make([]byte, 0, 12+len(data))
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(data)))
	b = append(b, length[:]...)
	b = append(b, chunkType...)
	b = append(b, data...)
	return append(b, 0, 0, 0, 0) // CRC, not checked by the extractor
}

func bmffWithManifest(t *testing.T, manifest []byte) []byte {
	t.Helper()
	var b bytes.Buffer

	ftypBox := append([]byte("ftyp"), "isom"...)
	_ = binary.Write(&b, binary.BigEndian, uint32(4+len(ftypBox)))
	b.Write(ftypBox)

	uuid := []byte{
		0xD8, 0xFE, 0xC3, 0xD6, 0x1B, 0x0E, 0x48, 0x3C,
		0x92, 0x97, 0x58, 0x28, 0x87, 0x7E, 0xC4, 0x81,
	}
	size := 8 + len(uuid) + len(manifest)
	_ = binary.Write(&b, binary.BigEndian, uint32(size))
	b.Write([]byte("uuid"))
	b.Write(uuid)
	b.Write(manifest)
	return b.Bytes()
}
