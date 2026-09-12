package provenance

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// C2PA reads Content Credentials out of an asset and checks what can honestly
// be checked without a trust list.
//
// Three separate questions get three separate answers, and conflating them is
// how a provenance feature becomes a lie:
//
//  1. **Is a manifest present?** Parsing alone. Its absence means nothing —
//     almost no honest tool emits one today.
//  2. **Is the manifest intact?** The COSE_Sign1 signature verifies against the
//     certificate embedded in the manifest itself. This proves nobody edited
//     the manifest after it was signed. It does NOT prove the signer is
//     anyone in particular: a self-signed manifest passes this.
//  3. **Does it describe THIS asset?** The hard binding hashes the asset's own
//     bytes. Without this check, a valid manifest could simply be copied from
//     a genuine file onto a forged one.
//
// Establishing that the signer is trustworthy needs the C2PA trust list and is
// deliberately out of scope here: C2PAIssuer is recorded so that check can be
// made by a policy that owns the list, rather than guessed at by this parser.

// C2PAResult is what was found.
type C2PAResult struct {
	Present      bool
	Intact       bool
	BindingValid bool
	Issuer       string
	Generator    string
	SignatureAlg string
	// Notes records what could not be checked and why. A check that did not run
	// is never reported as a check that passed.
	Notes []string
}

// c2pa box labels from the C2PA specification.
const (
	jumbfBoxType    = "jumb"
	jumbfDescType   = "jumd"
	jumbfContentBox = "cbor"
)

// ExtractC2PA finds and evaluates a Content Credentials manifest.
//
// asset is the complete file. It is needed in full because the hard binding is
// computed over the asset's own bytes with the manifest region excluded.
func ExtractC2PA(asset []byte) C2PAResult {
	var res C2PAResult

	store, exclusions, err := findManifestStore(asset)
	if err != nil || len(store) == 0 {
		return res
	}
	res.Present = true

	manifest, err := decodeCBORStrict(store)
	if err != nil {
		res.Notes = append(res.Notes,
			"a Content Credentials manifest is present but could not be parsed: "+err.Error())
		return res
	}

	storedClaim, sig := locateClaimAndSignature(manifest)
	if sig == nil {
		res.Notes = append(res.Notes,
			"the manifest carries no claim signature, so nothing about it can be verified")
		return res
	}

	verified, signedPayload, issuer, alg, err := verifyCOSESign1(*sig)
	res.Issuer, res.SignatureAlg = issuer, alg
	switch {
	case err != nil:
		res.Notes = append(res.Notes, "the claim signature could not be verified: "+err.Error())
		return res
	case !verified:
		res.Notes = append(res.Notes,
			"the claim signature does not verify against the certificate inside the manifest, "+
				"which means the manifest was altered after signing")
		return res
	}
	res.Intact = true

	// Everything read from here on comes from the payload the signature
	// actually covers.
	//
	// Reading the generator or the assertions from a separately-stored claim
	// box would defeat the entire verification: an attacker could pair a
	// genuine signature over one claim with a completely different claim
	// alongside it, and every check above would still pass. The signed bytes
	// are the only bytes that mean anything.
	claim, err := decodeCBORStrict(signedPayload)
	if err != nil {
		res.Intact = false
		res.Notes = append(res.Notes, "the signed claim could not be parsed: "+err.Error())
		return res
	}

	// A manifest that also stores the claim separately must store the same
	// claim. A disagreement is an attempt to have the signature vouch for
	// something it never saw.
	if storedClaim != nil && !sameClaim(*storedClaim, claim) {
		res.Intact = false
		res.Notes = append(res.Notes,
			"the manifest's stored claim differs from the claim the signature covers, "+
				"so the signature vouches for something other than what this manifest asserts")
		return res
	}

	if gen, ok := claim.lookupText("claim_generator"); ok {
		res.Generator, _ = gen.asText()
	} else if gen, ok := claim.lookupText("claim_generator_info"); ok && gen.kind == cborArray && len(gen.array) > 0 {
		if name, ok := gen.array[0].lookupText("name"); ok {
			res.Generator, _ = name.asText()
		}
	}

	res.BindingValid = verifyHardBinding(claim, asset, exclusions, &res)
	return res
}

// sameClaim compares two decoded claims on the fields that carry meaning.
//
// Comparing decoded values rather than raw bytes, because two encoders may
// legitimately order a map differently while asserting exactly the same thing;
// a byte comparison would reject honest producers.
func sameClaim(a, b cborValue) bool {
	if a.kind != b.kind {
		return false
	}
	switch a.kind {
	case cborMap:
		if len(a.mapKeys) != len(b.mapKeys) {
			return false
		}
		for i, k := range a.mapKeys {
			name, ok := k.asText()
			if !ok {
				// Non-text keys are compared positionally, which is strict but
				// correct: C2PA claims are text-keyed.
				if !sameClaim(k, b.mapKeys[i]) || !sameClaim(a.mapVals[i], b.mapVals[i]) {
					return false
				}
				continue
			}
			other, found := b.lookupText(name)
			if !found || !sameClaim(a.mapVals[i], other) {
				return false
			}
		}
		return true
	case cborArray:
		if len(a.array) != len(b.array) {
			return false
		}
		for i := range a.array {
			if !sameClaim(a.array[i], b.array[i]) {
				return false
			}
		}
		return true
	case cborBytes:
		return bytes.Equal(a.bytes, b.bytes)
	case cborText:
		return a.text == b.text
	case cborUint:
		return a.uint == b.uint
	case cborNegInt:
		return a.neg == b.neg
	case cborBool:
		return a.boolean == b.boolean
	case cborFloat:
		return a.float == b.float
	case cborTag:
		return a.tag == b.tag && a.tagged != nil && b.tagged != nil && sameClaim(*a.tagged, *b.tagged)
	}
	return true // null and undefined carry no payload to disagree about
}

// decodeCBORStrict decodes exactly one item and refuses trailing bytes, since
// trailing data after a manifest is a smuggling attempt rather than a format.
func decodeCBORStrict(b []byte) (cborValue, error) {
	v, n, err := decodeCBOR(b)
	if err != nil {
		return cborValue{}, err
	}
	if n != len(b) {
		// Trailing padding inside a JUMBF box is common and benign; trailing
		// *structure* is not. Accept the item, note the remainder.
		if !allZero(b[n:]) {
			return v, fmt.Errorf("%d bytes of unexpected data follow the manifest", len(b)-n)
		}
	}
	return v, nil
}

// locateClaimAndSignature walks the manifest store for the active manifest's
// claim and its claim_signature.
func locateClaimAndSignature(m cborValue) (claim, sig *cborValue) {
	var walk func(v cborValue, depth int)
	walk = func(v cborValue, depth int) {
		if depth > maxCBORNesting || (claim != nil && sig != nil) {
			return
		}
		switch v.kind {
		case cborMap:
			for i, k := range v.mapKeys {
				name, _ := k.asText()
				val := v.mapVals[i]
				switch {
				case strings.HasSuffix(name, "c2pa.claim") || name == "claim":
					c := val
					claim = &c
				case strings.HasSuffix(name, "c2pa.signature") || name == "claim_signature" || name == "signature":
					s := val
					sig = &s
				}
				walk(val, depth+1)
			}
		case cborArray:
			for _, it := range v.array {
				walk(it, depth+1)
			}
		case cborTag:
			if v.tagged != nil {
				walk(*v.tagged, depth+1)
			}
		}
	}
	walk(m, 0)
	return claim, sig
}

// ---- COSE_Sign1 -------------------------------------------------------------

// COSE header labels, from RFC 9052 and the COSE IANA registry.
const (
	coseHeaderAlg     = 1
	coseHeaderX5Chain = 33
)

// verifyCOSESign1 checks a COSE_Sign1 against the certificate it carries.
//
// The signature is computed over a Sig_structure, NOT over the payload
// directly:
//
//	Sig_structure = [ "Signature1", protected, external_aad, payload ]
//
// Reconstructing it exactly is the whole job. A verifier that signs the payload
// alone would accept a message whose protected headers — including the
// algorithm — had been swapped, which is the classic COSE downgrade.
func verifyCOSESign1(v cborValue) (ok bool, payload []byte, issuer, alg string, err error) {
	raw, isBytes := v.asBytes()
	item := v
	if isBytes {
		// The signature is frequently a byte string wrapping the COSE message.
		decoded, _, decodeErr := decodeCBOR(raw)
		if decodeErr != nil {
			return false, nil, "", "", fmt.Errorf("decoding the COSE message: %w", decodeErr)
		}
		item = decoded
	}

	msg := item.untag()
	if msg.kind != cborArray || len(msg.array) != 4 {
		return false, nil, "", "", errors.New("not a COSE_Sign1 structure")
	}

	protectedBytes, ok1 := msg.array[0].asBytes()
	signature, ok2 := msg.array[3].asBytes()
	if !ok1 || !ok2 {
		return false, nil, "", "", errors.New("COSE_Sign1 fields are not byte strings")
	}

	// Protected headers are a CBOR map wrapped in a byte string. An empty one
	// is legal and carries no algorithm, which we refuse rather than guess at.
	var protected cborValue
	if len(protectedBytes) > 0 {
		protected, _, err = decodeCBOR(protectedBytes)
		if err != nil {
			return false, nil, "", "", fmt.Errorf("decoding protected headers: %w", err)
		}
	}

	algValue, hasAlg := protected.lookup(coseHeaderAlg)
	if !hasAlg {
		return false, nil, "", "", errors.New("no algorithm in the protected headers")
	}
	algID, ok := algValue.asInt()
	if !ok {
		return false, nil, "", "", errors.New("the algorithm header is not an integer")
	}
	alg = coseAlgName(algID)

	chain := findX5Chain(protected, msg.array[1])
	if len(chain) == 0 {
		return false, nil, "", alg, errors.New("no certificate chain in the message")
	}
	cert, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return false, nil, "", alg, fmt.Errorf("parsing the signing certificate: %w", err)
	}
	issuer = certificateSubject(cert)

	// Payload may be detached (null). C2PA embeds it, and a detached payload
	// here means there is nothing for the signature to vouch for.
	payload, hasPayload := msg.array[2].asBytes()
	if !hasPayload || len(payload) == 0 {
		return false, nil, issuer, alg, errors.New("the COSE message has no payload, so it asserts nothing")
	}

	sigStructure := encodeCBORArray(
		encodeCBORText("Signature1"),
		encodeCBORBytes(protectedBytes),
		encodeCBORBytes(nil), // external_aad, always empty in C2PA
		encodeCBORBytes(payload),
	)

	verified, err := verifySignature(cert, algID, sigStructure, signature)
	return verified, payload, issuer, alg, err
}

// findX5Chain reads the certificate chain from the protected headers, falling
// back to the unprotected ones.
//
// The chain being unprotected is not a weakness here: the certificate's public
// key must verify the signature regardless, so substituting a different
// certificate breaks verification rather than bypassing it.
func findX5Chain(protected, unprotected cborValue) [][]byte {
	for _, hdrs := range []cborValue{protected, unprotected} {
		v, ok := hdrs.lookup(coseHeaderX5Chain)
		if !ok {
			continue
		}
		// A single certificate may appear bare rather than in an array.
		if der, ok := v.asBytes(); ok {
			return [][]byte{der}
		}
		if v.kind == cborArray {
			var chain [][]byte
			for _, item := range v.array {
				if der, ok := item.asBytes(); ok {
					chain = append(chain, der)
				}
			}
			if len(chain) > 0 {
				return chain
			}
		}
	}
	return nil
}

// verifySignature dispatches on the COSE algorithm identifier.
//
// The algorithm comes from the signed protected headers and the key from the
// certificate, and both must agree with each other: an ES256 header with an RSA
// key is a malformed message, not something to be helpful about.
func verifySignature(cert *x509.Certificate, algID int64, signed, signature []byte) (bool, error) {
	switch algID {
	case -7, -35, -36: // ES256, ES384, ES512
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return false, errors.New("the algorithm is ECDSA but the certificate key is not")
		}
		digest, size := ecdsaDigest(algID, signed)
		// COSE uses the fixed-width r‖s encoding, not ASN.1.
		if len(signature) != 2*size {
			// Some producers emit ASN.1 anyway. Accept it, because rejecting a
			// real signature over an encoding detail helps nobody.
			return verifyECDSAASN1(pub, digest, signature)
		}
		r := new(big.Int).SetBytes(signature[:size])
		s := new(big.Int).SetBytes(signature[size:])
		return ecdsa.Verify(pub, digest, r, s), nil

	case -37, -38, -39: // PS256, PS384, PS512
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return false, errors.New("the algorithm is RSA-PSS but the certificate key is not")
		}
		h, digest := hashFor(algID, signed)
		err := rsa.VerifyPSS(pub, h, digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		return err == nil, nil

	case -257, -258, -259: // RS256, RS384, RS512
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return false, errors.New("the algorithm is RSA but the certificate key is not")
		}
		h, digest := hashFor(algID, signed)
		err := rsa.VerifyPKCS1v15(pub, h, digest, signature)
		return err == nil, nil

	case -8: // EdDSA
		pub, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return false, errors.New("the algorithm is EdDSA but the certificate key is not")
		}
		return ed25519.Verify(pub, signed, signature), nil
	}
	return false, fmt.Errorf("unsupported COSE algorithm %d", algID)
}

func verifyECDSAASN1(pub *ecdsa.PublicKey, digest, signature []byte) (bool, error) {
	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(signature, &parsed); err != nil {
		return false, errors.New("the signature is neither fixed-width nor ASN.1 ECDSA")
	}
	return ecdsa.Verify(pub, digest, parsed.R, parsed.S), nil
}

func ecdsaDigest(algID int64, b []byte) (digest []byte, coordSize int) {
	switch algID {
	case -35: // ES384 / P-384
		d := sha512.Sum384(b)
		return d[:], 48
	case -36: // ES512 / P-521
		d := sha512.Sum512(b)
		return d[:], 66
	default: // ES256 / P-256
		d := sha256.Sum256(b)
		return d[:], 32
	}
}

// hashFor maps a COSE algorithm to its digest, explicitly.
//
// Explicitly, because arithmetic between algorithm identifiers is how a
// verifier silently ends up checking an RS512 signature with SHA-256: the
// numbers are registry assignments, not an encoding of the digest size, and
// PS384 and RS384 are 47 apart for no reason at all.
func hashFor(algID int64, b []byte) (crypto.Hash, []byte) {
	switch algID {
	case -38, -258: // PS384, RS384
		d := sha512.Sum384(b)
		return crypto.SHA384, d[:]
	case -39, -259: // PS512, RS512
		d := sha512.Sum512(b)
		return crypto.SHA512, d[:]
	case -37, -257: // PS256, RS256
		d := sha256.Sum256(b)
		return crypto.SHA256, d[:]
	}
	// Unreachable: every caller has already matched a known identifier.
	d := sha256.Sum256(b)
	return crypto.SHA256, d[:]
}

func coseAlgName(id int64) string {
	switch id {
	case -7:
		return "ES256"
	case -8:
		return "EdDSA"
	case -35:
		return "ES384"
	case -36:
		return "ES512"
	case -37:
		return "PS256"
	case -38:
		return "PS384"
	case -39:
		return "PS512"
	case -257:
		return "RS256"
	}
	return fmt.Sprintf("COSE alg %d", id)
}

// certificateSubject renders the signer for a human, preferring the common name
// and falling back to the whole subject rather than to an empty string.
func certificateSubject(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		if len(c.Subject.Organization) > 0 {
			return c.Subject.CommonName + " (" + c.Subject.Organization[0] + ")"
		}
		return c.Subject.CommonName
	}
	if len(c.Subject.Organization) > 0 {
		return c.Subject.Organization[0]
	}
	return c.Subject.String()
}

// ---- hard binding -----------------------------------------------------------

// verifyHardBinding checks that the manifest describes these exact bytes.
//
// Without this, a manifest lifted from a genuinely-credentialed file and
// pasted into a forgery would verify perfectly: the signature is over the
// manifest, and the manifest says nothing about the file unless this binding is
// checked against it.
func verifyHardBinding(claim cborValue, asset []byte, exclusions []byteRange, res *C2PAResult) bool {
	assertions, ok := claim.lookupText("assertions")
	if !ok {
		if assertions, ok = claim.lookupText("created_assertions"); !ok {
			res.Notes = append(res.Notes,
				"the claim lists no assertions, so the manifest cannot be tied to these bytes")
			return false
		}
	}
	if assertions.kind != cborArray {
		return false
	}

	for _, a := range assertions.array {
		url, _ := a.lookupText("url")
		name, _ := url.asText()
		if !strings.Contains(name, "c2pa.hash.data") && !strings.Contains(name, "c2pa.hash.boxes") {
			continue
		}
		hashValue, ok := a.lookupText("hash")
		if !ok {
			continue
		}
		want, ok := hashValue.asBytes()
		if !ok || len(want) == 0 {
			continue
		}

		got := sha256.Sum256(excludeRanges(asset, exclusions))
		if bytes.Equal(got[:], want) {
			return true
		}
		res.Notes = append(res.Notes,
			"the manifest's hard binding does not match these bytes, so the manifest describes a different asset")
		return false
	}

	res.Notes = append(res.Notes,
		"no hard-binding assertion was found, so the manifest is signed but not tied to these bytes")
	return false
}

type byteRange struct{ start, length int }

// excludeRanges rebuilds the asset with the manifest's own region removed,
// which is what the hard binding is computed over — the manifest cannot contain
// a hash of itself.
func excludeRanges(asset []byte, ranges []byteRange) []byte {
	if len(ranges) == 0 {
		return asset
	}
	out := make([]byte, 0, len(asset))
	prev := 0
	for _, r := range ranges {
		if r.start < prev || r.start > len(asset) {
			continue
		}
		out = append(out, asset[prev:r.start]...)
		prev = min(r.start+r.length, len(asset))
	}
	return append(out, asset[prev:]...)
}

// ---- container parsing ------------------------------------------------------

// findManifestStore locates the JUMBF manifest store and the byte range it
// occupies, which the hard binding excludes.
func findManifestStore(asset []byte) ([]byte, []byteRange, error) {
	switch {
	case bytes.HasPrefix(asset, []byte{0xFF, 0xD8, 0xFF}):
		return findJPEGManifest(asset)
	case bytes.HasPrefix(asset, []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}):
		return findPNGManifest(asset)
	case len(asset) > 12 && string(asset[4:8]) == "ftyp":
		return findBMFFManifest(asset)
	}
	return nil, nil, nil
}

// findJPEGManifest reassembles the manifest from APP11 segments.
//
// JPEG segments cap at 64 KiB, so a manifest larger than that is split across
// several APP11 markers sharing a box instance number, each carrying a packet
// sequence number. Reassembly has to follow that structure rather than
// concatenating whatever APP11 segments happen to appear.
func findJPEGManifest(asset []byte) ([]byte, []byteRange, error) {
	var store bytes.Buffer
	var ranges []byteRange

	i := 2 // past SOI
	for i+4 <= len(asset) {
		if asset[i] != 0xFF {
			i++
			continue
		}
		marker := asset[i+1]
		if marker == 0xD8 || (marker >= 0xD0 && marker <= 0xD9) {
			i += 2
			continue
		}
		if marker == 0xDA { // start of scan: entropy-coded data follows
			break
		}
		if i+4 > len(asset) {
			break
		}
		segLen := int(binary.BigEndian.Uint16(asset[i+2 : i+4]))
		if segLen < 2 || i+2+segLen > len(asset) {
			break
		}
		body := asset[i+4 : i+2+segLen]

		// APP11, common identifier "JP", then a 2-byte box instance, a 4-byte
		// packet sequence, and the payload.
		const app11HeaderLen = 8
		if marker == 0xEB && len(body) > app11HeaderLen && string(body[:2]) == "JP" {
			store.Write(body[app11HeaderLen:])
			ranges = append(ranges, byteRange{start: i, length: 2 + segLen})
		}
		i += 2 + segLen
	}

	if store.Len() == 0 {
		return nil, nil, nil
	}
	return unwrapJUMBF(store.Bytes()), ranges, nil
}

// findPNGManifest reads the caBX chunk.
func findPNGManifest(asset []byte) ([]byte, []byteRange, error) {
	i := 8 // past the signature
	for i+12 <= len(asset) {
		length := int(binary.BigEndian.Uint32(asset[i : i+4]))
		if length < 0 || i+12+length > len(asset) {
			break
		}
		chunkType := string(asset[i+4 : i+8])
		if chunkType == "caBX" {
			data := asset[i+8 : i+8+length]
			return unwrapJUMBF(data), []byteRange{{start: i, length: 12 + length}}, nil
		}
		if chunkType == "IEND" {
			break
		}
		i += 12 + length
	}
	return nil, nil, nil
}

// findBMFFManifest reads the top-level `uuid` box carrying the C2PA UUID, used
// by MP4, HEIF and AVIF.
func findBMFFManifest(asset []byte) ([]byte, []byteRange, error) {
	// The C2PA box UUID, from the specification.
	c2paUUID := []byte{
		0xD8, 0xFE, 0xC3, 0xD6, 0x1B, 0x0E, 0x48, 0x3C,
		0x92, 0x97, 0x58, 0x28, 0x87, 0x7E, 0xC4, 0x81,
	}
	i := 0
	for i+8 <= len(asset) {
		size := int(binary.BigEndian.Uint32(asset[i : i+4]))
		boxType := string(asset[i+4 : i+8])
		if size == 0 {
			size = len(asset) - i
		}
		if size < 8 || i+size > len(asset) {
			break
		}
		if boxType == "uuid" && i+24 <= len(asset) && bytes.Equal(asset[i+8:i+24], c2paUUID) {
			return unwrapJUMBF(asset[i+24 : i+size]), []byteRange{{start: i, length: size}}, nil
		}
		i += size
	}
	return nil, nil, nil
}

// unwrapJUMBF walks the JUMBF box tree and returns the CBOR payload of the
// manifest store.
//
// A JUMBF box is a 4-byte big-endian length, a 4-byte type, then content. The
// C2PA payload sits in a `cbor` box nested inside `jumb` boxes.
func unwrapJUMBF(b []byte) []byte {
	var found []byte
	var walk func(b []byte, depth int)
	walk = func(b []byte, depth int) {
		if depth > 16 || found != nil {
			return
		}
		i := 0
		for i+8 <= len(b) {
			size := int(binary.BigEndian.Uint32(b[i : i+4]))
			boxType := string(b[i+4 : i+8])
			if size == 0 {
				size = len(b) - i
			}
			if size < 8 || i+size > len(b) {
				return
			}
			content := b[i+8 : i+size]
			switch boxType {
			case jumbfContentBox:
				found = content
				return
			case jumbfBoxType:
				walk(content, depth+1)
				if found != nil {
					return
				}
			case jumbfDescType:
				// Description box: skipped, it names the box rather than
				// carrying the manifest.
			}
			i += size
		}
	}
	walk(b, 0)
	if found == nil {
		// Some producers store bare CBOR with no JUMBF wrapper at all.
		if len(b) > 0 && b[0]>>5 == 5 {
			return b
		}
	}
	return found
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
