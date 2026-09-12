package provenance

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// A minimal CBOR (RFC 8949) decoder, covering the subset C2PA and COSE use.
//
// It is implemented here rather than taken from a library for the reason that
// governs every dependency decision in this repository: this code parses
// attacker-controlled bytes out of an uploaded file, so its size is its
// auditability. The subset needed is small and the specification is stable.
//
// Everything below is hardened for hostile input. Each of these limits exists
// because its absence is a denial-of-service primitive in a parser that anyone
// can feed a file to:
//
//   - nesting is bounded, so a deeply recursive structure cannot exhaust the
//     goroutine stack;
//   - every length is checked against the remaining input BEFORE allocating,
//     so a header claiming four gigabytes in a twelve-byte file allocates
//     nothing;
//   - collection sizes are bounded by the bytes actually remaining, since each
//     element needs at least one byte.

const (
	maxCBORNesting  = 32
	maxCBORElements = 1 << 20
)

var (
	errCBORTruncated   = errors.New("provenance: truncated CBOR input")
	errCBORNesting     = errors.New("provenance: CBOR nesting is too deep")
	errCBORUnsupported = errors.New("provenance: unsupported CBOR item")
)

// cborValue is a decoded item. Only the shapes COSE and C2PA use are modelled.
type cborValue struct {
	kind  cborKind
	uint  uint64
	neg   int64
	bytes []byte
	text  string
	array []cborValue
	// mapKeys and mapVals are parallel slices rather than a Go map, because
	// COSE header labels are integers and CBOR permits duplicate keys — both of
	// which a map would quietly destroy, and the second of which is how a
	// forged header sneaks past a parser that keeps only the last value.
	mapKeys []cborValue
	mapVals []cborValue
	tag     uint64
	tagged  *cborValue
	boolean bool
	float   float64
}

type cborKind uint8

const (
	cborUint cborKind = iota
	cborNegInt
	cborBytes
	cborText
	cborArray
	cborMap
	cborTag
	cborBool
	cborNull
	cborUndefined
	cborFloat
)

// decodeCBOR decodes one item and returns it with the bytes it consumed.
func decodeCBOR(b []byte) (cborValue, int, error) {
	return decodeCBORAt(b, 0)
}

func decodeCBORAt(b []byte, depth int) (cborValue, int, error) {
	if depth > maxCBORNesting {
		return cborValue{}, 0, errCBORNesting
	}
	if len(b) == 0 {
		return cborValue{}, 0, errCBORTruncated
	}

	major := b[0] >> 5
	minor := b[0] & 0x1f
	arg, n, err := decodeArgument(b, minor)
	if err != nil {
		return cborValue{}, 0, err
	}
	rest := b[n:]

	switch major {
	case 0:
		return cborValue{kind: cborUint, uint: arg}, n, nil

	case 1:
		if arg > math.MaxInt64 {
			return cborValue{}, 0, errCBORUnsupported
		}
		return cborValue{kind: cborNegInt, neg: -1 - int64(arg)}, n, nil

	case 2, 3:
		if arg > uint64(len(rest)) {
			return cborValue{}, 0, fmt.Errorf("%w: item claims %d bytes, %d remain",
				errCBORTruncated, arg, len(rest))
		}
		payload := rest[:arg]
		if major == 2 {
			return cborValue{kind: cborBytes, bytes: payload}, n + int(arg), nil
		}
		return cborValue{kind: cborText, text: string(payload)}, n + int(arg), nil

	case 4:
		if err := checkCount(arg, len(rest)); err != nil {
			return cborValue{}, 0, err
		}
		v := cborValue{kind: cborArray, array: make([]cborValue, 0, min(int(arg), 64))}
		off := n
		for i := uint64(0); i < arg; i++ {
			item, used, err := decodeCBORAt(b[off:], depth+1)
			if err != nil {
				return cborValue{}, 0, err
			}
			v.array = append(v.array, item)
			off += used
		}
		return v, off, nil

	case 5:
		if err := checkCount(arg, len(rest)); err != nil {
			return cborValue{}, 0, err
		}
		v := cborValue{kind: cborMap}
		off := n
		for i := uint64(0); i < arg; i++ {
			k, used, err := decodeCBORAt(b[off:], depth+1)
			if err != nil {
				return cborValue{}, 0, err
			}
			off += used
			val, used, err := decodeCBORAt(b[off:], depth+1)
			if err != nil {
				return cborValue{}, 0, err
			}
			off += used
			v.mapKeys = append(v.mapKeys, k)
			v.mapVals = append(v.mapVals, val)
		}
		return v, off, nil

	case 6:
		inner, used, err := decodeCBORAt(b[n:], depth+1)
		if err != nil {
			return cborValue{}, 0, err
		}
		return cborValue{kind: cborTag, tag: arg, tagged: &inner}, n + used, nil

	case 7:
		switch minor {
		case 20:
			return cborValue{kind: cborBool, boolean: false}, n, nil
		case 21:
			return cborValue{kind: cborBool, boolean: true}, n, nil
		case 22:
			return cborValue{kind: cborNull}, n, nil
		case 23:
			return cborValue{kind: cborUndefined}, n, nil
		case 25:
			return cborValue{kind: cborFloat, float: float64(math.Float32frombits(halfToSingle(uint16(arg))))}, n, nil
		case 26:
			return cborValue{kind: cborFloat, float: float64(math.Float32frombits(uint32(arg)))}, n, nil
		case 27:
			return cborValue{kind: cborFloat, float: math.Float64frombits(arg)}, n, nil
		}
		return cborValue{}, 0, errCBORUnsupported
	}
	return cborValue{}, 0, errCBORUnsupported
}

// decodeArgument reads the additional-information argument, returning it and
// the total header length.
func decodeArgument(b []byte, minor byte) (uint64, int, error) {
	switch {
	case minor < 24:
		return uint64(minor), 1, nil
	case minor == 24:
		if len(b) < 2 {
			return 0, 0, errCBORTruncated
		}
		return uint64(b[1]), 2, nil
	case minor == 25:
		if len(b) < 3 {
			return 0, 0, errCBORTruncated
		}
		return uint64(binary.BigEndian.Uint16(b[1:3])), 3, nil
	case minor == 26:
		if len(b) < 5 {
			return 0, 0, errCBORTruncated
		}
		return uint64(binary.BigEndian.Uint32(b[1:5])), 5, nil
	case minor == 27:
		if len(b) < 9 {
			return 0, 0, errCBORTruncated
		}
		return binary.BigEndian.Uint64(b[1:9]), 9, nil
	}
	// 28..30 are reserved; 31 is the indefinite-length marker, which C2PA does
	// not use and which is a needless complication to accept from a stranger.
	return 0, 0, errCBORUnsupported
}

// checkCount refuses a collection whose declared size cannot possibly fit in
// the bytes that remain. Every element costs at least one byte, so this bounds
// the allocation before it happens.
func checkCount(count uint64, remaining int) error {
	if count > maxCBORElements {
		return fmt.Errorf("%w: collection declares %d elements", errCBORUnsupported, count)
	}
	if count > uint64(remaining) {
		return fmt.Errorf("%w: collection declares %d elements, %d bytes remain",
			errCBORTruncated, count, remaining)
	}
	return nil
}

func halfToSingle(h uint16) uint32 {
	sign := uint32(h&0x8000) << 16
	exp := (h >> 10) & 0x1f
	mant := uint32(h & 0x03ff)
	switch exp {
	case 0:
		if mant == 0 {
			return sign
		}
		// Subnormal: normalise.
		e := uint32(127 - 15 + 1)
		for mant&0x400 == 0 {
			mant <<= 1
			e--
		}
		return sign | (e << 23) | ((mant & 0x3ff) << 13)
	case 0x1f:
		return sign | 0x7f800000 | (mant << 13)
	}
	return sign | ((uint32(exp) - 15 + 127) << 23) | (mant << 13)
}

// ---- accessors --------------------------------------------------------------
//
// Each returns a value and whether the item was of the expected shape, so a
// caller never has to assume a structure an uploaded file controls.

func (v cborValue) lookup(label int64) (cborValue, bool) {
	if v.kind != cborMap {
		return cborValue{}, false
	}
	for i, k := range v.mapKeys {
		switch {
		case k.kind == cborUint && label >= 0 && k.uint == uint64(label),
			k.kind == cborNegInt && k.neg == label:
			return v.mapVals[i], true
		}
	}
	return cborValue{}, false
}

func (v cborValue) lookupText(key string) (cborValue, bool) {
	if v.kind != cborMap {
		return cborValue{}, false
	}
	for i, k := range v.mapKeys {
		if k.kind == cborText && k.text == key {
			return v.mapVals[i], true
		}
	}
	return cborValue{}, false
}

func (v cborValue) asBytes() ([]byte, bool) {
	if v.kind != cborBytes {
		return nil, false
	}
	return v.bytes, true
}

func (v cborValue) asText() (string, bool) {
	if v.kind != cborText {
		return "", false
	}
	return v.text, true
}

func (v cborValue) asInt() (int64, bool) {
	switch v.kind {
	case cborUint:
		if v.uint > math.MaxInt64 {
			return 0, false
		}
		return int64(v.uint), true
	case cborNegInt:
		return v.neg, true
	}
	return 0, false
}

// untag unwraps a tagged item, since COSE_Sign1 may arrive tagged (18) or bare.
func (v cborValue) untag() cborValue {
	if v.kind == cborTag && v.tagged != nil {
		return v.tagged.untag()
	}
	return v
}

// ---- encoding ---------------------------------------------------------------

// encodeCBORHead writes a major type and argument in the shortest form, which
// is what COSE's deterministic encoding requires for the Sig_structure.
func encodeCBORHead(major byte, arg uint64) []byte {
	switch {
	case arg < 24:
		return []byte{major<<5 | byte(arg)}
	case arg <= math.MaxUint8:
		return []byte{major<<5 | 24, byte(arg)}
	case arg <= math.MaxUint16:
		b := []byte{major<<5 | 25, 0, 0}
		binary.BigEndian.PutUint16(b[1:], uint16(arg))
		return b
	case arg <= math.MaxUint32:
		b := []byte{major<<5 | 26, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(b[1:], uint32(arg))
		return b
	default:
		b := []byte{major<<5 | 27, 0, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint64(b[1:], arg)
		return b
	}
}

func encodeCBORBytes(b []byte) []byte {
	return append(encodeCBORHead(2, uint64(len(b))), b...)
}

func encodeCBORText(s string) []byte {
	return append(encodeCBORHead(3, uint64(len(s))), s...)
}

func encodeCBORArray(items ...[]byte) []byte {
	out := encodeCBORHead(4, uint64(len(items)))
	for _, it := range items {
		out = append(out, it...)
	}
	return out
}
