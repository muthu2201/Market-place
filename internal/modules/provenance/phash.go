package provenance

import (
	"errors"
	"fmt"
	"image"
	"io"
	"math"
	"sort"

	// Registered for their decoders only. These are the raster formats a
	// digital-goods catalogue actually contains; anything else simply has no
	// perceptual hash, which is a normal outcome rather than an error.
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
)

// PerceptualHash computes a 64-bit DCT perceptual hash.
//
// The purpose is near-duplicate detection: catching the same work re-uploaded
// after re-compression, a resize, a crop or a watermark. That is the most
// common real harm on a marketplace for digital goods — somebody's work being
// resold by somebody else — and it is far more tractable than asking whether a
// generator was involved.
//
// The construction is the standard one, and every step exists to discard a
// dimension an attacker would otherwise vary freely:
//
//  1. Convert to greyscale, discarding colour — so a hue shift does not evade.
//  2. Resize to 32×32, discarding resolution — so a resize does not evade.
//  3. Take the 2-D DCT and keep the top-left 8×8, discarding fine detail — so
//     re-compression and light retouching do not evade.
//  4. Drop the DC coefficient, discarding overall brightness — so an exposure
//     change does not evade.
//  5. Emit one bit per remaining coefficient against the median, discarding
//     contrast — so a levels adjustment does not evade.
//
// What survives is the coarse structure of the image, which is the thing that
// has to stay the same for a copy to still be worth selling.
func PerceptualHash(r io.Reader) (uint64, error) {
	img, format, err := image.Decode(r)
	if err != nil {
		return 0, fmt.Errorf("provenance: decoding the image: %w", err)
	}
	_ = format
	return perceptualHashOf(img)
}

// ErrImageTooSmall is returned for images below the sampling size, where a
// perceptual hash carries no information.
var ErrImageTooSmall = errors.New("provenance: image is too small to hash perceptually")

const (
	sampleSize = 32 // the DCT input grid
	hashSize   = 8  // the retained low-frequency square, giving 64 bits
)

func perceptualHashOf(img image.Image) (uint64, error) {
	b := img.Bounds()
	if b.Dx() < hashSize || b.Dy() < hashSize {
		return 0, ErrImageTooSmall
	}

	// Greyscale, box-sampled down to the DCT grid. Box sampling rather than
	// nearest-neighbour because nearest-neighbour aliases, and aliasing on the
	// input to a frequency transform is exactly the noise this is meant to
	// discard.
	grid := make([]float64, sampleSize*sampleSize)
	cellW := float64(b.Dx()) / sampleSize
	cellH := float64(b.Dy()) / sampleSize

	for gy := 0; gy < sampleSize; gy++ {
		for gx := 0; gx < sampleSize; gx++ {
			x0 := b.Min.X + int(float64(gx)*cellW)
			y0 := b.Min.Y + int(float64(gy)*cellH)
			x1 := b.Min.X + int(float64(gx+1)*cellW)
			y1 := b.Min.Y + int(float64(gy+1)*cellH)
			if x1 <= x0 {
				x1 = x0 + 1
			}
			if y1 <= y0 {
				y1 = y0 + 1
			}
			if x1 > b.Max.X {
				x1 = b.Max.X
			}
			if y1 > b.Max.Y {
				y1 = b.Max.Y
			}

			var sum float64
			var n int
			for y := y0; y < y1; y++ {
				for x := x0; x < x1; x++ {
					r, g, bl, _ := img.At(x, y).RGBA()
					// Rec. 601 luma. The coefficients matter less than using
					// the same ones every time.
					sum += 0.299*float64(r>>8) + 0.587*float64(g>>8) + 0.114*float64(bl>>8)
					n++
				}
			}
			if n > 0 {
				grid[gy*sampleSize+gx] = sum / float64(n)
			}
		}
	}

	dct := dct2D(grid, sampleSize)

	// Keep the top-left 8×8 low-frequency block, dropping the DC term at [0][0]
	// because it is overall brightness and nothing else.
	coeffs := make([]float64, 0, hashSize*hashSize-1)
	for y := 0; y < hashSize; y++ {
		for x := 0; x < hashSize; x++ {
			if x == 0 && y == 0 {
				continue
			}
			coeffs = append(coeffs, dct[y*sampleSize+x])
		}
	}

	med := median(coeffs)

	// 63 comparison bits plus a constant 1 in the top position, so a hash is
	// never zero — zero is the sentinel for "not computed", and a legitimate
	// image must not be able to collide with it.
	var hash uint64 = 1 << 63
	for i, c := range coeffs {
		if c > med {
			hash |= 1 << uint(i)
		}
	}
	return hash, nil
}

// dct2D computes a separable 2-D DCT-II, rows then columns.
//
// The separable form is O(n³) where a naive 2-D transform is O(n⁴). At n=32
// that is 32k operations against 1M, which is the difference between a hash
// that can run inline on upload and one that needs its own worker.
func dct2D(in []float64, n int) []float64 {
	cos := cosTable(n)

	rows := make([]float64, n*n)
	for y := 0; y < n; y++ {
		for u := 0; u < n; u++ {
			var sum float64
			for x := 0; x < n; x++ {
				sum += in[y*n+x] * cos[u*n+x]
			}
			rows[y*n+u] = sum * alpha(u, n)
		}
	}

	out := make([]float64, n*n)
	for u := 0; u < n; u++ {
		for v := 0; v < n; v++ {
			var sum float64
			for y := 0; y < n; y++ {
				sum += rows[y*n+u] * cos[v*n+y]
			}
			out[v*n+u] = sum * alpha(v, n)
		}
	}
	return out
}

// cosTable precomputes cos((2x+1)uπ / 2n). Without it the transform spends
// almost all its time in math.Cos.
func cosTable(n int) []float64 {
	t := make([]float64, n*n)
	for u := 0; u < n; u++ {
		for x := 0; x < n; x++ {
			t[u*n+x] = math.Cos(float64(2*x+1) * float64(u) * math.Pi / float64(2*n))
		}
	}
	return t
}

func alpha(u, n int) float64 {
	if u == 0 {
		return math.Sqrt(1 / float64(n))
	}
	return math.Sqrt(2 / float64(n))
}

func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := make([]float64, len(v))
	copy(s, v)
	sort.Float64s(s)
	mid := len(s) / 2
	if len(s)%2 == 1 {
		return s[mid]
	}
	return (s[mid-1] + s[mid]) / 2
}
