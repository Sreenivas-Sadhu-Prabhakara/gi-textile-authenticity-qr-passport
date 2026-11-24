package qr

import "testing"

func TestGaloisFieldArithmetic(t *testing.T) {
	t.Run("zero and one", func(t *testing.T) {
		for _, v := range []byte{0, 1, 2, 3, 0x1d, 0x80, 0xff} {
			if got := gfMul(v, 0); got != 0 {
				t.Errorf("gfMul(%#x, 0) = %#x, want 0", v, got)
			}
			if got := gfMul(v, 1); got != v {
				t.Errorf("gfMul(%#x, 1) = %#x, want %#x", v, got, v)
			}
		}
	})

	t.Run("commutative and associative", func(t *testing.T) {
		values := []byte{1, 2, 3, 5, 0x1d, 0x7f, 0x80, 0xff}
		for _, a := range values {
			for _, b := range values {
				if gfMul(a, b) != gfMul(b, a) {
					t.Errorf("gfMul(%#x,%#x) != gfMul(%#x,%#x)", a, b, b, a)
				}
				for _, c := range values {
					if gfMul(gfMul(a, b), c) != gfMul(a, gfMul(b, c)) {
						t.Errorf("multiplication not associative at %#x %#x %#x", a, b, c)
					}
					// Addition in the field is XOR, so multiplication must
					// distribute over it.
					if gfMul(a, b^c) != gfMul(a, b)^gfMul(a, c) {
						t.Errorf("multiplication not distributive at %#x %#x %#x", a, b, c)
					}
				}
			}
		}
	})

	t.Run("every non-zero element has an inverse", func(t *testing.T) {
		for v := 1; v < 256; v++ {
			inverse := gfExp[255-gfLog[v]]
			if got := gfMul(byte(v), inverse); got != 1 {
				t.Errorf("%#x * %#x = %#x, want 1", v, inverse, got)
			}
		}
	})

	t.Run("exponent and logarithm are inverses", func(t *testing.T) {
		for i := 0; i < 255; i++ {
			if got := gfLog[gfExp[i]]; got != i {
				t.Errorf("gfLog[gfExp[%d]] = %d", i, got)
			}
		}
		if gfExp[255] != gfExp[0] {
			t.Error("the exponent table should wrap at 255")
		}
	})
}

func TestReedSolomonGeneratorPoly(t *testing.T) {
	for _, n := range []int{7, 10, 13, 15, 16, 17, 18, 20, 22, 24, 26, 28, 30} {
		gen := rsGeneratorPoly(n)
		if len(gen) != n {
			t.Fatalf("generator of degree %d has %d coefficients, want %d", n, len(gen), n)
		}
		// Every root of the generator must evaluate to zero: the polynomial is
		// the product of (x - 2^i) for i in 0..n-1. Reconstruct the full
		// coefficient list (the leading 1 is implied) and evaluate.
		full := append([]byte{1}, gen...)
		for i := 0; i < n; i++ {
			root := gfExp[i]
			var acc byte
			for _, c := range full {
				acc = gfMul(acc, root) ^ c
			}
			if acc != 0 {
				t.Errorf("generator of degree %d does not vanish at 2^%d", n, i)
			}
		}
	}
}

// TestReedSolomonKnownVector checks the error-correction codewords against the
// worked example in the specification: the sixteen data codewords of a version
// 1, level M symbol and the ten error-correction codewords they produce.
func TestReedSolomonKnownVector(t *testing.T) {
	data := []byte{0x10, 0x20, 0x0C, 0x56, 0x61, 0x80, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11}
	want := []byte{0xA5, 0x24, 0xD4, 0xC1, 0xED, 0x36, 0xC7, 0x87, 0x2C, 0x55}
	got := rsRemainder(data, 10)
	if len(got) != len(want) {
		t.Fatalf("got %d error-correction codewords, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("error-correction codewords = % X, want % X", got, want)
		}
	}
}

func TestReedSolomonSyndromes(t *testing.T) {
	data := []byte{0x10, 0x20, 0x0C, 0x56, 0x61, 0x80, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11}
	ec := rsRemainder(data, 10)
	codeword := append(append([]byte{}, data...), ec...)

	t.Run("intact codeword has zero syndromes", func(t *testing.T) {
		for i, s := range rsSyndromes(codeword, 10) {
			if s != 0 {
				t.Errorf("syndrome %d of an intact codeword is %#x, want 0", i, s)
			}
		}
	})

	t.Run("any single corruption shows up", func(t *testing.T) {
		for pos := range codeword {
			for _, delta := range []byte{0x01, 0x80, 0xff} {
				damaged := append([]byte{}, codeword...)
				damaged[pos] ^= delta
				zero := true
				for _, s := range rsSyndromes(damaged, 10) {
					if s != 0 {
						zero = false
						break
					}
				}
				if zero {
					t.Errorf("corrupting codeword %d with %#x left every syndrome zero", pos, delta)
				}
			}
		}
	})

	t.Run("no error correction means no codewords", func(t *testing.T) {
		if got := rsRemainder(data, 0); got != nil {
			t.Errorf("rsRemainder(data, 0) = %v, want nil", got)
		}
	})
}
