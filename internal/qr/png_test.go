package qr

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"
)

func TestPNGDimensions(t *testing.T) {
	m, err := Encode("HELLO WORLD", LevelM)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		scale, quiet int
		wantSide     int
	}{
		{1, 0, 21},
		{1, QuietZone, 29},
		{4, QuietZone, 116},
		{8, 2, 200},
	}
	for _, c := range cases {
		data, err := PNG(m, c.scale, c.quiet)
		if err != nil {
			t.Fatal(err)
		}
		img, err := png.Decode(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		if got := img.Bounds().Dx(); got != c.wantSide {
			t.Errorf("scale %d quiet %d: width %d, want %d", c.scale, c.quiet, got, c.wantSide)
		}
		if img.Bounds().Dy() != img.Bounds().Dx() {
			t.Errorf("scale %d quiet %d: image is not square", c.scale, c.quiet)
		}
	}
}

func TestPNGRejectsBadArguments(t *testing.T) {
	m, err := Encode("HELLO", LevelM)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name         string
		m            *Matrix
		scale, quiet int
		want         string
	}{
		{"no symbol", nil, 4, 4, "no symbol"},
		{"zero scale", m, 0, 4, "cannot be 0 pixels"},
		{"negative scale", m, -2, 4, "cannot be -2 pixels"},
		{"negative quiet zone", m, 4, -1, "cannot be -1 modules"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := PNG(c.m, c.scale, c.quiet); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v, want one mentioning %q", err, c.want)
			}
		})
	}
}

// TestPNGRoundTrip renders a symbol, reads the image back to a module grid
// with no help about its size, and decodes it. A symbol is only useful as an
// image of itself, so this is the check that matters most for printing.
func TestPNGRoundTrip(t *testing.T) {
	payloads := []struct {
		name    string
		payload string
		level   Level
		min     int
	}{
		{"smallest symbol", "GITP1:ABC", LevelM, 1},
		{"alignment patterns", strings.Repeat("GITP1:ABCDEF234567", 4), LevelQ, 7},
		{"long payload", strings.Repeat("ABCDEFGHIJ234567", 40), LevelM, 1},
		{"byte mode", strings.Repeat("the quick brown fox ", 8), LevelH, 1},
		{"largest symbol", strings.Repeat("A1B2C3D4E5", 429), LevelL, 40},
	}
	for _, c := range payloads {
		t.Run(c.name, func(t *testing.T) {
			m, err := EncodeVersion(c.payload, c.level, c.min)
			if err != nil {
				t.Fatal(err)
			}
			for _, scale := range []int{1, 3, 4} {
				data, err := PNG(m, scale, QuietZone)
				if err != nil {
					t.Fatal(err)
				}
				rows, err := ModulesFromPNG(data)
				if err != nil {
					t.Fatalf("scale %d: %v", scale, err)
				}
				if len(rows) != m.Size() {
					t.Fatalf("scale %d: sampled %d modules, want %d", scale, len(rows), m.Size())
				}
				back, err := FromModules(rows)
				if err != nil {
					t.Fatalf("scale %d: %v", scale, err)
				}
				got, level, mask, err := Decode(back)
				if err != nil {
					t.Fatalf("scale %d: %v", scale, err)
				}
				if got != c.payload {
					t.Errorf("scale %d: payload came back wrong (%d of %d characters)", scale, len(got), len(c.payload))
				}
				if level != c.level || mask != m.Mask {
					t.Errorf("scale %d: level %s mask %d, want %s and %d", scale, level, mask, c.level, m.Mask)
				}
			}
		})
	}
}

// blankImage is an all-light square, and rectImage an all-dark rectangle:
// images that are not symbols, for checking that the reader says so.
func blankImage(side int) *image.Paletted {
	return image.NewPaletted(image.Rect(0, 0, side, side), color.Palette{color.White, color.Black})
}

func rectImage(width, height int) *image.Paletted {
	img := image.NewPaletted(image.Rect(0, 0, width, height), color.Palette{color.White, color.Black})
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.SetColorIndex(x, y, 1)
		}
	}
	return img
}

func TestModulesFromPNGRejectsJunk(t *testing.T) {
	var allLightBuf bytes.Buffer
	if err := png.Encode(&allLightBuf, blankImage(40)); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"not a PNG", []byte("this is not an image"), "could not be read"},
		{"no dark pixels", allLightBuf.Bytes(), "no dark pixels"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ModulesFromPNG(c.data); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v, want one mentioning %q", err, c.want)
			}
		})
	}

	t.Run("a dark rectangle is not a symbol", func(t *testing.T) {
		var buf bytes.Buffer
		if err := png.Encode(&buf, rectImage(30, 20)); err != nil {
			t.Fatal(err)
		}
		if _, err := ModulesFromPNG(buf.Bytes()); err == nil || !strings.Contains(err.Error(), "square") {
			t.Errorf("error = %v, want one mentioning the shape", err)
		}
	})

	t.Run("a dark square without finder patterns is not a symbol", func(t *testing.T) {
		var buf bytes.Buffer
		if err := png.Encode(&buf, rectImage(21, 21)); err != nil {
			t.Fatal(err)
		}
		if _, err := ModulesFromPNG(buf.Bytes()); err == nil || !strings.Contains(err.Error(), "finder patterns") {
			t.Errorf("error = %v, want one mentioning the finder patterns", err)
		}
	})
}

func TestTextRendering(t *testing.T) {
	m, err := Encode("HELLO WORLD", LevelM)
	if err != nil {
		t.Fatal(err)
	}
	out := Text(m)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	wantLines := m.Size() + 2*QuietZone
	if len(lines) != wantLines {
		t.Fatalf("rendered %d lines, want %d", len(lines), wantLines)
	}
	for i, ln := range lines {
		if got, want := len(ln), 2*(m.Size()+2*QuietZone); got != want {
			t.Fatalf("line %d is %d characters wide, want %d", i, got, want)
		}
	}
	// The top and bottom quiet-zone lines carry nothing.
	if strings.TrimSpace(lines[0]) != "" || strings.TrimSpace(lines[len(lines)-1]) != "" {
		t.Error("the quiet zone is not blank")
	}
	// The first module row starts with the finder pattern.
	first := lines[QuietZone][2*QuietZone:]
	if !strings.HasPrefix(first, strings.Repeat("##", 7)) {
		t.Errorf("the first module row does not start with a finder pattern: %q", first[:20])
	}
}
