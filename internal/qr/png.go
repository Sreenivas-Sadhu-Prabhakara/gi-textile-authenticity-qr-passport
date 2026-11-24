package qr

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"strings"
)

// QuietZone is the width, in modules, of the light margin a symbol needs
// around it. Four modules is the minimum the specification allows, and a
// symbol printed without it is often unreadable however good the symbol is.
const QuietZone = 4

// PNG renders a symbol as a PNG image: scale pixels per module, with a quiet
// zone of quiet modules on every side. The image is two-colour, so a tag-sized
// symbol comes to a few hundred bytes.
func PNG(m *Matrix, scale, quiet int) ([]byte, error) {
	if m == nil {
		return nil, errors.New("there is no symbol to render")
	}
	if scale < 1 {
		return nil, fmt.Errorf("a module cannot be %d pixels across", scale)
	}
	if quiet < 0 {
		return nil, fmt.Errorf("a quiet zone cannot be %d modules wide", quiet)
	}
	side := (m.size + 2*quiet) * scale
	img := image.NewPaletted(image.Rect(0, 0, side, side), color.Palette{
		color.White,
		color.Black,
	})
	for row := 0; row < m.size; row++ {
		for col := 0; col < m.size; col++ {
			if !m.Dark(row, col) {
				continue
			}
			x0 := (col + quiet) * scale
			y0 := (row + quiet) * scale
			for y := y0; y < y0+scale; y++ {
				for x := x0; x < x0+scale; x++ {
					img.SetColorIndex(x, y, 1)
				}
			}
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ModulesFromPNG reads a module grid back out of a rendered PNG, working out
// the quiet zone and the pixels-per-module for itself and checking that what
// it found has the three finder patterns in the right corners.
//
// This closes the loop on rendering: a symbol is only as good as the image of
// it, and an image whose modules cannot be recovered is not a symbol anyone
// can scan.
func ModulesFromPNG(data []byte) ([][]bool, error) {
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("the image could not be read: %w", err)
	}
	b := img.Bounds()
	darkAt := func(x, y int) bool {
		r, g, bl, _ := img.At(b.Min.X+x, b.Min.Y+y).RGBA()
		return (r+g+bl)/3 < 0x8000
	}

	// Trim the light border on all four sides.
	left, right := b.Dx(), -1
	top, bottom := b.Dy(), -1
	for y := 0; y < b.Dy(); y++ {
		for x := 0; x < b.Dx(); x++ {
			if !darkAt(x, y) {
				continue
			}
			if x < left {
				left = x
			}
			if x > right {
				right = x
			}
			if y < top {
				top = y
			}
			if y > bottom {
				bottom = y
			}
		}
	}
	if right < 0 {
		return nil, errors.New("the image has no dark pixels, so it holds no symbol")
	}
	width, height := right-left+1, bottom-top+1
	if width != height {
		return nil, fmt.Errorf("the dark area is %dx%d pixels, and a symbol is square", width, height)
	}

	// The side length is the module count times the pixels per module, so try
	// each version whose module count divides it and keep the one whose finder
	// patterns are where they should be.
	for v := MinVersion; v <= MaxVersion; v++ {
		size := Size(v)
		if width%size != 0 {
			continue
		}
		scale := width / size
		rows := make([][]bool, size)
		for r := 0; r < size; r++ {
			rows[r] = make([]bool, size)
			for c := 0; c < size; c++ {
				rows[r][c] = darkAt(left+c*scale+scale/2, top+r*scale+scale/2)
			}
		}
		if hasFinderPatterns(rows) {
			return rows, nil
		}
	}
	return nil, fmt.Errorf("a %d pixel square does not sample to any symbol version with finder patterns in its corners", width)
}

// hasFinderPatterns checks the three 7x7 corner patterns, which is enough to
// tell a correctly sampled grid from a mis-sampled one.
func hasFinderPatterns(rows [][]bool) bool {
	size := len(rows)
	for _, corner := range [][2]int{{0, 0}, {0, size - 7}, {size - 7, 0}} {
		for dr := 0; dr < 7; dr++ {
			for dc := 0; dc < 7; dc++ {
				d := max(abs(dr-3), abs(dc-3))
				if rows[corner[0]+dr][corner[1]+dc] != (d != 2) {
					return false
				}
			}
		}
	}
	return true
}

// Text renders a symbol for a terminal, two characters per module so it comes
// out square, with a quiet zone included.
func Text(m *Matrix) string {
	var b strings.Builder
	line := strings.Repeat("  ", m.size+2*QuietZone)
	for i := 0; i < QuietZone; i++ {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	for row := 0; row < m.size; row++ {
		b.WriteString(strings.Repeat("  ", QuietZone))
		for col := 0; col < m.size; col++ {
			if m.Dark(row, col) {
				b.WriteString("##")
			} else {
				b.WriteString("  ")
			}
		}
		b.WriteString(strings.Repeat("  ", QuietZone))
		b.WriteByte('\n')
	}
	for i := 0; i < QuietZone; i++ {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
