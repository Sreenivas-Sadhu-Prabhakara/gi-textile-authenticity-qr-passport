package qr

// Module placement for a QR Code symbol: the fixed patterns a reader locks
// onto, the zigzag the data follows, the eight masks and the scoring that
// picks one, and the error-corrected format and version information.
//
// All coordinates are (row, column) with the origin at the top-left module,
// which is the corner holding the first finder pattern.

// Matrix is a finished or in-progress QR Code symbol.
type Matrix struct {
	Version int
	Level   Level
	Mask    int

	size int
	dark []bool // module colour, row-major
	fn   []bool // true where a module belongs to a function pattern
}

func newMatrix(version int) *Matrix {
	size := Size(version)
	m := &Matrix{Version: version, size: size, dark: make([]bool, size*size), fn: make([]bool, size*size)}
	m.placeFunctionPatterns()
	return m
}

// Size returns the symbol's side length in modules, excluding the quiet zone.
func (m *Matrix) Size() int { return m.size }

// Dark reports whether the module at (row, col) is dark. Coordinates outside
// the symbol read as light, which is what a quiet zone looks like.
func (m *Matrix) Dark(row, col int) bool {
	if row < 0 || col < 0 || row >= m.size || col >= m.size {
		return false
	}
	return m.dark[row*m.size+col]
}

func (m *Matrix) set(row, col int, dark bool) {
	m.dark[row*m.size+col] = dark
}

func (m *Matrix) setFn(row, col int, dark bool) {
	m.dark[row*m.size+col] = dark
	m.fn[row*m.size+col] = true
}

func (m *Matrix) isFn(row, col int) bool { return m.fn[row*m.size+col] }

// freeModules counts the modules not taken by a function pattern.
func (m *Matrix) freeModules() int {
	n := 0
	for _, f := range m.fn {
		if !f {
			n++
		}
	}
	return n
}

// dataModuleCount caches the free-module count of every version so the
// capacity arithmetic does not rebuild a matrix on each call.
var dataModuleCount [MaxVersion + 1]int

func init() {
	for v := MinVersion; v <= MaxVersion; v++ {
		dataModuleCount[v] = newMatrix(v).freeModules()
	}
}

func (m *Matrix) placeFunctionPatterns() {
	// The three finder patterns, each with its separator, in the top-left,
	// top-right and bottom-left corners.
	for _, c := range [][2]int{{0, 0}, {0, m.size - 7}, {m.size - 7, 0}} {
		m.placeFinder(c[0], c[1])
	}

	// Timing patterns: alternating modules along row 6 and column 6, dark at
	// even coordinates, joining the finder patterns.
	for i := 8; i < m.size-8; i++ {
		dark := i%2 == 0
		m.setFn(6, i, dark)
		m.setFn(i, 6, dark)
	}

	// Alignment patterns at every pairing of the version's centres, except
	// the three that would land on a finder pattern.
	if m.Version >= 2 {
		centres := alignmentCentres[m.Version-2]
		last := len(centres) - 1
		for i, r := range centres {
			for j, c := range centres {
				if (i == 0 && j == 0) || (i == 0 && j == last) || (i == last && j == 0) {
					continue
				}
				m.placeAlignment(r, c)
			}
		}
	}

	// Reserve the format information areas. The real bits go in once the mask
	// is chosen; reserving them now keeps data out.
	for i := 0; i <= 8; i++ {
		if i != 6 {
			m.setFn(8, i, false)
			m.setFn(i, 8, false)
		}
	}
	for i := 0; i < 8; i++ {
		m.setFn(8, m.size-1-i, false)
		m.setFn(m.size-1-i, 8, false)
	}
	// The module just above the bottom-left format copy is always dark. Like
	// the rest of the format information it is written once the mask is
	// chosen, so it takes no part in scoring the masks; reserve it here.
	m.setFn(m.size-8, 8, false)

	// Reserve the version information blocks, present from version 7.
	if m.Version >= 7 {
		for i := 0; i < 18; i++ {
			a, b := m.size-11+i%3, i/3
			m.setFn(b, a, false)
			m.setFn(a, b, false)
		}
	}
}

// placeFinder draws a 7x7 finder pattern with its top-left corner at (row,
// col), surrounded by the one-module light separator.
func (m *Matrix) placeFinder(row, col int) {
	for dr := -1; dr <= 7; dr++ {
		for dc := -1; dc <= 7; dc++ {
			r, c := row+dr, col+dc
			if r < 0 || c < 0 || r >= m.size || c >= m.size {
				continue
			}
			// Concentric rings: the 7x7 border and the 3x3 centre are dark.
			d := max(abs(dr-3), abs(dc-3))
			m.setFn(r, c, d != 2 && d <= 3)
		}
	}
}

// placeAlignment draws a 5x5 alignment pattern centred on (row, col).
func (m *Matrix) placeAlignment(row, col int) {
	for dr := -2; dr <= 2; dr++ {
		for dc := -2; dc <= 2; dc++ {
			d := max(abs(dr), abs(dc))
			m.setFn(row+dr, col+dc, d != 1)
		}
	}
}

// placeCodewords writes the interleaved codewords along the symbol's zigzag:
// upwards and downwards through two-module-wide columns from the right-hand
// edge, skipping function modules, with column 6 skipped because the timing
// pattern occupies it.
func (m *Matrix) placeCodewords(codewords []byte) {
	bit := 0
	total := len(codewords) * 8
	for right := m.size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := 0; vert < m.size; vert++ {
			for j := 0; j < 2; j++ {
				col := right - j
				upward := (right+1)&2 == 0
				row := vert
				if upward {
					row = m.size - 1 - vert
				}
				if m.isFn(row, col) {
					continue
				}
				dark := false
				if bit < total {
					dark = codewords[bit/8]>>(7-bit%8)&1 == 1
					bit++
				}
				m.set(row, col, dark)
			}
		}
	}
}

// maskBit reports whether the mask with the given pattern number inverts the
// module at (row, col). The eight conditions are fixed by the specification.
func maskBit(mask, row, col int) bool {
	x, y := col, row
	switch mask {
	case 0:
		return (x+y)%2 == 0
	case 1:
		return y%2 == 0
	case 2:
		return x%3 == 0
	case 3:
		return (x+y)%3 == 0
	case 4:
		return (x/3+y/2)%2 == 0
	case 5:
		return x*y%2+x*y%3 == 0
	case 6:
		return (x*y%2+x*y%3)%2 == 0
	case 7:
		return ((x+y)%2+x*y%3)%2 == 0
	}
	return false
}

// applyMask inverts every data module the mask selects. Applying the same mask
// twice restores the symbol, which is how a reader undoes it.
func (m *Matrix) applyMask(mask int) {
	for row := 0; row < m.size; row++ {
		for col := 0; col < m.size; col++ {
			if !m.isFn(row, col) && maskBit(mask, row, col) {
				m.set(row, col, !m.Dark(row, col))
			}
		}
	}
}

// Penalty weights from the specification. Masking exists to break up module
// patterns a reader could mistake for a finder pattern, and to keep the symbol
// from being mostly one colour; these weights say how much each fault costs.
const (
	penaltyRun       = 3  // a run of five or more same-coloured modules
	penaltyBlock     = 3  // a 2x2 block of one colour
	penaltyFinderish = 40 // a 1:1:3:1:1 run that mimics a finder pattern
	penaltyBalance   = 10 // per 5% that the dark share strays from half
)

// penalty scores a masked symbol. The lowest score wins.
func (m *Matrix) penalty() int {
	n1, n2, n3, n4 := m.penaltyParts()
	return n1 + n2 + n3 + n4
}

// penaltyParts returns the four penalties separately, which is how the
// specification states them and how they are checked in the tests.
func (m *Matrix) penaltyParts() (n1, n2, n3, n4 int) {
	dark := 0

	// Rules 1 and 3, applied along every row and every column.
	for i := 0; i < m.size; i++ {
		row := make([]bool, m.size)
		col := make([]bool, m.size)
		for j := 0; j < m.size; j++ {
			row[j] = m.Dark(i, j)
			col[j] = m.Dark(j, i)
			if row[j] {
				dark++
			}
		}
		n1 += runPenalty(row) + runPenalty(col)
		n3 += finderPenalty(row) + finderPenalty(col)
	}

	// Rule 2: every 2x2 block of a single colour.
	for row := 0; row+1 < m.size; row++ {
		for col := 0; col+1 < m.size; col++ {
			c := m.Dark(row, col)
			if c == m.Dark(row, col+1) && c == m.Dark(row+1, col) && c == m.Dark(row+1, col+1) {
				n2 += penaltyBlock
			}
		}
	}

	// Rule 4: how far the proportion of dark modules strays from one half,
	// in whole steps of 5%.
	total := m.size * m.size
	n4 = abs(dark*20-total*10) / total * penaltyBalance

	return n1, n2, n3, n4
}

// runPenalty charges for each run of five or more same-coloured modules.
func runPenalty(line []bool) int {
	score, run := 0, 1
	for i := 1; i < len(line); i++ {
		if line[i] == line[i-1] {
			run++
			continue
		}
		if run >= 5 {
			score += penaltyRun + run - 5
		}
		run = 1
	}
	if run >= 5 {
		score += penaltyRun + run - 5
	}
	return score
}

// finderCore is the module sequence a reader uses to find the symbol: the
// 1:1:3:1:1 ratio of dark, light, dark, light, dark at the heart of a finder
// pattern. Anywhere else in the symbol it is a hazard, and it counts against
// the mask when four light modules stand on one side of it — or when it meets
// the symbol's edge, where the quiet zone supplies them.
var finderCore = []bool{true, false, true, true, true, false, true}

func finderPenalty(line []bool) int {
	size := len(line)
	score := 0
	for at := 0; at+len(finderCore) <= size; {
		if !matchAt(line, at, finderCore) {
			at++
			continue
		}
		after := at + len(finderCore)
		if at == 0 || at == size-len(finderCore) ||
			allLight(line[max(at-4, 0):at]) || allLight(line[after:min(after+4, size)]) {
			score += penaltyFinderish
			at = after
			continue
		}
		// Not enough light either side. The next occurrence can overlap this
		// one by its three middle modules, so resume there.
		at += 4
	}
	return score
}

func allLight(modules []bool) bool {
	for _, m := range modules {
		if m {
			return false
		}
	}
	return true
}

func matchAt(line []bool, at int, pattern []bool) bool {
	for i, p := range pattern {
		if line[at+i] != p {
			return false
		}
	}
	return true
}

// formatInfo returns the 15-bit format information for a level and mask: five
// bits of data, ten bits of BCH(15,5) error correction, then an XOR with a
// fixed pattern so an all-zero format never reads as blank.
const formatMask = 0b101010000010010

func formatInfo(level Level, mask int) int {
	data := level.formatBits()<<3 | mask
	return (data<<10 | bchRemainder(data, 10, 0b10100110111)) ^ formatMask
}

// versionInfo returns the 18-bit version information written into symbols of
// version 7 and above: six bits of version number and twelve bits of
// BCH(18,6) error correction.
func versionInfo(version int) int {
	return version<<12 | bchRemainder(version, 12, 0b1111100100101)
}

// bchRemainder divides data * x^degree by the generator polynomial over GF(2)
// and returns the remainder.
func bchRemainder(data, degree, generator int) int {
	rem := data << degree
	genBits := bitLen(generator)
	for bitLen(rem) >= genBits {
		rem ^= generator << (bitLen(rem) - genBits)
	}
	return rem
}

func bitLen(v int) int {
	n := 0
	for v > 0 {
		n++
		v >>= 1
	}
	return n
}

// placeFormatInfo writes both copies of the format information, and the
// version information where the version calls for it.
func (m *Matrix) placeFormatInfo() {
	bits := formatInfo(m.Level, m.Mask)
	get := func(i int) bool { return bits>>i&1 == 1 }

	// First copy, around the top-left finder pattern.
	for i := 0; i <= 5; i++ {
		m.setFn(i, 8, get(i))
	}
	m.setFn(7, 8, get(6))
	m.setFn(8, 8, get(7))
	m.setFn(8, 7, get(8))
	for i := 9; i < 15; i++ {
		m.setFn(8, 14-i, get(i))
	}

	// Second copy, split between the bottom-left and top-right corners.
	for i := 0; i < 8; i++ {
		m.setFn(8, m.size-1-i, get(i))
	}
	for i := 8; i < 15; i++ {
		m.setFn(m.size-15+i, 8, get(i))
	}
	m.setFn(m.size-8, 8, true)

	if m.Version >= 7 {
		v := versionInfo(m.Version)
		for i := 0; i < 18; i++ {
			bit := v>>i&1 == 1
			a, b := m.size-11+i%3, i/3
			m.setFn(b, a, bit)
			m.setFn(a, b, bit)
		}
	}
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
