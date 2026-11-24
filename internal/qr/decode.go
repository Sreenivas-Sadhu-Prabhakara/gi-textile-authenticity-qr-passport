package qr

import (
	"errors"
	"fmt"
)

// Reading a symbol back. This is not a camera scanner — it takes a module grid
// that is already square and correctly oriented, which is what the encoder
// produces and what a rendered image of it yields.
//
// It is here so the encoder can be held to account: a symbol that cannot be
// read back, with its level and mask recovered from the symbol itself rather
// than remembered, is a symbol no scanner would read either. The tool exposes
// it as a self-check so whoever is about to print five hundred tags can
// confirm the generator works on their own machine first.

// FromModules builds a symbol from a raw module grid, true meaning dark. The
// grid must be square and a valid symbol size; the function patterns are
// reconstructed from the version that size implies.
func FromModules(rows [][]bool) (*Matrix, error) {
	size := len(rows)
	if size == 0 {
		return nil, errors.New("the module grid is empty")
	}
	for i, r := range rows {
		if len(r) != size {
			return nil, fmt.Errorf("row %d has %d modules, but the grid is %d wide", i, len(r), size)
		}
	}
	if (size-17)%4 != 0 {
		return nil, fmt.Errorf("a %dx%d grid is not a QR Code symbol size", size, size)
	}
	version := (size - 17) / 4
	if !validVersion(version) {
		return nil, fmt.Errorf("a %dx%d grid would be version %d, outside versions %d to %d",
			size, size, version, MinVersion, MaxVersion)
	}
	m := newMatrix(version)
	for r := 0; r < size; r++ {
		for c := 0; c < size; c++ {
			m.set(r, c, rows[r][c])
		}
	}
	return m, nil
}

// readFormatInfo recovers the error-correction level and mask from the
// symbol's own format information, using whichever of the two copies is
// closest to a legal value. The format bits carry BCH(15,5) error correction,
// so a copy with up to three wrong bits still names its level and mask.
func (m *Matrix) readFormatInfo() (Level, int, error) {
	copies := []int{0, 0}
	get := func(row, col int) int {
		if m.Dark(row, col) {
			return 1
		}
		return 0
	}
	for i := 0; i <= 5; i++ {
		copies[0] |= get(i, 8) << i
	}
	copies[0] |= get(7, 8) << 6
	copies[0] |= get(8, 8) << 7
	copies[0] |= get(8, 7) << 8
	for i := 9; i < 15; i++ {
		copies[0] |= get(8, 14-i) << i
	}
	for i := 0; i < 8; i++ {
		copies[1] |= get(8, m.size-1-i) << i
	}
	for i := 8; i < 15; i++ {
		copies[1] |= get(m.size-15+i, 8) << i
	}

	bestLevel, bestMask, bestDistance := LevelL, 0, 16
	for _, raw := range copies {
		for _, level := range Levels {
			for mask := 0; mask < 8; mask++ {
				if d := hamming15(raw, formatInfo(level, mask)); d < bestDistance {
					bestLevel, bestMask, bestDistance = level, mask, d
				}
			}
		}
	}
	if bestDistance > 3 {
		return 0, 0, errors.New("the symbol's format information is unreadable: neither copy is close to a legal value")
	}
	return bestLevel, bestMask, nil
}

func hamming15(a, b int) int {
	n := 0
	for i := 0; i < 15; i++ {
		if (a>>i)&1 != (b>>i)&1 {
			n++
		}
	}
	return n
}

// readCodewords walks the same zigzag the encoder wrote, undoing the mask.
func (m *Matrix) readCodewords(mask int) []byte {
	total := TotalCodewords(m.Version)
	out := make([]byte, total)
	bit := 0
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
				if m.isFn(row, col) || bit >= total*8 {
					continue
				}
				dark := m.Dark(row, col)
				if maskBit(mask, row, col) {
					dark = !dark
				}
				if dark {
					out[bit/8] |= 1 << (7 - bit%8)
				}
				bit++
			}
		}
	}
	return out
}

// Decode reads a symbol back to the text it carries. It reports the level and
// mask it found in the symbol, not what any caller claimed.
func Decode(m *Matrix) (text string, level Level, mask int, err error) {
	level, mask, err = m.readFormatInfo()
	if err != nil {
		return "", 0, 0, err
	}

	interleaved := m.readCodewords(mask)

	// Undo the interleaving.
	spec := ecSpecs[m.Version-1][level]
	sizes := DataCodewordsPerBlock(m.Version, level)
	dataBlocks := make([][]byte, len(sizes))
	for i := range dataBlocks {
		dataBlocks[i] = make([]byte, 0, sizes[i])
	}
	at := 0
	for i := 0; i < sizes[len(sizes)-1]; i++ {
		for b := range dataBlocks {
			if i < sizes[b] {
				dataBlocks[b] = append(dataBlocks[b], interleaved[at])
				at++
			}
		}
	}
	ecBlocks := make([][]byte, len(sizes))
	for i := range ecBlocks {
		ecBlocks[i] = make([]byte, spec.ecPerBlock)
	}
	for i := 0; i < spec.ecPerBlock; i++ {
		for b := range ecBlocks {
			ecBlocks[b][i] = interleaved[at]
			at++
		}
	}

	// Every block must be an intact Reed-Solomon codeword. Nothing here tries
	// to repair one: a passport read out of a damaged symbol must be refused,
	// not guessed at.
	var data []byte
	for i := range dataBlocks {
		codeword := append(append([]byte{}, dataBlocks[i]...), ecBlocks[i]...)
		for _, s := range rsSyndromes(codeword, spec.ecPerBlock) {
			if s != 0 {
				return "", 0, 0, fmt.Errorf("block %d of %d is damaged: its error-correction codewords do not match its data", i+1, len(dataBlocks))
			}
		}
		data = append(data, dataBlocks[i]...)
	}

	text, err = decodeDataStream(data, m.Version)
	if err != nil {
		return "", 0, 0, err
	}
	return text, level, mask, nil
}

// bitReader reads the data stream most-significant-bit first.
type bitReader struct {
	data []byte
	at   int
}

func (r *bitReader) read(n int) (int, error) {
	if r.at+n > len(r.data)*8 {
		return 0, errors.New("the data stream ends in the middle of a value")
	}
	v := 0
	for i := 0; i < n; i++ {
		bit := r.data[r.at/8] >> (7 - r.at%8) & 1
		v = v<<1 | int(bit)
		r.at++
	}
	return v, nil
}

// decodeDataStream reads the mode, the character count and the characters.
func decodeDataStream(data []byte, version int) (string, error) {
	r := &bitReader{data: data}
	indicator, err := r.read(4)
	if err != nil {
		return "", err
	}
	var mode Mode
	switch indicator {
	case 0b0010:
		mode = ModeAlphanumeric
	case 0b0100:
		mode = ModeByte
	case 0b0000:
		return "", errors.New("the symbol carries no data")
	case 0b0001:
		return "", errors.New("the symbol is in numeric mode, which this reader does not implement")
	case 0b1000:
		return "", errors.New("the symbol is in kanji mode, which this reader does not implement")
	default:
		return "", fmt.Errorf("mode indicator %04b is not one this reader implements", indicator)
	}

	count, err := r.read(mode.countBits(version))
	if err != nil {
		return "", err
	}
	need := count * 8
	if mode == ModeAlphanumeric {
		need = count/2*11 + count%2*6
	}
	if r.at+need > len(data)*8 {
		return "", fmt.Errorf("the symbol claims %d characters, which need %d bits, more than the %d bits left in its %d data codewords",
			count, need, len(data)*8-r.at, len(data))
	}

	out := make([]byte, 0, count)
	if mode == ModeByte {
		for i := 0; i < count; i++ {
			v, err := r.read(8)
			if err != nil {
				return "", err
			}
			out = append(out, byte(v))
		}
		return string(out), nil
	}
	for i := 0; i < count; i += 2 {
		if i+1 == count {
			v, err := r.read(6)
			if err != nil {
				return "", err
			}
			if v >= len(alphanumericChars) {
				return "", fmt.Errorf("alphanumeric value %d is out of range", v)
			}
			out = append(out, alphanumericChars[v])
			break
		}
		v, err := r.read(11)
		if err != nil {
			return "", err
		}
		if v >= 45*45 {
			return "", fmt.Errorf("alphanumeric pair %d is out of range", v)
		}
		out = append(out, alphanumericChars[v/45], alphanumericChars[v%45])
	}
	return string(out), nil
}
