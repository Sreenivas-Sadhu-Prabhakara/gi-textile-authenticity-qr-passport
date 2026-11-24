package qr

import (
	"errors"
	"fmt"
	"strings"
)

// Mode is a QR Code data encoding mode. Two of the four defined modes are
// implemented here:
//
//	alphanumeric — 45 characters (digits, capitals and nine punctuation
//	               marks) at 5.5 bits each;
//	byte         — any byte at 8 bits each.
//
// Numeric mode (3.33 bits per digit) and kanji mode are not implemented.
// A payload of digits therefore encodes in alphanumeric mode, which is correct
// and readable by any scanner but about 40% larger than numeric mode would be.
type Mode int

const (
	ModeAlphanumeric Mode = iota
	ModeByte
)

func (m Mode) String() string {
	if m == ModeAlphanumeric {
		return "alphanumeric"
	}
	return "byte"
}

// modeIndicator is the four-bit code that opens the data stream.
func (m Mode) modeIndicator() int {
	if m == ModeAlphanumeric {
		return 0b0010
	}
	return 0b0100
}

// countBits is the width of the character-count indicator, which widens with
// the symbol version.
func (m Mode) countBits(version int) int {
	switch {
	case version <= 9:
		if m == ModeAlphanumeric {
			return 9
		}
		return 8
	case version <= 26:
		if m == ModeAlphanumeric {
			return 11
		}
		return 16
	default:
		if m == ModeAlphanumeric {
			return 13
		}
		return 16
	}
}

// alphanumericChars is the alphanumeric mode's character set. A character's
// value is its index here.
const alphanumericChars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

// alphanumericValue returns a character's alphanumeric mode value, or -1.
func alphanumericValue(c byte) int {
	return strings.IndexByte(alphanumericChars, c)
}

// CanEncodeAlphanumeric reports whether every character of s is in the
// alphanumeric set, so the shorter encoding can be used.
func CanEncodeAlphanumeric(s string) bool {
	for i := 0; i < len(s); i++ {
		if alphanumericValue(s[i]) < 0 {
			return false
		}
	}
	return true
}

// BestMode returns the smaller of the two implemented encodings for s.
func BestMode(s string) Mode {
	if CanEncodeAlphanumeric(s) {
		return ModeAlphanumeric
	}
	return ModeByte
}

// bitWriter accumulates a bit stream most-significant-bit first.
type bitWriter struct {
	bits []bool
}

func (w *bitWriter) write(value, n int) {
	for i := n - 1; i >= 0; i-- {
		w.bits = append(w.bits, value>>i&1 == 1)
	}
}

func (w *bitWriter) len() int { return len(w.bits) }

// bytes pads the stream to a whole number of bytes with zero bits and returns
// it. The caller has already ensured the length is within capacity.
func (w *bitWriter) bytes() []byte {
	out := make([]byte, (len(w.bits)+7)/8)
	for i, b := range w.bits {
		if b {
			out[i/8] |= 1 << (7 - i%8)
		}
	}
	return out
}

// payloadBits returns the number of bits s occupies in the given mode, not
// counting the mode and character-count header.
func payloadBits(s string, mode Mode) int {
	if mode == ModeByte {
		return len(s) * 8
	}
	return len(s)/2*11 + len(s)%2*6
}

// writePayload appends the encoded characters.
func writePayload(w *bitWriter, s string, mode Mode) error {
	if mode == ModeByte {
		for i := 0; i < len(s); i++ {
			w.write(int(s[i]), 8)
		}
		return nil
	}
	for i := 0; i < len(s); i += 2 {
		hi := alphanumericValue(s[i])
		if hi < 0 {
			return fmt.Errorf("character %q cannot be encoded in alphanumeric mode", s[i])
		}
		if i+1 == len(s) {
			w.write(hi, 6)
			break
		}
		lo := alphanumericValue(s[i+1])
		if lo < 0 {
			return fmt.Errorf("character %q cannot be encoded in alphanumeric mode", s[i+1])
		}
		w.write(hi*45+lo, 11)
	}
	return nil
}

// Capacity returns the greatest number of characters of the given mode that a
// version at a level can carry.
func Capacity(version int, level Level, mode Mode) int {
	if !validVersion(version) {
		return 0
	}
	avail := DataBitCapacity(version, level) - 4 - mode.countBits(version)
	if avail < 0 {
		return 0
	}
	if mode == ModeByte {
		return avail / 8
	}
	n := avail / 11 * 2
	if avail%11 >= 6 {
		n++
	}
	return n
}

// MaxCapacity returns the largest payload this encoder can carry at a level —
// the capacity of version 40.
func MaxCapacity(level Level, mode Mode) int {
	return Capacity(MaxVersion, level, mode)
}

// smallestVersion returns the lowest version at or above minVersion whose
// capacity holds s, or an error naming what would fit.
func smallestVersion(s string, level Level, mode Mode, minVersion int) (int, error) {
	if minVersion < MinVersion {
		minVersion = MinVersion
	}
	if minVersion > MaxVersion {
		return 0, fmt.Errorf("version %d is beyond version %d, the largest symbol", minVersion, MaxVersion)
	}
	for v := minVersion; v <= MaxVersion; v++ {
		if Capacity(v, level, mode) >= len(s) {
			return v, nil
		}
	}
	return 0, fmt.Errorf("a payload of %d %s characters does not fit a version %d symbol at level %s, which holds %d",
		len(s), mode, MaxVersion, level, MaxCapacity(level, mode))
}

// padBytes alternate to fill the unused data codewords. The two values are
// fixed by the specification.
var padBytes = [2]byte{0xEC, 0x11}

// codewords builds the full interleaved codeword sequence for a payload at a
// chosen version and level: the encoded data stream, padded, split into
// blocks, each block's Reed-Solomon codewords computed, and the whole
// interleaved the way a reader expects to find it.
func codewords(s string, version int, level Level, mode Mode) ([]byte, error) {
	w := &bitWriter{}
	w.write(mode.modeIndicator(), 4)
	w.write(len(s), mode.countBits(version))
	if err := writePayload(w, s, mode); err != nil {
		return nil, err
	}

	capacity := DataBitCapacity(version, level)
	if w.len() > capacity {
		return nil, fmt.Errorf("payload needs %d bits, but version %d at level %s holds %d",
			w.len(), version, level, capacity)
	}

	// Terminator: up to four zero bits, then zeros to the next byte boundary.
	terminator := min(4, capacity-w.len())
	w.write(0, terminator)
	if rem := w.len() % 8; rem != 0 {
		w.write(0, 8-rem)
	}

	data := w.bytes()
	for i := 0; len(data) < DataCodewords(version, level); i++ {
		data = append(data, padBytes[i%2])
	}

	// Split into blocks and compute each block's error correction.
	spec := ecSpecs[version-1][level]
	sizes := DataCodewordsPerBlock(version, level)
	dataBlocks := make([][]byte, len(sizes))
	ecBlocks := make([][]byte, len(sizes))
	at := 0
	for i, n := range sizes {
		dataBlocks[i] = data[at : at+n]
		ecBlocks[i] = rsRemainder(dataBlocks[i], spec.ecPerBlock)
		at += n
	}
	if at != len(data) {
		return nil, fmt.Errorf("block sizes sum to %d but there are %d data codewords", at, len(data))
	}

	// Interleave: the first codeword of every block, then the second, and so
	// on, short blocks dropping out as they run dry; then the same across the
	// error-correction blocks.
	out := make([]byte, 0, TotalCodewords(version))
	for i := 0; i < sizes[len(sizes)-1]; i++ {
		for _, b := range dataBlocks {
			if i < len(b) {
				out = append(out, b[i])
			}
		}
	}
	for i := 0; i < spec.ecPerBlock; i++ {
		for _, b := range ecBlocks {
			out = append(out, b[i])
		}
	}
	if len(out) != TotalCodewords(version) {
		return nil, fmt.Errorf("interleaving produced %d codewords, want %d", len(out), TotalCodewords(version))
	}
	return out, nil
}

// Encode returns the smallest symbol that carries s at the given
// error-correction level, with the mask the specification's scoring prefers.
func Encode(s string, level Level) (*Matrix, error) {
	return EncodeVersion(s, level, MinVersion)
}

// EncodeVersion is Encode with a floor on the symbol version, for a caller
// that wants every tag it prints to be the same size.
func EncodeVersion(s string, level Level, minVersion int) (*Matrix, error) {
	if s == "" {
		return nil, errors.New("there is nothing to encode")
	}
	mode := BestMode(s)
	version, err := smallestVersion(s, level, mode, minVersion)
	if err != nil {
		return nil, err
	}
	cw, err := codewords(s, version, level, mode)
	if err != nil {
		return nil, err
	}

	base := newMatrix(version)
	base.Level = level
	base.placeCodewords(cw)

	// Try all eight masks and keep the one with the lowest penalty. The
	// symbol is scored with its format and version information still blank:
	// masking applies to the encoding region only, and the specification's
	// evaluation is of the masked encoding region, not of bits that are fixed
	// afterwards. On a tie the lower mask number wins.
	var best *Matrix
	bestScore := -1
	for mask := 0; mask < 8; mask++ {
		cand := base.clone()
		cand.Mask = mask
		cand.applyMask(mask)
		if score := cand.penalty(); bestScore < 0 || score < bestScore {
			best, bestScore = cand, score
		}
	}
	best.placeFormatInfo()
	return best, nil
}

// EncodeMask is EncodeVersion with the mask chosen by the caller rather than
// by the penalty scoring. It exists so the encoder can be checked against a
// fixed symbol, mask included.
func EncodeMask(s string, level Level, minVersion, mask int) (*Matrix, error) {
	if mask < 0 || mask > 7 {
		return nil, fmt.Errorf("mask %d is not in 0..7", mask)
	}
	mode := BestMode(s)
	version, err := smallestVersion(s, level, mode, minVersion)
	if err != nil {
		return nil, err
	}
	cw, err := codewords(s, version, level, mode)
	if err != nil {
		return nil, err
	}
	m := newMatrix(version)
	m.Level = level
	m.Mask = mask
	m.placeCodewords(cw)
	m.applyMask(mask)
	m.placeFormatInfo()
	return m, nil
}

func (m *Matrix) clone() *Matrix {
	out := &Matrix{Version: m.Version, Level: m.Level, Mask: m.Mask, size: m.size}
	out.dark = make([]bool, len(m.dark))
	out.fn = make([]bool, len(m.fn))
	copy(out.dark, m.dark)
	copy(out.fn, m.fn)
	return out
}
