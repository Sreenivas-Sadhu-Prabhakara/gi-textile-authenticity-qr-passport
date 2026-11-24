package qr

import "fmt"

// MinVersion and MaxVersion bound the symbol sizes this encoder produces.
// Version 1 is 21x21 modules; each later version adds 4 modules per side, so
// version 40 is 177x177.
const (
	MinVersion = 1
	MaxVersion = 40
)

// Level is a QR Code error-correction level. Higher levels survive more damage
// to the printed symbol but carry less data in the same number of modules.
// Roughly: L recovers 7% of codewords, M 15%, Q 25%, H 30%.
type Level int

const (
	LevelL Level = iota
	LevelM
	LevelQ
	LevelH
)

// Levels lists the four levels weakest-first, which is also the order in which
// an encoder would trade capacity for robustness.
var Levels = []Level{LevelL, LevelM, LevelQ, LevelH}

func (l Level) String() string {
	switch l {
	case LevelL:
		return "L"
	case LevelM:
		return "M"
	case LevelQ:
		return "Q"
	case LevelH:
		return "H"
	}
	return "?"
}

// Describe names the level and the share of codewords it can lose.
func (l Level) Describe() string {
	switch l {
	case LevelL:
		return "L — recovers about 7% damage"
	case LevelM:
		return "M — recovers about 15% damage"
	case LevelQ:
		return "Q — recovers about 25% damage"
	case LevelH:
		return "H — recovers about 30% damage"
	}
	return "?"
}

// ParseLevel reads a level from its single letter, in either case.
func ParseLevel(s string) (Level, error) {
	switch s {
	case "L", "l":
		return LevelL, nil
	case "M", "m":
		return LevelM, nil
	case "Q", "q":
		return LevelQ, nil
	case "H", "h":
		return LevelH, nil
	}
	return 0, fmt.Errorf("error-correction level %q is not one of L, M, Q, H", s)
}

// formatBits is the two-bit level indicator written into the symbol's format
// information. The values are not in level order: the specification assigns
// M=00, L=01, H=10, Q=11.
func (l Level) formatBits() int {
	switch l {
	case LevelL:
		return 0b01
	case LevelM:
		return 0b00
	case LevelQ:
		return 0b11
	case LevelH:
		return 0b10
	}
	return 0
}

// blockSpec is the error-correction geometry of one version at one level:
// how many error-correction codewords each block carries, and how many blocks
// the codewords are split into.
//
// Everything else about a version's capacity follows from these two numbers
// and from the symbol's geometry, so they are all this table has to hold:
//
//	total codewords = data modules available in the symbol / 8   (geometry)
//	data codewords  = total codewords - ecPerBlock * blocks
//	block sizes     = data codewords spread over blocks, the larger
//	                  blocks last (see DataCodewordsPerBlock)
//
// Deriving the rest means the one number most easily got wrong — a version's
// total capacity — is computed from the module layout rather than transcribed,
// and the table and the layout are cross-checked against each other in the
// tests.
type blockSpec struct {
	ecPerBlock int
	blocks     int
}

// ecSpecs is indexed by version-1 and then by Level (L, M, Q, H). These are
// the error-correction characteristics tabulated in ISO/IEC 18004.
var ecSpecs = [40][4]blockSpec{
	{{7, 1}, {10, 1}, {13, 1}, {17, 1}},      // 1
	{{10, 1}, {16, 1}, {22, 1}, {28, 1}},     // 2
	{{15, 1}, {26, 1}, {18, 2}, {22, 2}},     // 3
	{{20, 1}, {18, 2}, {26, 2}, {16, 4}},     // 4
	{{26, 1}, {24, 2}, {18, 4}, {22, 4}},     // 5
	{{18, 2}, {16, 4}, {24, 4}, {28, 4}},     // 6
	{{20, 2}, {18, 4}, {18, 6}, {26, 5}},     // 7
	{{24, 2}, {22, 4}, {22, 6}, {26, 6}},     // 8
	{{30, 2}, {22, 5}, {20, 8}, {24, 8}},     // 9
	{{18, 4}, {26, 5}, {24, 8}, {28, 8}},     // 10
	{{20, 4}, {30, 5}, {28, 8}, {24, 11}},    // 11
	{{24, 4}, {22, 8}, {26, 10}, {28, 11}},   // 12
	{{26, 4}, {22, 9}, {24, 12}, {22, 16}},   // 13
	{{30, 4}, {24, 9}, {20, 16}, {24, 16}},   // 14
	{{22, 6}, {24, 10}, {30, 12}, {24, 18}},  // 15
	{{24, 6}, {28, 10}, {24, 17}, {30, 16}},  // 16
	{{28, 6}, {28, 11}, {28, 16}, {28, 19}},  // 17
	{{30, 6}, {26, 13}, {28, 18}, {28, 21}},  // 18
	{{28, 7}, {26, 14}, {26, 21}, {26, 25}},  // 19
	{{28, 8}, {26, 16}, {30, 20}, {28, 25}},  // 20
	{{28, 8}, {26, 17}, {28, 23}, {30, 25}},  // 21
	{{28, 9}, {28, 17}, {30, 23}, {24, 34}},  // 22
	{{30, 9}, {28, 18}, {30, 25}, {30, 30}},  // 23
	{{30, 10}, {28, 20}, {30, 27}, {30, 32}}, // 24
	{{26, 12}, {28, 21}, {30, 29}, {30, 35}}, // 25
	{{28, 12}, {28, 23}, {28, 34}, {30, 37}}, // 26
	{{30, 12}, {28, 25}, {30, 34}, {30, 40}}, // 27
	{{30, 13}, {28, 26}, {30, 35}, {30, 42}}, // 28
	{{30, 14}, {28, 28}, {30, 38}, {30, 45}}, // 29
	{{30, 15}, {28, 29}, {30, 40}, {30, 48}}, // 30
	{{30, 16}, {28, 31}, {30, 43}, {30, 51}}, // 31
	{{30, 17}, {28, 33}, {30, 45}, {30, 54}}, // 32
	{{30, 18}, {28, 35}, {30, 48}, {30, 57}}, // 33
	{{30, 19}, {28, 37}, {30, 51}, {30, 60}}, // 34
	{{30, 19}, {28, 38}, {30, 53}, {30, 63}}, // 35
	{{30, 20}, {28, 40}, {30, 56}, {30, 66}}, // 36
	{{30, 21}, {28, 43}, {30, 59}, {30, 70}}, // 37
	{{30, 22}, {28, 45}, {30, 62}, {30, 74}}, // 38
	{{30, 24}, {28, 47}, {30, 65}, {30, 77}}, // 39
	{{30, 25}, {28, 49}, {30, 68}, {30, 81}}, // 40
}

// alignmentCentres is indexed by version-2: the row and column coordinates of
// the alignment pattern centres for versions 2 to 40. Version 1 has none.
var alignmentCentres = [39][]int{
	{6, 18},                        // 2
	{6, 22},                        // 3
	{6, 26},                        // 4
	{6, 30},                        // 5
	{6, 34},                        // 6
	{6, 22, 38},                    // 7
	{6, 24, 42},                    // 8
	{6, 26, 46},                    // 9
	{6, 28, 50},                    // 10
	{6, 30, 54},                    // 11
	{6, 32, 58},                    // 12
	{6, 34, 62},                    // 13
	{6, 26, 46, 66},                // 14
	{6, 26, 48, 70},                // 15
	{6, 26, 50, 74},                // 16
	{6, 30, 54, 78},                // 17
	{6, 30, 56, 82},                // 18
	{6, 30, 58, 86},                // 19
	{6, 34, 62, 90},                // 20
	{6, 28, 50, 72, 94},            // 21
	{6, 26, 50, 74, 98},            // 22
	{6, 30, 54, 78, 102},           // 23
	{6, 28, 54, 80, 106},           // 24
	{6, 32, 58, 84, 110},           // 25
	{6, 30, 58, 86, 114},           // 26
	{6, 34, 62, 90, 118},           // 27
	{6, 26, 50, 74, 98, 122},       // 28
	{6, 30, 54, 78, 102, 126},      // 29
	{6, 26, 52, 78, 104, 130},      // 30
	{6, 30, 56, 82, 108, 134},      // 31
	{6, 34, 60, 86, 112, 138},      // 32
	{6, 30, 58, 86, 114, 142},      // 33
	{6, 34, 62, 90, 118, 146},      // 34
	{6, 30, 54, 78, 102, 126, 150}, // 35
	{6, 24, 50, 76, 102, 128, 154}, // 36
	{6, 28, 54, 80, 106, 132, 158}, // 37
	{6, 32, 58, 84, 110, 136, 162}, // 38
	{6, 26, 54, 82, 110, 138, 166}, // 39
	{6, 30, 58, 86, 114, 142, 170}, // 40
}

// validVersion reports whether v names a symbol version this encoder handles.
func validVersion(v int) bool { return v >= MinVersion && v <= MaxVersion }

// Size returns the side length of a version's symbol in modules, excluding the
// quiet zone.
func Size(version int) int { return 4*version + 17 }

// TotalCodewords returns the number of 8-bit codewords a version's symbol
// holds. It is derived from the layout — the modules left over once the finder
// patterns, separators, timing patterns, alignment patterns, format
// information, version information and the dark module are placed — rather
// than read from a table.
func TotalCodewords(version int) int {
	return dataModules(version) / 8
}

// remainderBits is the number of unused modules at the end of a version's data
// region, which are left light. It too falls out of the layout.
func remainderBits(version int) int {
	return dataModules(version) % 8
}

// dataModules counts the modules available for data and error correction.
func dataModules(version int) int {
	if !validVersion(version) {
		return 0
	}
	return dataModuleCount[version]
}

// DataCodewords returns how many of a version's codewords carry data rather
// than error correction.
func DataCodewords(version int, level Level) int {
	spec := ecSpecs[version-1][level]
	return TotalCodewords(version) - spec.ecPerBlock*spec.blocks
}

// DataBitCapacity returns the number of bits available for the encoded data
// stream, including its mode and character-count header.
func DataBitCapacity(version int, level Level) int {
	return DataCodewords(version, level) * 8
}

// DataCodewordsPerBlock returns the data codeword count of each block, in the
// order the blocks are interleaved.
//
// The specification spreads the data codewords as evenly as the block count
// allows: with d data codewords in b blocks, b - (d mod b) blocks hold
// floor(d/b) codewords and the remaining d mod b blocks hold one more. The
// larger blocks come last.
func DataCodewordsPerBlock(version int, level Level) []int {
	spec := ecSpecs[version-1][level]
	data := DataCodewords(version, level)
	short := data / spec.blocks
	long := data % spec.blocks
	out := make([]int, 0, spec.blocks)
	for i := 0; i < spec.blocks-long; i++ {
		out = append(out, short)
	}
	for i := 0; i < long; i++ {
		out = append(out, short+1)
	}
	return out
}
