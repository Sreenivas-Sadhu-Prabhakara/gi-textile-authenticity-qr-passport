package qr

import "testing"

// publishedTotalCodewords is the number of codewords in each version's symbol,
// as tabulated in the specification. Here it is a check on arithmetic done the
// other way round: the encoder derives these numbers by counting the modules
// left once the function patterns are placed, so agreement means the module
// layout and the error-correction table describe the same symbol.
var publishedTotalCodewords = [40]int{
	26, 44, 70, 100, 134, 172, 196, 242, 292, 346,
	404, 466, 532, 581, 655, 733, 815, 901, 991, 1085,
	1156, 1258, 1364, 1474, 1588, 1706, 1828, 1921, 2051, 2185,
	2323, 2465, 2611, 2761, 2876, 3034, 3196, 3362, 3532, 3706,
}

// publishedRemainderBits is the number of modules each version has over and
// above a whole number of codewords, which are left light.
var publishedRemainderBits = [40]int{
	0, 7, 7, 7, 7, 7, 0, 0, 0, 0,
	0, 0, 0, 3, 3, 3, 3, 3, 3, 3,
	4, 4, 4, 4, 4, 4, 4, 3, 3, 3,
	3, 3, 3, 3, 0, 0, 0, 0, 0, 0,
}

func TestSymbolGeometry(t *testing.T) {
	cases := []struct {
		version int
		want    int
	}{
		{1, 21}, {2, 25}, {6, 41}, {7, 45}, {10, 57}, {25, 117}, {40, 177},
	}
	for _, c := range cases {
		if got := Size(c.version); got != c.want {
			t.Errorf("Size(%d) = %d, want %d", c.version, got, c.want)
		}
	}
}

func TestTotalCodewordsMatchPublishedTable(t *testing.T) {
	for v := MinVersion; v <= MaxVersion; v++ {
		if got, want := TotalCodewords(v), publishedTotalCodewords[v-1]; got != want {
			t.Errorf("version %d holds %d codewords by the module count, published table says %d", v, got, want)
		}
		if got, want := remainderBits(v), publishedRemainderBits[v-1]; got != want {
			t.Errorf("version %d has %d remainder bits by the module count, published table says %d", v, got, want)
		}
	}
}

func TestBlockStructureIsConsistent(t *testing.T) {
	for v := MinVersion; v <= MaxVersion; v++ {
		for _, level := range Levels {
			spec := ecSpecs[v-1][level]
			data := DataCodewords(v, level)
			if data <= 0 {
				t.Fatalf("version %d level %s has %d data codewords", v, level, data)
			}
			if got := data + spec.ecPerBlock*spec.blocks; got != TotalCodewords(v) {
				t.Errorf("version %d level %s: %d data + %d error = %d, but the symbol holds %d",
					v, level, data, spec.ecPerBlock*spec.blocks, got, TotalCodewords(v))
			}

			sizes := DataCodewordsPerBlock(v, level)
			if len(sizes) != spec.blocks {
				t.Errorf("version %d level %s: %d block sizes for %d blocks", v, level, len(sizes), spec.blocks)
			}
			sum, smallest, largest := 0, sizes[0], sizes[0]
			for _, n := range sizes {
				sum += n
				smallest = min(smallest, n)
				largest = max(largest, n)
			}
			if sum != data {
				t.Errorf("version %d level %s: block sizes sum to %d, want %d data codewords", v, level, sum, data)
			}
			if largest-smallest > 1 {
				t.Errorf("version %d level %s: block sizes range from %d to %d, which is more than one apart",
					v, level, smallest, largest)
			}
			// The larger blocks come last, which is what the interleaving
			// assumes.
			for i := 1; i < len(sizes); i++ {
				if sizes[i] < sizes[i-1] {
					t.Errorf("version %d level %s: block %d is smaller than block %d", v, level, i, i-1)
				}
			}
			// Error correction must be able to lose at least the share the
			// level promises.
			if spec.ecPerBlock < 7 {
				t.Errorf("version %d level %s: %d error-correction codewords per block is below any level's minimum", v, level, spec.ecPerBlock)
			}
		}
	}
}

// TestCapacityMatchesPublishedTable checks the character capacities against the
// published table. These are the numbers a user would look up, and getting one
// wrong would make the encoder either refuse a payload that fits or produce a
// symbol that overflows.
func TestCapacityMatchesPublishedTable(t *testing.T) {
	cases := []struct {
		version int
		level   Level
		alnum   int
		byteCap int
	}{
		{1, LevelL, 25, 17},
		{1, LevelM, 20, 14},
		{1, LevelQ, 16, 11},
		{1, LevelH, 10, 7},
		{10, LevelL, 395, 271},
		{10, LevelM, 311, 213},
		{10, LevelQ, 221, 151},
		{10, LevelH, 174, 119},
		{40, LevelL, 4296, 2953},
		{40, LevelM, 3391, 2331},
		{40, LevelQ, 2420, 1663},
		{40, LevelH, 1852, 1273},
	}
	for _, c := range cases {
		if got := Capacity(c.version, c.level, ModeAlphanumeric); got != c.alnum {
			t.Errorf("version %d level %s alphanumeric capacity = %d, want %d", c.version, c.level, got, c.alnum)
		}
		if got := Capacity(c.version, c.level, ModeByte); got != c.byteCap {
			t.Errorf("version %d level %s byte capacity = %d, want %d", c.version, c.level, got, c.byteCap)
		}
	}
	if got := Capacity(0, LevelM, ModeByte); got != 0 {
		t.Errorf("Capacity of a version 0 symbol = %d, want 0", got)
	}
	if got := Capacity(41, LevelM, ModeByte); got != 0 {
		t.Errorf("Capacity of a version 41 symbol = %d, want 0", got)
	}
	if got, want := MaxCapacity(LevelL, ModeAlphanumeric), 4296; got != want {
		t.Errorf("MaxCapacity(L, alphanumeric) = %d, want %d", got, want)
	}
}

func TestCapacityRisesWithVersionAndFallsWithLevel(t *testing.T) {
	for v := MinVersion; v < MaxVersion; v++ {
		for _, level := range Levels {
			if Capacity(v+1, level, ModeByte) <= Capacity(v, level, ModeByte) {
				t.Errorf("version %d level %s does not hold more than version %d", v+1, level, v)
			}
		}
		for i := 1; i < len(Levels); i++ {
			if Capacity(v, Levels[i], ModeByte) >= Capacity(v, Levels[i-1], ModeByte) {
				t.Errorf("version %d level %s does not hold less than level %s", v, Levels[i], Levels[i-1])
			}
		}
	}
}

func TestAlignmentPatternCentres(t *testing.T) {
	for v := 2; v <= MaxVersion; v++ {
		centres := alignmentCentres[v-2]
		if centres[0] != 6 {
			t.Errorf("version %d: first alignment centre is %d, want 6", v, centres[0])
		}
		if last := centres[len(centres)-1]; last != Size(v)-7 {
			t.Errorf("version %d: last alignment centre is %d, want %d", v, last, Size(v)-7)
		}
		for i := 1; i < len(centres); i++ {
			if centres[i] <= centres[i-1] {
				t.Errorf("version %d: alignment centres %v are not increasing", v, centres)
			}
		}
		// The specification spaces the centres evenly apart from the first
		// step, and never more than 28 modules apart.
		for i := 2; i < len(centres); i++ {
			if step := centres[i] - centres[i-1]; step != centres[2]-centres[1] {
				t.Errorf("version %d: uneven alignment spacing in %v", v, centres)
			}
		}
	}
}

func TestParseLevel(t *testing.T) {
	cases := []struct {
		in   string
		want Level
		ok   bool
	}{
		{"L", LevelL, true},
		{"m", LevelM, true},
		{"Q", LevelQ, true},
		{"h", LevelH, true},
		{"", 0, false},
		{"X", 0, false},
		{"MM", 0, false},
	}
	for _, c := range cases {
		got, err := ParseLevel(c.in)
		if (err == nil) != c.ok {
			t.Errorf("ParseLevel(%q) error = %v, want ok = %v", c.in, err, c.ok)
			continue
		}
		if c.ok && got != c.want {
			t.Errorf("ParseLevel(%q) = %s, want %s", c.in, got, c.want)
		}
	}
	for _, level := range Levels {
		if round, err := ParseLevel(level.String()); err != nil || round != level {
			t.Errorf("level %s does not survive a round trip through its letter", level)
		}
		if level.Describe() == "?" {
			t.Errorf("level %s has no description", level)
		}
	}
}

func TestFormatAndVersionInformation(t *testing.T) {
	// Published format information values, as written into the symbol after
	// the fixed XOR.
	known := []struct {
		level Level
		mask  int
		want  int
	}{
		{LevelM, 0, 21522},
		{LevelM, 1, 20773},
		{LevelM, 7, 19104},
		{LevelL, 0, 30660},
		{LevelQ, 0, 13663},
		{LevelH, 0, 5769},
	}
	for _, c := range known {
		if got := formatInfo(c.level, c.mask); got != c.want {
			t.Errorf("formatInfo(%s, %d) = %d, want %d", c.level, c.mask, got, c.want)
		}
	}

	// All 32 values must be distinct, and each must be a legal BCH(15,5)
	// codeword once the XOR pattern is undone.
	seen := map[int]string{}
	for _, level := range Levels {
		for mask := 0; mask < 8; mask++ {
			v := formatInfo(level, mask)
			if v>>15 != 0 {
				t.Errorf("formatInfo(%s, %d) = %d does not fit 15 bits", level, mask, v)
			}
			if prev, dup := seen[v]; dup {
				t.Errorf("formatInfo(%s, %d) collides with %s", level, mask, prev)
			}
			seen[v] = level.String()
			if rem := bchRemainder(v^formatMask, 0, 0b10100110111); rem != 0 {
				t.Errorf("formatInfo(%s, %d) is not a BCH codeword (remainder %d)", level, mask, rem)
			}
		}
	}

	// Published version information values.
	for _, c := range []struct{ version, want int }{{7, 31892}, {8, 34236}, {9, 39577}, {40, 167017}} {
		if got := versionInfo(c.version); got != c.want {
			t.Errorf("versionInfo(%d) = %d, want %d", c.version, got, c.want)
		}
	}
	for v := 7; v <= MaxVersion; v++ {
		info := versionInfo(v)
		if info>>18 != 0 {
			t.Errorf("versionInfo(%d) does not fit 18 bits", v)
		}
		if info>>12 != v {
			t.Errorf("versionInfo(%d) does not carry the version in its top six bits", v)
		}
		if rem := bchRemainder(info, 0, 0b1111100100101); rem != 0 {
			t.Errorf("versionInfo(%d) is not a BCH codeword (remainder %d)", v, rem)
		}
	}
}

func TestBchRemainder(t *testing.T) {
	cases := []struct {
		data, degree, generator, want int
	}{
		{0, 10, 0b10100110111, 0},
		{0b00101, 10, 0b10100110111, 0b0011011100},
		{1, 12, 0b1111100100101, 0b111100100101},
	}
	for _, c := range cases {
		if got := bchRemainder(c.data, c.degree, c.generator); got != c.want {
			t.Errorf("bchRemainder(%b, %d, %b) = %b, want %b", c.data, c.degree, c.generator, got, c.want)
		}
	}
}
