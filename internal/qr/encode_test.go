package qr

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// grid renders a symbol as one line per row, for comparing against a fixed
// reference.
func grid(m *Matrix) string {
	var b strings.Builder
	for r := 0; r < m.Size(); r++ {
		for c := 0; c < m.Size(); c++ {
			if m.Dark(r, c) {
				b.WriteByte('#')
			} else {
				b.WriteByte('.')
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// helloWorldV1M is the version 1, level M symbol for "HELLO WORLD" with the
// mask the scoring picks. Two independent QR Code implementations produce this
// same symbol module for module, and it decodes in an ordinary phone scanner,
// so it is frozen here: any change to this encoder that moves a module fails
// this test and has to be justified.
const helloWorldV1M = `#######...#.#.#######
#.....#.###...#.....#
#.###.#...#.#.#.###.#
#.###.#...#.#.#.###.#
#.###.#.#.###.#.###.#
#.....#..###..#.....#
#######.#.#.#.#######
.....................
#.#.#.#..#..#...#..#.
.####...#..#....#...#
...#######.#..#.##...
####.#.##..###.#.###.
.#..####.#.#..###.#.#
........#.#...#...#.#
#######.....#..#.##..
#.....#..##...##.#...
#.###.#.##..#.#######
#.###.#...##.#.#...#.
#.###.#.####.###.#..#
#.....#....###...#.##
#######.##.#.###....#
`

func TestEncodeKnownSymbol(t *testing.T) {
	m, err := Encode("HELLO WORLD", LevelM)
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != 1 {
		t.Errorf("version = %d, want 1", m.Version)
	}
	if m.Level != LevelM {
		t.Errorf("level = %s, want M", m.Level)
	}
	if m.Mask != 0 {
		t.Errorf("mask = %d, want 0", m.Mask)
	}
	if got := grid(m); got != helloWorldV1M {
		t.Errorf("symbol does not match the reference.\ngot:\n%s\nwant:\n%s", got, helloWorldV1M)
	}
}

// TestEncodeFrozenSymbols pins a spread of symbols by digest: both modes, the
// three widths of character-count indicator, versions with and without
// version information blocks, every error-correction level, and payloads that
// exactly fill a symbol as well as payloads that leave it to be padded. Each
// was checked module for module against an independent implementation.
func TestEncodeFrozenSymbols(t *testing.T) {
	cases := []struct {
		name       string
		payload    string
		level      Level
		minVersion int
		version    int
		mask       int
		digest     string
	}{
		{
			name: "short alphanumeric", payload: "HELLO WORLD", level: LevelM, minVersion: 1,
			version: 1, mask: 0,
			digest: "c40f7e9e0537045b8a1e027e327bbb3ddc61b0d212a639b5b39de80a04a9a651",
		},
		{
			name: "short byte", payload: "hello world", level: LevelH, minVersion: 1,
			version: 2, mask: 2,
			digest: "8fd7e539e29a0220f3315fdf0353d4a23707112382d6eb9c454e2e11722bfa5a",
		},
		{
			name: "version information block", payload: strings.Repeat("GITP1:ABCDEFGH234567", 5), level: LevelQ, minVersion: 7,
			version: 7, mask: 1,
			digest: "209baef30ebff3a738da3b6e34f92f905f86834289841c0f782dbee0f787723a",
		},
		{
			name: "sixteen-bit character count", payload: strings.Repeat("the quick brown fox; ", 10), level: LevelM, minVersion: 10,
			version: 10, mask: 2,
			digest: "a907242d47dfaa5c8a596c5446088aeb3973956ed2b4cbef0688e21477e0f4c8",
		},
		{
			name: "largest symbol, filled", payload: strings.Repeat("A1B2C3D4E5", 429), level: LevelL, minVersion: 40,
			version: 40, mask: 2,
			digest: "6c21043fdae7a54ab4dff8cf521a29d9d92df51985da1d239ba568bbff06ede1",
		},
		{
			name: "high version, heaviest correction", payload: strings.Repeat("~zyx{}|", 89), level: LevelH, minVersion: 27,
			version: 27, mask: 1,
			digest: "6f460a6d8574faa58f17bf643058b7531b60133e5d48d9e95474c59b50e28b67",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := EncodeVersion(c.payload, c.level, c.minVersion)
			if err != nil {
				t.Fatal(err)
			}
			if m.Version != c.version {
				t.Errorf("version = %d, want %d", m.Version, c.version)
			}
			if m.Mask != c.mask {
				t.Errorf("mask = %d, want %d", m.Mask, c.mask)
			}
			sum := sha256.Sum256([]byte(grid(m)))
			if got := hex.EncodeToString(sum[:]); got != c.digest {
				t.Errorf("symbol digest = %s, want %s", got, c.digest)
			}
		})
	}
}

func TestModeSelection(t *testing.T) {
	cases := []struct {
		in   string
		want Mode
	}{
		{"HELLO", ModeAlphanumeric},
		{"0123456789", ModeAlphanumeric},
		{"GITP1:ABC-234567 $%*+-./:", ModeAlphanumeric},
		{"hello", ModeByte},
		{"HELLO!", ModeByte},
		{"HELLO_WORLD", ModeByte},
		{"नमस्ते", ModeByte},
		{"", ModeAlphanumeric},
	}
	for _, c := range cases {
		if got := BestMode(c.in); got != c.want {
			t.Errorf("BestMode(%q) = %s, want %s", c.in, got, c.want)
		}
		if got := CanEncodeAlphanumeric(c.in); got != (c.want == ModeAlphanumeric) {
			t.Errorf("CanEncodeAlphanumeric(%q) = %v", c.in, got)
		}
	}
}

func TestEncodePicksTheSmallestSymbolThatFits(t *testing.T) {
	for _, level := range Levels {
		for v := MinVersion; v <= MaxVersion; v++ {
			capacity := Capacity(v, level, ModeAlphanumeric)
			payload := strings.Repeat("A", capacity)
			m, err := Encode(payload, level)
			if err != nil {
				t.Fatalf("level %s version %d: %v", level, v, err)
			}
			if m.Version > v {
				t.Errorf("level %s: %d characters went into version %d, but version %d holds %d",
					level, capacity, m.Version, v, capacity)
			}
			// One character more than this version holds must not fit it.
			if v < MaxVersion {
				bigger, err := Encode(payload+"A", level)
				if err != nil {
					t.Fatalf("level %s version %d plus one: %v", level, v, err)
				}
				if bigger.Version <= m.Version && Capacity(m.Version, level, ModeAlphanumeric) < capacity+1 {
					t.Errorf("level %s: %d characters stayed in version %d", level, capacity+1, bigger.Version)
				}
			}
		}
	}
}

func TestEncodeRefusesWhatCannotFit(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		level   Level
		min     int
		want    string
	}{
		{"empty", "", LevelM, 1, "nothing to encode"},
		{"beyond the largest symbol", strings.Repeat("A", MaxCapacity(LevelL, ModeAlphanumeric)+1), LevelL, 1, "does not fit"},
		{"beyond the largest symbol at level H", strings.Repeat("x", MaxCapacity(LevelH, ModeByte)+1), LevelH, 1, "does not fit"},
		{"version floor above the largest", "A", LevelM, 41, "largest symbol"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := EncodeVersion(c.payload, c.level, c.min)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

func TestEncodeMaskRejectsBadMask(t *testing.T) {
	for _, mask := range []int{-1, 8, 99} {
		if _, err := EncodeMask("HELLO", LevelM, 1, mask); err == nil {
			t.Errorf("mask %d was accepted", mask)
		}
	}
	for mask := 0; mask < 8; mask++ {
		m, err := EncodeMask("HELLO", LevelM, 1, mask)
		if err != nil {
			t.Fatalf("mask %d: %v", mask, err)
		}
		if m.Mask != mask {
			t.Errorf("asked for mask %d, got %d", mask, m.Mask)
		}
		got, level, gotMask, err := Decode(m)
		if err != nil {
			t.Fatalf("mask %d: %v", mask, err)
		}
		if got != "HELLO" || level != LevelM || gotMask != mask {
			t.Errorf("mask %d: read back %q level %s mask %d", mask, got, level, gotMask)
		}
	}
}

func TestFunctionPatternsArePlaced(t *testing.T) {
	for _, v := range []int{1, 2, 6, 7, 14, 40} {
		m := newMatrix(v)
		size := Size(v)

		// The three finder patterns: a dark 7x7 border, a light ring, a dark
		// 3x3 centre.
		for _, corner := range [][2]int{{0, 0}, {0, size - 7}, {size - 7, 0}} {
			for dr := 0; dr < 7; dr++ {
				for dc := 0; dc < 7; dc++ {
					want := max(abs(dr-3), abs(dc-3)) != 2
					if got := m.Dark(corner[0]+dr, corner[1]+dc); got != want {
						t.Fatalf("version %d: finder pattern at %v is wrong at (%d,%d)", v, corner, dr, dc)
					}
				}
			}
		}

		// The timing patterns alternate and are dark at even coordinates.
		for i := 8; i < size-8; i++ {
			if m.Dark(6, i) != (i%2 == 0) || m.Dark(i, 6) != (i%2 == 0) {
				t.Fatalf("version %d: timing pattern is wrong at %d", v, i)
			}
		}

		// The bottom-right corner of the data region is never a function
		// module, and the three finder corners always are.
		if m.isFn(size-1, size-1) {
			t.Errorf("version %d: the bottom-right module should carry data", v)
		}
		if !m.isFn(0, 0) || !m.isFn(0, size-1) || !m.isFn(size-1, 0) {
			t.Errorf("version %d: a finder corner is not marked as a function pattern", v)
		}

		// Version 1 has no alignment pattern; every later version has one
		// near the bottom right.
		if v == 1 {
			continue
		}
		centre := alignmentCentres[v-2][len(alignmentCentres[v-2])-1]
		if !m.Dark(centre, centre) || m.Dark(centre, centre+1) {
			t.Errorf("version %d: alignment pattern at (%d,%d) is wrong", v, centre, centre)
		}
	}
}

func TestMaskConditions(t *testing.T) {
	cases := []struct {
		mask, row, col int
		want           bool
	}{
		{0, 0, 0, true}, {0, 0, 1, false}, {0, 1, 1, true},
		{1, 0, 5, true}, {1, 1, 5, false},
		{2, 3, 0, true}, {2, 3, 1, false}, {2, 3, 3, true},
		{3, 0, 0, true}, {3, 1, 2, true}, {3, 1, 1, false},
		{4, 0, 0, true}, {4, 2, 0, false}, {4, 0, 3, false},
		{5, 0, 0, true}, {5, 1, 1, false}, {5, 2, 3, true},
		{6, 0, 0, true}, {6, 1, 1, true}, {6, 1, 3, false},
		{7, 0, 0, true}, {7, 0, 1, false}, {7, 1, 1, false},
		{9, 0, 0, false},
	}
	for _, c := range cases {
		if got := maskBit(c.mask, c.row, c.col); got != c.want {
			t.Errorf("maskBit(%d, %d, %d) = %v, want %v", c.mask, c.row, c.col, got, c.want)
		}
	}
}

func TestMaskIsItsOwnInverse(t *testing.T) {
	for mask := 0; mask < 8; mask++ {
		m := newMatrix(5)
		before := grid(m)
		m.applyMask(mask)
		if grid(m) == before {
			t.Errorf("mask %d changed nothing", mask)
		}
		m.applyMask(mask)
		if grid(m) != before {
			t.Errorf("mask %d applied twice did not restore the symbol", mask)
		}
	}
}

func TestPenaltyRules(t *testing.T) {
	line := func(s string) []bool {
		out := make([]bool, len(s))
		for i := 0; i < len(s); i++ {
			out[i] = s[i] == '#'
		}
		return out
	}

	t.Run("runs of five or more", func(t *testing.T) {
		cases := []struct {
			in   string
			want int
		}{
			{"", 0},
			{"####", 0},
			{"#####", penaltyRun},
			{"######", penaltyRun + 1},
			{"#########", penaltyRun + 4},
			{".....#####", penaltyRun * 2},
			{"#####.....", penaltyRun * 2},
			{"#.#.#.#.#.", 0},
		}
		for _, c := range cases {
			if got := runPenalty(line(c.in)); got != c.want {
				t.Errorf("runPenalty(%q) = %d, want %d", c.in, got, c.want)
			}
		}
	})

	t.Run("finder-like patterns", func(t *testing.T) {
		cases := []struct {
			in   string
			want int
		}{
			// At the start or the end of a line the quiet zone supplies the
			// light modules, so the bare ratio counts.
			{"#.###.#", penaltyFinderish},
			{"##.###.#", penaltyFinderish},
			{"###.###.####", 0},
			{"....#.###.#", penaltyFinderish},
			{"#.###.#....", penaltyFinderish},
			{"##.###.#....", penaltyFinderish},
			{"###########", 0},
			{"", 0},
		}
		for _, c := range cases {
			if got := finderPenalty(line(c.in)); got != c.want {
				t.Errorf("finderPenalty(%q) = %d, want %d", c.in, got, c.want)
			}
		}
	})

	t.Run("a real symbol scores on every rule", func(t *testing.T) {
		m, err := Encode(strings.Repeat("GITP1:ABCDEF234567", 8), LevelM)
		if err != nil {
			t.Fatal(err)
		}
		n1, n2, n3, n4 := m.penaltyParts()
		if n1 <= 0 || n2 <= 0 || n3 <= 0 {
			t.Errorf("penalties = %d, %d, %d, %d; the first three should all be positive on a real symbol", n1, n2, n3, n4)
		}
		if n4 < 0 || n4%penaltyBalance != 0 {
			t.Errorf("the balance penalty %d is not a multiple of %d", n4, penaltyBalance)
		}
		if m.penalty() != n1+n2+n3+n4 {
			t.Error("the total penalty is not the sum of its parts")
		}
	})

	t.Run("the chosen mask is the lowest scoring one", func(t *testing.T) {
		payload := strings.Repeat("GITP1:ABCDEF234567", 8)
		m, err := Encode(payload, LevelM)
		if err != nil {
			t.Fatal(err)
		}
		// Rebuild each candidate the way the encoder scores them: masked, but
		// with the format information not yet written.
		cw, err := codewords(payload, m.Version, LevelM, BestMode(payload))
		if err != nil {
			t.Fatal(err)
		}
		best, bestScore := -1, -1
		for mask := 0; mask < 8; mask++ {
			cand := newMatrix(m.Version)
			cand.placeCodewords(cw)
			cand.applyMask(mask)
			if score := cand.penalty(); bestScore < 0 || score < bestScore {
				best, bestScore = mask, score
			}
		}
		if m.Mask != best {
			t.Errorf("encoder chose mask %d, lowest penalty is mask %d", m.Mask, best)
		}
	})
}
