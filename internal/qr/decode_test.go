package qr

import (
	"strings"
	"testing"
)

// TestRoundTripEveryVersionAndLevel fills every version at every level to
// capacity, in both implemented modes, and reads the symbol back. The level
// and the mask come out of the symbol's own format information rather than
// being remembered, so this exercises the whole chain: encoding, padding,
// block splitting, error correction, interleaving, module placement, masking
// and the format bits.
func TestRoundTripEveryVersionAndLevel(t *testing.T) {
	alnum := "ABCDEFGHIJ0123456789 $%*+-./:ZYXWVUTSRQ"
	bytes := "abcdefghij0123456789~!@#^&(){}[]|\\\"'<>,?zyx"
	for v := MinVersion; v <= MaxVersion; v++ {
		for _, level := range Levels {
			for _, base := range []string{alnum, bytes} {
				mode := BestMode(base)
				capacity := Capacity(v, level, mode)
				payload := strings.Repeat(base, capacity/len(base)+1)[:capacity]

				m, err := EncodeVersion(payload, level, v)
				if err != nil {
					t.Fatalf("version %d level %s %s: %v", v, level, mode, err)
				}
				if m.Version != v {
					t.Fatalf("version %d level %s %s: encoded as version %d", v, level, mode, m.Version)
				}
				got, gotLevel, gotMask, err := Decode(m)
				if err != nil {
					t.Fatalf("version %d level %s %s: %v", v, level, mode, err)
				}
				if got != payload {
					t.Fatalf("version %d level %s %s: read back %d of %d characters", v, level, mode, len(got), len(payload))
				}
				if gotLevel != level {
					t.Fatalf("version %d level %s: read back level %s", v, level, gotLevel)
				}
				if gotMask != m.Mask {
					t.Fatalf("version %d level %s: read back mask %d, want %d", v, level, gotMask, m.Mask)
				}
			}
		}
	}
}

func TestRoundTripShortPayloads(t *testing.T) {
	cases := []string{
		"A",
		"AB",
		"GITP1:A",
		"HELLO WORLD",
		"0",
		"x",
		"a longer sentence with spaces and punctuation: yes.",
		strings.Repeat("GITP1:ABCDEFGHIJKLMNOP234567", 20),
		"कांजीवरम",
	}
	for _, payload := range cases {
		for _, level := range Levels {
			m, err := Encode(payload, level)
			if err != nil {
				t.Fatalf("%q at level %s: %v", payload, level, err)
			}
			got, gotLevel, _, err := Decode(m)
			if err != nil {
				t.Fatalf("%q at level %s: %v", payload, level, err)
			}
			if got != payload {
				t.Errorf("%q at level %s came back as %q", payload, level, got)
			}
			if gotLevel != level {
				t.Errorf("%q: level came back as %s, want %s", payload, gotLevel, level)
			}
		}
	}
}

func TestDamagedSymbolIsRefusedNotGuessed(t *testing.T) {
	payload := "GITP1:ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	m, err := Encode(payload, LevelM)
	if err != nil {
		t.Fatal(err)
	}

	// Flip one data module at a time. Every flip corrupts a codeword, so the
	// read must fail rather than return something that looks like a passport.
	flipped := 0
	for row := 0; row < m.Size(); row++ {
		for col := 0; col < m.Size(); col++ {
			if m.isFn(row, col) {
				continue
			}
			damaged := m.clone()
			damaged.set(row, col, !damaged.Dark(row, col))
			got, _, _, err := Decode(damaged)
			if err == nil && got == payload {
				t.Fatalf("flipping the module at (%d,%d) went unnoticed", row, col)
			}
			flipped++
			if flipped > 40 {
				return
			}
		}
	}
	if flipped == 0 {
		t.Fatal("no data modules were found to flip")
	}
}

func TestFormatInformationSurvivesSomeDamage(t *testing.T) {
	m, err := Encode("HELLO WORLD", LevelQ)
	if err != nil {
		t.Fatal(err)
	}
	// The format information is written twice and carries BCH correction, so
	// damaging one copy still leaves the level and mask readable.
	damaged := m.clone()
	for i := 0; i <= 2; i++ {
		damaged.set(i, 8, !damaged.Dark(i, 8))
	}
	level, mask, err := damaged.readFormatInfo()
	if err != nil {
		t.Fatalf("three wrong bits in one copy made the format unreadable: %v", err)
	}
	if level != LevelQ || mask != m.Mask {
		t.Errorf("read level %s mask %d, want %s and %d", level, mask, LevelQ, m.Mask)
	}

	// Wrecking both copies must be reported, not guessed at.
	wrecked := m.clone()
	for i := 0; i <= 8; i++ {
		if i == 6 {
			continue
		}
		wrecked.set(i, 8, true)
		wrecked.set(8, i, true)
	}
	for i := 0; i < 8; i++ {
		wrecked.set(8, wrecked.Size()-1-i, true)
		wrecked.set(wrecked.Size()-1-i, 8, true)
	}
	if _, _, err := wrecked.readFormatInfo(); err == nil {
		t.Error("a symbol with both format copies wrecked was read anyway")
	}
}

func TestFromModulesRejectsJunk(t *testing.T) {
	square := func(n int) [][]bool {
		out := make([][]bool, n)
		for i := range out {
			out[i] = make([]bool, n)
		}
		return out
	}
	cases := []struct {
		name string
		in   [][]bool
		want string
	}{
		{"empty", nil, "empty"},
		{"not square", [][]bool{{true, false}, {true}}, "has 1 modules"},
		{"not a symbol size", square(22), "not a QR Code symbol size"},
		{"beyond version 40", square(Size(41)), "outside versions"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := FromModules(c.in)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}

	// A well-formed grid must survive the trip.
	m, err := Encode("GITP1:ABCDEF", LevelM)
	if err != nil {
		t.Fatal(err)
	}
	rows := make([][]bool, m.Size())
	for r := range rows {
		rows[r] = make([]bool, m.Size())
		for c := range rows[r] {
			rows[r][c] = m.Dark(r, c)
		}
	}
	back, err := FromModules(rows)
	if err != nil {
		t.Fatal(err)
	}
	if got, _, _, err := Decode(back); err != nil || got != "GITP1:ABCDEF" {
		t.Errorf("rebuilt symbol read back as %q, %v", got, err)
	}
}

func TestDecodeDataStreamRejectsUnreadableStreams(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"terminator only", []byte{0x00, 0x00}, "no data"},
		{"numeric mode", []byte{0x10, 0x20, 0x0C}, "numeric mode"},
		{"kanji mode", []byte{0x80, 0x20, 0x0C}, "kanji mode"},
		{"unimplemented mode", []byte{0x70, 0x00}, "mode indicator"},
		{"truncated header", []byte{}, "ends in the middle"},
		{"character count beyond the stream", []byte{0x4f, 0xf0}, "characters"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := decodeDataStream(c.data, 1)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

func TestBitReader(t *testing.T) {
	r := &bitReader{data: []byte{0b10110010, 0b01000001}}
	cases := []struct {
		n, want int
	}{
		{1, 1},
		{3, 0b011},
		{4, 0b0010},
		{8, 0b01000001},
	}
	for _, c := range cases {
		got, err := r.read(c.n)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("read(%d) = %b, want %b", c.n, got, c.want)
		}
	}
	if _, err := r.read(1); err == nil {
		t.Error("reading past the end should fail")
	}
}
