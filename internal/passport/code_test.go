package passport

import (
	"strings"
	"testing"
)

func TestCodeRoundTrip(t *testing.T) {
	k := mustKeypair(t)
	priv, err := ParsePrivateKey(k.Private)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		p    Passport
	}{
		{"the sample", sample()},
		{"non-Latin names", func() Passport {
			p := sample()
			p.WeaverName = "ஆர். சரவணன்"
			return p
		}()},
		{"every field at its limit", maximalPassport()},
		{"no marks", func() Passport {
			p := sample()
			p.Marks = nil
			return p
		}()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := c.p
			p.IssuerPublicKey = k.Public
			sig, err := Sign(p, priv)
			if err != nil {
				t.Fatal(err)
			}
			code, err := EncodeCode(p, sig)
			if err != nil {
				t.Fatal(err)
			}
			back, backSig, err := ParseCode(code)
			if err != nil {
				t.Fatal(err)
			}
			if string(Canonicalise(back)) != string(Canonicalise(p)) {
				t.Error("the passport did not survive the code")
			}
			if string(backSig) != string(sig) {
				t.Error("the signature did not survive the code")
			}
		})
	}
}

// TestCodeStaysInsideTheSymbolsAlphabet is what makes a passport printable at
// the size it is. The symbol's alphanumeric mode packs two characters into
// eleven bits, but only for 45 particular characters; one character outside
// them and the whole symbol falls back to eight bits a character, growing by
// about a tenth in area for no reason.
func TestCodeStaysInsideTheSymbolsAlphabet(t *testing.T) {
	const symbolAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

	k := mustKeypair(t)
	for _, p := range []Passport{sample(), maximalPassport()} {
		sp, problems, _ := Issue(p, k, testNow)
		if len(problems) > 0 {
			t.Fatal(problems)
		}
		payload := QRPayload(sp.Code)
		for i := 0; i < len(payload); i++ {
			if !strings.ContainsRune(symbolAlphabet, rune(payload[i])) {
				t.Fatalf("character %q at position %d of the code is outside the symbol's alphabet", payload[i], i)
			}
		}
		if !strings.HasPrefix(payload, CodePrefix) {
			t.Errorf("the payload does not start with %s", CodePrefix)
		}
	}
}

func TestNormaliseAcceptsHowPeopleActuallyTypeACode(t *testing.T) {
	sp, k := issueSample(t)
	variants := []struct {
		name string
		code string
	}{
		{"as issued", sp.Code},
		{"grouped for printing", Grouped(sp.Code)},
		{"in lower case", strings.ToLower(sp.Code)},
		{"with line breaks", strings.ReplaceAll(Grouped(sp.Code), " ", "\n")},
		{"with tabs", strings.ReplaceAll(Grouped(sp.Code), " ", "\t")},
		{"with dashes between the groups", strings.ReplaceAll(Grouped(sp.Code), " ", "-")},
		{"with underscores", strings.ReplaceAll(Grouped(sp.Code), " ", "_")},
		{"with leading and trailing space", "  " + sp.Code + "  \n"},
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			if got := Normalise(v.code); got != sp.Code {
				t.Errorf("Normalise did not recover the code (got %d characters, want %d)", len(got), len(sp.Code))
			}
			res := VerifyCode(v.code, k.Public, testNow)
			if !res.Pass {
				t.Errorf("a code typed this way failed: %s", res.Reason)
			}
		})
	}
}

func TestGrouped(t *testing.T) {
	sp, _ := issueSample(t)
	grouped := Grouped(sp.Code)
	if !strings.HasPrefix(grouped, CodePrefix) {
		t.Errorf("the grouped form does not start with %s", CodePrefix)
	}
	body := strings.TrimPrefix(grouped, CodePrefix)
	for i, g := range strings.Fields(body) {
		if len(g) > groupSize {
			t.Errorf("group %d is %d characters long, want at most %d", i, len(g), groupSize)
		}
	}
	if Normalise(grouped) != sp.Code {
		t.Error("grouping and normalising are not inverses")
	}
	// Grouping is idempotent through normalisation.
	if Grouped(Normalise(grouped)) != grouped {
		t.Error("grouping an already grouped code changed it")
	}
}

func TestParseCodeRejectsJunk(t *testing.T) {
	sp, _ := issueSample(t)
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", "no code here"},
		{"whitespace only", "   \n ", "no code here"},
		{"no prefix", "ABCDEFGHIJKLMNOP", "starts with"},
		{"the wrong prefix", "GITP2:ABCDEFGH", "starts with"},
		{"characters outside the alphabet", CodePrefix + "ABC019!", "not part of a passport code"},
		{"base32 digits that do not exist", CodePrefix + "ABCD0189", "not part of a passport code"},
		{"too short for a signature", CodePrefix + "AAAAAAAAAAAAAAAA", "too short"},
		{"exactly a signature and nothing else", CodePrefix + strings.Repeat("A", 103), "too short"},
		{"random bytes of the right length", CodePrefix + strings.Repeat("A", 700), "version header"},
		{"the body truncated", sp.Code[:len(sp.Code)-20], "cut short"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := ParseCode(c.in)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}

	t.Run("a signature of the wrong size cannot be packed", func(t *testing.T) {
		if _, err := EncodeCode(sample(), []byte("short")); err == nil {
			t.Error("a 5-byte signature was packed into a code")
		}
	})
}

func TestMaxCodeLenCoversTheLongestPassport(t *testing.T) {
	k := mustKeypair(t)
	sp, problems, _ := Issue(maximalPassport(), k, testNow)
	if len(problems) > 0 {
		t.Fatal(problems)
	}
	if len(sp.Code) > MaxCodeLen() {
		t.Errorf("the longest passport makes a %d character code, over the stated maximum of %d", len(sp.Code), MaxCodeLen())
	}
	if MaxCodeLen()-len(sp.Code) > 16 {
		t.Errorf("the stated maximum of %d is well above the real worst case of %d", MaxCodeLen(), len(sp.Code))
	}
}

func TestEnumValuesAreUsable(t *testing.T) {
	for field, set := range Options() {
		if len(set) == 0 {
			t.Errorf("%s has no values", field)
		}
		codes, names := map[string]bool{}, map[string]bool{}
		for _, v := range set {
			if v.Code == "" || v.Name == "" || v.Label == "" {
				t.Errorf("%s has an incomplete value: %+v", field, v)
			}
			if codes[v.Code] {
				t.Errorf("%s has two values with the code %q", field, v.Code)
			}
			if names[v.Name] {
				t.Errorf("%s has two values named %q", field, v.Name)
			}
			codes[v.Code], names[v.Name] = true, true

			// Both forms, in any case, must resolve to the code.
			for _, in := range []string{v.Code, strings.ToLower(v.Code), v.Name, strings.ToUpper(v.Name)} {
				if got := canonicalCode(set, in); got != v.Code {
					t.Errorf("%s: canonicalCode(%q) = %q, want %q", field, in, got, v.Code)
				}
			}
			if got := label(set, v.Code); got != v.Label {
				t.Errorf("%s: label(%q) = %q", field, v.Code, got)
			}
			if got := name(set, v.Code); got != v.Name {
				t.Errorf("%s: name(%q) = %q", field, v.Code, got)
			}
		}
		// Something that is not a value is left alone, so validation can
		// quote it back.
		if got := canonicalCode(set, "nonsense"); got != "nonsense" {
			t.Errorf("%s: canonicalCode(\"nonsense\") = %q", field, got)
		}
		if got := label(set, "nonsense"); got != "nonsense" {
			t.Errorf("%s: label(\"nonsense\") = %q", field, got)
		}
	}
	if got := MarkNames(); len(got) != 2 {
		t.Errorf("MarkNames() = %v", got)
	}
}

func TestMarksCodeRoundTrip(t *testing.T) {
	cases := []struct {
		name  string
		in    []string
		code  string
		valid bool
	}{
		{"none", nil, MarksNone, true},
		{"the Handloom Mark", []string{"handloom_mark"}, "H", true},
		{"the Silk Mark", []string{"silk_mark"}, "S", true},
		{"both", []string{"handloom_mark", "silk_mark"}, "HS", true},
		{"both, entered the other way round", []string{"silk_mark", "handloom_mark"}, "HS", true},
		{"a duplicate", []string{"silk_mark", "silk_mark"}, "S", true},
		{"none spelled out", []string{"none"}, MarksNone, true},
		{"an empty entry", []string{""}, MarksNone, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cleaned := cleanMarks(c.in)
			if got := marksCode(cleaned); got != c.code {
				t.Fatalf("marksCode(%v) = %q, want %q", c.in, got, c.code)
			}
			back, ok := parseMarksCode(c.code)
			if !ok {
				t.Fatalf("parseMarksCode(%q) refused a code we produced", c.code)
			}
			if marksCode(back) != c.code {
				t.Errorf("the marks did not survive the round trip")
			}
		})
	}

	// A code with two readings would give one claim two signed forms.
	for _, bad := range []string{"SH", "HH", "SS", "X", "HX", "HSH", "", "-H"} {
		if _, ok := parseMarksCode(bad); ok {
			t.Errorf("parseMarksCode(%q) was accepted", bad)
		}
	}
}
