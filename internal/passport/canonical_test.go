package passport

import (
	"bytes"
	"strings"
	"testing"
)

// sample is a complete, valid passport, used as the starting point for tests
// that change one thing about it.
func sample() Passport {
	return Clean(Passport{
		Serial:           "KSS-2026-004128",
		GIName:           "Kanchipuram Silk",
		GIRegistrationNo: "GI 00143",
		Role:             "authorised_user",
		RegisterEntryNo:  "AU/143/2019/0217",
		Cluster:          "Kanchipuram Silk Weavers Co-op Society",
		WeaverName:       "R. Saravanan",
		WeaverID:         "HWID-33-004128",
		LoomNo:           "L-27",
		LoomType:         "handloom",
		Article:          "saree",
		WarpFibre:        "silk",
		WeftFibre:        "silk",
		Zari:             "pure_zari",
		LengthCM:         823,
		WidthCM:          120,
		OffLoomDate:      "2026-09-14",
		Marks:            []string{"handloom_mark", "silk_mark"},
		Binding:          "sewn_tag",
		IssuerPublicKey:  "nJLgWJuHoQHVxxtiHWNIoYIh2zIVNk4cCxO2V0O06aY",
	})
}

func TestCanonicalRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		p    Passport
	}{
		{"a complete passport", sample()},
		{"non-Latin script in the names", func() Passport {
			p := sample()
			p.WeaverName = "ஆர். சரவணன்"
			p.Cluster = "काञ्चीपुरम्"
			return p
		}()},
		{"a value holding the encoding's own punctuation", func() Passport {
			p := sample()
			p.LoomNo = "lm=9:x\n"
			p.WeaverID = "a:b=c"
			return p
		}()},
		{"no marks claimed", func() Passport {
			p := sample()
			p.Marks = nil
			return p
		}()},
		{"one mark claimed", func() Passport {
			p := sample()
			p.Marks = []string{"S"}
			return p
		}()},
		{"smallest measurements", func() Passport {
			p := sample()
			p.LengthCM, p.WidthCM = 10, 5
			return p
		}()},
		{"every field at its limit", maximalPassport()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			encoded := Canonicalise(c.p)
			back, err := DecodeCanonical(encoded)
			if err != nil {
				t.Fatalf("decoding what we encoded failed: %v", err)
			}
			if !bytes.Equal(Canonicalise(back), encoded) {
				t.Errorf("the passport did not survive the round trip\ngot:  %q\nwant: %q", Canonicalise(back), encoded)
			}
			// Encoding is deterministic: the same passport twice gives the
			// same bytes, which is what makes a signature reproducible.
			if !bytes.Equal(Canonicalise(c.p), encoded) {
				t.Error("encoding the same passport twice gave different bytes")
			}
		})
	}
}

// TestTwoFieldSplitsCannotShareBytes is the reason the encoding carries a
// length in front of every value. Without it, moving a character from the end
// of one field to the start of the next would leave the signed bytes
// unchanged, and one signature would cover two different passports — a forger
// could re-split a genuine passport and keep its signature.
func TestTwoFieldSplitsCannotShareBytes(t *testing.T) {
	// Each pair below moves one character across the boundary between two
	// fields that sit next to each other in the encoding, which is where the
	// hazard lives.
	cases := []struct {
		name          string
		first, second func(*Passport)
	}{
		{
			name:   "a character moved from the serial to the name",
			first:  func(p *Passport) { p.Serial = "KSS1"; p.GIName = "Silk" },
			second: func(p *Passport) { p.Serial = "KSS"; p.GIName = "1Silk" },
		},
		{
			name:   "a character moved from the register entry to the cluster",
			first:  func(p *Passport) { p.RegisterEntryNo = "AU7"; p.Cluster = "X" },
			second: func(p *Passport) { p.RegisterEntryNo = "AU"; p.Cluster = "7X" },
		},
		{
			name:   "a character moved from the cluster to the weaver",
			first:  func(p *Passport) { p.Cluster = "KANCHIX"; p.WeaverName = "Y" },
			second: func(p *Passport) { p.Cluster = "KANCHI"; p.WeaverName = "XY" },
		},
		{
			name:   "a character moved from the weaver to the weaver's identifier",
			first:  func(p *Passport) { p.WeaverName = "AB"; p.WeaverID = "1" },
			second: func(p *Passport) { p.WeaverName = "A"; p.WeaverID = "B1" },
		},
		{
			name:   "a character moved from the weaver's identifier to the loom",
			first:  func(p *Passport) { p.WeaverID = "ID7"; p.LoomNo = "L27" },
			second: func(p *Passport) { p.WeaverID = "ID"; p.LoomNo = "7L27" },
		},
		{
			name:   "a digit moved between the two measurements",
			first:  func(p *Passport) { p.LengthCM = 821; p.WidthCM = 20 },
			second: func(p *Passport) { p.LengthCM = 82; p.WidthCM = 120 },
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, b := sample(), sample()
			c.first(&a)
			c.second(&b)

			encA, encB := Canonicalise(a), Canonicalise(b)
			if bytes.Equal(encA, encB) {
				t.Fatalf("two different passports encoded to the same bytes:\n%q", encA)
			}

			// And each must decode back to itself, not to the other.
			backA, err := DecodeCanonical(encA)
			if err != nil {
				t.Fatal(err)
			}
			backB, err := DecodeCanonical(encB)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(Canonicalise(backA), encA) || !bytes.Equal(Canonicalise(backB), encB) {
				t.Error("a passport decoded to something other than itself")
			}

			// The reason the lengths are needed: with the values simply run
			// together, these two passports would be indistinguishable.
			if concatenated(a) != concatenated(b) {
				t.Errorf("this case does not demonstrate the hazard: the plain concatenations differ\n%q\n%q",
					concatenated(a), concatenated(b))
			}
		})
	}
}

// concatenated is what a careless encoding would produce: every value run
// together with no lengths. It exists only so the test above can show that the
// two passports it compares really would collide under such an encoding.
func concatenated(p Passport) string {
	var b strings.Builder
	for _, f := range fieldSpecs {
		b.WriteString(f.get(p))
	}
	return b.String()
}

func TestDecodeCanonicalIsStrict(t *testing.T) {
	good := string(Canonicalise(sample()))
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", "version header"},
		{"no header", strings.TrimPrefix(good, CanonicalVersion+"\n"), "version header"},
		{"a later version", strings.Replace(good, "gitp/v1", "gitp/v2", 1), "version header"},
		{"a field removed", strings.Replace(good, "lm=4:L-27\n", "", 1), `field "lm" is missing`},
		{"two fields swapped", swapLines(good, "lt=1:H", "ar=2:SA"), "out of order"},
		{"a length that is too small", strings.Replace(good, "lm=4:L-27", "lm=3:L-27", 1), "does not end where its length says"},
		{"a length that is too large", strings.Replace(good, "lm=4:L-27", "lm=9:L-27", 1), "does not end where its length says"},
		{"a length with a leading zero", strings.Replace(good, "lm=4:L-27", "lm=04:L-27", 1), "leading zero"},
		{"a signed length", strings.Replace(good, "lm=4:L-27", "lm=+4:L-27", 1), "no length prefix"},
		{"a signed measurement", strings.Replace(good, "lc=3:823", "lc=3:+82", 1), "must not carry a sign"},
		{"a length that is not a number", strings.Replace(good, "lm=4:L-27", "lm=xx:L-27", 1), "no length prefix"},
		{"a measurement that is not a number at all", strings.Replace(good, "wc=3:120", "wc=3:1x0", 1), "not a digit"},
		{"no length prefix at all", strings.Replace(good, "lm=4:L-27", "lm=L-27", 1), "no length prefix"},
		{"a field longer than its limit", strings.Replace(good, "lm=4:L-27", "lm=40:"+strings.Repeat("x", 40), 1), "more than the 16 it may hold"},
		{"trailing bytes", good + "zz\n", "extra bytes"},
		{"truncated at the end", good[:len(good)-10], "cut short"},
		{"a measurement that is not a number", strings.Replace(good, "lc=3:823", "lc=3:8x3", 1), "not a digit"},
		{"a marks code that is not one", strings.Replace(good, "mk=2:HS", "mk=2:HX", 1), "not a marks code"},
		{"a marks code out of order", strings.Replace(good, "mk=2:HS", "mk=2:SH", 1), "not a marks code"},
		{"a marks code repeated", strings.Replace(good, "mk=2:HS", "mk=2:HH", 1), "not a marks code"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := DecodeCanonical([]byte(c.in))
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

func swapLines(s, a, b string) string {
	lines := strings.Split(s, "\n")
	ia, ib := -1, -1
	for i, ln := range lines {
		if ln == a {
			ia = i
		}
		if ln == b {
			ib = i
		}
	}
	if ia < 0 || ib < 0 {
		panic("line not found")
	}
	lines[ia], lines[ib] = lines[ib], lines[ia]
	return strings.Join(lines, "\n")
}

func TestCoveredFieldsMatchTheEncoding(t *testing.T) {
	covered := CoveredFields()
	if len(covered) != len(fieldSpecs) {
		t.Fatalf("CoveredFields lists %d fields, the encoding has %d", len(covered), len(fieldSpecs))
	}
	seen := map[string]bool{}
	for i, f := range covered {
		if f.Key != fieldSpecs[i].Key {
			t.Errorf("field %d is %q in the list and %q in the encoding", i, f.Key, fieldSpecs[i].Key)
		}
		if f.Label == "" {
			t.Errorf("field %q has no label", f.Key)
		}
		if seen[f.Key] {
			t.Errorf("field %q appears twice", f.Key)
		}
		seen[f.Key] = true
	}
	// Every field of the struct must be covered. The count is asserted so
	// that adding a field to Passport without adding it here fails the test.
	if len(covered) != 20 {
		t.Errorf("the signature covers %d fields; the passport has 20", len(covered))
	}
}

func TestMaxCanonicalLenIsNotExceeded(t *testing.T) {
	p := maximalPassport()
	if got, limit := len(Canonicalise(p)), MaxCanonicalLen(); got > limit {
		t.Errorf("a passport with every field at its limit comes to %d bytes, over the stated maximum of %d", got, limit)
	}
	// And the stated maximum must be tight enough to be useful: within a few
	// bytes of the real worst case.
	if got, limit := len(Canonicalise(p)), MaxCanonicalLen(); limit-got > 8 {
		t.Errorf("the stated maximum of %d is %d bytes above the real worst case of %d", limit, limit-got, got)
	}
}

// maximalPassport fills every text field to its limit, for the size
// guarantees.
func maximalPassport() Passport {
	p := Passport{
		Role:        "authorised_user",
		LoomType:    "handloom",
		Article:     "saree",
		WarpFibre:   "silk",
		WeftFibre:   "silk",
		Zari:        "pure_zari",
		LengthCM:    10000,
		WidthCM:     300,
		OffLoomDate: "2026-09-14",
		Marks:       []string{"handloom_mark", "silk_mark"},
		Binding:     "sewn_tag",
	}
	for _, f := range fieldSpecs {
		switch f.Key {
		case "sn", "gn", "gr", "en", "cl", "wv", "wi", "lm":
			if err := f.set(&p, strings.Repeat("W", f.maxLen)); err != nil {
				panic(err)
			}
		case "pk":
			p.IssuerPublicKey = strings.Repeat("A", PublicKeyStringLen)
		}
	}
	return Clean(p)
}
