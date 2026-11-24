package passport

import (
	"strings"
	"testing"
	"time"
)

func TestCheckAcceptsGoodPassports(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Passport)
	}{
		{"the sample", func(p *Passport) {}},
		{"a proprietor rather than an authorised user", func(p *Passport) { p.Role = "proprietor" }},
		{"a cotton dupatta with no marks", func(p *Passport) {
			p.Article = "dupatta"
			p.WarpFibre, p.WeftFibre = "cotton", "cotton"
			p.LengthCM, p.WidthCM = 250, 90
			p.Marks = nil
			p.Zari = "none"
		}},
		{"a Philippine abaca piece", func(p *Passport) {
			p.GIName = "T'nalak"
			p.Article = "yardage"
			p.WarpFibre, p.WeftFibre = "abaca", "abaca"
			p.LengthCM, p.WidthCM = 400, 90
			p.Marks = nil
			p.Zari = "none"
		}},
		{"a piña stole", func(p *Passport) {
			p.Article = "stole"
			p.WarpFibre, p.WeftFibre = "pina", "pina"
			p.LengthCM, p.WidthCM = 180, 50
			p.Marks = nil
			p.Zari = "none"
		}},
		{"a nine-yard saree", func(p *Passport) { p.LengthCM = 880 }},
		{"a powerloom piece claiming nothing", func(p *Passport) {
			p.LoomType = "powerloom"
			p.Marks = nil
		}},
		{"a Silk Mark on pure silk", func(p *Passport) { p.Marks = []string{"silk_mark"} }},
		{"off the loom today", func(p *Passport) { p.OffLoomDate = Today(testNow).Format(DateLayout) }},
		{"off the loom on a leap day", func(p *Passport) { p.OffLoomDate = "2024-02-29" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := sample()
			c.change(&p)
			p = Clean(p)
			if problems, _ := Check(p, testNow); len(problems) > 0 {
				t.Errorf("problems: %v", problems)
			}
		})
	}
}

func TestCheckRefusesBadPassports(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Passport)
		want   string
	}{
		{"no serial", func(p *Passport) { p.Serial = "" }, "Piece serial is missing"},
		{"no geographical indication", func(p *Passport) { p.GIName = "" }, "Geographical indication is missing"},
		{"no registration number", func(p *Passport) { p.GIRegistrationNo = "" }, "GI registration number is missing"},
		{"a placeholder registration number", func(p *Passport) { p.GIRegistrationNo = "TBD" }, "looks like a placeholder"},
		{"a dash for a registration number", func(p *Passport) { p.GIRegistrationNo = "-" }, "looks like a placeholder"},
		{"no register entry", func(p *Passport) { p.RegisterEntryNo = "" }, "Register entry number is missing"},
		{"no cluster", func(p *Passport) { p.Cluster = "" }, "Cluster or society is missing"},
		{"no weaver", func(p *Passport) { p.WeaverName = "" }, "Weaver is missing"},
		{"no loom number", func(p *Passport) { p.LoomNo = "" }, "Loom number is missing"},
		{"no binding", func(p *Passport) { p.Binding = "" }, "Bound to the piece by is missing"},
		{"a weaver name that is too long", func(p *Passport) { p.WeaverName = strings.Repeat("x", 49) }, "the limit is 48"},
		{"a serial that is too long", func(p *Passport) { p.Serial = strings.Repeat("x", 25) }, "the limit is 24"},
		{"a control character in a name", func(p *Passport) { p.WeaverName = "R.\x07Saravanan" }, "control character"},
		{"a role that is not on the register", func(p *Passport) { p.Role = "middleman" }, "is not one of proprietor, authorised_user"},
		{"a loom type that does not exist", func(p *Passport) { p.LoomType = "waterloom" }, "Loom type"},
		{"an article that does not exist", func(p *Passport) { p.Article = "carpet" }, "Article"},
		{"a fibre that does not exist", func(p *Passport) { p.WarpFibre = "unicorn" }, "Warp fibre"},
		{"a binding that does not exist", func(p *Passport) { p.Binding = "sellotape" }, "Bound to the piece by"},

		{"zero length", func(p *Passport) { p.LengthCM = 0 }, "is not a length of cloth"},
		{"negative length", func(p *Passport) { p.LengthCM = -100 }, "is not a length of cloth"},
		{"an absurd length", func(p *Passport) { p.LengthCM = 99999 }, "is not a length of cloth"},
		{"zero width", func(p *Passport) { p.WidthCM = 0 }, "is not a width of cloth"},
		{"an absurd width", func(p *Passport) { p.WidthCM = 400 }, "is not a width of cloth"},

		{"no date", func(p *Passport) { p.OffLoomDate = "" }, "Date off the loom is missing"},
		{"a date that is not a date", func(p *Passport) { p.OffLoomDate = "not a date" }, "written as YYYY-MM-DD"},
		{"a day that does not exist", func(p *Passport) { p.OffLoomDate = "2026-02-30" }, "not a date written as"},
		{"29 February in a common year", func(p *Passport) { p.OffLoomDate = "2026-02-29" }, "not a date written as"},
		{"a date written the Indian way", func(p *Passport) { p.OffLoomDate = "14-09-2026" }, "not a date written as"},
		{"a date without padding", func(p *Passport) { p.OffLoomDate = "2026-9-4" }, "not a date written as"},
		{"a date in the future", func(p *Passport) { p.OffLoomDate = "2026-11-25" }, "has not happened yet"},
		{"a date before the floor", func(p *Passport) { p.OffLoomDate = "1949-12-31" }, "Check the year"},

		{"the Handloom Mark on a powerloom piece", func(p *Passport) { p.LoomType = "powerloom" }, "claims the Handloom Mark but records the piece as"},
		{"the Handloom Mark on a mill piece", func(p *Passport) { p.LoomType = "mill" }, "claims the Handloom Mark"},
		{"the Silk Mark with no silk anywhere", func(p *Passport) {
			p.WarpFibre, p.WeftFibre = "cotton", "cotton"
		}, "claims the Silk Mark but records"},
		{"the Silk Mark on polyester", func(p *Passport) {
			p.WarpFibre, p.WeftFibre = "polyester", "viscose"
			p.Marks = []string{"silk_mark"}
		}, "claims the Silk Mark"},
		{"a public key that cannot be read", func(p *Passport) { p.IssuerPublicKey = "nonsense" }, "Cluster public key"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := sample()
			c.change(&p)
			p = Clean(p)
			problems, _ := Check(p, testNow)
			if len(problems) == 0 {
				t.Fatal("this passport was accepted and should not have been")
			}
			if !strings.Contains(strings.Join(problems, "\n"), c.want) {
				t.Errorf("problems %v do not mention %q", problems, c.want)
			}
		})
	}
}

func TestCheckWarnsWithoutRefusing(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Passport)
		want   string
	}{
		{"a saree far too short for a saree", func(p *Passport) { p.LengthCM = 200 }, "outside the 450 to 900 cm a Saree usually runs"},
		{"a saree far too narrow", func(p *Passport) { p.WidthCM = 60 }, "outside the 100 to 135 cm"},
		{"a dupatta the length of a saree", func(p *Passport) {
			p.Article = "dupatta"
			p.Marks = nil
		}, "outside the 200 to 300 cm a Dupatta usually runs"},
		{"the Silk Mark on a silk and cotton blend", func(p *Passport) {
			p.WeftFibre = "silk_cotton"
		}, "for pure natural silk"},
		{"man-made fibre throughout", func(p *Passport) {
			p.WarpFibre, p.WeftFibre = "polyester", "viscose"
			p.Marks = nil
			p.LoomType = "powerloom"
		}, "is a natural fibre"},
		{"pure zari", func(p *Passport) {}, "zari testing centre"},
		{"a passport not bound to its piece", func(p *Passport) { p.Binding = "not_bound" }, "not bound to the piece"},
		{"a piece more than ten years old", func(p *Passport) { p.OffLoomDate = "2010-01-01" }, "more than ten years ago"},
		{"an article recorded as other", func(p *Passport) {
			p.Article = "other"
			p.LengthCM, p.WidthCM = 60, 60
			p.Marks = nil
		}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := sample()
			c.change(&p)
			p = Clean(p)
			problems, warnings := Check(p, testNow)
			if len(problems) > 0 {
				t.Fatalf("this should warn, not refuse: %v", problems)
			}
			if c.want == "" {
				return
			}
			if !strings.Contains(strings.Join(warnings, "\n"), c.want) {
				t.Errorf("warnings %v do not mention %q", warnings, c.want)
			}
		})
	}
}

func TestValidateIsCheckWithoutWarnings(t *testing.T) {
	p := sample()
	p.LengthCM = 200 // a warning, not a problem
	if got := Validate(Clean(p), testNow); len(got) != 0 {
		t.Errorf("Validate returned %v for a passport with only a warning", got)
	}
	p.Serial = ""
	if got := Validate(Clean(p), testNow); len(got) == 0 {
		t.Error("Validate accepted a passport with no serial")
	}
}

func TestParseDate(t *testing.T) {
	cases := []struct {
		in string
		ok bool
	}{
		{"2026-09-14", true},
		{"2024-02-29", true},
		{"2000-02-29", true},
		{"1900-02-29", false},
		{"2023-02-29", false},
		{"2026-02-30", false},
		{"2026-13-01", false},
		{"2026-00-10", false},
		{"2026-01-00", false},
		{"2026-04-31", false},
		{"2026-12-31", true},
		{"2026-9-14", false},
		{"26-09-14", false},
		{"14-09-2026", false},
		{"2026/09/14", false},
		{"", false},
		{"today", false},
		{"2026-09-14 ", false},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got, err := ParseDate(c.in)
			if (err == nil) != c.ok {
				t.Fatalf("ParseDate(%q) error = %v, want ok = %v", c.in, err, c.ok)
			}
			if c.ok && got.Format(DateLayout) != c.in {
				t.Errorf("ParseDate(%q) came back as %s", c.in, got.Format(DateLayout))
			}
		})
	}
}

func TestDaysBetween(t *testing.T) {
	day := func(s string) time.Time {
		t, err := ParseDate(s)
		if err != nil {
			panic(err)
		}
		return t
	}
	cases := []struct {
		from, to string
		want     int
	}{
		{"2026-09-14", "2026-09-14", 0},
		{"2026-09-14", "2026-09-15", 1},
		{"2026-09-15", "2026-09-14", -1},
		{"2024-02-28", "2024-03-01", 2},   // a leap year
		{"2026-02-28", "2026-03-01", 1},   // a common year
		{"2026-01-31", "2026-02-01", 1},   // a month end
		{"2025-12-31", "2026-01-01", 1},   // a year end
		{"2024-01-01", "2025-01-01", 366}, // a leap year is longer
		{"2025-01-01", "2026-01-01", 365},
	}
	for _, c := range cases {
		if got := DaysBetween(day(c.from), day(c.to)); got != c.want {
			t.Errorf("DaysBetween(%s, %s) = %d, want %d", c.from, c.to, got, c.want)
		}
	}
}

func TestAgeInWords(t *testing.T) {
	day := func(s string) time.Time {
		t, err := ParseDate(s)
		if err != nil {
			panic(err)
		}
		return t
	}
	now := day("2026-11-24")
	cases := []struct {
		off  string
		want string
	}{
		{"2026-11-24", "came off the loom today"},
		{"2026-11-23", "came off the loom yesterday"},
		{"2026-11-14", "came off the loom 10 days ago"},
		{"2026-10-14", "came off the loom about a month ago"},
		{"2026-09-14", "came off the loom about 2 months ago"},
		{"2025-09-14", "came off the loom about a year ago"},
		{"2021-09-14", "came off the loom about 5 years ago"},
		{"2026-11-25", "dated 1 days in the future"},
	}
	for _, c := range cases {
		if got := AgeInWords(day(c.off), now); got != c.want {
			t.Errorf("AgeInWords(%s) = %q, want %q", c.off, got, c.want)
		}
	}
}

func TestBands(t *testing.T) {
	if len(Bands()) != len(articles) {
		t.Errorf("there are %d bands for %d articles", len(Bands()), len(articles))
	}
	for _, b := range Bands() {
		if b.MinLengthCM >= b.MaxLengthCM || b.MinWidthCM >= b.MaxWidthCM {
			t.Errorf("band for %s is empty or inverted: %+v", b.Article, b)
		}
		if b.MinLengthCM < AbsoluteMinLengthCM || b.MaxLengthCM > AbsoluteMaxLengthCM {
			t.Errorf("band for %s falls outside the absolute bounds: %+v", b.Article, b)
		}
		if b.MinWidthCM < AbsoluteMinWidthCM || b.MaxWidthCM > AbsoluteMaxWidthCM {
			t.Errorf("band for %s falls outside the absolute bounds: %+v", b.Article, b)
		}
	}
	for _, c := range []struct {
		in string
		ok bool
	}{{"saree", true}, {"SA", true}, {"Saree", true}, {"carpet", false}, {"", false}} {
		if _, ok := BandFor(c.in); ok != c.ok {
			t.Errorf("BandFor(%q) found = %v, want %v", c.in, ok, c.ok)
		}
	}
}

func TestCleanNormalises(t *testing.T) {
	p := Clean(Passport{
		Serial:     "  KSS-2026-004128  ",
		WeaverName: "R.   Saravanan\t",
		Cluster:    "Kanchipuram\nSilk  Weavers",
		Role:       "AUTHORISED_USER",
		LoomType:   "Handloom",
		Article:    "SAREE",
		WarpFibre:  "Silk",
		Binding:    "SEWN_TAG",
		Marks:      []string{"silk_mark", "handloom_mark", "silk_mark", "", "none"},
	})
	if p.Serial != "KSS-2026-004128" {
		t.Errorf("serial = %q", p.Serial)
	}
	if p.WeaverName != "R. Saravanan" {
		t.Errorf("weaver = %q", p.WeaverName)
	}
	if p.Cluster != "Kanchipuram Silk Weavers" {
		t.Errorf("cluster = %q", p.Cluster)
	}
	if p.Role != "A" || p.LoomType != "H" || p.Article != "SA" || p.WarpFibre != "SI" || p.Binding != "T" {
		t.Errorf("coded fields = %+v", p)
	}
	if got := marksCode(p.Marks); got != "HS" {
		t.Errorf("marks = %q, want %q (sorted and with the duplicate dropped)", got, "HS")
	}
	// Cleaning twice changes nothing more, which is what makes a signature
	// over the cleaned bytes reproducible.
	if string(Canonicalise(Clean(p))) != string(Canonicalise(p)) {
		t.Error("cleaning a cleaned passport changed it")
	}
}

func TestDescribe(t *testing.T) {
	d := Describe(sample())
	for field, got := range map[string]string{
		"role": d.Role, "loomType": d.LoomType, "article": d.Article,
		"warpFibre": d.WarpFibre, "weftFibre": d.WeftFibre, "zari": d.Zari,
		"binding": d.Binding, "marks": d.Marks,
	} {
		if got == "" {
			t.Errorf("%s has no description", field)
		}
		if len(got) <= 2 {
			t.Errorf("%s was described as %q, which is still a code", field, got)
		}
	}
	if d.Marks != "Handloom Mark and Silk Mark" {
		t.Errorf("marks described as %q", d.Marks)
	}
	none := sample()
	none.Marks = nil
	if got := Describe(none).Marks; got != "No certification mark claimed" {
		t.Errorf("no marks described as %q", got)
	}
}

// TestTodayIsAcceptedInEveryTimeZone pins a bug worth remembering: a date
// parsed out of a passport is midnight UTC, while the machine issuing the
// passport may be anywhere. Comparing the two as instants rather than as
// calendar days made a piece woven today look like a piece woven tomorrow for
// everybody east of Greenwich — and refused it.
func TestTodayIsAcceptedInEveryTimeZone(t *testing.T) {
	for _, offset := range []int{-11 * 3600, -5 * 3600, 0, 5*3600 + 1800, 8 * 3600, 14 * 3600} {
		zone := time.FixedZone("test", offset)
		now := time.Date(2026, 11, 24, 9, 15, 0, 0, zone)
		p := sample()
		p.OffLoomDate = Today(now).Format(DateLayout)
		if problems, _ := Check(Clean(p), now); len(problems) > 0 {
			t.Errorf("at UTC%+d a piece woven today was refused: %v", offset/3600, problems)
		}
		// And tomorrow is still refused.
		p.OffLoomDate = Today(now).AddDate(0, 0, 1).Format(DateLayout)
		problems, _ := Check(Clean(p), now)
		if len(problems) == 0 {
			t.Errorf("at UTC%+d a piece woven tomorrow was accepted", offset/3600)
		}
	}
}
