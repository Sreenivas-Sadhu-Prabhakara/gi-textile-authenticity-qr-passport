package passport

import "fmt"

// The measurements in a passport are there for one reason: they are the only
// claim a buyer can test on the spot, with a tape measure, against the cloth
// in their hands. So they have to be plausible, and the passport has to say
// what to expect.
//
// The ranges below are craft norms, not law. No statute fixes the length of a
// saree. They are stated here as named constants, they only ever produce a
// warning, and a cluster weaving something unusual can issue the passport
// anyway — the warning is a question, not a refusal.

// Absolute bounds. Outside these a measurement is not unusual, it is wrong:
// cloth 9 centimetres long is not cloth, and nothing comes off a handloom
// 4 metres wide.
const (
	AbsoluteMinLengthCM = 10
	AbsoluteMaxLengthCM = 10000
	AbsoluteMinWidthCM  = 5
	AbsoluteMaxWidthCM  = 300
)

// Band is the range of measurements an article normally comes in.
type Band struct {
	Article     string `json:"article"`
	MinLengthCM int    `json:"minLengthCm"`
	MaxLengthCM int    `json:"maxLengthCm"`
	MinWidthCM  int    `json:"minWidthCm"`
	MaxWidthCM  int    `json:"maxWidthCm"`
	Note        string `json:"note"`
}

// bands is indexed by article code.
var bands = map[string]Band{
	"SA": {Article: "SA", MinLengthCM: 450, MaxLengthCM: 900, MinWidthCM: 100, MaxWidthCM: 135,
		Note: "A six-yard saree runs about 550 cm and a nine-yard about 820 cm, with the blouse piece adding to the length."},
	"DU": {Article: "DU", MinLengthCM: 200, MaxLengthCM: 300, MinWidthCM: 60, MaxWidthCM: 120},
	"ST": {Article: "ST", MinLengthCM: 150, MaxLengthCM: 220, MinWidthCM: 35, MaxWidthCM: 80},
	"SH": {Article: "SH", MinLengthCM: 180, MaxLengthCM: 280, MinWidthCM: 90, MaxWidthCM: 150},
	"YD": {Article: "YD", MinLengthCM: 90, MaxLengthCM: 5000, MinWidthCM: 70, MaxWidthCM: 160,
		Note: "Running fabric is measured as it is cut, so the length is whatever came off the loom in one piece."},
	"OT": {Article: "OT", MinLengthCM: AbsoluteMinLengthCM, MaxLengthCM: AbsoluteMaxLengthCM,
		MinWidthCM: AbsoluteMinWidthCM, MaxWidthCM: AbsoluteMaxWidthCM,
		Note: "Nothing is assumed about the measurements of an article recorded as other."},
}

// BandFor returns the expected measurements for an article code.
func BandFor(article string) (Band, bool) {
	b, ok := bands[canonicalCode(articles, article)]
	return b, ok
}

// Bands returns every band, for the documentation and the interface to show
// the figures they are judging against.
func Bands() []Band {
	out := make([]Band, 0, len(bands))
	for _, a := range articles {
		if b, ok := bands[a.Code]; ok {
			out = append(out, b)
		}
	}
	return out
}

// measurementProblems separates the impossible from the merely unusual.
func measurementProblems(p Passport) (problems, warnings []string) {
	if p.LengthCM < AbsoluteMinLengthCM || p.LengthCM > AbsoluteMaxLengthCM {
		problems = append(problems, fmt.Sprintf("Length off the loom: %d cm is not a length of cloth. Give it in centimetres, between %d and %d.",
			p.LengthCM, AbsoluteMinLengthCM, AbsoluteMaxLengthCM))
	}
	if p.WidthCM < AbsoluteMinWidthCM || p.WidthCM > AbsoluteMaxWidthCM {
		problems = append(problems, fmt.Sprintf("Width off the loom: %d cm is not a width of cloth. Give it in centimetres, between %d and %d.",
			p.WidthCM, AbsoluteMinWidthCM, AbsoluteMaxWidthCM))
	}
	if len(problems) > 0 {
		return problems, nil
	}

	band, ok := BandFor(p.Article)
	if !ok {
		return nil, nil
	}
	article := label(articles, p.Article)
	if p.LengthCM < band.MinLengthCM || p.LengthCM > band.MaxLengthCM {
		w := fmt.Sprintf("Length: %d cm is outside the %d to %d cm a %s usually runs. Check it before you sign — a buyer will measure the piece.",
			p.LengthCM, band.MinLengthCM, band.MaxLengthCM, article)
		if band.Note != "" {
			w += " " + band.Note
		}
		warnings = append(warnings, w)
	}
	if p.WidthCM < band.MinWidthCM || p.WidthCM > band.MaxWidthCM {
		warnings = append(warnings, fmt.Sprintf("Width: %d cm is outside the %d to %d cm a %s usually runs. Check it before you sign.",
			p.WidthCM, band.MinWidthCM, band.MaxWidthCM, article))
	}
	return nil, warnings
}
