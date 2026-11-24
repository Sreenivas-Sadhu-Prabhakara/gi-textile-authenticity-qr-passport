package passport

import (
	"sort"
	"strings"
)

// The enumerated fields of a passport. Each value has three forms:
//
//	Code  — one or two characters, and the only form the signed bytes carry.
//	        Short codes keep the signed payload small, which keeps the printed
//	        symbol small enough to go on a tag.
//	Name  — the stable identifier the interface and the stored file use.
//	Label — the words a buyer reads.
//
// A value's code never changes, because changing one would change the signed
// bytes of every passport ever issued.
type enumValue struct {
	Code  string `json:"code"`
	Name  string `json:"name"`
	Label string `json:"label"`
}

// roles: who on the geographical indication register issued this passport.
//
// Under the Indian Act it is the registered proprietor and the registered
// authorised users who may use a registered geographical indication, so a
// passport has to say which of the two the issuer is, and under which entry.
var roles = []enumValue{
	{"P", "proprietor", "Registered proprietor of the geographical indication"},
	{"A", "authorised_user", "Registered authorised user"},
}

// loomTypes: how the cloth was made. This is the field the whole tool turns
// on, because a powerloom copy of a handwoven weave is the counterfeit the
// buyer is trying to avoid.
var loomTypes = []enumValue{
	{"H", "handloom", "Handloom — woven by hand"},
	{"P", "powerloom", "Powerloom"},
	{"M", "mill", "Mill-made"},
}

// articles: what was woven. The article sets the measurements a buyer should
// expect to find when they put a tape measure to the cloth.
var articles = []enumValue{
	{"SA", "saree", "Saree"},
	{"DU", "dupatta", "Dupatta"},
	{"ST", "stole", "Stole"},
	{"SH", "shawl", "Shawl or blanket"},
	{"YD", "yardage", "Yardage or running fabric"},
	{"OT", "other", "Other"},
}

// fibres: what the warp and the weft are made of. Warp and weft are recorded
// separately because many pieces differ between the two, and because which
// certification marks a piece can honestly claim depends on them.
var fibres = []enumValue{
	{"SI", "silk", "Silk"},
	{"CO", "cotton", "Cotton"},
	{"SC", "silk_cotton", "Silk and cotton together"},
	{"WO", "wool", "Wool"},
	{"AB", "abaca", "Abaca"},
	{"PI", "pina", "Piña (pineapple fibre)"},
	{"JU", "jute", "Jute"},
	{"PE", "polyester", "Polyester"},
	{"VI", "viscose", "Viscose or art silk"},
	{"BL", "blend_other", "Another blend"},
}

// silkBearing lists the fibre codes that contain natural silk.
var silkBearing = map[string]bool{"SI": true, "SC": true}

// naturalFibres lists the fibre codes that are not man-made. A piece woven
// from a man-made fibre can be perfectly genuine; it simply cannot carry a
// mark that certifies natural silk.
var naturalFibres = map[string]bool{"SI": true, "CO": true, "SC": true, "WO": true, "AB": true, "PI": true, "JU": true}

// zaris: the metallic thread, where there is any. Pure zari is a real point of
// fraud in its own right, so it is recorded separately from the fibres.
var zaris = []enumValue{
	{"N", "none", "No zari"},
	{"P", "pure_zari", "Pure zari — silver gilded with gold"},
	{"H", "half_fine_zari", "Half-fine zari"},
	{"I", "imitation_zari", "Imitation zari"},
}

// bindings: how the passport is attached to the cloth. This is the field that
// decides whether a valid signature says anything at all about the piece in
// the buyer's hands, so it is required, and "not bound" is an answer the
// verify screen repeats back in plain words.
var bindings = []enumValue{
	{"T", "sewn_tag", "Sewn-in tag, stitched into the piece"},
	{"W", "woven_selvedge", "Woven into the selvedge of the piece itself"},
	{"L", "heat_sealed_label", "Heat-sealed label"},
	{"N", "not_bound", "Not bound to the piece — a loose card or slip"},
}

// marks: the certification marks a piece may be claimed to carry. They are
// granted by their own authorities on their own terms; this tool records a
// claim and checks it is not self-contradictory, which is all it can do.
var marks = []enumValue{
	{"H", "handloom_mark", "Handloom Mark"},
	{"S", "silk_mark", "Silk Mark"},
}

// MarksNone is the code stored when a piece claims no mark at all. It is an
// explicit value rather than an empty one so the signed bytes distinguish
// "claims nothing" from a field somebody forgot to fill in.
const MarksNone = "-"

func find(set []enumValue, s string) (enumValue, bool) {
	if s == "" {
		return enumValue{}, false
	}
	lower := strings.ToLower(s)
	upper := strings.ToUpper(s)
	for _, v := range set {
		if v.Code == upper || strings.EqualFold(v.Name, lower) {
			return v, true
		}
	}
	return enumValue{}, false
}

// canonicalCode turns either form of a value into its code, and leaves
// anything it does not recognise alone so validation can name it in an error.
func canonicalCode(set []enumValue, s string) string {
	s = collapse(s)
	if v, ok := find(set, s); ok {
		return v.Code
	}
	return s
}

// label returns the words for a code, or the code itself if it is not one.
func label(set []enumValue, code string) string {
	if v, ok := find(set, code); ok {
		return v.Label
	}
	return code
}

// name returns the stable identifier for a code.
func name(set []enumValue, code string) string {
	if v, ok := find(set, code); ok {
		return v.Name
	}
	return code
}

// cleanMarks brings a list of claimed marks to canonical codes, sorted and
// de-duplicated, so the same claim always encodes to the same bytes.
func cleanMarks(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range in {
		m = collapse(m)
		if m == "" || m == MarksNone || strings.EqualFold(m, "none") {
			continue
		}
		code := canonicalCode(marks, m)
		if seen[code] {
			continue
		}
		seen[code] = true
		out = append(out, code)
	}
	sort.Strings(out)
	return out
}

// marksCode is the marks field as the signed bytes carry it: the codes in
// order, or a single dash for none.
func marksCode(in []string) string {
	if len(in) == 0 {
		return MarksNone
	}
	return strings.Join(in, "")
}

// parseMarksCode is the inverse of marksCode.
func parseMarksCode(code string) ([]string, bool) {
	if code == MarksNone {
		return nil, true
	}
	var out []string
	for i := 0; i < len(code); i++ {
		c := string(code[i])
		if _, ok := find(marks, c); !ok {
			return nil, false
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, false
	}
	sorted := cleanMarks(out)
	if marksCode(sorted) != code {
		// Duplicated or out-of-order codes would give one claim two
		// encodings, which a signed payload must never have.
		return nil, false
	}
	return sorted, true
}

// markNames returns the stable identifiers of the claimed marks.
func markNames(in []string) []string {
	out := make([]string, 0, len(in))
	for _, m := range in {
		out = append(out, name(marks, m))
	}
	return out
}

func describeMarks(in []string) string {
	if len(in) == 0 {
		return "No certification mark claimed"
	}
	var out []string
	for _, m := range in {
		out = append(out, label(marks, m))
	}
	return strings.Join(out, " and ")
}

// Options lists the choices for every enumerated field, for an interface to
// build its menus from without hard-coding them a second time.
func Options() map[string][]enumValue {
	return map[string][]enumValue{
		"role":     roles,
		"loomType": loomTypes,
		"article":  articles,
		"fibre":    fibres,
		"zari":     zaris,
		"binding":  bindings,
		"marks":    marks,
	}
}

// MarkNames returns the stable identifiers of the marks a passport may claim.
func MarkNames() []string {
	out := make([]string, 0, len(marks))
	for _, m := range marks {
		out = append(out, m.Name)
	}
	return out
}
