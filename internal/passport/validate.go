package passport

import (
	"fmt"
	"strings"
	"time"
	"unicode"
)

// Check is every rule this tool has, applied to a cleaned passport.
//
// It returns two lists, kept apart on purpose:
//
//	problems — reasons nothing will be signed. A passport with a problem is
//	           either incomplete or contradicts itself.
//	warnings — things worth a second look that do not stop a cluster issuing
//	           the passport. Handloom work is irregular, and a tool that
//	           refuses the unusual would simply be worked around.
//
// It takes the current date rather than reading the clock, so every rule here
// is a pure function of its inputs and can be tested against any date.
func Check(p Passport, now time.Time) (problems, warnings []string) {
	problems = append(problems, requiredTextProblems(p)...)
	problems = append(problems, enumProblems(p)...)

	measurementErrs, measurementWarnings := measurementProblems(p)
	problems = append(problems, measurementErrs...)
	warnings = append(warnings, measurementWarnings...)

	dateErrs, dateWarnings := dateProblems(p, now)
	problems = append(problems, dateErrs...)
	warnings = append(warnings, dateWarnings...)

	markErrs, markWarnings := markProblems(p)
	problems = append(problems, markErrs...)
	warnings = append(warnings, markWarnings...)

	warnings = append(warnings, bindingWarnings(p)...)

	if p.IssuerPublicKey != "" {
		if _, err := ParsePublicKey(p.IssuerPublicKey); err != nil {
			problems = append(problems, "Cluster public key: "+err.Error())
		}
	}

	// The whole passport has to fit a printed symbol. Field limits make that
	// true by construction, so reaching this is a bug rather than a user
	// error — but it is checked, because a passport that cannot be printed is
	// of no use to anybody.
	if n := len(Canonicalise(p)); n > MaxCanonicalLen() {
		problems = append(problems, fmt.Sprintf("This passport comes to %d bytes, more than the %d a printable code holds.", n, MaxCanonicalLen()))
	}
	return problems, warnings
}

// requiredTextProblems checks that every text field is present, short enough
// and free of control characters.
func requiredTextProblems(p Passport) []string {
	var problems []string
	for _, f := range fieldSpecs {
		// The public key is filled in when the passport is signed, so it is
		// not required of whoever types the form.
		if f.Key == "pk" {
			continue
		}
		v := f.get(p)
		if v == "" {
			problems = append(problems, f.Label+" is missing.")
			continue
		}
		if len(v) > f.maxLen {
			problems = append(problems, fmt.Sprintf("%s is %d bytes long; the limit is %d. Shorten it — the whole passport has to fit on a tag.",
				f.Label, len(v), f.maxLen))
		}
		for _, r := range v {
			if unicode.IsControl(r) {
				problems = append(problems, f.Label+" has a control character in it.")
				break
			}
		}
	}

	// The registration number is the user's to supply and nobody's to
	// invent, so the only thing checked is that it is not obviously a
	// placeholder.
	if looksLikePlaceholder(p.GIRegistrationNo) {
		problems = append(problems, "GI registration number looks like a placeholder. Put the real number from the register on it, or do not issue the passport.")
	}
	return problems
}

func looksLikePlaceholder(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "-", "n/a", "na", "none", "tbd", "todo", "xxx", "xxxx", "0", "00", "test":
		return true
	}
	return false
}

// enumProblems checks the coded fields hold codes this version knows.
func enumProblems(p Passport) []string {
	var problems []string
	check := func(set []enumValue, code, field string) {
		if code == "" {
			return // already reported as missing
		}
		if _, ok := find(set, code); !ok {
			allowed := make([]string, 0, len(set))
			for _, v := range set {
				allowed = append(allowed, v.Name)
			}
			problems = append(problems, fmt.Sprintf("%s: %q is not one of %s.", field, code, strings.Join(allowed, ", ")))
		}
	}
	check(roles, p.Role, "Standing on the GI register")
	check(loomTypes, p.LoomType, "Loom type")
	check(articles, p.Article, "Article")
	check(fibres, p.WarpFibre, "Warp fibre")
	check(fibres, p.WeftFibre, "Weft fibre")
	check(zaris, p.Zari, "Zari")
	check(bindings, p.Binding, "Bound to the piece by")
	for _, m := range p.Marks {
		check(marks, m, "Certification mark claimed")
	}
	return problems
}

// dateProblems checks the date off the loom.
func dateProblems(p Passport, now time.Time) (problems, warnings []string) {
	if p.OffLoomDate == "" {
		return nil, nil // already reported as missing
	}
	off, err := ParseDate(p.OffLoomDate)
	if err != nil {
		return []string{"Date off the loom: " + err.Error()}, nil
	}
	today := Today(now)
	// Dates are compared as calendar days, never as instants. A date parsed
	// out of a passport is midnight UTC; the machine issuing the passport may
	// be anywhere. Comparing the two directly would make a piece woven today
	// look like a piece woven tomorrow for half the world.
	if DaysBetween(off, today) < 0 {
		return []string{fmt.Sprintf("Date off the loom: %s has not happened yet. A passport cannot be issued for a piece that is not woven.", p.OffLoomDate)}, nil
	}
	earliest, err := ParseDate(EarliestOffLoomDate)
	if err != nil {
		return []string{"Date off the loom: " + err.Error()}, nil
	}
	if DaysBetween(earliest, off) < 0 {
		return []string{fmt.Sprintf("Date off the loom: %s is before %s. Check the year.", p.OffLoomDate, EarliestOffLoomDate)}, nil
	}
	if DaysBetween(off, today) > 365*10 {
		warnings = append(warnings, fmt.Sprintf("The piece is recorded as coming off the loom on %s, which is more than ten years ago. Check the year.", p.OffLoomDate))
	}
	return nil, warnings
}

// bindingWarnings says plainly what an unbound passport is worth.
func bindingWarnings(p Passport) []string {
	if p.Binding != "N" {
		return nil
	}
	return []string{
		"This passport is recorded as not bound to the piece. A loose card can be moved to another piece, and a buyer checking it learns only that the cluster issued some passport — not that this is the cloth it describes. Sew the tag into the piece if you can.",
	}
}

// Validate is Check with the warnings dropped, for a caller that only wants to
// know whether a passport can be signed.
func Validate(p Passport, now time.Time) []string {
	problems, _ := Check(p, now)
	return problems
}
