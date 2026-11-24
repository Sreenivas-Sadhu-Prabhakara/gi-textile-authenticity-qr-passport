package passport

import "fmt"

// A certification mark is granted by its own authority on its own terms. This
// tool does not grant one and cannot check that one was granted. What it can
// do is refuse to sign a passport that contradicts itself, which is worth
// doing, because a self-contradicting passport is exactly what a careless
// forger produces.
//
// Two contradictions are flat refusals:
//
//   - the Handloom Mark certifies that cloth was woven by hand, so a piece
//     recorded as powerloom or mill-made cannot claim it;
//   - the Silk Mark certifies natural silk, so a piece with no silk recorded
//     in either the warp or the weft cannot claim it.
//
// One is a warning rather than a refusal: the Silk Mark is for pure silk, and
// a piece with silk on one side and cotton on the other is a blend. Some
// licences cover blended products and the rules change, so the tool says so
// and lets the cluster decide.

// markProblems checks the claimed marks against the rest of the passport.
func markProblems(p Passport) (problems, warnings []string) {
	claimed := map[string]bool{}
	for _, m := range p.Marks {
		claimed[m] = true
	}

	if claimed["H"] && p.LoomType != "H" {
		problems = append(problems, fmt.Sprintf(
			"This passport claims the Handloom Mark but records the piece as %s. The Handloom Mark certifies handwoven cloth. Correct the loom type or drop the claim.",
			label(loomTypes, p.LoomType)))
	}

	if claimed["S"] {
		warpSilk, weftSilk := silkBearing[p.WarpFibre], silkBearing[p.WeftFibre]
		switch {
		case !warpSilk && !weftSilk:
			problems = append(problems, fmt.Sprintf(
				"This passport claims the Silk Mark but records %s in the warp and %s in the weft. The Silk Mark certifies natural silk. Correct the fibres or drop the claim.",
				label(fibres, p.WarpFibre), label(fibres, p.WeftFibre)))
		case p.WarpFibre != "SI" || p.WeftFibre != "SI":
			warnings = append(warnings, fmt.Sprintf(
				"The Silk Mark is for pure natural silk, and this piece is recorded as %s in the warp and %s in the weft. Check your licence covers a blended piece before you claim the mark.",
				label(fibres, p.WarpFibre), label(fibres, p.WeftFibre)))
		}
	}

	// A piece recorded as man-made fibre throughout, sold under a
	// geographical indication for a natural-fibre weave, is worth a question
	// even with no mark claimed.
	if !naturalFibres[p.WarpFibre] && !naturalFibres[p.WeftFibre] && p.WarpFibre != "" && p.WeftFibre != "" {
		warnings = append(warnings, fmt.Sprintf(
			"Neither the warp (%s) nor the weft (%s) is a natural fibre. That can be perfectly genuine, but check it is what the geographical indication covers.",
			label(fibres, p.WarpFibre), label(fibres, p.WeftFibre)))
	}

	// Pure zari is tested, not asserted, and it is a target of fraud in its
	// own right.
	if p.Zari == "P" {
		warnings = append(warnings, "Pure zari is established by testing at a zari testing centre, not by this passport. Keep the test report with the piece, and tell the buyer where the piece was tested.")
	}

	return problems, warnings
}

// MarkClaims returns the claimed marks and what each one does and does not
// establish, for the verify screen to show a buyer.
type MarkClaim struct {
	Name      string `json:"name"`
	Label     string `json:"label"`
	GrantedBy string `json:"grantedBy"`
	Caution   string `json:"caution"`
}

// MarkClaims describes the marks a passport claims.
func MarkClaims(p Passport) []MarkClaim {
	var out []MarkClaim
	for _, m := range p.Marks {
		switch m {
		case "H":
			out = append(out, MarkClaim{
				Name:      "handloom_mark",
				Label:     "Handloom Mark",
				GrantedBy: SchemeHandloomMark,
				Caution:   "The mark is a separately issued label with its own number. This passport records that the cluster claims it; look for the label itself on the piece.",
			})
		case "S":
			out = append(out, MarkClaim{
				Name:      "silk_mark",
				Label:     "Silk Mark",
				GrantedBy: SchemeSilkMark,
				Caution:   "The mark is a separately issued hologram label with its own number, and it certifies natural silk. This passport records that the cluster claims it; look for the label itself on the piece.",
			})
		}
	}
	return out
}
