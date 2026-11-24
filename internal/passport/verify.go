package passport

import (
	"crypto/ed25519"
	"strconv"
	"time"
	"unicode"
)

// Result is what a buyer holding the cloth is shown after scanning or typing
// a passport code.
type Result struct {
	// Pass is true only when the signature is valid under a public key the
	// buyer supplied from somewhere other than this code. It is never true on
	// the strength of the key carried inside the code.
	Pass bool `json:"pass"`

	// Reason says in plain words why Pass is what it is.
	Reason string `json:"reason"`

	// Passport holds the decoded details whenever the code could be read at
	// all, even when the check fails, so a buyer can see what was claimed —
	// and so a cluster can see what a forgery is claiming in its name.
	Passport *Passport `json:"passport,omitempty"`

	// Described spells out the coded fields.
	Described *Described `json:"described,omitempty"`

	// Covered lists the fields the signature protects. Nothing outside this
	// list is protected by it.
	Covered []Field `json:"covered,omitempty"`

	// SelfConsistent means the signature matches the public key that is
	// inside the code. On its own this proves nothing about who issued the
	// passport: anyone can generate a key, sign their own text with it and
	// put their own key in the code. It is reported because a code that is
	// not even self-consistent is corrupt rather than forged, and that is
	// worth telling the holder apart.
	SelfConsistent bool `json:"selfConsistent"`

	// KeyMatch means the key inside the code is the key the buyer supplied.
	KeyMatch bool `json:"keyMatch"`

	// CheckedAgainst is the public key the check was made against.
	CheckedAgainst string `json:"checkedAgainst,omitempty"`

	// PhysicalChecks are the things to do with the cloth itself, which is
	// where the real answer lies.
	PhysicalChecks []PhysicalCheck `json:"physicalChecks,omitempty"`

	// BoundToPiece is false when the passport says it is not fastened to the
	// cloth, in which case even a valid signature says nothing about this
	// piece.
	BoundToPiece bool `json:"boundToPiece"`

	// Marks describes the certification marks claimed, and what each claim
	// does and does not establish.
	Marks []MarkClaim `json:"marks,omitempty"`

	// Inconsistencies are contradictions inside the signed content — a
	// Handloom Mark on a powerloom piece, measurements no such article comes
	// in. A genuine cluster's passport should have none. A valid signature
	// over a self-contradicting passport means the key holder signed
	// something that does not add up, which the buyer should be told.
	Inconsistencies []string `json:"inconsistencies,omitempty"`

	// Age describes how long ago the piece came off the loom.
	Age string `json:"age,omitempty"`

	// Limits is what this check does not establish. It is filled in whether
	// the check passes or fails, because the limits do not go away when the
	// signature is good.
	Limits []string `json:"limits"`
}

// VerifyCode checks a passport code against a public key the buyer already
// trusts — the key the cluster published.
//
// The trusted key is required, and this is the whole design. A passport code
// carries the issuer's public key inside it, so checking the signature against
// that embedded key shows only that the code is internally consistent. A
// forger generates a key in a second, signs whatever they like with it and
// puts their own key in the code; it verifies perfectly against itself.
// Authenticity is a comparison against a key the buyer obtained from the
// cluster by some other route: its noticeboard, its letterhead, a
// co-operative's published list, a sticker on the shop wall. Without that key
// there is nothing to compare, and this function will not pass.
func VerifyCode(code, trustedPublicKey string, now time.Time) Result {
	p, sig, err := ParseCode(code)
	if err != nil {
		return Result{Reason: err.Error(), Limits: VerificationLimits()}
	}

	res := Result{
		Passport:     &p,
		Covered:      CoveredFields(),
		Limits:       VerificationLimits(),
		BoundToPiece: p.Binding != "N",
		Marks:        MarkClaims(p),
	}
	described := Describe(p)
	res.Described = &described
	res.Inconsistencies, _ = Check(p, now)
	if off, err := ParseDate(p.OffLoomDate); err == nil {
		res.Age = AgeInWords(off, now)
	}

	embedded, embErr := ParsePublicKey(p.IssuerPublicKey)
	if embErr != nil {
		res.Reason = "The code carries an unreadable cluster public key: " + embErr.Error()
		return res
	}
	res.SelfConsistent = Verify(p, sig, embedded)

	if trimmed := collapse(trustedPublicKey); trimmed == "" {
		res.Reason = "No cluster public key was supplied, so nothing here has been checked against the cluster. " +
			"A code always verifies against the key printed inside it, forged or genuine. " +
			"Get the cluster's published key and paste it in."
		return res
	}

	trusted, err := ParsePublicKey(trustedPublicKey)
	if err != nil {
		res.Reason = "The public key you supplied could not be read: " + err.Error()
		return res
	}
	res.CheckedAgainst = EncodePublicKey(trusted)
	res.KeyMatch = res.CheckedAgainst == p.IssuerPublicKey

	if !res.KeyMatch {
		res.Reason = "This passport was signed by a different key from the one you supplied. Whoever issued it does not hold the cluster's signing key."
		return res
	}
	if !ed25519.Verify(trusted, Canonicalise(p), sig) {
		res.Reason = "The signature does not match these details. The passport has been altered since it was issued, or the code is damaged."
		return res
	}

	res.Pass = true
	res.Reason = "Issued by the holder of this cluster's signing key, and not altered since."
	if !res.BoundToPiece {
		res.Reason += " But the passport says it is not fastened to the cloth, so it does not tell you that this is the piece it describes."
	}
	res.PhysicalChecks = PhysicalChecks(p, now)
	return res
}

// VerificationLimits is the standing statement of what a signature check does
// not establish. It is the same whether the check passed or failed, and it is
// returned with every result rather than being left to an interface to
// remember.
func VerificationLimits() []string {
	return []string{
		"A valid signature means two things and no more: the holder of that private key issued this passport, and not one character of it has changed since.",
		"It does not mean the cloth in your hands is the piece described. A passport can be photographed, copied and sewn onto a counterfeit piece. Only the physical binding — a tag stitched into this piece, or a mark woven into its selvedge — ties the two together, and that is the cluster's doing and your eyes' checking, not this tool's.",
		"It does not mean the facts are true. The cluster typed them in. The weaver's name, the loom number and the fibres are the cluster's word, signed.",
		"It does not check the geographical indication register, the authorised-user entry or any certification mark. Those live with their authorities. Confirm the registration number and the entry with the registry itself.",
		"It cannot tell you that the same passport has not been issued twice, or printed a thousand times. Ask the cluster to look the serial up in its register.",
	}
}

// PhysicalCheck is one thing to do with the cloth rather than with the code.
type PhysicalCheck struct {
	// What to do.
	Do string `json:"do"`
	// Why it is worth doing, and what a wrong answer would mean.
	Why string `json:"why"`
}

// PhysicalChecks turns a verified passport into the things to check against
// the cloth. This is where a passport earns its keep: the signature settles
// what the cluster said, and these settle whether the piece in front of the
// buyer is what was described.
func PhysicalChecks(p Passport, now time.Time) []PhysicalCheck {
	var out []PhysicalCheck

	switch p.Binding {
	case "T":
		out = append(out, PhysicalCheck{
			Do:  "Find the tag and check it is stitched into the piece, not tied, pinned or stapled on.",
			Why: "A sewn tag is what connects this passport to this cloth. Look at the stitching: if it has been unpicked and re-sewn, the tag has been moved from another piece.",
		})
	case "W":
		out = append(out, PhysicalCheck{
			Do:  "Find the mark woven into the selvedge and check it matches the serial on the passport.",
			Why: "A mark woven into the cloth cannot be moved to another piece without reweaving it, which is the strongest binding there is. Check it is woven in and not printed on.",
		})
	case "L":
		out = append(out, PhysicalCheck{
			Do:  "Check the heat-sealed label is intact and has not been lifted and re-fixed.",
			Why: "A label that peels away can be moved to another piece. Look at the edges and the fabric under it.",
		})
	case "N":
		out = append(out, PhysicalCheck{
			Do:  "Treat this passport as describing a piece, not this piece.",
			Why: "The cluster recorded that the passport is not fastened to the cloth. Nothing about the code can tell you which piece it was meant for. Ask the cluster to look up the serial and describe the piece back to you before you pay.",
		})
	}

	out = append(out, PhysicalCheck{
		Do:  measureInstruction(p),
		Why: "Measurements are the one claim you can test on the spot. Washed and finished cloth shrinks by a few centimetres, so allow for that — but a piece a foot out from the passport is not the piece the passport describes.",
	})

	switch p.LoomType {
	case "H":
		out = append(out, PhysicalCheck{
			Do:  "Hold the piece up to the light and look along the weave and the selvedge.",
			Why: "This passport records the piece as handwoven. Handloom cloth is slightly irregular: the weft is not perfectly even, the selvedge wanders a little, and the reverse side is usually as finished as the front. Machine-even cloth with a flawless selvedge is not handwoven, whatever the passport says.",
		})
	case "P", "M":
		out = append(out, PhysicalCheck{
			Do:  "Note that this passport does not claim handwoven cloth.",
			Why: "It records the piece as " + label(loomTypes, p.LoomType) + ". That may be exactly what you are buying, but it is not handloom, and it should not be priced as handloom.",
		})
	}

	out = append(out, PhysicalCheck{
		Do:  fibreInstruction(p),
		Why: "Fibre is tested, not seen. A burn test or a laboratory test at a testing centre is the only way to be sure; the passport records what the cluster says the fibres are.",
	})

	for _, m := range MarkClaims(p) {
		out = append(out, PhysicalCheck{
			Do:  "Look for the " + m.Label + " label on the piece itself and check its number.",
			Why: m.Caution + " Granted by: " + m.GrantedBy + ".",
		})
	}

	out = append(out, PhysicalCheck{
		Do: "Ring the cluster and read them the serial " + p.Serial + ".",
		Why: "The cluster's own register is the only place that can say whether this serial was issued, to which weaver, for which piece — and whether it has been quoted before. " +
			"This tool holds a cluster's register locally; it is not a national database and cannot be queried from here.",
	})

	out = append(out, PhysicalCheck{
		Do:  "Confirm registration number " + p.GIRegistrationNo + " and " + label(roles, p.Role) + " entry " + p.RegisterEntryNo + " with the registry.",
		Why: "Only the registered proprietor and registered authorised users may use a registered geographical indication (" + RegulationIndia + ", " + RegulationIndiaRights + "). This tool ships no list of registrations and cannot check one: the number in the passport is the cluster's claim.",
	})

	return out
}

func measureInstruction(p Passport) string {
	article := label(articles, p.Article)
	return "Measure the piece. The passport says this " + lower(article) + " came off the loom at " +
		strconv.Itoa(p.LengthCM) + " cm by " + strconv.Itoa(p.WidthCM) + " cm."
}

// lower turns a label into something that reads correctly inside a sentence.
func lower(s string) string {
	r := []rune(s)
	if len(r) == 0 {
		return s
	}
	return string(unicode.ToLower(r[0])) + string(r[1:])
}

func fibreInstruction(p Passport) string {
	if p.WarpFibre == p.WeftFibre {
		return "The passport records " + lower(label(fibres, p.WarpFibre)) + " in both the warp and the weft. Feel the cloth and ask the seller the same question."
	}
	return "The passport records " + lower(label(fibres, p.WarpFibre)) + " in the warp and " +
		lower(label(fibres, p.WeftFibre)) + " in the weft. Feel the cloth and ask the seller the same question."
}
