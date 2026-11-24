// Package passport holds the rules for a woven piece's provenance passport:
// what a cluster records about one piece of cloth, what makes a record
// internally honest, how those facts are turned into the exact bytes that get
// signed, and what a buyer holding the cloth can and cannot conclude from a
// valid signature.
//
// Nothing here talks to a network or a registry. The geographical indication
// registration number, the authorised-user entry and the weaver's details are
// the cluster's to supply and the buyer's to confirm with the registry; this
// package checks that the record is complete, internally consistent and
// unaltered since it was signed, which is a different and smaller claim.
package passport

import "strings"

// The named regulations behind the fields this package records. They are
// stated in one place so the documentation and the user interface quote the
// same text, and so there is one thing to change when a scheme changes.
const (
	// RegulationIndia is the statute that makes a geographical indication
	// usable only by those on its register.
	RegulationIndia = "Geographical Indications of Goods (Registration and Protection) Act, 1999"

	// RegulationIndiaRights names the sections that restrict use of a
	// registered geographical indication to the registered proprietor and
	// registered authorised users.
	RegulationIndiaRights = "sections 17 and 21"

	// RegulationPhilippines is the statute under which the Philippine
	// geographical indication register was established.
	RegulationPhilippines = "Intellectual Property Code of the Philippines (Republic Act No. 8293)"

	// RegulationPhilippinesRules names the rules that opened that register.
	RegulationPhilippinesRules = "Rules and Regulations on Geographical Indications, Intellectual Property Office of the Philippines, 2022"

	// SchemeHandloomMark is the mark that certifies cloth as handwoven.
	SchemeHandloomMark = "Handloom Mark (Ministry of Textiles, through the Textiles Committee)"

	// SchemeSilkMark is the mark that certifies pure natural silk.
	SchemeSilkMark = "Silk Mark (Silk Mark Organisation of India, Central Silk Board)"
)

// CanonicalVersion tags the signed encoding. A later field set gets a later
// tag, so an older reader refuses a newer passport rather than misreading it.
const CanonicalVersion = "gitp/v1"

// CodePrefix opens the printed and scanned form of a passport, so whoever
// scans it can see what they are looking at before anything decodes it.
const CodePrefix = "GITP1:"

// Passport is the record of one woven piece. Every field here is covered by
// the signature; nothing outside it is.
type Passport struct {
	// Serial is the cluster's own number for this piece, unique in its
	// register. It is what a buyer quotes when ringing the cluster.
	Serial string `json:"serial"`

	// GIName is the geographical indication the piece is sold under, as it is
	// written on the register — for instance a town's silk or a village's
	// weave.
	GIName string `json:"giName"`

	// GIRegistrationNo is the registration number of that geographical
	// indication. It is the user's to supply and the buyer's to confirm: this
	// tool ships no list of registrations and cannot check one.
	GIRegistrationNo string `json:"giRegistrationNo"`

	// Role is the issuer's standing on the register: the registered
	// proprietor, or a registered authorised user.
	Role string `json:"role"`

	// RegisterEntryNo is the issuer's entry number on that register.
	RegisterEntryNo string `json:"registerEntryNo"`

	// Cluster is the weaver cluster, society or co-operative that issued the
	// passport.
	Cluster string `json:"cluster"`

	// WeaverName and WeaverID identify the weaver who wove this piece.
	WeaverName string `json:"weaverName"`
	WeaverID   string `json:"weaverId"`

	// LoomNo is the loom the piece came off.
	LoomNo string `json:"loomNo"`

	// LoomType is how it was woven: by hand, on a powerloom, or in a mill.
	LoomType string `json:"loomType"`

	// Article is what was woven.
	Article string `json:"article"`

	// WarpFibre and WeftFibre are the fibres in the two directions of the
	// weave. They are separate because a great many pieces are not the same
	// in both, and because the marks a piece may claim turn on them.
	WarpFibre string `json:"warpFibre"`
	WeftFibre string `json:"weftFibre"`

	// Zari records the metallic thread, where there is any.
	Zari string `json:"zari"`

	// LengthCM and WidthCM are the piece's measurements as it came off the
	// loom, in centimetres. They are in the passport because they are the one
	// thing a buyer can check against the cloth with a tape measure.
	LengthCM int `json:"lengthCm"`
	WidthCM  int `json:"widthCm"`

	// OffLoomDate is the day the piece came off the loom, as YYYY-MM-DD.
	OffLoomDate string `json:"offLoomDate"`

	// Marks are the certification marks the piece is claimed to carry. The
	// marks are granted by their own authorities; recording a claim here is
	// not the grant.
	Marks []string `json:"marks"`

	// Binding is how the passport is fastened to the cloth. It is a required
	// field because a passport that is not bound to its piece can be copied
	// onto another piece, and a buyer deserves to be told which they have.
	Binding string `json:"binding"`

	// IssuerPublicKey is the cluster's signing key, written as the cluster
	// publishes it. It is inside the signed bytes so that a passport cannot
	// be re-labelled with somebody else's key without breaking the signature
	// — but on its own it proves nothing, because anyone can make a key.
	IssuerPublicKey string `json:"issuerPublicKey"`
}

// Field names a signed field. The verify screen lists these so a buyer can
// see exactly which claims the signature covers, and therefore which it does
// not.
type Field struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

// Clean normalises a passport: whitespace trimmed, runs of spaces collapsed,
// enumerated values brought to their canonical codes, marks sorted and
// de-duplicated. Signing, verifying and storing all work on cleaned values, so
// a passport entered with a stray double space verifies against the same bytes
// it was signed as.
func Clean(p Passport) Passport {
	p.Serial = collapse(p.Serial)
	p.GIName = collapse(p.GIName)
	p.GIRegistrationNo = collapse(p.GIRegistrationNo)
	p.Role = canonicalCode(roles, p.Role)
	p.RegisterEntryNo = collapse(p.RegisterEntryNo)
	p.Cluster = collapse(p.Cluster)
	p.WeaverName = collapse(p.WeaverName)
	p.WeaverID = collapse(p.WeaverID)
	p.LoomNo = collapse(p.LoomNo)
	p.LoomType = canonicalCode(loomTypes, p.LoomType)
	p.Article = canonicalCode(articles, p.Article)
	p.WarpFibre = canonicalCode(fibres, p.WarpFibre)
	p.WeftFibre = canonicalCode(fibres, p.WeftFibre)
	p.Zari = canonicalCode(zaris, p.Zari)
	p.OffLoomDate = collapse(p.OffLoomDate)
	p.Marks = cleanMarks(p.Marks)
	p.Binding = canonicalCode(bindings, p.Binding)
	p.IssuerPublicKey = collapse(p.IssuerPublicKey)
	return p
}

// collapse trims a value and reduces every run of whitespace inside it to one
// space.
func collapse(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// Describe returns the passport's enumerated fields in the words a buyer
// reads, rather than the codes the signed bytes carry.
type Described struct {
	Role      string `json:"role"`
	LoomType  string `json:"loomType"`
	Article   string `json:"article"`
	WarpFibre string `json:"warpFibre"`
	WeftFibre string `json:"weftFibre"`
	Zari      string `json:"zari"`
	Binding   string `json:"binding"`
	Marks     string `json:"marks"`
}

// Describe spells out the coded fields.
func Describe(p Passport) Described {
	return Described{
		Role:      label(roles, p.Role),
		LoomType:  label(loomTypes, p.LoomType),
		Article:   label(articles, p.Article),
		WarpFibre: label(fibres, p.WarpFibre),
		WeftFibre: label(fibres, p.WeftFibre),
		Zari:      label(zaris, p.Zari),
		Binding:   label(bindings, p.Binding),
		Marks:     describeMarks(p.Marks),
	}
}

// Names returns the same fields as their stable identifiers rather than their
// wording. An exported spreadsheet uses these: the labels are written for
// someone to read and may be reworded, whereas a name is part of the
// interface and is not.
func Names(p Passport) Described {
	return Described{
		Role:      name(roles, p.Role),
		LoomType:  name(loomTypes, p.LoomType),
		Article:   name(articles, p.Article),
		WarpFibre: name(fibres, p.WarpFibre),
		WeftFibre: name(fibres, p.WeftFibre),
		Zari:      name(zaris, p.Zari),
		Binding:   name(bindings, p.Binding),
		Marks:     strings.Join(markNames(p.Marks), " "),
	}
}
