package passport

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// canonicalHeader opens the signed bytes. It names both the thing and its
// version, so a signature made over a textile passport can never be read as a
// signature over anything else, and a version 1 reader refuses a version 2
// payload instead of guessing at it.
var canonicalHeader = []byte(CanonicalVersion + "\n")

// fieldSpec is one signed field: its key in the canonical bytes, the words a
// reader sees, how long a value it accepts, and how to read and write it.
type fieldSpec struct {
	Field
	maxLen int
	get    func(Passport) string
	set    func(*Passport, string) error
}

// fieldSpecs is the single source of truth for the signed field set, its order
// and its length limits. The encoder, the decoder, the validator and the list
// of covered fields all read it, so the four cannot drift apart.
//
// The keys are two letters because the whole signed payload goes inside a
// printed symbol: every byte spent on a field name is a byte of symbol a
// weaver has to fit on a tag. The order is fixed and the keys are fixed
// forever; a new field means a new canonical version.
var fieldSpecs = []fieldSpec{
	{
		Field: Field{Key: "sn", Label: "Piece serial"}, maxLen: 24,
		get: func(p Passport) string { return p.Serial },
		set: func(p *Passport, v string) error { p.Serial = v; return nil },
	},
	{
		Field: Field{Key: "gn", Label: "Geographical indication"}, maxLen: 40,
		get: func(p Passport) string { return p.GIName },
		set: func(p *Passport, v string) error { p.GIName = v; return nil },
	},
	{
		Field: Field{Key: "gr", Label: "GI registration number"}, maxLen: 40,
		get: func(p Passport) string { return p.GIRegistrationNo },
		set: func(p *Passport, v string) error { p.GIRegistrationNo = v; return nil },
	},
	{
		Field: Field{Key: "ro", Label: "Standing on the GI register"}, maxLen: 1,
		get: func(p Passport) string { return p.Role },
		set: func(p *Passport, v string) error { p.Role = v; return nil },
	},
	{
		Field: Field{Key: "en", Label: "Register entry number"}, maxLen: 24,
		get: func(p Passport) string { return p.RegisterEntryNo },
		set: func(p *Passport, v string) error { p.RegisterEntryNo = v; return nil },
	},
	{
		Field: Field{Key: "cl", Label: "Cluster or society"}, maxLen: 48,
		get: func(p Passport) string { return p.Cluster },
		set: func(p *Passport, v string) error { p.Cluster = v; return nil },
	},
	{
		Field: Field{Key: "wv", Label: "Weaver"}, maxLen: 48,
		get: func(p Passport) string { return p.WeaverName },
		set: func(p *Passport, v string) error { p.WeaverName = v; return nil },
	},
	{
		Field: Field{Key: "wi", Label: "Weaver identifier"}, maxLen: 24,
		get: func(p Passport) string { return p.WeaverID },
		set: func(p *Passport, v string) error { p.WeaverID = v; return nil },
	},
	{
		Field: Field{Key: "lm", Label: "Loom number"}, maxLen: 16,
		get: func(p Passport) string { return p.LoomNo },
		set: func(p *Passport, v string) error { p.LoomNo = v; return nil },
	},
	{
		Field: Field{Key: "lt", Label: "Loom type"}, maxLen: 1,
		get: func(p Passport) string { return p.LoomType },
		set: func(p *Passport, v string) error { p.LoomType = v; return nil },
	},
	{
		Field: Field{Key: "ar", Label: "Article"}, maxLen: 2,
		get: func(p Passport) string { return p.Article },
		set: func(p *Passport, v string) error { p.Article = v; return nil },
	},
	{
		Field: Field{Key: "wa", Label: "Warp fibre"}, maxLen: 2,
		get: func(p Passport) string { return p.WarpFibre },
		set: func(p *Passport, v string) error { p.WarpFibre = v; return nil },
	},
	{
		Field: Field{Key: "we", Label: "Weft fibre"}, maxLen: 2,
		get: func(p Passport) string { return p.WeftFibre },
		set: func(p *Passport, v string) error { p.WeftFibre = v; return nil },
	},
	{
		Field: Field{Key: "za", Label: "Zari"}, maxLen: 1,
		get: func(p Passport) string { return p.Zari },
		set: func(p *Passport, v string) error { p.Zari = v; return nil },
	},
	{
		Field: Field{Key: "lc", Label: "Length off the loom (cm)"}, maxLen: 5,
		get: func(p Passport) string { return strconv.Itoa(p.LengthCM) },
		set: func(p *Passport, v string) error {
			n, err := parseStrictInt(v)
			if err != nil {
				return err
			}
			p.LengthCM = n
			return nil
		},
	},
	{
		Field: Field{Key: "wc", Label: "Width off the loom (cm)"}, maxLen: 5,
		get: func(p Passport) string { return strconv.Itoa(p.WidthCM) },
		set: func(p *Passport, v string) error {
			n, err := parseStrictInt(v)
			if err != nil {
				return err
			}
			p.WidthCM = n
			return nil
		},
	},
	{
		Field: Field{Key: "od", Label: "Date off the loom"}, maxLen: 10,
		get: func(p Passport) string { return p.OffLoomDate },
		set: func(p *Passport, v string) error { p.OffLoomDate = v; return nil },
	},
	{
		Field: Field{Key: "mk", Label: "Certification marks claimed"}, maxLen: 2,
		get: func(p Passport) string { return marksCode(p.Marks) },
		set: func(p *Passport, v string) error {
			out, ok := parseMarksCode(v)
			if !ok {
				return fmt.Errorf("%q is not a marks code", v)
			}
			p.Marks = out
			return nil
		},
	},
	{
		Field: Field{Key: "bd", Label: "Bound to the piece by"}, maxLen: 1,
		get: func(p Passport) string { return p.Binding },
		set: func(p *Passport, v string) error { p.Binding = v; return nil },
	},
	{
		Field: Field{Key: "pk", Label: "Cluster public key"}, maxLen: PublicKeyStringLen,
		get: func(p Passport) string { return p.IssuerPublicKey },
		set: func(p *Passport, v string) error { p.IssuerPublicKey = v; return nil },
	},
}

// CoveredFields returns the signed field set, in canonical order.
func CoveredFields() []Field {
	out := make([]Field, 0, len(fieldSpecs))
	for _, f := range fieldSpecs {
		out = append(out, f.Field)
	}
	return out
}

// MaxCanonicalLen is the largest the signed bytes can be once every field is
// at its limit. It is what guarantees that a passport which passes validation
// always fits a printable symbol.
func MaxCanonicalLen() int {
	n := len(canonicalHeader)
	for _, f := range fieldSpecs {
		n += len(f.Key) + 1 + len(strconv.Itoa(f.maxLen)) + 1 + f.maxLen + 1
	}
	return n
}

// Canonicalise produces the exact bytes that get signed.
//
// The encoding is the version header followed by one line per field, in the
// fixed order of fieldSpecs, written as:
//
//	<key>=<byte length>:<value>\n
//
// Nothing iterates a map, so the bytes never depend on Go's map ordering: the
// same passport always encodes the same way, in this process and any other.
//
// The length prefix is the point of the encoding. Plain concatenation would
// let one field's tail slide into the next field's head — a weaver named "AB"
// on loom "1" would produce the same bytes as a weaver named "A" on loom
// "B1", so one signature would cover both readings, and a forger could
// re-split a genuine passport into a different one without touching the
// signature. Here the two encode as "wv=2:AB\nlm=1:1\n" and
// "wv=1:A\nlm=2:B1\n", which differ. The prefix also lets a value contain a
// colon, a newline or a non-Latin script without confusing the decoder.
func Canonicalise(p Passport) []byte {
	var b bytes.Buffer
	b.Write(canonicalHeader)
	for _, f := range fieldSpecs {
		v := f.get(p)
		b.WriteString(f.Key)
		b.WriteByte('=')
		b.WriteString(strconv.Itoa(len(v)))
		b.WriteByte(':')
		b.WriteString(v)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// DecodeCanonical is the exact inverse of Canonicalise, and strict on purpose.
// A missing field, fields out of order, a length that does not match the
// value, a padded number, trailing bytes — each is an error rather than a best
// guess, because a payload that decodes two ways could be shown two ways under
// one signature.
func DecodeCanonical(b []byte) (Passport, error) {
	rest, ok := bytes.CutPrefix(b, canonicalHeader)
	if !ok {
		return Passport{}, fmt.Errorf("this is not a %s passport: the version header is wrong or missing", CanonicalVersion)
	}

	var p Passport
	for _, f := range fieldSpecs {
		rest, ok = bytes.CutPrefix(rest, []byte(f.Key+"="))
		if !ok {
			return Passport{}, fmt.Errorf("field %q is missing or out of order", f.Key)
		}
		// The length is the digits between the '=' and the ':', and nothing
		// else may stand there — so a field with no length prefix is reported
		// as such rather than being read as some other field's colon.
		digits := 0
		for digits < len(rest) && rest[digits] >= '0' && rest[digits] <= '9' {
			digits++
		}
		if digits == 0 || digits >= len(rest) || rest[digits] != ':' {
			return Passport{}, fmt.Errorf("field %q has no length prefix", f.Key)
		}
		n, err := parseStrictInt(string(rest[:digits]))
		if err != nil {
			return Passport{}, fmt.Errorf("the length of field %q: %w", f.Key, err)
		}
		colon := digits
		if n > f.maxLen {
			return Passport{}, fmt.Errorf("field %q claims %d bytes, more than the %d it may hold", f.Key, n, f.maxLen)
		}
		rest = rest[colon+1:]
		if len(rest) < n+1 {
			return Passport{}, fmt.Errorf("field %q is cut short", f.Key)
		}
		if rest[n] != '\n' {
			return Passport{}, fmt.Errorf("field %q does not end where its length says it does", f.Key)
		}
		if err := f.set(&p, string(rest[:n])); err != nil {
			return Passport{}, fmt.Errorf("field %q: %w", f.Key, err)
		}
		rest = rest[n+1:]
	}
	if len(rest) != 0 {
		return Passport{}, errors.New("there are extra bytes after the last field")
	}
	return p, nil
}

// parseStrictInt accepts plain decimal digits only: no sign, no space, no
// redundant leading zero, so every number has exactly one encoding and two
// different byte strings can never mean the same passport.
func parseStrictInt(s string) (int, error) {
	if s == "" {
		return 0, errors.New("the number is empty")
	}
	if strings.ContainsAny(s, "+-") {
		return 0, fmt.Errorf("the number %q must not carry a sign", s)
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("the number %q has something in it that is not a digit", s)
		}
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, fmt.Errorf("the number %q has a leading zero", s)
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("the number %q is too large", s)
	}
	return n, nil
}
