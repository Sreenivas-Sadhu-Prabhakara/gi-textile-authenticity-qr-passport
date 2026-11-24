package passport

import (
	"crypto/ed25519"
	"encoding/base32"
	"fmt"
	"strings"
)

// The passport code is the whole passport and its signature in one printable
// string: the prefix GITP1:, then the canonical bytes and the 64-byte
// signature together, in base32.
//
// Base32 rather than base64, for three reasons that all come from this being
// printed on a tag and read by a stranger:
//
//   - It is upper case and has no look-alike pairs of upper and lower case, so
//     a buyer can read it off a label and type it in when the symbol is torn.
//   - Its alphabet — A to Z and the digits 2 to 7 — is inside the printed
//     symbol's alphanumeric character set, which packs two characters into
//     eleven bits. Base64 would need the symbol's byte mode at eight bits a
//     character, and would come out about a tenth larger in area despite being
//     a shorter string.
//   - It has no '+' or '/' to be mangled by a web form or a messaging app.
//
// The code carries the passport itself, not a web address. A buyer with no
// network, or standing in a market in ten years' time when the cluster's
// website has gone, can still check the signature.
var codeEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// groupSize is how many characters of the code are printed together. Base32
// turns five bytes into eight characters, so groups of eight fall on byte
// boundaries.
const groupSize = 8

// EncodeCode packs a passport and its signature into one code.
func EncodeCode(p Passport, sig []byte) (string, error) {
	if len(sig) != ed25519.SignatureSize {
		return "", fmt.Errorf("a signature is %d bytes; this one is %d", ed25519.SignatureSize, len(sig))
	}
	blob := append(Canonicalise(p), sig...)
	return CodePrefix + codeEncoding.EncodeToString(blob), nil
}

// Grouped lays a code out for printing: the prefix, then the body in groups of
// eight separated by spaces.
func Grouped(code string) string {
	body := strings.TrimPrefix(code, CodePrefix)
	var b strings.Builder
	b.WriteString(CodePrefix)
	for i := 0; i < len(body); i += groupSize {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(body[i:min(i+groupSize, len(body))])
	}
	return b.String()
}

// Normalise brings a code to the one form everything else works on: no
// spaces, no dashes, no line breaks, upper case, prefix included. A code read
// off a tag, pasted from a message or typed in by hand all come out the same.
func Normalise(code string) string {
	code = strings.ToUpper(code)
	code = strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r', '-', '_':
			return -1
		}
		return r
	}, code)
	return code
}

// ParseCode reads a code back to the passport and signature it carries. It
// does not check the signature; that is VerifyCode's job, and keeping the two
// apart means a buyer can be shown what a code claims even when it fails.
func ParseCode(code string) (Passport, []byte, error) {
	normalised := Normalise(code)
	if normalised == "" {
		return Passport{}, nil, fmt.Errorf("there is no code here")
	}
	body, ok := strings.CutPrefix(normalised, CodePrefix)
	if !ok {
		return Passport{}, nil, fmt.Errorf("a passport code starts with %s; this one starts with %q", CodePrefix, firstRunes(normalised, 8))
	}
	blob, err := codeEncoding.DecodeString(body)
	if err != nil {
		return Passport{}, nil, fmt.Errorf("the code has characters in it that are not part of a passport code: %w", err)
	}
	if len(blob) <= ed25519.SignatureSize {
		return Passport{}, nil, fmt.Errorf("the code is %d bytes long, which is too short to hold a passport and its %d-byte signature", len(blob), ed25519.SignatureSize)
	}
	split := len(blob) - ed25519.SignatureSize
	p, err := DecodeCanonical(blob[:split])
	if err != nil {
		return Passport{}, nil, err
	}
	return p, blob[split:], nil
}

// QRPayload is what goes inside the printed symbol: the normalised code, which
// is entirely within the symbol's alphanumeric character set.
func QRPayload(code string) string { return Normalise(code) }

// MaxCodeLen is the longest a code can be once every field is at its limit.
// It is what lets the documentation promise a symbol size for every passport
// this tool will issue.
func MaxCodeLen() int {
	return len(CodePrefix) + codeEncoding.EncodedLen(MaxCanonicalLen()+ed25519.SignatureSize)
}

func firstRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}
