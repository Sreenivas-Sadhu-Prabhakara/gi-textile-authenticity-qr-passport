package passport

import (
	"crypto/ed25519"
	"fmt"
	"time"
)

// Sign signs a passport's canonical bytes with a cluster's private key.
//
// What a signature establishes is narrow and worth stating exactly: that the
// holder of the matching private key produced these bytes, and that not one
// byte of them has changed since. It says nothing about whether the facts in
// the passport are true, and nothing about which piece of cloth it is attached
// to.
func Sign(p Passport, priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("a private key is %d bytes; this one is %d", ed25519.PrivateKeySize, len(priv))
	}
	return ed25519.Sign(priv, Canonicalise(p)), nil
}

// Verify checks a signature over a passport against a public key.
func Verify(p Passport, sig []byte, pub ed25519.PublicKey) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, Canonicalise(p), sig)
}

// SignedPassport is a passport with its signature and the code that carries
// both. It is what the cluster keeps in its register and what goes on the tag.
type SignedPassport struct {
	Passport
	// Signature is the detached signature over the canonical bytes.
	Signature string `json:"signature"`
	// Code is the whole thing in one printable string: the passport and its
	// signature, which is what the printed symbol carries.
	Code string `json:"code"`
	// Described spells out the coded fields for display.
	Described Described `json:"described"`
}

// Issue validates, signs and packs a passport in one step. The problems slice
// is non-empty exactly when nothing was signed, and the warnings are things
// worth a second look that do not stop the passport being issued.
func Issue(p Passport, k Keypair, now time.Time) (SignedPassport, []string, []string) {
	p = Clean(p)
	if err := k.Validate(); err != nil {
		return SignedPassport{}, []string{"Signing key: " + err.Error()}, nil
	}
	// The passport carries the key it was signed with, so the two can never
	// be separated.
	p.IssuerPublicKey = k.Public

	problems, warnings := Check(p, now)
	if len(problems) > 0 {
		return SignedPassport{}, problems, warnings
	}

	priv, err := ParsePrivateKey(k.Private)
	if err != nil {
		return SignedPassport{}, []string{"Signing key: " + err.Error()}, warnings
	}
	sig, err := Sign(p, priv)
	if err != nil {
		return SignedPassport{}, []string{"Signing key: " + err.Error()}, warnings
	}
	code, err := EncodeCode(p, sig)
	if err != nil {
		return SignedPassport{}, []string{err.Error()}, warnings
	}
	return SignedPassport{
		Passport:  p,
		Signature: EncodeSignature(sig),
		Code:      code,
		Described: Describe(p),
	}, nil, warnings
}
