package passport

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Keys are Ed25519, from the standard library. A public key is 32 bytes, a
// private key 64, and a signature 64.
//
// Both keys are written as unpadded base64 with the URL alphabet, so a key
// survives being pasted into a web page, a text message or a printed sheet
// without a character needing to be escaped. The public key is 43 characters
// and the private key 86.
const (
	// PublicKeyStringLen is the length of an encoded public key.
	PublicKeyStringLen = 43
	// PrivateKeyStringLen is the length of an encoded private key.
	PrivateKeyStringLen = 86
	// SignatureStringLen is the length of an encoded signature.
	SignatureStringLen = 86
)

var keyEncoding = base64.URLEncoding.WithPadding(base64.NoPadding)

// Keypair is a cluster's signing key and the public key it publishes.
type Keypair struct {
	// Public is the key the cluster prints on its letterhead, puts on its
	// noticeboard and gives to its buyers. Verification is only worth
	// anything when the buyer got this key from the cluster by some route
	// other than the passport being checked.
	Public string `json:"publicKey"`
	// Private is the key that signs. It never leaves the cluster, and this
	// tool never writes it to its data file.
	Private string `json:"privateKey"`
}

// NewKeypair generates a fresh signing key from the operating system's random
// source.
func NewKeypair() (Keypair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Keypair{}, fmt.Errorf("a signing key could not be generated: %w", err)
	}
	return Keypair{
		Public:  keyEncoding.EncodeToString(pub),
		Private: keyEncoding.EncodeToString(priv),
	}, nil
}

// ParsePublicKey reads an encoded public key. Whitespace anywhere in it is
// ignored, because a key copied off a printed page arrives with line breaks in
// it.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	raw, err := decodeKey(s, ed25519.PublicKeySize, "public")
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(raw), nil
}

// ParsePrivateKey reads an encoded private key.
func ParsePrivateKey(s string) (ed25519.PrivateKey, error) {
	raw, err := decodeKey(s, ed25519.PrivateKeySize, "private")
	if err != nil {
		return nil, err
	}
	return ed25519.PrivateKey(raw), nil
}

func decodeKey(s string, want int, kind string) ([]byte, error) {
	s = strings.Join(strings.Fields(s), "")
	if s == "" {
		return nil, fmt.Errorf("the %s key is empty", kind)
	}
	raw, err := keyEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("the %s key is not valid base64: %w", kind, err)
	}
	if len(raw) != want {
		return nil, fmt.Errorf("a %s key is %d bytes; this one is %d", kind, want, len(raw))
	}
	return raw, nil
}

// EncodePublicKey writes a public key the way this tool reads it.
func EncodePublicKey(k ed25519.PublicKey) string {
	return keyEncoding.EncodeToString(k)
}

// EncodeSignature writes a signature as text, for showing beside a passport.
func EncodeSignature(sig []byte) string {
	return keyEncoding.EncodeToString(sig)
}

// ParseSignature reads an encoded signature.
func ParseSignature(s string) ([]byte, error) {
	s = strings.Join(strings.Fields(s), "")
	raw, err := keyEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("the signature is not valid base64: %w", err)
	}
	if len(raw) != ed25519.SignatureSize {
		return nil, fmt.Errorf("a signature is %d bytes; this one is %d", ed25519.SignatureSize, len(raw))
	}
	return raw, nil
}

// Validate checks a keypair is usable and that the two halves belong
// together: a private key whose public half is not the published one would
// sign passports nobody could verify.
func (k Keypair) Validate() error {
	priv, err := ParsePrivateKey(k.Private)
	if err != nil {
		return err
	}
	if k.Public == "" {
		return errors.New("the public key is missing")
	}
	pub, err := ParsePublicKey(k.Public)
	if err != nil {
		return err
	}
	if !pub.Equal(priv.Public()) {
		return errors.New("this private key does not belong to that public key")
	}
	return nil
}

// PublicFromPrivate derives the published key from the signing key, so a
// cluster that kept only the signing key can recover what to publish.
func PublicFromPrivate(privateKey string) (string, error) {
	priv, err := ParsePrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return "", errors.New("this key has no public half")
	}
	return EncodePublicKey(pub), nil
}
