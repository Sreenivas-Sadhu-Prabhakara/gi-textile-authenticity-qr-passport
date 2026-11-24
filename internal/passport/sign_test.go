package passport

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 11, 24, 10, 30, 0, 0, time.UTC)

func mustKeypair(t *testing.T) Keypair {
	t.Helper()
	k, err := NewKeypair()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestKeypairRoundTrip(t *testing.T) {
	k := mustKeypair(t)
	if len(k.Public) != PublicKeyStringLen {
		t.Errorf("public key is %d characters, want %d", len(k.Public), PublicKeyStringLen)
	}
	if len(k.Private) != PrivateKeyStringLen {
		t.Errorf("private key is %d characters, want %d", len(k.Private), PrivateKeyStringLen)
	}
	if err := k.Validate(); err != nil {
		t.Errorf("a freshly generated keypair did not validate: %v", err)
	}
	pub, err := ParsePublicKey(k.Public)
	if err != nil {
		t.Fatal(err)
	}
	if EncodePublicKey(pub) != k.Public {
		t.Error("a public key did not survive being parsed and written again")
	}
	derived, err := PublicFromPrivate(k.Private)
	if err != nil {
		t.Fatal(err)
	}
	if derived != k.Public {
		t.Error("the public key derived from the private key is not the published one")
	}

	// Two generated keys must differ, or the random source is not random.
	other := mustKeypair(t)
	if other.Public == k.Public || other.Private == k.Private {
		t.Error("two generated keypairs are the same")
	}
}

func TestKeyParsingRejectsJunk(t *testing.T) {
	k := mustKeypair(t)
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", "is empty"},
		{"whitespace only", "   \n\t ", "is empty"},
		{"not base64", "nJLgWJuHoQHVxxtiHWNIoYIh2zIVNk4cCxO2V0O06a!", "not valid base64"},
		{"too short", "nJLgWJuHoQHVxxtiHWNIoYIh2zIVNk4cCxO2V0O06a", "bytes"},
		{"too long", k.Public + "AAAA", "bytes"},
		{"a private key where a public one belongs", k.Private, "bytes"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParsePublicKey(c.in); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("ParsePublicKey error = %v, want one mentioning %q", err, c.want)
			}
		})
	}

	t.Run("whitespace inside a key is ignored", func(t *testing.T) {
		spaced := k.Public[:10] + "\n  " + k.Public[10:20] + " " + k.Public[20:]
		pub, err := ParsePublicKey(spaced)
		if err != nil {
			t.Fatal(err)
		}
		if EncodePublicKey(pub) != k.Public {
			t.Error("a key copied with line breaks in it did not come out the same")
		}
	})

	t.Run("mismatched halves are refused", func(t *testing.T) {
		other := mustKeypair(t)
		mixed := Keypair{Public: other.Public, Private: k.Private}
		err := mixed.Validate()
		if err == nil || !strings.Contains(err.Error(), "does not belong") {
			t.Errorf("error = %v, want one saying the halves do not belong together", err)
		}
	})

	t.Run("an empty public half is refused", func(t *testing.T) {
		if err := (Keypair{Private: k.Private}).Validate(); err == nil {
			t.Error("a keypair with no public key validated")
		}
	})
}

func TestSignatureParsing(t *testing.T) {
	k := mustKeypair(t)
	priv, err := ParsePrivateKey(k.Private)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(sample(), priv)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	encoded := EncodeSignature(sig)
	if len(encoded) != SignatureStringLen {
		t.Errorf("an encoded signature is %d characters, want %d", len(encoded), SignatureStringLen)
	}
	back, err := ParseSignature(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(back) != string(sig) {
		t.Error("a signature did not survive the round trip")
	}

	for _, c := range []struct{ name, in, want string }{
		{"not base64", "!!!", "not valid base64"},
		{"too short", encoded[:40], "bytes"},
		{"empty", "", "bytes"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseSignature(c.in); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v, want one mentioning %q", err, c.want)
			}
		})
	}

	t.Run("a key of the wrong size cannot sign", func(t *testing.T) {
		if _, err := Sign(sample(), ed25519.PrivateKey("short")); err == nil {
			t.Error("a 5-byte private key signed something")
		}
	})
}

// TestTamperOnEveryField changes one field at a time and checks the signature
// stops matching. It walks the field list itself, so a field added to the
// passport without being added to the signed bytes fails here.
func TestTamperOnEveryField(t *testing.T) {
	k := mustKeypair(t)
	priv, err := ParsePrivateKey(k.Private)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(k.Public)
	if err != nil {
		t.Fatal(err)
	}

	original := sample()
	original.IssuerPublicKey = k.Public
	sig, err := Sign(original, priv)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(original, sig, pub) {
		t.Fatal("the signature does not verify over the passport it was made for")
	}

	// A replacement value for each field that is different from the sample's
	// and legal for that field.
	replacements := map[string]string{
		"sn": "KSS-2026-004129",
		"gn": "Pochampally Ikat",
		"gr": "GI 00144",
		"ro": "P",
		"en": "AU/143/2019/0218",
		"cl": "Pochampally Handloom Weavers Society",
		"wv": "K. Lakshmi",
		"wi": "HWID-33-004129",
		"lm": "L-28",
		"lt": "P",
		"ar": "DU",
		"wa": "CO",
		"we": "CO",
		"za": "I",
		"lc": "824",
		"wc": "121",
		"od": "2026-09-15",
		"mk": "H",
		"bd": "N",
		"pk": strings.Repeat("B", PublicKeyStringLen),
	}
	if len(replacements) != len(fieldSpecs) {
		t.Fatalf("there are %d replacements for %d fields", len(replacements), len(fieldSpecs))
	}

	for _, f := range fieldSpecs {
		t.Run(f.Key, func(t *testing.T) {
			replacement, ok := replacements[f.Key]
			if !ok {
				t.Fatalf("no replacement value for field %q", f.Key)
			}
			tampered := original
			if err := f.set(&tampered, replacement); err != nil {
				t.Fatalf("setting field %q to %q: %v", f.Key, replacement, err)
			}
			if f.get(tampered) == f.get(original) {
				t.Fatalf("the replacement for field %q did not change it", f.Key)
			}
			if Verify(tampered, sig, pub) {
				t.Errorf("the signature still verifies after field %q was changed", f.Key)
			}
		})
	}
}

func TestVerifyRefusesWrongKeysAndBrokenSignatures(t *testing.T) {
	k := mustKeypair(t)
	other := mustKeypair(t)
	priv, _ := ParsePrivateKey(k.Private)
	pub, _ := ParsePublicKey(k.Public)
	otherPub, _ := ParsePublicKey(other.Public)

	p := sample()
	p.IssuerPublicKey = k.Public
	sig, err := Sign(p, priv)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		sig  []byte
		pub  ed25519.PublicKey
		want bool
	}{
		{"the right key and signature", sig, pub, true},
		{"another cluster's key", sig, otherPub, false},
		{"a signature with one bit flipped", flipFirstByte(sig), pub, false},
		{"a signature with the last bit flipped", flipLastByte(sig), pub, false},
		{"a truncated signature", sig[:32], pub, false},
		{"an empty signature", nil, pub, false},
		{"a signature of all zeroes", make([]byte, ed25519.SignatureSize), pub, false},
		{"a truncated key", sig, pub[:16], false},
		{"an empty key", sig, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Verify(p, c.sig, c.pub); got != c.want {
				t.Errorf("Verify = %v, want %v", got, c.want)
			}
		})
	}

	t.Run("a signature over another passport does not transfer", func(t *testing.T) {
		otherPassport := sample()
		otherPassport.IssuerPublicKey = k.Public
		otherPassport.Serial = "KSS-2026-009999"
		if Verify(otherPassport, sig, pub) {
			t.Error("one passport's signature verified over another")
		}
	})
}

func flipFirstByte(b []byte) []byte {
	out := append([]byte{}, b...)
	out[0] ^= 1
	return out
}

func flipLastByte(b []byte) []byte {
	out := append([]byte{}, b...)
	out[len(out)-1] ^= 1
	return out
}

func TestIssue(t *testing.T) {
	k := mustKeypair(t)

	t.Run("a good passport is issued", func(t *testing.T) {
		p := sample()
		p.IssuerPublicKey = "" // filled in by Issue
		sp, problems, warnings := Issue(p, k, testNow)
		if len(problems) > 0 {
			t.Fatalf("problems: %v", problems)
		}
		if sp.IssuerPublicKey != k.Public {
			t.Error("the issued passport does not carry the signing key")
		}
		if sp.Code == "" || sp.Signature == "" {
			t.Error("the issued passport has no code or no signature")
		}
		if !strings.HasPrefix(sp.Code, CodePrefix) {
			t.Errorf("the code does not start with %s", CodePrefix)
		}
		if sp.Described.LoomType == "" || sp.Described.Marks == "" {
			t.Error("the issued passport was not described")
		}
		// Pure zari always draws a warning, which is the point of it.
		if len(warnings) == 0 {
			t.Error("a pure-zari passport should warn about testing")
		}
	})

	t.Run("a passport with a problem is not signed", func(t *testing.T) {
		p := sample()
		p.LoomType = "powerloom" // but it claims the Handloom Mark
		sp, problems, _ := Issue(p, k, testNow)
		if len(problems) == 0 {
			t.Fatal("a contradicting passport was issued")
		}
		if sp.Code != "" || sp.Signature != "" {
			t.Error("something was signed despite the problem")
		}
	})

	t.Run("a bad signing key stops everything", func(t *testing.T) {
		_, problems, _ := Issue(sample(), Keypair{Public: k.Public, Private: "nonsense"}, testNow)
		if len(problems) != 1 || !strings.Contains(problems[0], "Signing key") {
			t.Errorf("problems = %v, want one about the signing key", problems)
		}
	})

	t.Run("issuing twice gives the same code", func(t *testing.T) {
		first, _, _ := Issue(sample(), k, testNow)
		second, _, _ := Issue(sample(), k, testNow)
		if first.Code != second.Code {
			t.Error("the same passport signed twice produced different codes")
		}
	})
}
