package passport

import (
	"strings"
	"testing"
)

// issueSample issues the sample passport under a fresh key and returns both.
func issueSample(t *testing.T) (SignedPassport, Keypair) {
	t.Helper()
	k := mustKeypair(t)
	sp, problems, _ := Issue(sample(), k, testNow)
	if len(problems) > 0 {
		t.Fatalf("problems: %v", problems)
	}
	return sp, k
}

func TestVerifyCodePasses(t *testing.T) {
	sp, k := issueSample(t)
	res := VerifyCode(sp.Code, k.Public, testNow)

	if !res.Pass {
		t.Fatalf("a genuine passport failed: %s", res.Reason)
	}
	if !res.SelfConsistent || !res.KeyMatch {
		t.Errorf("selfConsistent = %v, keyMatch = %v, want both true", res.SelfConsistent, res.KeyMatch)
	}
	if res.CheckedAgainst != k.Public {
		t.Error("the result does not say which key it checked against")
	}
	if res.Passport == nil || res.Passport.Serial != sp.Serial {
		t.Error("the result does not carry the passport it read")
	}
	if len(res.Covered) != len(fieldSpecs) {
		t.Errorf("the result lists %d covered fields, want %d", len(res.Covered), len(fieldSpecs))
	}
	if len(res.Limits) < 4 {
		t.Errorf("a passing result carries only %d statements of what it does not establish", len(res.Limits))
	}
	if !res.BoundToPiece {
		t.Error("a sewn-in tag should count as bound to the piece")
	}
	if len(res.PhysicalChecks) == 0 {
		t.Error("a passing result gives the buyer nothing to check against the cloth")
	}
	if res.Age == "" {
		t.Error("the result does not say how old the piece is")
	}
	if len(res.Inconsistencies) != 0 {
		t.Errorf("a valid passport has inconsistencies: %v", res.Inconsistencies)
	}
	if len(res.Marks) != 2 {
		t.Errorf("the result describes %d claimed marks, want 2", len(res.Marks))
	}
}

// TestVerifyNeverPassesOnTheKeyInsideTheCode is the rule the whole tool rests
// on. A forger can generate a keypair in a second, sign any passport they like
// with it and put their own public key in the code; that code is perfectly
// self-consistent. Only a key the buyer got from the cluster some other way
// can tell the two apart, so the check refuses to pass without one.
func TestVerifyNeverPassesOnTheKeyInsideTheCode(t *testing.T) {
	genuine, cluster := issueSample(t)

	// The forger's own passport, signed with the forger's own key.
	forger := mustKeypair(t)
	forged, problems, _ := Issue(sample(), forger, testNow)
	if len(problems) > 0 {
		t.Fatal(problems)
	}

	t.Run("no key supplied", func(t *testing.T) {
		res := VerifyCode(forged.Code, "", testNow)
		if res.Pass {
			t.Fatal("a forged passport passed with no key supplied")
		}
		if !res.SelfConsistent {
			t.Error("the forged code is in fact self-consistent; the result should say so")
		}
		if res.KeyMatch {
			t.Error("nothing was supplied to match")
		}
		if !strings.Contains(res.Reason, "forged or genuine") {
			t.Errorf("the reason does not explain that a code always verifies against its own key: %q", res.Reason)
		}
	})

	t.Run("no key supplied, genuine passport", func(t *testing.T) {
		// Even the genuine article must not pass without a trusted key: the
		// check would be meaningless, and a buyer shown a pass would learn
		// nothing.
		res := VerifyCode(genuine.Code, "", testNow)
		if res.Pass {
			t.Fatal("a genuine passport passed with no key supplied, which proves nothing")
		}
	})

	t.Run("the cluster's key refuses the forgery", func(t *testing.T) {
		res := VerifyCode(forged.Code, cluster.Public, testNow)
		if res.Pass {
			t.Fatal("a forged passport passed against the cluster's key")
		}
		if res.KeyMatch {
			t.Error("the forger's key matched the cluster's")
		}
		if !res.SelfConsistent {
			t.Error("the forgery is self-consistent; saying otherwise would mislead")
		}
		if !strings.Contains(res.Reason, "different key") {
			t.Errorf("the reason does not say the key is a different one: %q", res.Reason)
		}
	})

	t.Run("whitespace in the supplied key is tolerated", func(t *testing.T) {
		spaced := "  " + cluster.Public[:20] + "\n" + cluster.Public[20:] + " \n"
		if res := VerifyCode(genuine.Code, spaced, testNow); !res.Pass {
			t.Fatalf("a key pasted with line breaks failed: %s", res.Reason)
		}
	})

	t.Run("a key that cannot be read is reported, not ignored", func(t *testing.T) {
		res := VerifyCode(genuine.Code, "not-a-key", testNow)
		if res.Pass {
			t.Fatal("an unreadable key passed")
		}
		if !strings.Contains(res.Reason, "could not be read") {
			t.Errorf("reason = %q", res.Reason)
		}
	})
}

func TestVerifyRefusesAlteredAndBrokenCodes(t *testing.T) {
	sp, k := issueSample(t)

	// Alter the signed content and re-pack it with the original signature.
	altered := sp.Passport
	altered.LoomType = "P"
	sig, err := ParseSignature(sp.Signature)
	if err != nil {
		t.Fatal(err)
	}
	alteredCode, err := EncodeCode(altered, sig)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		code string
		key  string
		want string
	}{
		{"nothing at all", "", k.Public, "no code here"},
		{"a code with the wrong prefix", "HELLO:ABCDEF", k.Public, "starts with"},
		{"a code with no prefix", "ABCDEFGH", k.Public, "starts with"},
		{"characters that are not in the alphabet", CodePrefix + "ABC!@#", k.Public, "not part of a passport code"},
		{"too short to hold a signature", CodePrefix + "AAAAAAAA", k.Public, "too short"},
		{"a code of the right shape but random content", CodePrefix + strings.Repeat("A", 800), k.Public, "version header"},
		{"the content altered after signing", alteredCode, k.Public, "does not match these details"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := VerifyCode(c.code, c.key, testNow)
			if res.Pass {
				t.Fatal("this passed and should not have")
			}
			if !strings.Contains(res.Reason, c.want) {
				t.Errorf("reason %q does not mention %q", res.Reason, c.want)
			}
			// Whatever went wrong, the buyer is always told what a check does
			// not establish.
			if len(res.Limits) == 0 {
				t.Error("the result carries no statement of its limits")
			}
		})
	}

	t.Run("one character changed anywhere in the code is caught", func(t *testing.T) {
		body := strings.TrimPrefix(sp.Code, CodePrefix)
		// Walk a spread of positions rather than all of them, covering the
		// passport bytes and the signature bytes.
		for i := 0; i < len(body); i += 37 {
			swapped := []byte(body)
			if swapped[i] == 'A' {
				swapped[i] = 'B'
			} else {
				swapped[i] = 'A'
			}
			res := VerifyCode(CodePrefix+string(swapped), k.Public, testNow)
			if res.Pass {
				t.Fatalf("changing character %d of the code went unnoticed", i)
			}
		}
	})
}

func TestVerifyReportsAnUnboundPassport(t *testing.T) {
	k := mustKeypair(t)
	p := sample()
	p.Binding = "not_bound"
	sp, problems, warnings := Issue(p, k, testNow)
	if len(problems) > 0 {
		t.Fatal(problems)
	}
	if len(warnings) == 0 {
		t.Error("issuing an unbound passport should warn")
	}
	foundWarning := false
	for _, w := range warnings {
		if strings.Contains(w, "not bound to the piece") {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Errorf("warnings do not mention the binding: %v", warnings)
	}

	res := VerifyCode(sp.Code, k.Public, testNow)
	if !res.Pass {
		t.Fatalf("the signature should still be valid: %s", res.Reason)
	}
	if res.BoundToPiece {
		t.Error("an unbound passport is reported as bound to the piece")
	}
	if !strings.Contains(res.Reason, "not fastened to the cloth") {
		t.Errorf("the reason does not say the passport is not fastened to the cloth: %q", res.Reason)
	}
	found := false
	for _, c := range res.PhysicalChecks {
		if strings.Contains(c.Do, "describing a piece, not this piece") {
			found = true
		}
	}
	if !found {
		t.Error("the checks do not tell the buyer what an unbound passport is worth")
	}
}

func TestVerifyReportsInconsistenciesInSignedContent(t *testing.T) {
	// A cluster can sign something that does not add up — a key holder is not
	// thereby careful. Repack a contradiction under a valid signature and
	// check the buyer is told.
	k := mustKeypair(t)
	priv, err := ParsePrivateKey(k.Private)
	if err != nil {
		t.Fatal(err)
	}
	p := sample()
	p.IssuerPublicKey = k.Public
	p.LoomType = "P" // powerloom, while still claiming the Handloom Mark
	sig, err := Sign(p, priv)
	if err != nil {
		t.Fatal(err)
	}
	code, err := EncodeCode(p, sig)
	if err != nil {
		t.Fatal(err)
	}

	res := VerifyCode(code, k.Public, testNow)
	if !res.Pass {
		t.Fatalf("the signature is valid, so the check should pass: %s", res.Reason)
	}
	if len(res.Inconsistencies) == 0 {
		t.Fatal("a Handloom Mark on a powerloom piece was not reported")
	}
	if !strings.Contains(strings.Join(res.Inconsistencies, " "), "Handloom Mark") {
		t.Errorf("inconsistencies = %v", res.Inconsistencies)
	}
}

func TestPhysicalChecksCoverWhatMatters(t *testing.T) {
	cases := []struct {
		name    string
		change  func(*Passport)
		mustSay []string
	}{
		{
			name:    "a handwoven piece with both marks",
			change:  func(p *Passport) {},
			mustSay: []string{"stitched into the piece", "Measure the piece", "handwoven", "Handloom Mark", "Silk Mark", "read them the serial", "Confirm registration number"},
		},
		{
			name:    "a powerloom piece",
			change:  func(p *Passport) { p.LoomType = "powerloom"; p.Marks = nil },
			mustSay: []string{"does not claim handwoven cloth", "should not be priced as handloom"},
		},
		{
			name:    "woven into the selvedge",
			change:  func(p *Passport) { p.Binding = "woven_selvedge" },
			mustSay: []string{"woven into the selvedge", "cannot be moved to another piece"},
		},
		{
			name:    "a heat-sealed label",
			change:  func(p *Passport) { p.Binding = "heat_sealed_label" },
			mustSay: []string{"heat-sealed label"},
		},
		{
			name:    "different fibres in warp and weft",
			change:  func(p *Passport) { p.WarpFibre = "silk"; p.WeftFibre = "cotton"; p.Marks = nil },
			mustSay: []string{"silk in the warp", "cotton in the weft"},
		},
		{
			name:    "a Philippine abaca piece",
			change:  func(p *Passport) { p.WarpFibre = "abaca"; p.WeftFibre = "abaca"; p.Marks = nil; p.Zari = "none" },
			mustSay: []string{"abaca in both the warp and the weft"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := sample()
			c.change(&p)
			p = Clean(p)
			joined := ""
			for _, check := range PhysicalChecks(p, testNow) {
				if check.Do == "" || check.Why == "" {
					t.Errorf("a check is missing its instruction or its reason: %+v", check)
				}
				joined += check.Do + " " + check.Why + "\n"
			}
			for _, want := range c.mustSay {
				if !strings.Contains(joined, want) {
					t.Errorf("the checks do not mention %q", want)
				}
			}
		})
	}
}

func TestLimitsSayWhatASignatureDoesNotEstablish(t *testing.T) {
	joined := strings.Join(VerificationLimits(), "\n")
	for _, want := range []string{
		"not one character of it has changed",
		"does not mean the cloth in your hands is the piece described",
		"sewn onto a counterfeit piece",
		"does not mean the facts are true",
		"does not check the geographical indication register",
		"issued twice",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("the limits do not say %q", want)
		}
	}
}
