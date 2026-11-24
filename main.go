// Command gi-textile-passport issues and checks provenance passports for
// woven pieces sold under a geographical indication.
//
// It is one binary with no dependencies. It serves a small web interface on
// the machine it runs on, keeps its register in one local file, and makes no
// outbound network connection of any kind.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sreenivas-sadhu-prabhakara/gi-textile-authenticity-qr-passport/internal/passport"
	"github.com/sreenivas-sadhu-prabhakara/gi-textile-authenticity-qr-passport/internal/qr"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "address to listen on; 127.0.0.1 keeps the tool off the network")
	data := flag.String("data", "./gi-textile-passport-data.json", "the register file")
	keyPath := flag.String("key", "", "a file holding the cluster's private signing key, so it need not be pasted for every passport")
	selftest := flag.Bool("qr-selftest", false, "check the symbol generator on this machine and exit")
	flag.Parse()

	if *selftest {
		if err := runSelfTest(os.Stdout); err != nil {
			log.Fatalf("the symbol generator failed its own check: %v", err)
		}
		return
	}

	store, err := OpenStore(*data)
	if err != nil {
		log.Fatal(err)
	}

	srv := &Server{store: store, now: time.Now}
	if *keyPath != "" {
		key, err := loadSigningKey(*keyPath)
		if err != nil {
			log.Fatal(err)
		}
		srv.signingKey = key
	}

	fmt.Printf("GI textile authenticity passport\n")
	fmt.Printf("  register       %s (%d passport(s))\n", *data, store.Count())
	if srv.signingKey != nil {
		fmt.Printf("  signing key    loaded from %s\n", *keyPath)
		fmt.Printf("  public key     %s\n", srv.signingKey.Public)
	} else {
		fmt.Printf("  signing key    none loaded — generate one in the interface, or start with -key\n")
	}
	fmt.Printf("  open           http://%s\n", *addr)
	fmt.Printf("\nNothing leaves this machine. There is no telemetry and no outbound connection.\n")

	server := &http.Server{
		Addr:              *addr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// loadSigningKey reads a private key from a file and derives its public half.
// The file should hold nothing but the key.
func loadSigningKey(path string) (*passport.Keypair, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("the signing key could not be read: %w", err)
	}
	private := strings.Join(strings.Fields(string(raw)), "")
	public, err := passport.PublicFromPrivate(private)
	if err != nil {
		return nil, fmt.Errorf("%s does not hold a signing key: %w", path, err)
	}
	key := &passport.Keypair{Public: public, Private: private}
	if err := key.Validate(); err != nil {
		return nil, err
	}

	// A signing key readable by everyone on the machine is not a signing key.
	if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(os.Stderr, "warning: %s is readable by others (mode %#o). Run: chmod 600 %s\n", path, info.Mode().Perm(), path)
	}
	return key, nil
}

// runSelfTest proves the symbol generator on the machine that will print the
// tags, before anybody prints five hundred of them. It builds a passport of
// the longest shape this tool will issue, renders it, reads the image back to
// a grid of modules, and decodes it — recovering the error-correction level
// and the mask from the symbol itself rather than remembering them.
func runSelfTest(out io.Writer) error {
	key, err := passport.NewKeypair()
	if err != nil {
		return err
	}
	sample := passport.Passport{
		Serial: "SELFTEST-0001", GIName: "Self test weave", GIRegistrationNo: "SELFTEST 0001",
		Role: "authorised_user", RegisterEntryNo: "AU/0001/0001",
		Cluster: "Self test weavers co-operative society", WeaverName: "Self test weaver",
		WeaverID: "SELFTEST-0001", LoomNo: "L-01", LoomType: "handloom", Article: "saree",
		WarpFibre: "silk", WeftFibre: "silk", Zari: "none",
		LengthCM: 823, WidthCM: 120, OffLoomDate: passport.Today(time.Now()).Format(passport.DateLayout),
		Marks: []string{"handloom_mark"}, Binding: "sewn_tag",
	}
	signed, problems, _ := passport.Issue(sample, key, time.Now())
	if len(problems) > 0 {
		return fmt.Errorf("the sample passport would not issue: %s", strings.Join(problems, "; "))
	}

	payload := passport.QRPayload(signed.Code)
	fmt.Fprintf(out, "payload        %d characters, %s mode\n", len(payload), qr.BestMode(payload))

	for _, level := range qr.Levels {
		symbol, err := qr.Encode(payload, level)
		if err != nil {
			return fmt.Errorf("level %s: %w", level, err)
		}
		png, err := qr.PNG(symbol, 4, qr.QuietZone)
		if err != nil {
			return fmt.Errorf("level %s: %w", level, err)
		}
		rows, err := qr.ModulesFromPNG(png)
		if err != nil {
			return fmt.Errorf("level %s: reading the rendered image back: %w", level, err)
		}
		read, err := qr.FromModules(rows)
		if err != nil {
			return fmt.Errorf("level %s: %w", level, err)
		}
		got, gotLevel, gotMask, err := qr.Decode(read)
		if err != nil {
			return fmt.Errorf("level %s: decoding the rendered symbol: %w", level, err)
		}
		if got != payload {
			return fmt.Errorf("level %s: the symbol read back as %d characters, not the %d that went in", level, len(got), len(payload))
		}
		if gotLevel != level {
			return fmt.Errorf("level %s: the symbol says its level is %s", level, gotLevel)
		}
		if gotMask != symbol.Mask {
			return fmt.Errorf("level %s: the symbol says its mask is %d, not %d", level, gotMask, symbol.Mask)
		}
		fmt.Fprintf(out, "level %s        version %d, %d modules across, mask %d, %d byte image — rendered, read back and decoded\n",
			level, symbol.Version, symbol.Size(), symbol.Mask, len(png))
	}

	// And the whole round trip the buyer depends on.
	result := passport.VerifyCode(signed.Code, key.Public, time.Now())
	if !result.Pass {
		return fmt.Errorf("the sample passport did not verify against its own key: %s", result.Reason)
	}
	if bad := passport.VerifyCode(signed.Code, "", time.Now()); bad.Pass {
		return fmt.Errorf("a passport verified with no trusted key supplied, which must never happen")
	}
	fmt.Fprintf(out, "signature      signed, verified against the published key, and refused with no key supplied\n")
	fmt.Fprintf(out, "\nThe symbol generator works on this machine.\n")
	return nil
}
