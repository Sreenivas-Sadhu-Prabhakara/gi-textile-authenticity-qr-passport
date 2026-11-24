package main

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sreenivas-sadhu-prabhakara/gi-textile-authenticity-qr-passport/internal/passport"
)

var storeNow = time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)

func testPassport(serial string) passport.Passport {
	return passport.Passport{
		Serial: serial, GIName: "Kanchipuram Silk", GIRegistrationNo: "GI 00143",
		Role: "authorised_user", RegisterEntryNo: "AU/143/2019/0217",
		Cluster: "Kanchipuram Silk Weavers Co-op Society", WeaverName: "R. Saravanan",
		WeaverID: "HWID-33-004128", LoomNo: "L-27", LoomType: "handloom", Article: "saree",
		WarpFibre: "silk", WeftFibre: "silk", Zari: "none",
		LengthCM: 823, WidthCM: 120, OffLoomDate: "2026-09-14",
		Marks: []string{"handloom_mark", "silk_mark"}, Binding: "sewn_tag",
	}
}

func issueInto(t *testing.T, s *Store, k passport.Keypair, serial string) Record {
	t.Helper()
	signed, problems, _ := passport.Issue(testPassport(serial), k, storeNow)
	if len(problems) > 0 {
		t.Fatalf("problems: %v", problems)
	}
	record, err := s.Add(signed, storeNow)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "register.json")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	return s, path
}

func testKey(t *testing.T) passport.Keypair {
	t.Helper()
	k, err := passport.NewKeypair()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestStoreStartsEmptyAndPersists(t *testing.T) {
	store, path := newTestStore(t)
	if store.Count() != 0 {
		t.Fatalf("a new register holds %d passports", store.Count())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("opening a register that does not exist should not create a file")
	}

	k := testKey(t)
	record := issueInto(t, store, k, "KSS-1")
	if record.IssuedAt != "2026-11-24" {
		t.Errorf("issued at %q", record.IssuedAt)
	}

	// The file is written only readable by its owner: it holds every
	// passport the cluster has signed.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("the register was written with mode %#o, want 0600", perm)
	}

	// And it comes back.
	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Count() != 1 {
		t.Fatalf("the reopened register holds %d passports", reopened.Count())
	}
	if got, ok := reopened.Find("KSS-1"); !ok || got.Code != record.Code {
		t.Error("the passport did not survive being written and read")
	}
	if reopened.ClusterPublicKey() != k.Public {
		t.Error("the register does not remember the key its passports were issued under")
	}
}

func TestStoreRefusesADuplicateSerial(t *testing.T) {
	store, _ := newTestStore(t)
	k := testKey(t)
	issueInto(t, store, k, "KSS-1")

	signed, problems, _ := passport.Issue(testPassport("kss-1"), k, storeNow)
	if len(problems) > 0 {
		t.Fatal(problems)
	}
	_, err := store.Add(signed, storeNow)
	if err == nil {
		t.Fatal("a serial already in the register was accepted again")
	}
	for _, want := range []string{"already in the register", "2026-11-24", "R. Saravanan"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal %q does not mention %q", err, want)
		}
	}
	if store.Count() != 1 {
		t.Errorf("the register holds %d passports after a refused add", store.Count())
	}
}

func TestStoreListAndFind(t *testing.T) {
	store, _ := newTestStore(t)
	k := testKey(t)
	for _, serial := range []string{"KSS-1", "KSS-2", "KSS-3"} {
		issueInto(t, store, k, serial)
	}

	list := store.List()
	if len(list) != 3 {
		t.Fatalf("the register lists %d passports", len(list))
	}
	// Same day for all three, so the serial breaks the tie, newest first.
	if list[0].Serial != "KSS-3" || list[2].Serial != "KSS-1" {
		t.Errorf("the register is in the order %s, %s, %s", list[0].Serial, list[1].Serial, list[2].Serial)
	}
	// The returned slice is a copy: changing it must not change the register.
	list[0].Serial = "TAMPERED"
	if again := store.List(); again[0].Serial == "TAMPERED" {
		t.Error("List returns the register's own slice")
	}

	for _, c := range []struct {
		in string
		ok bool
	}{{"KSS-2", true}, {"kss-2", true}, {"KSS-9", false}, {"", false}} {
		if _, ok := store.Find(c.in); ok != c.ok {
			t.Errorf("Find(%q) found = %v, want %v", c.in, ok, c.ok)
		}
	}
}

func TestStoreRejectsUnreadableFiles(t *testing.T) {
	dir := t.TempDir()

	t.Run("not JSON", func(t *testing.T) {
		path := filepath.Join(dir, "junk.json")
		if err := os.WriteFile(path, []byte("this is not JSON"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenStore(path); err == nil || !strings.Contains(err.Error(), "not readable as JSON") {
			t.Errorf("error = %v", err)
		}
	})

	t.Run("written by a later version", func(t *testing.T) {
		path := filepath.Join(dir, "future.json")
		if err := os.WriteFile(path, []byte(`{"version":99,"passports":[]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenStore(path); err == nil || !strings.Contains(err.Error(), "later version") {
			t.Errorf("error = %v", err)
		}
	})

	t.Run("an empty file is an empty register", func(t *testing.T) {
		path := filepath.Join(dir, "empty.json")
		if err := os.WriteFile(path, []byte("  \n"), 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := OpenStore(path)
		if err != nil {
			t.Fatal(err)
		}
		if s.Count() != 0 {
			t.Error("an empty file should be an empty register")
		}
	})
}

func TestStoreCSV(t *testing.T) {
	store, _ := newTestStore(t)
	k := testKey(t)
	issueInto(t, store, k, "KSS-1")

	var buf bytes.Buffer
	if err := store.WriteCSV(csv.NewWriter(&buf)); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(bytes.NewReader(buf.Bytes())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("the export has %d rows, want a header and one passport", len(rows))
	}
	if len(rows[0]) != len(csvHeader) {
		t.Errorf("the header has %d columns, want %d", len(rows[0]), len(csvHeader))
	}
	row := map[string]string{}
	for i, name := range rows[0] {
		row[name] = rows[1][i]
	}
	// The coded fields are exported as names, not as one-letter codes, so the
	// file reads in a spreadsheet without this tool.
	for field, want := range map[string]string{
		"serial":     "KSS-1",
		"loom_type":  "handloom",
		"article":    "saree",
		"warp_fibre": "silk",
		"role":       "authorised_user",
		"binding":    "sewn_tag",
		"marks":      "handloom_mark silk_mark",
		"length_cm":  "823",
		"issued_at":  "2026-11-24",
		"zari":       "none",
	} {
		if row[field] != want {
			t.Errorf("column %s = %q, want %q", field, row[field], want)
		}
	}
	if row["code"] == "" || row["signature"] == "" || row["issuer_public_key"] != k.Public {
		t.Error("the export is missing the code, the signature or the key")
	}
}

func TestStoreSurvivesAFailedWrite(t *testing.T) {
	// A register whose directory has gone cannot be written. The in-memory
	// register must not pretend the passport was filed.
	dir := t.TempDir()
	path := filepath.Join(dir, "gone", "register.json")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	k := testKey(t)
	signed, problems, _ := passport.Issue(testPassport("KSS-1"), k, storeNow)
	if len(problems) > 0 {
		t.Fatal(problems)
	}
	if _, err := store.Add(signed, storeNow); err == nil {
		t.Fatal("filing a passport into a directory that does not exist succeeded")
	}
	if store.Count() != 0 {
		t.Errorf("the register holds %d passports after a failed write", store.Count())
	}
}
