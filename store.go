package main

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sreenivas-sadhu-prabhakara/gi-textile-authenticity-qr-passport/internal/passport"
)

// The register is one JSON file on the cluster's own machine. It holds the
// passports that have been issued and the public key they were issued under.
//
// It never holds the signing key. A private key in a data file is a private
// key in every backup of that file and in every copy of the machine; this tool
// takes the key from a file the cluster points at, or from the person issuing,
// and keeps it in memory for as long as it is signing.

// fileVersion tags the stored format.
const fileVersion = 1

// Record is one issued passport in the register.
type Record struct {
	passport.SignedPassport
	// IssuedAt is when this tool signed it, as a date.
	IssuedAt string `json:"issuedAt"`
}

// fileData is the whole stored file.
type fileData struct {
	Version int `json:"version"`
	// ClusterPublicKey is the key the register's passports were issued under,
	// kept so the tool can show the cluster what to publish.
	ClusterPublicKey string   `json:"clusterPublicKey,omitempty"`
	Passports        []Record `json:"passports"`
}

// Store is the register, guarded for concurrent requests.
type Store struct {
	path string
	mu   sync.RWMutex
	data fileData
}

// OpenStore reads the register at path, or starts an empty one if there is no
// file there yet.
func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, data: fileData{Version: fileVersion}}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("the register at %s could not be read: %w", path, err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return s, nil
	}
	var data fileData
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("the register at %s is not readable as JSON: %w", path, err)
	}
	if data.Version > fileVersion {
		return nil, fmt.Errorf("the register at %s was written by a later version of this tool (file version %d, this tool understands %d)", path, data.Version, fileVersion)
	}
	data.Version = fileVersion
	s.data = data
	return s, nil
}

// save writes the register atomically: a temporary file in the same directory,
// then a rename over the old one. An interrupted write leaves the previous
// register intact rather than half of a new one.
func (s *Store) save() error {
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')

	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".register-*.json")
	if err != nil {
		return fmt.Errorf("a temporary file could not be made in %s: %w", dir, err)
	}
	name := tmp.Name()
	defer os.Remove(name)

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, s.path)
}

// Add puts an issued passport in the register. A serial that is already there
// is refused: a cluster's register is the only place that can say whether a
// serial was issued once or twice, so it has to be able to answer.
func (s *Store) Add(sp passport.SignedPassport, now time.Time) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, r := range s.data.Passports {
		if strings.EqualFold(r.Serial, sp.Serial) {
			return Record{}, fmt.Errorf("serial %s is already in the register, issued on %s to %s. Give this piece its own serial",
				r.Serial, r.IssuedAt, r.WeaverName)
		}
	}

	rec := Record{SignedPassport: sp, IssuedAt: passport.Today(now).Format(passport.DateLayout)}
	s.data.Passports = append(s.data.Passports, rec)
	if s.data.ClusterPublicKey == "" {
		s.data.ClusterPublicKey = sp.IssuerPublicKey
	}
	if err := s.save(); err != nil {
		s.data.Passports = s.data.Passports[:len(s.data.Passports)-1]
		return Record{}, err
	}
	return rec, nil
}

// List returns the register, newest first.
func (s *Store) List() []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Record, len(s.data.Passports))
	copy(out, s.data.Passports)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].IssuedAt != out[j].IssuedAt {
			return out[i].IssuedAt > out[j].IssuedAt
		}
		return out[i].Serial > out[j].Serial
	})
	return out
}

// Find looks a serial up, which is what a cluster does when a buyer rings.
func (s *Store) Find(serial string) (Record, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.data.Passports {
		if strings.EqualFold(r.Serial, serial) {
			return r, true
		}
	}
	return Record{}, false
}

// ClusterPublicKey returns the key this register's passports were issued
// under.
func (s *Store) ClusterPublicKey() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.ClusterPublicKey
}

// Count returns how many passports are in the register.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.data.Passports)
}

// csvHeader is the exported register's columns.
var csvHeader = []string{
	"issued_at", "serial", "gi_name", "gi_registration_no", "role", "register_entry_no",
	"cluster", "weaver_name", "weaver_id", "loom_no", "loom_type", "article",
	"warp_fibre", "weft_fibre", "zari", "length_cm", "width_cm", "off_loom_date",
	"marks", "binding", "issuer_public_key", "signature", "code",
}

// WriteCSV exports the whole register. The coded fields are written as their
// stable names rather than their one-letter codes, so the file is readable in
// a spreadsheet without this tool to hand.
func (s *Store) WriteCSV(w *csv.Writer) error {
	if err := w.Write(csvHeader); err != nil {
		return err
	}
	for _, r := range s.List() {
		n := passport.Names(r.Passport)
		row := []string{
			r.IssuedAt, r.Serial, r.GIName, r.GIRegistrationNo, n.Role, r.RegisterEntryNo,
			r.Cluster, r.WeaverName, r.WeaverID, r.LoomNo, n.LoomType, n.Article,
			n.WarpFibre, n.WeftFibre, n.Zari, strconv.Itoa(r.LengthCM), strconv.Itoa(r.WidthCM), r.OffLoomDate,
			n.Marks, n.Binding, r.IssuerPublicKey, r.Signature, r.Code,
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}
