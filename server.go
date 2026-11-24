package main

import (
	"embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sreenivas-sadhu-prabhakara/gi-textile-authenticity-qr-passport/internal/passport"
	"github.com/sreenivas-sadhu-prabhakara/gi-textile-authenticity-qr-passport/internal/qr"
)

//go:embed web
var webFiles embed.FS

// maxBody caps a request body. The largest thing anyone sends is a passport
// and a key, so anything above this is a mistake or a nuisance.
const maxBody = 64 << 10

// defaultSymbolLevel is the error-correction level a tag is printed at unless
// the cluster asks for another. M recovers about 15% damage, which is the
// usual choice and the right trade for a label that will be handled.
const defaultSymbolLevel = qr.LevelM

// Server holds what the handlers need.
type Server struct {
	store *Store
	// signingKey is the keypair the tool was started with, if any. It is held
	// in memory only and never written to the register.
	signingKey *passport.Keypair
	// now supplies the date, so the rules can be driven from a fixed date in
	// tests.
	now func() time.Time
}

// Routes builds the handler for everything the tool serves.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	ui, err := fs.Sub(webFiles, "web")
	if err != nil {
		panic(err)
	}
	mux.Handle("/", http.FileServer(http.FS(ui)))

	mux.HandleFunc("/api/meta", s.handleMeta)
	mux.HandleFunc("/api/keys", s.handleNewKey)
	mux.HandleFunc("/api/check", s.handleCheck)
	mux.HandleFunc("/api/issue", s.handleIssue)
	mux.HandleFunc("/api/register", s.handleRegister)
	mux.HandleFunc("/api/verify", s.handleVerify)
	mux.HandleFunc("/api/qr", s.handleQR)

	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func readJSON(w http.ResponseWriter, r *http.Request, into any) bool {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "this address takes a POST")
		return false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "the request could not be read")
		return false
	}
	if len(body) > maxBody {
		writeError(w, http.StatusRequestEntityTooLarge, "the request is too large")
		return false
	}
	if err := json.Unmarshal(body, into); err != nil {
		writeError(w, http.StatusBadRequest, "the request is not readable as JSON: "+err.Error())
		return false
	}
	return true
}

// handleMeta is everything the interface needs that is not a passport: the
// choices for each field, the measurements it judges against, the fields the
// signature covers, the regulations behind them, and what a check does not
// establish.
func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"canonicalVersion": passport.CanonicalVersion,
		"codePrefix":       passport.CodePrefix,
		"options":          passport.Options(),
		"bands":            passport.Bands(),
		"covered":          passport.CoveredFields(),
		"limits":           passport.VerificationLimits(),
		"maxCodeLength":    passport.MaxCodeLen(),
		"dateLayout":       "YYYY-MM-DD",
		"today":            passport.Today(s.now()).Format(passport.DateLayout),
		"absoluteBounds": map[string]int{
			"minLengthCm": passport.AbsoluteMinLengthCM,
			"maxLengthCm": passport.AbsoluteMaxLengthCM,
			"minWidthCm":  passport.AbsoluteMinWidthCM,
			"maxWidthCm":  passport.AbsoluteMaxWidthCM,
		},
		"regulations": map[string]string{
			"india":           passport.RegulationIndia + ", " + passport.RegulationIndiaRights,
			"philippines":     passport.RegulationPhilippines + "; " + passport.RegulationPhilippinesRules,
			"handloomMark":    passport.SchemeHandloomMark,
			"silkMark":        passport.SchemeSilkMark,
			"earliestOffLoom": passport.EarliestOffLoomDate,
		},
		"signingKeyLoaded": s.signingKey != nil,
		"clusterPublicKey": s.clusterPublicKey(),
		"registerCount":    s.store.Count(),
		"errorLevels":      levelDescriptions(),
	})
}

func levelDescriptions() []map[string]string {
	out := make([]map[string]string, 0, len(qr.Levels))
	for _, l := range qr.Levels {
		out = append(out, map[string]string{"code": l.String(), "label": l.Describe()})
	}
	return out
}

// clusterPublicKey is the key to publish: the one the tool was started with,
// or failing that the one the register's passports were issued under.
func (s *Server) clusterPublicKey() string {
	if s.signingKey != nil {
		return s.signingKey.Public
	}
	return s.store.ClusterPublicKey()
}

// handleNewKey generates a signing key. It is returned once and stored
// nowhere: writing it to the register would put it in every backup.
func (s *Server) handleNewKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "this address takes a POST")
		return
	}
	k, err := passport.NewKeypair()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"publicKey":  k.Public,
		"privateKey": k.Private,
		"warning": "This is shown once and saved nowhere. Write the private key down, keep it where the cluster keeps its seal, " +
			"and publish only the public key. Lose the private key and you cannot issue another passport under it; " +
			"let it out and anyone can issue passports in the cluster's name.",
	})
}

// issueRequest is a passport, and optionally the key to sign it with.
type issueRequest struct {
	passport.Passport
	// PrivateKey signs this passport. It may be left out when the tool was
	// started with -key.
	PrivateKey string `json:"privateKey"`
}

// keyFor returns the keypair to sign with.
func (s *Server) keyFor(req issueRequest) (passport.Keypair, error) {
	if strings.TrimSpace(req.PrivateKey) != "" {
		public, err := passport.PublicFromPrivate(req.PrivateKey)
		if err != nil {
			return passport.Keypair{}, err
		}
		return passport.Keypair{Public: public, Private: strings.Join(strings.Fields(req.PrivateKey), "")}, nil
	}
	if s.signingKey != nil {
		return *s.signingKey, nil
	}
	return passport.Keypair{}, fmt.Errorf("there is no signing key. Start the tool with -key pointing at the cluster's key file, or paste the key in")
}

// handleCheck runs every rule without signing anything, so a cluster can see
// the problems and warnings while filling the form in.
func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	var req issueRequest
	if !readJSON(w, r, &req) {
		return
	}
	p := passport.Clean(req.Passport)
	problems, warnings := passport.Check(p, s.now())
	writeJSON(w, http.StatusOK, map[string]any{
		"problems":  problems,
		"warnings":  warnings,
		"described": passport.Describe(p),
	})
}

// handleIssue validates, signs and files a passport.
func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	var req issueRequest
	if !readJSON(w, r, &req) {
		return
	}
	key, err := s.keyFor(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"problems": []string{err.Error()}})
		return
	}

	signed, problems, warnings := passport.Issue(req.Passport, key, s.now())
	if len(problems) > 0 {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"problems": problems, "warnings": warnings})
		return
	}
	record, err := s.store.Add(signed, s.now())
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"problems": []string{err.Error()}, "warnings": warnings})
		return
	}

	symbol, err := qr.Encode(passport.QRPayload(signed.Code), defaultSymbolLevel)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"problems": []string{err.Error()}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"record":   record,
		"grouped":  passport.Grouped(signed.Code),
		"warnings": warnings,
		"symbol":   symbolInfo(symbol),
	})
}

// symbolInfo describes the printed symbol in the terms a cluster printing
// tags needs: how big it is in modules, and therefore how small it can be
// printed.
func symbolInfo(m *qr.Matrix) map[string]any {
	modules := m.Size()
	return map[string]any{
		"version":   m.Version,
		"level":     m.Level.String(),
		"mask":      m.Mask,
		"modules":   modules,
		"quietZone": qr.QuietZone,
		"advice":    fmt.Sprintf("%d modules across, plus a %d-module quiet zone on every side. Printed 40 mm square each module is about %.2f mm, which needs 300 dpi or better; print it 60 mm square if the tags are being stamped rather than printed.", modules, qr.QuietZone, 40.0/float64(modules+2*qr.QuietZone)),
	}
}

// handleRegister returns the register, as JSON or as a spreadsheet.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "this address takes a GET")
		return
	}
	if serial := r.URL.Query().Get("serial"); serial != "" {
		record, ok := s.store.Find(serial)
		if !ok {
			writeError(w, http.StatusNotFound, "serial "+serial+" is not in this register")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"record": record, "grouped": passport.Grouped(record.Code)})
		return
	}
	if r.URL.Query().Get("format") == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="passport-register.csv"`)
		cw := csv.NewWriter(w)
		if err := s.store.WriteCSV(cw); err != nil {
			// The header is already out, so the only honest thing left is to
			// make the file obviously broken rather than quietly short.
			fmt.Fprintf(w, "\nerror,%q\n", err.Error())
		}
		return
	}
	records := s.store.List()
	writeJSON(w, http.StatusOK, map[string]any{
		"records":          records,
		"count":            len(records),
		"clusterPublicKey": s.clusterPublicKey(),
	})
}

// verifyRequest is what a buyer sends: a code, and the key they got from the
// cluster.
type verifyRequest struct {
	Code             string `json:"code"`
	ClusterPublicKey string `json:"clusterPublicKey"`
}

// handleVerify is the buyer's end of the tool.
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req verifyRequest
	if !readJSON(w, r, &req) {
		return
	}
	result := passport.VerifyCode(req.Code, req.ClusterPublicKey, s.now())

	// If the code happens to be in this cluster's own register, say so. It is
	// a convenience for the cluster checking its own work, and it is reported
	// separately from the signature check because a local register says
	// nothing to a buyer standing somewhere else.
	inRegister := false
	if result.Passport != nil {
		if record, ok := s.store.Find(result.Passport.Serial); ok {
			inRegister = record.Code == passport.Normalise(req.Code)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"result":         result,
		"inThisRegister": inRegister,
		"registerRemark": "A match here means only that this machine's own register holds the same code. It is not a national database, and a buyer elsewhere cannot query it.",
	})
}

// handleQR renders a code as a printable symbol.
func (s *Server) handleQR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "this address takes a GET")
		return
	}
	q := r.URL.Query()
	code := passport.QRPayload(q.Get("code"))
	if code == "" {
		writeError(w, http.StatusBadRequest, "there is no code to render")
		return
	}
	level := defaultSymbolLevel
	if s := q.Get("level"); s != "" {
		parsed, err := qr.ParseLevel(s)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		level = parsed
	}
	scale := 6
	if s := q.Get("scale"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 20 {
			writeError(w, http.StatusBadRequest, "scale is a number of pixels per module, from 1 to 20")
			return
		}
		scale = n
	}

	symbol, err := qr.Encode(code, level)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	png, err := qr.PNG(symbol, scale, qr.QuietZone)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Symbol-Version", strconv.Itoa(symbol.Version))
	w.Header().Set("X-Symbol-Modules", strconv.Itoa(symbol.Size()))
	_, _ = w.Write(png)
}
