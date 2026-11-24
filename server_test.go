package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sreenivas-sadhu-prabhakara/gi-textile-authenticity-qr-passport/internal/passport"
	"github.com/sreenivas-sadhu-prabhakara/gi-textile-authenticity-qr-passport/internal/qr"
)

// newTestServer builds a server over a temporary register, with the date fixed
// so the rules behave the same on every machine and in every month.
func newTestServer(t *testing.T, key *passport.Keypair) (*httptest.Server, *Store) {
	t.Helper()
	store, _ := newTestStore(t)
	srv := &Server{store: store, signingKey: key, now: func() time.Time { return storeNow }}
	ts := httptest.NewServer(srv.Routes())
	t.Cleanup(ts.Close)
	return ts, store
}

func post(t *testing.T, ts *httptest.Server, path string, body any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(ts.URL+path, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decoding the reply from %s: %v", path, err)
	}
	return resp.StatusCode, out
}

func get(t *testing.T, ts *httptest.Server, path string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Get(ts.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decoding the reply from %s: %v", path, err)
	}
	return resp.StatusCode, out
}

func TestServerServesTheInterfaceFromTheBinary(t *testing.T) {
	ts, _ := newTestServer(t, nil)
	for _, path := range []string{"/", "/assets/app.js", "/assets/app.css", "/assets/style.css", "/assets/accent.css", "/assets/theme-init.js", "/assets/favicon.svg"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s returned %d", path, resp.StatusCode)
		}
		if len(body) == 0 {
			t.Errorf("%s is empty", path)
		}
	}
	// The page carries the strict policy it is written for.
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Contains(body, []byte("Content-Security-Policy")) {
		t.Error("the page has no content security policy")
	}
	for _, forbidden := range []string{"<style", "onclick=", "onsubmit=", "style=\""} {
		if bytes.Contains(body, []byte(forbidden)) {
			t.Errorf("the page contains %q", forbidden)
		}
	}
}

func TestServerMeta(t *testing.T) {
	key := testKey(t)
	ts, _ := newTestServer(t, &key)
	status, data := get(t, ts, "/api/meta")
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if data["canonicalVersion"] != passport.CanonicalVersion {
		t.Errorf("canonicalVersion = %v", data["canonicalVersion"])
	}
	if data["signingKeyLoaded"] != true {
		t.Error("the server does not report its loaded signing key")
	}
	if data["clusterPublicKey"] != key.Public {
		t.Error("the server does not report the key to publish")
	}
	if data["today"] != "2026-11-24" {
		t.Errorf("today = %v", data["today"])
	}
	options, ok := data["options"].(map[string]any)
	if !ok {
		t.Fatal("there are no options for the interface to build its menus from")
	}
	for _, field := range []string{"role", "loomType", "article", "fibre", "zari", "binding", "marks"} {
		values, ok := options[field].([]any)
		if !ok || len(values) == 0 {
			t.Errorf("there are no choices for %s", field)
		}
	}
	if bands, ok := data["bands"].([]any); !ok || len(bands) == 0 {
		t.Error("the measurements the tool judges against are not reported")
	}
	if limits, ok := data["limits"].([]any); !ok || len(limits) < 4 {
		t.Error("the limits of a check are not reported")
	}
	if covered, ok := data["covered"].([]any); !ok || len(covered) != 20 {
		t.Errorf("the covered fields are not reported properly: %v", data["covered"])
	}
}

func TestServerIssueAndVerify(t *testing.T) {
	key := testKey(t)
	ts, store := newTestServer(t, &key)

	body := map[string]any{
		"serial": "KSS-2026-004128", "giName": "Kanchipuram Silk", "giRegistrationNo": "GI 00143",
		"role": "authorised_user", "registerEntryNo": "AU/143/2019/0217",
		"cluster": "Kanchipuram Silk Weavers Co-op Society", "weaverName": "R. Saravanan",
		"weaverId": "HWID-33-004128", "loomNo": "L-27", "loomType": "handloom", "article": "saree",
		"warpFibre": "silk", "weftFibre": "silk", "zari": "none",
		"lengthCm": 823, "widthCm": 120, "offLoomDate": "2026-09-14",
		"marks": []string{"handloom_mark", "silk_mark"}, "binding": "sewn_tag",
	}

	t.Run("checking signs nothing", func(t *testing.T) {
		status, data := post(t, ts, "/api/check", body)
		if status != http.StatusOK {
			t.Fatalf("status %d: %v", status, data)
		}
		if data["problems"] != nil {
			t.Errorf("problems: %v", data["problems"])
		}
		if store.Count() != 0 {
			t.Error("checking a passport filed it")
		}
	})

	var code string
	t.Run("issuing files the passport", func(t *testing.T) {
		status, data := post(t, ts, "/api/issue", body)
		if status != http.StatusOK {
			t.Fatalf("status %d: %v", status, data)
		}
		record, ok := data["record"].(map[string]any)
		if !ok {
			t.Fatalf("there is no record in the reply: %v", data)
		}
		code, _ = record["code"].(string)
		if !strings.HasPrefix(code, passport.CodePrefix) {
			t.Errorf("the code is %q", code)
		}
		if record["issuerPublicKey"] != key.Public {
			t.Error("the passport was not signed with the loaded key")
		}
		if store.Count() != 1 {
			t.Error("the passport was not filed")
		}
		symbol, ok := data["symbol"].(map[string]any)
		if !ok || symbol["version"] == nil || symbol["modules"] == nil {
			t.Errorf("the reply does not describe the printed symbol: %v", data["symbol"])
		}
		if grouped, _ := data["grouped"].(string); !strings.Contains(grouped, " ") {
			t.Error("the reply has no grouped code for printing")
		}
	})

	t.Run("the same serial twice is refused", func(t *testing.T) {
		status, data := post(t, ts, "/api/issue", body)
		if status != http.StatusConflict {
			t.Fatalf("status %d, want 409: %v", status, data)
		}
		problems, _ := data["problems"].([]any)
		if len(problems) == 0 {
			t.Error("the refusal gives no reason")
		}
	})

	t.Run("a contradicting passport is refused", func(t *testing.T) {
		bad := map[string]any{}
		for k, v := range body {
			bad[k] = v
		}
		bad["serial"] = "KSS-2026-004130"
		bad["loomType"] = "powerloom" // still claiming the Handloom Mark
		status, data := post(t, ts, "/api/issue", bad)
		if status != http.StatusUnprocessableEntity {
			t.Fatalf("status %d, want 422: %v", status, data)
		}
		if problems, _ := data["problems"].([]any); len(problems) == 0 {
			t.Error("the refusal gives no reason")
		}
	})

	t.Run("verifying against the cluster key passes", func(t *testing.T) {
		status, data := post(t, ts, "/api/verify", map[string]string{"code": code, "clusterPublicKey": key.Public})
		if status != http.StatusOK {
			t.Fatalf("status %d", status)
		}
		result := data["result"].(map[string]any)
		if result["pass"] != true {
			t.Fatalf("a genuine passport failed: %v", result["reason"])
		}
		if data["inThisRegister"] != true {
			t.Error("the passport is in this register and the reply does not say so")
		}
		if checks, _ := result["physicalChecks"].([]any); len(checks) == 0 {
			t.Error("the buyer is given nothing to check against the cloth")
		}
	})

	t.Run("verifying with no key never passes", func(t *testing.T) {
		_, data := post(t, ts, "/api/verify", map[string]string{"code": code})
		result := data["result"].(map[string]any)
		if result["pass"] != false {
			t.Fatal("a passport passed with no trusted key supplied")
		}
		if result["selfConsistent"] != true {
			t.Error("the code is self-consistent and the reply should say so")
		}
	})

	t.Run("verifying against another cluster's key fails", func(t *testing.T) {
		other := testKey(t)
		_, data := post(t, ts, "/api/verify", map[string]string{"code": code, "clusterPublicKey": other.Public})
		result := data["result"].(map[string]any)
		if result["pass"] != false {
			t.Fatal("a passport passed against the wrong key")
		}
		if result["keyMatch"] != false {
			t.Error("the keys should not have matched")
		}
	})

	t.Run("the register can be read and exported", func(t *testing.T) {
		status, data := get(t, ts, "/api/register")
		if status != http.StatusOK {
			t.Fatalf("status %d", status)
		}
		if int(data["count"].(float64)) != 1 {
			t.Errorf("count = %v", data["count"])
		}

		resp, err := http.Get(ts.URL + "/api/register?format=csv")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/csv") {
			t.Errorf("the export is served as %q", got)
		}
		rows, err := csv.NewReader(resp.Body).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 2 {
			t.Errorf("the export has %d rows", len(rows))
		}

		status, _ = get(t, ts, "/api/register?serial=KSS-2026-004128")
		if status != http.StatusOK {
			t.Errorf("looking up a serial returned %d", status)
		}
		status, _ = get(t, ts, "/api/register?serial=NOT-A-SERIAL")
		if status != http.StatusNotFound {
			t.Errorf("looking up an unknown serial returned %d, want 404", status)
		}
	})

	t.Run("the symbol is served as a readable image", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/api/qr?code=" + url.QueryEscape(code) + "&scale=4")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d", resp.StatusCode)
		}
		if got := resp.Header.Get("Content-Type"); got != "image/png" {
			t.Errorf("served as %q", got)
		}
		png, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		// And the image really does carry the code: read it back the way a
		// scanner would.
		rows, err := qr.ModulesFromPNG(png)
		if err != nil {
			t.Fatal(err)
		}
		symbol, err := qr.FromModules(rows)
		if err != nil {
			t.Fatal(err)
		}
		got, level, _, err := qr.Decode(symbol)
		if err != nil {
			t.Fatal(err)
		}
		if got != code {
			t.Errorf("the served image decodes to %d characters, not the %d of the code", len(got), len(code))
		}
		if level != defaultSymbolLevel {
			t.Errorf("the image is at level %s, want %s", level, defaultSymbolLevel)
		}
	})
}

func TestServerWithoutASigningKey(t *testing.T) {
	ts, _ := newTestServer(t, nil)
	status, data := get(t, ts, "/api/meta")
	if status != http.StatusOK || data["signingKeyLoaded"] != false {
		t.Fatalf("meta = %v", data)
	}

	body := map[string]any{"serial": "KSS-1", "giName": "Kanchipuram Silk"}
	status, data = post(t, ts, "/api/issue", body)
	if status != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %v", status, data)
	}
	problems, _ := data["problems"].([]any)
	if len(problems) == 0 || !strings.Contains(problems[0].(string), "no signing key") {
		t.Errorf("problems = %v", problems)
	}

	t.Run("a key generated here is stored nowhere", func(t *testing.T) {
		status, data := post(t, ts, "/api/keys", map[string]string{})
		if status != http.StatusOK {
			t.Fatalf("status %d", status)
		}
		private, _ := data["privateKey"].(string)
		public, _ := data["publicKey"].(string)
		if len(private) != passport.PrivateKeyStringLen || len(public) != passport.PublicKeyStringLen {
			t.Fatalf("the generated key is the wrong length: %d and %d", len(private), len(public))
		}
		if warning, _ := data["warning"].(string); !strings.Contains(warning, "saved nowhere") {
			t.Errorf("the reply does not warn that the key is not saved: %q", warning)
		}
		// Issuing with that key works, and the key is still not stored.
		full := map[string]any{
			"serial": "KSS-2", "giName": "Kanchipuram Silk", "giRegistrationNo": "GI 00143",
			"role": "authorised_user", "registerEntryNo": "AU/143/2019/0217",
			"cluster": "Kanchipuram Silk Weavers Co-op Society", "weaverName": "R. Saravanan",
			"weaverId": "HWID-33-004128", "loomNo": "L-27", "loomType": "handloom", "article": "saree",
			"warpFibre": "silk", "weftFibre": "silk", "zari": "none",
			"lengthCm": 823, "widthCm": 120, "offLoomDate": "2026-09-14",
			"marks": []string{}, "binding": "sewn_tag", "privateKey": private,
		}
		status, data = post(t, ts, "/api/issue", full)
		if status != http.StatusOK {
			t.Fatalf("status %d: %v", status, data)
		}
		record := data["record"].(map[string]any)
		if record["issuerPublicKey"] != public {
			t.Error("the passport was not signed with the pasted key")
		}
	})
}

func TestServerRejectsBadRequests(t *testing.T) {
	key := testKey(t)
	ts, _ := newTestServer(t, &key)

	t.Run("wrong methods", func(t *testing.T) {
		for _, path := range []string{"/api/check", "/api/issue", "/api/verify", "/api/keys"} {
			resp, err := http.Get(ts.URL + path)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("GET %s returned %d, want 405", path, resp.StatusCode)
			}
		}
		for _, path := range []string{"/api/register", "/api/qr"} {
			resp, err := http.Post(ts.URL+path, "application/json", strings.NewReader("{}"))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("POST %s returned %d, want 405", path, resp.StatusCode)
			}
		}
	})

	t.Run("junk JSON", func(t *testing.T) {
		resp, err := http.Post(ts.URL+"/api/check", "application/json", strings.NewReader("{not json"))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status %d, want 400", resp.StatusCode)
		}
	})

	t.Run("an oversized body", func(t *testing.T) {
		huge := strings.Repeat("x", maxBody+100)
		resp, err := http.Post(ts.URL+"/api/check", "application/json", strings.NewReader(`{"serial":"`+huge+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Errorf("status %d, want 413", resp.StatusCode)
		}
	})

	t.Run("a bad signing key in the request", func(t *testing.T) {
		status, data := post(t, ts, "/api/issue", map[string]any{"serial": "KSS-9", "privateKey": "nonsense"})
		if status != http.StatusBadRequest {
			t.Fatalf("status %d: %v", status, data)
		}
	})

	t.Run("symbol requests", func(t *testing.T) {
		for _, c := range []struct {
			query string
			want  int
		}{
			{"", http.StatusBadRequest},
			{"?code=", http.StatusBadRequest},
			{"?code=GITP1:AAAA&level=Z", http.StatusBadRequest},
			{"?code=GITP1:AAAA&scale=0", http.StatusBadRequest},
			{"?code=GITP1:AAAA&scale=99", http.StatusBadRequest},
			{"?code=GITP1:AAAA&scale=two", http.StatusBadRequest},
			{"?code=GITP1:AAAA", http.StatusOK},
			{"?code=GITP1:AAAA&level=h&scale=2", http.StatusOK},
			{"?code=" + url.QueryEscape(strings.Repeat("A", 5000)), http.StatusBadRequest},
		} {
			resp, err := http.Get(ts.URL + "/api/qr" + c.query)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != c.want {
				t.Errorf("/api/qr%s returned %d, want %d", c.query, resp.StatusCode, c.want)
			}
		}
	})

	t.Run("an unreadable code is reported, not crashed on", func(t *testing.T) {
		status, data := post(t, ts, "/api/verify", map[string]string{"code": "rubbish", "clusterPublicKey": key.Public})
		if status != http.StatusOK {
			t.Fatalf("status %d", status)
		}
		result := data["result"].(map[string]any)
		if result["pass"] != false {
			t.Error("rubbish passed")
		}
		if limits, _ := result["limits"].([]any); len(limits) == 0 {
			t.Error("even a failed check should state its limits")
		}
	})
}

func TestSelfTestRuns(t *testing.T) {
	// The self-check is what a cluster runs before printing five hundred
	// tags, so it has to work on the machine it is run on.
	if err := runSelfTest(io.Discard); err != nil {
		t.Fatalf("the symbol generator failed its own check: %v", err)
	}
}
