package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"encoding/json"
)

// TestGolden: the answer of /generate for every capture under internal/testdata/golden must be byte for byte what
// cf2cnp 0.6.3 answered (the demos of the PoC that produced them). The policy types are Cilium's since 0.7.0 and the
// YAML is rendered by internal/render in cf2cnp's field order; this is the test that the swap changed nothing a
// reader would see. A deliberate change regenerates the fixtures (hack/golden/regenerate.sh) in the same commit.
func TestGolden(t *testing.T) {
	root := filepath.Join("..", "testdata", "golden")
	dirs, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(8080, "")
	n := 0
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		n++
		t.Run(d.Name(), func(t *testing.T) {
			dir := filepath.Join(root, d.Name())
			flows, err := os.ReadFile(filepath.Join(dir, "flows.ndjson"))
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(filepath.Join(dir, "expected.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			var opts map[string]string
			if b, err := os.ReadFile(filepath.Join(dir, "options.json")); err == nil {
				if err := json.Unmarshal(b, &opts); err != nil {
					t.Fatal(err)
				}
			}
			q := url.Values{}
			for k, v := range opts {
				q.Set(k, v)
			}
			target := "/generate"
			if len(q) > 0 {
				target += "?" + q.Encode()
			}
			rec := httptest.NewRecorder()
			s.handleGenerate(rec, httptest.NewRequest(http.MethodPost, target, strings.NewReader(string(flows))))
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
			}
			if got := rec.Body.String(); got != string(want) {
				t.Fatalf("output differs from 0.6.3's\n--- want\n%s\n--- got\n%s", want, got)
			}
		})
	}
	if n < 10 {
		t.Fatalf("expected the golden set, found %d cases", n)
	}
}
