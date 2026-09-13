package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hubble-policy-gen/internal/flow"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func post(t *testing.T, s *Server, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Host = "cf2cnp.example.test"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.handleGenerate(rec, req)
	return rec
}

func jsonBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var m map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("not JSON: %v: %s", err, rec.Body.String())
	}
	return m
}

// Before the fix a server behind a TLS-terminating gateway answered http://…: the listener has no TLS,
// and the proxy headers were not read. Each case is one way the base can be known.
func TestDownloadURL_Scheme(t *testing.T) {
	flow := fixture(t, "ingress-pos-to-shop.json")
	cases := []struct {
		name    string
		server  *Server
		headers map[string]string
		want    string
	}{
		{"plain request, no proxy", NewServer(8080, ""), nil, "http://cf2cnp.example.test/download/"},
		{"X-Forwarded-Proto https", NewServer(8080, ""), map[string]string{"X-Forwarded-Proto": "https"}, "https://cf2cnp.example.test/download/"},
		{"X-Forwarded-Proto list (first wins)", NewServer(8080, ""), map[string]string{"X-Forwarded-Proto": "https, http"}, "https://cf2cnp.example.test/download/"},
		{"X-Forwarded-Host too", NewServer(8080, ""), map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "cf2cnp.poc.local"}, "https://cf2cnp.poc.local/download/"},
		{"RFC 7239 Forwarded", NewServer(8080, ""), map[string]string{"Forwarded": `for=10.0.0.1;proto=https;host="cf2cnp.poc.local"`}, "https://cf2cnp.poc.local/download/"},
		{"garbage proto is ignored", NewServer(8080, ""), map[string]string{"X-Forwarded-Proto": "gopher"}, "http://cf2cnp.example.test/download/"},
		{"--external-url wins over headers", NewServer(8080, "https://policies.example.com/cf2cnp/"), map[string]string{"X-Forwarded-Proto": "http"}, "https://policies.example.com/cf2cnp/download/"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := map[string]string{"Accept": "application/json"}
			for k, v := range c.headers {
				h[k] = v
			}
			m := jsonBody(t, post(t, c.server, "/generate", flow, h))
			got, _ := m["download_url"].(string)
			if !strings.HasPrefix(got, c.want) {
				t.Fatalf("download_url = %q, want prefix %q", got, c.want)
			}
		})
	}
}

// Review finding: Forwarded (RFC 7239) must beat X-Forwarded-*, and a host header is a host, not a path
func TestDownloadURL_PrecedenceAndHostSanity(t *testing.T) {
	flow := fixture(t, "ingress-pos-to-shop.json")
	cases := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{"Forwarded wins over X-Forwarded-*", map[string]string{"Forwarded": `for=10.0.0.1;proto=https;host="cf2cnp.poc.local"`, "X-Forwarded-Proto": "http", "X-Forwarded-Host": "evil.example"}, "https://cf2cnp.poc.local/download/"},
		{"X-Forwarded-Host with a path is ignored", map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "evil.example/steal"}, "https://cf2cnp.example.test/download/"},
		{"trailing slash is not a host", map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "cf2cnp.poc.local/"}, "https://cf2cnp.example.test/download/"},
		{"CRLF in host is ignored", map[string]string{"X-Forwarded-Host": "evil.example\r\nX-Injected: 1"}, "http://cf2cnp.example.test/download/"},
		{"blank X-Forwarded-Host keeps r.Host", map[string]string{"X-Forwarded-Host": "   "}, "http://cf2cnp.example.test/download/"},
		{"Forwarded for= only", map[string]string{"Forwarded": "for=10.0.0.1"}, "http://cf2cnp.example.test/download/"},
		{"userinfo in host is ignored", map[string]string{"X-Forwarded-Host": "a@evil.example"}, "http://cf2cnp.example.test/download/"},
		{"host with port is a host", map[string]string{"X-Forwarded-Host": "cf2cnp.poc.local:8443", "X-Forwarded-Proto": "https"}, "https://cf2cnp.poc.local:8443/download/"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := map[string]string{"Accept": "application/json"}
			for k, v := range c.headers {
				h[k] = v
			}
			m := jsonBody(t, post(t, NewServer(8080, ""), "/generate", flow, h))
			got, _ := m["download_url"].(string)
			if !strings.HasPrefix(got, c.want) || strings.Contains(got, "//download") {
				t.Fatalf("download_url = %q, want prefix %q", got, c.want)
			}
		})
	}
}

func TestGenerate_BodyLimit(t *testing.T) {
	s := NewServer(8080, "")
	rec := post(t, s, "/generate", strings.Repeat("x", maxBodyBytes+1), nil)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize body: %d %s", rec.Code, rec.Body.String())
	}
	// a large but legitimate body: 500 flows
	body := strings.Repeat(fixture(t, "ingress-pos-to-shop.json")+"\n", 500)
	m := jsonBody(t, post(t, s, "/generate", body, map[string]string{"Accept": "application/json"}))
	if m["flows"].(float64) != 500 || m["policies"].(float64) != 1 {
		t.Fatalf("500 identical flows must be one policy: flows=%v policies=%v", m["flows"], m["policies"])
	}
}

func TestGenerate_GrafanaActionKeepsFlowUUIDAndServesDownload(t *testing.T) {
	s := NewServer(8080, "")
	flow := fixture(t, "ingress-pos-to-shop.json")
	m := jsonBody(t, post(t, s, "/generate", flow, map[string]string{"X-Grafana-Action": "1", "X-Forwarded-Proto": "https"}))
	url, _ := m["download_url"].(string)
	if !strings.HasSuffix(url, "/download/6a6f5d0f-9a1e-4a7e-9f39-1e1c6b7a2c11") && !strings.Contains(url, "/download/") {
		t.Fatalf("unexpected download_url %q", url)
	}
	id := url[strings.LastIndex(url, "/")+1:]
	var uuid struct {
		Flow struct {
			UUID string `json:"uuid"`
		} `json:"flow"`
	}
	json.Unmarshal([]byte(flow), &uuid)
	if id != uuid.Flow.UUID {
		t.Fatalf("cache id must be the flow's uuid (%s), got %s", uuid.Flow.UUID, id)
	}
	if m["filename"] != "cf2cnp-lab-shop.yaml" || m["flows"].(float64) != 1 || m["policies"].(float64) != 1 || !strings.Contains(m["yaml"].(string), "kind: CiliumNetworkPolicy") {
		t.Fatalf("answer must carry filename, counts and the yaml: %v", m)
	}
	req := httptest.NewRequest(http.MethodGet, "/download/"+id, nil)
	rec := httptest.NewRecorder()
	s.handleDownload(rec, req)
	if rec.Code != 200 || rec.Header().Get("Content-Disposition") != `attachment; filename="cf2cnp-lab-shop.yaml"` {
		t.Fatalf("download: %d %v", rec.Code, rec.Header())
	}
}

func TestGenerate_ManyFlowsOneBody(t *testing.T) {
	s := NewServer(8080, "")
	body := fixture(t, "ingress-pos-to-shop.json") + "\n" + fixture(t, "ingress-stranger-to-shop.json") + "\n" + fixture(t, "egress-pos-to-world.json")
	rec := post(t, s, "/generate", body, nil)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	yaml := rec.Body.String()
	if strings.Count(yaml, "kind: CiliumNetworkPolicy") != 2 || strings.Count(yaml, "fromEndpoints") != 2 {
		t.Fatalf("three flows must become two policies, shop with two peers:\n%s", yaml)
	}
	if rec.Header().Get("Content-Disposition") != `attachment; filename="ciliumnetworkpolicies-2.yaml"` {
		t.Fatalf("filename for several policies: %s", rec.Header().Get("Content-Disposition"))
	}
	m := jsonBody(t, post(t, s, "/generate", body, map[string]string{"Accept": "application/json"}))
	if m["flows"].(float64) != 3 || m["policies"].(float64) != 2 {
		t.Fatalf("counts: %v", m)
	}
}

func TestGenerate_NameParam(t *testing.T) {
	s := NewServer(8080, "")
	rec := post(t, s, "/generate?name=shop-from-pos", fixture(t, "ingress-pos-to-shop.json"), nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "name: shop-from-pos") || rec.Header().Get("Content-Disposition") != `attachment; filename="cf2cnp-lab-shop-from-pos.yaml"` {
		t.Fatalf("%d %s %s", rec.Code, rec.Header().Get("Content-Disposition"), rec.Body.String())
	}
	rec = post(t, s, "/generate?name=x", fixture(t, "ingress-pos-to-shop.json")+"\n"+fixture(t, "egress-pos-to-world.json"), nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "single policy") {
		t.Fatalf("a name over two policies must be a 400 with the reason, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestGenerate_BadInputs(t *testing.T) {
	s := NewServer(8080, "")
	if rec := post(t, s, "/generate", "", nil); rec.Code != 400 || !strings.Contains(rec.Body.String(), "empty") {
		t.Fatalf("empty body: %d %s", rec.Code, rec.Body.String())
	}
	if rec := post(t, s, "/generate", "{not json", nil); rec.Code != 400 {
		t.Fatalf("bad json: %d", rec.Code)
	}
	reply := strings.Replace(fixture(t, "ingress-pos-to-shop.json"), `"is_reply":false`, `"is_reply":true`, 1)
	if rec := post(t, s, "/generate", reply, nil); rec.Code != 400 || !strings.Contains(rec.Body.String(), "reply packet") {
		t.Fatalf("reply flow: %d %s", rec.Code, rec.Body.String())
	}
}

func TestYolo_JSONUsesBaseURL(t *testing.T) {
	m := jsonBody(t, post(t, NewServer(8080, ""), "/generate", "yolo ns dev", map[string]string{"Accept": "application/json", "X-Forwarded-Proto": "https"}))
	if !strings.HasPrefix(m["download_url"].(string), "https://cf2cnp.example.test/download/") || m["filename"] != "dev-yolo-allow-all-in-namespace.yaml" {
		t.Fatalf("%v", m)
	}
}

// E4: ?exclude=key=value drops the flows whose peer carries it; the peer is the source for INGRESS
func TestGenerate_ExcludePeers(t *testing.T) {
	s := NewServer(8080, "")
	body := fixture(t, "ingress-pos-to-shop.json") + "\n" + fixture(t, "ingress-stranger-to-shop.json")
	rec := post(t, s, "/generate?exclude=app.kubernetes.io%2Fname%3Dstranger", body, nil)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "stranger") || !strings.Contains(rec.Body.String(), "pos") {
		t.Fatalf("stranger must be gone, pos kept: %d %s", rec.Code, rec.Body.String())
	}
	rec = post(t, s, "/generate?exclude=app.kubernetes.io%2Fname%3Dnobody", body, nil)
	if rec.Code != 200 || strings.Count(rec.Body.String(), "fromEndpoints") != 2 {
		t.Fatalf("an exclude that matches nothing changes nothing: %d %s", rec.Code, rec.Body.String())
	}
	rec = post(t, s, "/generate?exclude=app.kubernetes.io%2Fname%3Dpos&exclude=app.kubernetes.io%2Fname%3Dstranger", body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("everything excluded must be a 400, got %d", rec.Code)
	}
	// EGRESS: the peer is the destination; excluding the source does nothing
	rec = post(t, s, "/generate?exclude=app.kubernetes.io%2Fname%3Dpos", fixture(t, "egress-pos-to-world.json"), nil)
	if rec.Code != 200 {
		t.Fatalf("egress flow: the source is not the peer, got %d", rec.Code)
	}
}

// Review finding: the exclude key must be the label the parser keeps — a peer with only an instance label (no
// name) is named by instance, and an exclude on its fallback app label must not match
func TestExclude_UsesTheLabelTheParserKeeps(t *testing.T) {
	f := &flow.ParsedFlow{Direction: "INGRESS", SourceLabels: map[string]string{"app.kubernetes.io/instance": "blue"}}
	if n := excludeFlows([]*flow.ParsedFlow{f}, []string{"app=payments"}); len(n) != 1 {
		t.Fatalf("exclude=app= must not drop a peer the parser named by instance")
	}
	if n := excludeFlows([]*flow.ParsedFlow{f}, []string{"app.kubernetes.io/instance=blue"}); len(n) != 0 {
		t.Fatalf("exclude=instance= must drop that peer")
	}
	// and the page's list is the parser's list, in order (kept in sync by this test reading the served page)
	rec := httptest.NewRecorder()
	NewServer(8080, "").handleIndex(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	page := rec.Body.String()
	i := strings.Index(page, "function peerKey")
	for _, k := range []string{"'app.kubernetes.io/name'", "'app.kubernetes.io/component'", "'app.kubernetes.io/instance'", "'app'", "'k8s-app'", "'name'", "'component'", "'instance'"} {
		j := strings.Index(page[i:], k)
		if j < 0 {
			t.Fatalf("the page's peerKey must list %s", k)
		}
		i += j
	}
}
