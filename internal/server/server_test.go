package server

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// Review finding: a peer is identified by its whole priority label set — unticking shop/frontend must not remove
// shop/backend, while a bare name=shop exclude still removes every shop component
func TestExclude_WholeLabelSetAndSingleLabel(t *testing.T) {
	front := &flow.ParsedFlow{Direction: "INGRESS", SourceLabels: map[string]string{"app.kubernetes.io/name": "shop", "app.kubernetes.io/component": "frontend"}}
	back := &flow.ParsedFlow{Direction: "INGRESS", SourceLabels: map[string]string{"app.kubernetes.io/name": "shop", "app.kubernetes.io/component": "backend"}}
	if n := excludeFlows([]*flow.ParsedFlow{front, back}, []string{"app.kubernetes.io/name=shop,app.kubernetes.io/component=frontend"}); len(n) != 1 || n[0] != back {
		t.Fatalf("the whole set must exclude only the frontend, got %d", len(n))
	}
	if n := excludeFlows([]*flow.ParsedFlow{front, back}, []string{"app.kubernetes.io/name=shop"}); len(n) != 0 {
		t.Fatalf("a bare name excludes every component, got %d", len(n))
	}
	inst := &flow.ParsedFlow{Direction: "INGRESS", SourceLabels: map[string]string{"app.kubernetes.io/instance": "blue"}}
	if n := excludeFlows([]*flow.ParsedFlow{inst}, []string{"app=payments"}); len(n) != 1 {
		t.Fatalf("exclude=app= must not drop a peer the parser named by instance")
	}
	// the page's key lists exactly the parser's priority labels, then the fallbacks, in order
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

// E6: CORS — any origin by default; a listed origin is echoed with Vary; an unlisted one gets no allow header
func TestCORS_AllowedOrigins(t *testing.T) {
	flow := fixture(t, "ingress-pos-to-shop.json")
	open := NewServer(8080, "")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/generate", strings.NewReader(flow))
	req.Header.Set("Origin", "https://anything.example")
	open.corsMiddleware(open.handleGenerate)(rec, req)
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("default must be *: %v", rec.Header())
	}
	strict := NewServerWithOptions(8080, "", Options{AllowedOrigins: []string{"https://grafana.poc.local"}})
	for origin, want := range map[string]string{"https://grafana.poc.local": "https://grafana.poc.local", "https://evil.example": ""} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodOptions, "/generate", nil)
		req.Header.Set("Origin", origin)
		strict.corsMiddleware(strict.handleGenerate)(rec, req)
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != want {
			t.Fatalf("origin %s: got %q want %q", origin, got, want)
		}
		if want != "" && rec.Header().Get("Vary") != "Origin" {
			t.Fatalf("a listed origin must set Vary: Origin")
		}
	}
}

// E6: the bearer token guards /generate and /download, not /health; preflight passes; wrong token is 401
func TestAuthToken(t *testing.T) {
	s := NewServerWithOptions(8080, "", Options{AuthToken: "s3cret"})
	flow := fixture(t, "ingress-pos-to-shop.json")
	call := func(method, path, token string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(flow))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		s.corsMiddleware(s.requireToken(s.handleGenerate))(rec, req)
		return rec
	}
	if rec := call(http.MethodPost, "/generate", ""); rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("no token: %d %v", rec.Code, rec.Header())
	}
	if rec := call(http.MethodPost, "/generate", "wrong"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", rec.Code)
	}
	if rec := call(http.MethodPost, "/generate", "s3cret"); rec.Code != http.StatusOK {
		t.Fatalf("right token: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodOptions, "/generate", ""); rec.Code != http.StatusOK {
		t.Fatalf("preflight must not be challenged: %d", rec.Code)
	}
	rec := httptest.NewRecorder()
	s.handleHealth(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/health is open: %d", rec.Code)
	}
}

// Review finding: the scheme is case-insensitive, and a wrong token of ANY length is refused the same way
func TestAuthToken_SchemeCaseAndLengths(t *testing.T) {
	s := NewServerWithOptions(8080, "", Options{AuthToken: "s3cret"})
	flow := fixture(t, "ingress-pos-to-shop.json")
	for header, want := range map[string]int{"bearer s3cret": 200, "BEARER s3cret": 200, "Bearer s3cret": 200, "Bearer s3cre": 401, "Bearer s3cret-and-more": 401, "Basic s3cret": 401, "": 401} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/generate", strings.NewReader(flow))
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		s.corsMiddleware(s.requireToken(s.handleGenerate))(rec, req)
		if rec.Code != want {
			t.Fatalf("%q: got %d want %d", header, rec.Code, want)
		}
	}
}

// 0.7.0: ?dnsProfile=openshift writes the OpenShift resolver rule; an unknown profile is a 400
func TestGenerate_DNSProfile(t *testing.T) {
	s := NewServer(8080, "")
	rec := post(t, s, "/generate?dnsVisibility=true&dnsProfile=openshift", fixture(t, "egress-pos-to-world.json"), nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "io.kubernetes.pod.namespace: openshift-dns") || !strings.Contains(rec.Body.String(), "port: \"5353\"") {
		t.Fatalf("openshift profile: %d %s", rec.Code, rec.Body.String())
	}
	if rec := post(t, s, "/generate?dnsProfile=nope", fixture(t, "egress-pos-to-world.json"), nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown profile must be a 400, got %d", rec.Code)
	}
}

// the API page: the build's version beside the logo, one <details> card per endpoint with its own Try-it-out panel
// (the operator, 2026-09-15: the cards were not clickable, the version was not shown, the try-out sat apart from the
// endpoints), and the placeholder never reaches the browser
func TestIndexPage_VersionAndTryItOut(t *testing.T) {
	rec := httptest.NewRecorder()
	NewServerWithOptions(8080, "", Options{Version: "0.7.0"}).handleIndex(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	page := rec.Body.String()
	if strings.Contains(page, "__CF2CNP_VERSION__") {
		t.Fatalf("the version placeholder reached the page")
	}
	for _, want := range []string{
		`<span class="version" title="cf2cnp's version, set when this binary was built">v0.7.0</span>`,
		"<title>CF2CNP v0.7.0 - Cilium Flow to CiliumNetworkPolicy</title>",
		`<details class="endpoint" id="ep-generate"`, `<details class="endpoint" id="ep-download"`, `<details class="endpoint" id="ep-health"`,
		`id="flowInput"`, `id="downloadId"`, `onclick="sendDownload()"`, `onclick="sendHealth()"`, `id="healthResult"`,
		"function onOpenGenerate", "function sendDownload", "function sendHealth",
		`#result, #downloadResult, #healthResult {`,
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("the page must contain %q", want)
		}
	}
	if n := strings.Count(page, `<details class="endpoint"`); n != 3 {
		t.Fatalf("three endpoint cards, got %d", n)
	}
	if n := strings.Count(page, "<h3>Try it out</h3>"); n != 3 {
		t.Fatalf("a Try it out panel under each endpoint, got %d", n)
	}
	if strings.Contains(page, "<h2>Try it out</h2>") {
		t.Fatalf("the separate Try it out section must be gone")
	}
}

// the Try-it-out checkboxes must sit on the same line as their labels: the full-width input rule
// used to catch them too (measured: each checkbox rendered as a block above its text)
func TestIndexPage_CheckboxLabelsInline(t *testing.T) {
	rec := httptest.NewRecorder()
	NewServer(8080, "").handleIndex(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	page := rec.Body.String()
	for _, want := range []string{
		`<label class="check"><input id="l7" type="checkbox">`,
		`<label class="check"><input id="dnsVisibility" type="checkbox">`,
		`.controls input[type=text], .controls input[type=password] {`,
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("the page must contain %q", want)
		}
	}
	if strings.Contains(page, `.controls input {`) {
		t.Fatalf("the old .controls input selector must be gone")
	}
}

// the curl example must use the same base URL as download_url (externalURL, else the request)
func TestIndexPage_CurlExampleUsesBaseURL(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "cf2cnp.example.test"
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	NewServer(8080, "").handleIndex(rec, req)
	page := rec.Body.String()
	if !strings.Contains(page, `curl -X POST https://cf2cnp.example.test/generate`) {
		t.Fatalf("the curl example must use the request's base URL")
	}
	if strings.Contains(page, "localhost:8080") {
		t.Fatalf("the hard-coded localhost must be gone")
	}
	if strings.Contains(page, "__CF2CNP_BASE__") {
		t.Fatalf("the base URL placeholder reached the page")
	}

	rec = httptest.NewRecorder()
	NewServer(8080, "https://fixed.example.test/prefix").handleIndex(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	page = rec.Body.String()
	if !strings.Contains(page, `https://fixed.example.test/prefix/generate`) {
		t.Fatalf("externalURL must win: %s", page)
	}
}

// displayVersion: what the three build paths hand main.version, and a local build
func TestDisplayVersion(t *testing.T) {
	for in, want := range map[string]string{
		"":       "dev",    // go build with no -X
		"dev":    "dev",    // main.go's default
		"0.7.0":  "v0.7.0", // binary-release.yml: ${GITHUB_REF_NAME#v}
		"v0.7.0": "v0.7.0", // docker-publish.yml on a tag: github.ref_name
		"0123456789abcdef0123456789abcdef01234567": "0123456789ab", // docker-publish.yml off a tag: github.sha
		" 0.7.0 ": "v0.7.0",
	} {
		if got := displayVersion(in); got != want {
			t.Errorf("displayVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

// Review C3: version and the derived base URL are written into the HTML page and must be escaped
func TestIndexPage_EscapesDynamicValues(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "safe.example"
	req.Header.Set("X-Forwarded-Host", "<svg>")
	rec := httptest.NewRecorder()
	NewServerWithOptions(8080, "", Options{Version: "<img>"}).handleIndex(rec, req)
	page := rec.Body.String()
	if strings.Contains(page, "<img>") {
		t.Fatalf("unescaped version reached the page")
	}
	if strings.Contains(page, "http://<svg>") {
		t.Fatalf("unescaped host reached the page")
	}
	if !strings.Contains(page, "&lt;img&gt;") {
		t.Fatalf("the page must contain %q", "&lt;img&gt;")
	}
	if !strings.Contains(page, "http://&lt;svg&gt;") {
		t.Fatalf("the page must contain %q", "http://&lt;svg&gt;")
	}
}

// Review C4: a caller-supplied flow uuid is the cache key and must not become a path such as /download/..
func TestDownloadIDCannotEscapeItsPath(t *testing.T) {
	s := NewServer(8080, "")
	flowJSON := fixture(t, "ingress-pos-to-shop.json")
	var wrap struct {
		Flow struct {
			UUID string `json:"uuid"`
		} `json:"flow"`
	}
	if err := json.Unmarshal([]byte(flowJSON), &wrap); err != nil || wrap.Flow.UUID == "" {
		t.Fatalf("fixture uuid: %v %q", err, wrap.Flow.UUID)
	}
	body := strings.Replace(flowJSON, wrap.Flow.UUID, "..", 1)
	m := jsonBody(t, post(t, s, "/generate", body, map[string]string{"Accept": "application/json"}))
	url, _ := m["download_url"].(string)
	if strings.HasSuffix(url, "/download/..") {
		t.Fatalf("download_url must not use the caller-supplied path: %q", url)
	}
	id := url[strings.LastIndex(url, "/")+1:]
	req := httptest.NewRequest(http.MethodGet, "/download/"+id, nil)
	rec := httptest.NewRecorder()
	s.handleDownload(rec, req)
	if rec.Code != 200 {
		t.Fatalf("download: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	s.handleIndex(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(rec.Body.String(), `/^[A-Za-z0-9_-]+$/`) {
		t.Fatalf("the page must contain the id regex")
	}
}

// Review C5: opening /generate must not load the example over typed whitespace
func TestIndexPage_OpenGeneratePreservesTypedWhitespace(t *testing.T) {
	rec := httptest.NewRecorder()
	NewServer(8080, "").handleIndex(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	page := rec.Body.String()
	if !strings.Contains(page, "input.value === ''") {
		t.Fatalf("the page must contain %q", "input.value === ''")
	}
	if strings.Contains(page, "document.getElementById('flowInput').value.trim()") {
		t.Fatalf("the trim check must be gone")
	}
}

func TestIndexPage_StatesActualCacheLifetime(t *testing.T) {
	rec := httptest.NewRecorder()
	NewServer(8080, "").handleIndex(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	page := rec.Body.String()
	if !strings.Contains(page, "keeps a policy for 10 minutes") {
		t.Fatalf("the page must contain %q", "keeps a policy for 10 minutes")
	}
	if strings.Contains(page, "for an hour") {
		t.Fatalf("the hour claim must be gone")
	}
}

func TestDownload_RejectsAnIDOutsideItsAlphabet(t *testing.T) {
	s := NewServer(8080, "")
	s.mu.Lock()
	s.cache["a/b"] = &CachedPolicy{Content: []byte("slash-id"), Filename: "slash.yaml"}
	s.cache["abc123"] = &CachedPolicy{Content: []byte("valid-id"), Filename: "valid.yaml"}
	s.mu.Unlock()

	rec := httptest.NewRecorder()
	s.handleDownload(rec, httptest.NewRequest(http.MethodGet, "/download/a/b", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("id outside the alphabet: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	s.handleDownload(rec, httptest.NewRequest(http.MethodGet, "/download/abc123", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("valid id: %d %s", rec.Code, rec.Body.String())
	}
}

func TestIndexPage_NewGenerateClearsTheDownloadPanel(t *testing.T) {
	rec := httptest.NewRecorder()
	NewServer(8080, "").handleIndex(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	page := rec.Body.String()
	start := strings.Index(page, "async function generatePolicy")
	if start < 0 {
		t.Fatal("generatePolicy not found")
	}
	rest := page[start+len("async function generatePolicy"):]
	end := len(rest)
	if i := strings.Index(rest, "async function"); i >= 0 && i < end {
		end = i
	}
	if i := strings.Index(rest, "function "); i >= 0 && i < end {
		end = i
	}
	fn := rest[:end]
	for _, want := range []string{
		"getElementById('downloadStatus').textContent = ''",
		"getElementById('downloadResult').textContent = ''",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("generatePolicy must contain %q", want)
		}
	}
}

func TestIndexPage_DownloadLinkHiddenWithToken(t *testing.T) {
	rec := httptest.NewRecorder()
	NewServer(8080, "").handleIndex(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	page := rec.Body.String()
	want := `a.style.display = document.getElementById('token').value.trim() ? 'none' : ''`
	if !strings.Contains(page, want) {
		t.Fatalf("the page must contain %q", want)
	}
}

func TestIndexPage_ExampleTextMatchesBehaviour(t *testing.T) {
	rec := httptest.NewRecorder()
	NewServer(8080, "").handleIndex(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	page := rec.Body.String()
	if !strings.Contains(page, "whenever this unfolds with an empty box") {
		t.Fatalf("the page must contain %q", "whenever this unfolds with an empty box")
	}
	if strings.Contains(page, "the first time this unfolds") {
		t.Fatalf("the first-time claim must be gone")
	}
}

func jsonLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &buf
}

func decodeLogs(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line not JSON: %v: %s", err, line)
		}
		out = append(out, m)
	}
	return out
}

func logsWithMsg(lines []map[string]any, msg string) []map[string]any {
	var out []map[string]any
	for _, m := range lines {
		if m["msg"] == msg {
			out = append(out, m)
		}
	}
	return out
}

func logInt(v any) int {
	n, _ := v.(float64)
	return int(n)
}

func TestRequestLog_OneLinePerRequest(t *testing.T) {
	logger, buf := jsonLogger()
	s := NewServerWithOptions(8080, "", Options{Logger: logger})

	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != 200 {
		t.Fatalf("/health: %d", rec.Code)
	}
	if rec.Header().Get("X-Request-Id") == "" {
		t.Fatal("response must carry X-Request-Id")
	}
	health := logsWithMsg(decodeLogs(t, buf), "request")
	if len(health) != 1 {
		t.Fatalf("GET /health: want one request line, got %d in %s", len(health), buf.String())
	}
	if health[0]["level"] != "DEBUG" || logInt(health[0]["status"]) != 200 || health[0]["request_id"] == nil || health[0]["request_id"] == "" {
		t.Fatalf("GET /health line: %v", health[0])
	}

	buf.Reset()
	rec = httptest.NewRecorder()
	s.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/generate", strings.NewReader("")))
	if rec.Code != 400 {
		t.Fatalf("empty POST /generate: %d %s", rec.Code, rec.Body.String())
	}
	id := rec.Header().Get("X-Request-Id")
	if id == "" {
		t.Fatal("response must carry X-Request-Id")
	}
	lines := decodeLogs(t, buf)
	refused := logsWithMsg(lines, "refused")
	reqLines := logsWithMsg(lines, "request")
	if len(refused) != 1 || refused[0]["level"] != "WARN" || refused[0]["reason"] != "body_empty" {
		t.Fatalf("refused: %v", refused)
	}
	if len(reqLines) != 1 || logInt(reqLines[0]["status"]) != 400 {
		t.Fatalf("request: %v", reqLines)
	}
	if refused[0]["request_id"] != id || reqLines[0]["request_id"] != id {
		t.Fatalf("request_id mismatch: refused=%v request=%v header=%s", refused[0]["request_id"], reqLines[0]["request_id"], id)
	}
}

func TestRequestLog_KeepsProxyRequestID(t *testing.T) {
	logger, buf := jsonLogger()
	s := NewServerWithOptions(8080, "", Options{Logger: logger})

	req := httptest.NewRequest(http.MethodPost, "/generate", strings.NewReader(""))
	req.Header.Set("X-Request-Id", "abc-123")
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)
	if rec.Header().Get("X-Request-Id") != "abc-123" {
		t.Fatalf("echo: %q", rec.Header().Get("X-Request-Id"))
	}
	for _, m := range decodeLogs(t, buf) {
		if m["request_id"] != "abc-123" {
			t.Fatalf("line must carry proxy id: %v", m)
		}
	}

	for _, bad := range []string{"abc 123", strings.Repeat("a", 200)} {
		buf.Reset()
		req := httptest.NewRequest(http.MethodPost, "/generate", strings.NewReader(""))
		req.Header.Set("X-Request-Id", bad)
		rec := httptest.NewRecorder()
		s.handler().ServeHTTP(rec, req)
		got := rec.Header().Get("X-Request-Id")
		if got == "" || got == bad || !validRequestID(got) {
			t.Fatalf("bad %q must be replaced, got %q", bad, got)
		}
		for _, m := range decodeLogs(t, buf) {
			if m["request_id"] != got {
				t.Fatalf("minted id %q missing from %v", got, m)
			}
		}
	}
}

func TestRefused_NeverLogsTheToken(t *testing.T) {
	logger, buf := jsonLogger()
	s := NewServerWithOptions(8080, "", Options{Logger: logger, AuthToken: "s3cret"})
	req := httptest.NewRequest(http.MethodPost, "/generate", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer wrong")
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	out := buf.String()
	if !strings.Contains(out, "unauthorized") {
		t.Fatalf("log must name unauthorized: %s", out)
	}
	refused := logsWithMsg(decodeLogs(t, buf), "refused")
	if len(refused) != 1 || refused[0]["has_header"] != true || refused[0]["reason"] != "unauthorized" {
		t.Fatalf("refused: %v", refused)
	}
	if strings.Contains(out, "s3cret") || strings.Contains(out, "wrong") {
		t.Fatalf("log leaked a secret: %s", out)
	}
}

func TestDownload_ThreeAnswers(t *testing.T) {
	logger, buf := jsonLogger()
	s := NewServerWithOptions(8080, "", Options{Logger: logger})

	rec := httptest.NewRecorder()
	s.handleDownload(rec, httptest.NewRequest(http.MethodGet, "/download/never-generated", nil))
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "No policy has been generated") {
		t.Fatalf("unknown: %d %s", rec.Code, rec.Body.String())
	}
	unknown := logsWithMsg(decodeLogs(t, buf), "refused")
	if len(unknown) != 1 || unknown[0]["reason"] != "download_unknown" {
		t.Fatalf("unknown reason: %v", unknown)
	}

	buf.Reset()
	created := time.Now().Add(-11 * time.Minute)
	s.mu.Lock()
	s.cache["expired1"] = &CachedPolicy{Content: []byte("kind: CiliumNetworkPolicy\n"), Filename: "old.yaml", CreatedAt: created}
	s.mu.Unlock()
	s.sweep(time.Now())
	rec = httptest.NewRecorder()
	s.handleDownload(rec, httptest.NewRequest(http.MethodGet, "/download/expired1", nil))
	if rec.Code != http.StatusGone || !strings.Contains(rec.Body.String(), "This download expired") {
		t.Fatalf("expired: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), created.UTC().Format(time.RFC3339)) {
		t.Fatalf("410 must name generated_at: %s", rec.Body.String())
	}
	expired := logsWithMsg(decodeLogs(t, buf), "refused")
	if len(expired) != 1 || expired[0]["reason"] != "download_expired" || expired[0]["kept_for"] != "10m" {
		t.Fatalf("expired reason: %v", expired)
	}

	s.mu.Lock()
	s.cache["live1"] = &CachedPolicy{Content: []byte("kind: CiliumNetworkPolicy\n"), Filename: "live.yaml", CreatedAt: time.Now()}
	s.mu.Unlock()
	rec = httptest.NewRecorder()
	s.handleDownload(rec, httptest.NewRequest(http.MethodGet, "/download/live1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("present: %d %s", rec.Code, rec.Body.String())
	}

	buf.Reset()
	rec = httptest.NewRecorder()
	s.handleDownload(rec, httptest.NewRequest(http.MethodGet, "/download/bad!id", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("invalid id: %d %s", rec.Code, rec.Body.String())
	}
	invalid := logsWithMsg(decodeLogs(t, buf), "refused")
	if len(invalid) != 1 || invalid[0]["reason"] != "download_id_invalid" {
		t.Fatalf("invalid reason: %v", invalid)
	}
	if invalid[0]["reason"] == "download_unknown" {
		t.Fatal("bad!id must be download_id_invalid, distinct from download_unknown")
	}
}

func TestParseLogLevel(t *testing.T) {
	for name, want := range map[string]slog.Level{
		"debug": slog.LevelDebug,
		"info":  slog.LevelInfo,
		"warn":  slog.LevelWarn,
		"error": slog.LevelError,
	} {
		got, err := ParseLogLevel(name)
		if err != nil || got != want {
			t.Errorf("ParseLogLevel(%q) = %v, %v; want %v", name, got, err, want)
		}
	}
	if _, err := ParseLogLevel("loud"); err == nil {
		t.Fatal(`ParseLogLevel("loud") must error`)
	}
}

func TestListeningAttrs_NoSecret(t *testing.T) {
	s := NewServerWithOptions(8080, "", Options{AuthToken: "s3cret", LogFormat: "json", LogLevel: "debug"})
	b, err := json.Marshal(s.listeningAttrs(":8080"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "s3cret") {
		t.Fatalf("listening attrs leaked the token: %s", b)
	}
	attrs := s.listeningAttrs(":8080")
	m := map[string]any{}
	for i := 0; i+1 < len(attrs); i += 2 {
		k, _ := attrs[i].(string)
		m[k] = attrs[i+1]
	}
	if m["auth_enabled"] != true || m["log_format"] != "json" || m["log_level"] != "debug" {
		t.Fatalf("listening attrs: %v", m)
	}
}

func TestRequestLog_HeaderSetBeforeHandler(t *testing.T) {
	s := NewServer(8080, "")
	var got string
	h := s.logRequests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = w.Header().Get("X-Request-Id")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if got == "" {
		t.Fatal("X-Request-Id must be set before the handler runs")
	}
}

func TestRequestLog_PanicIsLoggedAnd500(t *testing.T) {
	logger, buf := jsonLogger()
	s := NewServerWithOptions(8080, "", Options{Logger: logger})
	h := s.logRequests(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/boom", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	lines := decodeLogs(t, buf)
	panics := logsWithMsg(lines, "panic")
	reqs := logsWithMsg(lines, "request")
	if len(panics) != 1 || panics[0]["level"] != "ERROR" || !strings.Contains(buf.String(), "boom") {
		t.Fatalf("panic line: %v log=%s", panics, buf.String())
	}
	if len(reqs) != 1 || logInt(reqs[0]["status"]) != 500 {
		t.Fatalf("request: %v", reqs)
	}
	if panics[0]["request_id"] == nil || panics[0]["request_id"] == "" || panics[0]["request_id"] != reqs[0]["request_id"] {
		t.Fatalf("shared request_id: panic=%v request=%v", panics[0]["request_id"], reqs[0]["request_id"])
	}
}

func TestRequestLog_QueryLogsNamesOnly(t *testing.T) {
	logger, buf := jsonLogger()
	s := NewServerWithOptions(8080, "", Options{Logger: logger})
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health?name=s3cret-name&l7=true", nil))
	out := buf.String()
	if strings.Contains(out, "s3cret-name") {
		t.Fatalf("query value leaked: %s", out)
	}
	reqs := logsWithMsg(decodeLogs(t, buf), "request")
	if len(reqs) != 1 {
		t.Fatalf("request lines: %v", reqs)
	}
	got, err := json.Marshal(reqs[0]["params"])
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `["l7","name"]` {
		t.Fatalf("params = %s, want [\"l7\",\"name\"]", got)
	}
}

func TestRefused_ErrorAttrIsCut(t *testing.T) {
	logger, buf := jsonLogger()
	s := NewServerWithOptions(8080, "", Options{Logger: logger})
	body := `{"flow":{"l4":{"TCP":{"destination_port": ` + strings.Repeat("7", 5000) + `}}}}`
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/generate", strings.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	refused := logsWithMsg(decodeLogs(t, buf), "refused")
	if len(refused) != 1 {
		t.Fatalf("refused: %v log=%s", refused, buf.String())
	}
	errAttr, ok := refused[0]["error"].(string)
	if !ok {
		t.Fatalf("error attr missing: %v", refused[0])
	}
	if n := len([]rune(errAttr)); n > 200 {
		t.Fatalf("error attr is %d runes, want ≤ 200", n)
	}
}
