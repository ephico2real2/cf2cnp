package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	stdhtml "html"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"errors"

	"github.com/hubble-policy-gen/internal/aggregator"
	"github.com/hubble-policy-gen/internal/flow"
	"github.com/hubble-policy-gen/internal/policy"
)

// maxBodyBytes caps a /generate body (8 MiB: several thousand flows)
const maxBodyBytes = 8 << 20

// cacheTTL is how long a generated policy stays downloadable; tombstoneTTL is how long after CreatedAt we
// still remember that it existed, so /download/{id} can answer 410 instead of a misleading 404.
const (
	cacheTTL     = 10 * time.Minute
	tombstoneTTL = 24 * time.Hour
)

// CachedPolicy stores a generated policy for download
type CachedPolicy struct {
	Content   []byte
	Filename  string
	CreatedAt time.Time
}

// Server represents the HTTP server for policy generation
type Server struct {
	port           int
	externalURL    string
	allowedOrigins []string // E6: CORS allow-list; empty or ["*"] = any origin (the historical default)
	authToken      string   // E6: when set, /generate and /download need Authorization: Bearer <token>
	dnsProfile     string
	dnsResolver    string
	version        string // what the page shows beside the logo: main.version, set at build time (dev when unset)
	log            *slog.Logger
	logFormat      string // text | json: the listening line's log_format (not inferred from the handler)
	logLevel       string // debug | info | warn | error: the listening line's log_level
	cache          map[string]*CachedPolicy
	expired        map[string]time.Time // id → CreatedAt of an entry cleanupCache removed; 410 vs 404 on /download
	mu             sync.RWMutex
}

// Options are the optional settings of a server: CORS origins and a bearer token (E6); the DNS resolver defaults
// a request gets when it omits ?dnsProfile= / ?dnsResolver= (0.7.0 — an OpenShift deployment sets them once).
type Options struct {
	AllowedOrigins []string
	AuthToken      string
	DNSProfile     string
	DNSResolver    string
	Version        string       // the build's version (main.version): the page's badge; "dev" when empty
	Logger         *slog.Logger // nil → slog.Default(); request lines and refusals go here, never the token
	LogFormat      string       // text | json; only so the listening line can name it
	LogLevel       string       // debug | info | warn | error; only so the listening line can name it
}

// NewServer creates a new HTTP server. externalURL, when set, is the base URL clients reach the
// server at (scheme://host[:port][/prefix]); it wins over anything the request says when building
// download_url. Leave it empty to derive the base from the request (see baseURL).
func NewServer(port int, externalURL string) *Server {
	return NewServerWithOptions(port, externalURL, Options{})
}

// NewServerWithOptions is NewServer with the E6 options
func NewServerWithOptions(port int, externalURL string, opts Options) *Server {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{
		port:           port,
		externalURL:    strings.TrimRight(externalURL, "/"),
		allowedOrigins: opts.AllowedOrigins,
		authToken:      opts.AuthToken,
		dnsProfile:     opts.DNSProfile,
		dnsResolver:    opts.DNSResolver,
		version:        displayVersion(opts.Version),
		log:            logger,
		logFormat:      opts.LogFormat,
		logLevel:       opts.LogLevel,
		cache:          make(map[string]*CachedPolicy),
		expired:        make(map[string]time.Time),
	}
	go s.cleanupCache()
	return s
}

// displayVersion is the version the page shows: the release workflows build with "0.7.0" (binary-release strips the v)
// or "v0.7.0" (docker-publish keeps the tag) or a commit sha (an untagged image), and a local build has none —
// one "v" in front of a number, a sha cut to 12, "dev" for nothing
func displayVersion(v string) string {
	v = strings.TrimSpace(v)
	switch {
	case v == "":
		return "dev"
	case len(v) == 40 && strings.Trim(v, "0123456789abcdef") == "":
		return v[:12]
	case v[0] >= '0' && v[0] <= '9':
		return "v" + v
	}
	return v
}

// cleanupCache removes expired cache entries on a ticker; sweep is factored out so a test can expire an entry
// without waiting five minutes.
func (s *Server) cleanupCache() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		s.sweep(time.Now())
	}
}

func (s *Server) sweep(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, cached := range s.cache {
		if now.Sub(cached.CreatedAt) > cacheTTL {
			s.expired[id] = cached.CreatedAt
			delete(s.cache, id)
		}
	}
	for id, createdAt := range s.expired {
		if now.Sub(createdAt) > tombstoneTTL {
			delete(s.expired, id)
		}
	}
}

// generateID creates a random ID for caching
func generateID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// validDownloadID reports whether id is one safe URL path segment: the alphabet of generated ids and of Hubble
// UUIDs; anything else (a flow's uuid is caller-supplied) is replaced by a random id (review C4)
func validDownloadID(id string) bool {
	if id == "" {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// ctxKey is the type of the request-scoped values we stash (a logger with request_id). A private type so
// another package's context value cannot collide.
type ctxKey int

const logCtxKey ctxKey = 1

// ParseLogLevel maps a flag/env value to a slog level; an unknown name is an error so serve can refuse at
// start the same way a bad --dns-profile does.
func ParseLogLevel(name string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown log level %q (debug, info, warn, error)", name)
	}
}

// handler is the four routes behind logRequests; Start serves it, tests call it without binding a port.
func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/generate", s.corsMiddleware(s.requireToken(s.handleGenerate)))
	mux.HandleFunc("/download/", s.corsMiddleware(s.requireToken(s.handleDownload)))
	mux.HandleFunc("/health", s.corsMiddleware(s.handleHealth))
	mux.HandleFunc("/", s.handleIndex)
	return s.logRequests(mux)
}

// Start starts the HTTP server
func (s *Server) Start() error {
	addr := fmt.Sprintf(":%d", s.port)
	srv := &http.Server{
		Addr: addr, Handler: s.handler(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second, WriteTimeout: 60 * time.Second,
	}
	s.log.Info("listening", s.listeningAttrs(addr)...)
	return srv.ListenAndServe()
}

// listeningAttrs is the listening line: what is on, never the token (a secret in the process, not an event).
func (s *Server) listeningAttrs(addr string) []any {
	format, level := s.logFormat, s.logLevel
	if format == "" {
		format = "text"
	}
	if level == "" {
		level = "info"
	}
	var origins any = s.allowedOrigins
	if len(s.allowedOrigins) == 0 || (len(s.allowedOrigins) == 1 && s.allowedOrigins[0] == "*") {
		origins = "*"
	}
	return []any{
		"addr", addr,
		"version", s.version,
		"log_format", format,
		"log_level", level,
		"auth_enabled", s.authToken != "",
		"allowed_origins", origins,
		"dns_profile", s.dnsProfile,
		"dns_resolver", s.dnsResolver,
	}
}

// reqLog is the request-scoped logger (it carries request_id); handlers fall back to s.log when the
// middleware did not run — the existing tests call handleGenerate directly.
func (s *Server) reqLog(r *http.Request) *slog.Logger {
	if r != nil {
		if l, ok := r.Context().Value(logCtxKey).(*slog.Logger); ok && l != nil {
			return l
		}
	}
	return s.log
}

// refuse writes a public error to the client and logs the real reason. The public text is what tests and
// operators read; reason is a short snake_case tag for grep. Never pass a token, a header value, or the body.
func (s *Server) refuse(w http.ResponseWriter, r *http.Request, status int, public, reason string, attrs ...any) {
	http.Error(w, public, status)
	level := slog.LevelWarn
	if status >= 500 {
		level = slog.LevelError
	}
	args := make([]any, 0, 4+len(attrs))
	args = append(args, "status", status, "reason", reason)
	args = append(args, attrs...)
	s.reqLog(r).Log(r.Context(), level, "refused", args...)
}

// validRequestID reports whether id is a proxy-minted request id: 1–128 of [A-Za-z0-9._-]. Envoy and most
// proxies set one; anything else (a space, a 200-char paste) is replaced so the header cannot become a log bomb.
func validRequestID(id string) bool {
	n := len(id)
	if n < 1 || n > 128 {
		return false
	}
	for i := 0; i < n; i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// statusWriter captures status and bytes so the request line can name them after the handler returns.
// Default status is 200 when WriteHeader is never called (net/http's implicit 200).
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// logRequests is one line per request around every route: a request id (echoed, or minted), status, bytes,
// duration. /health is DEBUG so kubelet probes stay quiet at info; 4xx is WARN, 5xx is ERROR. Path is
// r.URL.Path only — a query can carry ?name= and is a separate attr, never the Authorization header or body.
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if !validRequestID(id) {
			id = generateID()
		}
		w.Header().Set("X-Request-Id", id)
		logger := s.log.With("request_id", id)
		r = r.WithContext(context.WithValue(r.Context(), logCtxKey, logger))
		sw := &statusWriter{ResponseWriter: w}
		start := time.Now()
		next.ServeHTTP(sw, r)
		status := sw.status
		if status == 0 {
			status = http.StatusOK
		}
		ms := math.Round(float64(time.Since(start).Nanoseconds())/1e6*10) / 10
		attrs := []any{
			"method", r.Method,
			"path", r.URL.Path,
			"status", status,
			"bytes", sw.bytes,
			"duration_ms", ms,
			"client", requestClient(r),
			"user_agent", cutRunes(r.UserAgent(), 120),
		}
		if q := r.URL.RawQuery; q != "" {
			attrs = append(attrs, "query", q)
		}
		if o := r.Header.Get("Origin"); o != "" {
			attrs = append(attrs, "origin", o)
		}
		level := slog.LevelInfo
		switch {
		case r.URL.Path == "/health":
			level = slog.LevelDebug
		case status >= 500:
			level = slog.LevelError
		case status >= 400:
			level = slog.LevelWarn
		}
		logger.Log(r.Context(), level, "request", attrs...)
	})
}

// requestClient is who called: the first X-Forwarded-For hop when a proxy set one, else the remote
// address without its port (the port is ephemeral and not useful in a grep).
func requestClient(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return firstValue(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func cutRunes(s string, n int) string {
	if n <= 0 || s == "" {
		return s
	}
	i := 0
	for j := range s {
		if i == n {
			return s[:j]
		}
		i++
	}
	return s
}

// baseURL is the base clients can reach this server at, for the download_url in JSON answers.
// Precedence: the configured external URL; then RFC 7239 `Forwarded` (proto=, host= of the first,
// client-most element); then the de-facto X-Forwarded-Proto / X-Forwarded-Host (first value); then the
// request itself (TLS on the listener, the Host header). Only http/https count as a proto and only a
// bare host[:port] counts as a host — a header carrying a path, a slash, whitespace or CRLF is ignored,
// so a client cannot be handed a URL that points elsewhere. Without the header check a server behind an
// https-only route answered http:// URLs to a port that was closed.
func (s *Server) baseURL(r *http.Request) string {
	if s.externalURL != "" {
		return s.externalURL
	}
	scheme, host := "", r.Host
	if r.TLS != nil {
		scheme = "https"
	}
	// lowest precedence of the headers first, so later assignments win
	if v := validProto(firstValue(r.Header.Get("X-Forwarded-Proto"))); v != "" {
		scheme = v
	}
	if v := validHost(firstValue(r.Header.Get("X-Forwarded-Host"))); v != "" {
		host = v
	}
	if fwd := r.Header.Get("Forwarded"); fwd != "" {
		for _, pair := range strings.Split(strings.Split(fwd, ",")[0], ";") {
			kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
			if len(kv) != 2 {
				continue
			}
			v := strings.Trim(strings.TrimSpace(kv[1]), "\"")
			switch strings.ToLower(strings.TrimSpace(kv[0])) {
			case "proto":
				if p := validProto(v); p != "" {
					scheme = p
				}
			case "host":
				if h := validHost(v); h != "" {
					host = h
				}
			}
		}
	}
	if scheme == "" {
		scheme = "http"
	}
	if host == "" {
		host = r.Host
	}
	return scheme + "://" + host
}

// firstValue is the first element of a comma-separated header value, trimmed
func firstValue(v string) string {
	return strings.TrimSpace(strings.Split(v, ",")[0])
}

// validProto returns http or https, else ""
func validProto(v string) string {
	switch strings.ToLower(v) {
	case "http", "https":
		return strings.ToLower(v)
	}
	return ""
}

// validHost returns v when it is a bare host[:port] (no path, userinfo, whitespace or control characters), else ""
func validHost(v string) string {
	v = strings.Trim(strings.TrimSpace(v), "\"")
	if v == "" || strings.ContainsAny(v, "/\\?#@ \t\r\n") {
		return ""
	}
	return v
}

// excludeFlows drops flows whose peer carries any of the excluded label=value pairs (E4). The peer is the
// side the rule would name: the source for an INGRESS flow, the destination for EGRESS. This is the
// operator's intent ("stranger may call nothing") applied at generation time instead of at collection time.
func excludeFlows(flows []*flow.ParsedFlow, excludes []string) []*flow.ParsedFlow {
	if len(excludes) == 0 {
		return flows
	}
	kept := make([]*flow.ParsedFlow, 0, len(flows))
	for _, f := range flows {
		peer := f.SourceLabels
		if f.Direction == "EGRESS" {
			peer = f.DestLabels
		}
		if !peerMatches(peer, excludes) {
			kept = append(kept, f)
		}
	}
	return kept
}

// peerMatches reports whether the labels carry one of the excludes. An exclude is "key=value", or several
// joined by commas that must ALL match — the page sends a peer's whole identifying set
// (app.kubernetes.io/name=shop,app.kubernetes.io/component=frontend), so unticking one component never
// removes the others (review finding); a single key=value still works and matches every peer carrying it.
func peerMatches(labels map[string]string, excludes []string) bool {
	for _, ex := range excludes {
		all := true
		n := 0
		for _, pair := range strings.Split(ex, ",") {
			kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
			if len(kv) != 2 {
				continue
			}
			n++
			if labels[kv[0]] != kv[1] {
				all = false
				break
			}
		}
		if n > 0 && all {
			return true
		}
	}
	return false
}

// bearerToken returns the credentials of an Authorization header whose scheme is "Bearer" (any case), else ""
func bearerToken(header string) string {
	parts := strings.SplitN(strings.TrimSpace(header), " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

// tokensEqual compares two secrets in constant time regardless of their lengths
func tokensEqual(a, b string) bool {
	ha, hb := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

// wantsJSON reports whether the client asked for the JSON answer (Grafana's action sets
// X-Grafana-Action; any client may send Accept: application/json)
func wantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "application/json") || r.Header.Get("X-Grafana-Action") != ""
}

// respond writes the generated YAML either as a direct attachment or, for JSON clients, caches it under
// id and answers with the download URL, the filename, the counts and the YAML itself.
func (s *Server) respond(w http.ResponseWriter, r *http.Request, id string, yamlBytes []byte, filename, message string, flows, policies int) {
	if !wantsJSON(r) {
		w.Header().Set("Content-Type", "application/x-yaml")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
		w.WriteHeader(http.StatusOK)
		w.Write(yamlBytes)
		s.reqLog(r).Info("generated", "mode", "direct", "filename", filename, "flows", flows, "policies", policies)
		return
	}
	s.mu.Lock()
	if !validDownloadID(id) {
		id = generateID()
	}
	s.cache[id] = &CachedPolicy{Content: yamlBytes, Filename: filename, CreatedAt: time.Now()}
	s.mu.Unlock()
	downloadURL := fmt.Sprintf("%s/download/%s", s.baseURL(r), id)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"filename":     filename,
		"download_url": downloadURL,
		"message":      message,
		"flows":        flows,
		"policies":     policies,
		"yaml":         string(yamlBytes),
	})
	s.reqLog(r).Info("generated", "mode", "cached", "filename", filename, "id", id, "flows", flows, "policies", policies)
}

// corsMiddleware answers preflight and echoes the request's Origin when it is allowed — any origin when
// the list is empty or "*" (the historical default), else only a listed one (E6). Grafana's action is a
// cross-origin fetch from the Grafana origin, so that origin is the one to list.
func (s *Server) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if origin := s.allowedOrigin(r.Header.Get("Origin")); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			if origin != "*" {
				w.Header().Add("Vary", "Origin")
			}
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept, X-Grafana-Action, X-Grafana-Device-Id, X-Grafana-Org-Id")
		w.Header().Set("Access-Control-Expose-Headers", "Content-Disposition")
		w.Header().Set("Access-Control-Max-Age", "86400")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}

// allowedOrigin returns the value for Access-Control-Allow-Origin: "*" when any origin is allowed, the
// request's origin when it is listed, "" when it is not
func (s *Server) allowedOrigin(origin string) string {
	if len(s.allowedOrigins) == 0 || (len(s.allowedOrigins) == 1 && s.allowedOrigins[0] == "*") {
		return "*"
	}
	for _, o := range s.allowedOrigins {
		if strings.EqualFold(strings.TrimRight(o, "/"), strings.TrimRight(origin, "/")) && origin != "" {
			return origin
		}
	}
	return ""
}

// requireToken checks Authorization: Bearer <token> when a token is configured (E6). The scheme is
// case-insensitive as HTTP requires; the compare hashes both sides first, so its timing never depends on
// where the tokens differ or on their lengths (ConstantTimeCompare returns at once on unequal lengths —
// review finding). Preflight (OPTIONS) is never challenged, or the browser cannot even ask.
func (s *Server) requireToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.authToken != "" && r.Method != http.MethodOptions {
			got := bearerToken(r.Header.Get("Authorization"))
			if !tokensEqual(got, s.authToken) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="cf2cnp"`)
				s.refuse(w, r, http.StatusUnauthorized, "Unauthorized", "unauthorized",
					"has_header", r.Header.Get("Authorization") != "")
				return
			}
		}
		next(w, r)
	}
}

// handleIndex serves a simple HTML page with usage instructions
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CF2CNP __CF2CNP_VERSION__ - Cilium Flow to CiliumNetworkPolicy</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            max-width: 900px;
            margin: 0 auto;
            padding: 2rem;
            background: #0f172a;
            color: #e2e8f0;
        }
        .header {
            display: flex;
            align-items: center;
            gap: 1.5rem;
            margin-bottom: 1rem;
        }
        .logo {
            width: 80px;
            height: 80px;
        }
        h1 { 
            background: linear-gradient(135deg, #06b6d4, #8b5cf6, #ec4899);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin: 0;
            font-size: 2rem;
        }
        .subtitle {
            color: #94a3b8;
            margin-top: 0.25rem;
        }
        h2 { 
            color: #06b6d4; 
            margin-top: 2rem;
            border-bottom: 1px solid #1e293b;
            padding-bottom: 0.5rem;
        }
        pre {
            background: #1e293b;
            padding: 1rem;
            border-radius: 8px;
            overflow-x: auto;
            border-left: 4px solid #8b5cf6;
        }
        code { color: #06b6d4; }
        /* each endpoint is a <details>: the method+path row is the click target (Swagger's collapsed rows), the
           description and the Try-it-out panel unfold under it — native, keyboard-reachable, no script to toggle */
        .endpoint {
            background: #1e293b;
            border-radius: 8px;
            margin: 1rem 0;
            border: 1px solid #334155;
        }
        .endpoint { transition: border-color 0.2s, box-shadow 0.2s; }          /* the frontend-design skill: tactile states, 150–300 ms */
        .endpoint:hover, .endpoint:focus-within { border-color: #8b5cf6; box-shadow: 0 0 0 3px rgba(139, 92, 246, 0.15); }
        .endpoint > summary {
            display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap;
            padding: 1rem; cursor: pointer; list-style: none; border-radius: 8px;
        }
        .endpoint > summary:focus-visible { outline: 2px solid #06b6d4; outline-offset: -2px; }   /* the keyboard reaches every card */
        @media (max-width: 640px) { .endpoint > summary .brief { flex-basis: 100%; } .endpoint > summary::after { margin-left: 0; } }
        .endpoint > summary::-webkit-details-marker { display: none; }
        .endpoint > summary::after {
            content: '▸'; margin-left: auto; color: #94a3b8; transition: transform 0.15s;
        }
        .endpoint[open] > summary::after { transform: rotate(90deg); }
        .endpoint > summary .brief { color: #94a3b8; font-weight: normal; font-size: 0.95em; }
        .endpoint > .body { padding: 0 1rem 1rem 1rem; border-top: 1px solid #334155; }
        .endpoint > .body > p:first-child { margin-top: 1rem; }
        .try { margin-top: 1rem; padding-top: 1rem; border-top: 1px dashed #334155; }
        .try h3 { margin: 0 0 0.5rem 0; color: #94a3b8; font-size: 0.9rem; text-transform: uppercase; letter-spacing: 0.06em; }
        .resp { color: #94a3b8; font-size: 0.9em; margin: 8px 0 4px 0; }
        .resp .ok { color: #34d399; } .resp .bad { color: #f87171; }
        .version {
            display: inline-block; vertical-align: middle; margin-left: 0.6rem;
            padding: 0.15rem 0.55rem; border-radius: 999px; font-size: 0.8rem; font-weight: 600;
            color: #e2e8f0; background: #1e293b; border: 1px solid #334155; font-family: monospace;
            -webkit-text-fill-color: #e2e8f0;   /* the h1 paints its text transparent for the gradient; the badge must not inherit that (measured: an empty pill) */
        }
        .method { 
            background: linear-gradient(135deg, #06b6d4, #8b5cf6);
            color: #0f172a; 
            padding: 0.25rem 0.5rem; 
            border-radius: 4px; 
            font-weight: bold;
        }
        .path { color: #fbbf24; font-weight: bold; }
        textarea {
            width: 100%;
            height: 300px;
            background: #1e293b;
            color: #e2e8f0;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 1rem;
            font-family: monospace;
            resize: vertical;
        }
        textarea:focus {
            outline: none;
            border-color: #8b5cf6;
            box-shadow: 0 0 0 3px rgba(139, 92, 246, 0.2);
        }
        button {
            background: linear-gradient(135deg, #06b6d4, #8b5cf6);
            color: #0f172a;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 8px;
            font-size: 1rem;
            cursor: pointer;
            font-weight: bold;
            margin-top: 1rem;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        button:hover { 
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(139, 92, 246, 0.4);
        }
        #result, #downloadResult, #healthResult {
            margin-top: 1rem;
            white-space: pre-wrap;
        }
        .summary { color: #94a3b8; font-size: 0.9em; margin: 8px 0; white-space: pre-wrap; }
        .muted { color: #64748b; font-weight: normal; }
        .controls { margin: 8px 0; }
        .controls label { display: block; margin-bottom: 4px; color: #cbd5e1; font-weight: 600; }
        .controls input[type=text], .controls input[type=password] { width: 100%; box-sizing: border-box; background: #0f172a; color: #e2e8f0; border: 1px solid #334155; border-radius: 6px; padding: 10px; font-family: monospace; }
        /* inline flow, not flex: flex made the bare text "Layer-7 rules" its own item and wrapped it (measured) */
        .controls label.check { display: block; }
        .controls label.check input { width: auto; vertical-align: middle; margin: 0 0.5rem 0 0; }
        .peers label { display: inline-block; margin: 4px 12px 4px 0; color: #cbd5e1; }
        .peers .muted { margin-left: 4px; }
        .buttons { display: flex; flex-wrap: wrap; gap: 8px; margin: 8px 0; }
        .buttons button { margin: 0; }
        button.secondary { background: #1e293b; border: 1px solid #334155; box-shadow: none; }
        button.secondary:hover { background: #334155; }
        button:disabled { opacity: 0.45; cursor: not-allowed; }
    </style>
</head>
<body>
    <div class="header">
        <svg class="logo" viewBox="0 0 128 128" xmlns="http://www.w3.org/2000/svg">
            <defs>
                <linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#06b6d4"/>
                    <stop offset="50%" style="stop-color:#8b5cf6"/>
                    <stop offset="100%" style="stop-color:#ec4899"/>
                </linearGradient>
            </defs>
            <circle cx="64" cy="64" r="60" fill="#0f172a"/>
            <circle cx="64" cy="64" r="58" fill="none" stroke="url(#grad)" stroke-width="2" opacity="0.7"/>
            <path d="M64 16 L108 40 L108 88 L64 112 L20 88 L20 40 Z" fill="none" stroke="url(#grad)" stroke-width="3" stroke-linejoin="round" opacity="0.6"/>
            <circle cx="28" cy="52" r="5" fill="#06b6d4"/>
            <circle cx="24" cy="64" r="5" fill="#8b5cf6"/>
            <circle cx="28" cy="76" r="5" fill="#ec4899"/>
            <path d="M33 52 L48 58" fill="none" stroke="#06b6d4" stroke-width="2" stroke-linecap="round"/>
            <path d="M29 64 L48 64" fill="none" stroke="#8b5cf6" stroke-width="2" stroke-linecap="round"/>
            <path d="M33 76 L48 70" fill="none" stroke="#ec4899" stroke-width="2" stroke-linecap="round"/>
            <rect x="48" y="50" width="32" height="28" rx="4" fill="#1e293b" stroke="url(#grad)" stroke-width="2"/>
            <path d="M54 64 L70 64 M64 58 L70 64 L64 70" fill="none" stroke="#f8fafc" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
            <g transform="translate(86, 48)">
                <rect x="0" y="0" width="20" height="26" rx="2" fill="#1e293b" stroke="#06b6d4" stroke-width="1.5"/>
                <line x1="4" y1="6" x2="16" y2="6" stroke="#06b6d4" stroke-width="1.5" stroke-linecap="round"/>
                <line x1="4" y1="11" x2="14" y2="11" stroke="#06b6d4" stroke-width="1" stroke-linecap="round" opacity="0.6"/>
                <line x1="4" y1="16" x2="12" y2="16" stroke="#06b6d4" stroke-width="1" stroke-linecap="round" opacity="0.6"/>
                <path d="M10 19 L10 22 Q10 25, 13 26 Q16 25, 16 22 L16 19 Z" fill="#06b6d4" opacity="0.8"/>
            </g>
            <g transform="translate(90, 68)">
                <rect x="0" y="0" width="18" height="22" rx="2" fill="#1e293b" stroke="#8b5cf6" stroke-width="1.5"/>
                <line x1="3" y1="5" x2="14" y2="5" stroke="#8b5cf6" stroke-width="1.5" stroke-linecap="round"/>
                <line x1="3" y1="9" x2="12" y2="9" stroke="#8b5cf6" stroke-width="1" stroke-linecap="round" opacity="0.6"/>
                <line x1="3" y1="13" x2="10" y2="13" stroke="#8b5cf6" stroke-width="1" stroke-linecap="round" opacity="0.6"/>
            </g>
        </svg>
        <div>
            <h1>CF2CNP <span class="version" title="cf2cnp's version, set when this binary was built">__CF2CNP_VERSION__</span></h1>
            <p class="subtitle">Cilium Flow to CiliumNetworkPolicy</p>
        </div>
    </div>
    <p>Generate CiliumNetworkPolicies from Hubble flow data.</p>

    <h2>API Endpoints <span class="muted" style="font-size:0.7em">— click an endpoint to unfold it and try it out</span></h2>

    <details class="endpoint" id="ep-generate" ontoggle="onOpenGenerate(this)">
        <summary><span class="method">POST</span> <span class="path">/generate</span> <span class="brief">Hubble flows in, CiliumNetworkPolicies out</span></summary>
        <div class="body">
        <p>Send Hubble flow JSON — one flow, a JSON array, or one flow per line — and receive the policies.
        <code>?name=&lt;name&gt;</code> names the (single) resulting policy.</p>
        <p><strong>Content-Type:</strong> application/json</p>
        <p><strong>Response:</strong> YAML (one document per policy) for curl; with <code>Accept: application/json</code>
        or <code>X-Grafana-Action</code>, JSON <code>{download_url, filename, yaml, flows, policies}</code></p>
        <div class="try">
        <h3>Try it out</h3>
        <p>Paste Hubble flow JSON below — one flow, a JSON array, or one flow per line (the output of
        <code>hubble observe -o json</code>). Flows to the same workload become one policy with one rule per peer.
        The example is loaded whenever this unfolds with an empty box (so after Clear, too); replace it with your own.</p>
            <textarea id="flowInput" placeholder='{"flow": {"traffic_direction": "INGRESS", ...}}' oninput="summarize()"></textarea>
            <div id="summary" class="summary"></div>
            <div id="peers" class="peers"></div>
            <div class="controls">
                <label for="policyName">Policy name <span class="muted">(optional, only when the flows make one policy)</span></label>
                <input id="policyName" type="text" placeholder="e.g. shop-from-pos" spellcheck="false">
                <label class="check"><input id="l7" type="checkbox"> Layer-7 rules <span class="muted">(HTTP method + path, DNS names, from flows that carry them; the port then goes through the proxy)</span></label>
                <label class="check"><input id="dnsVisibility" type="checkbox"> DNS visibility <span class="muted">(world traffic without names: add the DNS resolver rule so the next flows carry names)</span></label>
                <label for="dnsProfile">DNS resolver <span class="muted">(the rule toFQDNs and DNS visibility write: auto = from the observed DNS flows, else the server's default — kube-system/kube-dns:53 unless deployed otherwise; openshift = openshift-dns:5353)</span></label>
                <select id="dnsProfile"><option value="auto">auto</option><option value="kubernetes">kubernetes</option><option value="openshift">openshift</option></select>
                <label for="token">Access token <span class="muted">(only when the server requires one; kept in this tab's sessionStorage, never in the page)</span></label>
                <input id="token" type="password" placeholder="Bearer token" spellcheck="false" oninput="try { sessionStorage.setItem('cf2cnp-token', this.value); } catch (e) {}">
            </div>
            <div class="buttons">
                <button onclick="generatePolicy()">Generate Policy</button>
                <button class="secondary" onclick="copyYAML()" id="copyBtn" disabled>Copy YAML</button>
                <button class="secondary" onclick="downloadYAML()" id="downloadBtn" disabled>Download YAML</button>
                <button class="secondary" onclick="loadExample()">Load example</button>
                <button class="secondary" onclick="clearAll()">Clear</button>
            </div>
            <div id="apply" class="summary"></div>
            <pre id="result"></pre>
        </div>
        </div>
    </details>

    <details class="endpoint" id="ep-download">
        <summary><span class="method">GET</span> <span class="path">/download/{id}</span> <span class="brief">a generated policy, by its id</span></summary>
        <div class="body">
        <p>Download a generated policy by ID. The id is the last path segment of the <code>download_url</code> a
        <code>/generate</code> call returned; the server keeps a policy for 10 minutes, 410 when it has expired,
        404 when nothing was generated under the id.</p>
        <div class="try">
        <h3>Try it out</h3>
        <div class="controls">
            <label for="downloadId">id <span class="muted">(filled in by the last /generate above)</span></label>
            <input id="downloadId" type="text" placeholder="e.g. 8d5c2f1a3b9e" spellcheck="false">
        </div>
        <div class="buttons">
            <button onclick="sendDownload()">Send</button>
            <a id="downloadLink" class="muted" href="#" target="_blank" rel="noopener" style="display:none; align-self:center">open in a new tab</a>
        </div>
        <div id="downloadStatus" class="resp"></div>
        <pre id="downloadResult"></pre>
        </div>
        </div>
    </details>

    <details class="endpoint" id="ep-health">
        <summary><span class="method">GET</span> <span class="path">/health</span> <span class="brief">is the server up</span></summary>
        <div class="body">
        <p>Health check endpoint. Returns "OK" if the server is running.</p>
        <div class="try">
        <h3>Try it out</h3>
        <div class="buttons"><button onclick="sendHealth()">Send</button></div>
        <div id="healthStatus" class="resp"></div>
        <pre id="healthResult"></pre>
        </div>
        </div>
    </details>

    <h2>Example using curl</h2>
    <pre><code># one flow
curl -X POST __CF2CNP_BASE__/generate -H "Content-Type: application/json" -d @flow.json -o policy.yaml

# many flows at once: one policy per workload, one rule per peer
hubble observe --namespace my-namespace --last 200 -o json > flows.json
curl -X POST __CF2CNP_BASE__/generate --data-binary @flows.json -o policies.yaml

# name the resulting policy
curl -X POST "__CF2CNP_BASE__/generate?name=shop-from-pos" -d @flow.json -o policy.yaml</code></pre>

    <script>
        // Parse what the textarea holds the way the server does: an array, or objects separated by whitespace.
        function parseFlows(text) {
            const t = text.trim();
            if (!t) return [];
            if (t[0] === '[') return JSON.parse(t);
            const flows = []; let depth = 0, start = -1, inStr = false, esc = false;
            for (let i = 0; i < t.length; i++) {
                const c = t[i];
                if (inStr) { if (esc) esc = false; else if (c === '\\') esc = true; else if (c === '"') inStr = false; continue; }
                if (c === '"') inStr = true;
                else if (c === '{') { if (depth === 0) start = i; depth++; }
                else if (c === '}') { depth--; if (depth === 0 && start >= 0) { flows.push(JSON.parse(t.slice(start, i + 1))); start = -1; } }
            }
            return flows;
        }
        function who(ep) {
            if (!ep) return '?';
            const labels = ep.labels || [];
            const pick = (k) => { const l = labels.find(x => x.startsWith('k8s:' + k + '=')); return l ? l.split('=')[1] : null; };
            // the same identity the policy name is built from: name, then instance and component when present
            var name = pick('app.kubernetes.io/name') || pick('app') || pick('k8s-app') || ep.pod_name || (labels.find(x => x.startsWith('reserved:')) || '?').replace('reserved:', '');
            var inst = pick('app.kubernetes.io/instance'), comp = pick('app.kubernetes.io/component');
            if (inst && inst !== name) name += '/' + inst;
            if (comp && comp !== name) name += '/' + comp;
            return name;
        }
        // peerKey is the identifying label set the policy would name for a peer, joined by commas — the same labels
        // the server's extractLabels keeps: every app.kubernetes.io/{name,component,instance} present, else the first
        // fallback label (app, k8s-app, name, component, instance). Unticking a peer sends this whole set as one
        // exclude, so one component never removes its siblings (review finding).
        function peerKey(ep) {
            const labels = (ep && ep.labels) || [];
            const val = (k) => { const l = labels.find(x => x.startsWith('k8s:' + k + '=') || x.startsWith(k + '=')); return l ? l.split('=').slice(1).join('=') : null; };
            const parts = [];
            for (const k of ['app.kubernetes.io/name', 'app.kubernetes.io/component', 'app.kubernetes.io/instance']) { const v = val(k); if (v !== null) parts.push(k + '=' + v); }
            if (parts.length) return parts.join(',');
            for (const k of ['app', 'k8s-app', 'name', 'component', 'instance']) { const v = val(k); if (v !== null) return k + '=' + v; }
            return '';
        }
        // renderPeers lists every distinct peer (the source of an INGRESS flow, the destination of an EGRESS one)
        // as a checkbox; an unchecked peer becomes an exclude= parameter — review the intent before generating
        function renderPeers(flows) {
            const counts = {};
            for (const d of flows) {
                const f = d.flow || d; const ep = f.traffic_direction === 'EGRESS' ? f.destination : f.source;
                const key = peerKey(ep); if (!key) continue;
                counts[key] = (counts[key] || 0) + 1;
            }
            const box = document.getElementById('peers'); box.textContent = '';
            const keys = Object.keys(counts).sort();
            if (!keys.length) return;
            const title = document.createElement('div'); title.className = 'summary'; title.textContent = 'Peers the policy would allow — untick to exclude:'; box.appendChild(title);
            for (const k of keys) {
                const label = document.createElement('label'); const cb = document.createElement('input'); cb.type = 'checkbox'; cb.checked = true; cb.dataset.peer = k;
                label.appendChild(cb); label.appendChild(document.createTextNode(' ' + k.split(',').map(p => p.split('=').slice(1).join('=')).join('/')));
                const m = document.createElement('span'); m.className = 'muted'; m.textContent = '(' + counts[k] + ' flow' + (counts[k] === 1 ? '' : 's') + ')'; label.appendChild(m);
                box.appendChild(label);
            }
        }
        function excludedPeers() {
            return Array.from(document.querySelectorAll('#peers input[type=checkbox]')).filter(cb => !cb.checked).map(cb => cb.dataset.peer);
        }
        function summarize() {
            const box = document.getElementById('summary');
            try {
                const flows = parseFlows(document.getElementById('flowInput').value);
                if (!flows.length) { box.textContent = ''; return; }
                const lines = flows.slice(0, 8).map(d => {
                    const f = d.flow || d; const l4 = f.l4 || {}; const port = (l4.TCP || l4.UDP || {}).destination_port;
                    const names = (f.destination_names || []).join(',');
                    return (f.traffic_direction || '?') + ' ' + (f.verdict || '') + ' ' + who(f.source) + ' → ' + (names || who(f.destination)) + ':' + (port || '?') + (f.is_reply ? ' (reply — will be refused)' : '');
                });
                box.textContent = flows.length + ' flow(s) parsed: ' + lines.join(' | ') + (flows.length > 8 ? ' | …' : '');
                renderPeers(flows);
            } catch (e) { box.textContent = 'Not valid JSON yet: ' + e.message; }
        }
        let lastYAML = '', lastFilename = 'ciliumnetworkpolicy.yaml';
        // Swagger's "Try it out" shows the example value: the flow textarea is filled the first time /generate unfolds (never over what was typed)
        function onOpenGenerate(d) { const input = document.getElementById('flowInput'); if (d.open && input.value === '') loadExample(); }
        function authHeaders(h) { const token = document.getElementById('token').value.trim(); if (token) h['Authorization'] = 'Bearer ' + token; return h; }
        // one response line the way Swagger shows it: the status, the time, then the body
        function showResponse(statusId, resultId, response, body, ms) {
            const st = document.getElementById(statusId); st.textContent = ''; const b = document.createElement('span');
            b.className = response.ok ? 'ok' : 'bad'; b.textContent = 'HTTP ' + response.status + (response.statusText ? ' ' + response.statusText : ''); st.appendChild(b);
            st.appendChild(document.createTextNode(' · ' + ms + ' ms' + (response.headers.get('content-type') ? ' · ' + response.headers.get('content-type') : '')));
            document.getElementById(resultId).textContent = body;
        }
        async function sendDownload() {
            const id = document.getElementById('downloadId').value.trim();
            if (!id) { document.getElementById('downloadStatus').textContent = 'an id is needed — run /generate first, or paste one'; return; }
            if (!/^[A-Za-z0-9_-]+$/.test(id)) { document.getElementById('downloadStatus').textContent = 'the id must contain only letters, numbers, hyphens or underscores'; return; }
            const url = '/download/' + encodeURIComponent(id); const t0 = performance.now();
            try { const r = await fetch(url, { headers: authHeaders({}) }); showResponse('downloadStatus', 'downloadResult', r, await r.text(), Math.round(performance.now() - t0)); }
            catch (e) { document.getElementById('downloadStatus').textContent = 'Error: ' + e.message; }
            const a = document.getElementById('downloadLink'); a.href = url;
            // a navigation sends no Authorization header, so a token-guarded server 401s even with the right token in #token
            a.style.display = document.getElementById('token').value.trim() ? 'none' : '';
        }
        async function sendHealth() {
            const t0 = performance.now();
            try { const r = await fetch('/health'); showResponse('healthStatus', 'healthResult', r, await r.text(), Math.round(performance.now() - t0)); }
            catch (e) { document.getElementById('healthStatus').textContent = 'Error: ' + e.message; }
        }
        try { const t = sessionStorage.getItem('cf2cnp-token'); if (t) document.getElementById('token').value = t; } catch (e) {}
        async function generatePolicy() {
            const input = document.getElementById('flowInput').value;
            const result = document.getElementById('result'); const apply = document.getElementById('apply');
            const name = document.getElementById('policyName').value.trim();
            const params = []; if (name) params.push('name=' + encodeURIComponent(name));
            if (document.getElementById('l7').checked) params.push('l7=true');
            if (document.getElementById('dnsVisibility').checked) params.push('dnsVisibility=true');
            const dnsProfile = document.getElementById('dnsProfile').value; if (dnsProfile && dnsProfile !== 'auto') params.push('dnsProfile=' + dnsProfile);
            for (const p of excludedPeers()) params.push('exclude=' + encodeURIComponent(p));
            const url = '/generate' + (params.length ? '?' + params.join('&') : '');
            try {
                const headers = { 'Content-Type': 'application/json', 'Accept': 'application/json' };
                const token = document.getElementById('token').value.trim(); if (token) headers['Authorization'] = 'Bearer ' + token;
                const response = await fetch(url, { method: 'POST', headers: headers, body: input });
                if (response.status === 401) { result.textContent = 'Error: this server requires an access token (401)'; apply.textContent = ''; setButtons(false); return; }
                if (!response.ok) { result.textContent = 'Error: ' + await response.text(); apply.textContent = ''; setButtons(false); return; }
                const data = await response.json();
                lastYAML = data.yaml; lastFilename = data.filename; result.textContent = data.yaml;
                // the id for /download/{id}'s Try it out: the last path segment of the download_url this call returned
                if (data.download_url) { const seg = String(data.download_url).split('/').pop(); document.getElementById('downloadId').value = seg; document.getElementById('downloadLink').style.display = 'none'; document.getElementById('downloadStatus').textContent = ''; document.getElementById('downloadResult').textContent = ''; }
                apply.textContent = data.flows + ' flow(s) → ' + data.policies + (data.policies === 1 ? ' policy' : ' policies') + '. Review it, then: kubectl apply -f ' + data.filename;
                setButtons(true);
            } catch (err) { result.textContent = 'Error: ' + err.message; setButtons(false); }
        }
        function setButtons(on) { document.getElementById('copyBtn').disabled = !on; document.getElementById('downloadBtn').disabled = !on; }
        async function copyYAML() {
            try { await navigator.clipboard.writeText(lastYAML); flash('copyBtn', 'Copied'); }
            catch (e) { flash('copyBtn', 'Copy failed'); }
        }
        function downloadYAML() {
            const blob = new Blob([lastYAML], { type: 'application/x-yaml' }); const url = URL.createObjectURL(blob);
            const a = document.createElement('a'); a.href = url; a.download = lastFilename; a.click(); URL.revokeObjectURL(url);
        }
        function flash(id, text) { const b = document.getElementById(id); const old = b.textContent; b.textContent = text; setTimeout(() => b.textContent = old, 1200); }
        function clearAll() { document.getElementById('flowInput').value = ''; document.getElementById('policyName').value = ''; document.getElementById('result').textContent = ''; document.getElementById('summary').textContent = ''; document.getElementById('peers').textContent = ''; document.getElementById('apply').textContent = ''; setButtons(false); }
        function loadExample() {
            const ex = (src, uuid) => JSON.stringify({ flow: { uuid: uuid, verdict: 'AUDIT', IP: { source: '10.0.1.3', destination: '10.0.2.7', ipVersion: 'IPv4' },
                l4: { TCP: { source_port: 45248, destination_port: 80, flags: { SYN: true } } },
                source: { namespace: 'shop', labels: ['k8s:app.kubernetes.io/name=' + src, 'k8s:io.kubernetes.pod.namespace=shop'], pod_name: src },
                destination: { namespace: 'shop', labels: ['k8s:app.kubernetes.io/name=shop', 'k8s:io.kubernetes.pod.namespace=shop'], pod_name: 'shop-6d7d797759-4ddlt' },
                Type: 'L3_L4', traffic_direction: 'INGRESS', is_reply: false } });
            document.getElementById('flowInput').value = ex('pos', '11111111-1111-4111-8111-111111111111') + '\n' + ex('checkout', '22222222-2222-4222-8222-222222222222') + '\n';
            summarize();
        }
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(strings.NewReplacer(
		"__CF2CNP_VERSION__", stdhtml.EscapeString(s.version),
		"__CF2CNP_BASE__", stdhtml.EscapeString(s.baseURL(r)),
	).Replace(html)))
}

// handleHealth handles health check requests
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// handleDownload serves a cached policy file
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	// Extract ID from path: /download/{id}
	id := strings.TrimPrefix(r.URL.Path, "/download/")
	if id == "" {
		s.refuse(w, r, http.StatusBadRequest, "Missing download ID", "download_id_missing")
		return
	}
	if !validDownloadID(id) {
		s.refuse(w, r, http.StatusNotFound, "404 page not found", "download_id_invalid")
		return
	}

	s.mu.RLock()
	cached, exists := s.cache[id]
	expiredAt, tombstoned := s.expired[id]
	s.mu.RUnlock()

	if !exists && tombstoned {
		generatedAt := expiredAt.UTC().Format(time.RFC3339)
		s.refuse(w, r, http.StatusGone,
			fmt.Sprintf("This download expired: the policy was generated at %s, and a generated policy is kept for 10 minutes. Generate it again.", generatedAt),
			"download_expired", "generated_at", generatedAt, "kept_for", "10m")
		return
	}
	if !exists {
		s.refuse(w, r, http.StatusNotFound,
			"No policy has been generated under this id. Run Generate first (the Grafana action, the page, or POST /generate with Accept: application/json), then download within 10 minutes.",
			"download_unknown")
		return
	}

	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", cached.Filename))
	w.WriteHeader(http.StatusOK)
	w.Write(cached.Content)

	s.reqLog(r).Info("downloaded", "filename", cached.Filename, "id", id)
}

// handleGenerate handles policy generation requests
func (s *Server) handleGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.refuse(w, r, http.StatusMethodNotAllowed, "Method not allowed. Use POST.", "method_not_allowed")
		return
	}

	// Read request body — capped: a public /generate must not let one POST fill memory. maxBodyBytes holds
	// several thousand flows (a flow is ~1.5 KB); http.MaxBytesReader makes an oversize body a 413.
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			s.refuse(w, r, http.StatusRequestEntityTooLarge, fmt.Sprintf("Request body larger than %d bytes", maxBodyBytes),
				"body_too_large", "limit_bytes", maxBodyBytes)
			return
		}
		s.refuse(w, r, http.StatusBadRequest, fmt.Sprintf("Failed to read request body: %v", err),
			"body_unreadable", "error", err.Error())
		return
	}
	defer r.Body.Close()

	if len(body) == 0 {
		s.refuse(w, r, http.StatusBadRequest, "Request body is empty. Please provide Hubble flow JSON.", "body_empty")
		return
	}

	// 🎲 Easter egg: Check for YOLO mode
	bodyStr := strings.TrimSpace(string(body))
	if strings.HasPrefix(bodyStr, "yolo ns") {
		s.handleYoloNs(w, r, bodyStr)
		return
	}

	// Parse the flows: one object, a JSON array, or one object per line (`hubble observe -o json`)
	parsedFlows, err := flow.ParseFlowsFromBytes(body)
	if err != nil {
		s.refuse(w, r, http.StatusBadRequest, fmt.Sprintf("Failed to parse flow JSON: %v", err),
			"flow_json_invalid", "error", err.Error())
		return
	}

	parsedFlows = excludeFlows(parsedFlows, r.URL.Query()["exclude"]) // E4: ?exclude=key=value, repeatable
	aggregatedFlows := aggregator.AggregateFlows(parsedFlows)
	if len(aggregatedFlows) == 0 {
		s.refuse(w, r, http.StatusBadRequest, "No valid flows found in request (every flow excluded, or none parsed)",
			"no_valid_flows")
		return
	}

	generator := policy.NewGenerator("")
	if name := strings.TrimSpace(r.URL.Query().Get("name")); name != "" {
		generator = generator.WithName(name)
	}
	if r.URL.Query().Get("l7") == "true" {
		generator = generator.WithL7() // E2: opt-in layer-7 rules
	}
	// 0.7.0: the DNS resolver — the server's defaults (serve --dns-profile / --dns-resolver, checked at start), then
	// the request's: a profile named by the request replaces the server's resolver too, a resolver named by the
	// request wins over everything (as --dns-resolver does over --dns-profile)
	dnsProfile, dnsResolver := s.dnsProfile, s.dnsResolver
	if p := r.URL.Query().Get("dnsProfile"); p != "" {
		dnsProfile, dnsResolver = p, ""
	}
	if spec := r.URL.Query().Get("dnsResolver"); spec != "" {
		dnsResolver = spec
	}
	if dnsProfile != "" {
		if _, err := generator.WithDNSProfile(dnsProfile); err != nil { // auto | kubernetes | openshift
			s.refuse(w, r, http.StatusBadRequest, err.Error(), "dns_profile_invalid", "error", err.Error())
			return
		}
	}
	if dnsResolver != "" {
		if _, err := generator.WithDNSResolver(dnsResolver); err != nil { // <namespace>[/<label>=<value>]:<port>[/<proto>]
			s.refuse(w, r, http.StatusBadRequest, err.Error(), "dns_resolver_invalid", "error", err.Error())
			return
		}
	}
	if r.URL.Query().Get("dnsVisibility") == "true" {
		generator = generator.WithDNSVisibility() // E3: opt-in DNS visibility companion rule
	}
	policies, yamlBytes, err := generator.GeneratePoliciesWithYAML(aggregatedFlows)
	if err != nil {
		switch {
		case errors.Is(err, policy.ErrReplyFlow):
			s.refuse(w, r, http.StatusBadRequest, err.Error(), "reply_flow")
		case errors.Is(err, policy.ErrNameNeedsOnePolicy):
			n := 0
			fmt.Sscanf(strings.TrimPrefix(err.Error(), policy.ErrNameNeedsOnePolicy.Error()+": got "), "%d", &n)
			s.refuse(w, r, http.StatusBadRequest, err.Error(), "name_needs_single_policy", "policies", n)
		case errors.Is(err, policy.ErrInvalidPolicy):
			s.refuse(w, r, http.StatusBadRequest, err.Error(), "policy_invalid", "error", err.Error())
		default:
			s.refuse(w, r, http.StatusInternalServerError, fmt.Sprintf("Failed to generate policy: %v", err),
				"generate_failed", "error", err.Error())
		}
		return
	}

	// One policy is named after it; several get one file that holds them all
	filename := fmt.Sprintf("ciliumnetworkpolicies-%d.yaml", len(policies))
	if len(policies) == 1 && policies[0].Metadata.Namespace != "" && policies[0].Metadata.Name != "" {
		filename = fmt.Sprintf("%s-%s.yaml", policies[0].Metadata.Namespace, sanitizeName(policies[0].Metadata.Name))
	}

	// The cache key is the flow's UUID for a single flow (Grafana's Download link is built from it), else random
	id := ""
	if len(parsedFlows) == 1 {
		id = parsedFlows[0].UUID
	}
	if id == "" {
		id = generateID()
	}
	s.respond(w, r, id, yamlBytes, filename, "Policy generated successfully. Use the download_url to download the file.", len(parsedFlows), len(policies))
}

// handleYoloNs handles the YOLO namespace easter egg
func (s *Server) handleYoloNs(w http.ResponseWriter, r *http.Request, bodyStr string) {
	// Parse namespace from "yolo ns <namespace>" or default to "default"
	namespace := "default"
	parts := strings.Fields(bodyStr)
	if len(parts) >= 3 {
		namespace = parts[2]
	}

	s.reqLog(r).Info("yolo", "namespace", namespace)

	yamlBytes, err := policy.YOLONamespacePolicyYAML(namespace)
	if err != nil {
		s.refuse(w, r, http.StatusInternalServerError, fmt.Sprintf("Failed to generate YOLO policy: %v", err),
			"generate_failed", "error", err.Error())
		return
	}

	filename := fmt.Sprintf("%s-yolo-allow-all-in-namespace.yaml", namespace)
	s.respond(w, r, generateID(), yamlBytes, filename, "YOLO! Policy generated. Use the download_url to download the file.", 0, 1)
}

// sanitizeName ensures the name is valid for filenames
func sanitizeName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "-")
	// Remove any characters that aren't alphanumeric or hyphens
	var result strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			result.WriteRune(r)
		}
	}
	return result.String()
}
