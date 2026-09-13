package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hubble-policy-gen/internal/aggregator"
	"github.com/hubble-policy-gen/internal/flow"
)

func load(t *testing.T, names ...string) []*aggregator.AggregatedFlow {
	t.Helper()
	var all []*flow.ParsedFlow
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join("..", "testdata", n))
		if err != nil {
			t.Fatal(err)
		}
		f, err := flow.ParseFlowsFromBytes(b)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, f...)
	}
	return aggregator.AggregateFlows(all)
}

// Before: two flows into shop from two peers produced two policies both named "shop" (the second
// `kubectl apply` replaced the first). After: one policy with two ingress rules.
func TestBuildPolicies_MergesSameWorkload(t *testing.T) {
	policies, err := NewGenerator("").BuildPolicies(load(t, "ingress-pos-to-shop.json", "ingress-stranger-to-shop.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected 1 merged policy, got %d", len(policies))
	}
	p := policies[0]
	if p.Metadata.Name != "shop" || p.Metadata.Namespace != "cf2cnp-lab" || len(p.Spec.Ingress) != 2 {
		t.Fatalf("unexpected policy: name=%s ns=%s ingress=%d", p.Metadata.Name, p.Metadata.Namespace, len(p.Spec.Ingress))
	}
	peers := p.Spec.Ingress[0].FromEndpoints[0].MatchLabels["app.kubernetes.io/name"] + "," + p.Spec.Ingress[1].FromEndpoints[0].MatchLabels["app.kubernetes.io/name"]
	if peers != "pos,stranger" {
		t.Fatalf("rules must keep first-seen order, got %s", peers)
	}
	if !strings.Contains(p.Spec.Description, "2 rules merged from 2 observed flows") {
		t.Fatalf("description must say what was merged, got %q", p.Spec.Description)
	}
}

// The same flow twice is one rule, not two
func TestBuildPolicies_DedupesIdenticalRules(t *testing.T) {
	policies, err := NewGenerator("").BuildPolicies(load(t, "ingress-pos-to-shop.json", "ingress-pos-to-shop.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 1 || len(policies[0].Spec.Ingress) != 1 {
		t.Fatalf("expected one policy with one rule, got %d policies, %d rules", len(policies), len(policies[0].Spec.Ingress))
	}
}

// Different workloads stay different policies. The aggregator orders its output by key (direction
// first), so the EGRESS policy for pos precedes the INGRESS policy for shop whatever the input order.
func TestBuildPolicies_KeepsDistinctWorkloads(t *testing.T) {
	policies, err := NewGenerator("").BuildPolicies(load(t, "ingress-pos-to-shop.json", "egress-pos-to-world.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 2 || policies[0].Metadata.Name != "pos" || policies[1].Metadata.Name != "shop" {
		t.Fatalf("expected pos (egress) then shop (ingress), got %s, %s", policies[0].Metadata.Name, policies[1].Metadata.Name)
	}
	if len(policies[0].Spec.Egress) != 1 || policies[0].Spec.Egress[0].ToCIDR[0] != "104.20.23.154/32" {
		t.Fatalf("world flow without names must be a toCIDR rule, got %+v", policies[0].Spec.Egress)
	}
}

func TestBuildPolicies_NameOverride(t *testing.T) {
	// sanitizeK8sName (upstream, unchanged): lower-case, '_' → '-', anything else non [a-z0-9-] dropped
	policies, err := NewGenerator("").WithName("Shop_From_POS!").BuildPolicies(load(t, "ingress-pos-to-shop.json"))
	if err != nil {
		t.Fatal(err)
	}
	if policies[0].Metadata.Name != "shop-from-pos" {
		t.Fatalf("name must be sanitized for Kubernetes, got %q", policies[0].Metadata.Name)
	}
	_, err = NewGenerator("").WithName("x").BuildPolicies(load(t, "ingress-pos-to-shop.json", "egress-pos-to-world.json"))
	if err == nil || !strings.Contains(err.Error(), "single policy") {
		t.Fatalf("a name with two resulting policies must be refused, got %v", err)
	}
}

// File mode: before the merge, two flows to the same workload wrote the same file twice (the second
// overwrote the first). Now one file holds both rules.
func TestGeneratePolicies_OneFilePerWorkload(t *testing.T) {
	dir := t.TempDir()
	if err := NewGenerator(dir).GeneratePolicies(load(t, "ingress-pos-to-shop.json", "ingress-stranger-to-shop.json", "egress-pos-to-world.json")); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Fatalf("expected 2 files (shop, pos), got %d", len(entries))
	}
	b, _ := os.ReadFile(filepath.Join(dir, "cf2cnp-lab-shop.yaml"))
	if strings.Count(string(b), "fromEndpoints") != 2 {
		t.Fatalf("shop's file must carry both peers:\n%s", b)
	}
	b, _ = os.ReadFile(filepath.Join(dir, "cf2cnp-lab-pos.yaml"))
	if !strings.Contains(string(b), "# - toEntities:") {
		t.Fatalf("the world comment must survive the merge:\n%s", b)
	}
}

func TestEncodePolicies_MultiDocument(t *testing.T) {
	policies, _ := NewGenerator("").BuildPolicies(load(t, "ingress-pos-to-shop.json", "egress-pos-to-world.json"))
	out, err := EncodePolicies(policies)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(out), "---\n") != 1 || strings.Count(string(out), "kind: CiliumNetworkPolicy") != 2 {
		t.Fatalf("expected two documents separated once:\n%s", out)
	}
}

func mkIngress(ns, name, component, instance, peer string) *aggregator.AggregatedFlow {
	dst := map[string]string{"app.kubernetes.io/name": name}
	if component != "" {
		dst["app.kubernetes.io/component"] = component
	}
	if instance != "" {
		dst["app.kubernetes.io/instance"] = instance
	}
	return &aggregator.AggregatedFlow{Direction: "INGRESS", DestNamespace: ns, DestLabels: dst, SourceNamespace: ns,
		SourceLabels: map[string]string{"app.kubernetes.io/name": peer}, Ports: []aggregator.PortInfo{{Port: 80, Protocol: "TCP"}}}
}

// Kubernetes identifies an object by group/kind/namespace/name: two workloads that differ only by component
// or instance must not produce two objects with one name (the second apply replaces the first).
func TestBuildPolicies_NameIsAFunctionOfTheSelector(t *testing.T) {
	ps, err := NewGenerator("").BuildPolicies([]*aggregator.AggregatedFlow{
		mkIngress("store", "shop", "frontend", "", "pos"), mkIngress("store", "shop", "backend", "", "pos"),
		mkIngress("store", "shop", "", "", "pos"), mkIngress("store", "shop", "frontend", "blue", "pos"),
	})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, p := range ps {
		key := p.Metadata.Namespace + "/" + p.Metadata.Name
		if seen[key] {
			t.Fatalf("two policies share %s", key)
		}
		seen[key] = true
	}
	want := map[string]bool{"store/shop-frontend": true, "store/shop-backend": true, "store/shop": true, "store/shop-blue-frontend": true}
	for k := range want {
		if !seen[k] {
			t.Fatalf("expected %s among %v", k, seen)
		}
	}
	for _, p := range ps {
		if p.Metadata.Labels["app.kubernetes.io/managed-by"] != "cf2cnp" || p.Metadata.Labels["app.kubernetes.io/name"] != "shop" {
			t.Fatalf("labels must carry managed-by and the selector's name: %v", p.Metadata.Labels)
		}
		if c := p.Spec.EndpointSelector.MatchLabels["app.kubernetes.io/component"]; c != "" && p.Metadata.Labels["app.kubernetes.io/component"] != c {
			t.Fatalf("component label must be carried: %v", p.Metadata.Labels)
		}
	}
}

// A workload with only app.kubernetes.io/name keeps the name it always had
func TestBuildPolicies_NameUnchangedWithoutComponent(t *testing.T) {
	ps, _ := NewGenerator("").BuildPolicies(load(t, "ingress-pos-to-shop.json"))
	if ps[0].Metadata.Name != "shop" {
		t.Fatalf("got %s", ps[0].Metadata.Name)
	}
}

func firstRules(ps []*CiliumNetworkPolicy) *L7Rules {
	for _, p := range ps {
		for _, r := range p.Spec.Ingress {
			if len(r.ToPorts) > 0 && r.ToPorts[0].Rules != nil {
				return r.ToPorts[0].Rules
			}
		}
		for _, r := range p.Spec.Egress {
			if len(r.ToPorts) > 0 && r.ToPorts[0].Rules != nil {
				return r.ToPorts[0].Rules
			}
		}
	}
	return nil
}

// E2: HTTP REQUEST records become anchored, escaped method+path rules; only with WithL7. The fixture is a
// measured request through the Gateway (GET https://bankapi.poc.local/api/balance/chk-1001, demo 15).
func TestBuildPolicies_L7HTTPRules(t *testing.T) {
	ps, err := NewGenerator("").WithL7().BuildPolicies(load(t, "l7-http-request.json"))
	if err != nil {
		t.Fatal(err)
	}
	rules := firstRules(ps)
	if rules == nil || len(rules.HTTP) != 1 || rules.HTTP[0].Method != "GET" || rules.HTTP[0].Path != "^/api/balance/chk-1001$" {
		t.Fatalf("expected one anchored GET rule for the measured path, got %+v", rules)
	}
	plain, _ := NewGenerator("").BuildPolicies(load(t, "l7-http-request.json"))
	if out, _ := EncodePolicies(plain); strings.Contains(string(out), "http:") {
		t.Fatalf("without WithL7 the output must be layer-4 only:\n%s", out)
	}
}

// E2: a DNS REQUEST yields matchName without the trailing dot; a DNS RESPONSE is the reply side and yields no rule
func TestBuildPolicies_L7DNSRules(t *testing.T) {
	ps, _ := NewGenerator("").WithL7().BuildPolicies(load(t, "l7-dns-request.json"))
	rules := firstRules(ps)
	if rules == nil || len(rules.DNS) == 0 {
		t.Fatalf("expected a dns rule from a DNS REQUEST record: %+v", ps)
	}
	if n := rules.DNS[0].MatchName; n == "" || strings.HasSuffix(n, ".") {
		t.Fatalf("matchName must be the query without the trailing dot, got %q", n)
	}
	// the reply side (derived from the request record: type RESPONSE, is_reply true) yields no policy at all
	if _, err := NewGenerator("").WithL7().BuildPolicies(load(t, "l7-dns-response.json")); err == nil {
		t.Fatalf("a DNS RESPONSE is a reply and must be refused like any reply")
	}
}

// E2: regex metacharacters in a path are escaped
func TestL7Rules_PathIsEscaped(t *testing.T) {
	r := NewGenerator("").WithL7().l7Rules(&aggregator.AggregatedFlow{HTTPRequests: []aggregator.HTTPRequest{{Method: "GET", Path: "/v1/items.json"}}})
	if r.HTTP[0].Path != `^/v1/items\.json$` {
		t.Fatalf("got %q", r.HTTP[0].Path)
	}
}

// Review finding: the measured DNS request is a search-list expansion; the rule must name the real name
func TestBuildPolicies_L7DNSRules_StripsSearchDomain(t *testing.T) {
	ps, err := NewGenerator("").WithL7().BuildPolicies(load(t, "l7-dns-request.json"))
	if err != nil {
		t.Fatal(err)
	}
	rules := firstRules(ps)
	if rules == nil || len(rules.DNS) != 1 || rules.DNS[0].MatchName != "accounts.bank.svc.cluster.local" {
		t.Fatalf("ndots expansion must be stripped, got %+v", rules)
	}
}
