package policy

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
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
	if p.Spec.Description != "Allow ingress to shop in cf2cnp-lab: from pos on TCP/80; from stranger on TCP/80" {
		t.Fatalf("the description must say what the rules say, got %q", p.Spec.Description)
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

// E1: a cross-cluster flow (measured on the bank: payments@poc2 → redis-0@poc1:6379, an EGRESS flow reported by
// the source's node) must name the peer's cluster, because since Cilium 1.19 a selector without
// io.cilium.k8s.policy.cluster matches the local cluster only — the egress policy for payments (in poc2) would
// otherwise allow only a redis in poc2 and exclude the poc1 one the flow went to.
func TestBuildPolicies_CrossClusterPeerNamesItsCluster(t *testing.T) {
	ps, err := NewGenerator("").BuildPolicies(load(t, "egress-payments-poc2-to-redis-poc1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 1 || len(ps[0].Spec.Egress) != 1 || len(ps[0].Spec.Egress[0].ToEndpoints) != 1 {
		t.Fatalf("expected one policy with one endpoint egress rule, got %+v", ps)
	}
	to := ps[0].Spec.Egress[0].ToEndpoints[0].MatchLabels
	if to[ClusterLabel] != "poc1" {
		t.Fatalf("toEndpoints must carry %s=poc1, got %v", ClusterLabel, to)
	}
	if _, ok := ps[0].Spec.EndpointSelector.MatchLabels[ClusterLabel]; ok {
		t.Fatalf("the endpointSelector (the local workload) must not carry the cluster label")
	}
	if ps[0].Metadata.Namespace != "bank" || ps[0].Metadata.Name != "payments" {
		t.Fatalf("the policy is for the source workload: got %s/%s", ps[0].Metadata.Namespace, ps[0].Metadata.Name)
	}
}

// Same-cluster flows are untouched: no cluster label (the local-only default is what is wanted), so the
// output for every single-cluster fixture stays byte-identical
func TestBuildPolicies_SameClusterHasNoClusterLabel(t *testing.T) {
	for _, fx := range []string{"ingress-pos-to-shop.json", "egress-pos-to-world.json"} {
		ps, _ := NewGenerator("").BuildPolicies(load(t, fx))
		out, _ := EncodePolicies(ps)
		if strings.Contains(string(out), ClusterLabel) {
			t.Fatalf("%s: unexpected cluster label:\n%s", fx, out)
		}
	}
}

// Two peers with the same labels in two clusters are two rules
func TestBuildPolicies_SameLabelsTwoClustersTwoRules(t *testing.T) {
	mk := func(cluster string) *aggregator.AggregatedFlow {
		return &aggregator.AggregatedFlow{Direction: "INGRESS", DestNamespace: "bank", DestCluster: "poc1",
			DestLabels:      map[string]string{"app": "api"},
			SourceNamespace: "bank", SourceCluster: cluster, SourceLabels: map[string]string{"app": "payments"},
			Ports: []aggregator.PortInfo{{Port: 8080, Protocol: "TCP"}}}
	}
	ps, _ := NewGenerator("").BuildPolicies([]*aggregator.AggregatedFlow{mk("poc1"), mk("poc2")})
	if len(ps) != 1 || len(ps[0].Spec.Ingress) != 2 {
		t.Fatalf("expected one policy with two rules (local peer, poc2 peer), got %d policies", len(ps))
	}
	if ps[0].Spec.Ingress[0].FromEndpoints[0].MatchLabels[ClusterLabel] != "" || ps[0].Spec.Ingress[1].FromEndpoints[0].MatchLabels[ClusterLabel] != "poc2" {
		t.Fatalf("rules: %+v", ps[0].Spec.Ingress)
	}
}

// Review finding: an empty destination.cluster_name (Hubble without cluster.name) must not lose the cluster the
// flow's labels carry
func TestBuildPolicies_ClusterLabelWhenClusterNameEmpty(t *testing.T) {
	raw := []byte(`{"flow":{"uuid":"x","traffic_direction":"EGRESS","is_reply":false,"l4":{"TCP":{"destination_port":6379}},
	  "source":{"cluster_name":"poc2","namespace":"bank","labels":["k8s:app=payments","k8s:io.cilium.k8s.policy.cluster=poc2"]},
	  "destination":{"namespace":"bank","labels":["k8s:app=redis","k8s:io.cilium.k8s.policy.cluster=poc1"]}}}`)
	f, err := flow.ParseFlowsFromBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	ps, err := NewGenerator("").BuildPolicies(aggregator.AggregateFlows(f))
	if err != nil {
		t.Fatal(err)
	}
	if to := ps[0].Spec.Egress[0].ToEndpoints[0].MatchLabels; to[ClusterLabel] != "poc1" {
		t.Fatalf("empty destination.cluster_name must still yield cluster=poc1 from the label, got %v", to)
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
// measured request through the Gateway (GET https://bankapi.poc.local/api/balance/chk-1001, demo 15): the record
// the Gateway's Envoy (reserved:ingress) emitted on its EGRESS side, which since fork issue #7 is skipped — no pod
// to select — so the test reads it as the INGRESS record of the same request at api in bank.
func TestBuildPolicies_L7HTTPRules(t *testing.T) {
	raw := bytes.Replace(fixture(t, "l7-http-request.json"), []byte(`"traffic_direction": "EGRESS"`), []byte(`"traffic_direction": "INGRESS"`), 1)
	flows, err := flow.ParseFlowsFromBytes(raw)
	if err != nil || len(flows) != 1 || flows[0].Direction != "INGRESS" || flows[0].SourceEntity != "ingress" {
		t.Fatalf("the fixture must read as the INGRESS record from reserved:ingress: %+v %v", flows, err)
	}
	ps, err := NewGenerator("").WithL7().BuildPolicies(aggregator.AggregateFlows(flows))
	if err != nil {
		t.Fatal(err)
	}
	rules := firstRules(ps)
	if rules == nil || len(rules.HTTP) != 1 || rules.HTTP[0].Method != "GET" || rules.HTTP[0].Path != `^/api/balance/chk-1001(\?.*)?$` {
		t.Fatalf("expected one escaped GET rule for the measured path allowing a query, got %+v", rules)
	}
	plain, _ := NewGenerator("").BuildPolicies(aggregator.AggregateFlows(flows))
	if out, _ := EncodePolicies(plain); strings.Contains(string(out), "http:") {
		t.Fatalf("without WithL7 the output must be layer-4 only:\n%s", out)
	}
}

// fixture is one testdata file's bytes
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
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

// E2: regex metacharacters in a path are escaped, and a query string is allowed (Envoy matches the whole :path)
func TestL7Rules_PathIsEscapedAndAllowsAQuery(t *testing.T) {
	r := l7RulesFor(aggregator.PortInfo{Port: 80, Protocol: "TCP", HTTPRequests: []aggregator.HTTPRequest{{Method: "GET", Path: "/v1/items.json"}}})
	want := `^/v1/items\.json(\?.*)?$`
	if r.HTTP[0].Path != want {
		t.Fatalf("got %q want %q", r.HTTP[0].Path, want)
	}
	re := regexp.MustCompile(r.HTTP[0].Path)
	for path, ok := range map[string]bool{"/v1/items.json": true, "/v1/items.json?x=1": true, "/v1/itemsXjson": false, "/v1/items.json/extra": false} {
		if re.MatchString(path) != ok {
			t.Fatalf("%q matched=%v, want %v", path, !ok, ok)
		}
	}
}

// Review finding: L7 records belong to the port they were seen on — an HTTP rule on 8080 must not restrict 5432
func TestBuildPolicies_L7RulesArePerPort(t *testing.T) {
	agg := &aggregator.AggregatedFlow{Direction: "INGRESS", DestNamespace: "bank", DestLabels: map[string]string{"app": "api"},
		SourceNamespace: "bank", SourceLabels: map[string]string{"app": "web"},
		Ports: []aggregator.PortInfo{{Port: 5432, Protocol: "TCP"}, {Port: 8080, Protocol: "TCP", HTTPRequests: []aggregator.HTTPRequest{{Method: "POST", Path: "/payments"}}}}}
	ps, _ := NewGenerator("").WithL7().BuildPolicies([]*aggregator.AggregatedFlow{agg})
	tp := ps[0].Spec.Ingress[0].ToPorts
	if len(tp) != 2 || tp[0].Rules != nil || tp[0].Ports[0].Port != "5432" || tp[1].Rules == nil || tp[1].Ports[0].Port != "8080" {
		t.Fatalf("expected [5432 plain] [8080 with rules], got %+v", tp)
	}
	plain, _ := NewGenerator("").BuildPolicies([]*aggregator.AggregatedFlow{agg})
	if n := len(plain[0].Spec.Ingress[0].ToPorts); n != 1 {
		t.Fatalf("without WithL7 the ports stay in one rule, got %d", n)
	}
}

// Both reviewers weighed in and the docs decide: an L7 DNS policy allows ONLY the names it lists, and the
// resolver tries the search-list expansions first — so the measured expansion is kept exactly as observed
func TestBuildPolicies_L7DNSRules_KeepsTheQueryAsObserved(t *testing.T) {
	ps, err := NewGenerator("").WithL7().BuildPolicies(load(t, "l7-dns-request.json"))
	if err != nil {
		t.Fatal(err)
	}
	rules := firstRules(ps)
	if rules == nil || len(rules.DNS) != 1 || rules.DNS[0].MatchName != "accounts.bank.svc.cluster.local.bank.svc.cluster.local" {
		t.Fatalf("the query must be kept as the resolver sent it, got %+v", rules)
	}
}

// E3: a world flow without names gets, on request, the same DNS rule every toFQDNs policy carries; without
// the option the output is unchanged
func TestBuildPolicies_DNSVisibilityCompanion(t *testing.T) {
	plain, _ := NewGenerator("").BuildPolicies(load(t, "egress-pos-to-world.json"))
	if len(plain[0].Spec.Egress) != 1 {
		t.Fatalf("without the option: one rule, got %d", len(plain[0].Spec.Egress))
	}
	ps, _ := NewGenerator("").WithDNSVisibility().BuildPolicies(load(t, "egress-pos-to-world.json"))
	if len(ps[0].Spec.Egress) != 2 {
		t.Fatalf("with the option: two rules, got %d", len(ps[0].Spec.Egress))
	}
	if mustYAML(ps[0].Spec.Egress[1]) != mustYAML(dnsRuleFor(dnsProfiles[DNSProfileKubernetes])) {
		t.Fatalf("the second rule must be the DNS visibility rule:\n%s", mustYAML(ps[0].Spec.Egress[1]))
	}
	out, _ := EncodePolicies(ps)
	if !strings.Contains(string(out), "regenerate to get a toFQDNs rule") {
		t.Fatalf("the comment must say what the rule is for:\n%s", out)
	}
}

// Demo 31 finding (fork issue #1): a pod whose flows include its own DNS lookups got kube-dns 53/UDP twice — the plain
// rule from the lookup and the DNS-visibility rule. With --dns-visibility the plain one is dropped (the L7 rule with
// matchPattern "*" says everything it said); without the option nothing changes.
func TestDNSVisibility_OneKubeDNSRule(t *testing.T) {
	ps, err := NewGenerator("").WithDNSVisibility().BuildPolicies(load(t, "egress-pos-to-kube-dns.json", "egress-pos-to-world.json"))
	if err != nil || len(ps) != 1 {
		t.Fatalf("one policy expected: %d %v", len(ps), err)
	}
	dns := 0
	for _, r := range ps[0].Spec.Egress {
		if len(r.ToEndpoints) == 1 && r.ToEndpoints[0].MatchLabels["k8s-app"] == "kube-dns" {
			dns++
			if r.ToPorts[0].Rules == nil || len(r.ToPorts[0].Rules.DNS) != 1 {
				t.Fatalf("the surviving kube-dns rule must be the DNS-visibility one: %s", mustYAML(r))
			}
		}
	}
	if dns != 1 {
		t.Fatalf("kube-dns must appear once, got %d:\n%s", dns, mustYAML(ps[0].Spec.Egress))
	}
	plain, _ := NewGenerator("").BuildPolicies(load(t, "egress-pos-to-kube-dns.json", "egress-pos-to-world.json"))
	if n := len(plain[0].Spec.Egress); n != 2 {
		t.Fatalf("without the option the plain rule stays beside the CIDR: %d rules", n)
	}
}

// 0.7.0: a reserved:world SOURCE with an address (an egress-gateway IP, a load balancer's client) is a fromCIDR rule —
// what the receiver saw — not fromEntities: [world] (any external address), which 0.6.x wrote for every world source
func TestBuildPolicies_WorldSourceIsFromCIDR(t *testing.T) {
	ps, err := NewGenerator("").BuildPolicies(load(t, "ingress-world-cidr-to-receiver.json"))
	if err != nil || len(ps) != 1 {
		t.Fatalf("one policy expected: %d %v", len(ps), err)
	}
	r := ps[0].Spec.Ingress[0]
	if len(r.FromCIDR) != 1 || string(r.FromCIDR[0]) != "172.18.255.170/32" || len(r.FromEntities) != 0 {
		t.Fatalf("expected fromCIDR 172.18.255.170/32 and no entity, got %s", mustYAML(r))
	}
	if !strings.Contains(ps[0].Spec.Description, "from 172.18.255.170/32 on TCP/80") {
		t.Fatalf("the description must name the address: %q", ps[0].Spec.Description)
	}
	if err := Validate(ps[0]); err != nil {
		t.Fatal(err)
	}
}

// Fork issue #7: the Gateway's Envoy (reserved:ingress, identity 8) calling api-gateway is two Hubble flows of one
// connection — INGRESS at the pod, EGRESS at the ingress endpoint. 0.9.0 turned the EGRESS one into a policy named
// `unknown` in namespace `default` with an EMPTY endpointSelector (every endpoint of `default`, applied). A reserved
// identity has no pod to select: the egress flow is skipped with a warning, the ingress policy is the whole answer.
// The fixture is written after the issue's report (demo 41), not captured.
func TestBuildPolicies_SkipsEgressFromReservedSource(t *testing.T) {
	g := NewGenerator("")
	ps, err := g.BuildPolicies(load(t, "edge-ingress-to-api-gateway.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 1 || ps[0].Metadata.Name != "api-gateway" || ps[0].Metadata.Namespace != "shop-edge" {
		names := make([]string, 0, len(ps))
		for _, p := range ps {
			names = append(names, p.Metadata.Namespace+"/"+p.Metadata.Name+" selector="+mustYAML(p.Spec.EndpointSelector))
		}
		t.Fatalf("a reserved:ingress source must yield the ingress policy only, got %v", names)
	}
	if from := ps[0].Spec.Ingress[0].FromEntities; len(from) != 1 || from[0] != "ingress" {
		t.Fatalf("the ingress policy must be fromEntities: [ingress], got %s", mustYAML(ps[0].Spec.Ingress[0]))
	}
	ws := g.Warnings()
	if len(ws) != 1 || !strings.Contains(ws[0], "EGRESS flow from reserved:ingress to api-gateway in shop-edge on TCP/80 skipped") || !strings.Contains(ws[0], "reserved identity reserved:ingress") {
		t.Fatalf("one warning naming the skipped flow and the reserved identity, got %q", ws)
	}
	// the YAML answer opens with the warning as comments, and stays one valid document
	_, out, err := g.GeneratePoliciesWithYAML(load(t, "edge-ingress-to-api-gateway.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(out), "# WARNING: 1 flow(s) skipped, no generated policy covers them:\n# - EGRESS flow from reserved:ingress") {
		t.Fatalf("the YAML must open with the warning:\n%s", out)
	}
	docs, err := DecodePolicyDocuments(out)
	if err != nil || len(docs) != 1 || docs[0].Metadata.Name != "api-gateway" {
		t.Fatalf("the commented YAML must still decode to the one policy: %d %v", len(docs), err)
	}
	if err := Validate(docs[0]); err != nil {
		t.Fatal(err)
	}
	// a run with nothing left is refused like an all-replies run, and says why
	egressOnly := load(t, "edge-ingress-to-api-gateway.json")[:1]
	if egressOnly[0].Direction != "EGRESS" {
		t.Fatalf("the aggregator orders EGRESS first, got %s", egressOnly[0].Direction)
	}
	_, err = NewGenerator("").BuildPolicies(egressOnly)
	if !errors.Is(err, ErrNothingGenerated) || !strings.Contains(err.Error(), "reserved:ingress") {
		t.Fatalf("every flow skipped must be ErrNothingGenerated with the reason, got %v", err)
	}
	// a second run starts with a clean slate
	if _, err := g.BuildPolicies(load(t, "ingress-pos-to-shop.json")); err != nil || len(g.Warnings()) != 0 {
		t.Fatalf("warnings must be per run, got %v %v", g.Warnings(), err)
	}
}

// Review (Codex P1): a warning carries the flow's own text, which no Validate has seen. A line break in a crafted
// namespace ended the comment and started a document that decoded, validated and bypassed every generator check;
// six separators yaml reads as line breaks. The answer must stay the one policy, the warning one comment line.
func TestWarningsHeader_CannotInjectDocuments(t *testing.T) {
	injected, err := EncodePolicies([]*CiliumNetworkPolicy{YOLONamespacePolicy("victim")})
	if err != nil {
		t.Fatal(err)
	}
	for _, sep := range []string{"\n", "\r", "\r\n", "\u0085", " ", " "} {
		fs := load(t, "edge-ingress-to-api-gateway.json") // [0] is the skipped EGRESS flow: its namespace is in the warning
		fs[0].DestNamespace = "edge" + sep + "---" + sep + strings.ReplaceAll(string(injected), "\n", sep) + sep + "---" + sep + "# tail"
		ps, out, err := NewGenerator("").GeneratePoliciesWithYAML(fs)
		if err != nil || len(ps) != 1 {
			t.Fatalf("%q: %v %d", sep, err, len(ps))
		}
		docs, err := DecodePolicyDocuments(out)
		if err != nil || len(docs) != 1 || docs[0].Metadata.Name != "api-gateway" {
			t.Fatalf("%q: the warning must not add a document: decoded %d, err %v\n%s", sep, len(docs), err, out)
		}
		if bytes.Count(out, []byte("\n# - ")) != 1 || !strings.Contains(string(out), `edge\`) {
			t.Fatalf("%q: the separator must be escaped inside one comment line:\n%s", sep, out)
		}
	}
}

// Review (Codex P2): the CLI's artifacts — generate's files, merge's output — said nothing about skipped flows; only
// stderr did, which a policy PR does not keep. Each file now opens with the run's warnings. MergeDocument keeps a
// file's comments, so the next run must replace the block (or remove it when it skipped nothing): a warning that
// outlives its flow would be a lie. Codex's own fix only skipped an identical header and left a stale one in place.
func TestGeneratePolicies_FilesCarryTheRunsWarnings(t *testing.T) {
	dir := t.TempDir()
	g := NewGenerator(dir)
	if err := g.GeneratePolicies(load(t, "edge-ingress-to-api-gateway.json")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "shop-edge-api-gateway.yaml"))
	if err != nil || !strings.HasPrefix(string(b), "# WARNING: 1 flow(s) skipped, no generated policy covers them:\n# - EGRESS flow from reserved:ingress") {
		t.Fatalf("the file must open with the warning: %v\n%s", err, b)
	}
	docs, err := DecodePolicyDocuments(b)
	if err != nil || len(docs) != 1 {
		t.Fatalf("decode: %d %v", len(docs), err)
	}
	if err := Validate(docs[0]); err != nil {
		t.Fatal(err)
	}
	merged, _, err := MergeDocument(b, docs[0])
	if err != nil || !strings.HasPrefix(string(merged), "# WARNING: 1 flow(s) skipped") {
		t.Fatalf("MergeDocument keeps the comment at the head: %v\n%s", err, merged)
	}
	if again := g.AnnotateWarnings(b); !bytes.Equal(again, b) {
		t.Fatalf("the same run annotates idempotently:\n%s", again)
	}
	clean := NewGenerator("")
	if _, err := clean.BuildPolicies(load(t, "ingress-pos-to-shop.json")); err != nil || len(clean.Warnings()) != 0 {
		t.Fatal(err)
	}
	if out := clean.AnnotateWarnings(merged); strings.Contains(string(out), "# WARNING") || !strings.HasPrefix(string(out), "apiVersion:") {
		t.Fatalf("a run that skipped nothing must remove the previous warning:\n%s", out)
	}
	other := NewGenerator("")
	other.warnings = []string{"another run's reason"}
	out := string(other.AnnotateWarnings(merged))
	if strings.Count(out, "# WARNING:") != 1 || !strings.HasPrefix(out, "# WARNING: 1 flow(s) skipped, no generated policy covers them:\n# - another run's reason\napiVersion:") {
		t.Fatalf("a different warning must replace the old block, not stack on it:\n%s", out)
	}
}
