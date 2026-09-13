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
