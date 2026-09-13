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
