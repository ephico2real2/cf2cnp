package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hubble-policy-gen/internal/aggregator"
	"github.com/hubble-policy-gen/internal/crd"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Review ENH-003 (Cursor, finding 1): looksLikeDNS took every kube-system peer on 53/5353 as the resolver. The
// resolver is what the workload's lookups actually reach: CoreDNS (k8s-app=kube-dns or coredns), NodeLocal DNSCache
// when a Local Redirect Policy sends lookups to it (k8s-app=node-local-dns, kube-system — the flow's destination is
// then that pod, and a rule naming kube-dns would cut the pod off), or OpenShift's DNS operator (the namespace alone).
// Anything else in kube-system on those ports is not.
func TestLooksLikeDNS_NotTheWholeOfKubeSystem(t *testing.T) {
	if looksLikeDNS("kube-system", map[string]string{"app.kubernetes.io/name": "metrics-server"}) {
		t.Fatal("a kube-system peer without a resolver label is not the resolver")
	}
	if looksLikeDNS("kube-system", nil) {
		t.Fatal("kube-system alone is not the resolver")
	}
	for _, v := range []string{"kube-dns", "coredns", "node-local-dns"} {
		if !looksLikeDNS("kube-system", map[string]string{"k8s-app": v}) {
			t.Fatalf("k8s-app=%s is a resolver", v)
		}
	}
	if !looksLikeDNS("openshift-dns", nil) {
		t.Fatal("OpenShift's resolver is the namespace")
	}
	other := &aggregator.AggregatedFlow{
		Direction: "EGRESS", DestNamespace: "kube-system",
		DestLabels: map[string]string{"app.kubernetes.io/name": "other"},
		Ports:      []aggregator.PortInfo{{Port: 53, Protocol: "UDP"}},
	}
	if _, ok := DeriveDNSResolver([]*aggregator.AggregatedFlow{other}); ok {
		t.Fatal("kube-system:53 without a resolver label must not derive the resolver")
	}
	nodeLocal := &aggregator.AggregatedFlow{
		Direction: "EGRESS", DestNamespace: "kube-system",
		DestLabels: map[string]string{"k8s-app": "node-local-dns"},
		Ports:      []aggregator.PortInfo{{Port: 53, Protocol: "UDP"}},
	}
	r, ok := DeriveDNSResolver([]*aggregator.AggregatedFlow{nodeLocal})
	if !ok || r.Labels["k8s-app"] != "node-local-dns" {
		t.Fatalf("NodeLocal DNSCache is what the lookups reach under an LRP: %+v %v", r, ok)
	}
}

// Review ENH-003 (Cursor, finding 4): Cilium's own Kubernetes example (examples/kubernetes-dns/dns-matchname.yaml)
// writes the resolver rule as 53/ANY, and a lookup whose UDP answer is truncated retries over TCP; the kubernetes
// profile follows the guide (and, after Codex's C9, so does a resolver derived from the flows: TestDerivedDNSResolver_IsANY).
func TestDNSProfiles_FollowCiliumGuide(t *testing.T) {
	if r := dnsProfiles[DNSProfileKubernetes]; r.Port != "53" || r.Protocol != "ANY" || r.Labels["k8s-app"] != "kube-dns" || r.Namespace != "kube-system" {
		t.Fatalf("kubernetes profile: %+v", r)
	}
	if r := dnsProfiles[DNSProfileOpenShift]; r.Port != "5353" || r.Protocol != "ANY" || r.Labels != nil || r.Namespace != "openshift-dns" {
		t.Fatalf("openshift profile: %+v", r)
	}
	r, err := ParseDNSResolver("kube-system:53")
	if err != nil || r.Protocol != "ANY" {
		t.Fatalf("a resolver without a protocol is ANY: %+v %v", r, err)
	}
	ps, err := NewGenerator("").WithDNSVisibility().BuildPolicies(load(t, "egress-pos-to-world.json"))
	if err != nil || len(ps) != 1 {
		t.Fatalf("one policy: %d %v", len(ps), err)
	}
	if p := ps[0].Spec.Egress[len(ps[0].Spec.Egress)-1].ToPorts[0].Ports[0]; p.Port != "53" || p.Protocol != "ANY" {
		t.Fatalf("no DNS flow: the kubernetes profile, 53/ANY, got %s/%s", p.Protocol, p.Port)
	}
}

// Review ENH-003 (Cursor, finding 2): `cf2cnp validate` split a file on "\n---", so a literal block holding a line
// "---" became a second document. The YAML decoder knows where a document ends.
func TestDecodePolicyDocuments(t *testing.T) {
	doc := []byte(`apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: shop
  namespace: ns
spec:
  description: |
    note
    ---
    still one object
  endpointSelector:
    matchLabels:
      app: shop
  ingress:
    - fromEntities:
        - world
---
# a comment between documents
---
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: second
  namespace: ns
spec:
  endpointSelector: {}
`)
	ps, err := DecodePolicyDocuments(doc)
	if err != nil || len(ps) != 2 {
		t.Fatalf("two documents (the empty one skipped), got %d %v", len(ps), err)
	}
	if !strings.Contains(ps[0].Spec.Description, "---") || ps[1].Metadata.Name != "second" {
		t.Fatalf("description lost the separator or the order: %q %q", ps[0].Spec.Description, ps[1].Metadata.Name)
	}
	if _, err := DecodePolicyDocuments([]byte("a: [unclosed\n")); err == nil {
		t.Fatal("a broken document is an error")
	}
}

// Review ENH-003 (Cursor, finding 3): Sanitize checks the rule, not the object. The agent refuses an empty name
// (cnp_types.go Parse) and the API server a name that is not a DNS-1123 subdomain; so does Validate. And `specs`
// (Cilium's list form) is validated rule by rule.
func TestValidate_ObjectNameAndSpecs(t *testing.T) {
	good := Rule{EndpointSelector: Selector(map[string]string{"app": "x"}),
		Ingress: []IngressRule{{IngressCommonRule: IngressCommonRule{FromEntities: EntitySlice{"world"}}}}}
	for _, name := range []string{"", "Not_A_DNS_Name", "-leading"} {
		p := &CiliumNetworkPolicy{Metadata: metav1.ObjectMeta{Name: name, Namespace: "ns"}, Spec: good}
		err := Validate(p)
		if err == nil || !errors.Is(err, ErrInvalidPolicy) || !strings.Contains(err.Error(), "metadata.name") {
			t.Fatalf("%q: expected a metadata.name refusal, got %v", name, err)
		}
	}
	bad := good
	bad.Ingress = []IngressRule{{IngressCommonRule: IngressCommonRule{FromEntities: EntitySlice{"world"}, FromCIDR: CIDRSlice{"10.0.0.0/8"}}}}
	p := &CiliumNetworkPolicy{Metadata: metav1.ObjectMeta{Name: "ok", Namespace: "ns"}, Specs: []*Rule{&good, &bad}}
	err := Validate(p)
	if err == nil || !errors.Is(err, ErrInvalidPolicy) || !strings.Contains(err.Error(), "specs[1]") {
		t.Fatalf("the second of specs is refused and named: %v", err)
	}
}

// Review ENH-003 (Cursor, finding 6): hosted Renovate does not run postUpgradeTasks, so a Cilium bump lands without
// `go generate ./internal/crd`. CI's cmp catches the file; this catches the version from `go test` alone: the
// embedded CRD's version is the version go.mod requires. (Cursor's snippet read debug.ReadBuildInfo().Deps; on the
// GitHub runner the test binary reported no Deps at all — measured, CI run 34774484089 — so the source of truth is
// the go.mod line.)
func TestEmbeddedCRDVersionMatchesModule(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	want := ""
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "github.com/cilium/cilium" {
			want = f[1]
		}
	}
	if want == "" || crd.Version() != want {
		t.Fatalf("embedded CRD %q, go.mod requires %q — run go generate ./internal/crd", crd.Version(), want)
	}
}
