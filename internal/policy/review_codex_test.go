package policy

import (
	"strings"
	"testing"

	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/hubble-policy-gen/internal/aggregator"
	"github.com/hubble-policy-gen/internal/render"
	"sigs.k8s.io/yaml"
)

// Review ENH-003 (Codex, C5): Sanitize is the rule's. What refuses a document besides it — the API server's
// ObjectMeta checks (a namespace that is not DNS-1123, a label key with a space), the CRD's protocol enum (upper case
// only: Sanitize upper-cases on its copy, the schema sees the file), and the agent's Parse (a namespaced policy
// cannot carry a nodeSelector) — Validate refuses too.
func TestValidate_MatchesAdmission(t *testing.T) {
	cases := map[string]string{
		"metadata": `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: valid
  namespace: BAD_NAMESPACE
spec:
  endpointSelector: {}
  egress:
    - toEntities: [world]
`,
		"labelKey": `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: valid
  namespace: ns
  labels:
    bad key: value
spec:
  endpointSelector: {}
  egress:
    - toEntities: [world]
`,
		"protocol": `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: lower
  namespace: ns
spec:
  endpointSelector: {}
  egress:
    - toEntities: [world]
      toPorts:
        - ports:
            - port: "443"
              protocol: tcp
`,
		"denyProtocol": `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: lower
  namespace: ns
spec:
  endpointSelector: {}
  egressDeny:
    - toEntities: [world]
      toPorts:
        - ports:
            - port: "443"
              protocol: udp
`,
		"nodeSelector": `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: nodes
  namespace: ns
spec:
  nodeSelector:
    matchLabels:
      node-role.kubernetes.io/control-plane: ""
  egress:
    - toEntities: [world]
`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			var p CiliumNetworkPolicy
			if err := yaml.Unmarshal([]byte(raw), &p); err != nil {
				t.Fatal(err)
			}
			if err := Validate(&p); err == nil {
				t.Fatal("a document the API server, the CRD or the agent refuses was accepted")
			} else {
				t.Log(err)
			}
		})
	}
	// the same nodeSelector on a clusterwide policy is legal; a namespaced policy without a namespace is what
	// kubectl fills in (the default namespace), not a refusal
	cw := strings.Replace(strings.Replace(cases["nodeSelector"], "kind: CiliumNetworkPolicy", "kind: CiliumClusterwideNetworkPolicy", 1), "  namespace: ns\n", "", 1)
	var p CiliumNetworkPolicy
	if err := yaml.Unmarshal([]byte(cw), &p); err != nil {
		t.Fatal(err)
	}
	if err := Validate(&p); err != nil {
		t.Fatalf("a clusterwide policy may carry a nodeSelector: %v", err)
	}
	p = CiliumNetworkPolicy{}
	if err := yaml.Unmarshal([]byte(strings.Replace(cases["protocol"], "protocol: tcp", "protocol: TCP", 1)), &p); err != nil {
		t.Fatal(err)
	}
	p.Metadata.Namespace = ""
	if err := Validate(&p); err != nil {
		t.Fatalf("no namespace is kubectl's default, not a refusal: %v", err)
	}
}

// Review ENH-003 (Codex, C9): a resolver derived from the flows kept the one protocol observed (UDP, every golden),
// and a UDP-only rule denies the TCP retry a truncated answer needs. The rule exists to put lookups through the
// proxy, not to restrict a protocol: derived resolvers are ANY, as the profiles and Cilium's examples are, and the
// ANY L7 rule shadows the plain UDP rule the lookup itself produced.
func TestDerivedDNSResolver_IsANY(t *testing.T) {
	flows := []*aggregator.AggregatedFlow{{
		Direction: "EGRESS", DestNamespace: "kube-system",
		DestLabels: map[string]string{"k8s-app": "kube-dns"},
		Ports:      []aggregator.PortInfo{{Port: 53, Protocol: "UDP"}},
	}}
	r, ok := DeriveDNSResolver(flows)
	if !ok || r.Protocol != "ANY" || r.Port != "53" {
		t.Fatalf("derived resolver must be ANY: %+v %v", r, ok)
	}
	wildcard := dnsRuleFor(r)
	plain := wildcard.DeepCopy()
	plain.ToPorts[0].Rules = nil
	plain.ToPorts[0].Ports[0].Protocol = api.ProtoUDP
	got := dropShadowedDNSRule([]EgressRule{*plain, wildcard}, wildcard)
	if len(got) != 1 || mustYAML(got[0]) != mustYAML(wildcard) {
		t.Fatalf("the ANY DNS rule shadows the plain UDP one: %s", mustYAML(got))
	}
	// a plain rule on another port, or with a name-restricted L7 rule, is not shadowed
	other := plain.DeepCopy()
	other.ToPorts[0].Ports[0].Port = "5353"
	if got := dropShadowedDNSRule([]EgressRule{*other, wildcard}, wildcard); len(got) != 2 {
		t.Fatalf("another port is not shadowed: %s", mustYAML(got))
	}
}

// Review ENH-003 (Codex, C2): a document in Cilium's `specs` form renders its rules in the same field order as
// `spec` (the precedence table named "spec" only, so specs[] fell to the lexicographic tail: egress before
// endpointSelector).
func TestRender_SpecsUseRuleOrder(t *testing.T) {
	docs, err := DecodePolicyDocuments([]byte(`apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: multi
  namespace: ns
specs:
  - endpointSelector: {}
    egress:
      - toEntities: [world]
`))
	if err != nil || len(docs) != 1 {
		t.Fatalf("decode: %d %v", len(docs), err)
	}
	if err := Validate(docs[0]); err != nil {
		t.Fatalf("a specs-only policy is valid: %v", err)
	}
	b, err := render.Document(map[string]interface{}{"specs": docs[0].Specs})
	if err != nil {
		t.Fatal(err)
	}
	if s := string(b); strings.Index(s, "endpointSelector:") > strings.Index(s, "egress:") {
		t.Fatalf("specs[] must use the rule order:\n%s", s)
	}
}
