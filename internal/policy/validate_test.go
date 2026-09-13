package policy

import (
	"errors"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// 0.7.0: Cilium's own Sanitize runs on every generated policy (on a copy). A rule that mixes a pod peer and a CIDR
// peer is refused with the agent's sentence; a bad CIDR too; the copy keeps the rendered document untouched.
func TestValidate_RefusesWhatTheAgentRefuses(t *testing.T) {
	mixed := &CiliumNetworkPolicy{Metadata: metav1.ObjectMeta{Name: "x", Namespace: "y"}, Spec: Rule{
		EndpointSelector: Selector(map[string]string{"app": "x"}),
		Ingress: []IngressRule{{IngressCommonRule: IngressCommonRule{
			FromEndpoints: []EndpointSelector{Selector(map[string]string{"app": "a"})},
			FromCIDR:      CIDRSlice{"10.0.0.1/32"},
		}}}}}
	err := Validate(mixed)
	// Cilium names the two fields in whichever order its set iterates ("combining FromCIDR and FromEndpoints" on one
	// run, the reverse on another — CI caught it); assert the words, not their order
	if err == nil || !strings.Contains(err.Error(), "combining") || !strings.Contains(err.Error(), "FromCIDR") || !strings.Contains(err.Error(), "FromEndpoints") || !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("expected the agent's refusal wrapped in ErrInvalidPolicy, got %v", err)
	}
	bad := &CiliumNetworkPolicy{Metadata: metav1.ObjectMeta{Name: "x", Namespace: "y"}, Spec: Rule{
		EndpointSelector: Selector(map[string]string{"app": "x"}),
		Egress:           []EgressRule{{EgressCommonRule: EgressCommonRule{ToCIDR: CIDRSlice{"not-a-cidr"}}}}}}
	if err := Validate(bad); err == nil || !strings.Contains(err.Error(), "not-a-cidr") {
		t.Fatalf("expected the CIDR error, got %v", err)
	}
	good := &CiliumNetworkPolicy{Metadata: metav1.ObjectMeta{Name: "x", Namespace: "y"}, Spec: Rule{
		EndpointSelector: Selector(map[string]string{"app.kubernetes.io/name": "x"}),
		Ingress: []IngressRule{{IngressCommonRule: IngressCommonRule{FromEndpoints: []EndpointSelector{Selector(map[string]string{"app": "a"})}},
			ToPorts: PortRules{{Ports: []Port{{Port: "80", Protocol: "TCP"}}}}}}}}
	if err := Validate(good); err != nil {
		t.Fatal(err)
	}
	// the copy: the document still carries plain selector keys after validation
	if k := firstKey(MatchLabelsOf(good.Spec.EndpointSelector)); k != "app.kubernetes.io/name" {
		t.Fatalf("Validate must not touch the policy, selector key is now %q", k)
	}
}

func firstKey(m map[string]string) string {
	for k := range m {
		return k
	}
	return ""
}

// An IPv6 address gets /128, not /32 — on both sides (0.6.x wrote /32 for every address, which Cilium refuses)
func TestBuildPolicies_IPv6HostPrefixes(t *testing.T) {
	ps, err := NewGenerator("").BuildPolicies(load(t, "ingress-world6-cidr-to-receiver.json"))
	if err != nil || string(ps[0].Spec.Ingress[0].FromCIDR[0]) != "2001:db8::170/128" {
		t.Fatalf("fromCIDR: %v %s", err, mustYAML(ps[0].Spec.Ingress))
	}
	ps, err = NewGenerator("").BuildPolicies(load(t, "egress-pos-to-world6.json"))
	if err != nil || string(ps[0].Spec.Egress[0].ToCIDR[0]) != "2606:2800:21f:cb07:6820:80da:af6b:8b2c/128" {
		t.Fatalf("toCIDR: %v %s", err, mustYAML(ps[0].Spec.Egress))
	}
}
