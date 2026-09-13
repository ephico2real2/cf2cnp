package policy

import (
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
	if err == nil || !strings.Contains(err.Error(), "combining FromEndpoints and FromCIDR") {
		t.Fatalf("expected the agent's refusal, got %v", err)
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
