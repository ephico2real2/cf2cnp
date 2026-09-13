package policy

import (
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/policy/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The policy types are Cilium's own (github.com/cilium/cilium/pkg/policy/api at the version pinned in go.mod):
// every field of the CiliumNetworkPolicy spec exists here, Cilium's Sanitize() validates a rule the way the agent
// does at admission, and the version of the spec cf2cnp supports is the version of that module (`cf2cnp version`).
// The 0.6.x hand-written structs modelled 20 of the spec's 291 schema paths (docs/CRD-SPEC-FORENSICS.md).
//
// The aliases keep the generator, the merge and the tests reading as before; only construction changes, because
// Cilium nests the peers in an embedded IngressCommonRule / EgressCommonRule.

// CiliumNetworkPolicy is the document cf2cnp writes: the Kubernetes envelope and Cilium's rule as the spec. The
// metadata field keeps its name (`Metadata`) so `p.Metadata.Name` reads as it always did; there is no status.
type CiliumNetworkPolicy struct {
	metav1.TypeMeta `json:",inline"`
	Metadata        metav1.ObjectMeta `json:"metadata"`
	Spec            api.Rule          `json:"spec"`
}

type (
	Rule              = api.Rule
	IngressRule       = api.IngressRule
	IngressCommonRule = api.IngressCommonRule
	EgressRule        = api.EgressRule
	EgressCommonRule  = api.EgressCommonRule
	PortRule          = api.PortRule
	PortRules         = api.PortRules
	Port              = api.PortProtocol
	L7Rules           = api.L7Rules
	HTTPRule          = api.PortRuleHTTP
	DNSRule           = api.PortRuleDNS
	FQDNSelector      = api.FQDNSelector
	EndpointSelector  = api.EndpointSelector
	EntitySlice       = api.EntitySlice
	CIDRSlice         = api.CIDRSlice
)

// Selector builds an EndpointSelector from matchLabels the way a user writes it — a plain LabelSelector, without
// Cilium's internal label-source prefix. The api package's NewES… constructors add that prefix (`any:`), which is
// what the agent stores, not what a policy file says (docs/CRD-SPEC-FORENSICS.md §3, probe 2).
func Selector(matchLabels map[string]string) EndpointSelector {
	return EndpointSelector{LabelSelector: &slimv1.LabelSelector{MatchLabels: matchLabels}}
}

// MatchLabelsOf returns a selector's matchLabels, or nil for a selector without a LabelSelector
func MatchLabelsOf(es EndpointSelector) map[string]string {
	if es.LabelSelector == nil {
		return nil
	}
	return es.MatchLabels
}

// NewPolicy is the envelope every generated policy starts from
func NewPolicy() *CiliumNetworkPolicy {
	return &CiliumNetworkPolicy{TypeMeta: metav1.TypeMeta{APIVersion: "cilium.io/v2", Kind: "CiliumNetworkPolicy"}}
}
