package main

import (
	_ "embed"
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/cilium/cilium/pkg/policy/api"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

//go:embed crd/ciliumnetworkpolicies.yaml
var cnpCRD string

// the envelope cf2cnp would render: no Status, ObjectMeta from apimachinery (already a dependency of policy/api)
type Policy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              *api.Rule `json:"spec"`
}

func selector(labels map[string]string) api.EndpointSelector {
	return api.EndpointSelector{LabelSelector: &slimv1.LabelSelector{MatchLabels: labels}}
}

func main() {
	rule := &api.Rule{
		EndpointSelector: selector(map[string]string{"app.kubernetes.io/name": "receiver"}),
		Ingress: []api.IngressRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromEndpoints: []api.EndpointSelector{selector(map[string]string{"app.kubernetes.io/name": "ns1-caller", "io.kubernetes.pod.namespace": "ns1", "io.cilium.k8s.policy.cluster": "poc2"})},
				FromCIDR:      api.CIDRSlice{"172.18.255.170/32"},
			},
			ToPorts: api.PortRules{{Ports: []api.PortProtocol{{Port: "80", Protocol: "tcp"}}}},
		}},
		Description: "probe 3",
	}
	// validate a COPY with Cilium's own checks; render the original
	check := rule.DeepCopy()
	fmt.Println("sanitize (copy):", check.Sanitize(), "| protocol fixed on the copy:", check.Ingress[0].ToPorts[0].Ports[0].Protocol, "| selector key on the copy:", firstKey(check.EndpointSelector))
	p := Policy{TypeMeta: metav1.TypeMeta{APIVersion: "cilium.io/v2", Kind: "CiliumNetworkPolicy"},
		ObjectMeta: metav1.ObjectMeta{Name: "receiver", Namespace: "ns-recv", Labels: map[string]string{"app.kubernetes.io/managed-by": "cf2cnp"}}, Spec: rule}
	b, _ := yaml.Marshal(p)
	os.Stdout.Write(b)
	fmt.Println("embedded CRD bytes:", len(cnpCRD), "| names the v2 version:", strings.Contains(cnpCRD, "name: v2"))
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/cilium/cilium" {
				fmt.Println("supported spec: cilium.io/v2 CiliumNetworkPolicy as of cilium", d.Version)
			}
		}
	}
}

func firstKey(es api.EndpointSelector) string {
	for k := range es.LabelSelector.MatchLabels {
		return k
	}
	return ""
}
