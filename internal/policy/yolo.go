package policy

import (
	"fmt"

	"github.com/hubble-policy-gen/internal/render"
)

// YOLONamespacePolicy generates a CiliumNetworkPolicy that allows all traffic
// within the same namespace. This is an easter egg policy - use with caution!
func YOLONamespacePolicy(namespace string) *CiliumNetworkPolicy {
	p := NewPolicy()
	p.Metadata.Name = "yolo-allow-all-in-namespace"
	p.Metadata.Namespace = namespace
	p.Spec.Description = fmt.Sprintf("YOLO! Allow all traffic within the %s namespace.", namespace)
	p.Spec.EndpointSelector = Selector(map[string]string{})
	p.Spec.Ingress = []IngressRule{{IngressCommonRule: IngressCommonRule{FromEndpoints: []EndpointSelector{Selector(map[string]string{})}}}}
	p.Spec.Egress = []EgressRule{{EgressCommonRule: EgressCommonRule{ToEndpoints: []EndpointSelector{Selector(map[string]string{})}}}}
	return p
}

// YOLONamespacePolicyYAML generates the YOLO policy as YAML bytes
func YOLONamespacePolicyYAML(namespace string) ([]byte, error) {
	b, err := render.Document(YOLONamespacePolicy(namespace))
	if err != nil {
		return nil, fmt.Errorf("failed to encode YOLO policy to YAML: %w", err)
	}
	return b, nil
}
