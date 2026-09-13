package policy

// CiliumNetworkPolicy represents a Cilium Network Policy
type CiliumNetworkPolicy struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Spec       Spec     `yaml:"spec"`
}

// Metadata contains policy metadata
type Metadata struct {
	Name      string            `yaml:"name"`
	Namespace string            `yaml:"namespace"`
	Labels    map[string]string `yaml:"labels,omitempty"`
}

// Spec contains the policy specification
type Spec struct {
	Description      string        `yaml:"description,omitempty"`
	EndpointSelector LabelSelector `yaml:"endpointSelector"`
	Ingress          []IngressRule `yaml:"ingress,omitempty"`
	Egress           []EgressRule  `yaml:"egress,omitempty"`
}

// LabelSelector for selecting endpoints
type LabelSelector struct {
	MatchLabels map[string]string `yaml:"matchLabels,omitempty"`
}

// IngressRule represents an ingress rule
type IngressRule struct {
	FromEndpoints []LabelSelector `yaml:"fromEndpoints,omitempty"`
	FromEntities  []string        `yaml:"fromEntities,omitempty"`
	ToPorts       []PortRule      `yaml:"toPorts,omitempty"`
}

// EgressRule represents an egress rule
type EgressRule struct {
	ToEndpoints []LabelSelector `yaml:"toEndpoints,omitempty"`
	ToEntities  []string        `yaml:"toEntities,omitempty"`
	ToCIDR      []string        `yaml:"toCIDR,omitempty"`
	ToFQDNs     []FQDNSelector  `yaml:"toFQDNs,omitempty"`
	ToPorts     []PortRule      `yaml:"toPorts,omitempty"`
}

// FQDNSelector for selecting FQDNs
type FQDNSelector struct {
	MatchName    string `yaml:"matchName,omitempty"`
	MatchPattern string `yaml:"matchPattern,omitempty"`
}

// PortRule represents port rules
type PortRule struct {
	Ports []Port   `yaml:"ports,omitempty"`
	Rules *L7Rules `yaml:"rules,omitempty"`
}

// L7Rules is the `rules:` block of a port rule: HTTP request rules and/or DNS rules (E2)
type L7Rules struct {
	HTTP []HTTPRule `yaml:"http,omitempty"`
	DNS  []DNSRule  `yaml:"dns,omitempty"`
}

// HTTPRule: method and path are extended POSIX regexes (cilium pkg/policy/api/http.go)
type HTTPRule struct {
	Method string `yaml:"method,omitempty"`
	Path   string `yaml:"path,omitempty"`
}

// Port represents a single port
type Port struct {
	Port     string `yaml:"port"`
	Protocol string `yaml:"protocol"`
}

// DNSRule represents a DNS rule
type DNSRule struct {
	MatchPattern string `yaml:"matchPattern,omitempty"`
	MatchName    string `yaml:"matchName,omitempty"`
}
