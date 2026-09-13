// Package render turns a policy document into the YAML cf2cnp has always written: the fields in the order a
// reader expects (apiVersion, kind, metadata, spec; a rule's peers before its ports), two-space indentation, no
// status. The types come from Cilium (json tags, marshalled through sigs.k8s.io/yaml), whose output is alphabetical
// — `egress` before `endpointSelector`, `labels` before `name`; tools that write Kubernetes YAML for humans own a
// canonical order instead (kustomize's kyaml formatter does the same with a precedence list), so cf2cnp does too:
// known fields by precedence, unknown fields lexicographically, so every field of the CRD has a place.
package render

import (
	"bytes"
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"
	sigsyaml "sigs.k8s.io/yaml"
)

// order lists, per mapping, the keys that come first and in which order. A mapping is named by its key in the parent
// ("" is the document); a key not listed sorts after the listed ones, lexicographically. Sequences pass the parent's
// name through, so every ingress rule is ordered as "ingress".
var order = map[string][]string{
	"":                  {"apiVersion", "kind", "metadata", "spec", "specs"},
	"metadata":          {"name", "namespace", "labels", "annotations"},
	"spec":              {"description", "endpointSelector", "nodeSelector", "enableDefaultDeny", "ingress", "ingressDeny", "egress", "egressDeny", "labels", "log"},
	"endpointSelector":  {"matchLabels", "matchExpressions"},
	"nodeSelector":      {"matchLabels", "matchExpressions"},
	"ingress":           {"fromEndpoints", "fromEntities", "fromCIDR", "fromCIDRSet", "fromNodes", "fromGroups", "fromRequires", "toPorts", "icmps", "authentication"},
	"ingressDeny":       {"fromEndpoints", "fromEntities", "fromCIDR", "fromCIDRSet", "fromNodes", "fromGroups", "fromRequires", "toPorts", "icmps"},
	"egress":            {"toEndpoints", "toEntities", "toCIDR", "toCIDRSet", "toFQDNs", "toServices", "toNodes", "toGroups", "toRequires", "toPorts", "icmps", "authentication"},
	"egressDeny":        {"toEndpoints", "toEntities", "toCIDR", "toCIDRSet", "toServices", "toNodes", "toGroups", "toRequires", "toPorts", "icmps"},
	"fromEndpoints":     {"matchLabels", "matchExpressions"},
	"toEndpoints":       {"matchLabels", "matchExpressions"},
	"fromNodes":         {"matchLabels", "matchExpressions"},
	"toNodes":           {"matchLabels", "matchExpressions"},
	"fromCIDRSet":       {"cidr", "except", "cidrGroupRef", "cidrGroupSelector"},
	"toCIDRSet":         {"cidr", "except", "cidrGroupRef", "cidrGroupSelector"},
	"toFQDNs":           {"matchName", "matchPattern"},
	"toServices":        {"k8sService", "k8sServiceSelector"},
	"toPorts":           {"ports", "rules", "serverNames", "terminatingTLS", "originatingTLS", "listener"},
	"ports":             {"port", "endPort", "protocol"},
	"rules":             {"http", "dns", "kafka", "l7proto", "l7"},
	"http":              {"method", "path", "host", "headers", "headerMatches"},
	"dns":               {"matchName", "matchPattern"},
	"kafka":             {"role", "apiKey", "apiVersion", "clientID", "topic"},
	"icmps":             {"fields"},
	"fields":            {"type", "family"},
	"enableDefaultDeny": {"ingress", "egress"},
}

// Document renders one policy as YAML in cf2cnp's field order, two-space indentation, no trailing document marker.
func Document(v interface{}) ([]byte, error) {
	j, err := sigsyaml.Marshal(v) // json tags → YAML (alphabetical keys, Kubernetes quoting rules)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(j, &doc); err != nil {
		return nil, fmt.Errorf("reparse: %w", err)
	}
	if doc.Kind == yaml.DocumentNode && len(doc.Content) == 1 {
		reorder(doc.Content[0], "")
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// reorder sorts a mapping's keys by the precedence for its name, then lexicographically, and recurses
func reorder(n *yaml.Node, name string) {
	switch n.Kind {
	case yaml.MappingNode:
		type kv struct{ k, v *yaml.Node }
		pairs := make([]kv, 0, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			pairs = append(pairs, kv{n.Content[i], n.Content[i+1]})
		}
		rank := map[string]int{}
		for i, k := range order[name] {
			rank[k] = i
		}
		sort.SliceStable(pairs, func(a, b int) bool {
			ra, oka := rank[pairs[a].k.Value]
			rb, okb := rank[pairs[b].k.Value]
			switch {
			case oka && okb:
				return ra < rb
			case oka:
				return true
			case okb:
				return false
			}
			return pairs[a].k.Value < pairs[b].k.Value
		})
		n.Content = n.Content[:0]
		for _, p := range pairs {
			n.Content = append(n.Content, p.k, p.v)
			reorder(p.v, p.k.Value)
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			reorder(c, name)
		}
	}
}

// Known reports whether a key has a place in the precedence table for its mapping (used by the test that every
// CRD field is either ranked or knowingly left to the lexicographic tail)
func Known(mapping, key string) bool {
	for _, k := range order[mapping] {
		if k == key {
			return true
		}
	}
	return false
}
