package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"
)

// MergeDocument adds the generated policy's rules to an existing CiliumNetworkPolicy YAML document (E5) and
// returns the document with everything else as it was: key order, comments, scalar quoting, flow-style lists,
// and the 2-space indentation `generate` writes. Fields this tool does not model (ingressDeny, enableDefaultDeny,
// annotations, …) survive untouched because the document is edited as a YAML node tree, not re-built from a map.
// The first version decoded the document into a generic map and marshalled it back — every key came out in
// alphabetical order at yaml.v3's default indentation, and a pull request showed the whole file changed instead
// of one rule (demo 32). It refuses another target (namespace, name, endpointSelector) and, run twice, adds nothing
// the second time. yaml.v3 drops blank lines between keys; that is the one thing about the layout it does not keep.
func MergeDocument(existing []byte, generated *CiliumNetworkPolicy) (out []byte, added int, err error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(existing, &doc); err != nil {
		return nil, 0, fmt.Errorf("existing policy: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, 0, errors.New("existing policy: not a single YAML document with a mapping at the top")
	}
	root := doc.Content[0]
	meta, spec := mappingValue(root, "metadata"), mappingValue(root, "spec")
	if meta == nil {
		return nil, 0, errors.New("existing document has no metadata")
	}
	if spec == nil {
		if mappingValue(root, "specs") != nil { // Cilium's list form: merge writes spec.ingress / spec.egress only
			return nil, 0, errors.New("existing document uses specs (Cilium's list form), which merge does not write into: move the rule to spec, or edit the file by hand")
		}
		return nil, 0, errors.New("existing document has no spec")
	}
	if err := checkTarget(meta, spec, generated); err != nil {
		return nil, 0, err
	}
	if err := Validate(generated); err != nil {
		return nil, 0, err
	}
	for _, r := range generated.Spec.Ingress {
		if appendUnique(spec, "ingress", toGeneric(r)) {
			added++
		}
	}
	for _, r := range generated.Spec.Egress {
		if appendUnique(spec, "egress", toGeneric(r)) {
			added++
		}
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2) // the style `generate` writes, so an unchanged rule is an unchanged line
	if err := enc.Encode(&doc); err != nil {
		return nil, 0, err
	}
	if err := enc.Close(); err != nil {
		return nil, 0, err
	}
	return buf.Bytes(), added, nil
}

// checkTarget refuses a document that is not the generated policy's target: same namespace, same name, same
// endpointSelector, or nothing happens
func checkTarget(meta, spec *yaml.Node, generated *CiliumNetworkPolicy) error {
	name, namespace := scalarValue(meta, "name"), scalarValue(meta, "namespace")
	if name != generated.Metadata.Name || namespace != generated.Metadata.Namespace {
		return fmt.Errorf("target mismatch: existing %s/%s, generated %s/%s",
			namespace, name, generated.Metadata.Namespace, generated.Metadata.Name)
	}
	var selector interface{}
	if n := mappingValue(spec, "endpointSelector"); n != nil {
		_ = n.Decode(&selector)
	}
	if canonicalYAML(selector) != canonicalYAML(toGeneric(generated.Spec.EndpointSelector)) {
		return errors.New("target mismatch: the endpointSelector differs")
	}
	return nil
}

// appendUnique adds item to the list under key (created after the last key when missing) unless an equal item is
// already there. Equality is by canonical YAML, so a hand-written `port: 80` and the generated `port: "80"` are one
// rule (review finding — without this the merge appended a duplicate).
func appendUnique(spec *yaml.Node, key string, item interface{}) bool {
	list := mappingValue(spec, key)
	if list == nil {
		list = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		spec.Content = append(spec.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, list)
	}
	want := canonicalYAML(item)
	for _, n := range list.Content {
		var have interface{}
		if err := n.Decode(&have); err == nil && canonicalYAML(have) == want {
			return false
		}
	}
	var n yaml.Node
	if err := n.Encode(item); err != nil {
		return false
	}
	list.Content = append(list.Content, &n)
	return true
}

// mappingValue returns the value node of key in a mapping node, or nil
func mappingValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// scalarValue returns the scalar under key in a mapping node, or "" — the same "" a missing key or a non-scalar gives
func scalarValue(m *yaml.Node, key string) string {
	if n := mappingValue(m, key); n != nil && n.Kind == yaml.ScalarNode {
		return n.Value
	}
	return ""
}

// toGeneric round-trips a typed value through JSON (Cilium's types carry json tags) so it compares and stores
// like the existing document
func toGeneric(v interface{}) interface{} {
	var out interface{}
	b, _ := json.Marshal(v)
	_ = yaml.Unmarshal(b, &out)
	return out
}

// canonicalYAML renders a generic value for comparison with every scalar as a string: a hand-written
// `port: 80` and the generated `port: "80"` are one rule to Kubernetes and must be one rule here
func canonicalYAML(v interface{}) string {
	b, err := yaml.Marshal(stringifyScalars(v))
	if err != nil {
		return fmt.Sprintf("%#v", v)
	}
	return string(b)
}

func stringifyScalars(v interface{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(t))
		for k, val := range t {
			out[k] = stringifyScalars(val)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(t))
		for i, val := range t {
			out[i] = stringifyScalars(val)
		}
		return out
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, bool:
		return fmt.Sprint(t)
	default:
		return v
	}
}
