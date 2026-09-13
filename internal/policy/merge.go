package policy

import (
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"
)

// MergeInto adds the generated policy's rules to an existing CiliumNetworkPolicy document without
// touching anything else in it (E5). The document is handled as a generic map, so fields this tool
// does not model (ingressDeny, enableDefaultDeny, annotations, …) survive untouched. It refuses to
// merge into a different target: same namespace, same name, same endpointSelector, or nothing happens.
// Running it twice adds nothing the second time.
func MergeInto(existing map[string]interface{}, generated *CiliumNetworkPolicy) (added int, err error) {
	meta, _ := existing["metadata"].(map[string]interface{})
	spec, _ := existing["spec"].(map[string]interface{})
	if meta == nil || spec == nil {
		return 0, errors.New("existing document has no metadata/spec")
	}
	if fmt.Sprint(meta["name"]) != generated.Metadata.Name || fmt.Sprint(meta["namespace"]) != generated.Metadata.Namespace {
		return 0, fmt.Errorf("target mismatch: existing %v/%v, generated %s/%s",
			meta["namespace"], meta["name"], generated.Metadata.Namespace, generated.Metadata.Name)
	}
	if canonicalYAML(spec["endpointSelector"]) != canonicalYAML(toGeneric(generated.Spec.EndpointSelector)) {
		return 0, errors.New("target mismatch: the endpointSelector differs")
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
	return added, nil
}

// toGeneric round-trips a typed value through YAML so it compares and stores like the existing document
func toGeneric(v interface{}) interface{} {
	var out interface{}
	b, _ := yaml.Marshal(v)
	_ = yaml.Unmarshal(b, &out)
	return out
}

// appendUnique adds item to spec[key] (a list) unless an equal item is already there
func appendUnique(spec map[string]interface{}, key string, item interface{}) bool {
	list, _ := spec[key].([]interface{})
	want := canonicalYAML(item)
	for _, have := range list {
		if canonicalYAML(have) == want {
			return false
		}
	}
	spec[key] = append(list, item)
	return true
}

// canonicalYAML renders a generic value for comparison with every scalar as a string: a hand-written
// `port: 80` and the generated `port: "80"` are one rule to Kubernetes and must be one rule here (review
// finding — without this the merge appended a duplicate)
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
