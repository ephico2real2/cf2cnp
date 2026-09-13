package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
	sigsyaml "sigs.k8s.io/yaml"
)

// DecodePolicyDocuments reads every YAML document of a file as a CiliumNetworkPolicy, in order, skipping empty
// documents (a bare `---`, a comment). The YAML decoder finds the document boundaries; splitting the text on "---"
// would cut a literal block that holds such a line (review ENH-003). Documents are counted from 1 in errors.
func DecodePolicyDocuments(b []byte) ([]*CiliumNetworkPolicy, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var out []*CiliumNetworkPolicy
	for i := 1; ; i++ {
		var node yaml.Node
		if err := dec.Decode(&node); err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return out, fmt.Errorf("document %d: %w", i, err)
		}
		if node.Kind == 0 || (node.Kind == yaml.DocumentNode && (len(node.Content) == 0 || node.Content[0].Tag == "!!null")) {
			continue
		}
		raw, err := yaml.Marshal(&node)
		if err != nil {
			return out, fmt.Errorf("document %d: %w", i, err)
		}
		var p CiliumNetworkPolicy
		if err := sigsyaml.Unmarshal(raw, &p); err != nil {
			return out, fmt.Errorf("document %d: %w", i, err)
		}
		out = append(out, &p)
	}
}
