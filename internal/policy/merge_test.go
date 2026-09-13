package policy

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const existingShop = `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: shop
  namespace: cf2cnp-lab
  annotations:
    owner: platform-team
spec:
  description: hand-written, with a deny rule cf2cnp does not model
  endpointSelector:
    matchLabels:
      app.kubernetes.io/name: shop
  ingress:
    - fromEndpoints:
        - matchLabels:
            app.kubernetes.io/name: pos
      toPorts:
        - ports:
            - port: "80"
              protocol: TCP
  ingressDeny:
    - fromEntities: [world]
`

func existingDoc(t *testing.T) map[string]interface{} {
	t.Helper()
	var doc map[string]interface{}
	if err := yaml.Unmarshal([]byte(existingShop), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// E5: the stranger rule is added, pos (already there) is not duplicated, ingressDeny and the annotation survive
func TestMergeInto_AddsOnlyWhatIsMissing(t *testing.T) {
	doc := existingDoc(t)
	ps, _ := NewGenerator("").BuildPolicies(load(t, "ingress-pos-to-shop.json", "ingress-stranger-to-shop.json"))
	added, err := MergeInto(doc, ps[0])
	if err != nil || added != 1 {
		t.Fatalf("added=%d err=%v", added, err)
	}
	out, _ := yaml.Marshal(doc)
	s := string(out)
	for _, want := range []string{"ingressDeny", "owner: platform-team", "app.kubernetes.io/name: stranger", "hand-written"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in:\n%s", want, s)
		}
	}
	if strings.Count(s, "app.kubernetes.io/name: pos") != 1 {
		t.Fatalf("pos must appear once:\n%s", s)
	}
	// idempotent: a second merge adds nothing and changes nothing
	again, err := MergeInto(doc, ps[0])
	out2, _ := yaml.Marshal(doc)
	if err != nil || again != 0 || string(out2) != s {
		t.Fatalf("second merge: added=%d err=%v same=%v", again, err, string(out2) == s)
	}
}

// E5: a different target is refused
func TestMergeInto_RefusesAnotherTarget(t *testing.T) {
	doc := existingDoc(t)
	ps, _ := NewGenerator("").BuildPolicies(load(t, "egress-pos-to-world.json")) // policy "pos", not "shop"
	if _, err := MergeInto(doc, ps[0]); err == nil || !strings.Contains(err.Error(), "target mismatch") {
		t.Fatalf("expected a target mismatch, got %v", err)
	}
	doc2 := existingDoc(t)
	doc2["spec"].(map[string]interface{})["endpointSelector"] = map[string]interface{}{"matchLabels": map[string]interface{}{"app.kubernetes.io/name": "shop", "app.kubernetes.io/component": "frontend"}}
	ps2, _ := NewGenerator("").BuildPolicies(load(t, "ingress-pos-to-shop.json"))
	if _, err := MergeInto(doc2, ps2[0]); err == nil || !strings.Contains(err.Error(), "endpointSelector") {
		t.Fatalf("expected an endpointSelector mismatch, got %v", err)
	}
}

// Review finding: a hand-written `port: 80` (a YAML int) and the generated `port: "80"` are the same rule
func TestMergeInto_PortIntEqualsPortString(t *testing.T) {
	var doc map[string]interface{}
	if err := yaml.Unmarshal([]byte(`apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: {name: shop, namespace: cf2cnp-lab}
spec:
  endpointSelector: {matchLabels: {app.kubernetes.io/name: shop}}
  ingress:
    - fromEndpoints: [{matchLabels: {app.kubernetes.io/name: pos}}]
      toPorts: [{ports: [{port: 80, protocol: TCP}]}]
`), &doc); err != nil {
		t.Fatal(err)
	}
	ps, _ := NewGenerator("").BuildPolicies(load(t, "ingress-pos-to-shop.json"))
	added, err := MergeInto(doc, ps[0])
	if err != nil || added != 0 {
		t.Fatalf("port: 80 and port: \"80\" are one rule; added=%d err=%v", added, err)
	}
}
