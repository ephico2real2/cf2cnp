package policy

import (
	"strings"
	"testing"
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

// E5: the stranger rule is added, pos (already there) is not duplicated, ingressDeny and the annotation survive
func TestMergeDocument_AddsOnlyWhatIsMissing(t *testing.T) {
	ps, _ := NewGenerator("").BuildPolicies(load(t, "ingress-pos-to-shop.json", "ingress-stranger-to-shop.json"))
	out, added, err := MergeDocument([]byte(existingShop), ps[0])
	if err != nil || added != 1 {
		t.Fatalf("added=%d err=%v", added, err)
	}
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
	out2, again, err := MergeDocument(out, ps[0])
	if err != nil || again != 0 || string(out2) != s {
		t.Fatalf("second merge: added=%d err=%v same=%v", again, err, string(out2) == s)
	}
}

// Demo 32 finding: the merged file must be the existing file plus the new rule — not a re-serialisation. The
// first version re-ordered every key and re-indented the document, so a pull request showed the whole file
// changed. Here the existing document is in the style `generate` writes; the output must START with it verbatim.
func TestMergeDocument_KeepsTheDocumentAsItWas(t *testing.T) {
	ps, _ := NewGenerator("").BuildPolicies(load(t, "ingress-pos-to-shop.json", "ingress-stranger-to-shop.json"))
	existing := strings.TrimSuffix(existingShop, "  ingressDeny:\n    - fromEntities: [world]\n") // the list to grow is last
	out, added, err := MergeDocument([]byte(existing), ps[0])
	if err != nil || added != 1 {
		t.Fatalf("added=%d err=%v", added, err)
	}
	if !strings.HasPrefix(string(out), existing) {
		t.Fatalf("the existing document must be kept byte for byte; got:\n%s", out)
	}
	tail := strings.TrimPrefix(string(out), existing)
	if !strings.HasPrefix(tail, "    - fromEndpoints:\n        - matchLabels:\n            app.kubernetes.io/name: stranger\n") {
		t.Fatalf("the appended rule must be at the same indentation as the existing one; got:\n%s", tail)
	}
}

// Demo 32 finding, the hand-written case: key order, a comment and a flow-style list survive the merge
func TestMergeDocument_KeepsOrderCommentsAndStyle(t *testing.T) {
	existing := `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  labels: {team: shop}          # labels first, on purpose
  name: shop
  namespace: cf2cnp-lab
spec:
  endpointSelector: {matchLabels: {app.kubernetes.io/name: shop}}
  ingress:
    - fromEndpoints: [{matchLabels: {app.kubernetes.io/name: pos}}]   # pos: the till
      toPorts: [{ports: [{port: "80", protocol: TCP}]}]
`
	ps, _ := NewGenerator("").BuildPolicies(load(t, "ingress-pos-to-shop.json", "ingress-stranger-to-shop.json"))
	out, added, err := MergeDocument([]byte(existing), ps[0])
	if err != nil || added != 1 {
		t.Fatalf("added=%d err=%v", added, err)
	}
	s := string(out)
	for _, want := range []string{"# labels first, on purpose", "# pos: the till", "labels: {team: shop}", "fromEndpoints: [{matchLabels: {app.kubernetes.io/name: pos}}]"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in:\n%s", want, s)
		}
	}
	if strings.Index(s, "labels:") > strings.Index(s, "name: shop") {
		t.Fatalf("key order must be kept (labels before name):\n%s", s)
	}
}

// E5: a different target is refused
func TestMergeDocument_RefusesAnotherTarget(t *testing.T) {
	ps, _ := NewGenerator("").BuildPolicies(load(t, "egress-pos-to-world.json")) // policy "pos", not "shop"
	if _, _, err := MergeDocument([]byte(existingShop), ps[0]); err == nil || !strings.Contains(err.Error(), "target mismatch") {
		t.Fatalf("expected a target mismatch, got %v", err)
	}
	other := strings.Replace(existingShop, "      app.kubernetes.io/name: shop\n", "      app.kubernetes.io/name: shop\n      app.kubernetes.io/component: frontend\n", 1)
	ps2, _ := NewGenerator("").BuildPolicies(load(t, "ingress-pos-to-shop.json"))
	if _, _, err := MergeDocument([]byte(other), ps2[0]); err == nil || !strings.Contains(err.Error(), "endpointSelector") {
		t.Fatalf("expected an endpointSelector mismatch, got %v", err)
	}
	if _, _, err := MergeDocument([]byte("- not: a mapping\n"), ps2[0]); err == nil {
		t.Fatal("a document that is not a mapping must be refused")
	}
}

// Review finding: a hand-written `port: 80` (a YAML int) and the generated `port: "80"` are the same rule
func TestMergeDocument_PortIntEqualsPortString(t *testing.T) {
	existing := `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: {name: shop, namespace: cf2cnp-lab}
spec:
  endpointSelector: {matchLabels: {app.kubernetes.io/name: shop}}
  ingress:
    - fromEndpoints: [{matchLabels: {app.kubernetes.io/name: pos}}]
      toPorts: [{ports: [{port: 80, protocol: TCP}]}]
`
	ps, _ := NewGenerator("").BuildPolicies(load(t, "ingress-pos-to-shop.json"))
	if _, added, err := MergeDocument([]byte(existing), ps[0]); err != nil || added != 0 {
		t.Fatalf("port: 80 and port: \"80\" are one rule; added=%d err=%v", added, err)
	}
}

// A document without the list yet (an ingress-only policy receiving egress rules) gets the list created
func TestMergeDocument_CreatesTheMissingList(t *testing.T) {
	existing := `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: {name: pos, namespace: cf2cnp-lab}
spec:
  endpointSelector: {matchLabels: {app.kubernetes.io/name: pos}}
  ingress: []
`
	ps, _ := NewGenerator("").BuildPolicies(load(t, "egress-pos-to-world.json"))
	out, added, err := MergeDocument([]byte(existing), ps[0])
	if err != nil || added == 0 || !strings.Contains(string(out), "\n  egress:\n    - toCIDR:") {
		t.Fatalf("egress must be created after ingress; added=%d err=%v out:\n%s", added, err, out)
	}
}
