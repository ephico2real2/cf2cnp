package policy

import (
	"strings"
	"testing"
)

// 0.7.0: the DNS resolver rule is derived from the observed DNS flows. On a Kubernetes cluster the derived rule names
// what cf2cnp always named (kube-system, k8s-app=kube-dns, 53) — the kubernetes profile — with the protocol ANY
// (review ENH-003: 0.6.x wrote UDP, which denies the TCP retry of a truncated answer).
func TestDNSResolver_DerivedKubernetes(t *testing.T) {
	ps, err := NewGenerator("").WithDNSVisibility().BuildPolicies(load(t, "egress-pos-to-kube-dns.json", "egress-pos-to-world.json"))
	if err != nil || len(ps) != 1 {
		t.Fatalf("one policy expected: %d %v", len(ps), err)
	}
	if got, want := mustYAML(ps[0].Spec.Egress[len(ps[0].Spec.Egress)-1]), mustYAML(dnsRuleFor(dnsProfiles[DNSProfileKubernetes])); got != want {
		t.Fatalf("the derived Kubernetes resolver must equal the kubernetes profile:\n%s\n%s", got, want)
	}
}

// Cilium's DNS guide: "OpenShift users will need to modify the policies to match the namespace openshift-dns (instead
// of kube-system), remove the match on the k8s:k8s-app=kube-dns label, and change the port to 5353". Derived from a
// lookup to the DNS operator's pod: that rule, on the port observed, protocol ANY.
func TestDNSResolver_DerivedOpenShift(t *testing.T) {
	ps, err := NewGenerator("").WithDNSVisibility().BuildPolicies(load(t, "egress-pos-to-openshift-dns.json", "egress-pos-to-world.json"))
	if err != nil || len(ps) != 1 {
		t.Fatalf("one policy expected: %d %v", len(ps), err)
	}
	dns := ps[0].Spec.Egress[len(ps[0].Spec.Egress)-1]
	labels := MatchLabelsOf(dns.ToEndpoints[0])
	if labels["io.kubernetes.pod.namespace"] != "openshift-dns" || labels["k8s-app"] != "" || len(labels) != 1 {
		t.Fatalf("the OpenShift resolver is the namespace alone, got %v", labels)
	}
	if p := dns.ToPorts[0].Ports[0]; p.Port != "5353" || p.Protocol != "ANY" {
		t.Fatalf("port 5353 as observed, ANY, got %s/%s", p.Protocol, p.Port)
	}
	if dns.ToPorts[0].Rules == nil || dns.ToPorts[0].Rules.DNS[0].MatchPattern != "*" {
		t.Fatalf("the L7 DNS rule must be there: %s", mustYAML(dns))
	}
	if !strings.Contains(ps[0].Spec.Description, "to endpoints in openshift-dns on ANY/5353 (DNS *)") {
		t.Fatalf("description: %q", ps[0].Spec.Description)
	}
	// the plain 5353 rule the lookup itself produced is shadowed by the L7 one, as for kube-dns (issue #1)
	count := 0
	for _, r := range ps[0].Spec.Egress {
		if len(r.ToEndpoints) == 1 && MatchLabelsOf(r.ToEndpoints[0])["io.kubernetes.pod.namespace"] == "openshift-dns" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("the resolver must appear once, got %d", count)
	}
}

// Without a DNS flow the profile decides: openshift writes the guide's rule (5353/ANY); kubernetes the historic one
func TestDNSResolver_Profiles(t *testing.T) {
	g, err := NewGenerator("").WithDNSProfile(DNSProfileOpenShift)
	if err != nil {
		t.Fatal(err)
	}
	ps, err := g.WithDNSVisibility().BuildPolicies(load(t, "egress-pos-to-world.json"))
	if err != nil {
		t.Fatal(err)
	}
	dns := ps[0].Spec.Egress[1]
	if p := dns.ToPorts[0].Ports[0]; p.Port != "5353" || p.Protocol != "ANY" || MatchLabelsOf(dns.ToEndpoints[0])["io.kubernetes.pod.namespace"] != "openshift-dns" {
		t.Fatalf("openshift profile: %s", mustYAML(dns))
	}
	if _, err := NewGenerator("").WithDNSProfile("rancher"); err == nil {
		t.Fatal("an unknown profile must be refused")
	}
	if err := Validate(ps[0]); err != nil {
		t.Fatal(err)
	}
}

// --dns-resolver names any resolver: namespace, optional labels, port, optional protocol
func TestDNSResolver_Custom(t *testing.T) {
	r, err := ParseDNSResolver("dns-system/app=coredns,tier=infra:5353/ANY")
	if err != nil || r.Namespace != "dns-system" || r.Labels["app"] != "coredns" || r.Labels["tier"] != "infra" || r.Port != "5353" || r.Protocol != "ANY" {
		t.Fatalf("parse: %+v %v", r, err)
	}
	r, err = ParseDNSResolver("kube-system:53")
	if err != nil || r.Port != "53" || r.Protocol != "ANY" || r.Labels != nil {
		t.Fatalf("defaults: %+v %v", r, err)
	}
	for _, bad := range []string{"kube-system", ":53", "ns/notalabel:53", ""} {
		if _, err := ParseDNSResolver(bad); err == nil {
			t.Fatalf("%q must be refused", bad)
		}
	}
	g, _ := NewGenerator("").WithDNSResolver("dns-system/app=coredns:5353/TCP")
	ps, err := g.WithDNSVisibility().BuildPolicies(load(t, "egress-pos-to-world.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ps[0].Spec.Description, "to coredns in dns-system on TCP/5353 (DNS *)") {
		t.Fatalf("description: %q", ps[0].Spec.Description)
	}
}
