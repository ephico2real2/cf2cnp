package policy

import "testing"

// 0.6.2: the description is written from the final spec — subject, peers, ports, L7 — not a generic sentence
func TestDescribe(t *testing.T) {
	cases := []struct {
		name string
		p    CiliumNetworkPolicy
		want string
	}{
		{"ingress with L7 and a second peer",
			CiliumNetworkPolicy{Metadata: Metadata{Name: "shop-frontend", Namespace: "cf2cnp-lab27"}, Spec: Spec{Ingress: []IngressRule{
				{FromEndpoints: []LabelSelector{{MatchLabels: map[string]string{"app.kubernetes.io/name": "pos"}}},
					ToPorts: []PortRule{{Ports: []Port{{Port: "80", Protocol: "TCP"}}, Rules: &L7Rules{HTTP: []HTTPRule{{Method: "GET", Path: `^/(\?.*)?$`}, {Method: "GET", Path: `^/checkout(\?.*)?$`}}}}}},
				{FromEndpoints: []LabelSelector{{MatchLabels: map[string]string{"app.kubernetes.io/name": "kiosk"}}}, ToPorts: []PortRule{{Ports: []Port{{Port: "80", Protocol: "TCP"}}}}},
			}}},
			"Allow ingress to shop-frontend in cf2cnp-lab27: from pos on TCP/80 (HTTP GET /, GET /checkout); from kiosk on TCP/80"},
		{"egress: another namespace, DNS rule, FQDN, CIDR",
			CiliumNetworkPolicy{Metadata: Metadata{Name: "pos", Namespace: "cf2cnp-lab"}, Spec: Spec{Egress: []EgressRule{
				{ToEndpoints: []LabelSelector{{MatchLabels: map[string]string{"app.kubernetes.io/name": "shop"}}}, ToPorts: []PortRule{{Ports: []Port{{Port: "80", Protocol: "TCP"}}}}},
				{ToEndpoints: []LabelSelector{{MatchLabels: map[string]string{"io.kubernetes.pod.namespace": "kube-system", "k8s-app": "kube-dns"}}}, ToPorts: []PortRule{{Ports: []Port{{Port: "53", Protocol: "UDP"}}, Rules: &L7Rules{DNS: []DNSRule{{MatchPattern: "*"}}}}}},
				{ToFQDNs: []FQDNSelector{{MatchName: "example.com"}}, ToPorts: []PortRule{{Ports: []Port{{Port: "443", Protocol: "TCP"}}}}},
				{ToCIDR: []string{"104.20.23.154/32"}, ToPorts: []PortRule{{Ports: []Port{{Port: "443", Protocol: "TCP"}}}}},
			}}},
			"Allow egress from pos in cf2cnp-lab: to shop on TCP/80; to kube-dns in kube-system on UDP/53 (DNS *); to example.com on TCP/443; to 104.20.23.154/32 on TCP/443"},
		{"a ClusterMesh peer with a component, and entities",
			CiliumNetworkPolicy{Metadata: Metadata{Name: "cache-server", Namespace: "mesh-lab"}, Spec: Spec{Ingress: []IngressRule{
				{FromEndpoints: []LabelSelector{{MatchLabels: map[string]string{"app.kubernetes.io/name": "worker", "app.kubernetes.io/component": "batch", ClusterLabel: "poc2"}}}, ToPorts: []PortRule{{Ports: []Port{{Port: "6379", Protocol: "TCP"}}}}},
				{FromEntities: []string{"ingress", "host"}, ToPorts: []PortRule{{Ports: []Port{{Port: "8080", Protocol: "TCP"}}}}},
			}}},
			"Allow ingress to cache-server in mesh-lab: from worker/batch in cluster poc2 on TCP/6379; from entities ingress, host on TCP/8080"},
		{"both directions, an unnamed label, no ports",
			CiliumNetworkPolicy{Metadata: Metadata{Name: "api", Namespace: "bank"}, Spec: Spec{
				Ingress: []IngressRule{{FromEndpoints: []LabelSelector{{MatchLabels: map[string]string{"tier": "web"}}}}},
				Egress:  []EgressRule{{ToEntities: []string{"world"}}}}},
			"Allow ingress to api in bank: from (tier=web); egress from api in bank: to entities world"},
		{"nothing", CiliumNetworkPolicy{Metadata: Metadata{Name: "x", Namespace: "y"}}, "Allow nothing for x in y"},
	}
	for _, c := range cases {
		if got := Describe(&c.p); got != c.want {
			t.Errorf("%s:\n got  %q\n want %q", c.name, got, c.want)
		}
	}
}

// more than six peers are cut with a count, so the description stays a sentence
func TestDescribe_CutsLongLists(t *testing.T) {
	p := CiliumNetworkPolicy{Metadata: Metadata{Name: "hub", Namespace: "ns"}}
	for i := 0; i < 9; i++ {
		p.Spec.Ingress = append(p.Spec.Ingress, IngressRule{FromEndpoints: []LabelSelector{{MatchLabels: map[string]string{"app": "c" + string(rune('0'+i))}}}})
	}
	got := Describe(&p)
	if !contains(got, "from c5") || contains(got, "from c6") || !contains(got, "; and 3 more") {
		t.Fatalf("got %q", got)
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
