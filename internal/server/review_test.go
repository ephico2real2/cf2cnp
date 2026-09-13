package server

import (
	"strings"
	"testing"
)

// Review ENH-003 (Cursor, finding 5 / C13): a deployed server needs a cluster-wide default — an OpenShift Grafana
// action that omits ?dnsProfile= must not get the kubernetes resolver. Options carry the defaults `serve
// --dns-profile / --dns-resolver` set; the request's parameters still win.
func TestGenerate_ServerDNSDefaults(t *testing.T) {
	s := NewServerWithOptions(8080, "", Options{DNSProfile: "openshift"})
	rec := post(t, s, "/generate?dnsVisibility=true", fixture(t, "egress-pos-to-world.json"), nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "io.kubernetes.pod.namespace: openshift-dns") {
		t.Fatalf("server default openshift: %d %s", rec.Code, rec.Body.String())
	}
	rec = post(t, s, "/generate?dnsVisibility=true&dnsProfile=kubernetes", fixture(t, "egress-pos-to-world.json"), nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "k8s-app: kube-dns") {
		t.Fatalf("the request's profile wins over the server default: %d %s", rec.Code, rec.Body.String())
	}
	s = NewServerWithOptions(8080, "", Options{DNSResolver: "dns-system/app=coredns:5353/ANY"})
	rec = post(t, s, "/generate?dnsVisibility=true", fixture(t, "egress-pos-to-world.json"), nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "io.kubernetes.pod.namespace: dns-system") || !strings.Contains(rec.Body.String(), "protocol: ANY") {
		t.Fatalf("server default resolver: %d %s", rec.Code, rec.Body.String())
	}
	rec = post(t, s, "/generate?dnsVisibility=true&dnsResolver=openshift-dns:5353", fixture(t, "egress-pos-to-world.json"), nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "io.kubernetes.pod.namespace: openshift-dns") {
		t.Fatalf("the request's resolver wins: %d %s", rec.Code, rec.Body.String())
	}
}
