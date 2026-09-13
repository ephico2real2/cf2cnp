package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/hubble-policy-gen/internal/aggregator"
	"github.com/hubble-policy-gen/internal/flow"
)

// The DNS resolver rule — the egress rule that lets the selected endpoints ask the cluster's DNS and puts their
// lookups through Cilium's DNS proxy, which every toFQDNs rule needs and --dns-visibility asks for — used to be one
// hard-coded shape: kube-system, k8s-app=kube-dns, 53/UDP. That is a kind or kubeadm cluster (and UDP alone). OpenShift's DNS
// operator runs CoreDNS in openshift-dns, listening on 5353, without that label, and Cilium's own guide says so:
// "OpenShift users will need to modify the policies to match the namespace openshift-dns (instead of kube-system),
// remove the match on the k8s:k8s-app=kube-dns label, and change the port to 5353". A policy with the wrong resolver
// rule cuts the pod off from DNS the moment it is enforced.
//
// Since 0.7.0 the resolver is DERIVED from the observed DNS flows when the input has them (the pods the workload
// actually asked, on the port and protocol it used), and taken from a profile when it does not.

// DNSResolver is where the cluster's DNS answers, as a policy names it
type DNSResolver struct {
	Namespace string            // the resolver pods' namespace
	Labels    map[string]string // identifying labels of the resolver pods, if any (OpenShift: none)
	Port      string            // "53" on Kubernetes, "5353" on OpenShift
	Protocol  string            // UDP, TCP or ANY
}

// DNS profiles: what to write when the flows do not show the resolver
const (
	DNSProfileAuto       = "auto"       // from the flows, else kubernetes
	DNSProfileKubernetes = "kubernetes" // kube-system, k8s-app=kube-dns, 53/ANY — Cilium's DNS guide (dns-matchname.yaml)
	DNSProfileOpenShift  = "openshift"  // openshift-dns, no label, 5353/ANY — Cilium's DNS guide for OpenShift
)

// The profiles write ANY, as Cilium's examples do: a lookup whose UDP answer is truncated retries over TCP, and a
// rule with UDP alone denies that retry under default-deny egress. (0.6.x wrote 53/UDP; so does a derived resolver.)
var dnsProfiles = map[string]DNSResolver{
	DNSProfileKubernetes: {Namespace: "kube-system", Labels: map[string]string{"k8s-app": "kube-dns"}, Port: "53", Protocol: "ANY"},
	DNSProfileOpenShift:  {Namespace: "openshift-dns", Port: "5353", Protocol: "ANY"},
}

// WithDNSProfile chooses the resolver profile: auto (default), kubernetes or openshift
func (g *Generator) WithDNSProfile(name string) (*Generator, error) {
	switch name {
	case "", DNSProfileAuto, DNSProfileKubernetes, DNSProfileOpenShift:
		g.dnsProfile = name
		if name == "" {
			g.dnsProfile = DNSProfileAuto
		}
		return g, nil
	}
	return g, fmt.Errorf("unknown DNS profile %q (auto, kubernetes, openshift; or --dns-resolver)", name)
}

// WithDNSResolver names the resolver explicitly: "<namespace>[/<label>=<value>[,<label>=<value>]]:<port>[/<protocol>]",
// e.g. "kube-system/k8s-app=kube-dns:53/UDP" or "openshift-dns:5353" (no protocol: ANY)
func (g *Generator) WithDNSResolver(spec string) (*Generator, error) {
	r, err := ParseDNSResolver(spec)
	if err != nil {
		return g, err
	}
	g.dnsResolver = &r
	return g, nil
}

// ParseDNSResolver parses the --dns-resolver form
func ParseDNSResolver(spec string) (DNSResolver, error) {
	var r DNSResolver
	i := strings.LastIndex(spec, ":")
	if i <= 0 || i == len(spec)-1 {
		return r, fmt.Errorf("dns resolver %q: want <namespace>[/<label>=<value>]:<port>[/<protocol>]", spec)
	}
	where, portProto := spec[:i], spec[i+1:]
	r.Port, r.Protocol = portProto, "ANY" // no protocol named: both, as Cilium's examples write it
	if j := strings.Index(portProto, "/"); j > 0 {
		r.Port, r.Protocol = portProto[:j], strings.ToUpper(portProto[j+1:])
	}
	r.Namespace = where
	if j := strings.Index(where, "/"); j > 0 {
		r.Namespace = where[:j]
		r.Labels = map[string]string{}
		for _, kv := range strings.Split(where[j+1:], ",") {
			k, v, ok := strings.Cut(kv, "=")
			if !ok || k == "" {
				return r, fmt.Errorf("dns resolver %q: label %q is not key=value", spec, kv)
			}
			r.Labels[k] = v
		}
	}
	if r.Namespace == "" {
		return r, fmt.Errorf("dns resolver %q: the namespace is empty", spec)
	}
	return r, nil
}

// resolveDNS decides the resolver for this run: an explicit --dns-resolver, an explicit profile, or (auto) what the
// flows show — falling back to the kubernetes profile when no DNS flow is among them
func (g *Generator) resolveDNS(flows []*aggregator.AggregatedFlow) DNSResolver {
	if g.dnsResolver != nil {
		return *g.dnsResolver
	}
	if g.dnsProfile != "" && g.dnsProfile != DNSProfileAuto {
		return dnsProfiles[g.dnsProfile]
	}
	if r, ok := DeriveDNSResolver(flows); ok {
		return r
	}
	return dnsProfiles[DNSProfileKubernetes]
}

// DeriveDNSResolver finds the resolver in the observed flows: an EGRESS flow to a resolver pod (looksLikeDNS) on a
// DNS port (53 or 5353). The rule then names that namespace, the identifying label the pods carry (k8s-app=kube-dns
// on kubeadm and the managed clusters, app.kubernetes.io/name=coredns from the CoreDNS Helm chart; none on OpenShift,
// whose pods carry the operator's labels the naming does not use), the port as
// observed — and the protocol ANY, whatever was observed: the rule exists to put the lookups through the proxy, not
// to restrict a protocol, and a lookup whose UDP answer is truncated retries over TCP, which a UDP-only rule denies
// under default-deny egress (review ENH-003; Cilium's examples write ANY; 0.6.x wrote the observed UDP).
func DeriveDNSResolver(flows []*aggregator.AggregatedFlow) (DNSResolver, bool) {
	var found *DNSResolver
	for _, f := range flows {
		if f.Direction != "EGRESS" || f.IsReply || f.IsWorldTraffic || f.IsDestEntityTraffic {
			continue
		}
		for _, p := range f.Ports {
			if p.Port != 53 && p.Port != 5353 {
				continue
			}
			if !looksLikeDNS(f.DestNamespace, f.DestLabels) {
				continue
			}
			if found == nil {
				found = &DNSResolver{Namespace: f.DestNamespace, Port: fmt.Sprint(p.Port), Protocol: "ANY", Labels: resolverIDLabels(f.DestLabels)}
			}
		}
	}
	if found == nil {
		return DNSResolver{}, false
	}
	return *found, true
}

// resolverLabelKeys are the identifying labels a resolver pod may carry, in the order the parser prefers them:
// kubeadm, kind and the managed clusters label CoreDNS k8s-app=kube-dns; the official CoreDNS Helm chart labels
// app.kubernetes.io/name=coredns (and k8s-app=coredns only as a cluster service) — and extractLabels keeps the
// app.kubernetes.io/* labels and drops k8s-app when they are present (review ENH-003, second pass).
var resolverLabelKeys = []string{"k8s-app", "app.kubernetes.io/name", "app"}

// resolverIDLabels returns the one label that identifies a resolver pod among the labels the parser kept, or nil
func resolverIDLabels(labels map[string]string) map[string]string {
	for _, key := range resolverLabelKeys {
		switch labels[key] {
		case "kube-dns", "coredns", "node-local-dns":
			return map[string]string{key: labels[key]}
		}
	}
	return nil
}

// looksLikeDNS says whether a peer on a DNS port is the resolver: CoreDNS / kube-dns by its label, NodeLocal DNSCache
// by its label (under a Local Redirect Policy the lookups reach that pod, so the rule must name it — a rule naming
// kube-dns would cut the pod off), or OpenShift's DNS operator by its namespace (its pods carry no k8s-app label,
// Cilium's DNS guide). Anything else in kube-system on 53 is not the resolver (review ENH-003).
func looksLikeDNS(namespace string, labels map[string]string) bool {
	return resolverIDLabels(labels) != nil || namespace == "openshift-dns"
}

// dnsRule is the egress rule for the resolver in use: the pods it names on their port, with the L7 DNS rule that
// puts every lookup through the proxy (matchPattern "*": visibility, not restriction)
func (g *Generator) dnsRule() EgressRule {
	return dnsRuleFor(g.resolver)
}

func dnsRuleFor(r DNSResolver) EgressRule {
	labels := map[string]string{flow.GetNamespaceLabel(): r.Namespace}
	keys := make([]string, 0, len(r.Labels))
	for k := range r.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		labels[k] = r.Labels[k]
	}
	return EgressRule{
		EgressCommonRule: EgressCommonRule{ToEndpoints: []EndpointSelector{Selector(labels)}},
		ToPorts: PortRules{{
			Ports: []Port{{Port: r.Port, Protocol: api.L4Proto(r.Protocol)}},
			Rules: &L7Rules{DNS: []DNSRule{{MatchPattern: "*"}}},
		}},
	}
}
