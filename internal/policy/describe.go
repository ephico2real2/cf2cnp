package policy

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/hubble-policy-gen/internal/flow"
)

// Describe writes the policy's description from its own spec, so that it says what the rules say — who the
// subject is, which peers it may talk to, on which ports, with which L7 rules — instead of a generic sentence
// about namespaces. It runs once the rules are final (after the merge across flows), on every policy:
//
//	Allow ingress to shop/frontend in cf2cnp-lab27: from pos on TCP/80 (HTTP GET /, GET /checkout); from kiosk on TCP/80
//	Allow egress from pos in cf2cnp-lab: to shop on TCP/80; to kube-dns in kube-system on UDP/53 (DNS *); to example.com on TCP/443
//	Allow ingress to cache/server in mesh-lab: from worker/batch in cluster poc2 on TCP/6379
//
// Peers are named the way the selector names them (name, then component and instance), a peer in another namespace
// or cluster says so, entities and CIDRs are listed as written. A long policy is cut after maxDescribedRules peers
// with "and N more", so the description stays a sentence, not a second copy of the spec.
func Describe(p *CiliumNetworkPolicy) string {
	// the subject is named the way the peers are (name/component/instance from the selector), so the sentence reads
	// "shop/frontend … from shop/backend"; a policy without a selector falls back to its object name
	subject := describeSelector(MatchLabelsOf(p.Spec.EndpointSelector))
	if len(MatchLabelsOf(p.Spec.EndpointSelector)) == 0 {
		subject = p.Metadata.Name
	}
	subject += " in " + p.Metadata.Namespace
	var parts []string
	if n := len(p.Spec.Ingress); n > 0 {
		items := make([]string, 0, n)
		for _, r := range p.Spec.Ingress {
			items = append(items, "from "+peerList(r.FromEndpoints, r.FromEntities, r.FromCIDR, nil)+portList(r.ToPorts))
		}
		parts = append(parts, "ingress to "+subject+": "+joinRules(items))
	}
	if n := len(p.Spec.Egress); n > 0 {
		items := make([]string, 0, n)
		for _, r := range p.Spec.Egress {
			items = append(items, "to "+peerList(r.ToEndpoints, r.ToEntities, r.ToCIDR, r.ToFQDNs)+portList(r.ToPorts))
		}
		parts = append(parts, "egress from "+subject+": "+joinRules(items))
	}
	if len(parts) == 0 {
		return "Allow nothing for " + subject
	}
	return "Allow " + strings.Join(parts, "; ")
}

const maxDescribedRules = 6

func joinRules(items []string) string {
	if len(items) > maxDescribedRules {
		return strings.Join(items[:maxDescribedRules], "; ") + fmt.Sprintf("; and %d more", len(items)-maxDescribedRules)
	}
	return strings.Join(items, "; ")
}

// peerList names every peer of one rule: endpoints by their selector, entities, CIDRs and FQDNs as written
func peerList(endpoints []EndpointSelector, entities EntitySlice, cidrs CIDRSlice, fqdns []FQDNSelector) string {
	var peers []string
	for _, e := range endpoints {
		peers = append(peers, describeSelector(MatchLabelsOf(e)))
	}
	if len(entities) > 0 {
		names := make([]string, len(entities))
		for i, e := range entities {
			names[i] = string(e)
		}
		peers = append(peers, "entities "+strings.Join(names, ", "))
	}
	for _, c := range cidrs {
		peers = append(peers, string(c))
	}
	for _, f := range fqdns {
		if f.MatchName != "" {
			peers = append(peers, f.MatchName)
		} else if f.MatchPattern != "" {
			peers = append(peers, f.MatchPattern)
		}
	}
	if len(peers) == 0 {
		return "anyone"
	}
	return strings.Join(peers, ", ")
}

// describeSelector turns a peer's matchLabels into "name/component/instance", then "in <namespace>" when the
// selector names one (a peer in the policy's own namespace carries no namespace label), then "in cluster <c>"
// for a ClusterMesh peer. Labels the naming does not use are listed as key=value so nothing is hidden.
func describeSelector(labels map[string]string) string {
	if len(labels) == 0 {
		return "any endpoint"
	}
	used := map[string]bool{}
	var who []string
	for _, k := range []string{"app.kubernetes.io/name", "app", "k8s-app", "name"} {
		if v, ok := labels[k]; ok {
			who = append(who, v)
			used[k] = true
			break
		}
	}
	for _, k := range []string{"app.kubernetes.io/component", "app.kubernetes.io/instance"} {
		if v, ok := labels[k]; ok {
			who = append(who, v)
			used[k] = true
		}
	}
	out := strings.Join(who, "/")
	if ns, ok := labels[flow.GetNamespaceLabel()]; ok {
		if out == "" {
			out = "endpoints"
		}
		out += " in " + ns
		used[flow.GetNamespaceLabel()] = true
	}
	if c, ok := labels[ClusterLabel]; ok {
		out += " in cluster " + c
		used[ClusterLabel] = true
	}
	var rest []string
	for k, v := range labels {
		if !used[k] {
			rest = append(rest, k+"="+v)
		}
	}
	sort.Strings(rest)
	if len(rest) > 0 {
		if out != "" {
			out += " "
		}
		out += "(" + strings.Join(rest, ", ") + ")"
	}
	return out
}

// portList renders " on TCP/80, UDP/53" and the L7 rules a port carries: HTTP as "GET /path" (the anchors and the
// optional-query suffix the generator adds are stripped for reading), DNS as the names or patterns
func portList(rules PortRules) string {
	var ports []string
	for _, pr := range rules {
		for _, p := range pr.Ports {
			s := string(p.Protocol) + "/" + p.Port
			if p.Protocol == "" {
				s = p.Port
			}
			ports = append(ports, s)
		}
		if pr.Rules != nil {
			var l7 []string
			for _, h := range pr.Rules.HTTP {
				l7 = append(l7, strings.TrimSpace(h.Method+" "+readablePath(h.Path)))
			}
			for _, d := range pr.Rules.DNS {
				if d.MatchName != "" {
					l7 = append(l7, d.MatchName)
				} else if d.MatchPattern != "" {
					l7 = append(l7, d.MatchPattern)
				}
			}
			if len(l7) > 0 && len(ports) > 0 {
				kind := "HTTP"
				if len(pr.Rules.HTTP) == 0 {
					kind = "DNS"
				}
				ports[len(ports)-1] += " (" + kind + " " + strings.Join(l7, ", ") + ")"
			}
		}
	}
	if len(ports) == 0 {
		return ""
	}
	return " on " + strings.Join(ports, ", ")
}

var pathAnchors = regexp.MustCompile(`^\^|\(\\\?\.\*\)\?\$$|\$$`)

// readablePath strips what the generator adds around an observed path (^ … (\?.*)?$) and leaves a hand-written regex alone
func readablePath(p string) string {
	return pathAnchors.ReplaceAllString(p, "")
}
