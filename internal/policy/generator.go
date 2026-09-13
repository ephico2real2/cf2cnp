package policy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"encoding/json"

	"github.com/hubble-policy-gen/internal/aggregator"
	"github.com/hubble-policy-gen/internal/flow"
	"github.com/hubble-policy-gen/internal/render"

	"github.com/cilium/cilium/pkg/policy/api"
	"k8s.io/apimachinery/pkg/util/validation"
)

// ClusterLabel is the label Cilium puts on every endpoint of a ClusterMesh member and matches in
// fromEndpoints / toEndpoints (cilium Documentation/network/clustermesh/policy.rst). Since 1.19 a selector
// WITHOUT it matches the local cluster only.
const ClusterLabel = "io.cilium.k8s.policy.cluster"

// peerCluster is the cluster to name on a peer selector: the peer's, when it is known and differs from the
// local side's (the local side may be unknown — the peer's label is still what Cilium matches)
func peerCluster(local, peer string) string {
	if peer != "" && peer != local {
		return peer
	}
	return ""
}

// ErrReplyFlow is returned when attempting to generate a policy for a reply flow
var ErrReplyFlow = errors.New("this is a reply packet - you need to allow the original request, not the reply (Cilium's connection tracking automatically allows replies)")

// ErrNameNeedsOnePolicy is returned when a name override is requested but the flows produce more than one policy
var ErrNameNeedsOnePolicy = errors.New("a policy name can only be set when the flows produce a single policy")

// ErrInvalidPolicy wraps a refusal by Cilium's own rule checks (Validate); the API answers it with a 400 and the
// agent's sentence, not a 500
var ErrInvalidPolicy = errors.New("invalid CiliumNetworkPolicy")

// Generator generates CiliumNetworkPolicies from aggregated flows
type Generator struct {
	outputDir     string
	nameOverride  string
	l7            bool         // E2: emit HTTP/DNS rules from the flows' l7 records
	dnsVisibility bool         // E3: add the DNS resolver's L7 DNS rule to world policies that have no names
	dnsProfile    string       // 0.7.0: auto (from the flows), kubernetes or openshift
	dnsResolver   *DNSResolver // 0.7.0: an explicit --dns-resolver, over the profile
	resolver      DNSResolver  // the resolver of the current BuildPolicies run
}

// WithDNSVisibility adds the kube-dns L7 DNS rule to a world policy that has no names, so that the DNS
// proxy records them and the next generation can write toFQDNs instead of toCIDR. Names come only from
// the DNS proxy, and the proxy is enabled by exactly this rule (cilium Documentation/security/policy/layer3.rst,
// "Obtaining DNS Data for use by toFQDNs").
func (g *Generator) WithDNSVisibility() *Generator {
	g.dnsVisibility = true
	return g
}

// WithL7 makes the generator write layer-7 rules (HTTP method+path, DNS names) where the flows carry
// them. The port then goes through the node's Envoy proxy (cilium Documentation/security/policy/layer7.rst);
// the caller opted in.
func (g *Generator) WithL7() *Generator {
	g.l7 = true
	return g
}

// portRules builds the toPorts list for an aggregated flow. Without WithL7 (or without L7 records) it is
// one port rule with every port, as before. With them, every port that carries L7 records gets its own
// port rule with a rules: block, and the ports without stay together — an HTTP rule seen on 8080 must not
// restrict 5432 of the same peer pair (review finding). Cilium's L7Rules is a union: one protocol per port.
func (g *Generator) portRules(f *aggregator.AggregatedFlow) PortRules {
	if !g.l7 {
		return PortRules{{Ports: convertPorts(f.Ports)}}
	}
	var plain []aggregator.PortInfo
	var rules PortRules
	for _, p := range f.Ports {
		r := l7RulesFor(p)
		if r == nil {
			plain = append(plain, p)
			continue
		}
		rules = append(rules, PortRule{Ports: convertPorts([]aggregator.PortInfo{p}), Rules: r})
	}
	if len(plain) > 0 {
		rules = append(PortRules{{Ports: convertPorts(plain)}}, rules...)
	}
	return rules
}

// l7RulesFor is the rules: block for one port, or nil when nothing was seen on it
func l7RulesFor(p aggregator.PortInfo) *L7Rules {
	if len(p.HTTPRequests) == 0 && len(p.DNSQueries) == 0 {
		return nil
	}
	r := &L7Rules{}
	for _, req := range p.HTTPRequests {
		// Envoy matches the regex against the WHOLE :path header, which carries the query string too:
		// the path is escaped, and an optional query is allowed — "/payments?x=1" is still /payments.
		r.HTTP = append(r.HTTP, HTTPRule{Method: req.Method, Path: "^" + regexp.QuoteMeta(req.Path) + `(\?.*)?$`})
	}
	for _, q := range p.DNSQueries {
		r.DNS = append(r.DNS, DNSRule{MatchName: q})
	}
	return r
}

// NewGenerator creates a new policy generator
func NewGenerator(outputDir string) *Generator {
	return &Generator{outputDir: outputDir}
}

// WithName makes the generator name the (single) resulting policy as given, sanitized for Kubernetes.
// Without it a policy is named after the workload it selects, so two flows to the same workload from
// different peers produce two objects with the same name — the second applied replaces the first.
func (g *Generator) WithName(name string) *Generator {
	g.nameOverride = sanitizeK8sName(name)
	return g
}

// BuildPolicies turns aggregated flows into policies: one per flow, then flows that select the same
// workload (same namespace, name and endpointSelector) are merged into one object carrying every
// rule. Reply flows are skipped; if every flow is a reply, ErrReplyFlow is returned.
func (g *Generator) BuildPolicies(flows []*aggregator.AggregatedFlow) ([]*CiliumNetworkPolicy, error) {
	allReplies := true
	for _, f := range flows {
		if !f.IsReply {
			allReplies = false
			break
		}
	}
	if allReplies && len(flows) > 0 {
		return nil, ErrReplyFlow
	}

	g.resolver = g.resolveDNS(flows) // the DNS rule of this run: from the flows, or the profile (dns.go)

	var policies []*CiliumNetworkPolicy
	for _, f := range flows {
		if f.IsReply {
			continue
		}
		policies = append(policies, g.GeneratePolicy(f))
	}
	policies = mergePolicies(policies, g.dnsRule())
	for _, p := range policies {
		if err := Validate(p); err != nil {
			return nil, err
		}
	}

	if g.nameOverride != "" {
		if len(policies) != 1 {
			return nil, fmt.Errorf("%w: got %d", ErrNameNeedsOnePolicy, len(policies))
		}
		policies[0].Metadata.Name = g.nameOverride
	}
	return policies, nil
}

// Validate runs Cilium's own admission-time checks (api.Rule.Sanitize) on the policy and reports the agent's error
// text — "combining FromEndpoints and FromCIDR is not supported yet", an unparsable CIDR, an invalid selector. It works
// on a deep copy: Sanitize also normalises what it checks (selector keys get Cilium's label-source prefix, the protocol
// is upper-cased, enableDefaultDeny is filled), and none of that belongs in the document a user reads
// (docs/CRD-SPEC-FORENSICS.md §3, probes 2 and 3).
//
// Sanitize checks the rule, not the object: the name is checked here as the API server does (a DNS-1123 subdomain;
// the agent's own Parse refuses an empty one), and `specs` rule by rule (review ENH-003).
func Validate(p *CiliumNetworkPolicy) error {
	if errs := validation.IsDNS1123Subdomain(p.Metadata.Name); len(errs) > 0 {
		return fmt.Errorf("%w %s/%s: metadata.name %q: %s", ErrInvalidPolicy, p.Metadata.Namespace, p.Metadata.Name, p.Metadata.Name, strings.Join(errs, "; "))
	}
	if len(p.Specs) == 0 || !reflect.DeepEqual(p.Spec, Rule{}) { // Cilium's Parse: spec, specs, or both; never neither
		check := p.Spec.DeepCopy()
		if err := check.Sanitize(); err != nil {
			return fmt.Errorf("%w %s/%s: %w", ErrInvalidPolicy, p.Metadata.Namespace, p.Metadata.Name, err)
		}
	}
	for i, r := range p.Specs {
		if r == nil {
			return fmt.Errorf("%w %s/%s: specs[%d] is empty", ErrInvalidPolicy, p.Metadata.Namespace, p.Metadata.Name, i)
		}
		if err := r.DeepCopy().Sanitize(); err != nil {
			return fmt.Errorf("%w %s/%s: specs[%d]: %w", ErrInvalidPolicy, p.Metadata.Namespace, p.Metadata.Name, i, err)
		}
	}
	return nil
}

// MergePolicies folds policies that select the same workload into one, in first-seen order. Two
// generated policies are "the same workload" when namespace, name and endpointSelector match; their
// ingress and egress rules are concatenated, an identical rule (the DNS rule every FQDN policy
// carries) is kept once, and the description says how many observed flows the object now covers.
func MergePolicies(policies []*CiliumNetworkPolicy) []*CiliumNetworkPolicy {
	return mergePolicies(policies, dnsRuleFor(dnsProfiles[DNSProfileKubernetes]))
}

// mergePolicies is MergePolicies with the run's DNS rule, so the plain-rule shadow check knows what to compare against
func mergePolicies(policies []*CiliumNetworkPolicy, dnsRule EgressRule) []*CiliumNetworkPolicy {
	var order []string
	byKey := make(map[string]*CiliumNetworkPolicy)
	merged := make(map[string]int)
	for _, p := range policies {
		key := p.Metadata.Namespace + "/" + p.Metadata.Name + "/" + labelsKey(MatchLabelsOf(p.Spec.EndpointSelector))
		existing, ok := byKey[key]
		if !ok {
			byKey[key] = p
			order = append(order, key)
			continue
		}
		merged[key]++
		for _, r := range p.Spec.Ingress {
			if !containsIngress(existing.Spec.Ingress, r) {
				existing.Spec.Ingress = append(existing.Spec.Ingress, r)
			}
		}
		for _, r := range p.Spec.Egress {
			if !containsEgress(existing.Spec.Egress, r) {
				existing.Spec.Egress = append(existing.Spec.Egress, r)
			}
		}
	}
	result := make([]*CiliumNetworkPolicy, 0, len(order))
	for _, key := range order {
		p := byKey[key]
		p.Spec.Egress = dropShadowedDNSRule(p.Spec.Egress, dnsRule)
		p.Spec.Description = Describe(p) // from the final rules, merged or not (0.6.2: the per-flow sentence said only the namespaces)
		result = append(result, p)
	}
	return result
}

// dropShadowedDNSRule removes the plain kube-dns 53/UDP rule a pod's own lookups produce when the same policy also
// carries the DNS-visibility rule (E3, or the toFQDNs path): same peer, same port, and `matchPattern: "*"` allows
// every name, so the L7 rule says everything the plain one said. Cilium accepted both, but the policy read as if
// the rule were there twice (demo 31; fork issue #1). A narrower DNS rule (names from --l7) is not a superset and
// leaves the plain rule alone.
func dropShadowedDNSRule(rules []EgressRule, dnsRule EgressRule) []EgressRule {
	visibility := mustYAML(dnsRule)
	shadowed := false
	for _, r := range rules {
		if mustYAML(r) == visibility {
			shadowed = true
			break
		}
	}
	if !shadowed {
		return rules
	}
	plain := dnsRule.DeepCopy()
	plain.ToPorts[0].Rules = nil
	plainYAML := mustYAML(*plain)
	kept := rules[:0]
	for _, r := range rules {
		if mustYAML(r) != plainYAML {
			kept = append(kept, r)
		}
	}
	return kept
}

func labelsKey(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(labels[k])
		b.WriteByte(',')
	}
	return b.String()
}

func containsIngress(rules []IngressRule, r IngressRule) bool {
	want := mustYAML(r)
	for _, have := range rules {
		if mustYAML(have) == want {
			return true
		}
	}
	return false
}

func containsEgress(rules []EgressRule, r EgressRule) bool {
	want := mustYAML(r)
	for _, have := range rules {
		if mustYAML(have) == want {
			return true
		}
	}
	return false
}

// mustYAML is the canonical text of a value for equality: JSON of Cilium's types (their json tags, maps sorted)
func mustYAML(v interface{}) string {
	out, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%#v", v)
	}
	return string(out)
}

// hasCIDR reports whether a policy carries a toCIDR egress rule (the one that gets the world comment)
func hasCIDR(p *CiliumNetworkPolicy) bool {
	for _, r := range p.Spec.Egress {
		if len(r.ToCIDR) > 0 {
			return true
		}
	}
	return false
}

// GeneratePolicies generates CiliumNetworkPolicy files from aggregated flows — one file per workload
// (flows selecting the same workload are merged, so a later one no longer overwrites an earlier file)
func (g *Generator) GeneratePolicies(flows []*aggregator.AggregatedFlow) error {
	policies, err := g.BuildPolicies(flows)
	if err != nil {
		return err
	}
	for _, p := range policies {
		if err := g.writePolicyWithComment(p, hasCIDR(p)); err != nil {
			return err
		}
	}
	return nil
}

// GeneratePoliciesYAML generates CiliumNetworkPolicy YAML from aggregated flows and returns it as bytes
func (g *Generator) GeneratePoliciesYAML(flows []*aggregator.AggregatedFlow) ([]byte, error) {
	_, out, err := g.GeneratePoliciesWithYAML(flows)
	return out, err
}

// GeneratePoliciesWithYAML returns the policies and their YAML (one document per policy, separated by ---)
func (g *Generator) GeneratePoliciesWithYAML(flows []*aggregator.AggregatedFlow) ([]*CiliumNetworkPolicy, []byte, error) {
	policies, err := g.BuildPolicies(flows)
	if err != nil {
		return nil, nil, err
	}
	out, err := EncodePolicies(policies)
	if err != nil {
		return nil, nil, err
	}
	return policies, out, nil
}

// EncodePolicies renders policies as a multi-document YAML stream with the world/CIDR comment where it applies
func EncodePolicies(policies []*CiliumNetworkPolicy) ([]byte, error) {
	var buf bytes.Buffer
	for i, p := range policies {
		if i > 0 {
			buf.WriteString("---\n")
		}
		b, err := render.Document(p)
		if err != nil {
			return nil, fmt.Errorf("failed to encode policy to YAML: %w", err)
		}
		one := bytes.NewBuffer(b)
		if hasCIDR(p) {
			addToCIDRComment(one)
		}
		buf.Write(one.Bytes())
	}
	return buf.Bytes(), nil
}

// GeneratePolicy creates a CiliumNetworkPolicy from an aggregated flow
func (g *Generator) GeneratePolicy(f *aggregator.AggregatedFlow) *CiliumNetworkPolicy {
	policy := NewPolicy()

	if f.Direction == "INGRESS" {
		g.generateIngressPolicy(policy, f)
	} else {
		g.generateEgressPolicy(policy, f)
	}

	return policy
}

// generateIngressPolicy generates an ingress policy
func (g *Generator) generateIngressPolicy(policy *CiliumNetworkPolicy, f *aggregator.AggregatedFlow) {
	// For ingress, the destination is where the policy is applied
	policy.Metadata.Namespace = f.DestNamespace
	policy.Metadata.Name = generatePolicyName(f.DestLabels)
	policy.Metadata.Labels = policyLabels(f.DestLabels)

	// Generate description
	policy.Spec.Description = g.generateDescription(f)

	// Endpoint selector based on destination labels
	policy.Spec.EndpointSelector = Selector(f.DestLabels)

	if f.IsSourceEntity {
		// Entity-based ingress (from remote-node, host, etc.)
		g.generateEntityIngressRules(policy, f)
	} else {
		// Endpoint-based ingress (from pods)
		g.generateEndpointIngressRules(policy, f)
	}
}

// generateEndpointIngressRules generates endpoint-based ingress rules
func (g *Generator) generateEndpointIngressRules(policy *CiliumNetworkPolicy, f *aggregator.AggregatedFlow) {
	// Create ingress rule
	ingressRule := IngressRule{}

	// From endpoints with source labels
	fromLabels := copyLabels(f.SourceLabels)

	// Add namespace label if cross-namespace traffic
	if f.SourceNamespace != "" && f.SourceNamespace != f.DestNamespace {
		fromLabels[flow.GetNamespaceLabel()] = f.SourceNamespace
	}
	// ClusterMesh (E1): name the peer's cluster, or the rule matches the local cluster only
	if c := peerCluster(f.DestCluster, f.SourceCluster); c != "" {
		fromLabels[ClusterLabel] = c
	}

	ingressRule.FromEndpoints = []EndpointSelector{Selector(fromLabels)}

	// Add port rules
	ingressRule.ToPorts = g.portRules(f)

	policy.Spec.Ingress = []IngressRule{ingressRule}
}

// generateEntityIngressRules generates entity-based ingress rules (from remote-node, host, etc.). A world source
// with an address becomes fromCIDR (one /32 per observed address, 0.7.0): an egress-gateway IP, a load balancer's
// client, an office range — what the receiver actually saw. Without an address it stays fromEntities: [world].
func (g *Generator) generateEntityIngressRules(policy *CiliumNetworkPolicy, f *aggregator.AggregatedFlow) {
	// Create ingress rule with fromEntities
	ingressRule := IngressRule{}

	if f.SourceEntity == "world" && len(f.SourceIPs) > 0 {
		cidrs := make(CIDRSlice, 0, len(f.SourceIPs))
		for _, ip := range f.SourceIPs {
			cidrs = append(cidrs, hostCIDR(ip))
		}
		ingressRule.FromCIDR = cidrs
		ingressRule.ToPorts = g.portRules(f)
		policy.Spec.Ingress = []IngressRule{ingressRule}
		return
	}

	// For remote-node or host, include both to handle same-node and cross-node traffic
	if f.SourceEntity == "remote-node" || f.SourceEntity == "host" {
		ingressRule.FromEntities = EntitySlice{"remote-node", "host"}
	} else {
		ingressRule.FromEntities = EntitySlice{api.Entity(f.SourceEntity)}
	}

	// Add port rules
	ingressRule.ToPorts = g.portRules(f)

	policy.Spec.Ingress = []IngressRule{ingressRule}
}

// generateEgressPolicy generates an egress policy
func (g *Generator) generateEgressPolicy(policy *CiliumNetworkPolicy, f *aggregator.AggregatedFlow) {
	// For egress, the source is where the policy is applied
	policy.Metadata.Namespace = f.SourceNamespace
	policy.Metadata.Name = generatePolicyName(f.SourceLabels)
	policy.Metadata.Labels = policyLabels(f.SourceLabels)

	// Generate description
	policy.Spec.Description = g.generateDescription(f)

	// Endpoint selector based on source labels
	policy.Spec.EndpointSelector = Selector(f.SourceLabels)

	if f.IsDestEntityTraffic && f.DestEntity != "world" {
		// Entity-based egress (kube-apiserver, host, etc.)
		g.generateEntityEgressRules(policy, f)
	} else if f.IsWorldTraffic {
		if len(f.DestFQDNs) > 0 {
			// FQDN-based egress (world traffic with known FQDNs)
			g.generateFQDNEgressRules(policy, f)
		} else {
			// Entity-based egress (world traffic without FQDNs)
			g.generateWorldEgressRules(policy, f)
		}
	} else {
		// Endpoint-based egress (cluster internal traffic)
		g.generateEndpointEgressRules(policy, f)
	}
}

// generateFQDNEgressRules generates FQDN-based egress rules with DNS resolution
func (g *Generator) generateFQDNEgressRules(policy *CiliumNetworkPolicy, f *aggregator.AggregatedFlow) {
	// First rule: FQDN-based egress
	fqdnRule := EgressRule{}

	// Add FQDN selectors
	for _, fqdn := range f.DestFQDNs {
		fqdnRule.ToFQDNs = append(fqdnRule.ToFQDNs, FQDNSelector{
			MatchName: fqdn,
		})
	}

	// Add port rules
	fqdnRule.ToPorts = g.portRules(f)

	// Second rule: DNS resolution (required for toFQDNs to work)
	policy.Spec.Egress = []EgressRule{fqdnRule, g.dnsRule()}
}

// generateWorldEgressRules generates CIDR-based egress rules for world traffic without FQDNs
func (g *Generator) generateWorldEgressRules(policy *CiliumNetworkPolicy, f *aggregator.AggregatedFlow) {
	// Convert destination IPs to CIDRs
	cidrs := make(CIDRSlice, 0, len(f.DestIPs))
	for _, ip := range f.DestIPs {
		cidrs = append(cidrs, hostCIDR(ip))
	}

	// Rule for CIDR-based world traffic
	cidrRule := EgressRule{
		EgressCommonRule: EgressCommonRule{ToCIDR: cidrs},
		ToPorts:          g.portRules(f),
	}

	policy.Spec.Egress = []EgressRule{cidrRule}
	// E3: with the DNS proxy on, the next flows carry destination_names and the next generation writes toFQDNs
	if g.dnsVisibility {
		policy.Spec.Egress = append(policy.Spec.Egress, g.dnsRule())
	}
}

// generateEntityEgressRules generates entity-based egress rules for reserved entities (kube-apiserver, host, etc.)
func (g *Generator) generateEntityEgressRules(policy *CiliumNetworkPolicy, f *aggregator.AggregatedFlow) {
	// Rule for reserved entity traffic
	entityRule := EgressRule{}

	// For remote-node or host, include both to handle same-node and cross-node traffic
	if f.DestEntity == "remote-node" || f.DestEntity == "host" {
		entityRule.ToEntities = EntitySlice{"remote-node", "host"}
	} else {
		entityRule.ToEntities = EntitySlice{api.Entity(f.DestEntity)}
	}

	entityRule.ToPorts = g.portRules(f)

	policy.Spec.Egress = []EgressRule{entityRule}
}

// generateEndpointEgressRules generates endpoint-based egress rules
func (g *Generator) generateEndpointEgressRules(policy *CiliumNetworkPolicy, f *aggregator.AggregatedFlow) {
	egressRule := EgressRule{}

	// To endpoints with destination labels
	toLabels := copyLabels(f.DestLabels)

	// Add namespace label if cross-namespace traffic
	if f.DestNamespace != "" && f.DestNamespace != f.SourceNamespace {
		toLabels[flow.GetNamespaceLabel()] = f.DestNamespace
	}
	// ClusterMesh (E1): name the peer's cluster, or the rule matches the local cluster only
	if c := peerCluster(f.SourceCluster, f.DestCluster); c != "" {
		toLabels[ClusterLabel] = c
	}

	egressRule.ToEndpoints = []EndpointSelector{Selector(toLabels)}

	// Add port rules
	egressRule.ToPorts = g.portRules(f)

	policy.Spec.Egress = []EgressRule{egressRule}
}

// generateDescription creates a human-readable description for the policy
func (g *Generator) generateDescription(f *aggregator.AggregatedFlow) string {
	var direction, fromTo, target string

	if f.Direction == "INGRESS" {
		direction = "ingress"
		if f.IsSourceEntity {
			fromTo = fmt.Sprintf("from %s to %s", f.SourceEntity, f.DestNamespace)
		} else {
			fromTo = fmt.Sprintf("from %s to %s", f.SourceNamespace, f.DestNamespace)
		}
		target = getAppName(f.DestLabels)
	} else {
		direction = "egress"
		if f.IsDestEntityTraffic && f.DestEntity != "world" {
			fromTo = fmt.Sprintf("from %s to %s", f.SourceNamespace, f.DestEntity)
		} else if f.IsWorldTraffic {
			if len(f.DestFQDNs) > 0 {
				fromTo = fmt.Sprintf("from %s to %s", f.SourceNamespace, strings.Join(f.DestFQDNs, ", "))
			} else if len(f.DestIPs) > 0 {
				fromTo = fmt.Sprintf("from %s to %s", f.SourceNamespace, strings.Join(f.DestIPs, ", "))
			} else {
				fromTo = fmt.Sprintf("from %s to world", f.SourceNamespace)
			}
		} else {
			fromTo = fmt.Sprintf("from %s to %s", f.SourceNamespace, f.DestNamespace)
		}
		target = getAppName(f.SourceLabels)
	}

	return fmt.Sprintf("Allow %s traffic %s for the %s", direction, fromTo, target)
}

// generatePolicyName creates a policy name from the selector's labels. Kubernetes identifies an object by
// group, kind, namespace and name, so two workloads that share app.kubernetes.io/name but differ by
// instance or component (the recommended labels' own distinction: name = the application, instance =
// one installation of it, component = one part of it) must not produce two objects with one name —
// the second `kubectl apply` would replace the first, silently. The name is therefore a function of
// EVERY identifying label the selector carries, in the order name, instance, component, so that equal
// names imply equal selectors: "shop", "shop-frontend", "shop-blue-frontend".
func generatePolicyName(labels map[string]string) string {
	parts := []string{getAppName(labels)}
	for _, key := range []string{"app.kubernetes.io/instance", "app.kubernetes.io/component", "instance", "component"} {
		v, ok := labels[key]
		if !ok || v == "" {
			continue
		}
		dup := false
		for _, p := range parts {
			if p == v {
				dup = true
			}
		}
		if !dup {
			parts = append(parts, v)
		}
	}
	return sanitizeK8sName(strings.Join(parts, "-"))
}

// policyLabels are the labels stamped on every generated policy: who generated it, and the selector's
// identifying labels copied, so `kubectl get cnp -l app.kubernetes.io/name=shop` lists a workload's
// policies whatever they are named.
func policyLabels(selector map[string]string) map[string]string {
	out := map[string]string{"app.kubernetes.io/managed-by": "cf2cnp"}
	for _, key := range []string{"app.kubernetes.io/name", "app.kubernetes.io/instance", "app.kubernetes.io/component"} {
		if v, ok := selector[key]; ok && v != "" {
			out[key] = v
		}
	}
	return out
}

// getAppName extracts the application name from labels
func getAppName(labels map[string]string) string {
	// Priority order for app name
	priorityLabels := []string{
		"app.kubernetes.io/name",
		"app.kubernetes.io/instance",
		"app.kubernetes.io/component",
	}
	fallbackLabels := []string{
		"app",
		"k8s-app",
		"name",
		"component",
		"instance",
	}

	for _, label := range priorityLabels {
		if name, ok := labels[label]; ok {
			return name
		}
	}
	for _, label := range fallbackLabels {
		if name, ok := labels[label]; ok {
			return name
		}
	}
	return "unknown"
}

// sanitizeK8sName ensures the name is valid for Kubernetes resources
func sanitizeK8sName(name string) string {
	// Convert to lowercase
	name = strings.ToLower(name)
	// Replace underscores with hyphens
	name = strings.ReplaceAll(name, "_", "-")
	// Remove any invalid characters
	reg := regexp.MustCompile(`[^a-z0-9-]`)
	name = reg.ReplaceAllString(name, "")
	// Ensure it starts with a letter
	if len(name) > 0 && (name[0] < 'a' || name[0] > 'z') {
		name = "policy-" + name
	}
	// Truncate to 63 characters (Kubernetes limit)
	if len(name) > 63 {
		name = name[:63]
	}
	// Remove trailing hyphens
	name = strings.TrimRight(name, "-")
	return name
}

// writePolicy writes a policy to a YAML file
func (g *Generator) writePolicyWithComment(policy *CiliumNetworkPolicy, needsCIDRComment bool) error {
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(g.outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Generate filename from namespace and policy name
	filename := fmt.Sprintf("%s-%s.yaml", policy.Metadata.Namespace, policy.Metadata.Name)
	filePath := filepath.Join(g.outputDir, filename)

	b, err := render.Document(policy)
	if err != nil {
		return fmt.Errorf("failed to encode policy to YAML: %w", err)
	}
	buf := bytes.NewBuffer(b)
	if needsCIDRComment {
		addToCIDRComment(buf)
	}
	if err := os.WriteFile(filePath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write policy file: %w", err)
	}

	fmt.Printf("Generated policy: %s\n", filePath)
	return nil
}

// convertPorts converts aggregator.PortInfo to policy.Port
func convertPorts(ports []aggregator.PortInfo) []Port {
	result := make([]Port, len(ports))
	for i, p := range ports {
		result[i] = Port{
			Port:     fmt.Sprintf("%d", p.Port),
			Protocol: api.L4Proto(strings.ToUpper(p.Protocol)), // the CRD's enum is upper-case only
		}
	}
	return result
}

// hostCIDR is the single-address prefix for an observed address: /32 for IPv4, /128 for IPv6 (0.6.x wrote /32 for
// both, which Cilium refuses for an IPv6 address)
func hostCIDR(ip string) api.CIDR {
	if strings.Contains(ip, ":") {
		return api.CIDR(ip + "/128")
	}
	return api.CIDR(ip + "/32")
}

// copyLabels creates a copy of the labels map
func copyLabels(labels map[string]string) map[string]string {
	result := make(map[string]string, len(labels))
	for k, v := range labels {
		result[k] = v
	}
	return result
}

// addToCIDRComment inserts a comment after toCIDR in the YAML output
func addToCIDRComment(buf *bytes.Buffer) {
	content := buf.String()

	// Find toCIDR and toPorts to insert comment between them
	toCIDRIdx := strings.LastIndex(content, "toCIDR:")
	if toCIDRIdx == -1 {
		return
	}

	// Find toPorts after toCIDR
	restContent := content[toCIDRIdx:]
	toPortsIdx := strings.Index(restContent, "      toPorts:")
	if toPortsIdx == -1 {
		return
	}

	// Calculate the actual position (right before the indentation of "toPorts:")
	insertPos := toCIDRIdx + toPortsIdx

	// The comment should align with the list item when uncommented (4 spaces for the -)
	toCIDRComment := "    # To allow all traffic to world instead of specific IPs, replace toCIDR with:\n    # - toEntities:\n    #     - world\n"
	if strings.Contains(content, "rules:\n            dns:") {
		toCIDRComment += "    # The DNS rule below turns the DNS proxy on for these endpoints: once flows carry destination_names,\n    # regenerate to get a toFQDNs rule instead of this CIDR.\n"
	}

	// Insert the comment before toPorts
	newContent := content[:insertPos] + toCIDRComment + content[insertPos:]

	buf.Reset()
	buf.WriteString(newContent)
}
