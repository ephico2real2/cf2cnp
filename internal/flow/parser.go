package flow

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Priority labels to extract from endpoints (in order of preference)
var priorityLabels = []string{
	"app.kubernetes.io/name",
	"app.kubernetes.io/component",
	"app.kubernetes.io/instance",
}

// Fallback labels if no priority labels are found (in order of preference)
var fallbackLabels = []string{
	"app",
	"k8s-app",
	"name",
	"component",
	"instance",
}

// ParseFlowFile parses a single Hubble flow JSON file
func ParseFlowFile(filePath string) (*ParsedFlow, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	return ParseFlowFromBytes(data)
}

// ParseFlowFromBytes parses a Hubble flow from JSON bytes
func ParseFlowFromBytes(data []byte) (*ParsedFlow, error) {
	var flowData HubbleFlowData
	if err := json.Unmarshal(data, &flowData); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return parseFlow(&flowData.Flow)
}

// ParseFlowsFromBytes parses one or many Hubble flows from JSON bytes. Three shapes are accepted, because that is what
// the tools produce: a single flow object (a saved file, the Grafana action's log line), a JSON array of flow objects,
// and newline-delimited objects — the output of `hubble observe -o json`, one flow per line. Blank lines are skipped;
// the first object that does not parse names its position in the error.
func ParseFlowsFromBytes(data []byte) ([]*ParsedFlow, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, errors.New("no flow data")
	}

	var raw []HubbleFlowData
	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &raw); err != nil {
			return nil, fmt.Errorf("failed to parse JSON array of flows: %w", err)
		}
	} else {
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		for i := 1; ; i++ {
			var fd HubbleFlowData
			if err := dec.Decode(&fd); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return nil, fmt.Errorf("failed to parse flow #%d: %w", i, err)
			}
			raw = append(raw, fd)
		}
	}
	if len(raw) == 0 {
		return nil, errors.New("no flow objects found")
	}

	flows := make([]*ParsedFlow, 0, len(raw))
	for i := range raw {
		parsed, err := parseFlow(&raw[i].Flow)
		if err != nil {
			return nil, fmt.Errorf("flow #%d: %w", i+1, err)
		}
		flows = append(flows, parsed)
	}
	return flows, nil
}

// ParseFlowsFromDirectory parses all JSON flow files from a directory
func ParseFlowsFromDirectory(dirPath string) ([]*ParsedFlow, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %w", dirPath, err)
	}

	var flows []*ParsedFlow
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			continue
		}

		filePath := filepath.Join(dirPath, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
		}
		parsed, err := ParseFlowsFromBytes(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filePath, err)
		}
		flows = append(flows, parsed...)
	}

	return flows, nil
}

// parseFlow converts a Flow struct to a ParsedFlow with extracted information
func parseFlow(flow *Flow) (*ParsedFlow, error) {
	// A zero Flow decodes from `{}`, `null` or an object without a "flow" key without error; it would
	// become a policy with empty selectors. Refuse anything that names neither an endpoint nor a direction.
	if flow == nil || (flow.UUID == "" && flow.TrafficDirection == "" && len(flow.Source.Labels) == 0 && len(flow.Destination.Labels) == 0) {
		return nil, errors.New("not a Hubble flow (no flow.source/destination labels, no traffic_direction, no uuid)")
	}
	parsed := &ParsedFlow{
		UUID:         flow.UUID,
		SourceLabels: make(map[string]string),
		DestLabels:   make(map[string]string),
		IsReply:      flow.IsReply,
	}

	// Parse source endpoint
	parsed.SourceNamespace = flow.Source.Namespace
	parsed.SourceLabels = extractLabels(flow.Source.Labels)

	// Parse destination endpoint
	parsed.DestNamespace = flow.Destination.Namespace
	parsed.DestLabels = extractLabels(flow.Destination.Labels)

	// ClusterMesh: which cluster each side is in. Since Cilium 1.19 a selector without
	// io.cilium.k8s.policy.cluster matches the LOCAL cluster only, so a policy generated from a
	// cross-cluster flow must name the peer's cluster or it excludes that very peer.
	parsed.SourceCluster = clusterOf(flow.Source)
	parsed.DestCluster = clusterOf(flow.Destination)

	// Check if source is a reserved entity (remote-node, host, etc.)
	parsed.SourceEntity = getReservedEntity(flow.Source.Labels)
	parsed.IsSourceEntity = parsed.SourceEntity != ""

	// Check if destination is a reserved entity (kube-apiserver, host, world, etc.)
	parsed.DestEntity = getReservedEntity(flow.Destination.Labels)
	parsed.IsDestEntityTraffic = parsed.DestEntity != ""

	// A world SOURCE is an address too (an egress-gateway IP, a load balancer's client, an office range): keep it, so
	// the ingress rule can be a fromCIDR instead of the whole world (0.7.0; the 0.6.x rule was fromEntities: [world])
	if isWorldTraffic(flow.Source.Labels) {
		parsed.SourceIP = flow.IP.Source
	}

	// Check if destination is "world" (external traffic)
	parsed.IsWorldTraffic = isWorldTraffic(flow.Destination.Labels)
	if parsed.IsWorldTraffic {
		// Store destination IP for CIDR-based rules
		parsed.DestIP = flow.IP.Destination
		if len(flow.DestinationNames) > 0 {
			parsed.DestFQDNs = flow.DestinationNames
		}
	}

	// Determine traffic direction
	parsed.Direction = flow.TrafficDirection
	if parsed.Direction == "" {
		// Infer direction from flow data
		parsed.Direction = inferTrafficDirection(parsed)
	}

	// Parse L4 protocol and port
	// Always use destination_port - this is the port being accessed on the destination
	if flow.L4.TCP != nil {
		parsed.Protocol = "TCP"
		parsed.Port = flow.L4.TCP.DestinationPort
	} else if flow.L4.UDP != nil {
		parsed.Protocol = "UDP"
		parsed.Port = flow.L4.UDP.DestinationPort
	}

	// Layer 7 (E2): only REQUEST records describe what the client asked for; a RESPONSE is the reply
	// side, skipped like is_reply. A request carries either http or dns.
	if flow.L7 != nil && flow.L7.Type == "REQUEST" {
		if flow.L7.HTTP != nil && flow.L7.HTTP.URL != "" {
			parsed.HTTPMethod = flow.L7.HTTP.Method
			if u, err := url.Parse(flow.L7.HTTP.URL); err == nil {
				parsed.HTTPPath = u.Path
			}
		}
		if flow.L7.DNS != nil {
			// The query exactly as the resolver sent it, trailing dot removed. A search-list expansion
			// (accounts.bank.svc.cluster.local.bank.svc.cluster.local — ndots:5) is kept on purpose: an L7 DNS
			// policy allows ONLY the names it lists ("No other DNS queries will be allowed", layer7.rst), and
			// the resolver tries the expansions before the real name — deny them and lookups fail.
			parsed.DNSQuery = strings.TrimSuffix(flow.L7.DNS.Query, ".")
		}
	}

	return parsed, nil
}

// clusterOf is the endpoint's cluster: cluster_name when Hubble set it, else the io.cilium.k8s.policy.cluster
// label the endpoint carries anyway (review finding: a flow with an empty cluster_name still names the cluster
// in its labels, and dropping it there reintroduced the local-only bug E1 exists to fix)
func clusterOf(ep Endpoint) string {
	if ep.ClusterName != "" {
		return ep.ClusterName
	}
	return labelValue(ep.Labels, "io.cilium.k8s.policy.cluster")
}

// labelValue returns the value of key in Hubble's "k8s:key=value" (or "key=value") label list, or ""
func labelValue(labels []string, key string) string {
	for _, l := range labels {
		for _, prefix := range []string{"k8s:" + key + "=", key + "="} {
			if strings.HasPrefix(l, prefix) {
				return strings.TrimPrefix(l, prefix)
			}
		}
	}
	return ""
}

// extractLabels extracts and filters labels from Hubble label format
// Labels are in format "k8s:labelKey=labelValue"
func extractLabels(labels []string) map[string]string {
	result := make(map[string]string)
	allLabels := make(map[string]string)

	// First, parse all labels into a map
	for _, label := range labels {
		// Remove "k8s:" prefix if present
		labelStr := strings.TrimPrefix(label, "k8s:")

		// Split by "=" to get key and value
		parts := strings.SplitN(labelStr, "=", 2)
		if len(parts) != 2 {
			continue
		}
		allLabels[parts[0]] = parts[1]
	}

	// Try to find priority labels first
	foundPriority := false
	for _, priorityLabel := range priorityLabels {
		if value, exists := allLabels[priorityLabel]; exists {
			result[priorityLabel] = value
			foundPriority = true
		}
	}

	// If no priority labels found, try fallback labels (use all matching)
	if !foundPriority {
		for _, fallbackLabel := range fallbackLabels {
			if value, exists := allLabels[fallbackLabel]; exists {
				result[fallbackLabel] = value
			}
		}
	}

	return result
}

// isWorldTraffic checks if the endpoint is external "world" traffic
func isWorldTraffic(labels []string) bool {
	for _, label := range labels {
		if label == "reserved:world" {
			return true
		}
	}
	return false
}

// Reserved entities that Cilium supports
var reservedEntities = map[string]string{
	"reserved:kube-apiserver": "kube-apiserver",
	"reserved:host":           "host",
	"reserved:remote-node":    "remote-node",
	"reserved:world":          "world",
	"reserved:health":         "health",
	"reserved:init":           "init",
	"reserved:ingress":        "ingress",
}

// getReservedEntity checks if the endpoint is a reserved entity and returns the entity name
func getReservedEntity(labels []string) string {
	var foundEntity string

	for _, label := range labels {
		if entity, ok := reservedEntities[label]; ok {
			// Prefer kube-apiserver over other entities if present
			if entity == "kube-apiserver" {
				return entity
			}
			// Prefer non-remote-node entities, but remember remote-node as fallback
			if entity == "remote-node" {
				if foundEntity == "" {
					foundEntity = entity
				}
			} else {
				foundEntity = entity
			}
		}
	}
	return foundEntity
}

// GetNamespaceLabel returns the namespace label for cross-namespace traffic
func GetNamespaceLabel() string {
	return "io.kubernetes.pod.namespace"
}

// inferTrafficDirection infers the traffic direction when not explicitly set
// - If source is a reserved entity and destination is a pod -> INGRESS
// - If source is a pod and destination is a reserved entity -> EGRESS
// - If both are pods, default to INGRESS (traffic coming into the destination)
func inferTrafficDirection(parsed *ParsedFlow) string {
	// If source is a reserved entity (remote-node, host, etc.) and destination has a namespace
	// this is INGRESS traffic to the destination pod
	if parsed.IsSourceEntity && parsed.DestNamespace != "" {
		return "INGRESS"
	}

	// If destination is a reserved entity (kube-apiserver, world, etc.) and source has a namespace
	// this is EGRESS traffic from the source pod
	if parsed.IsDestEntityTraffic && parsed.SourceNamespace != "" {
		return "EGRESS"
	}

	// If destination is world traffic, it's EGRESS
	if parsed.IsWorldTraffic {
		return "EGRESS"
	}

	// Default: if both have namespaces, treat as INGRESS (traffic going to the destination)
	if parsed.DestNamespace != "" {
		return "INGRESS"
	}

	// Fallback
	return "EGRESS"
}
