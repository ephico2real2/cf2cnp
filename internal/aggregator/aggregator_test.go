package aggregator

import (
	"strconv"
	"strings"
	"testing"

	"github.com/hubble-policy-gen/internal/flow"
)

// pf is a parsed pod-to-pod flow: pos in lab calling shop in lab on TCP/80, INGRESS as the receiver saw it
func pf(mut ...func(*flow.ParsedFlow)) *flow.ParsedFlow {
	f := &flow.ParsedFlow{
		Direction:       "INGRESS",
		SourceNamespace: "lab",
		SourceLabels:    map[string]string{"app.kubernetes.io/name": "pos"},
		DestNamespace:   "lab",
		DestLabels:      map[string]string{"app.kubernetes.io/name": "shop"},
		Protocol:        "TCP",
		Port:            80,
	}
	for _, m := range mut {
		m(f)
	}
	return f
}

// portList renders an aggregated flow's ports as "TCP/53,UDP/53,TCP/80"
func portList(agg *AggregatedFlow) string {
	out := make([]string, 0, len(agg.Ports))
	for _, p := range agg.Ports {
		out = append(out, p.Protocol+"/"+strconv.Itoa(p.Port))
	}
	return strings.Join(out, ",")
}

// Flows between the same peers in the same direction are one aggregated flow whose ports are the distinct
// (port, protocol) pairs seen, sorted by port then protocol; the same pair twice is one port.
func TestAggregateFlows_MergesPortsOfOnePeerPair(t *testing.T) {
	flows := []*flow.ParsedFlow{
		pf(func(f *flow.ParsedFlow) { f.Port = 443 }),
		pf(),
		pf(func(f *flow.ParsedFlow) { f.Port = 53; f.Protocol = "UDP" }),
		pf(),
		pf(func(f *flow.ParsedFlow) { f.Port = 53; f.Protocol = "TCP" }),
	}
	aggs := AggregateFlows(flows)
	if len(aggs) != 1 {
		t.Fatalf("one peer pair must be one aggregated flow, got %d", len(aggs))
	}
	if got := portList(aggs[0]); got != "TCP/53,UDP/53,TCP/80,TCP/443" {
		t.Fatalf("ports must be distinct and sorted by port then protocol, got %s", got)
	}
	a := aggs[0]
	if a.Direction != "INGRESS" || a.SourceNamespace != "lab" || a.DestNamespace != "lab" || a.SourceLabels["app.kubernetes.io/name"] != "pos" || a.DestLabels["app.kubernetes.io/name"] != "shop" {
		t.Fatalf("the aggregated flow must carry the peers: %+v", a)
	}
}

// Each of these makes another peer pair: the direction, either namespace, either label set, either cluster
func TestAggregateFlows_SplitsOnEveryKeyPart(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*flow.ParsedFlow)
	}{
		{"direction", func(f *flow.ParsedFlow) { f.Direction = "EGRESS" }},
		{"source namespace", func(f *flow.ParsedFlow) { f.SourceNamespace = "other" }},
		{"destination namespace", func(f *flow.ParsedFlow) { f.DestNamespace = "other" }},
		{"source labels", func(f *flow.ParsedFlow) { f.SourceLabels = map[string]string{"app.kubernetes.io/name": "kiosk"} }},
		{"destination labels", func(f *flow.ParsedFlow) { f.DestLabels["app.kubernetes.io/component"] = "frontend" }},
		{"source cluster", func(f *flow.ParsedFlow) { f.SourceCluster = "poc2" }},
		{"destination cluster", func(f *flow.ParsedFlow) { f.DestCluster = "poc2" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			aggs := AggregateFlows([]*flow.ParsedFlow{pf(), pf(c.mut)})
			if len(aggs) != 2 {
				t.Fatalf("a different %s must be another aggregated flow, got %d", c.name, len(aggs))
			}
		})
	}
	// the key is the labels' content, not the map: equal labels in another order are the same peer
	aggs := AggregateFlows([]*flow.ParsedFlow{
		pf(func(f *flow.ParsedFlow) {
			f.DestLabels = map[string]string{"app.kubernetes.io/name": "shop", "app.kubernetes.io/component": "web"}
		}),
		pf(func(f *flow.ParsedFlow) {
			f.DestLabels = map[string]string{"app.kubernetes.io/component": "web", "app.kubernetes.io/name": "shop"}
		}),
	})
	if len(aggs) != 1 {
		t.Fatalf("equal label sets are one peer, got %d", len(aggs))
	}
}

// A reserved entity on either side is part of the key, and each side's flags and addresses are carried over
func TestAggregateFlows_Entities(t *testing.T) {
	fromEntity := func(entity string) *flow.ParsedFlow {
		return pf(func(f *flow.ParsedFlow) {
			f.SourceNamespace, f.SourceLabels = "", map[string]string{}
			f.SourceEntity, f.IsSourceEntity = entity, true
		})
	}
	aggs := AggregateFlows([]*flow.ParsedFlow{fromEntity("host"), fromEntity("remote-node"), fromEntity("host")})
	if len(aggs) != 2 || !aggs[0].IsSourceEntity || !aggs[1].IsSourceEntity || aggs[0].SourceEntity+","+aggs[1].SourceEntity != "host,remote-node" {
		t.Fatalf("host and remote-node sources are two aggregated flows, in key order: %+v", aggs)
	}
	toEntity := func(entity string, port int) *flow.ParsedFlow {
		return pf(func(f *flow.ParsedFlow) {
			f.Direction = "EGRESS"
			f.DestNamespace, f.DestLabels = "", map[string]string{}
			f.DestEntity, f.IsDestEntityTraffic = entity, true
			f.Port = port
		})
	}
	aggs = AggregateFlows([]*flow.ParsedFlow{toEntity("kube-apiserver", 6443), toEntity("host", 10250), toEntity("kube-apiserver", 443)})
	if len(aggs) != 2 || aggs[0].DestEntity != "host" || aggs[1].DestEntity != "kube-apiserver" || portList(aggs[1]) != "TCP/443,TCP/6443" {
		t.Fatalf("kube-apiserver (two ports) and host are two aggregated flows: %+v", aggs)
	}
	// a world source's addresses are collected for fromCIDR (0.7.0), distinct and in first-seen order
	world := func(ip string) *flow.ParsedFlow {
		return pf(func(f *flow.ParsedFlow) {
			f.SourceNamespace, f.SourceLabels = "", map[string]string{}
			f.SourceEntity, f.IsSourceEntity, f.SourceIP = "world", true, ip
		})
	}
	aggs = AggregateFlows([]*flow.ParsedFlow{world("172.18.255.170"), world("172.18.255.171"), world("172.18.255.170")})
	if len(aggs) != 1 || strings.Join(aggs[0].SourceIPs, ",") != "172.18.255.170,172.18.255.171" {
		t.Fatalf("world source addresses: %+v", aggs)
	}
}

// World destinations group by their FQDN set: the same names are one flow (its addresses collected, names sorted),
// other names another; a world flow without names is its own group
func TestAggregateFlows_WorldFQDNsAndIPs(t *testing.T) {
	world := func(ip string, names ...string) *flow.ParsedFlow {
		return pf(func(f *flow.ParsedFlow) {
			f.Direction = "EGRESS"
			f.DestNamespace, f.DestLabels = "", map[string]string{}
			f.DestEntity, f.IsDestEntityTraffic, f.IsWorldTraffic = "world", true, true
			f.DestIP, f.DestFQDNs, f.Port = ip, names, 443
		})
	}
	aggs := AggregateFlows([]*flow.ParsedFlow{
		world("104.20.23.154", "www.example.com", "example.com"),
		world("104.20.22.154", "example.com", "www.example.com"),
		world("104.20.23.154", "example.com", "www.example.com"),
		world("93.184.216.34", "other.example.net"),
		world("1.1.1.1"),
	})
	if len(aggs) != 3 {
		t.Fatalf("two name sets and one nameless flow are three aggregated flows, got %d", len(aggs))
	}
	byNames := map[string]*AggregatedFlow{}
	for _, a := range aggs {
		byNames[strings.Join(a.DestFQDNs, ",")] = a
	}
	if a := byNames["example.com,www.example.com"]; a == nil || strings.Join(a.DestIPs, ",") != "104.20.23.154,104.20.22.154" {
		t.Fatalf("the same name set must be one flow with sorted names and distinct addresses: %+v", aggs)
	}
	if a := byNames["other.example.net"]; a == nil || strings.Join(a.DestIPs, ",") != "93.184.216.34" {
		t.Fatalf("other names are another flow: %+v", aggs)
	}
	if a := byNames[""]; a == nil || !a.IsWorldTraffic || strings.Join(a.DestIPs, ",") != "1.1.1.1" {
		t.Fatalf("a nameless world flow keeps its address for toCIDR: %+v", aggs)
	}
}

// The output order is the key's: direction first (EGRESS before INGRESS), then the source, then the destination —
// whatever the input order, so two runs over a shuffled capture write the same documents
func TestAggregateFlows_OrderIsByKey(t *testing.T) {
	ingress := pf()
	egress := pf(func(f *flow.ParsedFlow) { f.Direction = "EGRESS" })
	other := pf(func(f *flow.ParsedFlow) { f.SourceLabels = map[string]string{"app.kubernetes.io/name": "kiosk"} })
	for _, in := range [][]*flow.ParsedFlow{{ingress, egress, other}, {other, ingress, egress}, {egress, other, ingress}} {
		aggs := AggregateFlows(in)
		got := aggs[0].Direction + ":" + aggs[0].SourceLabels["app.kubernetes.io/name"] + "," + aggs[1].Direction + ":" + aggs[1].SourceLabels["app.kubernetes.io/name"] + "," + aggs[2].Direction + ":" + aggs[2].SourceLabels["app.kubernetes.io/name"]
		if got != "EGRESS:pos,INGRESS:kiosk,INGRESS:pos" {
			t.Fatalf("order must not depend on the input, got %s", got)
		}
	}
}

// E2: layer-7 records are kept per port of the aggregated flow (an HTTP rule on 8080 must not restrict 5432), distinct
func TestAggregateFlows_L7PerPort(t *testing.T) {
	http := func(method, path string) *flow.ParsedFlow {
		return pf(func(f *flow.ParsedFlow) { f.Port, f.HTTPMethod, f.HTTPPath = 8080, method, path })
	}
	dns := func(name string) *flow.ParsedFlow {
		return pf(func(f *flow.ParsedFlow) { f.Port, f.Protocol, f.DNSQuery = 53, "UDP", name })
	}
	aggs := AggregateFlows([]*flow.ParsedFlow{
		pf(func(f *flow.ParsedFlow) { f.Port = 5432 }),
		http("GET", "/"), http("GET", "/checkout"), http("GET", "/"),
		dns("example.com"), dns("example.com"), dns("cdn.example.com"),
	})
	if len(aggs) != 1 || portList(aggs[0]) != "UDP/53,TCP/5432,TCP/8080" {
		t.Fatalf("three ports of one peer pair: %+v", aggs)
	}
	for _, p := range aggs[0].Ports {
		switch p.Port {
		case 5432:
			if len(p.HTTPRequests) != 0 || len(p.DNSQueries) != 0 {
				t.Fatalf("5432 saw no L7: %+v", p)
			}
		case 8080:
			if len(p.HTTPRequests) != 2 || p.HTTPRequests[0] != (HTTPRequest{"GET", "/"}) || p.HTTPRequests[1] != (HTTPRequest{"GET", "/checkout"}) {
				t.Fatalf("8080 must carry the two distinct requests in first-seen order: %+v", p.HTTPRequests)
			}
		case 53:
			if strings.Join(p.DNSQueries, ",") != "example.com,cdn.example.com" {
				t.Fatalf("53 must carry the distinct names in first-seen order: %+v", p.DNSQueries)
			}
		}
	}
}

// The aggregated flow owns its label maps: changing the parsed flow afterwards changes nothing
func TestAggregateFlows_CopiesLabels(t *testing.T) {
	in := pf()
	aggs := AggregateFlows([]*flow.ParsedFlow{in})
	in.SourceLabels["app.kubernetes.io/name"] = "changed"
	if aggs[0].SourceLabels["app.kubernetes.io/name"] != "pos" {
		t.Fatal("labels must be copied, not shared")
	}
	if AggregateFlows(nil) == nil || len(AggregateFlows(nil)) != 0 {
		t.Fatal("no flows is an empty, non-nil result")
	}
}

// A reply is never merged into a request (fork issue #13). Hubble reports a reply with the connection's
// traffic_direction, so it shares the request's key only when both peers carry the same labels (replica-set members
// talking to each other), and its destination_port is the client's ephemeral port. Merged, a reply arriving first
// marked the request's flow a reply and BuildPolicies dropped it; a reply arriving second added its ephemeral port to
// the request's rule. Kept apart, the request keeps its port alone in either order and the reply stays skippable.
func TestAggregateFlows_KeepsRepliesApart(t *testing.T) {
	peer := func(f *flow.ParsedFlow) {
		f.Direction = "EGRESS"
		f.SourceLabels = map[string]string{"app.kubernetes.io/name": "mongod"}
		f.DestLabels = map[string]string{"app.kubernetes.io/name": "mongod"}
	}
	request := pf(peer, func(f *flow.ParsedFlow) { f.Port = 27017 })
	reply := pf(peer, func(f *flow.ParsedFlow) { f.Port = 41234; f.IsReply = true })
	for _, tc := range []struct {
		name  string
		flows []*flow.ParsedFlow
	}{
		{"reply then request", []*flow.ParsedFlow{reply, request}},
		{"request then reply", []*flow.ParsedFlow{request, reply}},
		{"request between replies", []*flow.ParsedFlow{reply, request, reply}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := map[bool]string{}
			for _, a := range AggregateFlows(tc.flows) {
				got[a.IsReply] = portList(a)
			}
			if len(got) != 2 || got[false] != "TCP/27017" || got[true] != "TCP/41234" {
				t.Fatalf("want the request alone on TCP/27017 and the reply apart on TCP/41234, got %v", got)
			}
		})
	}
	if aggs := AggregateFlows([]*flow.ParsedFlow{reply, reply}); len(aggs) != 1 || !aggs[0].IsReply {
		t.Fatalf("replies of one peer pair are one reply flow, got %d", len(aggs))
	}
}
