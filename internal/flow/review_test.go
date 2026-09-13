package flow

import "testing"

// Review ENH-003 (Cursor): on a dual-stack Cilium (both address families enabled) the world identity is not 2
// (reserved:world) but 9 (reserved:world-ipv4) or 10 (reserved:world-ipv6) — pkg/labels/cidr.go getWorldLabel,
// pkg/identity/numericidentity.go GetWorldIdentityFromIP at v1.20.1. Both are "world" to a policy (the world entity
// covers all three, NumericIdentity.IsWorld), so both are world to the parser: an egress to them is world traffic
// with an address, an ingress from them carries the source address for fromCIDR.
func TestParse_DualStackWorldLabels(t *testing.T) {
	egress, err := ParseFlowsFromBytes(fixture(t, "egress-pos-to-world-ipv4.json"))
	if err != nil || len(egress) != 1 {
		t.Fatalf("parse: %d %v", len(egress), err)
	}
	if e := egress[0]; !e.IsWorldTraffic || e.DestEntity != "world" || e.DestIP != "104.20.23.154" || e.Direction != "EGRESS" {
		t.Fatalf("reserved:world-ipv4 must be world traffic with its address: %+v", e)
	}
	ingress, err := ParseFlowsFromBytes(fixture(t, "ingress-world-ipv4-cidr-to-receiver.json"))
	if err != nil || len(ingress) != 1 {
		t.Fatalf("parse: %d %v", len(ingress), err)
	}
	if i := ingress[0]; i.SourceIP != "172.18.255.170" || i.SourceEntity != "world" {
		t.Fatalf("a reserved:world-ipv4 source must keep its address and be the world entity: %+v", i)
	}
	for _, l := range []string{"reserved:world", "reserved:world-ipv4", "reserved:world-ipv6"} {
		if !isWorldTraffic([]string{l}) || getReservedEntity([]string{l}) != "world" {
			t.Fatalf("%s is world", l)
		}
	}
}
