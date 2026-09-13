package flow

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The three fixtures are real Hubble 1.20 flows captured on a kind cluster: two INGRESS audit verdicts
// into the same workload from two peers, and one EGRESS flow to the world without destination_names.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseFlowsFromBytes_Single(t *testing.T) {
	flows, err := ParseFlowsFromBytes(fixture(t, "ingress-pos-to-shop.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 1 || flows[0].Direction != "INGRESS" || flows[0].Port != 80 || flows[0].DestLabels["app.kubernetes.io/name"] != "shop" {
		t.Fatalf("unexpected parse: %+v", flows[0])
	}
}

func TestParseFlowsFromBytes_NDJSON(t *testing.T) {
	// `hubble observe -o json` output: one object per line, blank lines and trailing newline included
	body := string(fixture(t, "ingress-pos-to-shop.json")) + "\n\n" + string(fixture(t, "ingress-stranger-to-shop.json")) + "\n"
	flows, err := ParseFlowsFromBytes([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 2 || flows[0].SourceLabels["app.kubernetes.io/name"] != "pos" || flows[1].SourceLabels["app.kubernetes.io/name"] != "stranger" {
		t.Fatalf("expected pos then stranger, got %d flows: %+v", len(flows), flows)
	}
}

func TestParseFlowsFromBytes_Array(t *testing.T) {
	body := "[" + string(fixture(t, "ingress-pos-to-shop.json")) + "," + string(fixture(t, "egress-pos-to-world.json")) + "]"
	flows, err := ParseFlowsFromBytes([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 2 || flows[1].Direction != "EGRESS" || !flows[1].IsWorldTraffic || flows[1].DestIP != "104.20.23.154" {
		t.Fatalf("unexpected: %+v", flows)
	}
}

func TestParseFlowsFromBytes_Errors(t *testing.T) {
	if _, err := ParseFlowsFromBytes([]byte("  \n")); err == nil {
		t.Fatal("empty input must error")
	}
	bad := string(fixture(t, "ingress-pos-to-shop.json")) + "\n{not json}\n"
	_, err := ParseFlowsFromBytes([]byte(bad))
	if err == nil || !strings.Contains(err.Error(), "flow #2") {
		t.Fatalf("the bad line must be named by position, got %v", err)
	}
}

func TestParseFlowsFromDirectory_ManyPerFile(t *testing.T) {
	dir := t.TempDir()
	ndjson := string(fixture(t, "ingress-pos-to-shop.json")) + "\n" + string(fixture(t, "ingress-stranger-to-shop.json")) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "observe.json"), []byte(ndjson), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "world.json"), fixture(t, "egress-pos-to-world.json"), 0o644); err != nil {
		t.Fatal(err)
	}
	flows, err := ParseFlowsFromDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 3 {
		t.Fatalf("expected 3 flows from 2 files, got %d", len(flows))
	}
}
