package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hubble-policy-gen/internal/aggregator"
	"github.com/hubble-policy-gen/internal/flow"
	"github.com/hubble-policy-gen/internal/policy"
)

// Review (Codex P2): `merge` wrote the merged document without the run's warnings — the policy-PR template keeps the
// file, not the terminal. The output opens with the block; merging the same flows again changes nothing.
func TestRunMerge_OutputCarriesWarnings(t *testing.T) {
	oldInput, oldExisting, oldOutput, oldProfile := inputDir, existingFile, outputFile, dnsProfile
	t.Cleanup(func() { inputDir, existingFile, outputFile, dnsProfile = oldInput, oldExisting, oldOutput, oldProfile })
	inputDir = filepath.Join("..", "..", "internal", "testdata", "edge-ingress-to-api-gateway.json")
	existingFile = filepath.Join(t.TempDir(), "existing.yaml")
	outputFile = filepath.Join(t.TempDir(), "merged.yaml")
	dnsProfile = "auto"
	raw, err := os.ReadFile(inputDir)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := flow.ParseFlowsFromBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	ps, err := policy.NewGenerator("").BuildPolicies(aggregator.AggregateFlows(fs))
	if err != nil {
		t.Fatal(err)
	}
	existing, err := policy.EncodePolicies(ps) // the policy as a PR would hold it, without the comment
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(existingFile, existing, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runMerge(nil, nil); err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(outputFile)
	if err != nil || !strings.HasPrefix(string(out), "# WARNING: 1 flow(s) skipped, no generated policy covers them:\n# - EGRESS flow from reserved:ingress") {
		t.Fatalf("merge output must open with the run's warning: %v\n%s", err, out)
	}
	existingFile = outputFile
	if err := runMerge(nil, nil); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(outputFile); !bytes.Equal(again, out) {
		t.Fatalf("merging the same flows again must change nothing:\n%s", again)
	}
}
