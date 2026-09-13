#!/usr/bin/env bash
# copy-crd.sh — copy the CiliumNetworkPolicy CRD of the Cilium module pinned in go.mod into internal/crd/, where it is
# embedded into the binary (`cf2cnp version` names it; CI validates every golden output against it). Copying the FILE
# costs 0.4 MB; importing the package that embeds it upstream drags the Kubernetes client machinery in (measured:
# 18 MB → 94 MB, docs/CRD-SPEC-FORENSICS.md §3). Run by `go generate ./internal/crd`; CI asserts the copy is identical.
set -euo pipefail; cd "$(dirname "$0")/.."
DIR=$(go list -m -f '{{.Dir}}' github.com/cilium/cilium)
VERSION=$(go list -m -f '{{.Version}}' github.com/cilium/cilium)
cp "$DIR/pkg/k8s/apis/cilium.io/client/crds/v2/ciliumnetworkpolicies.yaml" internal/crd/ciliumnetworkpolicies.yaml
chmod u+w internal/crd/ciliumnetworkpolicies.yaml
printf '%s\n' "$VERSION" > internal/crd/VERSION
echo "internal/crd/ciliumnetworkpolicies.yaml <- cilium $VERSION"
