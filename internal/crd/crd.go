// Package crd carries the CiliumNetworkPolicy CustomResourceDefinition of the Cilium version cf2cnp is built
// against — the schema its output must satisfy. The file is copied from the module cache by `go generate`
// (hack/copy-crd.sh), not imported: the upstream package that embeds it pulls the Kubernetes client machinery
// in (docs/CRD-SPEC-FORENSICS.md §3). CI checks the copy is byte-identical to the module's.
package crd

import (
	_ "embed"
	"strings"
)

//go:generate sh ../../hack/copy-crd.sh

//go:embed ciliumnetworkpolicies.yaml
var cnp string

//go:embed VERSION
var version string

// CiliumNetworkPolicy is the CRD YAML (apiextensions.k8s.io/v1) as shipped by Cilium at Version
func CiliumNetworkPolicy() string { return cnp }

// Version is the Cilium module version the CRD was copied from — the spec version this build supports
func Version() string { return strings.TrimSpace(version) }
