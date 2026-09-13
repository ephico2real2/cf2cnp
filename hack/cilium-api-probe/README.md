# cilium-api-probe

The measurement behind `docs/CRD-SPEC-FORENSICS.md` §3: a separate module (so the main module's dependencies are
untouched) that builds against `github.com/cilium/cilium@v1.20.1`'s `pkg/policy/api`, renders a rule with
`sigs.k8s.io/yaml`, runs Cilium's own `Rule.Sanitize()` on a deep copy, and embeds the CRD file copied from the module
cache. Run it and validate its output against the same CRD offline:

```bash
cd hack/cilium-api-probe && go build -o probe . && ./probe
go run sigs.k8s.io/kubectl-validate@v0.0.4 --local-crds ./crd <a file holding the rendered document>
```

The copy of `crd/ciliumnetworkpolicies.yaml` must stay byte-identical to the module's:

```bash
cmp crd/ciliumnetworkpolicies.yaml "$(go list -m -f '{{.Dir}}' github.com/cilium/cilium)/pkg/k8s/apis/cilium.io/client/crds/v2/ciliumnetworkpolicies.yaml"
```
