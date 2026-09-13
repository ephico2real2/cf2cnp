# Forensic analysis — cf2cnp's policy types against the CiliumNetworkPolicy spec of Cilium 1.20.x

Date: 2026-09-13. Branch `enh/E12-cilium-policy-api`. Every number below was measured on this machine
(Go 1.27.1, darwin/amd64); the probe programs are under `hack/cilium-api-probe/` so the measurements can be repeated.

## 1. The question

cf2cnp writes CiliumNetworkPolicies from hand-written Go types (`internal/policy/types.go`, 20 fields). Cilium's
CRD for `cilium.io/v2` `CiliumNetworkPolicy` at v1.20.1 has **291 schema paths** under `spec`
(`pkg/k8s/apis/cilium.io/client/crds/v2/ciliumnetworkpolicies.yaml`, 398 532 bytes). Each field cf2cnp does not
model is something it cannot write, cannot preserve on a round trip, and cannot say it supports. The operator's
finding that started this: a world **source** becomes `fromEntities` because there is no `fromCIDR`, while a
world **destination** becomes `toCIDR`. The question is not "add `fromCIDR`" but **how cf2cnp consumes the spec so
that a release can state which Cilium spec it supports, and the next field is not a hand-written struct**.

## 2. What cf2cnp models today, field by field, against the CRD

Legend for the last column — how the field could be filled: **flows** = derivable from what Hubble reports today;
**intent** = an operator option, never observed; **pass-through** = only preserved by `merge` (the YAML node edit),
never generated; **n/a** = not applicable to a namespaced policy.

### 2.1 `spec` — top level

| CRD field | cf2cnp today | Source of a value |
|---|---|---|
| `description` | yes (0.6.2: written from the rules) | generated |
| `endpointSelector.matchLabels` | yes | flows |
| `endpointSelector.matchExpressions` | **no** | pass-through; intent |
| `ingress[]` | partial (§2.2) | flows |
| `egress[]` | partial (§2.3) | flows |
| `ingressDeny[]`, `egressDeny[]` | **no** | intent — the natural home of `exclude=`: "the stranger is denied", not merely unlisted |
| `enableDefaultDeny.{ingress,egress}` | **no** | intent — would replace the separate default-deny policy every demo applies by hand |
| `labels[]` (Cilium's policy labels, not metadata labels) | **no** | pass-through |
| `log.value` | **no** | pass-through; intent |
| `nodeSelector` | **no** | n/a for CNP; CCNP for host flows (§6) |

### 2.2 An ingress rule (`spec.ingress[]`; `ingressDeny[]` has the same peers and ports, no L7)

| CRD field | cf2cnp today | Source of a value |
|---|---|---|
| `fromEndpoints[].matchLabels` | yes (namespace and cluster labels included) | flows |
| `fromEndpoints[].matchExpressions` | **no** | pass-through |
| `fromEntities[]` | yes (`host`+`remote-node` paired; any other entity, `world` included, written as itself — §2.5) | flows |
| `fromCIDR[]` | **no** — the finding (0.7.0: yes) | **flows**: a `reserved:world` source with an address (an egress-gateway IP, a load-balancer client, an office range) |
| `fromCIDRSet[].{cidr,except,cidrGroupRef,cidrGroupSelector}` | **no** | intent (`except`), pass-through |
| `fromRequires[]` | **no** | intent |
| `fromGroups[].aws` | **no** | n/a here |
| `fromNodes[]` | **no** | flows (`reserved:host` / `remote-node` when node selectors are enabled), later |
| `icmps[].fields[].{type,family}` | **no** | flows: Hubble reports `l4.ICMPv4` / `ICMPv6` type and code |
| `toPorts[].ports[].port` | yes | flows |
| `toPorts[].ports[].protocol` | yes | flows |
| `toPorts[].ports[].endPort` | **no** | intent |
| `toPorts[].rules.http[].{method,path}` | yes (0.6.0) | flows |
| `toPorts[].rules.http[].{host,headers,headerMatches}` | **no** | flows (the URL's host, the request headers) — `host` deliberately not narrowed today (review) |
| `toPorts[].rules.dns[]` | yes (0.6.0) | flows |
| `toPorts[].rules.kafka[]`, `l7proto`, `l7[]` | **no** | flows if Kafka visibility is on; not in this PoC |
| `toPorts[].{terminatingTLS,originatingTLS,serverNames,listener}` | **no** | intent, pass-through |
| `authentication.mode` | **no** | intent (mutual authentication is deprecated in 1.20) |

### 2.3 An egress rule (`spec.egress[]`)

| CRD field | cf2cnp today | Source of a value |
|---|---|---|
| `toEndpoints[]` | yes | flows |
| `toEntities[]` | yes | flows |
| `toCIDR[]` | yes | flows |
| `toCIDRSet[]` | **no** | intent |
| `toFQDNs[].{matchName,matchPattern}` | yes | flows (with the DNS proxy) |
| `toServices[].{k8sService,k8sServiceSelector}` | **no** | intent; Hubble flows are post-translation, the Service name is not on the flow |
| `toRequires[]`, `toGroups[]`, `toNodes[]` | **no** | intent / later |
| `icmps[]` | **no** | flows |
| `toPorts[]` | as ingress | flows |
| `authentication` | **no** | intent |

### 2.4 The count

Of the 291 schema paths, cf2cnp's types cover **20**. Of the rest, the ones a flow can fill are `fromCIDR`,
`icmps`, `fromNodes`/`toNodes`, HTTP `host`/`headers`, Kafka; the ones an operator's intent fills are the deny
lists, `enableDefaultDeny`, CIDR sets with `except`, `endPort`, `toServices`, TLS/SNI, `authentication`; the rest
must at least survive a `merge` — which the 0.6.1 node-based merge already guarantees for any field it does not
model, but which the *generator* cannot emit.

### 2.5 Two mis-modellings found while reading the parser

- **Retracted on implementation (2026-09-13):** an earlier revision of this note said a world source "produces no
  peer at all". Re-reading `generateEntityIngressRules` with the code open: its `else` branch writes
  `fromEntities: [<entity>]` for every entity that is not `host`/`remote-node`, so a world source produced
  `fromEntities: [world]` — any external address, wider than the one address observed, but not an empty peer list.
  The finding stands as first stated in the plan (`fromEntities` where `fromCIDR` was wanted); the "no peer" reading
  was wrong and is withdrawn.
- `Port.Protocol` is written as observed (`TCP`/`UDP`); nothing upper-cases a lower-case value. The CRD's enum is
  upper-case only (measured below: `"tcp"` is rejected by the schema).

## 3. Can cf2cnp consume Cilium's own spec? Measured

Three probe programs, `hack/cilium-api-probe/`, built against `github.com/cilium/cilium@v1.20.1`.

| Probe | Imports | `go get` + build | Binary | Modules | `replace` lines needed |
|---|---|---|---|---|---|
| cf2cnp 0.6.3 today | cobra, yaml.v3 | — | 11.6 MB | 9 | 0 |
| 1 — `pkg/policy/api` only, rendered with `sigs.k8s.io/yaml` | policy/api, sigs yaml | 16 s get, 19 s cold build | 17.6 MB | 309 | **0** |
| 2 — plus `pkg/k8s/apis/cilium.io/v2` (the typed object) and `…/client` (the embedded CRDs) | + k8s client machinery | 85 s build | **93.6 MB** | ~600 | 0 |
| 3 — `pkg/policy/api` + `k8s.io/apimachinery` `ObjectMeta` + the CRD **file** embedded with `go:embed` | policy/api, apimachinery meta, sigs yaml | 4 s incremental build | 18.1 MB | 310 | 0 |

Facts that fell out of the probes:

1. **Zero `replace` directives.** `github.com/cilium/cilium v1.20.1` resolves as a plain dependency; the module's Go
   requirement is **1.26.0** (cf2cnp's `go.mod` says 1.25.5 and must move to 1.26).
2. **Rendering with `sigs.k8s.io/yaml`** (JSON tags → YAML) gives the CRD's own shapes — `fromCIDR`, `toCIDRSet`,
   `enableDefaultDeny`, everything — with keys in alphabetical order, which is also `kubectl get -o yaml`'s order.
   The document `apiVersion, kind, metadata, spec` stays in that order (alphabetical); within `metadata`, `labels`
   comes before `name`. The 0.6.1 `merge` edits YAML nodes and does not care.
3. **`api.Rule.Sanitize()` is Cilium's own admission-time validation**, available as a library call. On the probes it
   caught a semantic rule no schema expresses: *"combining FromEndpoints and FromCIDR is not supported yet"* — a
   generated rule that mixed a pod peer and a CIDR peer would be refused by the agent. **But `Sanitize` mutates:** it
   rewrote selector keys with Cilium's internal source prefix (`any:app.kubernetes.io/name`), upper-cased the
   protocol, and filled `enableDefaultDeny` on the rule. It must run on a **`DeepCopy()`** and its errors reported;
   the original is what gets rendered. Measured on probe 2 (rendered after Sanitize: the prefix and the filled
   fields appeared) and probe 3 (rendered the original: clean).
4. **The CRD schema and `Sanitize` catch different things.** The schema (offline, `kubectl-validate --local-crds`
   with the embedded file) rejected `protocol: tcp` ("supported values: TCP, UDP, SCTP, VRRP, IGMP, GRE, IPIP, IPV6,
   ESP, AH, ANY") and accepted the `fromEndpoints`+`fromCIDR` rule; `Sanitize` accepted the lower-case protocol (it
   fixes it) and rejected the mixed rule. A release needs **both** layers.
5. **The CRD YAML is embedded in the module** (`pkg/k8s/apis/cilium.io/client/register.go`, `//go:embed
   crds/v2/ciliumnetworkpolicies.yaml`, `GetPregeneratedCRD`), but importing that package costs 75 MB of client
   machinery. Copying the **file** out of the module cache at `go generate` time and embedding it in cf2cnp costs
   0.5 MB and stays byte-identical to the module's, which CI can assert (`cmp` against
   `$(go list -m -f '{{.Dir}}' github.com/cilium/cilium)/pkg/k8s/apis/cilium.io/client/crds/v2/…`).
6. **The typed object `v2.CiliumNetworkPolicy` renders `status: {}`** (no `omitempty`); an envelope of
   `metav1.TypeMeta` + `metav1.ObjectMeta` + `*api.Rule` (probe 3) renders clean and costs nothing new — apimachinery
   is already in `policy/api`'s graph.
7. **The supported spec version is a build fact:** `debug.ReadBuildInfo()` yields `github.com/cilium/cilium v1.20.1`;
   `cf2cnp version` can print "CiliumNetworkPolicy `cilium.io/v2` as of Cilium v1.20.1", and the embedded CRD file's
   `metadata.annotations` / the module version in `go.mod` are the same number.

## 4. The design

**Replace `internal/policy/types.go` with Cilium's types.** `api.Rule`, `api.IngressRule`, `api.EgressRule`,
`api.PortRule`, `api.L7Rules`, `api.EndpointSelector` (built as `EndpointSelector{LabelSelector: &slimv1.LabelSelector{MatchLabels: …}}`,
never through the `NewES…` constructors, which prefix). One envelope struct in cf2cnp:

```go
type Policy struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata"`
    Spec              *api.Rule `json:"spec"`
}
```

**Two validation layers, both in the binary and in CI.** `Sanitize()` on a deep copy before anything is written or
served (an error is a 400 with Cilium's own message on `/generate`, an exit 1 on `generate`/`merge`); the CRD
schema, embedded from the module's file, checked in CI on every fixture and on the demos' policies with
`kubectl-validate --local-crds` (the E10 template's mechanism). The generator itself normalises what `Sanitize`
would only fix on the copy (protocol upper-case) so the rendered document is what the agent would accept.

**Rendering — researched.** `sigs.k8s.io/yaml` marshals Kubernetes types through JSON and orders keys alphabetically
(it "does not respect original mapping key order"); tools that write Kubernetes YAML for humans own a canonical order
instead — kustomize/kpt's `kyaml` formatter orders "commonly encountered Resource fields" by a precedence list and
sorts the rest lexicographically. cf2cnp does the same: marshal with `sigs.k8s.io/yaml`, load the JSON into a
`yaml.v3` node tree, re-order by a cf2cnp-owned precedence table (`apiVersion, kind, metadata{name, namespace, labels,
annotations}, spec{description, endpointSelector, nodeSelector, enableDefaultDeny, ingress, egress, ingressDeny,
egressDeny, labels, log}`; a rule's `from*`/`to*` before `toPorts`, `icmps`, `authentication`; a port's `port, endPort,
protocol`, then `rules`; unknown keys lexicographically), add the comment lines as node comments, encode with a 2-space
indent. Today's layout is preserved exactly, so the golden tests demand byte identity; `merge` is unchanged (nodes). Golden files: every policy under the PoC's
`demos/2[6-9]*/policies` and `demos/3*/policies` regenerated from its saved flows and diffed — the only accepted
differences are key order within `metadata` and the fields the new generator adds.

**The supported spec, announced.** `cf2cnp version` prints the tool's version and the Cilium API version; the
README carries a table "cf2cnp release → Cilium spec"; the chart's `appVersion` note names it; a Renovate/Dependabot
rule bumps `github.com/cilium/cilium` and CI re-embeds the CRD and re-runs the golden tests, so a Cilium release
becomes a cf2cnp release with a known diff.

**What becomes generatable, in order of value** (each its own branch, tests, and a review claim):

| Item | From | Notes |
|---|---|---|
| `fromCIDR` for a world source (the finding) | flows | one `/32` per observed source address; a `toCIDR`-style comment; never mixed with `fromEndpoints` in one rule (Cilium refuses it — the rule per peer class) |
| `enableDefaultDeny` as an option | intent | `--default-deny` writes `enableDefaultDeny: {ingress: true}` on ingress policies: the demos' separate default-deny object disappears |
| `ingressDeny` for excluded peers as an option | intent | `--deny-excluded`: an `exclude=` peer becomes a deny rule instead of an omission |
| `icmps` | flows | Hubble `l4.ICMPv4`/`ICMPv6`; `ping` between services is a rule today only by accident |
| HTTP `host` / `headers` as options | flows | off by default (the review's reasoning stands) |
| `fromNodes`/`toNodes`, CCNP with `nodeSelector` | flows | host-network callers; a second output kind |
| `toCIDRSet` with `except`, `endPort`, `toServices`, TLS/SNI, `authentication`, Kafka | intent / later | modelled by the types now, written by hand or preserved by `merge` |

## 5. Risks and their measurements

- **Dependency weight.** 9 → 310 modules, 11.6 → 18.1 MB. Measured; acceptable for a CLI and a small server. The
  k8s **client** packages are the line not to cross (93.6 MB); the CRD file is copied, not imported.
- **Go version.** The module needs Go 1.26; the Dockerfile and `binary-release.yml` (`go-version-file: go.mod`)
  follow `go.mod`.
- **Upstream cadence.** Cilium tags every few weeks; a cf2cnp release states the version it was built against, and
  a newer agent accepts an older spec (CRDs are versioned `v2` and only add fields).
- **Behaviour changes on the swap.** Caught by the golden tests over 40+ real policies from the demos; the review
  brief for E12 lists them as claims.

## 6. The DNS resolver rule — derived from flows, with platform profiles

Cilium's DNS-policy guide gives the resolver rule for Kubernetes and adds, verbatim: "OpenShift users will need to
modify the policies to match the namespace `openshift-dns` (instead of `kube-system`), remove the match on the
`k8s:k8s-app=kube-dns` label, and change the port to 5353." OpenShift's DNS operator runs CoreDNS as the DaemonSet
`dns-default` in `openshift-dns` listening on **5353** (`dns`/UDP, `dns-tcp`/TCP) behind the Service `dns-default:53`,
with the operator's own labels. cf2cnp hard-codes one rule (`kube-system`, `k8s-app: kube-dns`, `53/UDP`) in
`dnsVisibilityRule()` for both the `toFQDNs` path and `--dns-visibility`; on OpenShift that rule selects nothing
and the FQDN policy cuts the pod off from DNS.

Design: the resolver rule is **derived from the observed DNS flows** when the input has them (the destination pod's
namespace and identifying labels, the destination port and protocol as Hubble reports them; `ANY` when both UDP
and TCP were seen), and from a **profile** otherwise — `--dns-profile auto` (default: from the flows, else
`kubernetes`), `kubernetes` (the docs' rule, `53/ANY`), `openshift` (`openshift-dns`, no `k8s-app` label, `5353/ANY`),
and `--dns-resolver <namespace>[/<label>=<value>]:<port>` for any other resolver. The same value is used by
`?dnsProfile=` on the API and a selector on the page. The description names what was written. Fixtures: the
Kubernetes DNS flow from the PoC's demo 31 and a synthesised OpenShift flow (destination in `openshift-dns`, labels
`dns.operator.openshift.io/daemonset-dns=default`, port 5353).

## 7. Out of scope, noted

CiliumClusterwideNetworkPolicy shares the rule types (`api.Rule` with `nodeSelector`); emitting it for
`reserved:host` flows is a later item. `CiliumCIDRGroup` references (`cidrGroupRef`) and cloud `toGroups` are not
observable here. Kafka L7 needs a Kafka workload.
