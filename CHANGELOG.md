# Changelog — the fork's releases

Every release below was built for a Cilium 1.20.1 ClusterMesh lab and proven there before it was tagged; each row
names the demo of [cilium-implementation-poc](https://github.com/ephico2real2/cilium-implementation-poc) that
exercises it (its README quotes the recorded transcript, the Hubble verdicts and the screenshots), and the review
record where two independent reviewers (Cursor, Codex) went through the claims. The CI of this repository prints a
test summary on every push (the workflow's job summary): the unit tests by package, the 14 golden captures that must
answer byte for byte, the CRD check, and `cf2cnp validate` over every golden output.

## Unreleased

- **Structured logging** on the HTTP server (`log/slog`, no extra library): `--log-format` (`text` / `json`, env
  `CF2CNP_LOG_FORMAT`) and `--log-level` (`debug` / `info` / `warn` / `error`, env `CF2CNP_LOG_LEVEL`); one `listening`
  line at start (addr, version, log_format, log_level, auth_enabled, allowed_origins, dns_profile, dns_resolver — never
  the token); one `request` line per call with a request id (`X-Request-Id` echoed when it is 1–128 of `[A-Za-z0-9._-]`,
  otherwise minted) and `params` (query parameter names only, never values) when the URL has a query; refusals log a
  `reason`. `/health` is at debug so kubelet probes stay quiet at info. No token, no Authorization header, no cookies,
  no request body.
- **Download's three answers:** `200` while the policy is cached (10 minutes), `410 Gone` once it has expired (the
  generated-at time is in the body; a tombstone is kept 1 hour so the id is not a silent 404), `404` when nothing was
  generated under the id.
- **Chart:** `logging.format` / `logging.level` (json by default in the chart, for a container).

## 0.8.0 — 2026-09-16 · the API page as a Swagger-like surface

- The build's version beside the logo: `main.version` reaches the server through `Options.Version`; `displayVersion`
  normalises the three build shapes (`0.8.0` → `v0.8.0`, a 40-hex sha → its first 12 chars, nothing → `dev`).
- Each endpoint is a `<details>` card whose method + path row unfolds a Try-it-out panel: `/generate` carries the form
  (controls unchanged; the example is loaded when the card unfolds with an empty box), `/download/{id}` an id filled
  from the last generate's `download_url` with Send and an open-in-a-new-tab link, `/health` a Send — each panel shows
  HTTP status · ms · content-type and the body. Checkboxes inline with their labels; the curl example on the page's
  own base URL (`baseURL(r)`) instead of localhost:8080. Hover/focus-within transitions, a `:focus-visible` ring, no
  horizontal overflow at 390 px.
- From the two review passes ([docs/REVIEW_API-PAGE.md](docs/REVIEW_API-PAGE.md)): the version and the base URL
  HTML-escaped at the sink (`X-Forwarded-Host: <svg>` had been served as markup); the download id is one path segment
  of `[A-Za-z0-9_-]` — `validDownloadID` on the id the server mints, on `/download/{id}` (404 otherwise) and in the
  panel; a new generate clears the previous download panel; the new-tab link is hidden when a token is in the field (a
  navigation carries no bearer header); the card states the cache's real lifetime, 10 minutes (`cleanupCache`).
- Fork PR #3 (develop). Twelve tests added in `internal/server/server_test.go`. No change to the CLI, the API
  contract, or the generated policies: the 14 golden captures answer byte for byte.

## 0.7.0 — 2026-09-13 · Cilium's own policy types, validated the way the agent validates

- **The policy document is `github.com/cilium/cilium/pkg/policy/api` at the pinned Cilium version (v1.20.1).** Every
  field of the CiliumNetworkPolicy spec exists (the 0.6.x hand-written structs modelled 20 of the schema's 291
  paths); rendering keeps cf2cnp's field order through a precedence table (the kustomize/kyaml pattern); the CRD of
  the same version is embedded and CI compares it byte for byte with the module's; `cf2cnp version` prints the spec
  version the build supports. Output for the 14 recorded captures is byte-identical to 0.6.3 except two deliberate
  changes named in `internal/testdata/golden/README.md`.
- **Validation:** Cilium's own `Sanitize()` on every generated policy (on a copy — the file stays as a user writes
  it), plus the object's checks: ObjectMeta (DNS-1123 names, label keys), the CRD's protocol enum, `apiVersion` and
  `kind`, no `nodeSelector` on a namespaced policy, no namespace on a clusterwide one, `specs` rule by rule. A
  refusal is a 400 on the API and exit 1 on the CLI. New: `cf2cnp validate <files…>`.
- **`fromCIDR` for external sources:** an ingress flow from `reserved:world` (or `world-ipv4` / `world-ipv6` on a
  dual-stack cluster) with an address becomes `fromCIDR: [<addr>/32]` (`/128` IPv6), what the receiver saw, instead
  of `fromEntities: [world]`.
- **The DNS resolver rule from the flows:** the rule `toFQDNs` and `--dns-visibility` need names the resolver the
  workload actually asked — kube-dns by `k8s-app`, the CoreDNS Helm chart by `app.kubernetes.io/name`, NodeLocal
  DNSCache, OpenShift's `openshift-dns` on 5353 without a label (Cilium's DNS guide) — on protocol `ANY`, as Cilium's
  examples write it (a truncated UDP answer retries over TCP). Profiles `--dns-profile auto|kubernetes|openshift`,
  any resolver with `--dns-resolver <ns>[/<label>=<v>]:<port>[/<proto>]`, the same on the API (`?dnsProfile=`,
  `?dnsResolver=`), the page, and as a cluster-wide default on `serve` and in the chart (`dns.profile`,
  `dns.resolver`, `networkPolicy.dnsEgress`).
- **`merge --l7`**, the flag the policy-PR template already passed.
- **Chart 0.7.0:** the DNS values above; the chart's own policy's DNS egress follows the profile and refuses to
  render when a custom resolver is named without a matching `dnsEgress`.
- Fixed: an IPv6 world peer got a `/32`; a dual-stack world peer was neither world nor an entity (an egress to it
  produced no peer at all); the hard-coded kube-dns `53/UDP` rule selected nothing on OpenShift and with the CoreDNS
  Helm chart and denied the TCP retry; a `specs`-only document was accepted as empty and merged into silently.
- Tests: 104 (46 at 0.6.3); the goldens; `kubectl-validate` over every golden in CI; the dependency guard (no
  Kubernetes client machinery, a 40 MB ceiling). Reviews: two passes,
  [REVIEW_ENH-003](https://github.com/ephico2real2/cilium-implementation-poc/blob/main/docs/REVIEW_ENH-003.md);
  forensics: [docs/CRD-SPEC-FORENSICS.md](docs/CRD-SPEC-FORENSICS.md). Demos: 35 (regenerated), the policy-PR
  template on 0.7.0.

## 0.6.3 — 2026-09-13 · descriptions from the rules

- The description names its subject the way it names the peers (name / component / instance from the selector), the
  peer's namespace or cluster when it differs, the ports and L7 rules; cut with "and N more" past six peers
  (0.6.2 wrote it from the rules; 0.6.3 named the subject). Demo 35 Part 4.

## 0.6.1 — 2026-09-13 · merge keeps the file as it was

- `merge` edits the YAML node tree: key order, comments, quoting and indentation kept, so a pull request shows the
  added rule only (0.6.0 re-serialised the whole file). One kube-dns rule when a pod's own lookups plus the
  DNS-visibility rule met. Demo 32 Part 2b, demo 31 Part 1.

## 0.6.0 — 2026-09-12 · enhancement 001, the enterprise set

- Cluster-aware selectors for ClusterMesh flows (`io.cilium.k8s.policy.cluster`, demo 29); layer-7 rules from flows
  that carry them, one port rule per port (demo 30); DNS visibility on demand (demo 31); review before generating
  with `?exclude=` and the page's peer checklist (demo 32); `cf2cnp merge` (demo 32); CORS allow-list, a bearer
  token, a CiliumNetworkPolicy for the pod (demo 33); release binaries for every `v*` tag (demo 32 Part 0).
  Review: [REVIEW_ENH-001](https://github.com/ephico2real2/cilium-implementation-poc/blob/main/docs/REVIEW_ENH-001.md).

## 0.5.1 — 2026-09-12

- A `{}` body is refused; the proxy's `Forwarded` host is sanitised (review findings).

## 0.5.0 — 2026-09-12 · the first fork release

- `download_url` correct behind a TLS-terminating proxy (`--external-url`, `Forwarded`, `X-Forwarded-*` — the bug
  of upstream #2); many flows per request merged per workload; policy names that cannot collide (a function of the
  whole selector); `app.kubernetes.io/managed-by: cf2cnp` and the selector's labels on every policy; `?name=`.
  Demos 26 and 27.
