# Golden fixtures

One directory per case: `flows.ndjson` (a Hubble capture from the PoC's demos, verbatim), `options.json` (the
`/generate` query parameters used), and `expected.yaml` — the multi-document answer **cf2cnp 0.6.3** gave for that
input, captured through `serve` on 2026-09-13. `TestGolden` in `internal/policy` asserts the current code reproduces
every `expected.yaml` byte for byte; a deliberate change of output regenerates the file in the same commit and says why.
Regenerate with `hack/golden/regenerate.sh <binary>`.

## Deliberate differences from 0.6.3

- `31-pos-egress-cidr` (regenerated with 0.7.0): 0.6.3 printed the "The DNS rule below turns the DNS proxy on …"
  comment under the CIDR whenever the document mentioned `k8s-app: kube-dns` — here that was the **plain** 53/UDP rule
  the pod's own lookup produced, which turns no proxy on. The comment is now tied to an actual `rules.dns` block.
- `31-pos-fqdn`, `31-pos-dns-visibility` (regenerated on the review of 0.7.0, Codex C9): the resolver rule's
  protocol is `ANY`, not the observed `UDP` — a lookup whose UDP answer is truncated retries over TCP, and the
  UDP-only rule 0.6.3 wrote denies that retry under default-deny egress. Cilium's own examples write `ANY`. The
  description says `ANY/53`.
