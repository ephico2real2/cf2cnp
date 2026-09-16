# cf2cnp Helm charts (fork ephico2real2/cf2cnp)

Charts released from the fork's `develop` branch by helm/chart-releaser-action; `index.yaml` is generated here.

    helm repo add cf2cnp-fork https://ephico2real2.github.io/cf2cnp

## Where a release lands

Every release of the fork is a **tag** `vX.Y.Z` on `develop`, pushed after `helm/cf2cnp/Chart.yaml` (`version`,
`appVersion`) and `CHANGELOG.md` were bumped in the same commit. A merge into `develop` alone runs only `ci.yml`
(vet, tests, the golden captures, the CRD check): the artefacts below are built by the tag, or — for this index —
by the bump commit's touch of `helm/**`. Measured for 0.8.0 (2026-09-16):

| Artefact | Workflow, its trigger | Where | Proof for 0.8.0 |
|---|---|---|---|
| Image | `docker-publish.yml` — tag push (or push to `main`) | `ghcr.io/ephico2real2/cf2cnp:<version>`, also `:<major>.<minor>`, `:<major>`, `:<sha>` | run 35061570383; manifest lists linux/amd64 + linux/arm64 |
| Chart, OCI | `helm-publish.yml` — tag push (or `helm/**` on `main`) | `oci://ghcr.io/ephico2real2/helm-charts/cf2cnp:<version>` | run 35061570406; `helm show chart … --version 0.8.0` → 0.8.0, digest `sha256:b748391…` |
| Chart, this index | `chart-releaser.yml` — `helm/**` changed on `develop`/`main` | `https://ephico2real2.github.io/cf2cnp/index.yaml`, the `.tgz` on release `cf2cnp-<version>` | run 35061568941; `index.yaml` entry `created 2026-09-16T05:57:05Z`, commit `a088437` |
| Binaries | `binary-release.yml` — tag `v*` | release `v<version>`: `cf2cnp_<version>_{linux,darwin}_{amd64,arm64}.tar.gz` + `cf2cnp_<version>_checksums.txt` | run 35061570394; published 2026-09-16T05:58:52Z, 5 assets |
| The gate | `ci.yml` — every push to `develop`/`main`, every PR | job summary: tests by package, the 14 golden captures, the CRD identity, `cf2cnp validate` over the goldens | run 35061568954 on `f00b9c6`, success |

So two GitHub releases exist per version: `cf2cnp-X.Y.Z` (the chart `.tgz`, made by chart-releaser) and `vX.Y.Z`
(the binaries and the notes). The consumer in the lab (`ephico2real2/cilium-implementation-poc`) pins the image tag
in `demos/25-hubble-observer-loki/values-hubble-observer.yaml` and the binary in `scripts/lab-policies.sh`
(`CF2CNP_VERSION`), verified against the checksums file.
