# CF2CNP Helm Chart

A Helm chart for deploying CF2CNP (Cilium Flow to CiliumNetworkPolicy) converter.

## Installation

### From OCI Registry

```bash
helm install cf2cnp oci://ghcr.io/onzack/helm-charts/cf2cnp --version <version>
```

## Configuration

The following table lists the configurable parameters of the CF2CNP chart and their default values.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `1` |
| `image.repository` | Image repository | `ghcr.io/onzack/cf2cnp` |
| `image.tag` | Image tag | `""` (defaults to appVersion) |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `imagePullSecrets` | Image pull secrets | `[]` |
| `nameOverride` | Override chart name | `""` |
| `fullnameOverride` | Override full name | `""` |
| `serviceAccount.create` | Create service account | `true` |
| `serviceAccount.annotations` | Service account annotations | `{}` |
| `serviceAccount.name` | Service account name | `""` |
| `podAnnotations` | Pod annotations | `{}` |
| `podSecurityContext` | Pod security context | `{}` |
| `securityContext` | Container security context | See values.yaml |
| `service.type` | Service type | `ClusterIP` |
| `service.port` | Service port | `80` |
| `containerPort` | Container port | `8080` |
| `externalURL` | Base URL clients reach cf2cnp at, for `download_url` (empty = derived from the request and its `Forwarded` / `X-Forwarded-Proto` / `X-Forwarded-Host` headers) | `""` |
| `cors.allowedOrigins` | Origins allowed by CORS (Grafana's, for the dashboard action); empty = any | `[]` |
| `auth.token`, `auth.existingSecret` | A bearer token required on `/generate` and `/download` (a Secret with key `token` preferred) | `""`, `""` |
| `networkPolicy.enabled`, `networkPolicy.fromEndpoints` | A CiliumNetworkPolicy for the pod: ingress from the Gateway (`reserved:ingress`), the kubelet (`reserved:host`) and the listed endpoints (add `io.kubernetes.pod.namespace` for another namespace), egress to kube-dns | `false`, `[]` |
| `extraArgs` | Extra arguments appended to `cf2cnp serve --port <containerPort>` | `[]` |
| `extraEnv` | Extra environment variables (`CF2CNP_EXTERNAL_URL` is an alternative to `externalURL`) | `[]` |
| `ingress.enabled` | Enable ingress | `false` |
| `ingress.className` | Ingress class name | `""` |
| `ingress.annotations` | Ingress annotations | `{}` |
| `ingress.hosts` | Ingress hosts configuration | See values.yaml |
| `ingress.tls` | Ingress TLS configuration | `[]` |
| `httpRoute.enabled` | Enable HTTPRoute (Gateway API) | `false` |
| `httpRoute.annotations` | HTTPRoute annotations | `{}` |
| `httpRoute.parentRefs` | Gateways the route is attached to | `[]` |
| `httpRoute.hostnames` | HTTPRoute hostnames | See values.yaml |
| `httpRoute.paths` | Path matches of the route | See values.yaml |
| `extraManifests` | Extra Kubernetes manifests to deploy | `[]` |
| `resources` | CPU/Memory resource requests/limits | `{}` |
| `nodeSelector` | Node selector | `{}` |
| `tolerations` | Tolerations | `[]` |
| `affinity` | Affinity rules | `{}` |
| `livenessProbe` | Liveness probe configuration | See values.yaml |
| `readinessProbe` | Readiness probe configuration | See values.yaml |

## Example

```bash
helm install cf2cnp ./helm/cf2cnp \
  --set replicaCount=2 \
  --set resources.limits.memory=256Mi \
  --set resources.requests.memory=128Mi
```

## Accessing the Service

After installation, you can access CF2CNP via port-forward:

```bash
kubectl port-forward svc/cf2cnp 8080:80
```

Then use the API:

```bash
curl -X POST http://localhost:8080/generate \
  -H "Content-Type: application/json" \
  -d @flow.json \
  -o policy.yaml
```
