# CF2CNP - Cilium Flow to CiliumNetworkPolicy

A CLI tool that generates CiliumNetworkPolicies from Hubble flow data. This tool analyzes network traffic patterns captured by Hubble and automatically creates corresponding Cilium network policies.

## Features

- **Automatic Policy Generation**: Reads Hubble flow JSON files and generates CiliumNetworkPolicy YAML files
- **Smart Label Filtering**: Extracts only relevant app labels (see [label Selection](#label-selection))
- **Cross-Namespace Support**: Automatically adds namespace labels for cross-namespace traffic
- **FQDN Egress Support**: Generates proper `toFQDNs` rules with required DNS resolution rules for external traffic
- **Flow Aggregation**: Combines multiple flows with the same source/destination into a single policy with multiple ports, and flows that select the same workload into one policy with one rule per peer (so two peers of one service are one object, not two objects with the same name)
- **Many Flows at Once**: A file, a request body or a pasted text may hold one flow, a JSON array of flows, or one flow per line — the output of `hubble observe -o json`
- **HTTP Server Mode**: Run as a containerized service to generate policies via HTTP API

> **Caution:** This project was created with the help of AI. While I have extensive experience with Kubernetes and Cilium, I do not have the Go programming expertise to write this tool from scratch. AI assistance made it possible to bring this idea to life and share it with the community. Please be careful when using this tool in production environments. Always review generated policies before applying them to your cluster.

## Binaries

Every `v*` tag publishes `cf2cnp_<version>_<os>_<arch>.tar.gz` (linux and darwin, amd64 and arm64) with a
checksums file on the tag's GitHub release, for pipelines that run `cf2cnp merge` without a Go toolchain:

```bash
curl -sSL -o cf2cnp.tgz https://github.com/ephico2real2/cf2cnp/releases/download/v0.6.0/cf2cnp_0.6.0_linux_amd64.tar.gz
tar -xzf cf2cnp.tgz && sudo install cf2cnp /usr/local/bin/cf2cnp
```

## Building

Clone the repository and build the binary:

```bash
# Clone the repository
git clone <repository-url>
cd cf2cnp

# Build the binary
go build -o cf2cnp ./cmd/cf2cnp

# Or on Windows
go build -o cf2cnp.exe ./cmd/cf2cnp
```

## Installation

> **Fork note (ephico2real2/cf2cnp):** while the changes on this fork are pending upstream, the fork's chart is published as a
> classic Helm repository at `https://ephico2real2.github.io/cf2cnp` (chart 0.6.1, appVersion 0.6.1) and its image as
> `ghcr.io/ephico2real2/cf2cnp:0.6.1`. `helm repo add cf2cnp-fork https://ephico2real2.github.io/cf2cnp`.

The easiest way to use `CF2CNP` is to deploy it together with the [hubble-observer Helm chart](https://github.com/onzack/hubble-observer). This chart installs both the Hubble observer (to collect network flow data) and `CF2CNP` into your Kubernetes cluster, so you can generate policies directly from observed traffic. You can find installation instructions and configuration options for the Helm chart in the [hubble-observer Helm chart repository](https://github.com/onzack/hubble-observer).

## Usage

The tool supports two modes of operation:

### 1. File-based Generation (CLI Mode)

Generate policies from flow files in a directory:

```bash
cf2cnp generate --input <input-directory> --output <output-directory>
```

#### Flags

| Flag        | Short | Description                                            | Required |
|-------------|-------|--------------------------------------------------------|----------|
| `--input`   | `-i`  | Directory containing Hubble flow JSON files            | Yes      |
| `--output`  | `-o`  | Directory for generated CiliumNetworkPolicy YAML files | Yes      |

#### Example

```bash
# Generate policies from an folder with Cilium flows in it.
cf2cnp generate --input ./inputfolder --output ./generated-policies
```

### 1b. Merge into an existing policy (CLI)

Evolve a policy that is already applied instead of regenerating it — every field of the existing document
survives (`ingressDeny`, annotations, …), only rules that are not there yet are added, and running it
twice changes nothing:

```bash
cf2cnp merge --existing policies/shop.yaml --input flows.json          # in place
cf2cnp merge --existing policies/shop.yaml --input flows/ -o new.yaml  # to another file
```

The merged file is the existing file plus the new rules — key order, comments, quoting and indentation are kept, so a pull
request shows the rules that were added and nothing else (0.6.1; 0.6.0 re-serialised the whole document).

```bash
```

The flows must produce exactly one policy, for the same target (namespace, name, endpointSelector) as the
existing file; otherwise the command refuses.

### 2. HTTP Server Mode

Start an HTTP server to generate policies via API:

```bash
cf2cnp serve --port 8080
```

#### Server Flags

| Flag             | Short | Type   | Description                                                                                                                                                           | Default |
|------------------|-------|--------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------|
| `--port`         | `-p`  | int    | Port number to listen on                                                                                                                                              | `8080`  |
| `--external-url` |       | string | Base URL clients reach the server at, used for `download_url` (env `CF2CNP_EXTERNAL_URL`). Empty: derived from the request and its `Forwarded` / `X-Forwarded-Proto` / `X-Forwarded-Host` headers | `""`    |

---

#### API Endpoints

| Method | Endpoint       | Description                                              | Request Body                  | Response            |
|--------|---------------|-----------------------------------------------------------|-------------------------------|---------------------|
| `POST` | `/generate`   | Generate policies from Hubble flow JSON: one flow, a JSON array, or one flow per line. `?name=<name>` names the (single) resulting policy | Hubble flow JSON | CiliumNetworkPolicy YAML (one document per policy), or JSON when the request carries `Accept: application/json` or `X-Grafana-Action` |
| `GET`  | `/download/{id}` | Download a policy generated by a JSON-mode request (cached for 10 minutes; `{id}` is the flow's UUID for a single flow) | _none_ | CiliumNetworkPolicy YAML as an attachment |
| `GET`  | `/health`     | Health check for the service                              | _none_                        | Status message      |
| `GET`  | `/`           | Access the integrated Web UI for testing and generation   | _none_                        | Web UI page         |

The JSON answer is `{"download_url", "filename", "message", "flows", "policies", "yaml"}` — the YAML is in it, so a client
need not follow the URL. `download_url` is built from `--external-url` when set, else from the request and the proxy
headers a TLS-terminating ingress or gateway sets (`Forwarded: proto=…;host=…`, `X-Forwarded-Proto`, `X-Forwarded-Host`).

#### Example: Using curl

```bash
# Generate a policy from a flow file
curl -X POST http://localhost:8080/generate \
  -H "Content-Type: application/json" \
  -d @flow.json \
  -o policy.yaml

# Many flows at once (the output of `hubble observe -o json`): one policy per workload, one rule per peer
hubble observe --namespace shop --last 200 -o json > flows.json
curl -X POST http://localhost:8080/generate --data-binary @flows.json -o policies.yaml

# Name the resulting policy yourself
curl -X POST "http://localhost:8080/generate?name=shop-from-pos" -d @flow.json -o policy.yaml
```

#### Example: Using the Web UI

Open `http://localhost:8080` in your browser to access the web interface where you can paste flow JSON and download the generated policy.

## Docker Deployment

### Build the Docker image

```bash
docker build -t cf2cnp .
```

### Run the container

```bash
docker run -p 8080:8080 cf2cnp serve
```

The server will be available at `http://localhost:8080`.

## Input Format

The tool expects Hubble flow data in JSON format. Each file should contain a single flow object with the following structure:

```json
{
  "flow": {
    "traffic_direction": "INGRESS",
    "source": {
      "namespace": "source-namespace",
      "labels": ["k8s:app.kubernetes.io/name=source-service", "k8s:app.kubernetes.io/component=source-component"]
    },
    "destination": {
      "namespace": "destination-namespace",
      "labels": ["k8s:app.kubernetes.io/name=source-service"]
    },
    "destination_names": ["onzack.com"],
    "l4": {
      "TCP": {
        "destination_port": 80
      }
    }
  }
}
```

### Collecting Flows from Hubble

You can export flows from Hubble using the Hubble CLI:

```bash
# Observe flows and save to JSON
hubble observe --output json > flows.json

# Or filter for specific traffic
hubble observe --namespace my-namespace --output json > my-flows.json
```

## Output Format

The generated CiliumNetworkPolicy files follow the [Cilium Network Policy specification](https://docs.cilium.io/en/stable/security/policy/language/).

### Ingress Policy Example

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: destination-service
  namespace: destination-namespace
spec:
  description: Allow ingress traffic from source-namespace to destination-namespace for the destination-service
  endpointSelector:
    matchLabels:
      app.kubernetes.io/component: destination-component
      app.kubernetes.io/name: destination-service
  ingress:
    - fromEndpoints:
        - matchLabels:
            app.kubernetes.io/name: source-service
            io.kubernetes.pod.namespace: source-namespace
      toPorts:
        - ports:
            - port: "80"
              protocol: TCP
```

### Egress Policy with FQDN Example

For external traffic (to "world"), the tool automatically includes DNS resolution rules:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: source-service
  namespace: source-namespace
spec:
  description: Allow egress traffic from source-namespace to onzack.com for the source-service
  endpointSelector:
    matchLabels:
      app.kubernetes.io/name: source-service
  egress:
    - toFQDNs:
        - matchName: onzack.com
      toPorts:
        - ports:
            - port: "443"
              protocol: TCP
    # DNS resolution rule (required for toFQDNs to work)
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: kube-system
            k8s-app: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: UDP
          rules:
            dns:
              - matchPattern: '*'
```

## Easter Egg: YOLO Mode

For those times when you just need to get things working in development, CF2CNP includes a YOLO mode that generates a policy allowing all traffic within a namespace.

### CLI Usage

```bash
# Generate a YOLO policy for the default namespace
cf2cnp yolo ns

# Generate a YOLO policy for a specific namespace
cf2cnp yolo ns --namespace my-dev-namespace
```

### API Usage

Send a POST request with the body `yolo ns <namespace>`:

```bash
# YOLO policy for the default namespace
curl -X POST http://localhost:8080/generate \
  -d "yolo ns" \
  -o yolo-policy.yaml

# YOLO policy for a specific namespace
curl -X POST http://localhost:8080/generate \
  -d "yolo ns my-dev-namespace" \
  -o yolo-policy.yaml
```

### Generated Policy

The YOLO policy allows all ingress and egress traffic within the specified namespace:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: yolo-allow-all-in-namespace
  namespace: my-dev-namespace
spec:
  description: YOLO! Allow all traffic within the my-dev-namespace namespace.
  endpointSelector:
    matchLabels: {}
  ingress:
    - fromEndpoints:
        - matchLabels: {}
  egress:
    - toEndpoints:
        - matchLabels: {}
```

## Label Selection

The tool filters labels to keep policies clean and maintainable:

1. **Priority Labels** (used if present):
   - `app.kubernetes.io/name`
   - `app.kubernetes.io/component`
   - `app.kubernetes.io/instance`

2. **Fallback Label** (used if no priority labels exist):
   - `app`
   - `k8s-app`
   - `name`
   - `component`
   - `instance`

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.
