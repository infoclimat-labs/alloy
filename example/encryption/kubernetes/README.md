# Run the forked Alloy in a Kubernetes cluster

This guide deploys the Alloy image of this fork, which contains
`otelcol.processor.encryption`, with the official `grafana/alloy` Helm chart.

## Images

The fork CI (`.github/workflows/encryption-poc.yml`) publishes two
multi-architecture images (amd64, arm64) after the tests and the end-to-end
demo pass on the `feat/otelcol-processor-encryption` branch:

| Image                                         | Content                                                     |
| --------------------------------------------- | ----------------------------------------------------------- |
| `ghcr.io/infoclimat-labs/alloy:encryption-poc` | Alloy built from the repository `Dockerfile` (web UI included). |
| `ghcr.io/infoclimat-labs/otelcrypt:encryption-poc` | The `otelcrypt` tool, with `curl` and `jq`.             |

Each image is also tagged `encryption-poc-<commit>`. Pin that tag, or the
digest, so a test cluster doesn't change under you.

GHCR packages of an organization are private by default. Either make them
public in the package settings on GitHub, or create a pull secret in the
cluster and set `image.pullSecrets` in `values.yaml`:

```shell
kubectl -n monitoring create secret docker-registry ghcr-pull \
  --docker-server=ghcr.io --docker-username=<github-user> \
  --docker-password=<token-with-read:packages>
```

## Keys

Generate the keys on the workstation of the control authority, not in the
cluster:

```shell
mkdir keys && cd keys
alias otelcrypt='docker run --rm -u "$(id -u)" -v "$PWD:/w" -w /w ghcr.io/infoclimat-labs/otelcrypt:encryption-poc'
for k in business technical escrow; do otelcrypt keygen -private $k.key -public $k.pub; done
otelcrypt keygen -signing -private signing.key -public signing.pub
```

Keep `business.key`, `technical.key` and `escrow.key` with their owners, for
example in an HSM or an offline vault. The cluster only receives the public
keys and Alloy's signing key:

```shell
kubectl -n monitoring create secret generic alloy-encryption-keys \
  --from-file=business.pub --from-file=technical.pub --from-file=escrow.pub \
  --from-file=signing.key
```

Give `signing.pub` to whoever verifies decrypted records
(`otelcrypt decrypt -verify-key signing.pub -require-signature`).

## Deploy

Edit the Tempo and Loki endpoints at the end of `values.yaml`, then:

```shell
helm repo add grafana https://grafana.github.io/helm-charts
helm upgrade --install alloy-encryption grafana/alloy -n monitoring -f values.yaml
kubectl -n monitoring rollout status deploy/alloy-encryption
```

Point the OTLP exporters of your agents to the service, for example
`http://alloy-encryption.monitoring.svc.cluster.local:4318`.

`values.yaml` sets `alloy.stabilityLevel: experimental`: without it, Alloy
refuses to start because `otelcol.processor.encryption` is experimental.

## Backends

- **Tempo truncates attribute values to 2048 bytes by default**, which
  corrupts encrypted values and wrapped keys. Set `max_attribute_bytes: 0` in
  the distributor configuration of Tempo, or a value larger than your largest
  prompt.
- **Loki** stores log attributes as structured metadata. Check that
  structured metadata is enabled and that its size limits fit your prompts.

## Check

Send a trace through Alloy, then, on the control workstation:

```shell
curl -s "http://<tempo>/api/traces/<trace-id>" > trace.json
grep -c 'enc:v1:' trace.json        # encrypted values stored in Tempo
otelcrypt inspect -in trace.json
otelcrypt decrypt -key escrow.key -verify-key signing.pub -require-signature \
  -reason "test of the encryption pipeline" -in trace.json
```

The Alloy UI (port 12345, `kubectl port-forward`) shows the
`otelcol.processor.encryption` component and its debug metrics, such as
`otelcol_processor_encryption_values_encrypted_total`.
