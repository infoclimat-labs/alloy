---
canonical: https://grafana.com/docs/alloy/latest/reference/components/otelcol/otelcol.processor.encryption/
description: Learn about otelcol.processor.encryption
labels:
  stage: experimental
  products:
    - oss
title: otelcol.processor.encryption
---

# `otelcol.processor.encryption`

{{< docs/shared lookup="stability/experimental.md" source="alloy" version="<ALLOY_VERSION>" >}}

`otelcol.processor.encryption` encrypts selected span attributes, span event attributes, log attributes, and log bodies with public-key encryption.
The encryption is reversible: holders of a matching private key can restore the original values outside of the telemetry pipeline.
{{< param "PRODUCT_NAME" >}} only needs the public keys, so it can't decrypt the data it encrypts.

Use `otelcol.processor.encryption` to keep the content of telemetry, such as prompts and tool payloads of generative AI applications, confidential, while metadata such as model names, token counts, durations, and errors stays in clear text for monitoring.

You can specify multiple `otelcol.processor.encryption` components by giving them different labels.

## Usage

```alloy
otelcol.processor.encryption "<LABEL>" {
  rule {
    recipients = ["<PUBLIC_KEY_PEM>", ...]
    attributes = ["<ATTRIBUTE_KEY>", ...]
  }

  output {
    logs   = [...]
    traces = [...]
  }
}
```

## Arguments

You can use the following arguments with `otelcol.processor.encryption`:

| Name       | Type     | Description                                         | Default    | Required |
| ---------- | -------- | --------------------------------------------------- | ---------- | -------- |
| `on_error` | `string` | What to do with a value that can't be encrypted.    | `"delete"` | no       |

`on_error` accepts the following values:

* `delete`: Remove the attribute, or empty the log body, so that the plaintext never leaves {{< param "PRODUCT_NAME" >}}.
* `reject`: Fail the whole batch and return the error to the previous component.

{{< param "PRODUCT_NAME" >}} never forwards a value in clear text when encryption fails.

## Blocks

You can use the following blocks with `otelcol.processor.encryption`:

| Block                            | Description                                                                | Required |
| -------------------------------- | -------------------------------------------------------------------------- | -------- |
| [`output`][output]               | Configures where to send received telemetry data.                          | yes      |
| [`rule`][rule]                   | Selects values to encrypt and the keys that can decrypt them.              | yes      |
| [`debug_metrics`][debug_metrics] | Configures the metrics that this component generates to monitor its state. | no       |
| [`key_rotation`][key_rotation]   | Configures the rotation of data encryption keys.                           | no       |

[output]: #output
[rule]: #rule
[debug_metrics]: #debug_metrics
[key_rotation]: #key_rotation

### `output`

{{< badge text="Required" >}}

{{< docs/shared lookup="reference/components/output-block.md" source="alloy" version="<ALLOY_VERSION>" >}}

`otelcol.processor.encryption` only processes logs and traces.
It rejects metrics, so don't configure a `metrics` output.

### `rule`

{{< badge text="Required" >}}

The `rule` block selects the values to encrypt and the recipients that can decrypt them.
You can specify multiple `rule` blocks, for example to encrypt prompts for one team and tool payloads for another.
When several rules match the same attribute, the first rule wins.

| Name                   | Type                   | Description                                                                         | Default | Required |
| ---------------------- | ---------------------- | ----------------------------------------------------------------------------------- | ------- | -------- |
| `recipients`           | `list(secret)`         | PEM-encoded recipient public keys. Every recipient can decrypt every value.         |         | yes      |
| `attribute_patterns`   | `list(string)`         | Regular expressions matched against attribute keys.                                 | `[]`    | no       |
| `attributes`           | `list(string)`         | Exact attribute keys to encrypt.                                                    | `[]`    | no       |
| `log_body`             | `bool`                 | Encrypt the body of log records.                                                    | `false` | no       |
| `log_body_event_names` | `list(string)`         | Only encrypt the body of log records with one of these event names.                 | `[]`    | no       |
| `name`                 | `string`               | Name of the rule, used in logs and in the `rule` metric attribute.                  | `""`    | no       |
| `presets`              | `list(string)`         | Well-known sets of attributes to encrypt.                                           | `[]`    | no       |

Each rule must select values with at least one of `presets`, `attributes`, `attribute_patterns`, or `log_body`.
The rule applies to span attributes, span event attributes, and log record attributes.
Resource and instrumentation scope attributes are never encrypted.

`presets` accepts the following values:

* `gen_ai`: The content attributes of the OpenTelemetry generative AI semantic conventions:
  `gen_ai.input.messages`, `gen_ai.output.messages`, `gen_ai.system_instructions`, `gen_ai.tool.definitions`, `gen_ai.tool.call.arguments`, `gen_ai.tool.call.result`, `gen_ai.embeddings.input`, the deprecated `gen_ai.prompt` and `gen_ai.completion`, and indexed attributes that match `^gen_ai\.(prompt|completion)\.\d+\.`.
* `openinference`: The content attributes of the OpenInference semantic conventions, such as `input.value`, `output.value`, `llm.input_messages.*`, and `llm.output_messages.*`.

`log_body_event_names` matches the `EventName` field of the log record, or the `event.name` attribute when the field is empty.
When `log_body_event_names` is empty, `log_body` encrypts the body of every log record.

Generate key pairs with the `otelcrypt` command described in [Decrypt telemetry](#decrypt-telemetry).
Recipients can use different key types.
The following key encapsulation mechanisms are supported: `MLKEM768-X25519` (default), `MLKEM768-P256`, `MLKEM1024-P384`, `MLKEM768`, `MLKEM1024`, `X25519`, and `P256`.

### `key_rotation`

The `key_rotation` block configures how often `otelcol.processor.encryption` renews the data encryption key it uses for each rule.

| Name         | Type       | Description                                                       | Default    | Required |
| ------------ | ---------- | ----------------------------------------------------------------- | ---------- | -------- |
| `max_age`    | `duration` | Maximum lifetime of a data encryption key.                        | `"10m"`    | no       |
| `max_values` | `number`   | Number of values encrypted with a data encryption key before it's renewed. | `16777216` | no |

`max_values` can't exceed 2<sup>32</sup>.
Shorter lifetimes reduce how much telemetry a data encryption key leaked from memory can expose.
Each renewal costs one public-key operation per recipient, which takes well under a millisecond.

### `debug_metrics`

{{< docs/shared lookup="reference/components/otelcol-debug-metrics-block.md" source="alloy" version="<ALLOY_VERSION>" >}}

## Exported fields

The following fields are exported and can be referenced by other components:

| Name    | Type               | Description                                                   |
| ------- | ------------------ | ------------------------------------------------------------- |
| `input` | `otelcol.Consumer` | Accepts `otelcol.Consumer` data for logs or traces. |

`input` accepts `otelcol.Consumer` data for logs and traces.

## Component health

`otelcol.processor.encryption` is only reported as unhealthy if given an invalid configuration.

## Debug information

`otelcol.processor.encryption` doesn't expose any component-specific debug information.

## Debug metrics

* `otelcol_processor_encryption_values_encrypted_total` (counter): Number of attribute values and log bodies encrypted, by `rule`.
* `otelcol_processor_encryption_plaintext_bytes_total` (counter): Number of plaintext bytes encrypted, by `rule`.
* `otelcol_processor_encryption_failures_total` (counter): Number of values that couldn't be encrypted, by `rule`.

## How encryption works

For each rule, `otelcol.processor.encryption` generates a random 256-bit data encryption key and wraps it for every recipient with Hybrid Public Key Encryption (HPKE, [RFC 9180][]).
Each selected value is then encrypted with AES-256-GCM and replaced with a string token:

```text
enc:v1:<DATA_KEY_ID>:<BASE64URL_CIPHERTEXT>
```

The wrapped data encryption key is attached to the same span or log record, in an attribute named `encryption.dek.<DATA_KEY_ID>`.
Every span or log record therefore carries what its recipients need to decrypt it, and stays decryptable after sampling, batching, or export to any backend.

Each ciphertext is bound to its location: the signal, whether the value is an attribute or a log body, the attribute key, and the trace and span IDs.
A token copied to another attribute, span, or trace fails to decrypt.
The attribute key is bound after replacing every character outside `[A-Za-z0-9_]` with `_`, so values stay decryptable after a backend such as Loki sanitizes attribute names.

Non-string values, such as maps and lists, are serialized as JSON before encryption.
Decryption restores their original type.

Values that are already encrypted are left unchanged, so you can run `otelcol.processor.encryption` at several stages of a pipeline.

The default key encapsulation mechanism, `MLKEM768-X25519`, combines a post-quantum and a classical algorithm.
This protects telemetry that you retain for a long time against attackers who record it now and decrypt it later with a quantum computer.

[RFC 9180]: https://www.rfc-editor.org/rfc/rfc9180

## Decrypt telemetry

The `otelcrypt` command generates keys and decrypts exported telemetry.
Run it on a workstation that holds the private keys, outside of the telemetry pipeline.

Build it from the {{< param "PRODUCT_NAME" >}} source repository:

```shell
go build -o otelcrypt ./internal/cmd/otelcrypt
```

Generate a key pair:

```shell
otelcrypt keygen -private control.key -public control.pub
```

Protect `control.key`, for example in a hardware security module or an offline vault.
Only distribute `control.pub` to {{< param "PRODUCT_NAME" >}}.

Decrypt a trace exported from Tempo, or a Loki query response:

```shell
curl -s http://tempo:3200/api/traces/<TRACE_ID> \
  | otelcrypt decrypt -key control.key -reason "<JUSTIFICATION>" -audit-log audit.jsonl
```

`otelcrypt decrypt` requires a justification and can append an audit record with the user, the input digest, the keys used, and the number of decrypted values.
It accepts OTLP JSON traces and logs, Tempo API responses, and Loki query responses.

`otelcrypt inspect` lists the data encryption keys and recipients found in a document without decrypting it.

## Examples

### Encrypt generative AI content

This example encrypts the prompts, completions, and tool payloads of generative AI traces and logs, and sends the result to Tempo and Loki.
Model names, token usage, and latencies stay in clear text.

```alloy
local.file "control_key" {
  filename = "/etc/alloy/keys/control.pub"
}

otelcol.receiver.otlp "default" {
  grpc {}
  http {}

  output {
    logs   = [otelcol.processor.encryption.gen_ai.input]
    traces = [otelcol.processor.encryption.gen_ai.input]
  }
}

otelcol.processor.encryption "gen_ai" {
  rule {
    name       = "content"
    recipients = [local.file.control_key.content]
    presets    = ["gen_ai"]

    log_body             = true
    log_body_event_names = [
      "gen_ai.system.message",
      "gen_ai.user.message",
      "gen_ai.assistant.message",
      "gen_ai.tool.message",
      "gen_ai.choice",
    ]
  }

  output {
    logs   = [otelcol.processor.batch.default.input]
    traces = [otelcol.processor.batch.default.input]
  }
}

otelcol.processor.batch "default" {
  output {
    logs   = [otelcol.exporter.otlphttp.loki.input]
    traces = [otelcol.exporter.otlp.tempo.input]
  }
}

otelcol.exporter.otlp "tempo" {
  client {
    endpoint = "tempo:4317"
  }
}

otelcol.exporter.otlphttp "loki" {
  client {
    endpoint = "http://loki:3100/otlp"
  }
}
```

### Separate who can read what

This example encrypts messages for a business review team and tool payloads for a technical team.
Tool names and call IDs stay in clear text.
A third recipient, an escrow key kept offline, can decrypt everything.

```alloy
otelcol.processor.encryption "gen_ai" {
  rule {
    name       = "messages"
    recipients = [
      local.file.business_key.content,
      local.file.escrow_key.content,
    ]
    attributes = [
      "gen_ai.input.messages",
      "gen_ai.output.messages",
      "gen_ai.system_instructions",
    ]
  }

  rule {
    name       = "tools"
    recipients = [
      local.file.technical_key.content,
      local.file.escrow_key.content,
    ]
    attributes = [
      "gen_ai.tool.definitions",
      "gen_ai.tool.call.arguments",
      "gen_ai.tool.call.result",
    ]
  }

  output {
    traces = [otelcol.exporter.otlp.default.input]
  }
}
```

<!-- START GENERATED COMPATIBLE COMPONENTS -->

## Compatible components

`otelcol.processor.encryption` can accept arguments from the following components:

- Components that export [OpenTelemetry `otelcol.Consumer`](../../../compatibility/#opentelemetry-otelcolconsumer-exporters)

`otelcol.processor.encryption` has exports that can be consumed by the following components:

- Components that consume [OpenTelemetry `otelcol.Consumer`](../../../compatibility/#opentelemetry-otelcolconsumer-consumers)

{{< admonition type="note" >}}
Connecting some components may not be sensible or components may require further configuration to make the connection work correctly.
Refer to the linked documentation for more details.
{{< /admonition >}}

<!-- END GENERATED COMPATIBLE COMPONENTS -->
