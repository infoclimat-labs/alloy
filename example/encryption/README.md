# Reversible encryption of generative AI telemetry

This example demonstrates `otelcol.processor.encryption`, a processor of this
fork that encrypts the content of OpenTelemetry signals (prompts, completions,
system instructions, tool payloads) with public-key encryption, while keeping
metadata (models, token usage, latencies, tool names, errors) in clear text.

The goal is to let an agentic platform support technical, business and
compliance controls of its AI systems without exposing user content to
everyone who can read the observability backends.

```text
 agent (OTel SDK) ──OTLP──▶ Alloy ──▶ Tempo / Loki ──▶ Grafana (metadata only)
                            │ encrypts with                │
                            │ PUBLIC keys only             │ export (API)
                            ▼                              ▼
                     never holds a                 otelcrypt decrypt
                     private key                   (control authority,
                                                    PRIVATE key, audited)
```

## Run the demo

Requirements: Docker with Compose v2. The first build compiles Alloy and takes
a few minutes.

```shell
cd example/encryption
docker compose up -d --build
# wait ~30 s for a few conversations, then:
docker compose run --rm toolbox /demo/decrypt.sh
```

`decrypt.sh` fetches the latest trace from Tempo and recent events from Loki,
shows what is visible without a key, then decrypts with each of the three keys:

| Key         | Can read                                                    |
| ----------- | ----------------------------------------------------------- |
| `business`  | messages and system instructions (rule `messages`)          |
| `technical` | tool definitions, call arguments and results (rule `tools`) |
| `escrow`    | everything (break-glass key, kept offline in real life)     |

Every decryption requires a justification and appends a record to
`audit/audit.jsonl`.

Grafana runs on <http://localhost:3000>: open the Tempo data source and look at
a trace of `agent-meteo`. Content attributes show `enc:v1:...` tokens, while
model, token usage and timings are readable.

Stop and remove everything:

```shell
docker compose down -v
```

## What is where

| File                       | Purpose                                                           |
| -------------------------- | ----------------------------------------------------------------- |
| `config.alloy`             | Pipeline: OTLP receiver → encryption → batch → Tempo and Loki.    |
| `generator/generate.py`    | Agent instrumented with the OpenTelemetry Python SDK (GenAI semconv). |
| `decrypt.sh`               | Control authority workflow: fetch, inspect, decrypt, audit.       |
| `Dockerfile`               | Builds the forked Alloy and the `otelcrypt` tool.                 |
| `compose.yaml`             | Alloy, Tempo, Loki, Grafana, key generation, generator, toolbox.  |

The demo generates keys in a Docker volume for convenience. Only the public
keys volume is mounted into Alloy.

## Design

### Cryptography

* **Recipients** are HPKE ([RFC 9180]) public keys. The default KEM is the
  post-quantum hybrid `MLKEM768-X25519` (X-Wing), with HKDF-SHA256 and
  AES-256-GCM. Classical (`X25519`, `P256`) and other hybrid suites
  (`MLKEM768-P256`, `MLKEM1024-P384`) are available. Everything comes from the
  Go standard library (`crypto/hpke`, `crypto/mlkem`); there is no third-party
  cryptographic dependency.
* **Envelope encryption.** For each rule, Alloy draws a random 256-bit data
  encryption key (DEK), wraps it once per recipient with HPKE, and encrypts
  each value with AES-256-GCM and a random 96-bit nonce. The DEK is rotated
  after `key_rotation.max_values` values (default 2^24, far below the 2^32
  random-nonce bound) or `key_rotation.max_age` (default 10 minutes). The
  public-key operation is therefore amortized: about 0.2 ms per rotation.
* **Self-contained records.** The wrapped DEK is attached to each span or log
  record (`encryption.dek.<id>`), so every record stays decryptable on its own
  after sampling, batching, retention or export, in any backend.
* **Context binding.** The AEAD additional data binds each ciphertext to the
  signal, the scope (span, span event, log, log body), the attribute key and
  the trace and span IDs. Moving a token to another attribute or trace makes
  it undecryptable. Keys are bound in their sanitized form (`[A-Za-z0-9_]`),
  so values stay decryptable after Loki rewrites attribute names.
* **Header authentication.** The wrapped-key blob header (version, suite, key
  ID) is part of the HPKE `info`, so it can't be altered without detection.
* **Typed values.** Maps, lists and numbers are serialized as JSON with a type
  marker and restored with their original type.

### Wire format

```text
attribute value : enc:v1:<dek-id>:<base64url(nonce ‖ ciphertext ‖ tag)>
record attribute: encryption.dek.<dek-id> = <blob>[.<blob>...]
blob            : base64url("OE" ‖ 0x01 ‖ KEM ‖ KDF ‖ AEAD ‖ key-id[8] ‖ HPKE enc ‖ HPKE ciphertext)
dek-id          : hex(SHA-256(record attribute value))[0:18]
key-id          : hex(SHA-256("otel-encryption/v1 kid" ‖ suite ‖ public key))[0:16]
```

### Threat model

| Threat                                              | Mitigation                                                                 |
| --------------------------------------------------- | -------------------------------------------------------------------------- |
| Backend operators or users read prompts             | Content is encrypted before it leaves Alloy; backends only store tokens.   |
| Compromise of the Alloy cluster                     | Alloy holds public keys only: past telemetry stays confidential. A live attacker can still read new traffic in memory, as with any in-line processor. |
| Leak of a DEK from Alloy memory                     | Bounded by the rotation window (10 minutes / 2^24 values by default).      |
| Tokens copied between records to forge evidence     | AEAD context binding to key, scope and trace/span IDs.                     |
| "Harvest now, decrypt later" on long-term archives  | Post-quantum hybrid KEM by default.                                        |
| Encryption failure leaks clear text                 | Fail-closed: `on_error = "delete"` (default) or `"reject"`.                 |
| Unaccountable decryption                            | `otelcrypt decrypt` requires a reason and writes an audit trail.           |
| One team reads another team's data                  | One rule per audience, each with its own recipients.                       |

Out of scope for this proof of concept: protecting the private keys (use an
HSM or an offline vault), hiding metadata (span names, attribute keys, sizes
and timing remain visible), searching inside encrypted content.

### GDPR and AI Act notes

Reversible encryption is **pseudonymization** (GDPR art. 4(5)): encrypted
telemetry remains personal data, but access to clear text is restricted to the
holders of the private keys, which supports data minimization (art. 5(1)(c)),
security of processing (art. 32) and data protection by design (art. 25).
Keeping complete, but controlled, interaction records also helps meet the
logging and record-keeping duties of the AI Act for high-risk systems.
This is engineering guidance, not legal advice.

### Performance

Measured on 2 vCPUs in a sandbox: a batch of 100 spans carrying two 4 KiB
prompts each is encrypted in about 5 ms (≈170 MB/s of content per core,
≈20 000 spans/s); sealing one value costs about 14 µs for 4 KiB.

[RFC 9180]: https://www.rfc-editor.org/rfc/rfc9180
