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

Every record is signed by Alloy (Ed25519 key generated at first start) and
`decrypt.sh` only decrypts records whose signature verifies against
`alloy-signing.pub`. Every decryption requires a justification and appends a
record to the hash-chained trail `audit/audit.jsonl`, checked at the end with
`otelcrypt audit-verify`.

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

The demo generates keys in Docker volumes for convenience. Alloy only mounts
the recipients' public keys and its own signing key; the recipients' private
keys live in a separate volume mounted by the toolbox only.

`tempo.yaml` sets `max_attribute_bytes: 0`: Tempo truncates attribute values
to 2048 bytes by default, which would corrupt ciphertexts and wrapped keys.

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
  signal, a random per-record ID (`encryption.rid`), the trace and span IDs,
  the scope (span, span event, span link, log, log body), the event or link
  position and the attribute key. Moving a token to another attribute, event,
  record or trace makes it undecryptable. Keys are bound in their sanitized
  form (`[A-Za-z0-9_]`) so values stay decryptable after Loki rewrites
  attribute names; the exact key is encrypted with the value and checked.
* **Record signatures (optional, recommended).** Alloy signs every record
  (Ed25519, or ML-DSA-65/87), with or without encrypted values, over the
  record ID, IDs, wrapped keys, every token with its location and a digest of
  the clear-text metadata (span name, timestamps, event names and times, set
  of attribute keys). With `-require-signature`, `otelcrypt` refuses forged
  records, including ones built with a recipient public key, and detects
  moved, altered or deleted values, injected or removed attributes and
  records stripped of their encryption. Clear-text attribute values aren't
  covered. Loki rewrites attribute names: for Loki exports the metadata
  digest is taken as signed, not recomputed.
* **Untrusted input.** Incoming processor attributes are dropped and
  token-looking values are encrypted like any other value. A second Alloy tier
  with `accept_encrypted_input` keeps encrypted values only from records that
  carry a valid signature from a pinned upstream key.
* **Who said what.** The event name of an encrypted log body (user,
  assistant, tool message) is bound to the ciphertext.
* **Header authentication.** The wrapped-key blob header (version, suite, key
  ID) is part of the HPKE `info`, so it can't be altered without detection.
* **Typed values.** Maps, lists, numbers and byte arrays are restored with
  their original type.

### Wire format

```text
attribute value : enc:v1:<dek-id>:<base64url(nonce ‖ AES-256-GCM(plaintext, AAD))>
plaintext       : kind ('s'|'j'|'b') ‖ uvarint(len(key)) ‖ key ‖ value
AAD             : lp("otel-encryption/v1 value") ‖ lp(dek-id) ‖ lp(signal) ‖ lp(scope)
                  ‖ lp(position) ‖ lp(normalized key) ‖ lp(rid) ‖ lp(trace-id) ‖ lp(span-id)
record attrs    : encryption.rid = hex(16 random bytes)
                  encryption.dek.<dek-id> = <blob>[.<blob>...]
                  encryption.sig = <signing-key-id>.<base64url(signature)>   (optional)
blob            : base64url("OE" ‖ 0x01 ‖ KEM ‖ KDF ‖ AEAD ‖ key-id[8] ‖ HPKE enc ‖ HPKE ciphertext)
dek-id          : hex(SHA-256(record attribute value))[0:18]
key-id          : hex(SHA-256("otel-encryption/v1 kid" ‖ suite ‖ public key))[0:16]
signature       : Sign(SHA-256(canonical manifest: signal, rid, IDs, sorted entries
                  (scope, position, normalized key, token), sorted wrapped keys))
```

### Threat model

| Threat                                                   | Mitigation                                                                 |
| -------------------------------------------------------- | -------------------------------------------------------------------------- |
| Backend operators or users read prompts                  | Content is encrypted before it leaves Alloy; backends only store tokens.   |
| Compromise of the Alloy cluster                          | Alloy holds public keys only: telemetry already stored stays confidential. A live attacker can read new traffic in memory and sign records with Alloy's key, as with any in-line processor. |
| Leak of a DEK from Alloy memory                          | Bounded by the rotation window (10 minutes / 2^24 values by default; best effort, Go can't wipe memory). |
| Forged records (anyone holding a recipient public key)   | Record signatures, verified with `-require-signature`. Without a signing key the scheme gives confidentiality only. |
| Forged values laundered through a second Alloy tier      | Upstream values kept only with a valid signature from a pinned upstream key. |
| Tokens moved, swapped or deleted to alter evidence       | AEAD binding to record ID, position, key, event name and IDs; deletions detected by the signature. |
| Clear text injected next to signed content, record stripped of its encryption | Metadata digest (attribute key set, names, timestamps) in the signature; every record signed. |
| Client smuggles clear text with an `enc:v1:` prefix      | Incoming tokens and processor attributes aren't trusted by default.        |
| Encrypted `event.name` disables body encryption          | The body rule is resolved before attributes; unreadable names fail closed. |
| "Harvest now, decrypt later" on long-term archives       | Post-quantum hybrid KEM by default; ML-DSA signatures available.           |
| Encryption failure leaks clear text                      | Fail-closed: `on_error = "delete"` (default) or `"reject"`.                 |
| Backend truncates long values                            | Detected (AEAD failure, with a hint); configure the backend (Tempo `max_attribute_bytes`). |
| Unaccountable decryption                                 | Mandatory reason; locked, hash-chained audit trail written before clear text is released; optional remote audit sink (`-audit-url`) that must accept the record; `audit-verify -head` detects truncation. A local trail alone can be rewritten by the workstation owner. |
| One team reads another team's data                       | One rule per audience, each with its own recipients; first matching rule wins. |

Out of scope for this proof of concept: protecting the private keys (use an
HSM or an offline vault), integrity of clear-text attribute values and of
resource attributes, hiding metadata (span names, resource attributes,
attribute keys, value sizes and timing remain visible), and searching inside
encrypted content.

### GDPR and AI Act notes

Reversible encryption is **pseudonymization** (GDPR art. 4(5)): encrypted
telemetry remains personal data, but access to clear text is restricted to the
holders of the private keys, which supports data minimization (art. 5(1)(c)),
security of processing (art. 32) and data protection by design (art. 25).
Keeping complete, but controlled, interaction records also helps meet the
logging and record-keeping duties of the AI Act for high-risk systems.
This is engineering guidance, not legal advice.

### Performance

Measured on a GitHub-hosted runner (4 vCPU): a batch of 100 spans carrying two
4 KiB prompts each is encrypted in about 2.5 ms (≈340 MB/s of content,
≈40 000 spans/s on one core); sealing one 4 KiB value takes about 8 µs; a DEK
rotation (post-quantum hybrid KEM) about 0.17 ms. Record signatures add about
30 µs (Ed25519) or 1 ms (ML-DSA-65) per record.

[RFC 9180]: https://www.rfc-editor.org/rfc/rfc9180
