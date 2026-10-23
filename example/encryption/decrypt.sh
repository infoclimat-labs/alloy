#!/bin/sh
# Runs on the control authority workstation (the "toolbox" service).
#
# Fetches the latest agent trace from Tempo and recent events from Loki,
# shows that the content is encrypted at rest, then decrypts it with each
# private key and records an audit entry for every decryption.
#
# With --check, exits non-zero if clear text content reached a backend or if
# the escrow key can't decrypt everything (used by CI).
set -eu

TEMPO=${TEMPO:-http://tempo:3200}
LOKI=${LOKI:-http://loki:3100}
SERVICE=${SERVICE:-agent-meteo}
MARKER=${MARKER:-Velizy-Villacoublay}
OUT=${OUT:-/audit}
CHECK=0
[ "${1:-}" = "--check" ] && CHECK=1

fail() { echo "FAIL: $*" >&2; exit 1; }
mkdir -p "$OUT"

echo "== Latest trace of $SERVICE in Tempo"
trace_id=""
for _ in $(seq 1 30); do
  trace_id=$(curl -sf -G "$TEMPO/api/search" \
      --data-urlencode "tags=service.name=$SERVICE" --data-urlencode "limit=1" \
    | jq -r '.traces[0].traceID // empty' || true)
  [ -n "$trace_id" ] && break
  sleep 2
done
[ -n "$trace_id" ] || fail "no trace found in Tempo"
echo "trace: $trace_id"

# Tempo may return the trace before every span is flushed: wait for the 4 spans.
for _ in $(seq 1 30); do
  curl -sf "$TEMPO/api/traces/$trace_id" > "$OUT/trace-encrypted.json"
  spans=$(jq '[.. | objects | select(has("spanId"))] | length' "$OUT/trace-encrypted.json")
  [ "$spans" -ge 4 ] && break
  sleep 2
done

tokens=$(grep -o 'enc:v1:' "$OUT/trace-encrypted.json" | wc -l)
echo "encrypted values stored in Tempo: $tokens"
if grep -q "$MARKER" "$OUT/trace-encrypted.json"; then
  fail "clear text content found in Tempo"
fi
echo "clear text marker \"$MARKER\" absent from Tempo: OK"
echo
echo "== What the stored trace reveals without any key"
jq -r '[.. | objects | select(has("spanId"))][] | .name as $n
  | [.attributes[]? | select(.key | test("^gen_ai\\.(operation\\.name|request\\.model|usage\\.input_tokens|tool\\.name)$"))
     | "\(.key)=\(.value | to_entries[0].value)"] | "\($n): \(join(", "))"' "$OUT/trace-encrypted.json"
echo
otelcrypt inspect -in "$OUT/trace-encrypted.json"

echo
echo "== Decryption by each authority"
VERIFY="-verify-key /public/alloy-signing.pub -require-signature"
for who in business technical escrow; do
  status=0
  rm -f "$OUT/trace-$who.json"
  # shellcheck disable=SC2086 # VERIFY holds several flags
  otelcrypt decrypt -key "/keys/$who.key" $VERIFY -in "$OUT/trace-encrypted.json" \
    -out "$OUT/trace-$who.json" -reason "demo: review of trace $trace_id by $who" \
    -audit-log "$OUT/audit.jsonl" 2> "$OUT/decrypt-$who.log" || status=$?
  echo "-- $who: $(head -1 "$OUT/decrypt-$who.log") (exit $status)"
  # Errors are expected for the values this key can't open; show the others.
  grep -v 'no private key matches' "$OUT/decrypt-$who.log" | sed -n '2,4p'
  [ -f "$OUT/trace-$who.json" ] || continue
  jq -r '[.. | objects | select(has("key") and (.key | startswith("gen_ai.")))
    | select(.key | test("messages|instructions|definitions|arguments|result"))
    | "   \(.key): \(.value.stringValue // .value | tostring | .[0:110])"] | unique | .[]' "$OUT/trace-$who.json"
done
if [ $CHECK -eq 1 ]; then
  [ -f "$OUT/trace-escrow.json" ] || fail "escrow decryption failed: $(cat "$OUT/decrypt-escrow.log")"
  grep -q "$MARKER" "$OUT/trace-escrow.json" || fail "escrow key did not restore the content: $(cat "$OUT/decrypt-escrow.log")"
  grep -q 'enc:v1:' "$OUT/trace-escrow.json" && fail "escrow key left encrypted values"
  grep -q '"signatures_verified":0' "$OUT/audit.jsonl" && fail "records without a verified signature"
fi

echo
echo "== Loki events of $SERVICE"
now=$(date +%s)
for _ in $(seq 1 30); do
  curl -sf -G "$LOKI/loki/api/v1/query_range" \
      --data-urlencode "query={service_name=\"$SERVICE\"}" \
      --data-urlencode "start=$(( (now - 900) * 1000000000 ))" \
      --data-urlencode "limit=20" > "$OUT/logs-encrypted.json"
  [ "$(jq '[.data.result[].values[]] | length' "$OUT/logs-encrypted.json")" -gt 0 ] && break
  sleep 2
done
lines=$(jq '[.data.result[].values[]] | length' "$OUT/logs-encrypted.json")
echo "log entries: $lines"
[ "$lines" -gt 0 ] || fail "no log entry found in Loki"
if grep -q "$MARKER" "$OUT/logs-encrypted.json"; then
  fail "clear text content found in Loki"
fi
echo "clear text marker absent from Loki: OK"
rm -f "$OUT/logs-escrow.json"
# shellcheck disable=SC2086
otelcrypt decrypt -key /keys/escrow.key $VERIFY -in "$OUT/logs-encrypted.json" -out "$OUT/logs-escrow.json" \
  -reason "demo: review of agent events" -audit-log "$OUT/audit.jsonl"
jq -r '.data.result[].values[] | "   \(.[1] | .[0:120])"' "$OUT/logs-escrow.json" | head -8
if [ $CHECK -eq 1 ]; then
  grep -q "$MARKER" "$OUT/logs-escrow.json" || fail "escrow key did not restore log content"
fi

echo
echo "== Audit trail ($OUT/audit.jsonl)"
jq -c '{time, user, reason, keys, decrypted, failed, signatures_verified}' "$OUT/audit.jsonl" | tail -4
otelcrypt audit-verify -in "$OUT/audit.jsonl"
echo
echo "OK"
