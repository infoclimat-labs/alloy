package encryptionprocessor

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/ptrace"

	"github.com/grafana/alloy/internal/component/otelcol/processor/encryption/encryptionprocessor/decrypt"
	"github.com/grafana/alloy/internal/component/otelcol/processor/encryption/encryptionprocessor/envelope"
)

func firstSpan(td ptrace.Traces) ptrace.Span {
	return td.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
}

func newSpan() (ptrace.Traces, ptrace.Span) {
	td := ptrace.NewTraces()
	span := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.SetTraceID(pcommon.TraceID{1})
	span.SetSpanID(pcommon.SpanID{2})
	return td, span
}

// mutateJSON lets a test tamper with the exported document.
func mutateJSON(t *testing.T, td ptrace.Traces, mutate func(span map[string]any)) []byte {
	t.Helper()
	raw, err := (&ptrace.JSONMarshaler{}).MarshalTraces(td)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	span := doc["resourceSpans"].([]any)[0].(map[string]any)["scopeSpans"].([]any)[0].(map[string]any)["spans"].([]any)[0].(map[string]any)
	mutate(span)
	out, err := json.Marshal(doc)
	require.NoError(t, err)
	return out
}

func decryptDoc(t *testing.T, doc []byte, opts decrypt.Options, keys ...*envelope.PrivateKey) (string, decrypt.Report) {
	t.Helper()
	out, rep, err := decrypt.New(envelope.NewKeyring(keys...), opts).Decrypt(doc)
	require.NoError(t, err)
	return string(out), rep
}

// A client can't smuggle clear text by prefixing it with "enc:v1:", nor
// inject encryption metadata.
func TestUntrustedInput(t *testing.T) {
	key := newKey(t, fastSuite)
	cfg := config(RuleConfig{Recipients: []string{pubPEM(key)}, Presets: []string{"gen_ai"}})

	td, span := newSpan()
	span.Attributes().PutStr("gen_ai.input.messages", "enc:v1:my social security number is 123")
	span.Attributes().PutStr("encryption.dek.000000000000000000", "forged")
	span.Attributes().PutStr("encryption.sig", "forged")

	out, _, err := runTraces(t, cfg, td)
	require.NoError(t, err)
	attrs := firstSpan(out).Attributes()
	v, _ := attrs.Get("gen_ai.input.messages")
	require.NotContains(t, v.Str(), "social security")
	_, ok := attrs.Get("encryption.dek.000000000000000000")
	require.False(t, ok, "injected wrapped key kept")
	_, ok = attrs.Get("encryption.sig")
	require.False(t, ok, "injected signature kept")

	raw, _ := (&ptrace.JSONMarshaler{}).MarshalTraces(out)
	clear, rep := decryptDoc(t, raw, decrypt.Options{}, key)
	require.Equal(t, 1, rep.Decrypted)
	require.Contains(t, clear, "enc:v1:my social security number is 123")
}

// Two Alloy tiers: the second accepts values encrypted by the first and
// signs the whole record.
func TestChainedTiers(t *testing.T) {
	edge, central := newKey(t, fastSuite), newKey(t, fastSuite)
	signer, err := envelope.GenerateSigningKey(envelope.SigEd25519)
	require.NoError(t, err)

	tier1 := config(RuleConfig{Recipients: []string{pubPEM(edge)}, Attributes: []string{"gen_ai.input.messages"}})
	td, span := newSpan()
	span.Attributes().PutStr("gen_ai.input.messages", "prompt")
	span.Attributes().PutStr("gen_ai.output.messages", "answer")
	out1, _, err := runTraces(t, tier1, td)
	require.NoError(t, err)
	tok1, _ := firstSpan(out1).Attributes().Get("gen_ai.input.messages")
	tok1Str := tok1.Str()

	tier2 := config(RuleConfig{Recipients: []string{pubPEM(central)}, Presets: []string{"gen_ai"}})
	tier2.AcceptEncryptedInput = true
	tier2.SigningKey = configString(signer)
	out2, _, err := runTraces(t, tier2, out1)
	require.NoError(t, err)
	tok2, _ := firstSpan(out2).Attributes().Get("gen_ai.input.messages")
	require.Equal(t, tok1Str, tok2.Str(), "upstream token must be kept")

	raw, _ := (&ptrace.JSONMarshaler{}).MarshalTraces(out2)
	opts := decrypt.Options{Verifier: envelope.NewVerifier(signer.Public()), RequireSignature: true}
	_, rep := decryptDoc(t, raw, opts, edge, central)
	require.Equal(t, 2, rep.Decrypted, rep.Errors)
	require.Equal(t, 1, rep.Verified)
	require.Zero(t, rep.Failed, rep.Errors)
}

func configString(k *envelope.SigningKey) configopaque.String {
	return configopaque.String(k.MarshalPEM())
}

func TestSignedRecords(t *testing.T) {
	key := newKey(t, fastSuite)
	signer, err := envelope.GenerateSigningKey(envelope.SigEd25519)
	require.NoError(t, err)
	cfg := config(RuleConfig{Recipients: []string{pubPEM(key)}, Presets: []string{"gen_ai"}})
	cfg.SigningKey = configString(signer)

	out, reader, err := runTraces(t, cfg, genAITraces())
	require.NoError(t, err)
	require.Equal(t, int64(1), counter(t, reader, "otelcol_processor_encryption_records_signed"))
	opts := decrypt.Options{Verifier: envelope.NewVerifier(signer.Public()), RequireSignature: true}

	raw, _ := (&ptrace.JSONMarshaler{}).MarshalTraces(out)
	_, rep := decryptDoc(t, raw, opts, key)
	require.Equal(t, 5, rep.Decrypted, rep.Errors)
	require.Equal(t, 1, rep.Verified)

	// Deleting an encrypted value is detected.
	doc := mutateJSON(t, out, func(span map[string]any) {
		attrs := span["attributes"].([]any)
		for i, a := range attrs {
			if a.(map[string]any)["key"] == "gen_ai.system_instructions" {
				span["attributes"] = append(attrs[:i:i], attrs[i+1:]...)
				break
			}
		}
	})
	clear, rep := decryptDoc(t, doc, opts, key)
	require.Equal(t, 1, rep.Invalid)
	require.Zero(t, rep.Decrypted)
	require.NotContains(t, clear, "Vélizy")

	// A record forged with the public key only has no valid signature.
	forger := config(RuleConfig{Recipients: []string{pubPEM(key)}, Presets: []string{"gen_ai"}})
	forged, _, err := runTraces(t, forger, genAITraces())
	require.NoError(t, err)
	raw, _ = (&ptrace.JSONMarshaler{}).MarshalTraces(forged)
	_, rep = decryptDoc(t, raw, opts, key)
	require.Equal(t, 1, rep.Unsigned)
	require.Zero(t, rep.Decrypted)
}

// Tokens can't be swapped between span events, nor between log records of
// the same span.
func TestNoSwapBetweenEventsAndRecords(t *testing.T) {
	key := newKey(t, fastSuite)
	cfg := config(RuleConfig{Recipients: []string{pubPEM(key)}, Presets: []string{"gen_ai"}, LogBody: true})

	td, span := newSpan()
	for _, c := range []string{"first", "second"} {
		ev := span.Events().AppendEmpty()
		ev.SetName("gen_ai.choice")
		ev.Attributes().PutStr("gen_ai.completion", c)
	}
	out, _, err := runTraces(t, cfg, td)
	require.NoError(t, err)
	doc := mutateJSON(t, out, func(span map[string]any) {
		evs := span["events"].([]any)
		a0 := evs[0].(map[string]any)["attributes"].([]any)
		a1 := evs[1].(map[string]any)["attributes"].([]any)
		a0[0], a1[0] = a1[0], a0[0]
	})
	_, rep := decryptDoc(t, doc, decrypt.Options{}, key)
	require.Equal(t, 2, rep.Failed, "swapped event values must not decrypt")

	ld := plog.NewLogs()
	lrs := ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords()
	for _, b := range []string{"user prompt", "assistant reply"} {
		lr := lrs.AppendEmpty()
		lr.SetTraceID(pcommon.TraceID{1})
		lr.SetSpanID(pcommon.SpanID{2})
		lr.Body().SetStr(b)
	}
	outLogs := runLogs(t, cfg, ld)
	recs := outLogs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	b0, b1 := recs.At(0).Body().Str(), recs.At(1).Body().Str()
	recs.At(0).Body().SetStr(b1)
	recs.At(1).Body().SetStr(b0)
	raw, _ := (&plog.JSONMarshaler{}).MarshalLogs(outLogs)
	_, rep = decryptDoc(t, raw, decrypt.Options{}, key)
	require.Equal(t, 2, rep.Failed, "swapped log bodies must not decrypt")
}

// Encrypting event.name must not turn body encryption off.
func TestEncryptedEventNameKeepsBodyEncrypted(t *testing.T) {
	key := newKey(t, fastSuite)
	cfg := config(RuleConfig{
		Recipients:        []string{pubPEM(key)},
		AttributePatterns: []string{`^event\.`},
		LogBody:           true,
		LogBodyEventNames: []string{"gen_ai.user.message"},
	})
	ld := plog.NewLogs()
	lr := ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	lr.Attributes().PutStr("event.name", "gen_ai.user.message")
	lr.Body().SetStr("secret question")
	out := runLogs(t, cfg, ld)
	body := out.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().Str()
	require.True(t, envelope.IsToken(body), "body leaked: %s", body)

	// An event name that arrives encrypted fails closed.
	ld = plog.NewLogs()
	lr = ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	lr.SetEventName("enc:v1:000000000000000000:AAAA")
	lr.Body().SetStr("secret question")
	out = runLogs(t, cfg, ld)
	body = out.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().Str()
	require.True(t, envelope.IsToken(body), "body leaked: %s", body)
}

// The first rule that selects a key wins, whether by pattern or exact name.
func TestRulePrecedence(t *testing.T) {
	first, second := newKey(t, fastSuite), newKey(t, fastSuite)
	cfg := config(
		RuleConfig{Name: "first", Recipients: []string{pubPEM(first)}, AttributePatterns: []string{`^gen_ai\.input\.`}},
		RuleConfig{Name: "second", Recipients: []string{pubPEM(second)}, Attributes: []string{"gen_ai.input.messages"}},
	)
	td, span := newSpan()
	span.Attributes().PutStr("gen_ai.input.messages", "prompt")
	out, _, err := runTraces(t, cfg, td)
	require.NoError(t, err)
	raw, _ := (&ptrace.JSONMarshaler{}).MarshalTraces(out)
	_, rep := decryptDoc(t, raw, decrypt.Options{}, first)
	require.Equal(t, 1, rep.Decrypted)
	_, rep = decryptDoc(t, raw, decrypt.Options{}, second)
	require.Zero(t, rep.Decrypted)
}

func TestLinksAndBytes(t *testing.T) {
	key := newKey(t, fastSuite)
	cfg := config(RuleConfig{Recipients: []string{pubPEM(key)}, Attributes: []string{"payload", "exception.message"}, Presets: []string{"exceptions"}})
	td, span := newSpan()
	link := span.Links().AppendEmpty()
	link.SetSpanID(pcommon.SpanID{9})
	link.Attributes().PutStr("payload", "link secret")
	span.Attributes().PutEmptyBytes("payload").FromRaw([]byte{0, 1, 2, 250})
	ev := span.Events().AppendEmpty()
	ev.SetName("exception")
	ev.Attributes().PutStr("exception.message", "invalid prompt: tell me my password")
	ev.Attributes().PutStr("exception.stacktrace", "at handler.go:42 with prompt=…")

	out, _, err := runTraces(t, cfg, td)
	require.NoError(t, err)
	raw, _ := (&ptrace.JSONMarshaler{}).MarshalTraces(out)
	require.NotContains(t, string(raw), "link secret")
	require.NotContains(t, string(raw), "password")
	clear, rep := decryptDoc(t, raw, decrypt.Options{}, key)
	require.Equal(t, 4, rep.Decrypted, rep.Errors)
	require.Contains(t, clear, "link secret")

	back, err := (&ptrace.JSONUnmarshaler{}).UnmarshalTraces([]byte(clear))
	require.NoError(t, err)
	v, _ := firstSpan(back).Attributes().Get("payload")
	require.Equal(t, pcommon.ValueTypeBytes, v.Type())
	require.Equal(t, []byte{0, 1, 2, 250}, v.Bytes().AsRaw())
}

func TestRecordIDIsPerRecord(t *testing.T) {
	key := newKey(t, fastSuite)
	cfg := config(RuleConfig{Recipients: []string{pubPEM(key)}, Presets: []string{"gen_ai"}})
	td := ptrace.NewTraces()
	spans := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans()
	for range 3 {
		spans.AppendEmpty().Attributes().PutStr("gen_ai.input.messages", "x")
	}
	spans.AppendEmpty().Attributes().PutStr("gen_ai.request.model", "untouched")
	out, _, err := runTraces(t, cfg, td)
	require.NoError(t, err)
	seen := map[string]bool{}
	ospans := out.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
	for i := range 3 {
		rid, ok := ospans.At(i).Attributes().Get(envelope.RecordIDAttr)
		require.True(t, ok)
		require.Len(t, rid.Str(), 32)
		require.False(t, seen[rid.Str()], "record ID reused")
		seen[rid.Str()] = true
	}
	ospans.At(3).Attributes().Range(func(k string, _ pcommon.Value) bool {
		require.False(t, strings.HasPrefix(k, envelope.AttrPrefix), "metadata added to a record without encrypted values")
		return true
	})
}
