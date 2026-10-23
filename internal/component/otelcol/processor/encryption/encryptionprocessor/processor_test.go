package encryptionprocessor

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/processor/processortest"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/grafana/alloy/internal/component/otelcol/processor/encryption/encryptionprocessor/decrypt"
	"github.com/grafana/alloy/internal/component/otelcol/processor/encryption/encryptionprocessor/envelope"
)

var fastSuite = envelope.Suite{KEM: envelope.KEMX25519HKDFSHA256, KDF: envelope.KDFHKDFSHA256, AEAD: envelope.AEADAES256GCM}

func newKey(t testing.TB, s envelope.Suite) *envelope.PrivateKey {
	t.Helper()
	k, err := envelope.GenerateKey(s)
	require.NoError(t, err)
	return k
}

func pubPEM(k *envelope.PrivateKey) string { return string(k.Public().MarshalPEM()) }

func settings(t testing.TB) (processor.Settings, *sdkmetric.ManualReader) {
	t.Helper()
	set := processortest.NewNopSettings(NewFactory().Type())
	reader := sdkmetric.NewManualReader()
	set.MeterProvider = sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	return set, reader
}

func counter(t testing.TB, reader *sdkmetric.ManualReader, name string) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	var total int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			for _, dp := range m.Data.(metricdata.Sum[int64]).DataPoints {
				total += dp.Value
			}
		}
	}
	return total
}

func runTraces(t testing.TB, cfg *Config, td ptrace.Traces) (ptrace.Traces, error, *sdkmetric.ManualReader) {
	t.Helper()
	require.NoError(t, cfg.Validate())
	set, reader := settings(t)
	sink := new(consumertest.TracesSink)
	p, err := NewFactory().CreateTraces(context.Background(), set, cfg, sink)
	require.NoError(t, err)
	require.NoError(t, p.Start(context.Background(), componenttest.NewNopHost()))
	defer func() { require.NoError(t, p.Shutdown(context.Background())) }()
	if err := p.ConsumeTraces(context.Background(), td); err != nil {
		return ptrace.Traces{}, err, reader
	}
	require.Len(t, sink.AllTraces(), 1)
	return sink.AllTraces()[0], nil, reader
}

func runLogs(t testing.TB, cfg *Config, ld plog.Logs) plog.Logs {
	t.Helper()
	require.NoError(t, cfg.Validate())
	set, _ := settings(t)
	sink := new(consumertest.LogsSink)
	p, err := NewFactory().CreateLogs(context.Background(), set, cfg, sink)
	require.NoError(t, err)
	require.NoError(t, p.Start(context.Background(), componenttest.NewNopHost()))
	defer func() { require.NoError(t, p.Shutdown(context.Background())) }()
	require.NoError(t, p.ConsumeLogs(context.Background(), ld))
	require.Len(t, sink.AllLogs(), 1)
	return sink.AllLogs()[0]
}

func config(rules ...RuleConfig) *Config {
	cfg := createDefaultConfig().(*Config)
	cfg.Rules = rules
	return cfg
}

func genAITraces() ptrace.Traces {
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().PutStr("service.name", "agent")
	span := rs.ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.SetName("chat mistral-large")
	span.SetTraceID(pcommon.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	span.SetSpanID(pcommon.SpanID{1, 2, 3, 4, 5, 6, 7, 8})
	a := span.Attributes()
	a.PutStr("gen_ai.operation.name", "chat")
	a.PutStr("gen_ai.request.model", "mistral-large")
	a.PutInt("gen_ai.usage.input_tokens", 42)
	a.PutStr("gen_ai.input.messages", `[{"role":"user","parts":[{"type":"text","content":"Quel temps fait-il à Vélizy ?"}]}]`)
	a.PutStr("gen_ai.system_instructions", "Tu es un assistant météo.")
	args := a.PutEmptyMap("gen_ai.tool.call.arguments")
	args.PutStr("city", "Vélizy-Villacoublay")
	args.PutInt("days", 3)
	a.PutStr("gen_ai.prompt.0.content", "legacy indexed prompt")

	ev := span.Events().AppendEmpty()
	ev.SetName("gen_ai.content.completion")
	ev.Attributes().PutStr("gen_ai.completion", "Il fera beau.")
	return td
}

// decryptTraces round-trips the processor output through OTLP JSON and the
// out-of-pipeline decryptor.
func decryptTraces(t testing.TB, td ptrace.Traces, keys ...*envelope.PrivateKey) (ptrace.Traces, decrypt.Report) {
	t.Helper()
	raw, err := (&ptrace.JSONMarshaler{}).MarshalTraces(td)
	require.NoError(t, err)
	out, rep, err := decrypt.New(envelope.NewKeyring(keys...), decrypt.Options{}).Decrypt(raw)
	require.NoError(t, err)
	clear, err := (&ptrace.JSONUnmarshaler{}).UnmarshalTraces(out)
	require.NoError(t, err)
	return clear, rep
}

func TestTracesRoundTrip(t *testing.T) {
	key := newKey(t, envelope.DefaultSuite)
	cfg := config(RuleConfig{Name: "content", Recipients: []string{pubPEM(key)}, Presets: []string{"gen_ai"}})

	in := genAITraces()
	want := ptrace.NewTraces()
	in.CopyTo(want)

	out, err, reader := runTraces(t, cfg, in)
	require.NoError(t, err)

	span := out.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
	attrs := span.Attributes()

	// Metadata stays in clear text.
	model, _ := attrs.Get("gen_ai.request.model")
	require.Equal(t, "mistral-large", model.Str())
	tokens, _ := attrs.Get("gen_ai.usage.input_tokens")
	require.Equal(t, int64(42), tokens.Int())

	// Content is replaced by tokens.
	for _, k := range []string{"gen_ai.input.messages", "gen_ai.system_instructions", "gen_ai.tool.call.arguments", "gen_ai.prompt.0.content"} {
		v, ok := attrs.Get(k)
		require.True(t, ok, k)
		require.Equal(t, pcommon.ValueTypeStr, v.Type(), k)
		require.True(t, envelope.IsToken(v.Str()), "%s = %s", k, v.Str())
		require.NotContains(t, v.Str(), "Vélizy")
	}
	evAttr, _ := span.Events().At(0).Attributes().Get("gen_ai.completion")
	require.True(t, envelope.IsToken(evAttr.Str()))

	// One wrapped key per record and rule.
	var dekAttrs []string
	attrs.Range(func(k string, _ pcommon.Value) bool {
		if strings.HasPrefix(k, envelope.WrappedKeyAttrPrefix) {
			dekAttrs = append(dekAttrs, k)
		}
		return true
	})
	require.Len(t, dekAttrs, 1)

	require.Equal(t, int64(5), counter(t, reader, "otelcol_processor_encryption_values_encrypted"))
	require.Zero(t, counter(t, reader, "otelcol_processor_encryption_failures"))

	// The decryptor restores the original data, including types.
	clear, rep := decryptTraces(t, out, key)
	require.Equal(t, 5, rep.Decrypted)
	require.Zero(t, rep.Failed)
	require.Equal(t,
		want.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes().AsRaw(),
		clear.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes().AsRaw())
	require.Equal(t,
		want.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Events().At(0).Attributes().AsRaw(),
		clear.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Events().At(0).Attributes().AsRaw())
}

func TestSegregationOfDuties(t *testing.T) {
	business := newKey(t, fastSuite)
	technical := newKey(t, fastSuite)
	escrow := newKey(t, envelope.DefaultSuite)
	cfg := config(
		RuleConfig{Name: "messages", Recipients: []string{pubPEM(business), pubPEM(escrow)},
			Attributes: []string{"gen_ai.input.messages", "gen_ai.system_instructions"}},
		RuleConfig{Name: "tools", Recipients: []string{pubPEM(technical), pubPEM(escrow)},
			AttributePatterns: []string{`^gen_ai\.tool\.`}},
	)
	out, err, _ := runTraces(t, cfg, genAITraces())
	require.NoError(t, err)

	attrs := out.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
	n := 0
	attrs.Range(func(k string, _ pcommon.Value) bool {
		if strings.HasPrefix(k, envelope.WrappedKeyAttrPrefix) {
			n++
		}
		return true
	})
	require.Equal(t, 2, n, "one wrapped key per rule")

	clear, rep := decryptTraces(t, out, business)
	require.Equal(t, 2, rep.Decrypted)
	require.Equal(t, 1, rep.Failed)
	cattrs := clear.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
	v, _ := cattrs.Get("gen_ai.input.messages")
	require.Contains(t, v.Str(), "Vélizy")
	v, _ = cattrs.Get("gen_ai.tool.call.arguments")
	require.True(t, envelope.IsToken(v.Str()), "business key must not open tool payloads")

	_, rep = decryptTraces(t, out, technical)
	require.Equal(t, 1, rep.Decrypted)
	require.Equal(t, 2, rep.Failed)

	_, rep = decryptTraces(t, out, escrow)
	require.Equal(t, 3, rep.Decrypted)
	require.Zero(t, rep.Failed)
}

func TestIdempotent(t *testing.T) {
	key := newKey(t, fastSuite)
	cfg := config(RuleConfig{Recipients: []string{pubPEM(key)}, Presets: []string{"gen_ai"}})
	once, err, _ := runTraces(t, cfg, genAITraces())
	require.NoError(t, err)
	snapshot := once.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes().AsRaw()

	twice, err, reader := runTraces(t, cfg, once)
	require.NoError(t, err)
	require.Equal(t, snapshot, twice.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes().AsRaw())
	require.Zero(t, counter(t, reader, "otelcol_processor_encryption_values_encrypted"))

	_, rep := decryptTraces(t, twice, key)
	require.Equal(t, 5, rep.Decrypted)
	require.Zero(t, rep.Failed)
}

func TestOnError(t *testing.T) {
	key := newKey(t, fastSuite)
	td := func() ptrace.Traces {
		td := ptrace.NewTraces()
		span := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
		span.Attributes().PutDouble("secret.score", math.NaN()) // not JSON-serializable
		span.Attributes().PutStr("secret.text", "hello")
		return td
	}
	rule := RuleConfig{Recipients: []string{pubPEM(key)}, AttributePatterns: []string{`^secret\.`}}

	cfg := config(rule)
	out, err, reader := runTraces(t, cfg, td())
	require.NoError(t, err)
	attrs := out.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
	_, ok := attrs.Get("secret.score")
	require.False(t, ok, "unencryptable value must be deleted")
	v, _ := attrs.Get("secret.text")
	require.True(t, envelope.IsToken(v.Str()))
	require.Equal(t, int64(1), counter(t, reader, "otelcol_processor_encryption_failures"))

	cfg = config(rule)
	cfg.OnError = OnErrorReject
	_, err, _ = runTraces(t, cfg, td())
	require.ErrorContains(t, err, "secret.score")
}

func TestLogs(t *testing.T) {
	key := newKey(t, fastSuite)
	cfg := config(RuleConfig{
		Recipients:        []string{pubPEM(key)},
		Presets:           []string{"gen_ai"},
		LogBody:           true,
		LogBodyEventNames: []string{"gen_ai.user.message", "gen_ai.choice"},
	})

	ld := plog.NewLogs()
	lrs := ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords()

	user := lrs.AppendEmpty()
	user.SetEventName("gen_ai.user.message")
	user.SetTraceID(pcommon.TraceID{9})
	user.Body().SetEmptyMap().PutStr("content", "données personnelles")

	choice := lrs.AppendEmpty()
	choice.Attributes().PutStr("event.name", "gen_ai.choice")
	choice.Body().SetStr("réponse")

	details := lrs.AppendEmpty()
	details.SetEventName("gen_ai.client.inference.operation.details")
	details.Attributes().PutStr("gen_ai.output.messages", "sortie")
	details.Body().SetStr("not selected")

	plain := lrs.AppendEmpty()
	plain.Body().SetStr("regular application log")

	out := runLogs(t, cfg, ld)
	recs := out.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	require.True(t, envelope.IsToken(recs.At(0).Body().Str()))
	require.True(t, envelope.IsToken(recs.At(1).Body().Str()))
	require.Equal(t, "not selected", recs.At(2).Body().Str())
	v, _ := recs.At(2).Attributes().Get("gen_ai.output.messages")
	require.True(t, envelope.IsToken(v.Str()))
	require.Equal(t, "regular application log", recs.At(3).Body().Str())
	require.Zero(t, recs.At(3).Attributes().Len(), "no wrapped key on untouched records")

	raw, err := (&plog.JSONMarshaler{}).MarshalLogs(out)
	require.NoError(t, err)
	clearJSON, rep, err := decrypt.New(envelope.NewKeyring(key), decrypt.Options{}).Decrypt(raw)
	require.NoError(t, err)
	require.Equal(t, 3, rep.Decrypted)
	require.Zero(t, rep.Failed)
	clear, err := (&plog.JSONUnmarshaler{}).UnmarshalLogs(clearJSON)
	require.NoError(t, err)
	crecs := clear.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	require.Equal(t, map[string]any{"content": "données personnelles"}, crecs.At(0).Body().Map().AsRaw())
	require.Equal(t, "réponse", crecs.At(1).Body().Str())
}

func TestConfigValidate(t *testing.T) {
	key := pubPEM(newKey(t, fastSuite))
	valid := RuleConfig{Recipients: []string{key}, Presets: []string{"gen_ai"}}
	tests := map[string]struct {
		mutate func(*Config)
		err    string
	}{
		"valid":           {mutate: func(*Config) {}},
		"no rules":        {mutate: func(c *Config) { c.Rules = nil }, err: "at least one rule"},
		"bad on_error":    {mutate: func(c *Config) { c.OnError = "ignore" }, err: "on_error"},
		"no recipient":    {mutate: func(c *Config) { c.Rules[0].Recipients = nil }, err: "recipient"},
		"bad key":         {mutate: func(c *Config) { c.Rules[0].Recipients = []string{"nope"} }, err: "PEM"},
		"duplicate key":   {mutate: func(c *Config) { c.Rules[0].Recipients = []string{key, key} }, err: "duplicate key"},
		"no selector":     {mutate: func(c *Config) { c.Rules[0].Presets = nil }, err: "select at least one"},
		"unknown preset":  {mutate: func(c *Config) { c.Rules[0].Presets = []string{"pii"} }, err: "unknown preset"},
		"bad pattern":     {mutate: func(c *Config) { c.Rules[0].AttributePatterns = []string{"("} }, err: "invalid attribute pattern"},
		"events w/o body": {mutate: func(c *Config) { c.Rules[0].LogBodyEventNames = []string{"x"} }, err: "requires log_body"},
		"too many values": {mutate: func(c *Config) { c.KeyRotation.MaxValues = 1 << 33 }, err: "2^32"},
		"duplicate names": {mutate: func(c *Config) {
			c.Rules = []RuleConfig{{Name: "a", Recipients: []string{key}, LogBody: true}, {Name: "a", Recipients: []string{key}, LogBody: true}}
		}, err: "duplicate name"},
		"private key used": {mutate: func(c *Config) { c.Rules[0].Recipients = []string{privPEM(t)} }, err: "PEM block type"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := config(valid)
			cfg.Rules = append([]RuleConfig(nil), cfg.Rules...)
			tc.mutate(cfg)
			err := cfg.Validate()
			if tc.err == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.err)
			}
		})
	}
	require.NoError(t, componenttest.CheckConfigStruct(createDefaultConfig()))
}

func privPEM(t testing.TB) string {
	b, err := newKey(t, fastSuite).MarshalPEM()
	require.NoError(t, err)
	return string(b)
}

func BenchmarkTraces(b *testing.B) {
	key := newKey(b, envelope.DefaultSuite)
	cfg := config(RuleConfig{Recipients: []string{pubPEM(key)}, Presets: []string{"gen_ai"}})
	set, _ := settings(b)
	e, err := newEncryptor(cfg, set.Logger, set.MeterProvider.Meter(scopeName))
	require.NoError(b, err)

	prompt := strings.Repeat("Lorem ipsum dolor sit amet, ", 150) // ~4 KiB
	td := ptrace.NewTraces()
	spans := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans()
	for i := range 100 {
		s := spans.AppendEmpty()
		s.SetTraceID(pcommon.TraceID{byte(i), 1})
		s.SetSpanID(pcommon.SpanID{byte(i), 2})
		s.Attributes().PutStr("gen_ai.request.model", "m")
		s.Attributes().PutStr("gen_ai.input.messages", prompt)
		s.Attributes().PutStr("gen_ai.output.messages", prompt)
	}
	raw, _ := json.Marshal(prompt)
	b.SetBytes(int64(100 * 2 * len(raw)))
	b.ReportAllocs()
	for b.Loop() {
		b.StopTimer()
		batch := ptrace.NewTraces()
		td.CopyTo(batch)
		b.StartTimer()
		if _, err := e.processTraces(context.Background(), batch); err != nil {
			b.Fatal(err)
		}
	}
}
