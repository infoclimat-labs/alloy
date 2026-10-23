package encryptionprocessor

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/ptrace"

	"github.com/grafana/alloy/internal/component/otelcol/processor/encryption/encryptionprocessor/decrypt"
	"github.com/grafana/alloy/internal/component/otelcol/processor/encryption/encryptionprocessor/envelope"
)

// Regression tests for the findings of the second security review.

func signedSetup(t *testing.T) (*envelope.PrivateKey, *envelope.SigningKey, *Config, decrypt.Options) {
	key := newKey(t, fastSuite)
	signer, err := envelope.GenerateSigningKey(envelope.SigEd25519)
	require.NoError(t, err)
	cfg := config(RuleConfig{Recipients: []string{pubPEM(key)}, Presets: []string{"gen_ai"}})
	cfg.SigningKey = configString(signer)
	return key, signer, cfg, decrypt.Options{Verifier: envelope.NewVerifier(signer.Public()), RequireSignature: true}
}

// N1: a token forged with the public key and sent to a tier that accepts
// encrypted input must not come out signed.
func TestAcceptInputDoesNotLaunderForgeries(t *testing.T) {
	key, _, cfg, opts := signedSetup(t)
	upstream, err := envelope.GenerateSigningKey(envelope.SigEd25519)
	require.NoError(t, err)
	cfg.AcceptEncryptedInput = true
	cfg.UpstreamVerifyKeys = []string{string(upstream.Public().MarshalPEM())}

	s, err := envelope.NewSealer([]*envelope.PublicKey{key.Public()}, envelope.SealerOptions{})
	require.NoError(t, err)
	d, _ := s.Current()
	rid := make([]byte, 16)
	_, _ = rand.Read(rid)
	tok, err := d.Seal(envelope.EncodeString("gen_ai.output.messages", "I approve wiring 1M EUR"), envelope.Context{
		Signal: "traces", Scope: "span", Key: "gen_ai.output.messages", RecordID: rid,
		TraceID: (&[16]byte{1})[:], SpanID: (&[8]byte{2})[:]})
	require.NoError(t, err)
	td, span := newSpan()
	span.Attributes().PutStr("gen_ai.output.messages", tok)
	span.Attributes().PutStr(d.AttributeKey(), d.WrappedKey())
	span.Attributes().PutStr(envelope.RecordIDAttr, hex.EncodeToString(rid))

	out, _, err := runTraces(t, cfg, td)
	require.NoError(t, err)
	raw, _ := (&ptrace.JSONMarshaler{}).MarshalTraces(out)
	clear, rep := decryptDoc(t, raw, opts, key)
	require.Equal(t, 1, rep.Verified, rep.Errors)
	// The forged token was treated as clear text and encrypted again: it
	// decrypts to the token string, never to the forged content.
	require.NotContains(t, clear, "I approve wiring 1M EUR")
	require.Contains(t, clear, tok)

	// accept_encrypted_input without pinned upstream keys is refused.
	bad := config(RuleConfig{Recipients: []string{pubPEM(key)}, Presets: []string{"gen_ai"}})
	bad.AcceptEncryptedInput = true
	require.ErrorContains(t, bad.Validate(), "upstream_verify_keys")
}

// N2: clear text added to a signed record is detected.
func TestPlaintextInjectionDetected(t *testing.T) {
	key, _, cfg, opts := signedSetup(t)
	td, span := newSpan()
	span.Attributes().PutStr("gen_ai.input.messages", "hello")
	out, _, err := runTraces(t, cfg, td)
	require.NoError(t, err)
	doc := mutateJSON(t, out, func(span map[string]any) {
		span["attributes"] = append(span["attributes"].([]any), map[string]any{
			"key": "gen_ai.output.messages", "value": map[string]any{"stringValue": "FORGED ANSWER"}})
	})
	_, rep := decryptDoc(t, doc, opts, key)
	require.Equal(t, 1, rep.Invalid)
	require.Zero(t, rep.Verified)

	// Retiming or renaming the span is detected too.
	doc = mutateJSON(t, out, func(span map[string]any) { span["name"] = "renamed" })
	_, rep = decryptDoc(t, doc, opts, key)
	require.Equal(t, 1, rep.Invalid)
}

// N3: stripping the encryption from a signed record is detected.
func TestStrippedRecordDetected(t *testing.T) {
	key, _, cfg, opts := signedSetup(t)
	td, span := newSpan()
	span.Attributes().PutStr("gen_ai.input.messages", "hello")
	out, _, err := runTraces(t, cfg, td)
	require.NoError(t, err)
	doc := mutateJSON(t, out, func(span map[string]any) {
		var keep []any
		for _, a := range span["attributes"].([]any) {
			am := a.(map[string]any)
			k := am["key"].(string)
			if strings.HasPrefix(k, "encryption.") {
				continue
			}
			if k == "gen_ai.input.messages" {
				am["value"] = map[string]any{"stringValue": "FORGED PROMPT"}
			}
			keep = append(keep, am)
		}
		span["attributes"] = keep
	})
	_, rep := decryptDoc(t, doc, opts, key)
	require.Equal(t, 1, rep.Unsigned)
	require.Equal(t, 1, rep.Failed)

	// Records without encrypted values are signed as well.
	td2, span2 := newSpan()
	span2.Attributes().PutStr("gen_ai.request.model", "m")
	out2, _, err := runTraces(t, cfg, td2)
	require.NoError(t, err)
	_, ok := firstSpan(out2).Attributes().Get(envelope.SignatureAttr)
	require.True(t, ok)
}

// N4: the event name of an encrypted log body is authenticated.
func TestEventNameAuthenticated(t *testing.T) {
	key, signer, _, opts := signedSetup(t)
	cfg := config(RuleConfig{Recipients: []string{pubPEM(key)}, LogBody: true})
	cfg.SigningKey = configString(signer)
	ld := plog.NewLogs()
	lr := ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	lr.SetEventName("gen_ai.user.message")
	lr.SetTraceID(pcommon.TraceID{1})
	lr.Body().SetStr("delete all backups")
	out := runLogs(t, cfg, ld)
	olr := out.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	v, _ := olr.Attributes().Get(envelope.EventAttr)
	require.Equal(t, "gen_ai.user.message", v.Str())

	raw, _ := (&plog.JSONMarshaler{}).MarshalLogs(out)
	_, rep, err := decrypt.New(envelope.NewKeyring(key), opts).Decrypt(raw)
	require.NoError(t, err)
	require.Equal(t, 1, rep.Verified)
	require.Equal(t, 1, rep.Decrypted)

	// Changing who spoke breaks the signature (EventName field)...
	olr.SetEventName("gen_ai.assistant.message")
	raw, _ = (&plog.JSONMarshaler{}).MarshalLogs(out)
	_, rep, _ = decrypt.New(envelope.NewKeyring(key), opts).Decrypt(raw)
	require.Equal(t, 1, rep.Invalid)
	require.Zero(t, rep.Decrypted)

	// ...and the ciphertext binding (bound event attribute), even unsigned.
	olr.SetEventName("gen_ai.user.message")
	olr.Attributes().PutStr(envelope.EventAttr, "gen_ai.assistant.message")
	raw, _ = (&plog.JSONMarshaler{}).MarshalLogs(out)
	_, rep, _ = decrypt.New(envelope.NewKeyring(key), decrypt.Options{}).Decrypt(raw)
	require.Equal(t, 1, rep.Failed)
}

// N5: processor metadata keys can't hide content on events and links, and
// other encryption.* keys are matched like any key.
func TestEncryptionPrefixedKeysOnEvents(t *testing.T) {
	key := newKey(t, fastSuite)
	cfg := config(RuleConfig{Recipients: []string{pubPEM(key)}, AttributePatterns: []string{`.*`}})
	td, span := newSpan()
	ev := span.Events().AppendEmpty()
	ev.Attributes().PutStr("encryption.note", "secret in clear")
	ev.Attributes().PutStr("encryption.dek.000000000000000000", "secret in a fake wrapped key")
	out, _, err := runTraces(t, cfg, td)
	require.NoError(t, err)
	attrs := firstSpan(out).Events().At(0).Attributes()
	v, _ := attrs.Get("encryption.note")
	require.True(t, envelope.IsToken(v.Str()))
	_, ok := attrs.Get("encryption.dek.000000000000000000")
	require.False(t, ok)
}
