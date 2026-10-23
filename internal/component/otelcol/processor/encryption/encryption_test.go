package encryption_test

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"

	"github.com/grafana/alloy/internal/component/otelcol"
	"github.com/grafana/alloy/internal/component/otelcol/internal/fakeconsumer"
	"github.com/grafana/alloy/internal/component/otelcol/processor/encryption"
	"github.com/grafana/alloy/internal/component/otelcol/processor/encryption/encryptionprocessor"
	"github.com/grafana/alloy/internal/component/otelcol/processor/encryption/encryptionprocessor/envelope"
	"github.com/grafana/alloy/internal/runtime/componenttest"
	"github.com/grafana/alloy/internal/util"
	"github.com/grafana/alloy/syntax"
)

func publicKey(t *testing.T) (*envelope.PrivateKey, string) {
	t.Helper()
	k, err := envelope.GenerateKey(envelope.Suite{KEM: envelope.KEMX25519HKDFSHA256, KDF: envelope.KDFHKDFSHA256, AEAD: envelope.AEADAES256GCM})
	require.NoError(t, err)
	return k, string(k.Public().MarshalPEM())
}

// alloyString renders a PEM key as an Alloy raw string.
func alloyString(s string) string { return "`" + s + "`" }

func TestArguments_UnmarshalAlloy(t *testing.T) {
	_, pub := publicKey(t)
	sk, err := envelope.GenerateSigningKey(envelope.SigEd25519)
	require.NoError(t, err)
	cfg := `
		on_error = "reject"
		signing_key = ` + alloyString(string(sk.MarshalPEM())) + `
		accept_encrypted_input = true
		upstream_verify_keys = [` + alloyString(string(sk.Public().MarshalPEM())) + `]

		key_rotation {
			max_values = 1000
			max_age    = "1m"
		}

		rule {
			name       = "content"
			recipients = [` + alloyString(pub) + `]
			presets    = ["gen_ai"]
			attributes = ["app.user.question"]
			attribute_patterns = ["^mcp\\..*\\.arguments$"]
			log_body   = true
			log_body_event_names = ["gen_ai.user.message"]
		}

		rule {
			recipients = [` + alloyString(pub) + `]
			attributes = ["gen_ai.tool.call.result"]
		}

		output {}
	`
	var args encryption.Arguments
	require.NoError(t, syntax.Unmarshal([]byte(cfg), &args))

	converted, err := args.Convert()
	require.NoError(t, err)
	c := converted.(*encryptionprocessor.Config)
	require.Equal(t, encryptionprocessor.OnErrorReject, c.OnError)
	require.Equal(t, string(sk.MarshalPEM()), string(c.SigningKey))
	require.True(t, c.AcceptEncryptedInput)
	require.Len(t, c.UpstreamVerifyKeys, 1)
	require.Equal(t, uint64(1000), c.KeyRotation.MaxValues)
	require.Equal(t, time.Minute, c.KeyRotation.MaxAge)
	require.Len(t, c.Rules, 2)
	require.Equal(t, encryptionprocessor.RuleConfig{
		Name:              "content",
		Recipients:        []string{pub},
		Presets:           []string{"gen_ai"},
		Attributes:        []string{"app.user.question"},
		AttributePatterns: []string{`^mcp\..*\.arguments$`},
		LogBody:           true,
		LogBodyEventNames: []string{"gen_ai.user.message"},
	}, c.Rules[0])
	require.NoError(t, c.Validate())
}

func TestArguments_Defaults(t *testing.T) {
	_, pub := publicKey(t)
	var args encryption.Arguments
	require.NoError(t, syntax.Unmarshal([]byte(`
		rule {
			recipients = [`+alloyString(pub)+`]
			presets    = ["gen_ai"]
		}
		output {}
	`), &args))
	converted, err := args.Convert()
	require.NoError(t, err)
	c := converted.(*encryptionprocessor.Config)
	require.Equal(t, encryptionprocessor.OnErrorDelete, c.OnError)
	require.Equal(t, uint64(envelope.DefaultMaxUses), c.KeyRotation.MaxValues)
	require.Equal(t, envelope.DefaultMaxAge, c.KeyRotation.MaxAge)
}

func TestArguments_Validate(t *testing.T) {
	_, pub := publicKey(t)
	tests := map[string]struct {
		cfg string
		err string
	}{
		"no rule": {
			cfg: `output {}`,
			err: `missing required block "rule"`,
		},
		"invalid key": {
			cfg: `
				rule {
					recipients = ["not a key"]
					presets    = ["gen_ai"]
				}
				output {}`,
			err: "no PEM block found",
		},
		"no selector": {
			cfg: `
				rule {
					recipients = [` + alloyString(pub) + `]
				}
				output {}`,
			err: "select at least one",
		},
		"bad on_error": {
			cfg: `
				on_error = "ignore"
				rule {
					recipients = [` + alloyString(pub) + `]
					presets    = ["gen_ai"]
				}
				output {}`,
			err: "on_error",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var args encryption.Arguments
			err := syntax.Unmarshal([]byte(tc.cfg), &args)
			require.ErrorContains(t, err, tc.err)
		})
	}
}

// TestPipeline runs the component in the Alloy runtime and decrypts its
// output.
func TestPipeline(t *testing.T) {
	priv, pub := publicKey(t)
	ctx := componenttest.TestContext(t)
	l := util.TestLogger(t)

	ctrl, err := componenttest.NewControllerFromID(l, "otelcol.processor.encryption")
	require.NoError(t, err)

	var args encryption.Arguments
	require.NoError(t, syntax.Unmarshal([]byte(`
		rule {
			recipients = [`+alloyString(pub)+`]
			presets    = ["gen_ai"]
		}
		output {}
	`), &args))

	traceCh := make(chan ptrace.Traces, 1)
	args.Output = &otelcol.ConsumerArguments{
		Traces: []otelcol.Consumer{&fakeconsumer.Consumer{
			ConsumeTracesFunc: func(_ context.Context, td ptrace.Traces) error {
				select {
				case traceCh <- td:
				default:
				}
				return nil
			},
		}},
	}

	go func() { require.NoError(t, ctrl.Run(ctx, args)) }()
	require.NoError(t, ctrl.WaitRunning(time.Second))
	require.NoError(t, ctrl.WaitExports(time.Second))

	td := ptrace.NewTraces()
	span := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.SetTraceID([16]byte{1})
	span.SetSpanID([8]byte{2})
	span.Attributes().PutStr("gen_ai.input.messages", "secret prompt")
	span.Attributes().PutStr("gen_ai.request.model", "model")

	exports := ctrl.Exports().(otelcol.ConsumerExports)
	require.Eventually(t, func() bool {
		return exports.Input.ConsumeTraces(ctx, td) == nil
	}, 5*time.Second, 50*time.Millisecond)

	select {
	case out := <-traceCh:
		attrs := out.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
		v, ok := attrs.Get("gen_ai.input.messages")
		require.True(t, ok)
		require.True(t, envelope.IsToken(v.Str()))
		model, _ := attrs.Get("gen_ai.request.model")
		require.Equal(t, "model", model.Str())

		var wrapped, dekID string
		attrs.Range(func(k string, val pcommon.Value) bool {
			if id, ok := strings.CutPrefix(k, envelope.WrappedKeyAttrPrefix); ok {
				dekID, wrapped = id, val.Str()
			}
			return true
		})
		dek, err := envelope.NewKeyring(priv).Unwrap(dekID, wrapped)
		require.NoError(t, err)
		ridAttr, ok := attrs.Get(envelope.RecordIDAttr)
		require.True(t, ok)
		rid, err := hex.DecodeString(ridAttr.Str())
		require.NoError(t, err)
		traceID, spanID := [16]byte{1}, [8]byte{2}
		pt, err := dek.Open(v.Str(), envelope.Context{Signal: "traces", Scope: "span", Key: "gen_ai.input.messages", RecordID: rid, TraceID: traceID[:], SpanID: spanID[:]})
		require.NoError(t, err)
		require.Equal(t, envelope.EncodeString("gen_ai.input.messages", "secret prompt"), pt)
	case <-time.After(5 * time.Second):
		t.Fatal("no output received")
	}
}
