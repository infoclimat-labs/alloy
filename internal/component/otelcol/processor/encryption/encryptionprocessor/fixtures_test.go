package encryptionprocessor

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/ptrace"

	"github.com/grafana/alloy/internal/component/otelcol/processor/encryption/encryptionprocessor/decrypt"
	"github.com/grafana/alloy/internal/component/otelcol/processor/encryption/encryptionprocessor/envelope"
)

// The fixtures are OTLP/HTTP protobuf payloads captured from the OpenTelemetry
// Python SDK running example/encryption/generator/generate.py. They contain the
// marker "Velizy-Villacoublay" in prompts, tool payloads and log bodies.
const fixtureMarker = "Velizy-Villacoublay"

func demoConfig(business, technical, escrow *envelope.PrivateKey) *Config {
	return config(
		RuleConfig{
			Name:       "messages",
			Recipients: []string{pubPEM(business), pubPEM(escrow)},
			Attributes: []string{
				"gen_ai.input.messages", "gen_ai.output.messages", "gen_ai.system_instructions",
				"gen_ai.prompt", "gen_ai.completion",
			},
			LogBody:           true,
			LogBodyEventNames: []string{"gen_ai.system.message", "gen_ai.user.message", "gen_ai.assistant.message", "gen_ai.choice"},
		},
		RuleConfig{
			Name:              "tools",
			Recipients:        []string{pubPEM(technical), pubPEM(escrow)},
			Attributes:        []string{"gen_ai.tool.definitions", "gen_ai.tool.call.arguments", "gen_ai.tool.call.result"},
			LogBody:           true,
			LogBodyEventNames: []string{"gen_ai.tool.message"},
		},
	)
}

func TestPythonSDKFixtures(t *testing.T) {
	business, technical, escrow := newKey(t, fastSuite), newKey(t, fastSuite), newKey(t, envelope.DefaultSuite)
	cfg := demoConfig(business, technical, escrow)

	t.Run("traces", func(t *testing.T) {
		raw, err := os.ReadFile("testdata/python-sdk-traces.pb")
		require.NoError(t, err)
		td, err := (&ptrace.ProtoUnmarshaler{}).UnmarshalTraces(raw)
		require.NoError(t, err)
		require.Equal(t, 4, td.SpanCount())

		out, err, _ := runTraces(t, cfg, td)
		require.NoError(t, err)
		js, err := (&ptrace.JSONMarshaler{}).MarshalTraces(out)
		require.NoError(t, err)
		require.NotContains(t, string(js), fixtureMarker, "content leaked in clear text")
		require.Contains(t, string(js), "mistral-large-latest", "metadata must stay in clear text")

		for _, tc := range []struct {
			key               *envelope.PrivateKey
			decrypted, failed int
		}{
			// messages: 2 attributes on the first chat span, 1 on the second.
			// tools: definitions on the first chat span, arguments and result on the tool span.
			{business, 4, 3},
			{technical, 3, 4},
			{escrow, 7, 0},
		} {
			clear, rep, err := decrypt.New(envelope.NewKeyring(tc.key), decrypt.Options{}).Decrypt(js)
			require.NoError(t, err)
			require.Equal(t, tc.decrypted, rep.Decrypted, rep.Errors)
			require.Equal(t, tc.failed, rep.Failed, rep.Errors)
			if tc.key == escrow {
				require.Contains(t, string(clear), fixtureMarker)
				require.NotContains(t, string(clear), envelope.TokenPrefix)
			}
		}
	})

	t.Run("logs", func(t *testing.T) {
		raw, err := os.ReadFile("testdata/python-sdk-logs.pb")
		require.NoError(t, err)
		ld, err := (&plog.ProtoUnmarshaler{}).UnmarshalLogs(raw)
		require.NoError(t, err)
		require.Equal(t, 4, ld.LogRecordCount())

		out := runLogs(t, cfg, ld)
		js, err := (&plog.JSONMarshaler{}).MarshalLogs(out)
		require.NoError(t, err)
		require.NotContains(t, string(js), fixtureMarker)
		require.False(t, bytes.Contains(js, []byte("ne divulgue")), "system message leaked")

		clear, rep, err := decrypt.New(envelope.NewKeyring(escrow), decrypt.Options{}).Decrypt(js)
		require.NoError(t, err)
		require.Equal(t, 4, rep.Decrypted, rep.Errors)
		require.Zero(t, rep.Failed, rep.Errors)
		require.Contains(t, string(clear), fixtureMarker)
	})
}
