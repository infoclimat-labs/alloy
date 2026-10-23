// Package encryptionprocessor implements an OpenTelemetry Collector processor
// that encrypts selected span, span event and log attributes, as well as log
// bodies, with hybrid public-key encryption (HPKE, RFC 9180).
//
// Values are encrypted for one or more recipient public keys. The collector
// never holds a private key: decryption happens outside the pipeline, for
// example with the otelcrypt command.
package encryptionprocessor

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/processor/processorhelper"
)

const (
	typeStr   = "encryption"
	stability = component.StabilityLevelDevelopment
	scopeName = "github.com/grafana/alloy/internal/component/otelcol/processor/encryption/encryptionprocessor"
)

var processorCapabilities = consumer.Capabilities{MutatesData: true}

// NewFactory returns the factory of the encryption processor.
func NewFactory() processor.Factory {
	return processor.NewFactory(
		component.MustNewType(typeStr),
		createDefaultConfig,
		processor.WithTraces(createTraces, stability),
		processor.WithLogs(createLogs, stability),
	)
}

func newFromSettings(set processor.Settings, cfg component.Config) (*encryptor, error) {
	c := cfg.(*Config)
	if len(c.Rules) == 0 {
		return nil, errNoRules
	}
	return newEncryptor(c, set.Logger, set.MeterProvider.Meter(scopeName))
}

func createTraces(ctx context.Context, set processor.Settings, cfg component.Config, next consumer.Traces) (processor.Traces, error) {
	e, err := newFromSettings(set, cfg)
	if err != nil {
		return nil, err
	}
	return processorhelper.NewTraces(ctx, set, cfg, next, e.processTraces,
		processorhelper.WithCapabilities(processorCapabilities))
}

func createLogs(ctx context.Context, set processor.Settings, cfg component.Config, next consumer.Logs) (processor.Logs, error) {
	e, err := newFromSettings(set, cfg)
	if err != nil {
		return nil, err
	}
	return processorhelper.NewLogs(ctx, set, cfg, next, e.processLogs,
		processorhelper.WithCapabilities(processorCapabilities))
}
