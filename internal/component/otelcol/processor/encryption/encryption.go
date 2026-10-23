// Package encryption provides an otelcol.processor.encryption component.
package encryption

import (
	"time"

	"github.com/grafana/alloy/internal/component"
	"github.com/grafana/alloy/internal/component/otelcol"
	otelcolCfg "github.com/grafana/alloy/internal/component/otelcol/config"
	"github.com/grafana/alloy/internal/component/otelcol/processor"
	"github.com/grafana/alloy/internal/component/otelcol/processor/encryption/encryptionprocessor"
	"github.com/grafana/alloy/internal/component/otelcol/processor/encryption/encryptionprocessor/envelope"
	"github.com/grafana/alloy/internal/featuregate"
	"github.com/grafana/alloy/syntax"
	"github.com/grafana/alloy/syntax/alloytypes"
	otelcomponent "go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/pipeline"
)

func init() {
	component.Register(component.Registration{
		Name:      "otelcol.processor.encryption",
		Stability: featuregate.StabilityExperimental,
		Exports:   otelcol.ConsumerExports{},
		Args:      Arguments{},

		Build: func(opts component.Options, args component.Arguments) (component.Component, error) {
			return processor.New(opts, encryptionprocessor.NewFactory(), args.(Arguments))
		},
	})
}

// Arguments configures the otelcol.processor.encryption component.
type Arguments struct {
	// OnError selects what happens when a value can't be encrypted.
	OnError string `alloy:"on_error,attr,optional"`

	// SigningKey is an optional PEM encoded record signing key.
	SigningKey alloytypes.Secret `alloy:"signing_key,attr,optional"`

	// AcceptEncryptedInput keeps values already encrypted by another tier,
	// when the record is signed by one of UpstreamVerifyKeys.
	AcceptEncryptedInput bool `alloy:"accept_encrypted_input,attr,optional"`

	// UpstreamVerifyKeys are the PEM encoded verification keys of the
	// upstream tiers.
	UpstreamVerifyKeys []string `alloy:"upstream_verify_keys,attr,optional"`

	// KeyRotation controls data encryption key rotation.
	KeyRotation KeyRotationArguments `alloy:"key_rotation,block,optional"`

	// Rules select the values to encrypt and their recipients.
	Rules []RuleArguments `alloy:"rule,block"`

	// Output configures where to send processed data. Required.
	Output *otelcol.ConsumerArguments `alloy:"output,block"`

	// DebugMetrics configures component internal metrics. Optional.
	DebugMetrics otelcolCfg.DebugMetricsArguments `alloy:"debug_metrics,block,optional"`
}

// KeyRotationArguments configures data encryption key rotation.
type KeyRotationArguments struct {
	MaxValues uint64        `alloy:"max_values,attr,optional"`
	MaxAge    time.Duration `alloy:"max_age,attr,optional"`
}

// RuleArguments configures one encryption rule.
type RuleArguments struct {
	Name              string                      `alloy:"name,attr,optional"`
	Recipients        []alloytypes.OptionalSecret `alloy:"recipients,attr"`
	Presets           []string                    `alloy:"presets,attr,optional"`
	Attributes        []string                    `alloy:"attributes,attr,optional"`
	AttributePatterns []string                    `alloy:"attribute_patterns,attr,optional"`
	LogBody           bool                        `alloy:"log_body,attr,optional"`
	LogBodyEventNames []string                    `alloy:"log_body_event_names,attr,optional"`
}

var (
	_ processor.Arguments = Arguments{}
	_ syntax.Validator    = (*Arguments)(nil)
	_ syntax.Defaulter    = (*Arguments)(nil)
	_ syntax.Defaulter    = (*KeyRotationArguments)(nil)
)

// SetToDefault implements syntax.Defaulter.
func (args *Arguments) SetToDefault() {
	*args = Arguments{OnError: string(encryptionprocessor.OnErrorDelete)}
	args.KeyRotation.SetToDefault()
	args.DebugMetrics.SetToDefault()
}

// SetToDefault implements syntax.Defaulter.
func (args *KeyRotationArguments) SetToDefault() {
	*args = KeyRotationArguments{
		MaxValues: envelope.DefaultMaxUses,
		MaxAge:    envelope.DefaultMaxAge,
	}
}

// Validate implements syntax.Validator.
func (args *Arguments) Validate() error {
	cfg, err := args.Convert()
	if err != nil {
		return err
	}
	return cfg.(*encryptionprocessor.Config).Validate()
}

// Convert implements processor.Arguments.
func (args Arguments) Convert() (otelcomponent.Config, error) {
	cfg := encryptionprocessor.NewFactory().CreateDefaultConfig().(*encryptionprocessor.Config)
	cfg.OnError = encryptionprocessor.OnError(args.OnError)
	cfg.SigningKey = configopaque.String(args.SigningKey)
	cfg.AcceptEncryptedInput = args.AcceptEncryptedInput
	cfg.UpstreamVerifyKeys = append([]string(nil), args.UpstreamVerifyKeys...)
	cfg.KeyRotation = encryptionprocessor.KeyRotationConfig{
		MaxValues: args.KeyRotation.MaxValues,
		MaxAge:    args.KeyRotation.MaxAge,
	}
	cfg.Rules = make([]encryptionprocessor.RuleConfig, 0, len(args.Rules))
	for _, r := range args.Rules {
		recipients := make([]string, 0, len(r.Recipients))
		for _, k := range r.Recipients {
			recipients = append(recipients, k.Value)
		}
		cfg.Rules = append(cfg.Rules, encryptionprocessor.RuleConfig{
			Name:              r.Name,
			Recipients:        recipients,
			Presets:           append([]string(nil), r.Presets...),
			Attributes:        append([]string(nil), r.Attributes...),
			AttributePatterns: append([]string(nil), r.AttributePatterns...),
			LogBody:           r.LogBody,
			LogBodyEventNames: append([]string(nil), r.LogBodyEventNames...),
		})
	}
	return cfg, nil
}

// Extensions implements processor.Arguments.
func (args Arguments) Extensions() map[otelcomponent.ID]otelcomponent.Component {
	return nil
}

// Exporters implements processor.Arguments.
func (args Arguments) Exporters() map[pipeline.Signal]map[otelcomponent.ID]otelcomponent.Component {
	return nil
}

// NextConsumers implements processor.Arguments.
func (args Arguments) NextConsumers() *otelcol.ConsumerArguments {
	return args.Output
}

// DebugMetricsConfig implements processor.Arguments.
func (args Arguments) DebugMetricsConfig() otelcolCfg.DebugMetricsArguments {
	return args.DebugMetrics
}
