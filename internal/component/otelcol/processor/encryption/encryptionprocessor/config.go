package encryptionprocessor

import (
	"errors"
	"fmt"
	"regexp"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configopaque"

	"github.com/grafana/alloy/internal/component/otelcol/processor/encryption/encryptionprocessor/envelope"
)

// OnError selects what happens when a value can't be encrypted.
type OnError string

const (
	// OnErrorDelete removes the attribute (or empties the log body) so that
	// plaintext never leaves the processor. This is the default.
	OnErrorDelete OnError = "delete"
	// OnErrorReject fails the whole batch and returns the error upstream.
	OnErrorReject OnError = "reject"
)

// Config is the configuration of the encryption processor.
type Config struct {
	// Rules select values to encrypt and the recipients able to decrypt
	// them. An attribute matched by several rules is encrypted by the first
	// one.
	Rules []RuleConfig `mapstructure:"rules"`

	// OnError selects the behaviour when encryption fails.
	OnError OnError `mapstructure:"on_error"`

	// KeyRotation controls how often data encryption keys are renewed.
	KeyRotation KeyRotationConfig `mapstructure:"key_rotation"`

	// SigningKey is an optional PEM encoded signing key. When set, every
	// record carrying encrypted values is signed, so that a decryptor
	// pinning the verification key detects forged, moved, altered or
	// deleted values.
	SigningKey configopaque.String `mapstructure:"signing_key"`

	// AcceptEncryptedInput keeps values that are already encrypted, for
	// example by another Alloy tier, instead of encrypting them again.
	// Encrypted values of a record are only kept when the record carries a
	// valid signature from one of UpstreamVerifyKeys; otherwise, and when
	// false (the default), incoming encryption attributes are removed and
	// token-like values are encrypted like any other value, so a client can't
	// smuggle clear text or forged values past the processor.
	AcceptEncryptedInput bool `mapstructure:"accept_encrypted_input"`

	// UpstreamVerifyKeys are the PEM encoded verification keys of the
	// upstream tiers whose signed records are accepted. Required by
	// AcceptEncryptedInput.
	UpstreamVerifyKeys []string `mapstructure:"upstream_verify_keys"`

	_ struct{}
}

// KeyRotationConfig controls data encryption key rotation.
type KeyRotationConfig struct {
	// MaxValues is the number of values encrypted with one data encryption
	// key before it is rotated.
	MaxValues uint64 `mapstructure:"max_values"`
	// MaxAge is the maximum lifetime of a data encryption key.
	MaxAge time.Duration `mapstructure:"max_age"`
}

// RuleConfig selects values and the recipients they are encrypted for.
type RuleConfig struct {
	// Name identifies the rule in metrics and logs.
	Name string `mapstructure:"name"`

	// Recipients are PEM encoded public keys. Every recipient can decrypt
	// every value encrypted by the rule.
	Recipients []string `mapstructure:"recipients"`

	// Presets add well-known attribute sets. Supported: "gen_ai",
	// "openinference", "exceptions".
	Presets []string `mapstructure:"presets"`

	// Attributes are exact attribute keys to encrypt.
	Attributes []string `mapstructure:"attributes"`

	// AttributePatterns are regular expressions matched against attribute
	// keys.
	AttributePatterns []string `mapstructure:"attribute_patterns"`

	// LogBody encrypts the body of log records.
	LogBody bool `mapstructure:"log_body"`

	// LogBodyEventNames restricts LogBody to log records whose event name
	// (the EventName field or the event.name attribute) is in the list. An
	// empty list encrypts every log body.
	LogBodyEventNames []string `mapstructure:"log_body_event_names"`
}

var _ component.Config = (*Config)(nil)

func createDefaultConfig() component.Config {
	return &Config{
		OnError: OnErrorDelete,
		KeyRotation: KeyRotationConfig{
			MaxValues: envelope.DefaultMaxUses,
			MaxAge:    envelope.DefaultMaxAge,
		},
	}
}

// Validate checks the configuration.
func (cfg *Config) Validate() error {
	if len(cfg.Rules) == 0 {
		return errors.New("at least one rule is required")
	}
	switch cfg.OnError {
	case OnErrorDelete, OnErrorReject:
	default:
		return fmt.Errorf("on_error must be %q or %q, got %q", OnErrorDelete, OnErrorReject, cfg.OnError)
	}
	if cfg.KeyRotation.MaxValues > 1<<31 {
		return errors.New("key_rotation.max_values must not exceed 2^31 (AES-GCM random nonce limit)")
	}
	if cfg.KeyRotation.MaxAge < 0 {
		return errors.New("key_rotation.max_age must not be negative")
	}

	if _, err := cfg.signingKey(); err != nil {
		return fmt.Errorf("signing_key: %w", err)
	}
	if cfg.AcceptEncryptedInput && len(cfg.UpstreamVerifyKeys) == 0 {
		return errors.New("accept_encrypted_input requires upstream_verify_keys: unsigned encrypted input can be forged by anyone holding a recipient public key")
	}
	if _, err := cfg.upstreamVerifier(); err != nil {
		return fmt.Errorf("upstream_verify_keys: %w", err)
	}

	names := make(map[string]bool, len(cfg.Rules))
	var errs []error
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		label := r.label(i)
		if r.Name != "" {
			if names[r.Name] {
				errs = append(errs, fmt.Errorf("rule %s: duplicate name", label))
			}
			names[r.Name] = true
		}
		if err := r.validate(); err != nil {
			errs = append(errs, fmt.Errorf("rule %s: %w", label, err))
		}
	}
	return errors.Join(errs...)
}

func (r *RuleConfig) label(i int) string {
	if r.Name != "" {
		return fmt.Sprintf("%q", r.Name)
	}
	return fmt.Sprintf("#%d", i)
}

func (r *RuleConfig) validate() error {
	if len(r.Recipients) == 0 {
		return errors.New("at least one recipient is required")
	}
	if _, err := r.publicKeys(); err != nil {
		return err
	}
	if len(r.Presets) == 0 && len(r.Attributes) == 0 && len(r.AttributePatterns) == 0 && !r.LogBody {
		return errors.New("select at least one of presets, attributes, attribute_patterns or log_body")
	}
	if len(r.LogBodyEventNames) > 0 && !r.LogBody {
		return errors.New("log_body_event_names requires log_body")
	}
	for _, p := range r.Presets {
		if _, ok := presets[p]; !ok {
			return fmt.Errorf("unknown preset %q", p)
		}
	}
	for _, p := range r.AttributePatterns {
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("invalid attribute pattern %q: %w", p, err)
		}
	}
	return nil
}

func (r *RuleConfig) publicKeys() ([]*envelope.PublicKey, error) {
	keys := make([]*envelope.PublicKey, 0, len(r.Recipients))
	seen := make(map[string]bool, len(r.Recipients))
	for i, pemData := range r.Recipients {
		k, err := envelope.ParsePublicKey([]byte(pemData))
		if err != nil {
			return nil, fmt.Errorf("recipient #%d: %w", i, err)
		}
		if seen[k.KeyID()] {
			return nil, fmt.Errorf("recipient #%d: duplicate key %s", i, k.KeyID())
		}
		seen[k.KeyID()] = true
		keys = append(keys, k)
	}
	return keys, nil
}

func (cfg *Config) signingKey() (*envelope.SigningKey, error) {
	if cfg.SigningKey == "" {
		return nil, nil
	}
	return envelope.ParseSigningKey([]byte(cfg.SigningKey))
}

func (cfg *Config) upstreamVerifier() (*envelope.Verifier, error) {
	if len(cfg.UpstreamVerifyKeys) == 0 {
		return nil, nil
	}
	keys := make([]*envelope.VerifyKey, 0, len(cfg.UpstreamVerifyKeys))
	for i, p := range cfg.UpstreamVerifyKeys {
		k, err := envelope.ParseVerifyKey([]byte(p))
		if err != nil {
			return nil, fmt.Errorf("key #%d: %w", i, err)
		}
		keys = append(keys, k)
	}
	return envelope.NewVerifier(keys...), nil
}
