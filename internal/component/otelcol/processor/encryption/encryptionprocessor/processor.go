package encryptionprocessor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.uber.org/zap"

	"github.com/grafana/alloy/internal/component/otelcol/processor/encryption/encryptionprocessor/envelope"
)

// Scope values bound into the AEAD additional data.
const (
	scopeSpan      = "span"
	scopeSpanEvent = "span_event"
	scopeLog       = "log"
	scopeLogBody   = "log_body"

	signalTraces = "traces"
	signalLogs   = "logs"

	eventNameAttr = "event.name"
)

type rule struct {
	name       string
	sealer     *envelope.Sealer
	logBody    bool
	bodyEvents map[string]bool

	attrs metric.MeasurementOption
}

type encryptor struct {
	logger  *zap.Logger
	onError OnError

	rules    []*rule
	exact    map[string]*rule
	patterns []patternRule

	valuesEncrypted metric.Int64Counter
	bytesEncrypted  metric.Int64Counter
	failures        metric.Int64Counter
}

type patternRule struct {
	re   *regexp.Regexp
	rule *rule
}

func newEncryptor(cfg *Config, logger *zap.Logger, meter metric.Meter) (*encryptor, error) {
	e := &encryptor{
		logger:  logger,
		onError: cfg.OnError,
		exact:   map[string]*rule{},
	}
	if e.onError == "" {
		e.onError = OnErrorDelete
	}

	opts := envelope.SealerOptions{MaxUses: cfg.KeyRotation.MaxValues, MaxAge: cfg.KeyRotation.MaxAge}
	for i := range cfg.Rules {
		rc := &cfg.Rules[i]
		keys, err := rc.publicKeys()
		if err != nil {
			return nil, err
		}
		sealer, err := envelope.NewSealer(keys, opts)
		if err != nil {
			return nil, err
		}
		name := rc.Name
		if name == "" {
			name = fmt.Sprintf("rule_%d", i)
		}
		r := &rule{
			name:    name,
			sealer:  sealer,
			logBody: rc.LogBody,
			attrs:   metric.WithAttributeSet(attribute.NewSet(attribute.String("rule", name))),
		}
		if len(rc.LogBodyEventNames) > 0 {
			r.bodyEvents = make(map[string]bool, len(rc.LogBodyEventNames))
			for _, n := range rc.LogBodyEventNames {
				r.bodyEvents[n] = true
			}
		}
		e.rules = append(e.rules, r)

		attrs, patterns := slices.Clone(rc.Attributes), slices.Clone(rc.AttributePatterns)
		for _, p := range rc.Presets {
			attrs = append(attrs, presets[p].attributes...)
			patterns = append(patterns, presets[p].patterns...)
		}
		for _, a := range attrs {
			if _, taken := e.exact[a]; !taken {
				e.exact[a] = r
			}
		}
		for _, p := range patterns {
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("rule %q: %w", name, err)
			}
			e.patterns = append(e.patterns, patternRule{re: re, rule: r})
		}
		logger.Info("encryption rule configured",
			zap.String("rule", name),
			zap.Strings("recipients", sealer.Recipients()),
			zap.Int("attributes", len(attrs)),
			zap.Int("attribute_patterns", len(patterns)),
			zap.Bool("log_body", rc.LogBody))
	}

	var err error
	if e.valuesEncrypted, err = meter.Int64Counter(
		"otelcol_processor_encryption_values_encrypted",
		metric.WithDescription("Number of attribute values and log bodies encrypted."),
		metric.WithUnit("{value}"),
	); err != nil {
		return nil, err
	}
	if e.bytesEncrypted, err = meter.Int64Counter(
		"otelcol_processor_encryption_plaintext_bytes",
		metric.WithDescription("Number of plaintext bytes encrypted."),
		metric.WithUnit("By"),
	); err != nil {
		return nil, err
	}
	if e.failures, err = meter.Int64Counter(
		"otelcol_processor_encryption_failures",
		metric.WithDescription("Number of values that could not be encrypted."),
		metric.WithUnit("{value}"),
	); err != nil {
		return nil, err
	}
	return e, nil
}

// match returns the rule encrypting the attribute key, if any.
func (e *encryptor) match(key string) *rule {
	if r, ok := e.exact[key]; ok {
		return r
	}
	for _, p := range e.patterns {
		if p.re.MatchString(key) {
			return p.rule
		}
	}
	return nil
}

// record tracks the data encryption keys used for one span or log record, so
// that every value of the record under the same rule shares one wrapped key.
type record struct {
	deks map[*rule]*envelope.DEK
}

func (rec *record) dek(r *rule) (*envelope.DEK, error) {
	if d, ok := rec.deks[r]; ok {
		return d, nil
	}
	d, err := r.sealer.Current()
	if err != nil {
		return nil, err
	}
	if rec.deks == nil {
		rec.deks = make(map[*rule]*envelope.DEK, 1)
	}
	rec.deks[r] = d
	return d, nil
}

// finish attaches the wrapped keys to the record attributes.
func (rec *record) finish(attrs pcommon.Map) {
	for _, d := range rec.deks {
		attrs.PutStr(d.AttributeKey(), d.WrappedKey())
	}
}

func encodeValue(v pcommon.Value) ([]byte, error) {
	if v.Type() == pcommon.ValueTypeStr {
		return envelope.EncodeString(v.Str()), nil
	}
	raw, err := json.Marshal(v.AsRaw())
	if err != nil {
		return nil, err
	}
	return envelope.EncodeJSON(raw)
}

func (e *encryptor) seal(ctx context.Context, rec *record, r *rule, v pcommon.Value, c envelope.Context) error {
	if v.Type() == pcommon.ValueTypeEmpty {
		return nil
	}
	if v.Type() == pcommon.ValueTypeStr && envelope.IsToken(v.Str()) {
		// Already encrypted, for example by an upstream Alloy instance.
		return nil
	}
	pt, err := encodeValue(v)
	if err != nil {
		return err
	}
	d, err := rec.dek(r)
	if err != nil {
		return err
	}
	tok, err := d.Seal(pt, c)
	if err != nil {
		return err
	}
	v.SetStr(tok)
	e.valuesEncrypted.Add(ctx, 1, r.attrs)
	e.bytesEncrypted.Add(ctx, int64(len(pt)-1), r.attrs)
	return nil
}

func (e *encryptor) fail(ctx context.Context, r *rule, c envelope.Context, err error) error {
	e.failures.Add(ctx, 1, r.attrs)
	// Never log the value itself.
	e.logger.Warn("failed to encrypt value",
		zap.String("rule", r.name),
		zap.String("scope", c.Scope),
		zap.String("key", c.Key),
		zap.String("on_error", string(e.onError)),
		zap.Error(err))
	if e.onError == OnErrorReject {
		return fmt.Errorf("encrypting %s %q: %w", c.Scope, c.Key, err)
	}
	return nil
}

// processAttributes encrypts the matching attributes of attrs.
func (e *encryptor) processAttributes(ctx context.Context, rec *record, attrs pcommon.Map, base envelope.Context) error {
	var failed []string
	var rejectErr error
	attrs.Range(func(k string, v pcommon.Value) bool {
		if strings.HasPrefix(k, envelope.WrappedKeyAttrPrefix) {
			return true
		}
		r := e.match(k)
		if r == nil {
			return true
		}
		c := base
		c.Key = k
		if err := e.seal(ctx, rec, r, v, c); err != nil {
			if rejectErr = e.fail(ctx, r, c, err); rejectErr != nil {
				return false
			}
			failed = append(failed, k)
		}
		return true
	})
	if rejectErr != nil {
		return rejectErr
	}
	for _, k := range failed {
		attrs.Remove(k)
	}
	return nil
}

func idBytes[T interface{ IsEmpty() bool }](id T, raw []byte) []byte {
	if id.IsEmpty() {
		return nil
	}
	return raw
}

func (e *encryptor) processTraces(ctx context.Context, td ptrace.Traces) (ptrace.Traces, error) {
	rss := td.ResourceSpans()
	for i := 0; i < rss.Len(); i++ {
		sss := rss.At(i).ScopeSpans()
		for j := 0; j < sss.Len(); j++ {
			spans := sss.At(j).Spans()
			for k := 0; k < spans.Len(); k++ {
				if err := e.processSpan(ctx, spans.At(k)); err != nil {
					return td, err
				}
			}
		}
	}
	return td, nil
}

func (e *encryptor) processSpan(ctx context.Context, span ptrace.Span) error {
	traceID, spanID := span.TraceID(), span.SpanID()
	base := envelope.Context{
		Signal:  signalTraces,
		Scope:   scopeSpan,
		TraceID: idBytes(traceID, traceID[:]),
		SpanID:  idBytes(spanID, spanID[:]),
	}
	var rec record
	if err := e.processAttributes(ctx, &rec, span.Attributes(), base); err != nil {
		return err
	}
	base.Scope = scopeSpanEvent
	events := span.Events()
	for i := 0; i < events.Len(); i++ {
		if err := e.processAttributes(ctx, &rec, events.At(i).Attributes(), base); err != nil {
			return err
		}
	}
	rec.finish(span.Attributes())
	return nil
}

func (e *encryptor) processLogs(ctx context.Context, ld plog.Logs) (plog.Logs, error) {
	rls := ld.ResourceLogs()
	for i := 0; i < rls.Len(); i++ {
		sls := rls.At(i).ScopeLogs()
		for j := 0; j < sls.Len(); j++ {
			logs := sls.At(j).LogRecords()
			for k := 0; k < logs.Len(); k++ {
				if err := e.processLog(ctx, logs.At(k)); err != nil {
					return ld, err
				}
			}
		}
	}
	return ld, nil
}

func eventName(lr plog.LogRecord) string {
	if n := lr.EventName(); n != "" {
		return n
	}
	if v, ok := lr.Attributes().Get(eventNameAttr); ok && v.Type() == pcommon.ValueTypeStr {
		return v.Str()
	}
	return ""
}

func (e *encryptor) processLog(ctx context.Context, lr plog.LogRecord) error {
	traceID, spanID := lr.TraceID(), lr.SpanID()
	base := envelope.Context{
		Signal:  signalLogs,
		Scope:   scopeLog,
		TraceID: idBytes(traceID, traceID[:]),
		SpanID:  idBytes(spanID, spanID[:]),
	}
	var rec record
	if err := e.processAttributes(ctx, &rec, lr.Attributes(), base); err != nil {
		return err
	}

	if r := e.bodyRule(lr); r != nil {
		c := base
		c.Scope = scopeLogBody
		if err := e.seal(ctx, &rec, r, lr.Body(), c); err != nil {
			if err := e.fail(ctx, r, c, err); err != nil {
				return err
			}
			lr.Body().SetStr("")
		}
	}
	rec.finish(lr.Attributes())
	return nil
}

func (e *encryptor) bodyRule(lr plog.LogRecord) *rule {
	var name string
	var nameKnown bool
	for _, r := range e.rules {
		if !r.logBody {
			continue
		}
		if r.bodyEvents == nil {
			return r
		}
		if !nameKnown {
			name, nameKnown = eventName(lr), true
		}
		if r.bodyEvents[name] {
			return r
		}
	}
	return nil
}

var errNoRules = errors.New("no encryption rule configured")
