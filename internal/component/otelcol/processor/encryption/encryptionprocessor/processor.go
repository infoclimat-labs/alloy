package encryptionprocessor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

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
	scopeSpanLink  = "span_link"
	scopeLog       = "log"
	scopeLogBody   = "log_body"

	signalTraces = "traces"
	signalLogs   = "logs"

	eventNameAttr = "event.name"
	recordIDSize  = 16
	maxMatchCache = 4096
)

type rule struct {
	name       string
	sealer     *envelope.Sealer
	exact      map[string]bool
	patterns   []*regexp.Regexp
	logBody    bool
	bodyEvents map[string]bool

	attrs metric.MeasurementOption
}

func (r *rule) matches(key string) bool {
	if r.exact[key] {
		return true
	}
	for _, re := range r.patterns {
		if re.MatchString(key) {
			return true
		}
	}
	return false
}

type encryptor struct {
	logger      *zap.Logger
	onError     OnError
	acceptInput bool
	signer      *envelope.SigningKey

	rules []*rule

	// cache memoizes the rule matching an attribute key (nil for none).
	cacheMu sync.RWMutex
	cache   map[string]*rule

	valuesEncrypted metric.Int64Counter
	bytesEncrypted  metric.Int64Counter
	failures        metric.Int64Counter
	recordsSigned   metric.Int64Counter
}

func newEncryptor(cfg *Config, logger *zap.Logger, meter metric.Meter) (*encryptor, error) {
	e := &encryptor{
		logger:      logger,
		onError:     cfg.OnError,
		acceptInput: cfg.AcceptEncryptedInput,
		cache:       map[string]*rule{},
	}
	if e.onError == "" {
		e.onError = OnErrorDelete
	}
	var err error
	if e.signer, err = cfg.signingKey(); err != nil {
		return nil, fmt.Errorf("signing_key: %w", err)
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
			exact:   map[string]bool{},
			logBody: rc.LogBody,
			attrs:   metric.WithAttributeSet(attribute.NewSet(attribute.String("rule", name))),
		}
		if len(rc.LogBodyEventNames) > 0 {
			r.bodyEvents = make(map[string]bool, len(rc.LogBodyEventNames))
			for _, n := range rc.LogBodyEventNames {
				r.bodyEvents[n] = true
			}
		}
		attrs, patterns := append([]string(nil), rc.Attributes...), append([]string(nil), rc.AttributePatterns...)
		for _, p := range rc.Presets {
			attrs = append(attrs, presets[p].attributes...)
			patterns = append(patterns, presets[p].patterns...)
		}
		for _, a := range attrs {
			r.exact[a] = true
		}
		for _, p := range patterns {
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("rule %q: %w", name, err)
			}
			r.patterns = append(r.patterns, re)
		}
		e.rules = append(e.rules, r)
		logger.Info("encryption rule configured",
			zap.String("rule", name),
			zap.Strings("recipients", sealer.Recipients()),
			zap.Int("attributes", len(attrs)),
			zap.Int("attribute_patterns", len(patterns)),
			zap.Bool("log_body", rc.LogBody))
	}
	if e.signer != nil {
		logger.Info("records are signed", zap.String("key_id", e.signer.KeyID()), zap.String("algorithm", e.signer.Public().Algorithm()))
	}

	for _, c := range []struct {
		dst        *metric.Int64Counter
		name, desc string
		unit       string
	}{
		{&e.valuesEncrypted, "otelcol_processor_encryption_values_encrypted", "Number of attribute values and log bodies encrypted.", "{value}"},
		{&e.bytesEncrypted, "otelcol_processor_encryption_plaintext_bytes", "Number of plaintext bytes encrypted.", "By"},
		{&e.failures, "otelcol_processor_encryption_failures", "Number of values that could not be encrypted.", "{value}"},
		{&e.recordsSigned, "otelcol_processor_encryption_records_signed", "Number of records signed.", "{record}"},
	} {
		if *c.dst, err = meter.Int64Counter(c.name, metric.WithDescription(c.desc), metric.WithUnit(c.unit)); err != nil {
			return nil, err
		}
	}
	return e, nil
}

// match returns the rule encrypting the attribute key, if any. Rules are
// evaluated in configuration order: the first rule that selects the key, by
// exact name, preset or pattern, wins.
func (e *encryptor) match(key string) *rule {
	e.cacheMu.RLock()
	r, ok := e.cache[key]
	e.cacheMu.RUnlock()
	if ok {
		return r
	}
	for _, candidate := range e.rules {
		if candidate.matches(key) {
			r = candidate
			break
		}
	}
	e.cacheMu.Lock()
	if len(e.cache) < maxMatchCache {
		e.cache[key] = r
	}
	e.cacheMu.Unlock()
	return r
}

// record holds the state of one span or log record being encrypted.
type record struct {
	e      *encryptor
	signal string
	// attrs are the attributes of the span or log record, where the record
	// ID, wrapped keys and signature are stored.
	attrs   pcommon.Map
	rid     []byte
	traceID []byte
	spanID  []byte
	deks    map[*rule]*envelope.DEK
	// wrapped holds every wrapped key referenced by the record, including
	// accepted upstream ones.
	wrapped map[string]string
	entries []envelope.Entry
}

func (e *encryptor) newRecord(signal string, attrs pcommon.Map, traceID, spanID []byte) *record {
	rec := &record{e: e, signal: signal, attrs: attrs, traceID: traceID, spanID: spanID}
	if !e.acceptInput {
		// Never trust encryption metadata coming from clients.
		attrs.RemoveIf(func(k string, _ pcommon.Value) bool { return strings.HasPrefix(k, envelope.AttrPrefix) })
		return rec
	}
	if v, ok := attrs.Get(envelope.RecordIDAttr); ok && v.Type() == pcommon.ValueTypeStr {
		if rid, err := hex.DecodeString(v.Str()); err == nil && len(rid) == recordIDSize {
			rec.rid = rid
		}
	}
	attrs.Range(func(k string, v pcommon.Value) bool {
		if id, ok := strings.CutPrefix(k, envelope.WrappedKeyAttrPrefix); ok && v.Type() == pcommon.ValueTypeStr {
			if rec.wrapped == nil {
				rec.wrapped = map[string]string{}
			}
			rec.wrapped[id] = v.Str()
		}
		return true
	})
	attrs.Remove(envelope.SignatureAttr)
	return rec
}

func (rec *record) context(scope, position, key string) (envelope.Context, error) {
	if rec.rid == nil {
		rec.rid = make([]byte, recordIDSize)
		if _, err := rand.Read(rec.rid); err != nil {
			return envelope.Context{}, err
		}
	}
	return envelope.Context{
		Signal:   rec.signal,
		Scope:    scope,
		Position: position,
		Key:      key,
		RecordID: rec.rid,
		TraceID:  rec.traceID,
		SpanID:   rec.spanID,
	}, nil
}

func (rec *record) dek(r *rule) (*envelope.DEK, error) {
	if d, ok := rec.deks[r]; ok && d.Uses() < r.sealer.MaxUses() {
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
	if rec.wrapped == nil {
		rec.wrapped = map[string]string{}
	}
	rec.wrapped[d.ID()] = d.WrappedKey()
	return d, nil
}

// accepted reports whether an incoming value is a token to keep as is.
func (rec *record) accepted(v pcommon.Value) bool {
	if !rec.e.acceptInput || v.Type() != pcommon.ValueTypeStr {
		return false
	}
	id, _, err := envelope.ParseToken(v.Str())
	if err != nil {
		return false
	}
	_, ok := rec.wrapped[id]
	return ok
}

func encodeValue(key string, v pcommon.Value) ([]byte, error) {
	switch v.Type() {
	case pcommon.ValueTypeStr:
		return envelope.EncodeValue(envelope.KindString, key, []byte(v.Str()))
	case pcommon.ValueTypeBytes:
		return envelope.EncodeValue(envelope.KindBytes, key, v.Bytes().AsRaw())
	default:
		raw, err := json.Marshal(v.AsRaw())
		if err != nil {
			return nil, err
		}
		return envelope.EncodeValue(envelope.KindJSON, key, raw)
	}
}

// seal encrypts v in place.
func (rec *record) seal(ctx context.Context, r *rule, v pcommon.Value, scope, position, key string) error {
	if v.Type() == pcommon.ValueTypeEmpty {
		return nil
	}
	if rec.accepted(v) {
		rec.entries = append(rec.entries, envelope.Entry{Scope: scope, Position: position, Key: key, Token: v.Str()})
		return nil
	}
	pt, err := encodeValue(key, v)
	if err != nil {
		return err
	}
	c, err := rec.context(scope, position, key)
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
	rec.entries = append(rec.entries, envelope.Entry{Scope: scope, Position: position, Key: key, Token: tok})
	rec.e.valuesEncrypted.Add(ctx, 1, r.attrs)
	rec.e.bytesEncrypted.Add(ctx, int64(len(pt)), r.attrs)
	return nil
}

func (e *encryptor) fail(ctx context.Context, r *rule, scope, key string, err error) error {
	e.failures.Add(ctx, 1, r.attrs)
	// Never log the value itself.
	e.logger.Warn("failed to encrypt value",
		zap.String("rule", r.name),
		zap.String("scope", scope),
		zap.String("key", key),
		zap.String("on_error", string(e.onError)),
		zap.Error(err))
	if e.onError == OnErrorReject {
		return fmt.Errorf("encrypting %s %q: %w", scope, key, err)
	}
	return nil
}

// processAttributes encrypts the matching attributes of attrs.
func (rec *record) processAttributes(ctx context.Context, attrs pcommon.Map, scope, position string) error {
	var failed []string
	var rejectErr error
	attrs.Range(func(k string, v pcommon.Value) bool {
		if strings.HasPrefix(k, envelope.AttrPrefix) {
			return true
		}
		r := rec.e.match(k)
		if r == nil {
			return true
		}
		if err := rec.seal(ctx, r, v, scope, position, k); err != nil {
			if rejectErr = rec.e.fail(ctx, r, scope, k, err); rejectErr != nil {
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

// finish attaches the record ID, wrapped keys and signature.
func (rec *record) finish(ctx context.Context) error {
	if len(rec.entries) == 0 {
		return nil
	}
	rec.attrs.PutStr(envelope.RecordIDAttr, hex.EncodeToString(rec.rid))
	used := map[string]string{}
	for _, entry := range rec.entries {
		id, _, err := envelope.ParseToken(entry.Token)
		if err != nil {
			continue
		}
		if w, ok := rec.wrapped[id]; ok {
			used[id] = w
		}
	}
	for id, w := range used {
		rec.attrs.PutStr(envelope.WrappedKeyAttrPrefix+id, w)
	}
	if rec.e.signer == nil {
		return nil
	}
	sig, err := rec.e.signer.Sign(envelope.Manifest{
		Signal:      rec.signal,
		RecordID:    rec.rid,
		TraceID:     rec.traceID,
		SpanID:      rec.spanID,
		Entries:     rec.entries,
		WrappedKeys: used,
	})
	if err != nil {
		return fmt.Errorf("signing record: %w", err)
	}
	rec.attrs.PutStr(envelope.SignatureAttr, sig)
	rec.e.recordsSigned.Add(ctx, 1)
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

// position identifies an event or link inside its span.
func position(i int, name string) string {
	return strconv.Itoa(i) + "/" + name
}

func (e *encryptor) processSpan(ctx context.Context, span ptrace.Span) error {
	traceID, spanID := span.TraceID(), span.SpanID()
	rec := e.newRecord(signalTraces, span.Attributes(), idBytes(traceID, traceID[:]), idBytes(spanID, spanID[:]))
	if err := rec.processAttributes(ctx, span.Attributes(), scopeSpan, ""); err != nil {
		return err
	}
	events := span.Events()
	for i := 0; i < events.Len(); i++ {
		ev := events.At(i)
		if err := rec.processAttributes(ctx, ev.Attributes(), scopeSpanEvent, position(i, ev.Name())); err != nil {
			return err
		}
	}
	links := span.Links()
	for i := 0; i < links.Len(); i++ {
		link := links.At(i)
		if err := rec.processAttributes(ctx, link.Attributes(), scopeSpanLink, position(i, link.SpanID().String())); err != nil {
			return err
		}
	}
	return rec.finish(ctx)
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

// eventName returns the event name of a log record, and whether it can be
// trusted. A name that is itself encrypted can't be matched.
func eventName(lr plog.LogRecord) (string, bool) {
	if n := lr.EventName(); n != "" {
		return n, !envelope.IsToken(n)
	}
	if v, ok := lr.Attributes().Get(eventNameAttr); ok {
		if v.Type() != pcommon.ValueTypeStr || envelope.IsToken(v.Str()) {
			return "", false
		}
		return v.Str(), true
	}
	return "", true
}

func (e *encryptor) processLog(ctx context.Context, lr plog.LogRecord) error {
	// Select the body rule before attributes are encrypted: a rule may
	// encrypt event.name, which must not turn body encryption off.
	bodyRule := e.bodyRule(lr)

	traceID, spanID := lr.TraceID(), lr.SpanID()
	rec := e.newRecord(signalLogs, lr.Attributes(), idBytes(traceID, traceID[:]), idBytes(spanID, spanID[:]))
	if err := rec.processAttributes(ctx, lr.Attributes(), scopeLog, ""); err != nil {
		return err
	}
	if bodyRule != nil {
		if err := rec.seal(ctx, bodyRule, lr.Body(), scopeLogBody, "", ""); err != nil {
			if err := e.fail(ctx, bodyRule, scopeLogBody, "", err); err != nil {
				return err
			}
			lr.Body().SetStr("")
		}
	}
	return rec.finish(ctx)
}

func (e *encryptor) bodyRule(lr plog.LogRecord) *rule {
	name, trusted := eventName(lr)
	var first *rule
	for _, r := range e.rules {
		if !r.logBody {
			continue
		}
		if first == nil {
			first = r
		}
		if r.bodyEvents == nil || r.bodyEvents[name] {
			return r
		}
	}
	if !trusted {
		// The event name is unreadable: fail closed and encrypt the body
		// with the first rule that encrypts bodies.
		return first
	}
	return nil
}

var errNoRules = errors.New("no encryption rule configured")
