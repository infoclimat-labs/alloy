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
	upstream    *envelope.Verifier

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
	if e.upstream, err = cfg.upstreamVerifier(); err != nil {
		return nil, fmt.Errorf("upstream_verify_keys: %w", err)
	}
	if e.acceptInput && e.upstream.Len() == 0 {
		return nil, errors.New("accept_encrypted_input requires upstream_verify_keys")
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
	// ID, wrapped keys, metadata digest and signature are stored.
	attrs   pcommon.Map
	meta    func() envelope.RecordMeta
	rid     []byte
	traceID []byte
	spanID  []byte
	deks    map[*rule]*envelope.DEK
	// wrapped holds every wrapped key referenced by the record, including
	// those of a trusted upstream tier.
	wrapped map[string]string
	entries []envelope.Entry
	// trusted is true when the record carries a valid upstream signature,
	// in which case its encrypted values are kept.
	trusted bool
}

func (e *encryptor) newRecord(signal string, attrs pcommon.Map, traceID, spanID []byte, meta func() envelope.RecordMeta, in func() []envelope.Entry) *record {
	rec := &record{e: e, signal: signal, attrs: attrs, traceID: traceID, spanID: spanID, meta: meta}
	if e.acceptInput {
		rec.trusted = rec.verifyUpstream(in())
	}
	if !rec.trusted {
		// Never trust encryption metadata that isn't vouched for by a
		// pinned upstream signature.
		attrs.RemoveIf(func(k string, _ pcommon.Value) bool { return envelope.IsMetaKey(k) })
		rec.wrapped = nil
		rec.rid = nil
	}
	return rec
}

// verifyUpstream checks the signature of an incoming record before any
// modification, and loads its record ID and wrapped keys when it is valid.
func (rec *record) verifyUpstream(entries []envelope.Entry) bool {
	get := func(k string) string {
		if v, ok := rec.attrs.Get(k); ok && v.Type() == pcommon.ValueTypeStr {
			return v.Str()
		}
		return ""
	}
	sig := get(envelope.SignatureAttr)
	if sig == "" {
		return false
	}
	rid, err := hex.DecodeString(get(envelope.RecordIDAttr))
	if err != nil || len(rid) != recordIDSize {
		return false
	}
	metaDigest := envelope.MetaDigest(rec.meta())
	if hex.EncodeToString(metaDigest) != get(envelope.MetaAttr) {
		return false
	}
	wrapped := map[string]string{}
	rec.attrs.Range(func(k string, v pcommon.Value) bool {
		if id, ok := strings.CutPrefix(k, envelope.WrappedKeyAttrPrefix); ok && v.Type() == pcommon.ValueTypeStr {
			wrapped[id] = v.Str()
		}
		return true
	})
	used := map[string]string{}
	for _, en := range entries {
		id, _, err := envelope.ParseToken(en.Token)
		if err != nil {
			return false
		}
		w, ok := wrapped[id]
		if !ok {
			return false
		}
		used[id] = w
	}
	if _, err := rec.e.upstream.Verify(envelope.Manifest{
		Signal:      rec.signal,
		RecordID:    rid,
		TraceID:     rec.traceID,
		SpanID:      rec.spanID,
		Entries:     entries,
		WrappedKeys: used,
		Meta:        metaDigest,
	}, sig); err != nil {
		return false
	}
	rec.rid, rec.wrapped = rid, used
	return true
}

func (rec *record) ensureRID() error {
	if rec.rid == nil {
		rec.rid = make([]byte, recordIDSize)
		if _, err := rand.Read(rec.rid); err != nil {
			return err
		}
	}
	return nil
}

func (rec *record) context(scope, position, key string) (envelope.Context, error) {
	if err := rec.ensureRID(); err != nil {
		return envelope.Context{}, err
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

// accepted reports whether an incoming value is a token of a trusted
// upstream record, to keep as is.
func (rec *record) accepted(v pcommon.Value) bool {
	if !rec.trusted || v.Type() != pcommon.ValueTypeStr {
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

// processAttributes encrypts the matching attributes of attrs. Processor
// metadata keys are only legitimate on the record itself: they are removed
// from events and links.
func (rec *record) processAttributes(ctx context.Context, attrs pcommon.Map, scope, position string) error {
	if scope == scopeSpanEvent || scope == scopeSpanLink {
		attrs.RemoveIf(func(k string, _ pcommon.Value) bool { return envelope.IsMetaKey(k) })
	}
	var failed []string
	var rejectErr error
	attrs.Range(func(k string, v pcommon.Value) bool {
		if envelope.IsMetaKey(k) {
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

// finish attaches the record ID, wrapped keys, metadata digest and
// signature. With a signing key, every record is signed, including records
// without encrypted values, so that stripping encryption from a record is
// detectable.
func (rec *record) finish(ctx context.Context) error {
	if len(rec.entries) == 0 && rec.e.signer == nil {
		return nil
	}
	if err := rec.ensureRID(); err != nil {
		return err
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
	rec.attrs.RemoveIf(func(k string, _ pcommon.Value) bool {
		return strings.HasPrefix(k, envelope.WrappedKeyAttrPrefix) || k == envelope.SignatureAttr || k == envelope.MetaAttr
	})
	for id, w := range used {
		rec.attrs.PutStr(envelope.WrappedKeyAttrPrefix+id, w)
	}
	if rec.e.signer == nil {
		return nil
	}
	metaDigest := envelope.MetaDigest(rec.meta())
	rec.attrs.PutStr(envelope.MetaAttr, hex.EncodeToString(metaDigest))
	sig, err := rec.e.signer.Sign(envelope.Manifest{
		Signal:      rec.signal,
		RecordID:    rec.rid,
		TraceID:     rec.traceID,
		SpanID:      rec.spanID,
		Entries:     rec.entries,
		WrappedKeys: used,
		Meta:        metaDigest,
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

// metaKeys appends the attribute keys of a map to keys, as expected by
// envelope.RecordMeta.
func metaKeys(keys []string, attrs pcommon.Map, scope, position string) []string {
	attrs.Range(func(k string, _ pcommon.Value) bool {
		if !envelope.IsMetaKey(k) {
			keys = append(keys, envelope.MetaKey(scope, position, k))
		}
		return true
	})
	return keys
}

// tokenEntries appends the tokens of a map to entries.
func tokenEntries(entries []envelope.Entry, attrs pcommon.Map, scope, position string) []envelope.Entry {
	attrs.Range(func(k string, v pcommon.Value) bool {
		if !envelope.IsMetaKey(k) && v.Type() == pcommon.ValueTypeStr && envelope.IsToken(v.Str()) {
			entries = append(entries, envelope.Entry{Scope: scope, Position: position, Key: k, Token: v.Str()})
		}
		return true
	})
	return entries
}

func spanMeta(span ptrace.Span) envelope.RecordMeta {
	m := envelope.RecordMeta{
		Name:  span.Name(),
		Start: uint64(span.StartTimestamp()),
		End:   uint64(span.EndTimestamp()),
	}
	m.Keys = metaKeys(m.Keys, span.Attributes(), scopeSpan, "")
	events := span.Events()
	for i := 0; i < events.Len(); i++ {
		ev := events.At(i)
		pos := position(i, ev.Name())
		m.Events = append(m.Events, pos+"@"+strconv.FormatUint(uint64(ev.Timestamp()), 10))
		m.Keys = metaKeys(m.Keys, ev.Attributes(), scopeSpanEvent, pos)
	}
	links := span.Links()
	for i := 0; i < links.Len(); i++ {
		link := links.At(i)
		m.Keys = metaKeys(m.Keys, link.Attributes(), scopeSpanLink, position(i, link.SpanID().String()))
	}
	return m
}

func spanTokens(span ptrace.Span) []envelope.Entry {
	entries := tokenEntries(nil, span.Attributes(), scopeSpan, "")
	events := span.Events()
	for i := 0; i < events.Len(); i++ {
		ev := events.At(i)
		entries = tokenEntries(entries, ev.Attributes(), scopeSpanEvent, position(i, ev.Name()))
	}
	links := span.Links()
	for i := 0; i < links.Len(); i++ {
		link := links.At(i)
		entries = tokenEntries(entries, link.Attributes(), scopeSpanLink, position(i, link.SpanID().String()))
	}
	return entries
}

func (e *encryptor) processSpan(ctx context.Context, span ptrace.Span) error {
	traceID, spanID := span.TraceID(), span.SpanID()
	rec := e.newRecord(signalTraces, span.Attributes(), idBytes(traceID, traceID[:]), idBytes(spanID, spanID[:]),
		func() envelope.RecordMeta { return spanMeta(span) },
		func() []envelope.Entry { return spanTokens(span) })
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

func logMeta(lr plog.LogRecord) envelope.RecordMeta {
	return envelope.RecordMeta{
		Name:  lr.EventName(),
		Start: uint64(lr.Timestamp()),
		Keys:  metaKeys(nil, lr.Attributes(), scopeLog, ""),
	}
}

func logTokens(lr plog.LogRecord) []envelope.Entry {
	entries := tokenEntries(nil, lr.Attributes(), scopeLog, "")
	if lr.Body().Type() == pcommon.ValueTypeStr && envelope.IsToken(lr.Body().Str()) {
		var pos string
		if v, ok := lr.Attributes().Get(envelope.EventAttr); ok {
			pos = v.AsString()
		}
		entries = append(entries, envelope.Entry{Scope: scopeLogBody, Position: pos, Token: lr.Body().Str()})
	}
	return entries
}

func (e *encryptor) processLog(ctx context.Context, lr plog.LogRecord) error {
	traceID, spanID := lr.TraceID(), lr.SpanID()
	rec := e.newRecord(signalLogs, lr.Attributes(), idBytes(traceID, traceID[:]), idBytes(spanID, spanID[:]),
		func() envelope.RecordMeta { return logMeta(lr) },
		func() []envelope.Entry { return logTokens(lr) })

	// Select the body rule before attributes are encrypted: a rule may
	// encrypt event.name, which must not turn body encryption off.
	bodyRule, name := e.bodyRule(lr)
	// An accepted upstream body keeps the event name it was bound to.
	bodyPos := name
	if rec.trusted {
		if v, ok := lr.Attributes().Get(envelope.EventAttr); ok {
			bodyPos = v.AsString()
		}
	}

	if err := rec.processAttributes(ctx, lr.Attributes(), scopeLog, ""); err != nil {
		return err
	}
	if bodyRule != nil {
		// The event name tells who said what (user, assistant, tool): it is
		// bound to the body ciphertext and carried in clear text next to it.
		if err := rec.seal(ctx, bodyRule, lr.Body(), scopeLogBody, bodyPos, ""); err != nil {
			if err := e.fail(ctx, bodyRule, scopeLogBody, "", err); err != nil {
				return err
			}
			lr.Body().SetStr("")
		} else if bodyPos != "" && envelope.IsToken(lr.Body().Str()) {
			lr.Attributes().PutStr(envelope.EventAttr, bodyPos)
		}
	}
	return rec.finish(ctx)
}

// bodyRule returns the rule encrypting the body of lr, if any, and the
// trusted event name of the record.
func (e *encryptor) bodyRule(lr plog.LogRecord) (*rule, string) {
	name, trusted := eventName(lr)
	if !trusted {
		name = ""
	}
	var first *rule
	for _, r := range e.rules {
		if !r.logBody {
			continue
		}
		if first == nil {
			first = r
		}
		if r.bodyEvents == nil || (trusted && r.bodyEvents[name]) {
			return r, name
		}
	}
	if !trusted {
		// The event name is unreadable: fail closed and encrypt the body
		// with the first rule that encrypts bodies.
		return first, name
	}
	return nil, name
}

var errNoRules = errors.New("no encryption rule configured")
