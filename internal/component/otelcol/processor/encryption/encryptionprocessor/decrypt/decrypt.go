// Package decrypt restores values encrypted by the encryption processor in
// exported telemetry documents. It supports OTLP JSON (traces and logs,
// including the Tempo API flavour) and Loki query responses, and verifies
// record signatures against pinned verification keys.
//
// The package only depends on the Go standard library and on the envelope
// package, so it can run on an isolated workstation that holds the private
// keys.
package decrypt

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/grafana/alloy/internal/component/otelcol/processor/encryption/encryptionprocessor/envelope"
)

// Options control decryption.
type Options struct {
	// KeepKeyAttributes keeps the encryption.* attributes in the output.
	KeepKeyAttributes bool
	// Verifier checks record signatures. Records are not verified when nil.
	Verifier *envelope.Verifier
	// RequireSignature refuses to decrypt records without a valid signature
	// from a pinned key. It requires a Verifier.
	RequireSignature bool
}

// Report summarizes a decryption run.
type Report struct {
	Format    string `json:"format"`
	Records   int    `json:"records"`
	Decrypted int    `json:"decrypted"`
	Failed    int    `json:"failed"`
	// Signature verification, when a verifier is configured.
	Verified int `json:"signatures_verified"`
	Unsigned int `json:"unsigned_records"`
	Invalid  int `json:"invalid_signatures"`
	// MetaUnchecked counts verified records whose clear-text metadata
	// couldn't be recomputed (Loki rewrites attribute names): only their
	// encrypted values are verified.
	MetaUnchecked int `json:"metadata_unchecked"`
	// TraceIDs lists the traces whose content was decrypted (at most 1000).
	TraceIDs []string `json:"trace_ids,omitempty"`
	Errors   []string `json:"errors,omitempty"`
}

func (r *Report) fail(where string, err error) {
	r.Failed++
	if len(r.Errors) < 100 {
		r.Errors = append(r.Errors, fmt.Sprintf("%s: %v", where, err))
	}
}

// Decryptor decrypts documents with a keyring. It caches unwrapped data
// encryption keys and is not safe for concurrent use.
type Decryptor struct {
	kr        *envelope.Keyring
	opts      Options
	deks      map[string]*envelope.DEK
	failed    map[string]error
	traceSeen map[string]bool
}

// New creates a decryptor.
func New(kr *envelope.Keyring, opts Options) *Decryptor {
	return &Decryptor{kr: kr, opts: opts, deks: map[string]*envelope.DEK{}, failed: map[string]error{}, traceSeen: map[string]bool{}}
}

// Document formats.
const (
	FormatOTLPTraces = "otlp-traces"
	FormatOTLPLogs   = "otlp-logs"
	FormatLoki       = "loki"
)

// Decrypt detects the format of doc, decrypts every token it can and
// returns the rewritten document.
func (d *Decryptor) Decrypt(doc []byte) ([]byte, Report, error) {
	if d.opts.RequireSignature && d.opts.Verifier.Len() == 0 {
		return nil, Report{}, errors.New("requiring signatures needs at least one verification key")
	}
	var root map[string]any
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return nil, Report{}, fmt.Errorf("parsing JSON: %w", err)
	}

	var rep Report
	switch {
	case root["resourceSpans"] != nil || root["batches"] != nil:
		rep.Format = FormatOTLPTraces
		d.traces(root, &rep)
	case root["trace"] != nil:
		rep.Format = FormatOTLPTraces
		if t, ok := root["trace"].(map[string]any); ok {
			d.traces(t, &rep)
		}
	case root["resourceLogs"] != nil:
		rep.Format = FormatOTLPLogs
		d.logs(root, &rep)
	case isLoki(root):
		rep.Format = FormatLoki
		d.loki(root, &rep)
	default:
		return nil, rep, errors.New("unrecognized document: expected OTLP JSON traces or logs, or a Loki query response")
	}
	rep.TraceIDs = slices.Sorted(maps.Keys(d.traceSeen))
	if len(rep.TraceIDs) > 1000 {
		rep.TraceIDs = rep.TraceIDs[:1000]
	}

	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(root); err != nil {
		return nil, rep, err
	}
	return out.Bytes(), rep, nil
}

func list(m map[string]any, keys ...string) []any {
	for _, k := range keys {
		if l, ok := m[k].([]any); ok {
			return l
		}
	}
	return nil
}

func objects(l []any) []map[string]any {
	out := make([]map[string]any, 0, len(l))
	for _, v := range l {
		if m, ok := v.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// decodeID accepts the hex encoding mandated by OTLP JSON and the base64
// encoding produced by some backends (for example the Tempo API).
func decodeID(v any, size int) []byte {
	s, _ := v.(string)
	if s == "" {
		return nil
	}
	if len(s) == 2*size {
		if b, err := hex.DecodeString(s); err == nil {
			return nonZero(b)
		}
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == size {
		return nonZero(b)
	}
	return nil
}

func nonZero(b []byte) []byte {
	for _, c := range b {
		if c != 0 {
			return b
		}
	}
	return nil
}

// recordState carries what is shared by the values of one record.
type recordState struct {
	where   string
	ctx     envelope.Context
	wrapped map[string]string
	sig     string
	entries []envelope.Entry
	// meta is the digest of the clear-text metadata of the record,
	// recomputed from the document, unless metaFromAttr is set (the backend
	// rewrote the record) and the signed MetaAttr value is used instead.
	meta         []byte
	metaFromAttr bool
	metaAttr     string
	// event is the event name bound to an encrypted log body.
	event string
	// exactKeys is false when the backend sanitized attribute names.
	exactKeys bool
	// allowed is false when the record must not be decrypted (signature
	// required but missing or invalid).
	allowed bool
}

// kv is an OTLP JSON attribute.
type kv struct {
	m     map[string]any
	key   string
	value map[string]any
}

func attributes(m map[string]any) []kv {
	var out []kv
	for _, a := range objects(list(m, "attributes")) {
		key, _ := a["key"].(string)
		value, _ := a["value"].(map[string]any)
		out = append(out, kv{m: a, key: key, value: value})
	}
	return out
}

func strValue(a kv) (string, bool) {
	s, ok := a.value["stringValue"].(string)
	return s, ok
}

// readMeta extracts the record ID, wrapped keys and signature attributes.
func (st *recordState) readMeta(attrs []kv) {
	st.wrapped = map[string]string{}
	for _, a := range attrs {
		s, ok := strValue(a)
		if !ok {
			continue
		}
		switch a.key {
		case envelope.RecordIDAttr:
			st.ctx.RecordID, _ = hex.DecodeString(s)
		case envelope.SignatureAttr:
			st.sig = s
		case envelope.MetaAttr:
			st.metaAttr = s
		case envelope.EventAttr:
			st.event = s
		default:
			if id, ok := strings.CutPrefix(a.key, envelope.WrappedKeyAttrPrefix); ok {
				st.wrapped[id] = s
			}
		}
	}
}

// collect records a token of the record for signature verification.
func (st *recordState) collect(scope, position, key, token string) {
	st.entries = append(st.entries, envelope.Entry{Scope: scope, Position: position, Key: key, Token: token})
}

// verify checks the record signature once every token is collected. With
// a verifier, every record is checked, including records without encrypted
// values: the processor signs them all, so a record stripped of its
// encryption (values replaced by clear text) is reported.
func (d *Decryptor) verify(st *recordState, rep *Report) {
	st.allowed = true
	if len(st.entries) > 0 {
		rep.Records++
	}
	if d.opts.Verifier.Len() == 0 {
		return
	}
	reject := func(err error, counter *int) {
		*counter++
		if d.opts.RequireSignature {
			st.allowed = false
			rep.fail(st.where, err)
		} else if len(rep.Errors) < 100 && len(st.entries) > 0 {
			rep.Errors = append(rep.Errors, fmt.Sprintf("%s: %v (decrypted anyway)", st.where, err))
		}
	}
	if st.sig == "" {
		reject(errors.New("record is not signed"), &rep.Unsigned)
		return
	}
	used := map[string]string{}
	for _, e := range st.entries {
		if id, _, err := envelope.ParseToken(e.Token); err == nil {
			if w, ok := st.wrapped[id]; ok {
				used[id] = w
			}
		}
	}
	meta := st.meta
	if st.metaFromAttr {
		meta, _ = hex.DecodeString(st.metaAttr)
	} else if hex.EncodeToString(meta) != st.metaAttr {
		reject(errors.New("clear-text metadata of the record was altered (attributes added, removed or renamed, or timestamps changed)"), &rep.Invalid)
		return
	}
	_, err := d.opts.Verifier.Verify(envelope.Manifest{
		Signal:      st.ctx.Signal,
		RecordID:    st.ctx.RecordID,
		TraceID:     st.ctx.TraceID,
		SpanID:      st.ctx.SpanID,
		Entries:     st.entries,
		WrappedKeys: used,
		Meta:        meta,
	}, st.sig)
	if err != nil {
		reject(err, &rep.Invalid)
		return
	}
	rep.Verified++
	if st.metaFromAttr {
		rep.MetaUnchecked++
	}
}

func (d *Decryptor) dek(id string, st *recordState) (*envelope.DEK, error) {
	wrapped, ok := st.wrapped[id]
	if !ok {
		return nil, fmt.Errorf("wrapped key %s%s not found on the record", envelope.WrappedKeyAttrPrefix, id)
	}
	if dek, ok := d.deks[wrapped]; ok {
		return dek, nil
	}
	if err, ok := d.failed[wrapped]; ok {
		return nil, err
	}
	dek, err := d.kr.Unwrap(id, wrapped)
	if err != nil {
		if len(d.failed) < 10000 {
			d.failed[wrapped] = err
		}
		return nil, truncationHint(err, wrapped)
	}
	d.deks[wrapped] = dek
	return dek, nil
}

// truncationHint explains authentication failures caused by backends that
// truncate long attribute values (Tempo truncates them to 2048 bytes by
// default).
func truncationHint(err error, value string) error {
	if errors.Is(err, envelope.ErrAuthentication) || errors.Is(err, envelope.ErrDEKMismatch) {
		if n := len(value); n == 2048 || n == 1024 || n == 4096 || n == 16384 || n == 65536 {
			return fmt.Errorf("%w (the value is exactly %d bytes long: the backend probably truncated it)", err, n)
		}
	}
	return err
}

// open decrypts one token and checks the embedded attribute key.
func (d *Decryptor) open(token, scope, position, key string, st *recordState) (envelope.Value, error) {
	id, _, err := envelope.ParseToken(token)
	if err != nil {
		return envelope.Value{}, err
	}
	dek, err := d.dek(id, st)
	if err != nil {
		return envelope.Value{}, err
	}
	c := st.ctx
	c.Scope, c.Position, c.Key = scope, position, key
	pt, err := dek.Open(token, c)
	if err != nil {
		return envelope.Value{}, truncationHint(err, token)
	}
	v, err := envelope.DecodeValue(pt)
	if err != nil {
		return envelope.Value{}, err
	}
	if err := v.CheckKey(key, st.exactKeys); err != nil {
		return envelope.Value{}, err
	}
	if st.ctx.TraceID != nil {
		d.traceSeen[hex.EncodeToString(st.ctx.TraceID)] = true
	}
	return v, nil
}

type location struct {
	m        map[string]any
	scope    string
	position string
	where    string
}

func tokensOf(m map[string]any) []kv {
	var out []kv
	for _, a := range attributes(m) {
		if s, ok := strValue(a); ok && envelope.IsToken(s) && !envelope.IsMetaKey(a.key) {
			out = append(out, a)
		}
	}
	return out
}

func (d *Decryptor) decryptLocations(st *recordState, locs []location, rep *Report) {
	for _, l := range locs {
		for _, a := range tokensOf(l.m) {
			s, _ := strValue(a)
			st.collect(l.scope, l.position, a.key, s)
		}
	}
	d.verify(st, rep)
	if !st.allowed {
		return
	}
	for _, l := range locs {
		for _, a := range tokensOf(l.m) {
			s, _ := strValue(a)
			v, err := d.open(s, l.scope, l.position, a.key, st)
			if err != nil {
				rep.fail(l.where+" "+a.key, err)
				continue
			}
			av, err := toAnyValue(v)
			if err != nil {
				rep.fail(l.where+" "+a.key, err)
				continue
			}
			a.m["value"] = av
			rep.Decrypted++
		}
	}
}

func (d *Decryptor) stripKeys(m map[string]any) {
	if d.opts.KeepKeyAttributes {
		return
	}
	in := list(m, "attributes")
	if in == nil {
		return
	}
	out := in[:0]
	for _, a := range in {
		if am, ok := a.(map[string]any); ok {
			if k, _ := am["key"].(string); envelope.IsMetaKey(k) {
				continue
			}
		}
		out = append(out, a)
	}
	m["attributes"] = out
}

func position(i int, name string) string { return strconv.Itoa(i) + "/" + name }

func (d *Decryptor) traces(root map[string]any, rep *Report) {
	for _, rs := range objects(list(root, "resourceSpans", "batches")) {
		for _, ss := range objects(list(rs, "scopeSpans", "instrumentationLibrarySpans")) {
			for _, span := range objects(list(ss, "spans")) {
				st := &recordState{exactKeys: true, ctx: envelope.Context{
					Signal:  "traces",
					TraceID: decodeID(span["traceId"], 16),
					SpanID:  decodeID(span["spanId"], 8),
				}}
				st.where = fmt.Sprintf("span %x/%x", st.ctx.TraceID, st.ctx.SpanID)
				st.readMeta(attributes(span))
				name, _ := span["name"].(string)
				meta := envelope.RecordMeta{Name: name, Start: timestamp(span["startTimeUnixNano"]), End: timestamp(span["endTimeUnixNano"])}
				meta.Keys = metaKeys(meta.Keys, span, "span", "")
				locs := []location{{m: span, scope: "span", where: st.where}}
				for i, ev := range objects(list(span, "events")) {
					evName, _ := ev["name"].(string)
					pos := position(i, evName)
					meta.Events = append(meta.Events, pos+"@"+strconv.FormatUint(timestamp(ev["timeUnixNano"]), 10))
					meta.Keys = metaKeys(meta.Keys, ev, "span_event", pos)
					locs = append(locs, location{m: ev, scope: "span_event", position: pos, where: st.where + " event " + strconv.Itoa(i)})
				}
				for i, link := range objects(list(span, "links")) {
					pos := position(i, linkSpanID(link["spanId"]))
					meta.Keys = metaKeys(meta.Keys, link, "span_link", pos)
					locs = append(locs, location{m: link, scope: "span_link", position: pos, where: st.where + " link " + strconv.Itoa(i)})
				}
				st.meta = envelope.MetaDigest(meta)
				d.decryptLocations(st, locs, rep)
				d.stripKeys(span)
			}
		}
	}
}

// timestamp parses an OTLP JSON timestamp, encoded as a string or a number.
func timestamp(v any) uint64 {
	var s string
	switch t := v.(type) {
	case string:
		s = t
	case json.Number:
		s = t.String()
	default:
		return 0
	}
	n, _ := strconv.ParseUint(s, 10, 64)
	return n
}

// metaKeys appends the attribute keys of an OTLP JSON object, as the
// processor does when it computes the metadata digest.
func metaKeys(keys []string, m map[string]any, scope, position string) []string {
	for _, a := range attributes(m) {
		if !envelope.IsMetaKey(a.key) {
			keys = append(keys, envelope.MetaKey(scope, position, a.key))
		}
	}
	return keys
}

// linkSpanID renders a link span ID like pcommon.SpanID.String (hex).
func linkSpanID(v any) string {
	if b := decodeID(v, 8); b != nil {
		return hex.EncodeToString(b)
	}
	return ""
}

func (d *Decryptor) logs(root map[string]any, rep *Report) {
	for _, rl := range objects(list(root, "resourceLogs")) {
		for _, sl := range objects(list(rl, "scopeLogs", "instrumentationLibraryLogs")) {
			for _, lr := range objects(list(sl, "logRecords")) {
				st := &recordState{exactKeys: true, ctx: envelope.Context{
					Signal:  "logs",
					TraceID: decodeID(lr["traceId"], 16),
					SpanID:  decodeID(lr["spanId"], 8),
				}}
				st.where = fmt.Sprintf("log %x/%x", st.ctx.TraceID, st.ctx.SpanID)
				st.readMeta(attributes(lr))
				eventName, _ := lr["eventName"].(string)
				st.meta = envelope.MetaDigest(envelope.RecordMeta{
					Name:  eventName,
					Start: timestamp(lr["timeUnixNano"]),
					Keys:  metaKeys(nil, lr, "log", ""),
				})

				body, _ := lr["body"].(map[string]any)
				bodyTok, _ := body["stringValue"].(string)
				if !envelope.IsToken(bodyTok) {
					bodyTok = ""
				}
				if bodyTok != "" {
					st.collect("log_body", st.event, "", bodyTok)
				}
				d.decryptLocations(st, []location{{m: lr, scope: "log", where: st.where}}, rep)
				if bodyTok != "" && st.allowed {
					v, err := d.open(bodyTok, "log_body", st.event, "", st)
					if err == nil {
						var av map[string]any
						if av, err = toAnyValue(v); err == nil {
							lr["body"] = av
							rep.Decrypted++
						}
					}
					if err != nil {
						rep.fail(st.where+" body", err)
					}
				}
				d.stripKeys(lr)
			}
		}
	}
}

// toAnyValue converts a decrypted value into an OTLP JSON AnyValue.
func toAnyValue(v envelope.Value) (map[string]any, error) {
	switch v.Kind {
	case envelope.KindString:
		return map[string]any{"stringValue": string(v.Payload)}, nil
	case envelope.KindBytes:
		return map[string]any{"bytesValue": base64.StdEncoding.EncodeToString(v.Payload)}, nil
	}
	dec := json.NewDecoder(bytes.NewReader(v.Payload))
	dec.UseNumber()
	var raw any
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}
	return rawToAnyValue(raw), nil
}

func rawToAnyValue(raw any) map[string]any {
	switch v := raw.(type) {
	case nil:
		return map[string]any{}
	case string:
		return map[string]any{"stringValue": v}
	case bool:
		return map[string]any{"boolValue": v}
	case json.Number:
		if !strings.ContainsAny(v.String(), ".eE") {
			return map[string]any{"intValue": v.String()}
		}
		return map[string]any{"doubleValue": v}
	case []any:
		values := make([]any, len(v))
		for i, e := range v {
			values[i] = rawToAnyValue(e)
		}
		return map[string]any{"arrayValue": map[string]any{"values": values}}
	case map[string]any:
		keys := slices.Sorted(maps.Keys(v))
		values := make([]any, 0, len(v))
		for _, k := range keys {
			values = append(values, map[string]any{"key": k, "value": rawToAnyValue(v[k])})
		}
		return map[string]any{"kvlistValue": map[string]any{"values": values}}
	default:
		return map[string]any{"stringValue": fmt.Sprint(v)}
	}
}
