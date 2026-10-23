// Package decrypt restores values encrypted by the encryption processor in
// exported telemetry documents. It supports OTLP JSON (traces and logs,
// including the Tempo API flavour) and Loki query responses.
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
	"strings"

	"github.com/grafana/alloy/internal/component/otelcol/processor/encryption/encryptionprocessor/envelope"
)

// Options control decryption.
type Options struct {
	// KeepKeyAttributes keeps the encryption.dek.* attributes in the output.
	KeepKeyAttributes bool
}

// Report summarizes a decryption run.
type Report struct {
	Format    string   `json:"format"`
	Decrypted int      `json:"decrypted"`
	Failed    int      `json:"failed"`
	Errors    []string `json:"errors,omitempty"`
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
	kr   *envelope.Keyring
	opts Options
	deks map[string]*envelope.DEK
}

// New creates a decryptor.
func New(kr *envelope.Keyring, opts Options) *Decryptor {
	return &Decryptor{kr: kr, opts: opts, deks: map[string]*envelope.DEK{}}
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

func wrappedKeys(attrs []kv) map[string]string {
	keys := map[string]string{}
	for _, a := range attrs {
		if id, ok := strings.CutPrefix(a.key, envelope.WrappedKeyAttrPrefix); ok {
			if s, ok := a.value["stringValue"].(string); ok {
				keys[id] = s
			}
		}
	}
	return keys
}

func (d *Decryptor) open(token string, c envelope.Context, keys map[string]string) ([]byte, error) {
	id, _, err := envelope.ParseToken(token)
	if err != nil {
		return nil, err
	}
	wrapped, ok := keys[id]
	if !ok {
		return nil, fmt.Errorf("wrapped key %s%s not found on the record", envelope.WrappedKeyAttrPrefix, id)
	}
	dek, ok := d.deks[wrapped]
	if !ok {
		if dek, err = d.kr.Unwrap(id, wrapped); err != nil {
			return nil, err
		}
		d.deks[wrapped] = dek
	}
	pt, err := dek.Open(token, c)
	if err != nil {
		return nil, err
	}
	return pt, nil
}

func (d *Decryptor) decryptAttributes(m map[string]any, c envelope.Context, keys map[string]string, rep *Report, where string) {
	for _, a := range attributes(m) {
		tok, ok := a.value["stringValue"].(string)
		if !ok || !envelope.IsToken(tok) {
			continue
		}
		c.Key = a.key
		pt, err := d.open(tok, c, keys)
		if err != nil {
			rep.fail(where+" "+a.key, err)
			continue
		}
		v, err := toAnyValue(pt)
		if err != nil {
			rep.fail(where+" "+a.key, err)
			continue
		}
		a.m["value"] = v
		rep.Decrypted++
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
			if k, _ := am["key"].(string); strings.HasPrefix(k, envelope.WrappedKeyAttrPrefix) {
				continue
			}
		}
		out = append(out, a)
	}
	m["attributes"] = out
}

func (d *Decryptor) traces(root map[string]any, rep *Report) {
	for _, rs := range objects(list(root, "resourceSpans", "batches")) {
		for _, ss := range objects(list(rs, "scopeSpans", "instrumentationLibrarySpans")) {
			for _, span := range objects(list(ss, "spans")) {
				c := envelope.Context{
					Signal:  "traces",
					Scope:   "span",
					TraceID: decodeID(span["traceId"], 16),
					SpanID:  decodeID(span["spanId"], 8),
				}
				keys := wrappedKeys(attributes(span))
				where := fmt.Sprintf("span %x/%x", c.TraceID, c.SpanID)
				d.decryptAttributes(span, c, keys, rep, where)
				c.Scope = "span_event"
				for _, ev := range objects(list(span, "events")) {
					d.decryptAttributes(ev, c, keys, rep, where+" event")
				}
				d.stripKeys(span)
			}
		}
	}
}

func (d *Decryptor) logs(root map[string]any, rep *Report) {
	for _, rl := range objects(list(root, "resourceLogs")) {
		for _, sl := range objects(list(rl, "scopeLogs", "instrumentationLibraryLogs")) {
			for _, lr := range objects(list(sl, "logRecords")) {
				c := envelope.Context{
					Signal:  "logs",
					Scope:   "log",
					TraceID: decodeID(lr["traceId"], 16),
					SpanID:  decodeID(lr["spanId"], 8),
				}
				keys := wrappedKeys(attributes(lr))
				where := fmt.Sprintf("log %x/%x", c.TraceID, c.SpanID)
				d.decryptAttributes(lr, c, keys, rep, where)

				if body, ok := lr["body"].(map[string]any); ok {
					if tok, ok := body["stringValue"].(string); ok && envelope.IsToken(tok) {
						c.Scope, c.Key = "log_body", ""
						pt, err := d.open(tok, c, keys)
						if err == nil {
							var v map[string]any
							if v, err = toAnyValue(pt); err == nil {
								lr["body"] = v
								rep.Decrypted++
							}
						}
						if err != nil {
							rep.fail(where+" body", err)
						}
					}
				}
				d.stripKeys(lr)
			}
		}
	}
}

// toAnyValue converts a decrypted plaintext into an OTLP JSON AnyValue.
func toAnyValue(pt []byte) (map[string]any, error) {
	kind, payload, err := envelope.DecodeValue(pt)
	if err != nil {
		return nil, err
	}
	if kind == envelope.KindString {
		return map[string]any{"stringValue": string(payload)}, nil
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
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
