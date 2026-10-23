package decrypt

import (
	"strings"

	"github.com/grafana/alloy/internal/component/otelcol/processor/encryption/encryptionprocessor/envelope"
)

// Loki stores OTLP log attributes as structured metadata with sanitized
// names (gen_ai.input.messages becomes gen_ai_input_messages) and the body as
// the log line. The encryption processor binds normalized keys, so both
// forms decrypt.
var lokiWrappedKeyPrefix = envelope.NormalizeKey(envelope.WrappedKeyAttrPrefix)

func isLoki(root map[string]any) bool {
	data, ok := root["data"].(map[string]any)
	if !ok {
		return false
	}
	t, _ := data["resultType"].(string)
	return t == "streams"
}

func (d *Decryptor) loki(root map[string]any, rep *Report) {
	data := root["data"].(map[string]any)
	for _, stream := range objects(list(data, "result")) {
		labels, _ := stream["stream"].(map[string]any)
		for _, entry := range list(stream, "values") {
			e, ok := entry.([]any)
			if !ok || len(e) < 2 {
				continue
			}
			// Structured metadata is either merged into the stream labels or,
			// with categorized labels, returned per entry.
			meta := map[string]any{}
			if len(e) > 2 {
				if cat, ok := e[2].(map[string]any); ok {
					meta, _ = cat["structuredMetadata"].(map[string]any)
				}
			}
			d.lokiEntry(e, labels, meta, rep)
		}
		if !d.opts.KeepKeyAttributes {
			stripLokiKeys(labels)
		}
	}
}

func lookup(name string, maps ...map[string]any) string {
	for _, m := range maps {
		if s, ok := m[name].(string); ok {
			return s
		}
	}
	return ""
}

func (d *Decryptor) lokiEntry(e []any, labels, meta map[string]any, rep *Report) {
	keys := map[string]string{}
	for _, m := range []map[string]any{labels, meta} {
		for k, v := range m {
			s, ok := v.(string)
			if !ok {
				continue
			}
			if id, ok := strings.CutPrefix(k, lokiWrappedKeyPrefix); ok {
				keys[id] = s
			} else if id, ok := strings.CutPrefix(k, envelope.WrappedKeyAttrPrefix); ok {
				keys[id] = s
			}
		}
	}
	c := envelope.Context{
		Signal:  "logs",
		Scope:   "log",
		TraceID: decodeID(lookup("trace_id", meta, labels), 16),
		SpanID:  decodeID(lookup("span_id", meta, labels), 8),
	}
	where := "loki entry"
	if ts, ok := e[0].(string); ok {
		where += " " + ts
	}

	for _, m := range []map[string]any{labels, meta} {
		for k, v := range m {
			tok, ok := v.(string)
			if !ok || !envelope.IsToken(tok) {
				continue
			}
			c.Key = k
			pt, err := d.open(tok, c, keys)
			if err != nil {
				rep.fail(where+" "+k, err)
				continue
			}
			s, err := plaintextString(pt)
			if err != nil {
				rep.fail(where+" "+k, err)
				continue
			}
			m[k] = s
			rep.Decrypted++
		}
	}

	if line, ok := e[1].(string); ok && envelope.IsToken(line) {
		c.Scope, c.Key = "log_body", ""
		pt, err := d.open(line, c, keys)
		if err == nil {
			var s string
			if s, err = plaintextString(pt); err == nil {
				e[1] = s
				rep.Decrypted++
			}
		}
		if err != nil {
			rep.fail(where+" line", err)
		}
	}
	if !d.opts.KeepKeyAttributes {
		stripLokiKeys(meta)
	}
}

func stripLokiKeys(m map[string]any) {
	for k := range m {
		if strings.HasPrefix(k, lokiWrappedKeyPrefix) || strings.HasPrefix(k, envelope.WrappedKeyAttrPrefix) {
			delete(m, k)
		}
	}
}

// plaintextString renders a decrypted value as text: strings as-is, other
// values as their JSON serialization.
func plaintextString(pt []byte) (string, error) {
	_, payload, err := envelope.DecodeValue(pt)
	if err != nil {
		return "", err
	}
	return string(payload), nil
}
