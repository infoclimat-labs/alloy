package decrypt

import (
	"encoding/hex"
	"strings"

	"github.com/grafana/alloy/internal/component/otelcol/processor/encryption/encryptionprocessor/envelope"
)

// Loki stores OTLP log attributes as structured metadata with sanitized
// names (gen_ai.input.messages becomes gen_ai_input_messages) and the body as
// the log line. The encryption processor binds normalized keys and embeds the
// exact key in the plaintext, so values decrypt and the key is still checked.
var (
	lokiWrappedKeyPrefix = envelope.NormalizeKey(envelope.WrappedKeyAttrPrefix)
	lokiRecordIDLabel    = envelope.NormalizeKey(envelope.RecordIDAttr)
	lokiSignatureLabel   = envelope.NormalizeKey(envelope.SignatureAttr)
	lokiMetaLabel        = envelope.NormalizeKey(envelope.MetaAttr)
	lokiEventLabel       = envelope.NormalizeKey(envelope.EventAttr)
)

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
		if labels == nil {
			labels = map[string]any{}
		}
		// Labels shared by every entry of the stream are decrypted once per
		// entry from a pristine copy, then written back.
		pristine := make(map[string]any, len(labels))
		for k, v := range labels {
			pristine[k] = v
		}
		for _, entry := range list(stream, "values") {
			e, ok := entry.([]any)
			if !ok || len(e) < 2 {
				continue
			}
			// Structured metadata is either merged into the stream labels or,
			// with categorized labels, returned per entry.
			var meta map[string]any
			if len(e) > 2 {
				if cat, ok := e[2].(map[string]any); ok {
					meta, _ = cat["structuredMetadata"].(map[string]any)
				}
			}
			if meta == nil {
				meta = map[string]any{}
			}
			streamLabels := make(map[string]any, len(pristine))
			for k, v := range pristine {
				streamLabels[k] = v
			}
			d.lokiEntry(e, streamLabels, meta, rep)
			for k, v := range streamLabels {
				labels[k] = v
			}
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

func isMetaLabel(k string) bool {
	switch k {
	case lokiRecordIDLabel, lokiSignatureLabel, lokiMetaLabel, lokiEventLabel:
		return true
	}
	return envelope.IsMetaKey(k) || strings.HasPrefix(k, lokiWrappedKeyPrefix)
}

func (d *Decryptor) lokiEntry(e []any, labels, meta map[string]any, rep *Report) {
	// Loki rewrites attribute names and adds labels of its own: the
	// metadata digest can't be recomputed, only the signed one is used.
	st := &recordState{metaFromAttr: true, ctx: envelope.Context{
		Signal:  "logs",
		TraceID: decodeID(lookup("trace_id", meta, labels), 16),
		SpanID:  decodeID(lookup("span_id", meta, labels), 8),
	}}
	st.where = "loki entry"
	if ts, ok := e[0].(string); ok {
		st.where += " " + ts
	}
	st.wrapped = map[string]string{}
	for _, m := range []map[string]any{labels, meta} {
		for k, v := range m {
			s, ok := v.(string)
			if !ok {
				continue
			}
			switch k {
			case lokiRecordIDLabel, envelope.RecordIDAttr:
				st.ctx.RecordID, _ = hex.DecodeString(s)
			case lokiSignatureLabel, envelope.SignatureAttr:
				st.sig = s
			case lokiMetaLabel, envelope.MetaAttr:
				st.metaAttr = s
			case lokiEventLabel, envelope.EventAttr:
				st.event = s
			default:
				if id, ok := strings.CutPrefix(k, lokiWrappedKeyPrefix); ok {
					st.wrapped[id] = s
				} else if id, ok := strings.CutPrefix(k, envelope.WrappedKeyAttrPrefix); ok {
					st.wrapped[id] = s
				}
			}
		}
	}

	type labelToken struct {
		m        map[string]any
		key, tok string
	}
	var toks []labelToken
	// With categorized labels, structured metadata is per entry: tokens of
	// the stream labels belong to other records.
	sources := []map[string]any{labels}
	if len(meta) > 0 {
		sources = []map[string]any{meta}
	}
	for _, m := range sources {
		for k, v := range m {
			if s, ok := v.(string); ok && envelope.IsToken(s) && !isMetaLabel(k) {
				toks = append(toks, labelToken{m, k, s})
				st.collect("log", "", k, s)
			}
		}
	}
	line, _ := e[1].(string)
	if envelope.IsToken(line) {
		st.collect("log_body", st.event, "", line)
	} else {
		line = ""
	}
	d.verify(st, rep)
	if !st.allowed {
		return
	}

	for _, t := range toks {
		v, err := d.open(t.tok, "log", "", t.key, st)
		if err != nil {
			rep.fail(st.where+" "+t.key, err)
			continue
		}
		t.m[t.key] = string(v.Payload)
		rep.Decrypted++
	}
	if line != "" {
		v, err := d.open(line, "log_body", st.event, "", st)
		if err != nil {
			rep.fail(st.where+" line", err)
		} else {
			e[1] = string(v.Payload)
			rep.Decrypted++
		}
	}
	if !d.opts.KeepKeyAttributes {
		stripLokiKeys(meta)
	}
}

func stripLokiKeys(m map[string]any) {
	for k := range m {
		if isMetaLabel(k) {
			delete(m, k)
		}
	}
}
