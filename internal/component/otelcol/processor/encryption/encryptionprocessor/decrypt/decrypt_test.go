package decrypt

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/grafana/alloy/internal/component/otelcol/processor/encryption/encryptionprocessor/envelope"
)

var (
	traceID = bytes.Repeat([]byte{0x11}, 16)
	spanID  = bytes.Repeat([]byte{0x22}, 8)
	fast    = envelope.Suite{KEM: envelope.KEMX25519HKDFSHA256, KDF: envelope.KDFHKDFSHA256, AEAD: envelope.AEADAES256GCM}
)

type fixture struct {
	t    *testing.T
	priv *envelope.PrivateKey
	dek  *envelope.DEK
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	priv, err := envelope.GenerateKey(fast)
	if err != nil {
		t.Fatal(err)
	}
	s, err := envelope.NewSealer([]*envelope.PublicKey{priv.Public()}, envelope.SealerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	dek, err := s.Current()
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{t: t, priv: priv, dek: dek}
}

func (f *fixture) seal(pt []byte, signal, scope, key string) string {
	f.t.Helper()
	tok, err := f.dek.Seal(pt, envelope.Context{Signal: signal, Scope: scope, Key: key, TraceID: traceID, SpanID: spanID})
	if err != nil {
		f.t.Fatal(err)
	}
	return tok
}

func strAttr(k, v string) map[string]any {
	return map[string]any{"key": k, "value": map[string]any{"stringValue": v}}
}

func (f *fixture) decrypt(doc any, opts Options) (map[string]any, Report) {
	f.t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		f.t.Fatal(err)
	}
	out, rep, err := New(envelope.NewKeyring(f.priv), opts).Decrypt(raw)
	if err != nil {
		f.t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		f.t.Fatal(err)
	}
	return m, rep
}

func dig(t *testing.T, v any, path ...any) any {
	t.Helper()
	for _, p := range path {
		switch k := p.(type) {
		case string:
			v = v.(map[string]any)[k]
		case int:
			v = v.([]any)[k]
		}
	}
	return v
}

func attrMap(t *testing.T, attrs any) map[string]any {
	t.Helper()
	m := map[string]any{}
	for _, a := range attrs.([]any) {
		am := a.(map[string]any)
		m[am["key"].(string)] = am["value"]
	}
	return m
}

func TestOTLPTraces(t *testing.T) {
	f := newFixture(t)
	jsonVal, _ := envelope.EncodeJSON([]byte(`{"city":"Paris","count":3,"ratio":0.5,"tags":["a",true,null]}`))
	doc := map[string]any{
		"resourceSpans": []any{map[string]any{
			"scopeSpans": []any{map[string]any{
				"spans": []any{map[string]any{
					"traceId": hex.EncodeToString(traceID),
					"spanId":  hex.EncodeToString(spanID),
					"attributes": []any{
						strAttr("gen_ai.request.model", "mistral-large"),
						strAttr("gen_ai.input.messages", f.seal(envelope.EncodeString("Bonjour"), "traces", "span", "gen_ai.input.messages")),
						strAttr("gen_ai.tool.call.arguments", f.seal(jsonVal, "traces", "span", "gen_ai.tool.call.arguments")),
						strAttr(f.dek.AttributeKey(), f.dek.WrappedKey()),
					},
					"events": []any{map[string]any{
						"name":       "gen_ai.content.prompt",
						"attributes": []any{strAttr("gen_ai.prompt", f.seal(envelope.EncodeString("event content"), "traces", "span_event", "gen_ai.prompt"))},
					}},
				}},
			}},
		}},
	}

	out, rep := f.decrypt(doc, Options{})
	if rep.Format != FormatOTLPTraces || rep.Decrypted != 3 || rep.Failed != 0 {
		t.Fatalf("report = %+v", rep)
	}
	span := dig(t, out, "resourceSpans", 0, "scopeSpans", 0, "spans", 0)
	attrs := attrMap(t, dig(t, span, "attributes"))
	if got := attrs["gen_ai.input.messages"].(map[string]any)["stringValue"]; got != "Bonjour" {
		t.Errorf("input messages = %v", got)
	}
	if got := attrs["gen_ai.request.model"].(map[string]any)["stringValue"]; got != "mistral-large" {
		t.Errorf("clear attribute modified: %v", got)
	}
	if _, ok := attrs[f.dek.AttributeKey()]; ok {
		t.Error("wrapped key attribute not stripped")
	}
	kv := attrMap(t, dig(t, attrs["gen_ai.tool.call.arguments"], "kvlistValue", "values"))
	if kv["count"].(map[string]any)["intValue"] != "3" || kv["ratio"].(map[string]any)["doubleValue"] != 0.5 {
		t.Errorf("typed values not restored: %v", kv)
	}
	tags := dig(t, kv["tags"], "arrayValue", "values").([]any)
	if len(tags) != 3 || tags[1].(map[string]any)["boolValue"] != true {
		t.Errorf("array not restored: %v", tags)
	}
	ev := attrMap(t, dig(t, span, "events", 0, "attributes"))
	if got := ev["gen_ai.prompt"].(map[string]any)["stringValue"]; got != "event content" {
		t.Errorf("event attribute = %v", got)
	}

	// Keeping the wrapped key attributes.
	out, _ = f.decrypt(doc, Options{KeepKeyAttributes: true})
	attrs = attrMap(t, dig(t, out, "resourceSpans", 0, "scopeSpans", 0, "spans", 0, "attributes"))
	if _, ok := attrs[f.dek.AttributeKey()]; !ok {
		t.Error("wrapped key attribute stripped despite KeepKeyAttributes")
	}
}

func TestTempoFlavour(t *testing.T) {
	f := newFixture(t)
	doc := map[string]any{"trace": map[string]any{
		"batches": []any{map[string]any{
			"instrumentationLibrarySpans": []any{map[string]any{
				"spans": []any{map[string]any{
					"traceId": base64.StdEncoding.EncodeToString(traceID),
					"spanId":  base64.StdEncoding.EncodeToString(spanID),
					"attributes": []any{
						strAttr("gen_ai.output.messages", f.seal(envelope.EncodeString("Réponse"), "traces", "span", "gen_ai.output.messages")),
						strAttr(f.dek.AttributeKey(), f.dek.WrappedKey()),
					},
				}},
			}},
		}},
	}}
	out, rep := f.decrypt(doc, Options{})
	if rep.Decrypted != 1 || rep.Failed != 0 {
		t.Fatalf("report = %+v", rep)
	}
	attrs := attrMap(t, dig(t, out, "trace", "batches", 0, "instrumentationLibrarySpans", 0, "spans", 0, "attributes"))
	if got := attrs["gen_ai.output.messages"].(map[string]any)["stringValue"]; got != "Réponse" {
		t.Errorf("value = %v", got)
	}
}

func TestOTLPLogs(t *testing.T) {
	f := newFixture(t)
	body, _ := envelope.EncodeJSON([]byte(`{"content":"Quelle est la météo ?","role":"user"}`))
	doc := map[string]any{
		"resourceLogs": []any{map[string]any{
			"scopeLogs": []any{map[string]any{
				"logRecords": []any{map[string]any{
					"traceId":   hex.EncodeToString(traceID),
					"spanId":    hex.EncodeToString(spanID),
					"eventName": "gen_ai.user.message",
					"body":      map[string]any{"stringValue": f.seal(body, "logs", "log_body", "")},
					"attributes": []any{
						strAttr("gen_ai.input.messages", f.seal(envelope.EncodeString("x"), "logs", "log", "gen_ai.input.messages")),
						strAttr(f.dek.AttributeKey(), f.dek.WrappedKey()),
					},
				}},
			}},
		}},
	}
	out, rep := f.decrypt(doc, Options{})
	if rep.Format != FormatOTLPLogs || rep.Decrypted != 2 || rep.Failed != 0 {
		t.Fatalf("report = %+v", rep)
	}
	kv := attrMap(t, dig(t, out, "resourceLogs", 0, "scopeLogs", 0, "logRecords", 0, "body", "kvlistValue", "values"))
	if kv["content"].(map[string]any)["stringValue"] != "Quelle est la météo ?" {
		t.Errorf("body = %v", kv)
	}
}

func TestLoki(t *testing.T) {
	for _, categorized := range []bool{false, true} {
		t.Run(map[bool]string{false: "merged", true: "categorized"}[categorized], func(t *testing.T) {
			f := newFixture(t)
			meta := map[string]any{
				"trace_id":              hex.EncodeToString(traceID),
				"span_id":               hex.EncodeToString(spanID),
				"gen_ai_input_messages": f.seal(envelope.EncodeString("prompt"), "logs", "log", "gen_ai.input.messages"),
				envelope.NormalizeKey(f.dek.AttributeKey()): f.dek.WrappedKey(),
			}
			line := f.seal(envelope.EncodeString("body text"), "logs", "log_body", "")
			stream := map[string]any{"service_name": "agent"}
			entry := []any{"1761200000000000000", line}
			if categorized {
				entry = append(entry, map[string]any{"structuredMetadata": meta})
			} else {
				for k, v := range meta {
					stream[k] = v
				}
			}
			doc := map[string]any{"status": "success", "data": map[string]any{
				"resultType": "streams",
				"result":     []any{map[string]any{"stream": stream, "values": []any{entry}}},
			}}

			out, rep := f.decrypt(doc, Options{})
			if rep.Format != FormatLoki || rep.Decrypted != 2 || rep.Failed != 0 {
				t.Fatalf("report = %+v", rep)
			}
			res := dig(t, out, "data", "result", 0)
			if got := dig(t, res, "values", 0, 1); got != "body text" {
				t.Errorf("line = %v", got)
			}
			labels := dig(t, res, "stream").(map[string]any)
			if categorized {
				labels = dig(t, res, "values", 0, 2, "structuredMetadata").(map[string]any)
			}
			if labels["gen_ai_input_messages"] != "prompt" {
				t.Errorf("metadata = %v", labels)
			}
			for k := range labels {
				if strings.HasPrefix(k, "encryption_dek_") {
					t.Errorf("wrapped key label %s not stripped", k)
				}
			}
		})
	}
}

func TestFailures(t *testing.T) {
	f := newFixture(t)
	tok := f.seal(envelope.EncodeString("secret"), "traces", "span", "gen_ai.input.messages")
	span := func(attrs ...any) map[string]any {
		return map[string]any{"resourceSpans": []any{map[string]any{"scopeSpans": []any{map[string]any{"spans": []any{map[string]any{
			"traceId": hex.EncodeToString(traceID), "spanId": hex.EncodeToString(spanID), "attributes": attrs,
		}}}}}}}
	}

	// Wrapped key missing from the record.
	_, rep := f.decrypt(span(strAttr("gen_ai.input.messages", tok)), Options{})
	if rep.Failed != 1 || !strings.Contains(rep.Errors[0], "not found") {
		t.Errorf("missing key: %+v", rep)
	}

	// Token moved to another attribute.
	_, rep = f.decrypt(span(strAttr("gen_ai.output.messages", tok), strAttr(f.dek.AttributeKey(), f.dek.WrappedKey())), Options{})
	if rep.Failed != 1 {
		t.Errorf("moved token: %+v", rep)
	}

	// Wrong private key.
	other, _ := envelope.GenerateKey(fast)
	raw, _ := json.Marshal(span(strAttr("gen_ai.input.messages", tok), strAttr(f.dek.AttributeKey(), f.dek.WrappedKey())))
	_, rep, err := New(envelope.NewKeyring(other), Options{}).Decrypt(raw)
	if err != nil || rep.Failed != 1 || !strings.Contains(rep.Errors[0], "no private key") {
		t.Errorf("wrong key: %+v %v", rep, err)
	}

	if _, _, err := New(envelope.NewKeyring(f.priv), Options{}).Decrypt([]byte(`{"foo":1}`)); err == nil {
		t.Error("unknown document accepted")
	}
}

func TestInspect(t *testing.T) {
	f := newFixture(t)
	doc, _ := json.Marshal(map[string]any{"resourceSpans": []any{map[string]any{"scopeSpans": []any{map[string]any{"spans": []any{map[string]any{
		"attributes": []any{
			strAttr("a", f.seal(envelope.EncodeString("1"), "traces", "span", "a")),
			strAttr("b", f.seal(envelope.EncodeString("2"), "traces", "span", "b")),
			strAttr(f.dek.AttributeKey(), f.dek.WrappedKey()),
		},
	}}}}}}})
	inv, err := Inspect(doc)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Tokens != 2 || len(inv.DataKeys) != 1 || inv.DataKeys[0].ID != f.dek.ID() || inv.ByKey[f.priv.KeyID()] != 1 {
		t.Fatalf("inventory = %+v", inv)
	}
}
