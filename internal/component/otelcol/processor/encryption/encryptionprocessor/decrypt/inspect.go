package decrypt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/grafana/alloy/internal/component/otelcol/processor/encryption/encryptionprocessor/envelope"
)

// DataKey describes a wrapped data encryption key found in a document.
type DataKey struct {
	ID         string   `json:"id"`
	Recipients []string `json:"recipients"`
	Error      string   `json:"error,omitempty"`
}

// Inventory lists what a document contains without decrypting anything.
type Inventory struct {
	Tokens   int            `json:"tokens"`
	DataKeys []DataKey      `json:"data_keys"`
	ByKey    map[string]int `json:"data_keys_per_recipient"`
}

// Inspect walks any JSON document and reports the encryption tokens and the
// wrapped keys (with their recipients) it contains. It needs no private key.
func Inspect(doc []byte) (Inventory, error) {
	var root any
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return Inventory{}, fmt.Errorf("parsing JSON: %w", err)
	}
	inv := Inventory{ByKey: map[string]int{}}
	wrapped := map[string]string{}
	walk(root, &inv, wrapped)

	for _, id := range slices.Sorted(maps.Keys(wrapped)) {
		dk := DataKey{ID: id}
		recipients, err := envelope.WrappedKeyRecipients(wrapped[id])
		if err != nil {
			dk.Error = err.Error()
		}
		dk.Recipients = recipients
		for _, r := range recipients {
			inv.ByKey[r]++
		}
		inv.DataKeys = append(inv.DataKeys, dk)
	}
	return inv, nil
}

func wrappedKeyID(name string) (string, bool) {
	if id, ok := strings.CutPrefix(name, envelope.WrappedKeyAttrPrefix); ok {
		return id, true
	}
	return strings.CutPrefix(name, lokiWrappedKeyPrefix)
}

func walk(v any, inv *Inventory, wrapped map[string]string) {
	switch t := v.(type) {
	case string:
		if envelope.IsToken(t) {
			inv.Tokens++
		}
	case []any:
		for _, e := range t {
			walk(e, inv, wrapped)
		}
	case map[string]any:
		// OTLP JSON attribute: {"key": "...", "value": {"stringValue": "..."}}
		if k, ok := t["key"].(string); ok {
			if id, ok := wrappedKeyID(k); ok {
				if val, ok := t["value"].(map[string]any); ok {
					if s, ok := val["stringValue"].(string); ok {
						wrapped[id] = s
						return
					}
				}
			}
		}
		for k, e := range t {
			// Label maps (Loki): {"encryption_dek_<id>": "..."}
			if id, ok := wrappedKeyID(k); ok {
				if s, ok := e.(string); ok {
					wrapped[id] = s
					continue
				}
			}
			walk(e, inv, wrapped)
		}
	}
}
