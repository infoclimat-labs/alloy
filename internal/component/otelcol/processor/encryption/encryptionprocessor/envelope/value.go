package envelope

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Value kinds encoded in the first byte of every plaintext, so that a
// decryptor can restore the original type of an attribute or log body.
const (
	// KindString marks a UTF-8 string value.
	KindString byte = 's'
	// KindJSON marks any other value (map, slice, number, boolean, bytes),
	// serialized as JSON.
	KindJSON byte = 'j'
)

// EncodeString prepares a string value for sealing.
func EncodeString(s string) []byte {
	b := make([]byte, 1+len(s))
	b[0] = KindString
	copy(b[1:], s)
	return b
}

// EncodeJSON prepares a non-string value, already serialized as JSON, for
// sealing.
func EncodeJSON(raw []byte) ([]byte, error) {
	if !json.Valid(raw) {
		return nil, errors.New("invalid JSON value")
	}
	b := make([]byte, 1+len(raw))
	b[0] = KindJSON
	copy(b[1:], raw)
	return b, nil
}

// DecodeValue splits a decrypted plaintext into its kind and payload.
func DecodeValue(pt []byte) (kind byte, payload []byte, err error) {
	if len(pt) == 0 {
		return 0, nil, errors.New("empty plaintext")
	}
	switch pt[0] {
	case KindString, KindJSON:
		return pt[0], pt[1:], nil
	default:
		return 0, nil, fmt.Errorf("unknown value kind %q", pt[0])
	}
}
