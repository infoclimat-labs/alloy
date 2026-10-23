package envelope

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

// Value kinds encoded in the first byte of every plaintext, so that a
// decryptor can restore the original type of an attribute or log body.
const (
	// KindString marks a UTF-8 string value.
	KindString byte = 's'
	// KindJSON marks a map, slice, number or boolean, serialized as JSON.
	KindJSON byte = 'j'
	// KindBytes marks a byte slice.
	KindBytes byte = 'b'
)

// maxKeyLen bounds the attribute key embedded in a plaintext.
const maxKeyLen = 4096

// EncodeValue builds the plaintext of a value:
//
//	kind (1 byte) | uvarint(len(key)) | key | payload
//
// The exact attribute key travels inside the ciphertext. The additional data
// only binds its normalized form (see NormalizeKey), so that values survive
// backends that sanitize keys; embedding the exact key lets a decryptor
// detect a token moved to a different key with the same normalized form.
func EncodeValue(kind byte, key string, payload []byte) ([]byte, error) {
	switch kind {
	case KindString, KindBytes:
	case KindJSON:
		if !json.Valid(payload) {
			return nil, errors.New("invalid JSON value")
		}
	default:
		return nil, fmt.Errorf("unknown value kind %q", kind)
	}
	if len(key) > maxKeyLen {
		return nil, errors.New("attribute key too long")
	}
	b := make([]byte, 0, 1+binary.MaxVarintLen64+len(key)+len(payload))
	b = append(b, kind)
	b = binary.AppendUvarint(b, uint64(len(key)))
	b = append(b, key...)
	return append(b, payload...), nil
}

// EncodeString prepares a string value for sealing.
func EncodeString(key, s string) []byte {
	b, _ := EncodeValue(KindString, key, []byte(s))
	return b
}

// EncodeJSON prepares a non-string value, already serialized as JSON, for
// sealing.
func EncodeJSON(key string, raw []byte) ([]byte, error) {
	return EncodeValue(KindJSON, key, raw)
}

// Value is a decoded plaintext.
type Value struct {
	Kind    byte
	Key     string
	Payload []byte
}

// DecodeValue parses a decrypted plaintext.
func DecodeValue(pt []byte) (Value, error) {
	if len(pt) == 0 {
		return Value{}, errors.New("empty plaintext")
	}
	kind := pt[0]
	switch kind {
	case KindString, KindJSON, KindBytes:
	default:
		return Value{}, fmt.Errorf("unknown value kind %q", kind)
	}
	n, sz := binary.Uvarint(pt[1:])
	if sz <= 0 || n > maxKeyLen || uint64(len(pt)-1-sz) < n {
		return Value{}, errors.New("malformed plaintext")
	}
	start := 1 + sz
	return Value{Kind: kind, Key: string(pt[start : start+int(n)]), Payload: pt[start+int(n):]}, nil
}

// CheckKey verifies that the key embedded in a plaintext matches the key the
// token was found under. When the document went through key sanitization
// (exact is false), the normalized forms must match.
func (v Value) CheckKey(key string, exact bool) error {
	if exact && v.Key != key {
		return fmt.Errorf("token was encrypted for attribute %q, found under %q", v.Key, key)
	}
	if !exact && NormalizeKey(v.Key) != NormalizeKey(key) {
		return fmt.Errorf("token was encrypted for attribute %q, found under %q", v.Key, key)
	}
	return nil
}
