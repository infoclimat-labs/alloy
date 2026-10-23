package envelope

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Wire format constants.
//
// An encrypted value is rendered as a string token:
//
//	enc:v1:<dek-id>:<base64url(nonce || ciphertext || tag)>
//
// The data encryption key (DEK) it was sealed with travels next to it, on the
// same span or log record, in an attribute named
//
//	encryption.dek.<dek-id>
//
// whose value is one or more wrapped-key blobs (one per recipient), each
// base64url encoded and joined with ".". A wrapped-key blob is:
//
//	"OE" | version (1 byte) | KEM (u16) | KDF (u16) | AEAD (u16) | key ID (8 bytes) | HPKE enc || HPKE ciphertext
//
// The dek-id is derived from the wrapped-key attribute value, which lets a
// decryptor verify that a token and a wrapped key belong together.
const (
	TokenPrefix          = "enc:v1:"
	WrappedKeyAttrPrefix = "encryption.dek."

	blobMagic0  = 'O'
	blobMagic1  = 'E'
	blobVersion = 1
	blobHeader  = 2 + 1 + 6 + kidSize

	dekSize      = 32 // AES-256
	dekIDSize    = 9  // bytes, 18 hex characters (hex survives label sanitization)
	nonceSize    = 12
	recipientSep = "."

	dekWrapLabel = "otel-encryption/v1 dek"
	valueLabel   = "otel-encryption/v1 value"
)

var b64 = base64.RawURLEncoding

// Errors returned when decrypting.
var (
	ErrNotToken       = errors.New("value is not an encryption token")
	ErrNoMatchingKey  = errors.New("no private key matches the wrapped data encryption key")
	ErrDEKMismatch    = errors.New("token does not belong to this data encryption key")
	ErrAuthentication = errors.New("message authentication failed")
)

// Context binds a ciphertext to its location in the telemetry. It is used as
// AEAD additional data, so a token copied to another attribute, record or
// trace fails to decrypt.
type Context struct {
	// Signal is "traces" or "logs".
	Signal string
	// Scope is where the value lives: "span", "span_event", "log" or "log_body".
	Scope string
	// Key is the attribute key, or empty for a log body. It is bound in its
	// normalized form, see NormalizeKey.
	Key string
	// TraceID and SpanID are the raw identifiers of the record, if any.
	TraceID []byte
	SpanID  []byte
}

// NormalizeKey maps an attribute key to the form bound into the additional
// data: every character outside [A-Za-z0-9_] becomes "_". This matches the
// label sanitization applied by Prometheus-style backends such as Loki, so a
// value stays decryptable after its key went through that sanitization
// (gen_ai.input.messages and gen_ai_input_messages bind identically).
func NormalizeKey(k string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			return r
		default:
			return '_'
		}
	}, k)
}

func (c Context) aad(dekID string) []byte {
	var buf bytes.Buffer
	for _, field := range [][]byte{
		[]byte(valueLabel),
		[]byte(dekID),
		[]byte(c.Signal),
		[]byte(c.Scope),
		[]byte(NormalizeKey(c.Key)),
		c.TraceID,
		c.SpanID,
	} {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(field)))
		buf.Write(l[:])
		buf.Write(field)
	}
	return buf.Bytes()
}

// DEK is a data encryption key together with its wrapped form.
type DEK struct {
	id      string
	wrapped string
	aead    cipher.AEAD
	created time.Time
	uses    atomic.Uint64
	rand    io.Reader
}

func newDEKCipher(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func dekIDFor(wrapped string) string {
	sum := sha256.Sum256([]byte(wrapped))
	return hex.EncodeToString(sum[:dekIDSize])
}

// ID returns the identifier referenced by tokens sealed with this key.
func (d *DEK) ID() string { return d.id }

// WrappedKey returns the value of the wrapped-key attribute.
func (d *DEK) WrappedKey() string { return d.wrapped }

// AttributeKey returns the name of the wrapped-key attribute.
func (d *DEK) AttributeKey() string { return WrappedKeyAttrPrefix + d.id }

// Uses returns how many values have been sealed with the key.
func (d *DEK) Uses() uint64 { return d.uses.Load() }

// Seal encrypts plaintext and returns a token.
func (d *DEK) Seal(plaintext []byte, c Context) (string, error) {
	nonce := make([]byte, nonceSize, nonceSize+len(plaintext)+d.aead.Overhead())
	if _, err := io.ReadFull(d.rand, nonce); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}
	d.uses.Add(1)
	sealed := d.aead.Seal(nonce, nonce, plaintext, c.aad(d.id))

	var sb strings.Builder
	sb.Grow(len(TokenPrefix) + len(d.id) + 1 + b64.EncodedLen(len(sealed)))
	sb.WriteString(TokenPrefix)
	sb.WriteString(d.id)
	sb.WriteByte(':')
	sb.WriteString(b64.EncodeToString(sealed))
	return sb.String(), nil
}

// Open decrypts a token produced by Seal with the same context.
func (d *DEK) Open(token string, c Context) ([]byte, error) {
	id, sealed, err := ParseToken(token)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(id), []byte(d.id)) != 1 {
		return nil, ErrDEKMismatch
	}
	if len(sealed) < nonceSize+d.aead.Overhead() {
		return nil, errors.New("token payload is too short")
	}
	pt, err := d.aead.Open(nil, sealed[:nonceSize], sealed[nonceSize:], c.aad(d.id))
	if err != nil {
		return nil, ErrAuthentication
	}
	return pt, nil
}

// IsToken reports whether s looks like an encryption token.
func IsToken(s string) bool { return strings.HasPrefix(s, TokenPrefix) }

// ParseToken splits a token into its DEK ID and sealed payload.
func ParseToken(token string) (dekID string, sealed []byte, err error) {
	if !IsToken(token) {
		return "", nil, ErrNotToken
	}
	rest := token[len(TokenPrefix):]
	id, payload, ok := strings.Cut(rest, ":")
	if !ok || len(id) != hex.EncodedLen(dekIDSize) {
		return "", nil, errors.New("malformed encryption token")
	}
	sealed, err = b64.DecodeString(payload)
	if err != nil {
		return "", nil, fmt.Errorf("malformed encryption token payload: %w", err)
	}
	return id, sealed, nil
}

func wrapInfo(header []byte) []byte {
	info := make([]byte, 0, len(dekWrapLabel)+len(header))
	info = append(info, dekWrapLabel...)
	return append(info, header...)
}

func blobHeaderFor(p *PublicKey) []byte {
	h := make([]byte, 0, blobHeader)
	h = append(h, blobMagic0, blobMagic1, blobVersion)
	h = append(h, p.suite.bytes()...)
	return append(h, p.kid...)
}

func wrapDEK(key []byte, recipients []*PublicKey) (string, error) {
	parts := make([]string, 0, len(recipients))
	for _, r := range recipients {
		header := blobHeaderFor(r)
		ct, err := hpke.Seal(r.pk, r.kdf, r.aead, wrapInfo(header), key)
		if err != nil {
			return "", fmt.Errorf("wrapping key for recipient %s: %w", r.KeyID(), err)
		}
		parts = append(parts, b64.EncodeToString(append(header, ct...)))
	}
	return strings.Join(parts, recipientSep), nil
}

// SealerOptions control data encryption key rotation.
type SealerOptions struct {
	// MaxUses is the number of values sealed with one DEK before it is
	// rotated. Zero selects DefaultMaxUses.
	MaxUses uint64
	// MaxAge is how long a DEK is used before it is rotated. Zero selects
	// DefaultMaxAge.
	MaxAge time.Duration

	// Rand and Now are test hooks.
	Rand io.Reader
	Now  func() time.Time
}

// Rotation defaults. AES-GCM with random 96-bit nonces must stay well below
// 2^32 messages per key; rotating after 2^24 values keeps the collision
// probability negligible, and the age limit bounds how much telemetry a key
// leaked from process memory can expose.
const (
	DefaultMaxUses = 1 << 24
	DefaultMaxAge  = 10 * time.Minute
)

// Sealer hands out the current DEK for a set of recipients and rotates it
// according to its options. It is safe for concurrent use.
type Sealer struct {
	recipients []*PublicKey
	maxUses    uint64
	maxAge     time.Duration
	rand       io.Reader
	now        func() time.Time

	mu        sync.Mutex
	current   *DEK
	rotations atomic.Uint64
}

// NewSealer creates a sealer wrapping each DEK for all recipients.
func NewSealer(recipients []*PublicKey, opts SealerOptions) (*Sealer, error) {
	if len(recipients) == 0 {
		return nil, errors.New("at least one recipient is required")
	}
	seen := make(map[string]bool, len(recipients))
	for _, r := range recipients {
		if r == nil {
			return nil, errors.New("nil recipient")
		}
		if seen[r.KeyID()] {
			return nil, fmt.Errorf("duplicate recipient %s", r.KeyID())
		}
		seen[r.KeyID()] = true
	}
	s := &Sealer{
		recipients: append([]*PublicKey(nil), recipients...),
		maxUses:    opts.MaxUses,
		maxAge:     opts.MaxAge,
		rand:       opts.Rand,
		now:        opts.Now,
	}
	if s.maxUses == 0 {
		s.maxUses = DefaultMaxUses
	}
	if s.maxAge == 0 {
		s.maxAge = DefaultMaxAge
	}
	if s.rand == nil {
		s.rand = rand.Reader
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s, nil
}

// Recipients returns the key IDs of the recipients.
func (s *Sealer) Recipients() []string {
	ids := make([]string, len(s.recipients))
	for i, r := range s.recipients {
		ids[i] = r.KeyID()
	}
	return ids
}

// Rotations returns how many DEKs the sealer has generated.
func (s *Sealer) Rotations() uint64 { return s.rotations.Load() }

// Current returns the DEK to use for the next record, rotating it first if
// it reached its use or age limit.
func (s *Sealer) Current() (*DEK, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d := s.current; d != nil && d.Uses() < s.maxUses && s.now().Sub(d.created) < s.maxAge {
		return d, nil
	}
	d, err := s.newDEK()
	if err != nil {
		return nil, err
	}
	s.current = d
	s.rotations.Add(1)
	return d, nil
}

func (s *Sealer) newDEK() (*DEK, error) {
	key := make([]byte, dekSize)
	if _, err := io.ReadFull(s.rand, key); err != nil {
		return nil, fmt.Errorf("generating data encryption key: %w", err)
	}
	wrapped, err := wrapDEK(key, s.recipients)
	if err != nil {
		return nil, err
	}
	aead, err := newDEKCipher(key)
	if err != nil {
		return nil, err
	}
	return &DEK{
		id:      dekIDFor(wrapped),
		wrapped: wrapped,
		aead:    aead,
		created: s.now(),
		rand:    s.rand,
	}, nil
}

// Keyring holds private keys used to unwrap DEKs. It is safe for concurrent
// use once built.
type Keyring struct {
	keys map[string]*PrivateKey
}

// NewKeyring builds a keyring from private keys.
func NewKeyring(keys ...*PrivateKey) *Keyring {
	kr := &Keyring{keys: make(map[string]*PrivateKey, len(keys))}
	for _, k := range keys {
		kr.keys[k.KeyID()] = k
	}
	return kr
}

// KeyIDs returns the identifiers of the keys in the keyring.
func (kr *Keyring) KeyIDs() []string {
	ids := make([]string, 0, len(kr.keys))
	for id := range kr.keys {
		ids = append(ids, id)
	}
	return ids
}

// WrappedKeyRecipients lists the recipient key IDs of a wrapped-key value
// without decrypting it.
func WrappedKeyRecipients(wrapped string) ([]string, error) {
	var ids []string
	for _, part := range strings.Split(wrapped, recipientSep) {
		blob, err := b64.DecodeString(part)
		if err != nil {
			return nil, fmt.Errorf("malformed wrapped key: %w", err)
		}
		if err := checkBlob(blob); err != nil {
			return nil, err
		}
		ids = append(ids, hex.EncodeToString(blob[9:blobHeader]))
	}
	return ids, nil
}

func checkBlob(blob []byte) error {
	if len(blob) <= blobHeader || blob[0] != blobMagic0 || blob[1] != blobMagic1 {
		return errors.New("malformed wrapped key blob")
	}
	if blob[2] != blobVersion {
		return fmt.Errorf("unsupported wrapped key version %d", blob[2])
	}
	return nil
}

// Unwrap recovers the DEK from a wrapped-key attribute value using any
// matching private key. dekID, when non-empty, must match the identifier
// derived from the wrapped value.
func (kr *Keyring) Unwrap(dekID, wrapped string) (*DEK, error) {
	if dekID != "" && subtle.ConstantTimeCompare([]byte(dekID), []byte(dekIDFor(wrapped))) != 1 {
		return nil, ErrDEKMismatch
	}
	for _, part := range strings.Split(wrapped, recipientSep) {
		blob, err := b64.DecodeString(part)
		if err != nil {
			return nil, fmt.Errorf("malformed wrapped key: %w", err)
		}
		if err := checkBlob(blob); err != nil {
			return nil, err
		}
		kid := hex.EncodeToString(blob[9:blobHeader])
		k, ok := kr.keys[kid]
		if !ok {
			continue
		}
		header := blob[:blobHeader]
		if !bytes.Equal(header[3:9], k.pub.suite.bytes()) {
			return nil, fmt.Errorf("wrapped key suite does not match key %s", kid)
		}
		key, err := hpke.Open(k.sk, k.pub.kdf, k.pub.aead, wrapInfo(header), blob[blobHeader:])
		if err != nil {
			return nil, fmt.Errorf("unwrapping key with %s: %w", kid, ErrAuthentication)
		}
		if len(key) != dekSize {
			return nil, errors.New("unexpected data encryption key size")
		}
		aead, err := newDEKCipher(key)
		if err != nil {
			return nil, err
		}
		return &DEK{id: dekIDFor(wrapped), wrapped: wrapped, aead: aead, rand: rand.Reader}, nil
	}
	return nil, ErrNoMatchingKey
}
