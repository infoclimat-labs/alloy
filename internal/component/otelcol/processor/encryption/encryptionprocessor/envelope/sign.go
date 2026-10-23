package envelope

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Record signatures.
//
// Encryption alone gives confidentiality, not authenticity: anyone holding a
// recipient public key can produce tokens that decrypt. When a signing key is
// configured, the processor signs every record it encrypts. The signature
// covers the record ID, trace and span IDs, the wrapped keys and every token
// with its location, so forged, moved, altered or deleted tokens are
// detected by a decryptor that pins the verification key.

// PEM block types of signing keys.
const (
	SigningKeyPEMType = "OTEL ENCRYPTION SIGNING KEY"
	VerifyKeyPEMType  = "OTEL ENCRYPTION VERIFY KEY"

	pemHeaderAlg = "Algorithm"
	sigKIDLabel  = "otel-encryption/v1 sigkid"
	recordLabel  = "otel-encryption/v1 record"
	mldsaContext = "otel-encryption/v1"
)

// Signature algorithms.
const (
	SigEd25519 = "Ed25519"
	SigMLDSA65 = "ML-DSA-65"
	SigMLDSA87 = "ML-DSA-87"
)

// Errors returned when verifying signatures.
var (
	ErrUnknownSigner = errors.New("record signed by an unknown key")
	ErrBadSignature  = errors.New("invalid record signature")
)

func normalizeAlg(alg string) (string, error) {
	for _, a := range []string{SigEd25519, SigMLDSA65, SigMLDSA87} {
		if strings.EqualFold(a, alg) {
			return a, nil
		}
	}
	return "", fmt.Errorf("unsupported signature algorithm %q (supported: %s, %s, %s)", alg, SigEd25519, SigMLDSA65, SigMLDSA87)
}

func mldsaParams(alg string) mldsa.Parameters {
	if alg == SigMLDSA87 {
		return mldsa.MLDSA87()
	}
	return mldsa.MLDSA65()
}

func sigKeyID(alg string, pub []byte) []byte {
	h := sha256.New()
	h.Write([]byte(sigKIDLabel))
	h.Write([]byte(alg))
	h.Write(pub)
	return h.Sum(nil)[:kidSize]
}

// VerifyKey verifies record signatures.
type VerifyKey struct {
	alg string
	kid []byte
	raw []byte
	ed  ed25519.PublicKey
	ml  *mldsa.PublicKey
}

// KeyID returns the 16 hex character identifier of the key.
func (k *VerifyKey) KeyID() string { return hex.EncodeToString(k.kid) }

// Algorithm returns the signature algorithm.
func (k *VerifyKey) Algorithm() string { return k.alg }

func newVerifyKey(alg string, raw []byte) (*VerifyKey, error) {
	alg, err := normalizeAlg(alg)
	if err != nil {
		return nil, err
	}
	k := &VerifyKey{alg: alg, kid: sigKeyID(alg, raw), raw: append([]byte(nil), raw...)}
	if alg == SigEd25519 {
		if len(raw) != ed25519.PublicKeySize {
			return nil, errors.New("invalid Ed25519 public key")
		}
		k.ed = ed25519.PublicKey(k.raw)
		return k, nil
	}
	if k.ml, err = mldsa.NewPublicKey(mldsaParams(alg), raw); err != nil {
		return nil, fmt.Errorf("invalid %s public key: %w", alg, err)
	}
	return k, nil
}

// MarshalPEM serializes the verification key.
func (k *VerifyKey) MarshalPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:    VerifyKeyPEMType,
		Headers: map[string]string{pemHeaderAlg: k.alg, pemHeaderKID: k.KeyID()},
		Bytes:   k.raw,
	})
}

// ParseVerifyKey parses a PEM encoded verification key.
func ParseVerifyKey(data []byte) (*VerifyKey, error) {
	block, err := decodePEM(data, VerifyKeyPEMType)
	if err != nil {
		return nil, err
	}
	k, err := newVerifyKey(block.Headers[pemHeaderAlg], block.Bytes)
	if err != nil {
		return nil, err
	}
	return k, checkKeyIDHeader(block.Headers, k.KeyID())
}

func (k *VerifyKey) verify(msg, sig []byte) bool {
	if k.ed != nil {
		return ed25519.Verify(k.ed, msg, sig)
	}
	return mldsa.Verify(k.ml, msg, sig, &mldsa.Options{Context: mldsaContext}) == nil
}

// SigningKey signs records.
type SigningKey struct {
	pub    *VerifyKey
	seed   []byte
	signer crypto.Signer
}

// GenerateSigningKey creates a signing key pair.
func GenerateSigningKey(alg string) (*SigningKey, error) {
	alg, err := normalizeAlg(alg)
	if err != nil {
		return nil, err
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	return newSigningKey(alg, seed)
}

func newSigningKey(alg string, seed []byte) (*SigningKey, error) {
	if len(seed) != 32 {
		return nil, errors.New("invalid signing key seed")
	}
	var signer crypto.Signer
	var pub []byte
	if alg == SigEd25519 {
		sk := ed25519.NewKeyFromSeed(seed)
		signer, pub = sk, sk.Public().(ed25519.PublicKey)
	} else {
		sk, err := mldsa.NewPrivateKey(mldsaParams(alg), seed)
		if err != nil {
			return nil, err
		}
		signer, pub = sk, sk.PublicKey().Bytes()
	}
	vk, err := newVerifyKey(alg, pub)
	if err != nil {
		return nil, err
	}
	return &SigningKey{pub: vk, seed: append([]byte(nil), seed...), signer: signer}, nil
}

// Public returns the verification key.
func (k *SigningKey) Public() *VerifyKey { return k.pub }

// KeyID returns the identifier of the key pair.
func (k *SigningKey) KeyID() string { return k.pub.KeyID() }

// MarshalPEM serializes the signing key. The output must be protected like
// any other secret.
func (k *SigningKey) MarshalPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:    SigningKeyPEMType,
		Headers: map[string]string{pemHeaderAlg: k.pub.alg, pemHeaderKID: k.KeyID()},
		Bytes:   k.seed,
	})
}

// ParseSigningKey parses a PEM encoded signing key.
func ParseSigningKey(data []byte) (*SigningKey, error) {
	block, err := decodePEM(data, SigningKeyPEMType)
	if err != nil {
		return nil, err
	}
	alg, err := normalizeAlg(block.Headers[pemHeaderAlg])
	if err != nil {
		return nil, err
	}
	k, err := newSigningKey(alg, block.Bytes)
	if err != nil {
		return nil, err
	}
	return k, checkKeyIDHeader(block.Headers, k.KeyID())
}

// Entry is one encrypted value of a record.
type Entry struct {
	Scope    string
	Position string
	Key      string
	Token    string
}

// Manifest lists what a record signature covers.
type Manifest struct {
	Signal   string
	RecordID []byte
	TraceID  []byte
	SpanID   []byte
	Entries  []Entry
	// WrappedKeys maps DEK IDs to wrapped-key attribute values.
	WrappedKeys map[string]string
}

// digest canonicalizes the manifest. Keys are normalized so that a
// signature survives backends that sanitize attribute names.
func (m Manifest) digest() []byte {
	entries := make([]Entry, len(m.Entries))
	for i, e := range m.Entries {
		e.Key = NormalizeKey(e.Key)
		entries[i] = e
	}
	slices.SortFunc(entries, func(a, b Entry) int {
		return strings.Compare(a.Scope+"\x00"+a.Position+"\x00"+a.Key+"\x00"+a.Token, b.Scope+"\x00"+b.Position+"\x00"+b.Key+"\x00"+b.Token)
	})
	ids := make([]string, 0, len(m.WrappedKeys))
	for id := range m.WrappedKeys {
		ids = append(ids, id)
	}
	slices.Sort(ids)

	var buf bytes.Buffer
	put := func(b []byte) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(b)))
		buf.Write(l[:])
		buf.Write(b)
	}
	put([]byte(recordLabel))
	put([]byte(m.Signal))
	put(m.RecordID)
	put(m.TraceID)
	put(m.SpanID)
	put(binary.BigEndian.AppendUint32(nil, uint32(len(entries))))
	for _, e := range entries {
		put([]byte(e.Scope))
		put([]byte(e.Position))
		put([]byte(e.Key))
		put([]byte(e.Token))
	}
	put(binary.BigEndian.AppendUint32(nil, uint32(len(ids))))
	for _, id := range ids {
		put([]byte(id))
		put([]byte(m.WrappedKeys[id]))
	}
	sum := sha256.Sum256(buf.Bytes())
	return sum[:]
}

// Sign returns the value of the signature attribute for a manifest:
// "<key-id>.<base64url(signature)>".
func (k *SigningKey) Sign(m Manifest) (string, error) {
	var opts crypto.SignerOpts = crypto.Hash(0)
	if k.pub.alg != SigEd25519 {
		opts = &mldsa.Options{Context: mldsaContext}
	}
	sig, err := k.signer.Sign(rand.Reader, m.digest(), opts)
	if err != nil {
		return "", err
	}
	return k.KeyID() + "." + b64.EncodeToString(sig), nil
}

// Verifier checks record signatures against pinned verification keys.
type Verifier struct {
	keys map[string]*VerifyKey
}

// NewVerifier builds a verifier.
func NewVerifier(keys ...*VerifyKey) *Verifier {
	v := &Verifier{keys: make(map[string]*VerifyKey, len(keys))}
	for _, k := range keys {
		v.keys[k.KeyID()] = k
	}
	return v
}

// Len returns the number of pinned keys.
func (v *Verifier) Len() int {
	if v == nil {
		return 0
	}
	return len(v.keys)
}

// Verify checks a signature attribute value against a manifest and returns
// the ID of the signing key.
func (v *Verifier) Verify(m Manifest, sigValue string) (string, error) {
	kid, encoded, ok := strings.Cut(sigValue, ".")
	if !ok {
		return "", ErrBadSignature
	}
	k, ok := v.keys[kid]
	if !ok {
		return kid, ErrUnknownSigner
	}
	sig, err := b64.DecodeString(encoded)
	if err != nil || !k.verify(m.digest(), sig) {
		return kid, ErrBadSignature
	}
	return kid, nil
}
