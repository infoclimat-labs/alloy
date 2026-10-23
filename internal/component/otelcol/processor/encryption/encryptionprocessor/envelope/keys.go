// Package envelope implements the cryptographic core of the encryption
// processor: recipient key handling, HPKE (RFC 9180) wrapping of data
// encryption keys, AES-256-GCM sealing of individual telemetry values and the
// versioned token format that carries them.
//
// The package only depends on the Go standard library so that it can be
// reused by out-of-pipeline tooling (key generation, decryption) without
// pulling in the OpenTelemetry Collector.
package envelope

import (
	"crypto/hpke"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// PEM block types used for serialized keys.
const (
	PublicKeyPEMType  = "OTEL ENCRYPTION PUBLIC KEY"
	PrivateKeyPEMType = "OTEL ENCRYPTION PRIVATE KEY"
)

const (
	pemHeaderKEM  = "KEM"
	pemHeaderKDF  = "KDF"
	pemHeaderAEAD = "AEAD"
	pemHeaderKID  = "Key-ID"

	kidLabel = "otel-encryption/v1 kid"
	kidSize  = 8 // bytes, rendered as 16 hex characters
)

// Suite identifies an HPKE cipher suite by its IANA code points.
type Suite struct {
	KEM  uint16
	KDF  uint16
	AEAD uint16
}

// HPKE code points supported by this package. They match the IANA HPKE
// registry and the identifiers accepted by crypto/hpke.
const (
	KEMP256HKDFSHA256   uint16 = 0x0010
	KEMX25519HKDFSHA256 uint16 = 0x0020
	KEMMLKEM768         uint16 = 0x0041
	KEMMLKEM1024        uint16 = 0x0042
	KEMMLKEM768P256     uint16 = 0x0050
	KEMMLKEM1024P384    uint16 = 0x0051
	KEMMLKEM768X25519   uint16 = 0x647a

	KDFHKDFSHA256 uint16 = 0x0001
	KDFHKDFSHA384 uint16 = 0x0002
	KDFHKDFSHA512 uint16 = 0x0003

	AEADAES128GCM        uint16 = 0x0001
	AEADAES256GCM        uint16 = 0x0002
	AEADChaCha20Poly1305 uint16 = 0x0003
)

// DefaultSuite is the suite used when none is specified: the post-quantum
// hybrid MLKEM768-X25519 KEM (X-Wing), HKDF-SHA256 and AES-256-GCM.
//
// A hybrid KEM is the default because encrypted telemetry is typically
// retained for months or years, which makes it a target for
// "harvest now, decrypt later" attacks.
var DefaultSuite = Suite{KEM: KEMMLKEM768X25519, KDF: KDFHKDFSHA256, AEAD: AEADAES256GCM}

var kemNames = map[uint16]string{
	KEMP256HKDFSHA256:   "P256",
	KEMX25519HKDFSHA256: "X25519",
	KEMMLKEM768:         "MLKEM768",
	KEMMLKEM1024:        "MLKEM1024",
	KEMMLKEM768P256:     "MLKEM768-P256",
	KEMMLKEM1024P384:    "MLKEM1024-P384",
	KEMMLKEM768X25519:   "MLKEM768-X25519",
}

var kdfNames = map[uint16]string{
	KDFHKDFSHA256: "HKDF-SHA256",
	KDFHKDFSHA384: "HKDF-SHA384",
	KDFHKDFSHA512: "HKDF-SHA512",
}

var aeadNames = map[uint16]string{
	AEADAES128GCM:        "AES-128-GCM",
	AEADAES256GCM:        "AES-256-GCM",
	AEADChaCha20Poly1305: "ChaCha20-Poly1305",
}

func lookupName(names map[uint16]string, kind, name string) (uint16, error) {
	for id, n := range names {
		if strings.EqualFold(n, name) {
			return id, nil
		}
	}
	valid := make([]string, 0, len(names))
	for _, n := range names {
		valid = append(valid, n)
	}
	return 0, fmt.Errorf("unsupported %s %q (supported: %s)", kind, name, strings.Join(valid, ", "))
}

// ParseSuite builds a Suite from human-readable algorithm names, for example
// ("MLKEM768-X25519", "HKDF-SHA256", "AES-256-GCM"). Empty names select the
// corresponding DefaultSuite algorithm.
func ParseSuite(kem, kdf, aead string) (Suite, error) {
	s := DefaultSuite
	var err error
	if kem != "" {
		if s.KEM, err = lookupName(kemNames, "KEM", kem); err != nil {
			return Suite{}, err
		}
	}
	if kdf != "" {
		if s.KDF, err = lookupName(kdfNames, "KDF", kdf); err != nil {
			return Suite{}, err
		}
	}
	if aead != "" {
		if s.AEAD, err = lookupName(aeadNames, "AEAD", aead); err != nil {
			return Suite{}, err
		}
	}
	return s, s.validate()
}

func (s Suite) validate() error {
	if _, ok := kemNames[s.KEM]; !ok {
		return fmt.Errorf("unsupported KEM 0x%04x", s.KEM)
	}
	if _, ok := kdfNames[s.KDF]; !ok {
		return fmt.Errorf("unsupported KDF 0x%04x", s.KDF)
	}
	if _, ok := aeadNames[s.AEAD]; !ok {
		return fmt.Errorf("unsupported AEAD 0x%04x", s.AEAD)
	}
	return nil
}

// String renders the suite with its algorithm names.
func (s Suite) String() string {
	return fmt.Sprintf("%s/%s/%s", kemNames[s.KEM], kdfNames[s.KDF], aeadNames[s.AEAD])
}

func (s Suite) primitives() (hpke.KEM, hpke.KDF, hpke.AEAD, error) {
	if err := s.validate(); err != nil {
		return nil, nil, nil, err
	}
	kem, err := hpke.NewKEM(s.KEM)
	if err != nil {
		return nil, nil, nil, err
	}
	kdf, err := hpke.NewKDF(s.KDF)
	if err != nil {
		return nil, nil, nil, err
	}
	aead, err := hpke.NewAEAD(s.AEAD)
	if err != nil {
		return nil, nil, nil, err
	}
	return kem, kdf, aead, nil
}

func (s Suite) bytes() []byte {
	b := make([]byte, 6)
	binary.BigEndian.PutUint16(b[0:], s.KEM)
	binary.BigEndian.PutUint16(b[2:], s.KDF)
	binary.BigEndian.PutUint16(b[4:], s.AEAD)
	return b
}

// computeKeyID derives a stable identifier from the suite and the serialized
// public key, so that a key ID never needs to be configured by hand and can
// be recomputed by anyone holding the public key.
func computeKeyID(s Suite, pub []byte) []byte {
	h := sha256.New()
	h.Write([]byte(kidLabel))
	h.Write(s.bytes())
	h.Write(pub)
	return h.Sum(nil)[:kidSize]
}

// PublicKey is a recipient key used to wrap data encryption keys.
type PublicKey struct {
	suite Suite
	kid   []byte
	raw   []byte
	pk    hpke.PublicKey
	kdf   hpke.KDF
	aead  hpke.AEAD
}

// KeyID returns the 16 hex character identifier of the key.
func (p *PublicKey) KeyID() string { return hex.EncodeToString(p.kid) }

// Suite returns the HPKE suite the key is bound to.
func (p *PublicKey) Suite() Suite { return p.suite }

// MarshalPEM serializes the public key.
func (p *PublicKey) MarshalPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:    PublicKeyPEMType,
		Headers: suiteHeaders(p.suite, p.KeyID()),
		Bytes:   p.raw,
	})
}

// NewPublicKey builds a public key from its raw HPKE serialization.
func NewPublicKey(s Suite, raw []byte) (*PublicKey, error) {
	kem, kdf, aead, err := s.primitives()
	if err != nil {
		return nil, err
	}
	pk, err := kem.NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid %s public key: %w", kemNames[s.KEM], err)
	}
	return &PublicKey{
		suite: s,
		kid:   computeKeyID(s, raw),
		raw:   append([]byte(nil), raw...),
		pk:    pk,
		kdf:   kdf,
		aead:  aead,
	}, nil
}

// ParsePublicKey parses a PEM encoded public key produced by MarshalPEM.
func ParsePublicKey(data []byte) (*PublicKey, error) {
	block, err := decodePEM(data, PublicKeyPEMType)
	if err != nil {
		return nil, err
	}
	s, err := suiteFromHeaders(block.Headers)
	if err != nil {
		return nil, err
	}
	pub, err := NewPublicKey(s, block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := checkKeyIDHeader(block.Headers, pub.KeyID()); err != nil {
		return nil, err
	}
	return pub, nil
}

// PrivateKey is a recipient private key used to unwrap data encryption keys.
type PrivateKey struct {
	pub *PublicKey
	sk  hpke.PrivateKey
}

// GenerateKey creates a new recipient key pair for the given suite.
func GenerateKey(s Suite) (*PrivateKey, error) {
	kem, _, _, err := s.primitives()
	if err != nil {
		return nil, err
	}
	sk, err := kem.GenerateKey()
	if err != nil {
		return nil, err
	}
	return newPrivateKey(s, sk)
}

func newPrivateKey(s Suite, sk hpke.PrivateKey) (*PrivateKey, error) {
	pub, err := NewPublicKey(s, sk.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	return &PrivateKey{pub: pub, sk: sk}, nil
}

// Public returns the public half of the key pair.
func (k *PrivateKey) Public() *PublicKey { return k.pub }

// KeyID returns the identifier of the key pair.
func (k *PrivateKey) KeyID() string { return k.pub.KeyID() }

// MarshalPEM serializes the private key. The output must be protected like
// any other secret.
func (k *PrivateKey) MarshalPEM() ([]byte, error) {
	raw, err := k.sk.Bytes()
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:    PrivateKeyPEMType,
		Headers: suiteHeaders(k.pub.suite, k.KeyID()),
		Bytes:   raw,
	}), nil
}

// ParsePrivateKey parses a PEM encoded private key produced by MarshalPEM.
func ParsePrivateKey(data []byte) (*PrivateKey, error) {
	block, err := decodePEM(data, PrivateKeyPEMType)
	if err != nil {
		return nil, err
	}
	s, err := suiteFromHeaders(block.Headers)
	if err != nil {
		return nil, err
	}
	kem, _, _, err := s.primitives()
	if err != nil {
		return nil, err
	}
	sk, err := kem.NewPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid %s private key: %w", kemNames[s.KEM], err)
	}
	k, err := newPrivateKey(s, sk)
	if err != nil {
		return nil, err
	}
	if err := checkKeyIDHeader(block.Headers, k.KeyID()); err != nil {
		return nil, err
	}
	return k, nil
}

func decodePEM(data []byte, wantType string) (*pem.Block, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if block.Type != wantType {
		return nil, fmt.Errorf("unexpected PEM block type %q, want %q", block.Type, wantType)
	}
	return block, nil
}

func suiteHeaders(s Suite, kid string) map[string]string {
	return map[string]string{
		pemHeaderKEM:  kemNames[s.KEM],
		pemHeaderKDF:  kdfNames[s.KDF],
		pemHeaderAEAD: aeadNames[s.AEAD],
		pemHeaderKID:  kid,
	}
}

func suiteFromHeaders(h map[string]string) (Suite, error) {
	if h[pemHeaderKEM] == "" {
		return Suite{}, errors.New("PEM block is missing the KEM header")
	}
	return ParseSuite(h[pemHeaderKEM], h[pemHeaderKDF], h[pemHeaderAEAD])
}

func checkKeyIDHeader(h map[string]string, kid string) error {
	if want, ok := h[pemHeaderKID]; ok && !strings.EqualFold(want, kid) {
		return fmt.Errorf("key ID header %q does not match the key material (%s)", want, kid)
	}
	return nil
}
