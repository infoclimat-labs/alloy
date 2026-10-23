package envelope

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

var allSuites = []Suite{
	DefaultSuite,
	{KEM: KEMX25519HKDFSHA256, KDF: KDFHKDFSHA256, AEAD: AEADAES256GCM},
	{KEM: KEMP256HKDFSHA256, KDF: KDFHKDFSHA256, AEAD: AEADAES256GCM},
	{KEM: KEMMLKEM768P256, KDF: KDFHKDFSHA256, AEAD: AEADAES256GCM},
	{KEM: KEMMLKEM1024P384, KDF: KDFHKDFSHA384, AEAD: AEADAES256GCM},
	{KEM: KEMMLKEM768, KDF: KDFHKDFSHA256, AEAD: AEADChaCha20Poly1305},
	{KEM: KEMMLKEM1024, KDF: KDFHKDFSHA512, AEAD: AEADAES128GCM},
}

var testCtx = Context{
	Signal:   "traces",
	Scope:    "span",
	Key:      "gen_ai.input.messages",
	RecordID: bytes.Repeat([]byte{0xef}, 16),
	TraceID:  bytes.Repeat([]byte{0xab}, 16),
	SpanID:   bytes.Repeat([]byte{0xcd}, 8),
}

func mustKey(t testing.TB, s Suite) *PrivateKey {
	t.Helper()
	k, err := GenerateKey(s)
	if err != nil {
		t.Fatalf("GenerateKey(%v): %v", s, err)
	}
	return k
}

func mustSealer(t testing.TB, opts SealerOptions, pubs ...*PublicKey) *Sealer {
	t.Helper()
	s, err := NewSealer(pubs, opts)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRoundTripAllSuites(t *testing.T) {
	for _, suite := range allSuites {
		t.Run(suite.String(), func(t *testing.T) {
			priv := mustKey(t, suite)
			dek, err := mustSealer(t, SealerOptions{}, priv.Public()).Current()
			if err != nil {
				t.Fatal(err)
			}
			pt := EncodeString("k", `[{"role":"user","parts":[{"type":"text","content":"Bonjour"}]}]`)
			tok, err := dek.Seal(pt, testCtx)
			if err != nil {
				t.Fatal(err)
			}
			if !IsToken(tok) {
				t.Fatalf("not a token: %s", tok)
			}

			opened, err := NewKeyring(priv).Unwrap(dek.ID(), dek.WrappedKey())
			if err != nil {
				t.Fatal(err)
			}
			got, err := opened.Open(tok, testCtx)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, pt) {
				t.Fatalf("plaintext mismatch: %q", got)
			}
		})
	}
}

func TestPEMRoundTrip(t *testing.T) {
	for _, suite := range allSuites {
		t.Run(suite.String(), func(t *testing.T) {
			priv := mustKey(t, suite)
			privPEM, err := priv.MarshalPEM()
			if err != nil {
				t.Fatal(err)
			}
			priv2, err := ParsePrivateKey(privPEM)
			if err != nil {
				t.Fatal(err)
			}
			pub2, err := ParsePublicKey(priv.Public().MarshalPEM())
			if err != nil {
				t.Fatal(err)
			}
			if priv2.KeyID() != priv.KeyID() || pub2.KeyID() != priv.KeyID() {
				t.Fatalf("key IDs differ: %s %s %s", priv.KeyID(), priv2.KeyID(), pub2.KeyID())
			}
			if pub2.Suite() != suite {
				t.Fatalf("suite mismatch: %v", pub2.Suite())
			}

			// A DEK wrapped for the re-parsed public key opens with the re-parsed private key.
			dek, err := mustSealer(t, SealerOptions{}, pub2).Current()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NewKeyring(priv2).Unwrap(dek.ID(), dek.WrappedKey()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestParseKeyErrors(t *testing.T) {
	priv := mustKey(t, DefaultSuite)
	pubPEM := priv.Public().MarshalPEM()

	if _, err := ParsePrivateKey(pubPEM); err == nil {
		t.Error("public key accepted as private key")
	}
	if _, err := ParsePublicKey([]byte("garbage")); err == nil {
		t.Error("garbage accepted")
	}
	tampered := strings.Replace(string(pubPEM), "Key-ID: "+priv.KeyID(), "Key-ID: 0000000000000000", 1)
	if _, err := ParsePublicKey([]byte(tampered)); err == nil {
		t.Error("key ID mismatch not detected")
	}
	if _, err := ParseSuite("RSA", "", ""); err == nil {
		t.Error("unknown KEM accepted")
	}
}

func TestContextBinding(t *testing.T) {
	priv := mustKey(t, DefaultSuite)
	dek, err := mustSealer(t, SealerOptions{}, priv.Public()).Current()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := dek.Seal(EncodeString("k", "secret"), testCtx)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := NewKeyring(priv).Unwrap(dek.ID(), dek.WrappedKey())
	if err != nil {
		t.Fatal(err)
	}

	mutations := map[string]func(c *Context){
		"key":     func(c *Context) { c.Key = "gen_ai.output.messages" },
		"scope":   func(c *Context) { c.Scope = "span_event" },
		"signal":  func(c *Context) { c.Signal = "logs" },
		"trace":   func(c *Context) { c.TraceID = bytes.Repeat([]byte{1}, 16) },
		"span":    func(c *Context) { c.SpanID = nil },
		"record":  func(c *Context) { c.RecordID = bytes.Repeat([]byte{1}, 16) },
		"event":   func(c *Context) { c.Position = "1/gen_ai.choice" },
		"shifted": func(c *Context) { c.Key, c.Scope = "", "span"+c.Key },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			c := testCtx
			mutate(&c)
			if _, err := opened.Open(tok, c); !errors.Is(err, ErrAuthentication) {
				t.Fatalf("want ErrAuthentication, got %v", err)
			}
		})
	}
}

func TestNormalizedKeyBinding(t *testing.T) {
	priv := mustKey(t, DefaultSuite)
	dek, err := mustSealer(t, SealerOptions{}, priv.Public()).Current()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := dek.Seal(EncodeString("k", "secret"), testCtx)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := NewKeyring(priv).Unwrap(dek.ID(), dek.WrappedKey())
	if err != nil {
		t.Fatal(err)
	}
	c := testCtx
	c.Key = "gen_ai_input_messages" // as stored by Loki
	if _, err := opened.Open(tok, c); err != nil {
		t.Fatalf("sanitized key should decrypt: %v", err)
	}
	if NormalizeKey("encryption.dek."+dek.ID()) != "encryption_dek_"+dek.ID() {
		t.Fatal("DEK ID does not survive label sanitization")
	}
}

func TestTamperedToken(t *testing.T) {
	priv := mustKey(t, DefaultSuite)
	dek, err := mustSealer(t, SealerOptions{}, priv.Public()).Current()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := dek.Seal(EncodeString("k", "secret"), testCtx)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := NewKeyring(priv).Unwrap(dek.ID(), dek.WrappedKey())
	if err != nil {
		t.Fatal(err)
	}

	id, sealed, err := ParseToken(tok)
	if err != nil {
		t.Fatal(err)
	}
	sealed[len(sealed)-1] ^= 1
	bad := TokenPrefix + id + ":" + b64.EncodeToString(sealed)
	if _, err := opened.Open(bad, testCtx); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("want ErrAuthentication, got %v", err)
	}

	other, err := mustSealer(t, SealerOptions{}, priv.Public()).Current()
	if err != nil {
		t.Fatal(err)
	}
	tok2, err := other.Seal(EncodeString("k", "secret"), testCtx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := opened.Open(tok2, testCtx); !errors.Is(err, ErrDEKMismatch) {
		t.Fatalf("want ErrDEKMismatch, got %v", err)
	}

	for _, malformed := range []string{"enc:v1:", "enc:v1:short:abc", "enc:v1:000000000000000000:!!!", "plain"} {
		if _, err := opened.Open(malformed, testCtx); err == nil {
			t.Errorf("malformed token %q accepted", malformed)
		}
	}
}

func TestWrappedKeyIntegrity(t *testing.T) {
	priv := mustKey(t, DefaultSuite)
	dek, err := mustSealer(t, SealerOptions{}, priv.Public()).Current()
	if err != nil {
		t.Fatal(err)
	}
	kr := NewKeyring(priv)

	// Wrong DEK ID for the wrapped value.
	if _, err := kr.Unwrap("000000000000000000", dek.WrappedKey()); !errors.Is(err, ErrDEKMismatch) {
		t.Fatalf("want ErrDEKMismatch, got %v", err)
	}

	// Flipping a ciphertext bit in the blob fails HPKE authentication.
	blob, err := b64.DecodeString(dek.WrappedKey())
	if err != nil {
		t.Fatal(err)
	}
	blob[len(blob)-1] ^= 1
	if _, err := kr.Unwrap("", b64.EncodeToString(blob)); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("want ErrAuthentication, got %v", err)
	}

	// The header is authenticated through the HPKE info: changing the
	// advertised AEAD of a valid blob must not decrypt.
	blob, _ = b64.DecodeString(dek.WrappedKey())
	blob[8] = byte(AEADChaCha20Poly1305)
	if _, err := kr.Unwrap("", b64.EncodeToString(blob)); err == nil {
		t.Fatal("tampered header accepted")
	}

	// Unknown recipient.
	if _, err := NewKeyring(mustKey(t, DefaultSuite)).Unwrap(dek.ID(), dek.WrappedKey()); !errors.Is(err, ErrNoMatchingKey) {
		t.Fatalf("want ErrNoMatchingKey, got %v", err)
	}
}

func TestMultipleRecipients(t *testing.T) {
	a := mustKey(t, DefaultSuite)
	b := mustKey(t, Suite{KEM: KEMX25519HKDFSHA256, KDF: KDFHKDFSHA256, AEAD: AEADAES256GCM})
	sealer := mustSealer(t, SealerOptions{}, a.Public(), b.Public())
	dek, err := sealer.Current()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := dek.Seal(EncodeString("k", "for both"), testCtx)
	if err != nil {
		t.Fatal(err)
	}

	ids, err := WrappedKeyRecipients(dek.WrappedKey())
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != a.KeyID() || ids[1] != b.KeyID() {
		t.Fatalf("recipients = %v", ids)
	}

	for _, k := range []*PrivateKey{a, b} {
		opened, err := NewKeyring(k).Unwrap(dek.ID(), dek.WrappedKey())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := opened.Open(tok, testCtx); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := NewSealer([]*PublicKey{a.Public(), a.Public()}, SealerOptions{}); err == nil {
		t.Fatal("duplicate recipient accepted")
	}
	if _, err := NewSealer(nil, SealerOptions{}); err == nil {
		t.Fatal("empty recipients accepted")
	}
}

func TestRotation(t *testing.T) {
	priv := mustKey(t, Suite{KEM: KEMX25519HKDFSHA256, KDF: KDFHKDFSHA256, AEAD: AEADAES256GCM})
	now := time.Unix(0, 0)
	s := mustSealer(t, SealerOptions{MaxUses: 3, MaxAge: time.Minute, Now: func() time.Time { return now }}, priv.Public())

	first, _ := s.Current()
	for range 3 {
		d, err := s.Current()
		if err != nil {
			t.Fatal(err)
		}
		if d != first {
			t.Fatal("rotated before reaching the use limit")
		}
		if _, err := d.Seal(EncodeString("k", "x"), testCtx); err != nil {
			t.Fatal(err)
		}
	}
	second, _ := s.Current()
	if second == first {
		t.Fatal("not rotated after the use limit")
	}

	now = now.Add(time.Minute)
	third, _ := s.Current()
	if third == second {
		t.Fatal("not rotated after the age limit")
	}
	if s.Rotations() != 3 {
		t.Fatalf("rotations = %d", s.Rotations())
	}
	if first.ID() == second.ID() || second.ID() == third.ID() {
		t.Fatal("DEK IDs are not unique")
	}
}

func TestConcurrentSealing(t *testing.T) {
	priv := mustKey(t, Suite{KEM: KEMX25519HKDFSHA256, KDF: KDFHKDFSHA256, AEAD: AEADAES256GCM})
	s := mustSealer(t, SealerOptions{MaxUses: 50}, priv.Public())
	kr := NewKeyring(priv)

	type result struct{ wrapped, tok string }
	results := make(chan result, 800)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				d, err := s.Current()
				if err != nil {
					t.Error(err)
					return
				}
				tok, err := d.Seal(EncodeString("k", "v"), testCtx)
				if err != nil {
					t.Error(err)
					return
				}
				results <- result{d.WrappedKey(), tok}
			}
		})
	}
	wg.Wait()
	close(results)

	deks := map[string]*DEK{}
	for r := range results {
		d, ok := deks[r.wrapped]
		if !ok {
			var err error
			if d, err = kr.Unwrap("", r.wrapped); err != nil {
				t.Fatal(err)
			}
			deks[r.wrapped] = d
		}
		if _, err := d.Open(r.tok, testCtx); err != nil {
			t.Fatal(err)
		}
	}
	if len(deks) < 2 {
		t.Fatalf("expected rotations under load, got %d DEKs", len(deks))
	}
}

func TestValueEncoding(t *testing.T) {
	v, err := DecodeValue(EncodeString("gen_ai.prompt", "héllo"))
	if err != nil || v.Kind != KindString || v.Key != "gen_ai.prompt" || string(v.Payload) != "héllo" {
		t.Fatalf("string: %+v %v", v, err)
	}
	enc, err := EncodeJSON("args", []byte(`{"a":[1,2]}`))
	if err != nil {
		t.Fatal(err)
	}
	v, err = DecodeValue(enc)
	if err != nil || v.Kind != KindJSON || v.Key != "args" || string(v.Payload) != `{"a":[1,2]}` {
		t.Fatalf("json: %+v %v", v, err)
	}
	if err := v.CheckKey("args", true); err != nil {
		t.Fatal(err)
	}
	if err := v.CheckKey("other", true); err == nil {
		t.Fatal("key mismatch not detected")
	}
	enc, _ = EncodeValue(KindString, "gen_ai.input.messages", nil)
	v, _ = DecodeValue(enc)
	if v.CheckKey("gen_ai_input_messages", false) != nil || v.CheckKey("gen_ai_input_messages", true) == nil {
		t.Fatal("normalized key check")
	}
	if _, err := EncodeJSON("k", []byte("{")); err == nil {
		t.Fatal("invalid JSON accepted")
	}
	for _, bad := range [][]byte{nil, []byte("x"), {KindString}, {KindString, 10, 'a'}} {
		if _, err := DecodeValue(bad); err == nil {
			t.Fatalf("malformed plaintext %q accepted", bad)
		}
	}
}

func TestSealLimit(t *testing.T) {
	var c counter
	c.n = MaxSealsPerDEK - 1
	if !c.TryAdd(MaxSealsPerDEK) || c.TryAdd(MaxSealsPerDEK) {
		t.Fatal("hard seal limit not enforced")
	}
	priv := mustKey(t, Suite{KEM: KEMX25519HKDFSHA256, KDF: KDFHKDFSHA256, AEAD: AEADAES256GCM})
	d, _ := mustSealer(t, SealerOptions{}, priv.Public()).Current()
	d.uses.n = MaxSealsPerDEK
	if _, err := d.Seal(EncodeString("k", "x"), testCtx); !errors.Is(err, ErrDEKExhausted) {
		t.Fatalf("want ErrDEKExhausted, got %v", err)
	}
}

func TestUnwrapTriesEveryMatchingBlob(t *testing.T) {
	priv := mustKey(t, Suite{KEM: KEMX25519HKDFSHA256, KDF: KDFHKDFSHA256, AEAD: AEADAES256GCM})
	d, _ := mustSealer(t, SealerOptions{}, priv.Public()).Current()
	// A bogus blob for the same key ID placed before the genuine one.
	blob, _ := b64.DecodeString(d.WrappedKey())
	bogus := append([]byte(nil), blob...)
	bogus[len(bogus)-1] ^= 1
	wrapped := b64.EncodeToString(bogus) + "." + d.WrappedKey()
	if _, err := NewKeyring(priv).Unwrap("", wrapped); err != nil {
		t.Fatalf("genuine blob hidden by a bogus one: %v", err)
	}
}

func FuzzOpen(f *testing.F) {
	priv := mustKey(f, Suite{KEM: KEMX25519HKDFSHA256, KDF: KDFHKDFSHA256, AEAD: AEADAES256GCM})
	dek, err := mustSealer(f, SealerOptions{}, priv.Public()).Current()
	if err != nil {
		f.Fatal(err)
	}
	tok, _ := dek.Seal(EncodeString("k", "seed"), testCtx)
	f.Add(tok)
	f.Add("enc:v1:")
	f.Add(dek.WrappedKey())
	kr := NewKeyring(priv)
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = dek.Open(s, testCtx)
		_, _ = kr.Unwrap("", s)
		_, _ = WrappedKeyRecipients(s)
	})
}

func BenchmarkSeal(b *testing.B) {
	priv := mustKey(b, DefaultSuite)
	dek, err := mustSealer(b, SealerOptions{}, priv.Public()).Current()
	if err != nil {
		b.Fatal(err)
	}
	for _, size := range []int{256, 4096, 65536} {
		pt := EncodeString("k", strings.Repeat("a", size))
		b.Run(byteSize(size), func(b *testing.B) {
			b.SetBytes(int64(len(pt)))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := dek.Seal(pt, testCtx); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkRotation(b *testing.B) {
	for _, suite := range allSuites[:3] {
		priv := mustKey(b, suite)
		s := mustSealer(b, SealerOptions{MaxUses: 1}, priv.Public())
		b.Run(suite.String(), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				d, err := s.Current()
				if err != nil {
					b.Fatal(err)
				}
				d.uses.Add(1)
			}
		})
	}
}

func byteSize(n int) string {
	if n >= 1<<10 {
		return fmt.Sprintf("%dKiB", n>>10)
	}
	return fmt.Sprintf("%dB", n)
}
