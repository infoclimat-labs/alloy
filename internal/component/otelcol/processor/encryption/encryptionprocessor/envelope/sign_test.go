package envelope

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func testManifest() Manifest {
	return Manifest{
		Signal:   "traces",
		RecordID: bytes.Repeat([]byte{1}, 16),
		TraceID:  bytes.Repeat([]byte{2}, 16),
		SpanID:   bytes.Repeat([]byte{3}, 8),
		Entries: []Entry{
			{Scope: "span", Key: "gen_ai.input.messages", Token: "enc:v1:aa:1"},
			{Scope: "span_event", Position: "0/gen_ai.choice", Key: "gen_ai.completion", Token: "enc:v1:aa:2"},
		},
		WrappedKeys: map[string]string{"aa": "wrapped"},
	}
}

func TestSignVerify(t *testing.T) {
	for _, alg := range []string{SigEd25519, SigMLDSA65, SigMLDSA87} {
		t.Run(alg, func(t *testing.T) {
			sk, err := GenerateSigningKey(alg)
			if err != nil {
				t.Fatal(err)
			}
			// PEM round trips.
			sk2, err := ParseSigningKey(sk.MarshalPEM())
			if err != nil {
				t.Fatal(err)
			}
			vk, err := ParseVerifyKey(sk.Public().MarshalPEM())
			if err != nil {
				t.Fatal(err)
			}
			if sk2.KeyID() != sk.KeyID() || vk.KeyID() != sk.KeyID() || vk.Algorithm() != alg {
				t.Fatal("key IDs or algorithm differ after PEM round trip")
			}

			m := testManifest()
			sig, err := sk2.Sign(m)
			if err != nil {
				t.Fatal(err)
			}
			v := NewVerifier(vk)
			if kid, err := v.Verify(m, sig); err != nil || kid != sk.KeyID() {
				t.Fatalf("verify: %s %v", kid, err)
			}

			// Entry order and key sanitization don't matter.
			m2 := testManifest()
			m2.Entries[0], m2.Entries[1] = m2.Entries[1], m2.Entries[0]
			m2.Entries[0].Key = "gen_ai_completion"
			if _, err := v.Verify(m2, sig); err != nil {
				t.Fatalf("canonical form: %v", err)
			}

			tampered := map[string]func(*Manifest){
				"deleted token": func(m *Manifest) { m.Entries = m.Entries[:1] },
				"moved token":   func(m *Manifest) { m.Entries[0].Key = "gen_ai.output.messages" },
				"changed token": func(m *Manifest) { m.Entries[0].Token += "x" },
				"moved event":   func(m *Manifest) { m.Entries[1].Position = "1/gen_ai.choice" },
				"other record":  func(m *Manifest) { m.RecordID = bytes.Repeat([]byte{9}, 16) },
				"other trace":   func(m *Manifest) { m.TraceID = nil },
				"wrapped key":   func(m *Manifest) { m.WrappedKeys["aa"] = "forged" },
				"extra key":     func(m *Manifest) { m.WrappedKeys["bb"] = "x" },
				"signal":        func(m *Manifest) { m.Signal = "logs" },
			}
			for name, mutate := range tampered {
				m := testManifest()
				mutate(&m)
				if _, err := v.Verify(m, sig); !errors.Is(err, ErrBadSignature) {
					t.Errorf("%s: want ErrBadSignature, got %v", name, err)
				}
			}

			other, _ := GenerateSigningKey(alg)
			if _, err := NewVerifier(other.Public()).Verify(m, sig); !errors.Is(err, ErrUnknownSigner) {
				t.Fatalf("want ErrUnknownSigner, got %v", err)
			}
			if _, err := v.Verify(m, "garbage"); !errors.Is(err, ErrBadSignature) {
				t.Fatalf("want ErrBadSignature, got %v", err)
			}
		})
	}
}

func TestSigningKeyErrors(t *testing.T) {
	if _, err := GenerateSigningKey("RSA"); err == nil {
		t.Fatal("unknown algorithm accepted")
	}
	sk, _ := GenerateSigningKey(SigEd25519)
	if _, err := ParseVerifyKey(sk.MarshalPEM()); err == nil {
		t.Fatal("signing key accepted as verification key")
	}
	pemData := strings.Replace(string(sk.Public().MarshalPEM()), sk.KeyID(), "0000000000000000", 1)
	if _, err := ParseVerifyKey([]byte(pemData)); err == nil {
		t.Fatal("key ID mismatch not detected")
	}
}

func BenchmarkSign(b *testing.B) {
	for _, alg := range []string{SigEd25519, SigMLDSA65} {
		sk, _ := GenerateSigningKey(alg)
		m := testManifest()
		b.Run(alg, func(b *testing.B) {
			for b.Loop() {
				if _, err := sk.Sign(m); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
