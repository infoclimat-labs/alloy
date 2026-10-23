package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grafana/alloy/internal/component/otelcol/processor/encryption/encryptionprocessor/envelope"
)

func runCLI(t *testing.T, stdin string, args ...string) (string, string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	err := run(args, strings.NewReader(stdin), &out, &errOut)
	return out.String(), errOut.String(), err
}

func TestKeygenAndDecrypt(t *testing.T) {
	dir := t.TempDir()
	priv := filepath.Join(dir, "control.key")
	pub := filepath.Join(dir, "control.pub")

	if _, _, err := runCLI(t, "", "keygen", "-kem", "X25519", "-private", priv, "-public", pub); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(priv); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode: %v %v", fi.Mode(), err)
	}
	if _, _, err := runCLI(t, "", "keygen", "-private", priv); err == nil {
		t.Fatal("existing private key overwritten")
	}

	// pubkey reproduces the public key file.
	pubFromPriv, _, err := runCLI(t, "", "pubkey", "-key", priv)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, _ := os.ReadFile(pub)
	if pubFromPriv != string(pubPEM) {
		t.Fatal("pubkey output differs from the generated public key")
	}

	// Encrypt a value for the generated key, as the processor would.
	pk, err := envelope.ParsePublicKey(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := envelope.NewSealer([]*envelope.PublicKey{pk}, envelope.SealerOptions{})
	dek, _ := s.Current()
	tid, sid := bytes.Repeat([]byte{7}, 16), bytes.Repeat([]byte{8}, 8)
	tok, _ := dek.Seal(envelope.EncodeString("secret prompt"), envelope.Context{
		Signal: "traces", Scope: "span", Key: "gen_ai.input.messages", TraceID: tid, SpanID: sid,
	})
	doc, _ := json.Marshal(map[string]any{"resourceSpans": []any{map[string]any{"scopeSpans": []any{map[string]any{"spans": []any{map[string]any{
		"traceId": hex.EncodeToString(tid),
		"spanId":  hex.EncodeToString(sid),
		"attributes": []any{
			map[string]any{"key": "gen_ai.input.messages", "value": map[string]any{"stringValue": tok}},
			map[string]any{"key": dek.AttributeKey(), "value": map[string]any{"stringValue": dek.WrappedKey()}},
		},
	}}}}}}})

	inv, _, err := runCLI(t, string(doc), "inspect")
	if err != nil || !strings.Contains(inv, pk.KeyID()) || !strings.Contains(inv, `"tokens": 1`) {
		t.Fatalf("inspect: %v\n%s", err, inv)
	}

	if _, _, err := runCLI(t, string(doc), "decrypt", "-key", priv); err == nil {
		t.Fatal("decrypt without -reason accepted")
	}

	audit := filepath.Join(dir, "audit.jsonl")
	out, stderr, err := runCLI(t, string(doc), "decrypt", "-key", priv, "-reason", "contrôle d'emploi #42", "-audit-log", audit)
	if err != nil {
		t.Fatalf("decrypt: %v\n%s", err, stderr)
	}
	if !strings.Contains(out, "secret prompt") || strings.Contains(out, envelope.TokenPrefix) {
		t.Fatalf("output not decrypted:\n%s", out)
	}
	line, _ := os.ReadFile(audit)
	var rec auditRecord
	if err := json.Unmarshal(line, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Reason != "contrôle d'emploi #42" || rec.Decrypted != 1 || len(rec.Keys) != 1 || rec.Keys[0] != pk.KeyID() || len(rec.InputSHA256) != 64 {
		t.Fatalf("audit record = %+v", rec)
	}

	// A key that can't open the document yields exit status 3.
	other := filepath.Join(dir, "other.key")
	if _, _, err := runCLI(t, "", "keygen", "-kem", "X25519", "-private", other); err != nil {
		t.Fatal(err)
	}
	_, _, err = runCLI(t, string(doc), "decrypt", "-key", other, "-reason", "test")
	var ee exitError
	if !errors.As(err, &ee) || ee != 3 {
		t.Fatalf("want exit status 3, got %v", err)
	}
}

func TestUsage(t *testing.T) {
	if _, _, err := runCLI(t, ""); err == nil {
		t.Fatal("no command accepted")
	}
	if _, _, err := runCLI(t, "", "frobnicate"); err == nil {
		t.Fatal("unknown command accepted")
	}
	if out, _, err := runCLI(t, "", "help"); err != nil || !strings.Contains(out, "decrypt") {
		t.Fatal("help")
	}
}
