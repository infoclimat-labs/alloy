package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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

// encryptedDoc builds an OTLP JSON trace with one value encrypted for pubPEM,
// signed with signer when it isn't nil.
func encryptedDoc(t *testing.T, pubPEM []byte, signer *envelope.SigningKey) []byte {
	t.Helper()
	pk, err := envelope.ParsePublicKey(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := envelope.NewSealer([]*envelope.PublicKey{pk}, envelope.SealerOptions{})
	dek, _ := s.Current()
	tid, sid, rid := bytes.Repeat([]byte{7}, 16), bytes.Repeat([]byte{8}, 8), bytes.Repeat([]byte{9}, 16)
	const key = "gen_ai.input.messages"
	tok, err := dek.Seal(envelope.EncodeString(key, "secret prompt"), envelope.Context{
		Signal: "traces", Scope: "span", Key: key, RecordID: rid, TraceID: tid, SpanID: sid,
	})
	if err != nil {
		t.Fatal(err)
	}
	attrs := []any{
		map[string]any{"key": key, "value": map[string]any{"stringValue": tok}},
		map[string]any{"key": dek.AttributeKey(), "value": map[string]any{"stringValue": dek.WrappedKey()}},
		map[string]any{"key": envelope.RecordIDAttr, "value": map[string]any{"stringValue": hex.EncodeToString(rid)}},
	}
	if signer != nil {
		meta := envelope.MetaDigest(envelope.RecordMeta{Keys: []string{envelope.MetaKey("span", "", key)}})
		sig, err := signer.Sign(envelope.Manifest{
			Signal: "traces", RecordID: rid, TraceID: tid, SpanID: sid,
			Entries:     []envelope.Entry{{Scope: "span", Key: key, Token: tok}},
			WrappedKeys: map[string]string{dek.ID(): dek.WrappedKey()},
			Meta:        meta,
		})
		if err != nil {
			t.Fatal(err)
		}
		attrs = append(attrs,
			map[string]any{"key": envelope.SignatureAttr, "value": map[string]any{"stringValue": sig}},
			map[string]any{"key": envelope.MetaAttr, "value": map[string]any{"stringValue": hex.EncodeToString(meta)}})
	}
	doc, _ := json.Marshal(map[string]any{"resourceSpans": []any{map[string]any{"scopeSpans": []any{map[string]any{"spans": []any{map[string]any{
		"traceId": hex.EncodeToString(tid), "spanId": hex.EncodeToString(sid), "attributes": attrs,
	}}}}}}})
	return doc
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
	pubFromPriv, _, err := runCLI(t, "", "pubkey", "-key", priv)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, _ := os.ReadFile(pub)
	if pubFromPriv != string(pubPEM) {
		t.Fatal("pubkey output differs from the generated public key")
	}

	doc := string(encryptedDoc(t, pubPEM, nil))
	pk, _ := envelope.ParsePublicKey(pubPEM)

	inv, _, err := runCLI(t, doc, "inspect")
	if err != nil || !strings.Contains(inv, pk.KeyID()) || !strings.Contains(inv, `"tokens": 1`) {
		t.Fatalf("inspect: %v\n%s", err, inv)
	}

	audit := filepath.Join(dir, "audit", "trail.jsonl")
	if _, _, err := runCLI(t, doc, "decrypt", "-key", priv, "-audit-log", audit); err == nil {
		t.Fatal("decrypt without -reason accepted")
	}
	if _, _, err := runCLI(t, doc, "decrypt", "-key", priv, "-reason", "x", "-audit-log", ""); err == nil {
		t.Fatal("decrypt without audit trail accepted")
	}

	outFile := filepath.Join(dir, "clear.json")
	_, stderr, err := runCLI(t, doc, "decrypt", "-key", priv, "-reason", "contrôle d'emploi #42", "-audit-log", audit, "-out", outFile)
	if err != nil {
		t.Fatalf("decrypt: %v\n%s", err, stderr)
	}
	clear, _ := os.ReadFile(outFile)
	if !strings.Contains(string(clear), "secret prompt") || strings.Contains(string(clear), envelope.TokenPrefix) {
		t.Fatalf("output not decrypted:\n%s", clear)
	}
	if fi, _ := os.Stat(outFile); fi.Mode().Perm() != 0o600 {
		t.Fatalf("output mode %v", fi.Mode())
	}
	if _, _, err := runCLI(t, doc, "decrypt", "-key", priv, "-reason", "again", "-audit-log", audit, "-out", outFile); err == nil {
		t.Fatal("existing output file overwritten")
	}

	trail, _ := os.ReadFile(audit)
	lines := strings.Split(strings.TrimSpace(string(trail)), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 audit records, got %d", len(lines))
	}
	var rec auditRecord
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Reason != "contrôle d'emploi #42" || rec.Decrypted != 1 || rec.Keys[0] != pk.KeyID() || len(rec.InputSHA256) != 64 ||
		rec.Prev != "" || len(rec.TraceIDs) != 1 || !rec.ClearTextReleased {

		t.Fatalf("audit record = %+v", rec)
	}

	out, _, err := runCLI(t, "", "audit-verify", "-in", audit)
	if err != nil || !strings.Contains(out, "2 record(s), hash chain intact") {
		t.Fatalf("audit-verify: %v %s", err, out)
	}
	headHash := strings.Fields(strings.SplitN(out, "head ", 2)[1])[0]
	// Truncating the trail is detected when the head is known.
	if err := os.WriteFile(audit+".trunc", []byte(lines[0]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCLI(t, "", "audit-verify", "-in", audit+".trunc", "-head", headHash); err == nil {
		t.Fatal("truncated trail not detected")
	}
	// Tampering with the first record breaks the chain.
	tampered := strings.Replace(string(trail), "contrôle d'emploi #42", "routine check", 1)
	if err := os.WriteFile(audit, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCLI(t, "", "audit-verify", "-in", audit); err == nil || !strings.Contains(err.Error(), "hash chain broken") {
		t.Fatalf("tampering not detected: %v", err)
	}

	// A key that can't open the document yields exit status 3.
	other := filepath.Join(dir, "other.key")
	if _, _, err := runCLI(t, "", "keygen", "-kem", "X25519", "-private", other); err != nil {
		t.Fatal(err)
	}
	_, _, err = runCLI(t, doc, "decrypt", "-key", other, "-reason", "test", "-audit-log", filepath.Join(dir, "a2.jsonl"))
	var ee exitError
	if !errors.As(err, &ee) || ee != 3 {
		t.Fatalf("want exit status 3, got %v", err)
	}

	if _, _, err := runCLI(t, doc, "decrypt", "-key", priv, "-reason", "x", "-audit-log", filepath.Join(dir, "a3.jsonl"), "-max-size", "10"); err == nil {
		t.Fatal("input size limit not enforced")
	}
}

func TestSignatures(t *testing.T) {
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "control.key"), filepath.Join(dir, "control.pub")
	sigPriv, sigPub := filepath.Join(dir, "alloy.key"), filepath.Join(dir, "alloy.pub")
	if _, _, err := runCLI(t, "", "keygen", "-kem", "X25519", "-private", priv, "-public", pub); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCLI(t, "", "keygen", "-signing", "-private", sigPriv, "-public", sigPub); err != nil {
		t.Fatal(err)
	}
	if out, _, err := runCLI(t, "", "pubkey", "-key", sigPriv); err != nil || !strings.Contains(out, envelope.VerifyKeyPEMType) {
		t.Fatalf("pubkey of signing key: %v %s", err, out)
	}
	pubPEM, _ := os.ReadFile(pub)
	sigPEM, _ := os.ReadFile(sigPriv)
	signer, err := envelope.ParseSigningKey(sigPEM)
	if err != nil {
		t.Fatal(err)
	}
	audit := filepath.Join(dir, "audit.jsonl")
	args := func(extra ...string) []string {
		return append([]string{"decrypt", "-key", priv, "-reason", "r", "-audit-log", audit, "-verify-key", sigPub}, extra...)
	}

	signed := string(encryptedDoc(t, pubPEM, signer))
	_, stderr, err := runCLI(t, signed, args("-require-signature")...)
	if err != nil || !strings.Contains(stderr, "1 verified, 0 unsigned, 0 invalid") {
		t.Fatalf("signed document: %v %s", err, stderr)
	}

	unsigned := string(encryptedDoc(t, pubPEM, nil))
	out, stderr, err := runCLI(t, unsigned, args("-require-signature")...)
	if err == nil || strings.Contains(out, "secret prompt") || !strings.Contains(stderr, "not signed") {
		t.Fatalf("unsigned document decrypted under -require-signature: %v %s", err, stderr)
	}
	if _, stderr, err := runCLI(t, unsigned, args()...); err != nil || !strings.Contains(stderr, "1 unsigned") {
		t.Fatalf("unsigned document without -require-signature: %v %s", err, stderr)
	}

	// Forged: a valid signature over another record.
	other := encryptedDoc(t, pubPEM, signer)
	var a, b map[string]any
	_ = json.Unmarshal([]byte(signed), &a)
	_ = json.Unmarshal(other, &b)
	spanA := a["resourceSpans"].([]any)[0].(map[string]any)["scopeSpans"].([]any)[0].(map[string]any)["spans"].([]any)[0].(map[string]any)
	spanB := b["resourceSpans"].([]any)[0].(map[string]any)["scopeSpans"].([]any)[0].(map[string]any)["spans"].([]any)[0].(map[string]any)
	spanA["attributes"].([]any)[3] = spanB["attributes"].([]any)[3]
	forged, _ := json.Marshal(a)
	out, _, err = runCLI(t, string(forged), args("-require-signature")...)
	if err == nil || strings.Contains(out, "secret prompt") {
		t.Fatalf("record with a foreign signature decrypted: %v", err)
	}
	if _, _, err := runCLI(t, signed, "decrypt", "-key", priv, "-reason", "r", "-audit-log", audit, "-require-signature"); err == nil {
		t.Fatal("-require-signature without -verify-key accepted")
	}
}

func TestRemoteAudit(t *testing.T) {
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "k"), filepath.Join(dir, "p")
	if _, _, err := runCLI(t, "", "keygen", "-kem", "X25519", "-private", priv, "-public", pub); err != nil {
		t.Fatal(err)
	}
	pubPEM, _ := os.ReadFile(pub)
	doc := string(encryptedDoc(t, pubPEM, nil))

	var received [][]byte
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		received = append(received, b)
	}))
	defer ok.Close()
	out, _, err := runCLI(t, doc, "decrypt", "-key", priv, "-reason", "r", "-audit-log", filepath.Join(dir, "a"), "-audit-url", ok.URL)
	if err != nil || len(received) != 1 || !strings.Contains(string(received[0]), `"reason":"r"`) || !strings.Contains(out, "secret prompt") {
		t.Fatalf("remote audit: %v %d", err, len(received))
	}

	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failing.Close()
	out, _, err = runCLI(t, doc, "decrypt", "-key", priv, "-reason", "r", "-audit-log", filepath.Join(dir, "a"), "-audit-url", failing.URL)
	if err == nil || strings.Contains(out, "secret prompt") {
		t.Fatal("output released although the remote audit failed")
	}
}

func TestUsage(t *testing.T) {
	if _, _, err := runCLI(t, ""); err == nil {
		t.Fatal("no command accepted")
	}
	if _, _, err := runCLI(t, "", "frobnicate"); err == nil {
		t.Fatal("unknown command accepted")
	}
	if out, _, err := runCLI(t, "", "help"); err != nil || !strings.Contains(out, "audit-verify") {
		t.Fatal("help")
	}
}
