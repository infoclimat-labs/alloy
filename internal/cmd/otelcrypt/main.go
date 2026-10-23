// Command otelcrypt manages the keys of the otelcol.processor.encryption
// component and decrypts telemetry exported from a backend.
//
//	otelcrypt keygen  -private control.key -public control.pub [-kem MLKEM768-X25519]
//	otelcrypt pubkey  -key control.key
//	otelcrypt inspect -in trace.json
//	otelcrypt decrypt -key control.key -reason "ticket 42" [-in trace.json] [-out clear.json] [-audit-log audit.jsonl]
//
// Decryption is meant to run on a workstation that holds the private keys,
// outside the telemetry pipeline. It only depends on the Go standard library.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"slices"
	"strings"
	"time"

	"github.com/grafana/alloy/internal/component/otelcol/processor/encryption/encryptionprocessor/decrypt"
	"github.com/grafana/alloy/internal/component/otelcol/processor/encryption/encryptionprocessor/envelope"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "otelcrypt:", err)
		var ee exitError
		if errors.As(err, &ee) {
			os.Exit(int(ee))
		}
		os.Exit(1)
	}
}

type exitError int

func (e exitError) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

const usage = `usage: otelcrypt <command> [flags]

commands:
  keygen    generate a recipient key pair
  pubkey    print the public key of a private key
  inspect   list the wrapped keys and recipients found in a document
  decrypt   decrypt an exported OTLP JSON or Loki document

Run "otelcrypt <command> -h" for the flags of a command.
`

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return exitError(2)
	}
	switch args[0] {
	case "keygen":
		return keygen(args[1:], stdout, stderr)
	case "pubkey":
		return pubkey(args[1:], stdout, stderr)
	case "inspect":
		return inspect(args[1:], stdin, stdout, stderr)
	case "decrypt":
		return decryptCmd(args[1:], stdin, stdout, stderr)
	case "-h", "--help", "help":
		_, _ = fmt.Fprint(stdout, usage)
		return nil
	default:
		_, _ = fmt.Fprint(stderr, usage)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func keygen(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("keygen", stderr)
	kem := fs.String("kem", "MLKEM768-X25519", "KEM: MLKEM768-X25519, MLKEM768-P256, MLKEM1024-P384, MLKEM768, MLKEM1024, X25519, P256")
	kdf := fs.String("kdf", "HKDF-SHA256", "KDF: HKDF-SHA256, HKDF-SHA384, HKDF-SHA512")
	aead := fs.String("aead", "AES-256-GCM", "AEAD: AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305")
	privPath := fs.String("private", "", "file to write the private key to (mode 0600, required)")
	pubPath := fs.String("public", "", "file to write the public key to (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *privPath == "" {
		return errors.New("keygen: -private is required")
	}
	suite, err := envelope.ParseSuite(*kem, *kdf, *aead)
	if err != nil {
		return err
	}
	k, err := envelope.GenerateKey(suite)
	if err != nil {
		return err
	}
	privPEM, err := k.MarshalPEM()
	if err != nil {
		return err
	}
	if err := writeNew(*privPath, privPEM, 0o600); err != nil {
		return err
	}
	pubPEM := k.Public().MarshalPEM()
	if *pubPath == "" {
		_, err = stdout.Write(pubPEM)
	} else {
		err = writeNew(*pubPath, pubPEM, 0o644)
	}
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stderr, "generated %s key %s\n", suite, k.KeyID())
	return nil
}

// writeNew refuses to overwrite an existing file, so a key is never lost by
// mistake.
func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func pubkey(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("pubkey", stderr)
	keyPath := fs.String("key", "", "private key file (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" {
		return errors.New("pubkey: -key is required")
	}
	k, err := loadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	_, err = stdout.Write(k.Public().MarshalPEM())
	return err
}

func loadPrivateKey(path string) (*envelope.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := envelope.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return k, nil
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func readInput(path string, stdin io.Reader) ([]byte, error) {
	if path == "" || path == "-" {
		return io.ReadAll(stdin)
	}
	return os.ReadFile(path)
}

func inspect(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := newFlagSet("inspect", stderr)
	in := fs.String("in", "-", "input document")
	if err := fs.Parse(args); err != nil {
		return err
	}
	doc, err := readInput(*in, stdin)
	if err != nil {
		return err
	}
	inv, err := decrypt.Inspect(doc)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(inv)
}

type auditRecord struct {
	Time        time.Time `json:"time"`
	User        string    `json:"user"`
	Host        string    `json:"host"`
	Reason      string    `json:"reason"`
	Input       string    `json:"input"`
	InputSHA256 string    `json:"input_sha256"`
	Keys        []string  `json:"keys"`
	Format      string    `json:"format"`
	Decrypted   int       `json:"decrypted"`
	Failed      int       `json:"failed"`
}

func decryptCmd(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := newFlagSet("decrypt", stderr)
	var keyPaths stringList
	fs.Var(&keyPaths, "key", "private key file (repeatable)")
	in := fs.String("in", "-", "input document (OTLP JSON traces or logs, Tempo API response, Loki query response)")
	out := fs.String("out", "-", "output file")
	reason := fs.String("reason", "", "justification recorded in the audit trail (required)")
	auditLog := fs.String("audit-log", "", "append a JSON audit record to this file")
	keep := fs.Bool("keep-key-attributes", false, "keep the encryption.dek.* attributes in the output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(keyPaths) == 0 {
		return errors.New("decrypt: at least one -key is required")
	}
	if strings.TrimSpace(*reason) == "" {
		return errors.New("decrypt: -reason is required: decryption must be justified")
	}

	var keys []*envelope.PrivateKey
	for _, p := range keyPaths {
		k, err := loadPrivateKey(p)
		if err != nil {
			return err
		}
		keys = append(keys, k)
	}
	kr := envelope.NewKeyring(keys...)

	doc, err := readInput(*in, stdin)
	if err != nil {
		return err
	}
	clear, rep, err := decrypt.New(kr, decrypt.Options{KeepKeyAttributes: *keep}).Decrypt(doc)
	if err != nil {
		return err
	}

	sum := sha256.Sum256(doc)
	rec := auditRecord{
		Time:        time.Now().UTC(),
		User:        currentUser(),
		Host:        hostname(),
		Reason:      *reason,
		Input:       *in,
		InputSHA256: hex.EncodeToString(sum[:]),
		Keys:        slices.Sorted(slices.Values(kr.KeyIDs())),
		Format:      rep.Format,
		Decrypted:   rep.Decrypted,
		Failed:      rep.Failed,
	}
	if *auditLog != "" {
		if err := appendAudit(*auditLog, rec); err != nil {
			return fmt.Errorf("writing audit record (output withheld): %w", err)
		}
	}

	if *out == "" || *out == "-" {
		_, err = stdout.Write(clear)
	} else {
		err = os.WriteFile(*out, clear, 0o600)
	}
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(stderr, "decrypted %d value(s), %d failure(s) [%s]\n", rep.Decrypted, rep.Failed, rep.Format)
	for _, e := range rep.Errors {
		_, _ = fmt.Fprintln(stderr, "  -", e)
	}
	if rep.Failed > 0 {
		return exitError(3)
	}
	return nil
}

func appendAudit(path string, rec auditRecord) error {
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func currentUser() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return os.Getenv("USER")
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}
