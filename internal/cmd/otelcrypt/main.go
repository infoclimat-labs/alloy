// Command otelcrypt manages the keys of the otelcol.processor.encryption
// component and decrypts telemetry exported from a backend.
//
//	otelcrypt keygen        -private control.key -public control.pub [-kem MLKEM768-X25519]
//	otelcrypt keygen        -signing -private alloy-signing.key -public alloy-signing.pub [-alg Ed25519]
//	otelcrypt pubkey        -key control.key
//	otelcrypt inspect       -in trace.json
//	otelcrypt decrypt       -key control.key -reason "ticket 42" [-verify-key alloy-signing.pub -require-signature]
//	otelcrypt audit-verify  -in otelcrypt-audit.jsonl
//
// Decryption is meant to run on a workstation that holds the private keys,
// outside the telemetry pipeline. It only depends on the Go standard library.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
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
  keygen        generate a recipient key pair, or a signing key pair with -signing
  pubkey        print the public key of a private key
  inspect       list the wrapped keys and recipients found in a document
  decrypt       decrypt an exported OTLP JSON or Loki document
  audit-verify  check the hash chain of an audit trail

Run "otelcrypt <command> -h" for the flags of a command.
`

const defaultAuditLog = "otelcrypt-audit.jsonl"

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
	case "audit-verify":
		return auditVerify(args[1:], stdout, stderr)
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
	signing := fs.Bool("signing", false, "generate a record signing key pair instead of a recipient key pair")
	alg := fs.String("alg", envelope.SigEd25519, "signature algorithm with -signing: Ed25519, ML-DSA-65, ML-DSA-87")
	privPath := fs.String("private", "", "file to write the private key to (mode 0600, required)")
	pubPath := fs.String("public", "", "file to write the public key to (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *privPath == "" {
		return errors.New("keygen: -private is required")
	}

	var privPEM, pubPEM []byte
	var desc, kid string
	if *signing {
		k, err := envelope.GenerateSigningKey(*alg)
		if err != nil {
			return err
		}
		privPEM, pubPEM, desc, kid = k.MarshalPEM(), k.Public().MarshalPEM(), k.Public().Algorithm()+" signing", k.KeyID()
	} else {
		suite, err := envelope.ParseSuite(*kem, *kdf, *aead)
		if err != nil {
			return err
		}
		k, err := envelope.GenerateKey(suite)
		if err != nil {
			return err
		}
		if privPEM, err = k.MarshalPEM(); err != nil {
			return err
		}
		pubPEM, desc, kid = k.Public().MarshalPEM(), suite.String(), k.KeyID()
	}
	if err := writeNew(*privPath, privPEM, 0o600); err != nil {
		return err
	}
	var err error
	if *pubPath == "" {
		_, err = stdout.Write(pubPEM)
	} else {
		err = writeNew(*pubPath, pubPEM, 0o644)
	}
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stderr, "generated %s key %s\n", desc, kid)
	return nil
}

// writeNew refuses to overwrite or follow an existing file, so a key or a
// clear text export never lands somewhere unexpected.
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
	keyPath := fs.String("key", "", "private key file, recipient or signing (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" {
		return errors.New("pubkey: -key is required")
	}
	data, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	if sk, err := envelope.ParseSigningKey(data); err == nil {
		_, err = stdout.Write(sk.Public().MarshalPEM())
		return err
	}
	k, err := envelope.ParsePrivateKey(data)
	if err != nil {
		return fmt.Errorf("%s: %w", *keyPath, err)
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

func loadVerifyKey(path string) (*envelope.VerifyKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := envelope.ParseVerifyKey(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return k, nil
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// readInput reads at most maxSize bytes.
func readInput(path string, stdin io.Reader, maxSize int64) ([]byte, error) {
	r := stdin
	if path != "" && path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	data, err := io.ReadAll(io.LimitReader(r, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("input larger than %d bytes, raise -max-size if expected", maxSize)
	}
	return data, nil
}

const defaultMaxSize = 256 << 20

func inspect(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := newFlagSet("inspect", stderr)
	in := fs.String("in", "-", "input document")
	maxSize := fs.Int64("max-size", defaultMaxSize, "maximum input size in bytes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	doc, err := readInput(*in, stdin, *maxSize)
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
	VerifyKeys  []string  `json:"verify_keys,omitempty"`
	Format      string    `json:"format"`
	Records     int       `json:"records"`
	Decrypted   int       `json:"decrypted"`
	Failed      int       `json:"failed"`
	Verified    int       `json:"signatures_verified"`
	Unsigned    int       `json:"unsigned_records"`
	Invalid     int       `json:"invalid_signatures"`
	TraceIDs    []string  `json:"trace_ids,omitempty"`
	// ClearTextReleased is true when the run is about to release decrypted
	// values: the record is written before the output.
	ClearTextReleased bool `json:"clear_text_released"`
	// Prev is the SHA-256 of the previous line of the trail, which makes
	// edits and deletions detectable with audit-verify.
	Prev string `json:"prev"`
}

func decryptCmd(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := newFlagSet("decrypt", stderr)
	var keyPaths, verifyPaths stringList
	fs.Var(&keyPaths, "key", "private key file (repeatable)")
	fs.Var(&verifyPaths, "verify-key", "verification key of the signing Alloy instances (repeatable)")
	requireSig := fs.Bool("require-signature", false, "only decrypt records with a valid signature from a -verify-key")
	in := fs.String("in", "-", "input document (OTLP JSON traces or logs, Tempo API response, Loki query response)")
	out := fs.String("out", "-", "output file, created with mode 0600; must not exist")
	reason := fs.String("reason", "", "justification recorded in the audit trail (required)")
	auditLog := fs.String("audit-log", envOr("OTELCRYPT_AUDIT_LOG", defaultAuditLog), "audit trail file (JSON lines, hash chained); default from $OTELCRYPT_AUDIT_LOG")
	auditURL := fs.String("audit-url", os.Getenv("OTELCRYPT_AUDIT_URL"), "also POST each audit record to this URL (for example a remote append-only log); the output is withheld if it fails; default from $OTELCRYPT_AUDIT_URL")
	keep := fs.Bool("keep-key-attributes", false, "keep the encryption.* attributes in the output")
	maxSize := fs.Int64("max-size", defaultMaxSize, "maximum input size in bytes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(keyPaths) == 0 {
		return errors.New("decrypt: at least one -key is required")
	}
	if strings.TrimSpace(*reason) == "" {
		return errors.New("decrypt: -reason is required: decryption must be justified")
	}
	if *auditLog == "" {
		return errors.New("decrypt: -audit-log can't be empty: every decryption is audited")
	}
	if *requireSig && len(verifyPaths) == 0 {
		return errors.New("decrypt: -require-signature needs at least one -verify-key")
	}

	var keys []*envelope.PrivateKey
	for _, p := range keyPaths {
		k, err := loadPrivateKey(p)
		if err != nil {
			return err
		}
		keys = append(keys, k)
	}
	var vkeys []*envelope.VerifyKey
	var vkids []string
	for _, p := range verifyPaths {
		k, err := loadVerifyKey(p)
		if err != nil {
			return err
		}
		vkeys = append(vkeys, k)
		vkids = append(vkids, k.KeyID())
	}
	kr := envelope.NewKeyring(keys...)

	doc, err := readInput(*in, stdin, *maxSize)
	if err != nil {
		return err
	}
	opts := decrypt.Options{KeepKeyAttributes: *keep, RequireSignature: *requireSig}
	if len(vkeys) > 0 {
		opts.Verifier = envelope.NewVerifier(vkeys...)
	}
	clear, rep, err := decrypt.New(kr, opts).Decrypt(doc)
	if err != nil {
		return err
	}

	// The audit record is written before any clear text is released.
	sum := sha256.Sum256(doc)
	rec := auditRecord{
		Time:              time.Now().UTC(),
		User:              currentUser(),
		Host:              hostname(),
		Reason:            *reason,
		Input:             *in,
		InputSHA256:       hex.EncodeToString(sum[:]),
		Keys:              slices.Sorted(slices.Values(kr.KeyIDs())),
		VerifyKeys:        vkids,
		Format:            rep.Format,
		Records:           rep.Records,
		Decrypted:         rep.Decrypted,
		Failed:            rep.Failed,
		Verified:          rep.Verified,
		Unsigned:          rep.Unsigned,
		Invalid:           rep.Invalid,
		TraceIDs:          rep.TraceIDs,
		ClearTextReleased: rep.Decrypted > 0,
	}
	line, err := appendAudit(*auditLog, rec)
	if err != nil {
		return fmt.Errorf("writing audit record (output withheld): %w", err)
	}
	if *auditURL != "" {
		if err := postAudit(*auditURL, line); err != nil {
			return fmt.Errorf("sending audit record to %s (output withheld): %w", *auditURL, err)
		}
	}

	if *out == "" || *out == "-" {
		_, err = stdout.Write(clear)
	} else {
		err = writeNew(*out, clear, 0o600)
	}
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(stderr, "decrypted %d value(s) in %d record(s), %d failure(s) [%s]", rep.Decrypted, rep.Records, rep.Failed, rep.Format)
	if opts.Verifier != nil {
		_, _ = fmt.Fprintf(stderr, "; signatures: %d verified, %d unsigned, %d invalid", rep.Verified, rep.Unsigned, rep.Invalid)
	}
	_, _ = fmt.Fprintln(stderr)
	for _, e := range rep.Errors {
		_, _ = fmt.Fprintln(stderr, "  -", e)
	}
	if rep.Failed > 0 || rep.Invalid > 0 {
		return exitError(3)
	}
	return nil
}

// lastLineHash returns the SHA-256 of the last line of the trail.
func lastLineHash(path string) (string, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	data = bytes.TrimRight(data, "\n")
	if len(data) == 0 {
		return "", nil
	}
	last := data[bytes.LastIndexByte(data, '\n')+1:]
	sum := sha256.Sum256(last)
	return hex.EncodeToString(sum[:]), nil
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// appendAudit appends a record to the trail under an exclusive lock, so
// concurrent runs can't fork the hash chain, and returns the written line.
func appendAudit(path string, rec auditRecord) ([]byte, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := lockFile(f); err != nil {
		return nil, fmt.Errorf("locking audit trail: %w", err)
	}
	defer func() { _ = unlockFile(f) }()

	prev, err := lastLineHash(path)
	if err != nil {
		return nil, err
	}
	rec.Prev = prev
	line, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return nil, err
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	return line, nil
}

// postAudit sends an audit record to a remote collector.
func postAudit(url string, line []byte) error {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(line))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("unexpected status %s", resp.Status)
	}
	return nil
}

func auditVerify(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("audit-verify", stderr)
	in := fs.String("in", envOr("OTELCRYPT_AUDIT_LOG", defaultAuditLog), "audit trail file")
	head := fs.String("head", "", "expected head hash, recorded elsewhere, to detect a truncated trail")
	if err := fs.Parse(args); err != nil {
		return err
	}
	f, err := os.Open(*in)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
	prev, n := "", 0
	for sc.Scan() {
		line := sc.Bytes()
		n++
		var rec auditRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return fmt.Errorf("line %d: %w", n, err)
		}
		if rec.Prev != prev {
			return fmt.Errorf("line %d: hash chain broken: the trail was edited or truncated before this line", n)
		}
		sum := sha256.Sum256(line)
		prev = hex.EncodeToString(sum[:])
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if *head != "" && *head != prev {
		return fmt.Errorf("head %s doesn't match the expected head %s: records were removed from the end of the trail", prev, *head)
	}
	_, _ = fmt.Fprintf(stdout, "%d record(s), hash chain intact, head %s\n", n, prev)
	if *head == "" {
		_, _ = fmt.Fprintln(stdout, "note: keep the head hash outside this machine to detect truncation (-head)")
	}
	return nil
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
