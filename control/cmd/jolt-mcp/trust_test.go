package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type root struct {
	cert        *x509.Certificate
	key         *ecdsa.PrivateKey
	pem         []byte
	fingerprint string
}

func newRoot(t *testing.T) root {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Jolt Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	sum := sha256.Sum256(der)
	return root{cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), hex.EncodeToString(sum[:])}
}

// controlTower stands in for the Control Tower: a plain-HTTP listener with the
// public root, and an HTTPS one whose certificate the root signed.
func controlTower(t *testing.T, authority root) (publicURL, secureURL string) {
	t.Helper()
	public := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/jolt/ca.pem" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(authority.pem)
	}))
	t.Cleanup(public.Close)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Jolt Control Tower"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, authority.cert, &key.PublicKey, authority.key)
	if err != nil {
		t.Fatal(err)
	}
	secure := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jolt/ca.pem" {
			_, _ = w.Write(authority.pem)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/content") {
			_, _ = io.WriteString(w, "text from node")
			return
		}
		_, _ = io.WriteString(w, `{"items":[]}`)
	}))
	secure.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	secure.StartTLS()
	t.Cleanup(secure.Close)
	return public.URL, secure.URL
}

func TestRunTrustParsesArgumentsAndReportsOutcomes(t *testing.T) {
	// No test may touch the real configuration directory.
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "config"))
	authority := newRoot(t)
	public, _ := controlTower(t, authority)
	file := filepath.Join(t.TempDir(), "ca.pem")
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := runTrust(args, &stdout, &stderr, func(string) string { return "" })
		return code, stdout.String(), stderr.String()
	}
	for name, args := range map[string][]string{
		"url first":  {public, "--fingerprint", authority.fingerprint, "--ca-file", file},
		"url last":   {"--fingerprint", authority.fingerprint, "--ca-file", file, public},
		"url middle": {"--fingerprint", authority.fingerprint, public, "--ca-file", file},
	} {
		_ = os.Remove(file)
		code, stdout, stderr := run(args...)
		if code != 0 || !strings.Contains(stdout, authority.fingerprint) || !strings.Contains(stdout, "(1 root)") || stderr != "" {
			t.Fatalf("%s: code=%d stdout=%q stderr=%q", name, code, stdout, stderr)
		}
	}
	code, stdout, _ := run(public, "--fingerprint", authority.fingerprint, "--ca-file", file)
	if code != 0 || !strings.HasPrefix(stdout, "already trusted") {
		t.Fatalf("again: code=%d stdout=%q", code, stdout)
	}
	_ = os.Remove(file)
	for name, tc := range map[string]struct {
		args []string
		code int
	}{
		"wrong fingerprint": {[]string{public, "--fingerprint", strings.Repeat("00", 32), "--ca-file", file}, 1},
		"no fingerprint":    {[]string{public, "--ca-file", file}, 2},
		"no url":            {[]string{"--fingerprint", authority.fingerprint, "--ca-file", file}, 2},
		"two urls":          {[]string{public, public, "--fingerprint", authority.fingerprint, "--ca-file", file}, 2},
		"unknown flag":      {[]string{public, "--fingerprint", authority.fingerprint, "--nope"}, 2},
	} {
		code, stdout, stderr := run(tc.args...)
		if code != tc.code || stdout != "" || stderr == "" {
			t.Errorf("%s: code=%d stdout=%q stderr=%q", name, code, stdout, stderr)
		}
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("a failed trust left a file behind")
	}
}

func TestCAOptionsPreferTheExplicitFileThenTheDefaultOnlyOnceItExists(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	env := map[string]string{}
	getenv := func(key string) string { return env[key] }
	if got := caOptions(getenv); len(got) != 0 {
		t.Fatal("trust configured before any root was stored")
	}
	env["JOLT_MCP_CA_FILE"] = filepath.Join(home, "missing.pem")
	if got := caOptions(getenv); len(got) != 1 {
		t.Fatal("an explicit file must apply even when missing, so a typo fails loudly")
	}
	delete(env, "JOLT_MCP_CA_FILE")
	defaultFile := mcpDefault(t)
	if err := os.MkdirAll(filepath.Dir(defaultFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(defaultFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := caOptions(getenv); len(got) != 1 {
		t.Fatal("the default file was ignored once it exists")
	}
}

func mcpDefault(t *testing.T) string {
	t.Helper()
	dir, err := os.UserConfigDir()
	if err != nil {
		t.Skip("no user configuration directory")
	}
	return filepath.Join(dir, "jolt-mcp", "ca.pem")
}

func TestBinaryTrustThenServeOverHTTPS(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "jolt-mcp")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v %s", err, output)
	}
	authority := newRoot(t)
	public, secure := controlTower(t, authority)
	home := t.TempDir()
	credential := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(credential, []byte("agent-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, "config"), "JOLT_MCP_CA_FILE=")
	call := func(extra ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.Command(binary)
		cmd.Env = append(append([]string{}, base...), append([]string{"JOLT_MCP_CONTROL_URL=" + secure, "JOLT_MCP_CREDENTIAL_FILE=" + credential}, extra...)...)
		session, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "list", Arguments: map[string]any{"node_id": "n", "mount_id": "m", "path": ""}})
		if err != nil {
			return err
		}
		if result.IsError {
			return os.ErrInvalid
		}
		return nil
	}
	if call() == nil {
		t.Fatal("a Control Tower under an unknown root was reached before trust")
	}
	// The plain-HTTP port, with the fingerprint as the operator would copy it.
	trust := exec.Command(binary, "trust", public, "--fingerprint", strings.ToUpper(strings.Join(pairs(authority.fingerprint), ":")))
	trust.Env = base
	output, err := trust.CombinedOutput()
	if err != nil {
		t.Fatalf("trust: %v %s", err, output)
	}
	if !strings.Contains(string(output), authority.fingerprint) || !strings.Contains(string(output), home) {
		t.Fatalf("trust output: %s", output)
	}
	// No configuration at all: the server finds what trust stored.
	if err := call(); err != nil {
		t.Fatalf("after trust: %v", err)
	}
	// The HTTPS listener serves the root too, and a wrong hash still stores nothing.
	other := exec.Command(binary, "trust", secure, "--fingerprint", strings.Repeat("11", 32), "--ca-file", filepath.Join(home, "other.pem"))
	other.Env = base
	if out, err := other.CombinedOutput(); err == nil || !strings.Contains(string(out), "not the one given") {
		t.Fatalf("wrong hash over https: %v %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(home, "other.pem")); !os.IsNotExist(err) {
		t.Fatal("stored under a wrong hash")
	}
	// An explicit file wins over the default and is the only trust.
	empty := filepath.Join(home, "elsewhere.pem")
	if err := os.WriteFile(empty, []byte("not roots"), 0o600); err != nil {
		t.Fatal(err)
	}
	if call("JOLT_MCP_CA_FILE="+empty) == nil {
		t.Fatal("a broken explicit file fell back to something else")
	}
	if out, err := exec.Command(binary, "unknown").CombinedOutput(); err == nil || !strings.Contains(string(out), "usage") {
		t.Fatalf("unknown subcommand: %v %s", err, out)
	}
}

func pairs(value string) []string {
	var out []string
	for i := 0; i+2 <= len(value); i += 2 {
		out = append(out, value[i:i+2])
	}
	return out
}
