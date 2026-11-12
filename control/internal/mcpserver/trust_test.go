package mcpserver

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
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testRoot struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func (r testRoot) fingerprint() string {
	sum := sha256.Sum256(r.cert.Raw)
	return hex.EncodeToString(sum[:])
}

func newTestRoot(t *testing.T, name string, notBefore, notAfter time.Time, isCA bool) testRoot {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: notBefore, NotAfter: notAfter, IsCA: isCA, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testRoot{cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func validRoot(t *testing.T, name string) testRoot {
	now := time.Now()
	return newTestRoot(t, name, now.Add(-time.Hour), now.Add(24*time.Hour), true)
}

// issue signs a server certificate for 127.0.0.1 under root.
func (r testRoot) issue(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "Jolt Control Tower"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, r.cert, &key.PublicKey, r.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// authority serves roots the way the Control Tower does.
func authority(t *testing.T, current, next []byte) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(currentRootPath, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(current) })
	mux.HandleFunc(nextRootPath, func(w http.ResponseWriter, _ *http.Request) {
		if next == nil {
			http.NotFound(w, nil)
			return
		}
		_, _ = w.Write(next)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func caPath(t *testing.T) string { return filepath.Join(t.TempDir(), "sub", "ca.pem") }

func TestTrustStoresTheRootWhenTheFingerprintMatches(t *testing.T) {
	root := validRoot(t, "Jolt Root")
	server := authority(t, root.pem, nil)
	file := caPath(t)
	// The fingerprint as the Control Tower shows it: upper case, colon-separated.
	shown := strings.ToUpper(strings.Join(splitPairs(root.fingerprint()), ":"))
	result, err := Trust(context.Background(), TrustOptions{URL: server.URL, Fingerprint: shown, CAFile: file})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Added || result.Roots != 1 || result.Fingerprint != root.fingerprint() || result.Subject != "Jolt Root" {
		t.Fatalf("result=%+v", result)
	}
	info, err := os.Stat(file)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode=%v err=%v", info, err)
	}
	if dir, _ := os.Stat(filepath.Dir(file)); dir.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode=%v", dir.Mode().Perm())
	}
	roots, err := LoadRoots(file)
	if err != nil || len(roots) != 1 || !roots[0].Equal(root.cert) {
		t.Fatalf("roots=%v err=%v", roots, err)
	}
}

func splitPairs(value string) []string {
	var out []string
	for i := 0; i+2 <= len(value); i += 2 {
		out = append(out, value[i:i+2])
	}
	return out
}

func TestTrustStoresNothingWhenTheFingerprintDiffers(t *testing.T) {
	served := validRoot(t, "Served")
	other := validRoot(t, "Other")
	server := authority(t, served.pem, nil)
	file := caPath(t)
	_, err := Trust(context.Background(), TrustOptions{URL: server.URL, Fingerprint: other.fingerprint(), CAFile: file})
	if err == nil || !strings.Contains(err.Error(), "not the one given") {
		t.Fatalf("err=%v", err)
	}
	if _, statErr := os.Stat(file); !os.IsNotExist(statErr) {
		t.Fatal("a root whose fingerprint did not match was stored")
	}
	if _, statErr := os.Stat(filepath.Dir(file)); !os.IsNotExist(statErr) {
		t.Fatal("the directory was created before the root was accepted")
	}
}

func TestTrustRefusesWhatIsNotAUsableRoot(t *testing.T) {
	now := time.Now()
	leaf := newTestRoot(t, "Leaf", now.Add(-time.Hour), now.Add(time.Hour), false)
	expired := newTestRoot(t, "Expired", now.Add(-48*time.Hour), now.Add(-time.Hour), true)
	future := newTestRoot(t, "Future", now.Add(72*time.Hour), now.Add(96*time.Hour), true)
	two := validRoot(t, "Two")
	one := validRoot(t, "One")
	// A root whose signature was damaged after it was made.
	damaged := append([]byte{}, one.cert.Raw...)
	damaged[len(damaged)-1] ^= 0x01
	damagedCert, err := x509.ParseCertificate(damaged)
	if err != nil {
		t.Fatal(err)
	}
	damagedSum := sha256.Sum256(damagedCert.Raw)
	damagedPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: damaged})
	// Signed by its own key, but naming another issuer: not self-issued.
	renamed, err := func() (testRoot, error) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return testRoot{}, err
		}
		subject := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Subject"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		issuer := &x509.Certificate{SerialNumber: big.NewInt(8), Subject: pkix.Name{CommonName: "Another issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, err := x509.CreateCertificate(rand.Reader, subject, issuer, &key.PublicKey, key)
		if err != nil {
			return testRoot{}, err
		}
		cert, err := x509.ParseCertificate(der)
		return testRoot{cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, err
	}()
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(one.key)
	cases := map[string]struct {
		body        []byte
		fingerprint string
		want        string
	}{
		"not a CA":               {leaf.pem, leaf.fingerprint(), "not a self-signed root"},
		"expired":                {expired.pem, expired.fingerprint(), "expired"},
		"not valid yet":          {future.pem, future.fingerprint(), "not valid yet"},
		"two certificates":       {append(append([]byte{}, one.pem...), two.pem...), one.fingerprint(), "exactly one PEM certificate"},
		"trailing data":          {append(append([]byte{}, one.pem...), "junk"...), one.fingerprint(), "exactly one PEM certificate"},
		"a private key":          {pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), one.fingerprint(), "exactly one PEM certificate"},
		"not PEM":                {[]byte("<html>captive portal</html>"), one.fingerprint(), "exactly one PEM certificate"},
		"bad self-signature":     {damagedPEM, hex.EncodeToString(damagedSum[:]), "not a self-signed root"},
		"issuer is another name": {renamed.pem, renamed.fingerprint(), "not a self-signed root"},
		"too large":              {append([]byte(strings.Repeat("A", maxRootBytes+1)), one.pem...), one.fingerprint(), "too large"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			server := authority(t, tc.body, nil)
			file := caPath(t)
			_, err := Trust(context.Background(), TrustOptions{URL: server.URL, Fingerprint: tc.fingerprint, CAFile: file})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v, want %q", err, tc.want)
			}
			if _, statErr := os.Stat(file); !os.IsNotExist(statErr) {
				t.Fatal("a refused root was stored")
			}
		})
	}
}

func TestTrustAcceptsAClockSkewOfADayBeforeTheRootStarts(t *testing.T) {
	now := time.Now()
	root := newTestRoot(t, "Fresh", now.Add(30*time.Minute), now.Add(time.Hour), true)
	server := authority(t, root.pem, nil)
	if _, err := Trust(context.Background(), TrustOptions{URL: server.URL, Fingerprint: root.fingerprint(), CAFile: caPath(t)}); err != nil {
		t.Fatalf("a root that starts in half an hour was refused: %v", err)
	}
}

func TestTrustDoesNotFollowRedirectsOrAcceptErrors(t *testing.T) {
	root := validRoot(t, "Root")
	elsewhere := authority(t, root.pem, nil)
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+currentRootPath, http.StatusFound)
	}))
	defer redirect.Close()
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write(root.pem)
	}))
	defer failing.Close()
	for name, url := range map[string]string{"redirect": redirect.URL, "502": failing.URL} {
		file := caPath(t)
		if _, err := Trust(context.Background(), TrustOptions{URL: url, Fingerprint: root.fingerprint(), CAFile: file}); err == nil {
			t.Fatalf("%s: accepted", name)
		}
		if _, err := os.Stat(file); !os.IsNotExist(err) {
			t.Fatalf("%s: stored", name)
		}
	}
}

func TestTrustFetchesTheNextRootAndKeepsTheCurrentOne(t *testing.T) {
	current, next := validRoot(t, "Current"), validRoot(t, "Next")
	server := authority(t, current.pem, next.pem)
	file := caPath(t)
	if _, err := Trust(context.Background(), TrustOptions{URL: server.URL, Fingerprint: current.fingerprint(), CAFile: file}); err != nil {
		t.Fatal(err)
	}
	result, err := Trust(context.Background(), TrustOptions{URL: server.URL, Fingerprint: next.fingerprint(), CAFile: file, Next: true})
	if err != nil || !result.Added || result.Roots != 2 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	roots, err := LoadRoots(file)
	if err != nil || len(roots) != 2 || !roots[0].Equal(current.cert) || !roots[1].Equal(next.cert) {
		t.Fatalf("roots=%v err=%v", roots, err)
	}
	// The next root is not served by the current URL, so the current
	// fingerprint cannot be confused with it.
	if _, err := Trust(context.Background(), TrustOptions{URL: server.URL, Fingerprint: current.fingerprint(), CAFile: file, Next: true}); err == nil {
		t.Fatal("the next root was accepted under the current fingerprint")
	}
}

func TestTrustSaysWhenNoRotationIsUnderWay(t *testing.T) {
	root := validRoot(t, "Root")
	server := authority(t, root.pem, nil)
	_, err := Trust(context.Background(), TrustOptions{URL: server.URL, Fingerprint: root.fingerprint(), CAFile: caPath(t), Next: true})
	if err == nil || !strings.Contains(err.Error(), "rotation") {
		t.Fatalf("err=%v", err)
	}
}

func TestTrustMergesReplacesAndDropsExpiredRoots(t *testing.T) {
	first, second := validRoot(t, "First"), validRoot(t, "Second")
	file := caPath(t)
	run := func(root testRoot, replace bool, now time.Time) (*TrustResult, error) {
		server := authority(t, root.pem, nil)
		return Trust(context.Background(), TrustOptions{URL: server.URL, Fingerprint: root.fingerprint(), CAFile: file, Replace: replace, Now: func() time.Time { return now }})
	}
	now := time.Now()
	if _, err := run(first, false, now); err != nil {
		t.Fatal(err)
	}
	again, err := run(first, false, now)
	if err != nil || again.Added || again.Roots != 1 {
		t.Fatalf("again=%+v err=%v", again, err)
	}
	merged, err := run(second, false, now)
	if err != nil || !merged.Added || merged.Roots != 2 {
		t.Fatalf("merged=%+v err=%v", merged, err)
	}
	// Both roots live a day; two days on, the stored ones expire and are dropped.
	third := newTestRoot(t, "Third", now.Add(47*time.Hour), now.Add(100*time.Hour), true)
	later, err := run(third, false, now.Add(48*time.Hour))
	if err != nil || later.Roots != 1 {
		t.Fatalf("later=%+v err=%v", later, err)
	}
	replaced, err := run(first, true, now)
	if err != nil || replaced.Roots != 1 {
		t.Fatalf("replaced=%+v err=%v", replaced, err)
	}
	roots, _ := LoadRoots(file)
	if len(roots) != 1 || !roots[0].Equal(first.cert) {
		t.Fatalf("roots=%v", roots)
	}
}

func TestTrustRefusesAStoreThatGrowsWithoutBound(t *testing.T) {
	file := caPath(t)
	for i := 0; i < maxTrustedRoots; i++ {
		root := validRoot(t, "Root")
		server := authority(t, root.pem, nil)
		if _, err := Trust(context.Background(), TrustOptions{URL: server.URL, Fingerprint: root.fingerprint(), CAFile: file}); err != nil {
			t.Fatalf("root %d: %v", i, err)
		}
	}
	root := validRoot(t, "One too many")
	server := authority(t, root.pem, nil)
	_, err := Trust(context.Background(), TrustOptions{URL: server.URL, Fingerprint: root.fingerprint(), CAFile: file})
	if err == nil || !strings.Contains(err.Error(), "--replace") {
		t.Fatalf("err=%v", err)
	}
	if roots, _ := LoadRoots(file); len(roots) != maxTrustedRoots {
		t.Fatalf("roots=%d", len(roots))
	}
}

func TestTrustRefusesToOverwriteAStoreItCannotRead(t *testing.T) {
	root := validRoot(t, "Root")
	server := authority(t, root.pem, nil)
	file := caPath(t)
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("precious notes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Trust(context.Background(), TrustOptions{URL: server.URL, Fingerprint: root.fingerprint(), CAFile: file}); err == nil {
		t.Fatal("overwrote a file that is not a root store")
	}
	if data, _ := os.ReadFile(file); string(data) != "precious notes\n" {
		t.Fatalf("file changed: %q", data)
	}
	// --replace is the explicit way out.
	if _, err := Trust(context.Background(), TrustOptions{URL: server.URL, Fingerprint: root.fingerprint(), CAFile: file, Replace: true}); err != nil {
		t.Fatal(err)
	}
}

func TestTrustBootstrapsOverHTTPSWithoutTrustingTheServer(t *testing.T) {
	root := validRoot(t, "Root")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(root.pem) }))
	defer server.Close()
	file := caPath(t)
	if _, err := Trust(context.Background(), TrustOptions{URL: server.URL, Fingerprint: root.fingerprint(), CAFile: file}); err != nil {
		t.Fatal(err)
	}
	// Whoever answers over TLS still has to produce the pinned root.
	other := validRoot(t, "Other")
	if _, err := Trust(context.Background(), TrustOptions{URL: server.URL, Fingerprint: other.fingerprint(), CAFile: caPath(t)}); err == nil {
		t.Fatal("a server with the wrong root was accepted")
	}
}

func TestTrustValidatesTheInputs(t *testing.T) {
	root := validRoot(t, "Root")
	server := authority(t, root.pem, nil)
	good := root.fingerprint()
	for name, options := range map[string]TrustOptions{
		"no fingerprint":    {URL: server.URL, CAFile: caPath(t)},
		"short fingerprint": {URL: server.URL, Fingerprint: good[:62], CAFile: caPath(t)},
		"not hex":           {URL: server.URL, Fingerprint: strings.Repeat("zz", 32), CAFile: caPath(t)},
		"no file":           {URL: server.URL, Fingerprint: good},
		"ftp":               {URL: "ftp://host", Fingerprint: good, CAFile: caPath(t)},
		"credentials":       {URL: strings.Replace(server.URL, "http://", "http://user:pass@", 1), Fingerprint: good, CAFile: caPath(t)},
		"path":              {URL: server.URL + "/elsewhere", Fingerprint: good, CAFile: caPath(t)},
		"query":             {URL: server.URL + "?x=1", Fingerprint: good, CAFile: caPath(t)},
		"fragment":          {URL: server.URL + "#x", Fingerprint: good, CAFile: caPath(t)},
		"no host":           {URL: "http://", Fingerprint: good, CAFile: caPath(t)},
		"unreachable":       {URL: "http://127.0.0.1:1", Fingerprint: good, CAFile: caPath(t)},
	} {
		_, err := Trust(context.Background(), options)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		// The refusals that name the cause, rather than failing further on.
		for _, tc := range []struct{ name, want string }{{"ftp", "http://"}, {"no host", "http://"}, {"credentials", "http://"}, {"no file", "no CA file"}, {"short fingerprint", "SHA-256"}, {"not hex", "SHA-256"}} {
			if name == tc.name && !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%s: error %q does not say %q", name, err, tc.want)
			}
		}
	}
	if _, err := Trust(context.Background(), TrustOptions{URL: server.URL + "/", Fingerprint: good, CAFile: caPath(t)}); err != nil {
		t.Fatalf("trailing slash refused: %v", err)
	}
}

func TestLoadRootsRefusesAnUnsafeOrForeignStore(t *testing.T) {
	root := validRoot(t, "Root")
	dir := t.TempDir()
	write := func(name string, data []byte, mode os.FileMode) string {
		file := filepath.Join(dir, name)
		if err := os.WriteFile(file, data, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(file, mode); err != nil {
			t.Fatal(err)
		}
		return file
	}
	if _, err := LoadRoots(write("ok.pem", root.pem, 0o600)); err != nil {
		t.Fatalf("a good store was refused: %v", err)
	}
	if _, err := LoadRoots(write("readable.pem", root.pem, 0o644)); err != nil {
		t.Fatalf("a world-readable store is public information and must load: %v", err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(root.key)
	leaf := newTestRoot(t, "Leaf", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), false)
	// A valid root buried under more text than the store may hold.
	huge := write("huge.pem", append(bytes.Repeat([]byte("# padding\n"), maxTrustedRoots*maxRootBytes/10+1), root.pem...), 0o600)
	if _, err := LoadRoots(huge); err == nil {
		t.Error("an oversized store was read")
	}
	if _, err := LoadRoots(write("key2.pem", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)); err == nil || !strings.Contains(err.Error(), "other than certificates") {
		t.Errorf("a private key was not named as foreign: %v", err)
	}
	for name, file := range map[string]string{
		"group writable": write("group.pem", root.pem, 0o664),
		"world writable": write("world.pem", root.pem, 0o666),
		"empty":          write("empty.pem", nil, 0o600),
		"garbage":        write("garbage.pem", []byte("hello"), 0o600),
		"trailing":       write("trailing.pem", append(append([]byte{}, root.pem...), "x"...), 0o600),
		"key":            write("key.pem", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600),
		"leaf":           write("leaf.pem", leaf.pem, 0o600),
		"directory":      dir,
	} {
		if _, err := LoadRoots(file); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	link := filepath.Join(dir, "link.pem")
	if err := os.Symlink(filepath.Join(dir, "ok.pem"), link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRoots(link); err == nil {
		t.Error("a symlink was followed")
	}
	if _, err := LoadRoots(filepath.Join(dir, "missing.pem")); !os.IsNotExist(err) {
		t.Errorf("missing file: %v", err)
	}
}

func TestNormalizeFingerprint(t *testing.T) {
	plain := strings.Repeat("ab", 32)
	for _, form := range []string{plain, strings.ToUpper(plain), strings.Join(splitPairs(plain), ":"), strings.ToUpper(strings.Join(splitPairs(plain), ":")), "  " + plain + "\n", strings.Join(splitPairs(plain), " ")} {
		got, err := NormalizeFingerprint(form)
		if err != nil || got != plain {
			t.Errorf("%q → %q, %v", form, got, err)
		}
	}
	for _, bad := range []string{"", "ab", plain + "00", plain[:62], strings.Repeat("g", 64)} {
		if _, err := NormalizeFingerprint(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestDefaultCAFileLivesInTheUserConfigDirectory(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/cfg")
	t.Setenv("HOME", "/home/someone")
	got := DefaultCAFile()
	if got == "" || filepath.Base(got) != "ca.pem" || filepath.Base(filepath.Dir(got)) != "jolt-mcp" {
		t.Fatalf("default=%q", got)
	}
}

// secureServer is a Control Tower stand-in over HTTPS with a certificate from root.
func secureServer(t *testing.T, root testRoot, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{root.issue(t)}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func listArgsFor() listArgs {
	return listArgs{fileArgs: fileArgs{NodeID: "node", MountID: "media", Path: ""}}
}

func TestServerTrustsOnlyTheStoredRootsAndFollowsTheFile(t *testing.T) {
	jolt, other := validRoot(t, "Jolt"), validRoot(t, "Other")
	server := secureServer(t, jolt, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"items":[]}`) }))
	credential := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(credential, []byte("token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := caPath(t)
	if err := writeRoots(store, []*x509.Certificate{other.cert}); err != nil {
		t.Fatal(err)
	}
	mcpServer, err := New(server.URL, credential, WithCAFile(store))
	if err != nil {
		t.Fatal(err)
	}
	call := func() error {
		result, _, err := mcpServer.list(context.Background(), nil, listArgsFor())
		if err == nil && result.IsError {
			t.Fatal("unexpected tool error result")
		}
		return err
	}
	if err := call(); err == nil {
		t.Fatal("a Control Tower under an unknown root was reached")
	}
	// `trust` rewrites the file; the running server picks it up.
	if err := writeRoots(store, []*x509.Certificate{other.cert, jolt.cert}); err != nil {
		t.Fatal(err)
	}
	if err := call(); err != nil {
		t.Fatalf("after trust: %v", err)
	}
	// A rotation that drops the root cuts the server off again.
	if err := writeRoots(store, []*x509.Certificate{other.cert}); err != nil {
		t.Fatal(err)
	}
	if err := call(); err == nil {
		t.Fatal("a root removed from the file was still trusted")
	}
}

func TestServerWithoutAStoreUsesTheSystemTrust(t *testing.T) {
	jolt := validRoot(t, "Jolt")
	server := secureServer(t, jolt, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{}`) }))
	credential := filepath.Join(t.TempDir(), "credential")
	_ = os.WriteFile(credential, []byte("token\n"), 0o600)
	mcpServer, err := New(server.URL, credential)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := mcpServer.list(context.Background(), nil, listArgsFor()); err == nil {
		t.Fatal("an unknown root was trusted without a store")
	}
}

func TestServerFailsClearlyWhenTheStoreIsMissingOrBroken(t *testing.T) {
	jolt := validRoot(t, "Jolt")
	reached := false
	server := secureServer(t, jolt, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached = true; _, _ = io.WriteString(w, `{}`) }))
	credential := filepath.Join(t.TempDir(), "credential")
	_ = os.WriteFile(credential, []byte("token\n"), 0o600)
	store := caPath(t)
	mcpServer, _ := New(server.URL, credential, WithCAFile(store))
	if _, _, err := mcpServer.list(context.Background(), nil, listArgsFor()); err == nil || !strings.Contains(err.Error(), "jolt-mcp trust") {
		t.Fatalf("missing: %v", err)
	}
	_ = os.MkdirAll(filepath.Dir(store), 0o700)
	_ = os.WriteFile(store, []byte("not roots"), 0o600)
	if _, _, err := mcpServer.list(context.Background(), nil, listArgsFor()); err == nil || !strings.Contains(err.Error(), "jolt-mcp trust") {
		t.Fatalf("broken: %v", err)
	}
	if reached {
		t.Fatal("a request went out without a usable trust store")
	}
}

func TestServerReloadsWhenTheFileIsReplacedWithTheSameSizeAndTime(t *testing.T) {
	a, b := validRoot(t, "Jolt A"), validRoot(t, "Jolt B")
	server := secureServer(t, b, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{}`) }))
	credential := filepath.Join(t.TempDir(), "credential")
	_ = os.WriteFile(credential, []byte("token\n"), 0o600)
	store := caPath(t)
	if err := writeRoots(store, []*x509.Certificate{a.cert}); err != nil {
		t.Fatal(err)
	}
	mcpServer, _ := New(server.URL, credential, WithCAFile(store))
	if _, _, err := mcpServer.list(context.Background(), nil, listArgsFor()); err == nil {
		t.Fatal("root A must not vouch for a certificate from root B")
	}
	info, _ := os.Stat(store)
	if err := writeRoots(store, []*x509.Certificate{b.cert}); err != nil {
		t.Fatal(err)
	}
	// Same size, and the old modification time restored: only the inode differs.
	if err := os.Chtimes(store, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := mcpServer.list(context.Background(), nil, listArgsFor()); err != nil {
		t.Fatalf("the replaced file was not noticed: %v", err)
	}
}

// writeInPlace rewrites the file without replacing it, as an editor or a
// `cp` would, so only its size and time say that it changed.
func writeInPlace(t *testing.T, filename string, data []byte, modified time.Time) {
	t.Helper()
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filename, modified, modified); err != nil {
		t.Fatal(err)
	}
}

// padTo prefixes data with a text line, which PEM skips, so it has size bytes.
// The line must end in a newline: PEM finds -----BEGIN only at the start of
// the data or of a line.
func padTo(data []byte, size int) []byte {
	n := size - len(data)
	if n <= 0 {
		return data
	}
	return append([]byte(strings.Repeat("#", n-1)+"\n"), data...)
}

func TestServerNoticesAnInPlaceRewriteByTimeOrBySize(t *testing.T) {
	a, b := validRoot(t, "Jolt A"), validRoot(t, "Jolt B")
	server := secureServer(t, b, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{}`) }))
	credential := filepath.Join(t.TempDir(), "credential")
	_ = os.WriteFile(credential, []byte("token\n"), 0o600)
	call := func(mcpServer *Server) error {
		_, _, err := mcpServer.list(context.Background(), nil, listArgsFor())
		return err
	}
	stamp := time.Now().Add(-time.Hour).Truncate(time.Second)
	// Different time, same size: pad both stores to one size with a leading
	// text line, which PEM skips. Both are always padded, so the padding is
	// exercised on every run, not only when the two encodings differ in length.
	t.Run("time", func(t *testing.T) {
		pemA, pemB := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.cert.Raw}), b.pem
		size := max(len(pemA), len(pemB)) + 2
		pemA, pemB = padTo(pemA, size), padTo(pemB, size)
		store := caPath(t)
		_ = os.MkdirAll(filepath.Dir(store), 0o700)
		_ = os.WriteFile(store, pemA, 0o600)
		_ = os.Chtimes(store, stamp, stamp)
		// A refusal below must come from root A not vouching for B, not from
		// a store that cannot be read.
		if _, err := LoadRoots(store); err != nil {
			t.Fatalf("padded store A does not load: %v", err)
		}
		mcpServer, _ := New(server.URL, credential, WithCAFile(store))
		if call(mcpServer) == nil {
			t.Fatal("root A vouched for a certificate from root B")
		}
		writeInPlace(t, store, pemB, stamp.Add(time.Minute))
		if _, err := LoadRoots(store); err != nil {
			t.Fatalf("padded store B does not load: %v", err)
		}
		if err := call(mcpServer); err != nil {
			t.Fatalf("the rewrite was not noticed: %v", err)
		}
	})
	// Same time, different size: a second root appended.
	t.Run("size", func(t *testing.T) {
		store := caPath(t)
		if err := writeRoots(store, []*x509.Certificate{a.cert}); err != nil {
			t.Fatal(err)
		}
		_ = os.Chtimes(store, stamp, stamp)
		mcpServer, _ := New(server.URL, credential, WithCAFile(store))
		if call(mcpServer) == nil {
			t.Fatal("root A vouched for a certificate from root B")
		}
		both := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.cert.Raw}), b.pem...)
		writeInPlace(t, store, both, stamp)
		if err := call(mcpServer); err != nil {
			t.Fatalf("the rewrite was not noticed: %v", err)
		}
	})
}
