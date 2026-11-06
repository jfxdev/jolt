package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/config"
	"github.com/jfxdev/jolt/control/internal/pki"
	"github.com/jfxdev/jolt/control/internal/store"
)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

func openStore(t *testing.T) *store.Store {
	t.Helper()
	storage, err := store.Open(filepath.Join(t.TempDir(), "control.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	return storage
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestManualModeStartsNoAuthority(t *testing.T) {
	cfg := config.Config{TLSMode: config.TLSManual, EncryptionKey: make([]byte, 32)}
	authority, err := startAuthority(context.Background(), &cfg, openStore(t), quiet())
	if err != nil || authority != nil || cfg.Authority != nil || cfg.SigningSource != nil {
		t.Fatalf("manual mode built an authority: %v %v", authority, err)
	}
}

func TestManagedModeBuildsTheAuthorityAndUsesItForSigning(t *testing.T) {
	cfg := config.Config{TLSMode: config.TLSManaged, EncryptionKey: make([]byte, 32), TLSNames: []string{"control.lan"}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	authority, err := startAuthority(ctx, &cfg, openStore(t), quiet())
	if err != nil || authority == nil || cfg.Authority != authority || cfg.SigningSource == nil {
		t.Fatalf("managed mode: %v", err)
	}
	if id, key := cfg.SigningSource.Current(); id == "" || len(key) == 0 {
		t.Fatal("no signing key from the authority")
	}
}

func TestManagedModeFailsToStartWhenTheDatabaseKeyIsWrong(t *testing.T) {
	storage := openStore(t)
	cfg := config.Config{TLSMode: config.TLSManaged, EncryptionKey: make([]byte, 32)}
	if _, err := startAuthority(context.Background(), &cfg, storage, quiet()); err != nil {
		t.Fatal(err)
	}
	wrong := config.Config{TLSMode: config.TLSManaged, EncryptionKey: []byte("ffffffffffffffffffffffffffffffff")}
	if _, err := startAuthority(context.Background(), &wrong, storage, quiet()); err == nil {
		t.Fatal("an authority sealed under another key was started")
	}
}

// listen serves handler over TLS from the authority, the way main does, and
// returns the address.
func listen(t *testing.T, authority *pki.Manager, handler http.Handler) string {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: withRootDownload(authority, handler), TLSConfig: authority.TLSConfig(), ReadHeaderTimeout: time.Second}
	go func() { _ = server.Serve(tls.NewListener(raw, authority.TLSConfig())) }()
	t.Cleanup(func() { _ = server.Close() })
	return raw.Addr().String()
}

func client(roots *x509.CertPool) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
}

func serial(t *testing.T, c *http.Client, url string) (string, int) {
	t.Helper()
	response, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	c.CloseIdleConnections()
	return response.TLS.PeerCertificates[0].SerialNumber.Text(16), response.StatusCode
}

func TestTheControlTowerServesHTTPSFromItsOwnAuthorityAndRenewsWithoutARestart(t *testing.T) {
	// The authority starts 61 days in the past, so the first certificate is
	// still valid for a real client and is due for renewal "today".
	real := time.Now().UTC()
	clock := &fakeClock{now: real.Add(-61 * 24 * time.Hour)}
	authority, err := pki.NewManager(openStore(t), pki.Options{Key: make([]byte, 32), Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	address := listen(t, authority, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("app")) }))

	// A client that knows only the published root, fetched from the public page.
	public := httptest.NewServer(pki.PublicHandler(authority))
	defer public.Close()
	response, err := http.Get(public.URL + "/ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	rootPEM, _ := io.ReadAll(response.Body)
	response.Body.Close()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("the published root cannot be loaded")
	}
	trusting := client(roots)
	first, status := serial(t, trusting, "https://localhost:"+strings.Split(address, ":")[1]+"/")
	if status != 200 {
		t.Fatalf("status %d", status)
	}

	// Without the root the same server is refused: nothing is trusted by default.
	if _, err := client(x509.NewCertPool()).Get("https://localhost:" + strings.Split(address, ":")[1] + "/"); err == nil {
		t.Fatal("a client that does not know the root accepted the certificate")
	}
	// And the name must match.
	if _, err := trusting.Get("https://127.0.0.1:" + strings.Split(address, ":")[1] + "/"); err != nil {
		t.Fatalf("the loopback address is covered by default: %v", err)
	}

	// Past two thirds of its life the certificate is renewed on the live listener.
	clock.now = real
	if err := authority.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	renewed, status := serial(t, trusting, "https://localhost:"+strings.Split(address, ":")[1]+"/")
	if status != 200 || renewed == first {
		t.Fatalf("the live listener did not pick up the renewal: %s vs %s", renewed, first)
	}
	// The root did not change, so the device that installed it needs nothing.
	if _, status := serial(t, trusting, "https://localhost:"+strings.Split(address, ":")[1]+"/.well-known/jolt/ca.pem"); status != 200 {
		t.Fatalf("root download on the HTTPS listener: %d", status)
	}
}

func TestOnlyTheRootPathIsRoutedAroundTheApplication(t *testing.T) {
	authority, err := pki.NewManager(openStore(t), pki.Options{Key: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	handler := withRootDownload(authority, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("app:" + r.URL.Path)) }))
	for path, want := range map[string]string{"/": "app:/", "/ca": "app:/ca", "/ca.pem": "app:/ca.pem", "/api/v1/control-tower/about": "app:/api/v1/control-tower/about"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Body.String() != want {
			t.Errorf("%s: %q", path, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/jolt/ca.pem", nil))
	if w.Header().Get("Content-Type") != "application/x-pem-file" {
		t.Fatalf("root path: %q", w.Header().Get("Content-Type"))
	}
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/.well-known/jolt/ca.pem", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST on the root path: %d", w.Code)
	}
}

func TestThePublicRootServerIsHardened(t *testing.T) {
	authority, _ := pki.NewManager(openStore(t), pki.Options{Key: make([]byte, 32)})
	server := publicRootServer(authority, ":0")
	if server.ReadHeaderTimeout == 0 || server.ReadTimeout == 0 || server.WriteTimeout == 0 || server.IdleTimeout == 0 || server.MaxHeaderBytes == 0 || server.MaxHeaderBytes > 16<<10 {
		t.Fatalf("limits: %+v", server)
	}
}
