package httpapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/config"
	"github.com/jfxdev/jolt/control/internal/pki"
)

// nodeServer plays a managed node's API: a certificate its own authority
// issued, and a requirement that the client present one from that authority.
func nodeServer(t *testing.T, authority *pki.Manager) (*httptest.Server, *string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	request, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "n1"}}, key)
	chain, leaf, err := authority.IssueServerCertificate(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request}), "n1", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{PrivateKey: key, Leaf: leaf}
	rest := []byte(chain)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		certificate.Certificate = append(certificate.Certificate, block.Bytes)
	}
	var seen string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) > 0 {
			seen = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		_, _ = w.Write([]byte("ok"))
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: authority.RootPool()}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, &seen
}

func httpsClient(config *tls.Config) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: config}}
}

func TestTheControlTowerTrustsAndAuthenticatesToNodesOfItsOwnAuthority(t *testing.T) {
	authority := managedAuthority(t)
	server, seen := nodeServer(t, authority)
	cfg := config.Config{Authority: authority}
	response, err := httpsClient(withAuthority(cfg, nil)).Get(server.URL)
	if err != nil {
		t.Fatalf("the managed node was not reached: %v", err)
	}
	response.Body.Close()
	if *seen != pki.ControlTowerName {
		t.Fatalf("the node saw the client as %q", *seen)
	}
	// Without the authority the same node is neither trusted nor reached.
	if _, err := httpsClient(withAuthority(config.Config{}, nil)).Get(server.URL); err == nil {
		t.Fatal("a client that knows no authority reached the node")
	}
	if got := withAuthority(config.Config{}, nil); got != nil {
		t.Fatal("settings were invented without an authority")
	}
}

func TestWhatTheOperatorConfiguredByHandKeepsWorkingBesideTheAuthority(t *testing.T) {
	authority := managedAuthority(t)
	server, _ := nodeServer(t, authority)
	// A hand-configured extra CA is kept, and the base settings are not mutated.
	extra := x509.NewCertPool()
	base := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: extra}
	merged := withAuthority(config.Config{Authority: authority}, base)
	response, err := httpsClient(merged).Get(server.URL)
	if err != nil {
		t.Fatalf("authority root was not added to the configured pool: %v", err)
	}
	response.Body.Close()
	if len(extra.Subjects()) != 0 {
		t.Fatal("the operator's pool was modified in place")
	}
	if base.GetClientCertificate != nil {
		t.Fatal("the operator's settings were modified in place")
	}
}

func TestACertificateTheNodeDoesNotAskForIsNotOffered(t *testing.T) {
	authority := managedAuthority(t)
	other := managedAuthority(t)
	// A node that trusts only another authority asks for certificates from it.
	server, seen := nodeServer(t, other)
	merged := withAuthority(config.Config{Authority: authority}, nil)
	merged.InsecureSkipVerify = true // the server's own chain is not the point here
	_, err := httpsClient(merged).Get(server.URL)
	if err == nil {
		t.Fatal("a node of another authority accepted this Control Tower")
	}
	if *seen == pki.ControlTowerName {
		t.Fatal("the client certificate was offered to an authority that does not know it")
	}
}
