package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
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

// A node the authority enrolled, served with a certificate the test chooses.
type issuedNode struct {
	server      *httptest.Server
	fingerprint string
	serial      string
}

func clockedAuthority(t *testing.T, clock *testClock) *pki.Manager {
	t.Helper()
	storage, err := store.Open(filepath.Join(t.TempDir(), "pki.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	authority, err := pki.NewManager(storage, pki.Options{Key: make([]byte, 32), Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	return authority
}

func issueAndServe(t *testing.T, authority *pki.Manager) issuedNode {
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
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return issuedNode{server: server, fingerprint: pki.Fingerprint(leaf), serial: leaf.SerialNumber.Text(16)}
}

// drain reads the body to its end, so the connection goes back to the pool: a
// body closed unread makes some Go versions drop the connection, and the tests
// that follow an open connection need it kept.
func drain(response *http.Response) {
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
}

// reach calls the node the way the Control Tower does. host, when set, is the
// name dialed in place of the node's IP address.
func reach(authority *pki.Manager, node issuedNode, host string) error {
	address := node.server.URL
	if host != "" {
		address = "https://" + host + ":" + address[strings.LastIndex(address, ":")+1:]
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: newNodeTransport(config.Config{Authority: authority}, nil)}
	response, err := client.Get(address)
	if err != nil {
		return err
	}
	response.Body.Close()
	return nil
}

func TestANodeCertificateTheBundleRevokesIsRefusedEvenIfTheAuthorityIssuedIt(t *testing.T) {
	clock := &testClock{now: time.Now().UTC()}
	authority := clockedAuthority(t, clock)
	node := issueAndServe(t, authority)
	if err := reach(authority, node, ""); err != nil {
		t.Fatalf("before the revocation: %v", err)
	}
	authority.Pin([]string{node.fingerprint})
	if err := authority.Revoke(context.Background(), pki.Revocation{Serial: node.serial}); err != nil {
		t.Fatal(err)
	}
	if err := reach(authority, node, ""); err == nil {
		t.Fatal("a revoked certificate was reached, and being pinned did not make it an exception")
	}
}

func TestNodesSignedByARevokedIntermediateAreReachedOnlyIfTheAuthorityIssuedThemTheirCertificate(t *testing.T) {
	clock := &testClock{now: time.Now().UTC()}
	authority := clockedAuthority(t, clock)
	node := issueAndServe(t, authority)
	if err := authority.RotateIntermediate(context.Background(), true, "key leaked"); err != nil {
		t.Fatal(err)
	}
	if err := reach(authority, node, ""); err == nil {
		t.Fatal("a certificate signed by a revoked intermediate was trusted")
	}
	authority.Pin([]string{node.fingerprint})
	if err := reach(authority, node, ""); err != nil {
		t.Fatalf("the node the authority issued this certificate to could not be reached to renew: %v", err)
	}
	// What the authority issued but then revoked on its own is not an exception.
	if err := authority.Revoke(context.Background(), pki.Revocation{Serial: node.serial}); err != nil {
		t.Fatal(err)
	}
	if err := reach(authority, node, ""); err == nil {
		t.Fatal("a pinned certificate that was also revoked by itself was reached")
	}
}

func TestANodeThatWasAwayPastItsExpiryIsReachedOnlyByTheCertificateItWasGiven(t *testing.T) {
	clock := &testClock{now: time.Now().UTC().Add(-100 * 24 * time.Hour)}
	authority := clockedAuthority(t, clock)
	node := issueAndServe(t, authority) // valid for 90 days from 100 days ago
	clock.now = time.Now().UTC()
	if err := authority.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := reach(authority, node, ""); err == nil {
		t.Fatal("an expired certificate was trusted")
	}
	authority.Pin([]string{"0000"})
	if err := reach(authority, node, ""); err == nil {
		t.Fatal("a certificate that was not issued to this node was accepted because something else is pinned")
	}
	authority.Pin([]string{node.fingerprint})
	if err := reach(authority, node, ""); err != nil {
		t.Fatalf("the node could not be reached to renew: %v", err)
	}
	// Even then, only for the name it was issued for.
	if err := reach(authority, node, "localhost"); err == nil {
		t.Fatal("an expired pinned certificate was accepted for a name it does not cover")
	}
}

func TestNodesStayReachableThroughEveryStepOfARootRotationUntilTheOldRootLeaves(t *testing.T) {
	ctx := context.Background()
	clock := &testClock{now: time.Now().UTC()}
	authority := clockedAuthority(t, clock)
	old := issueAndServe(t, authority)
	steps := []struct {
		name string
		do   func() error
	}{
		{"prepared", func() error { return authority.BeginRootRotation(ctx) }},
		{"promoted", func() error { return authority.PromoteRoot(ctx) }},
	}
	for _, step := range steps {
		if err := step.do(); err != nil {
			t.Fatal(err)
		}
		if err := reach(authority, old, ""); err != nil {
			t.Fatalf("%s: a node on the old chain was lost: %v", step.name, err)
		}
	}
	fresh := issueAndServe(t, authority)
	if err := reach(authority, fresh, ""); err != nil {
		t.Fatalf("a node on the new chain was not reached: %v", err)
	}
	if err := authority.RetireRoot(ctx); err != nil {
		t.Fatal(err)
	}
	if err := reach(authority, fresh, ""); err != nil {
		t.Fatalf("after retirement: %v", err)
	}
	if err := reach(authority, old, ""); err == nil {
		t.Fatal("a node on the retired chain was still trusted, with nothing pinned")
	}
}

func TestACertificateForAnotherNameIsRefusedEvenWhenItChainsToTheAuthority(t *testing.T) {
	clock := &testClock{now: time.Now().UTC()}
	authority := clockedAuthority(t, clock)
	node := issueAndServe(t, authority) // covers 127.0.0.1 only
	if err := reach(authority, node, "localhost"); err == nil {
		t.Fatal("a certificate that does not cover the name that was dialed was accepted")
	}
	if err := reach(authority, node, ""); err != nil {
		t.Fatalf("the right name was refused: %v", err)
	}
}

func TestAnOperatorWhoTurnedVerificationOffKeepsItOff(t *testing.T) {
	other := clockedAuthority(t, &testClock{now: time.Now().UTC()})
	foreign := issueAndServe(t, other)
	ours := clockedAuthority(t, &testClock{now: time.Now().UTC()})
	strict := &http.Client{Timeout: 5 * time.Second, Transport: newNodeTransport(config.Config{Authority: ours}, nil)}
	if response, err := strict.Get(foreign.server.URL); err == nil {
		response.Body.Close()
		t.Fatal("a node of another authority was reached with verification on")
	}
	lax := &http.Client{Timeout: 5 * time.Second, Transport: newNodeTransport(config.Config{Authority: ours}, &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true})}
	response, err := lax.Get(foreign.server.URL)
	if err != nil {
		t.Fatalf("the operator's choice not to verify was overridden: %v", err)
	}
	response.Body.Close()
}

func TestAConnectionAlreadyOpenIsDroppedWhenTheBundleRevokesItsNode(t *testing.T) {
	clock := &testClock{now: time.Now().UTC()}
	authority := clockedAuthority(t, clock)
	node := issueAndServe(t, authority)
	transport := newNodeTransport(config.Config{Authority: authority}, nil)
	client := &http.Client{Timeout: 5 * time.Second, Transport: transport}
	get := func() error {
		response, err := client.Get(node.server.URL)
		if err != nil {
			return err
		}
		drain(response)
		return nil
	}
	if err := get(); err != nil {
		t.Fatal(err)
	}
	if err := authority.Revoke(context.Background(), pki.Revocation{Serial: node.serial}); err != nil {
		t.Fatal(err)
	}
	// Nothing was judged again: the connection the client holds still works.
	if err := get(); err != nil {
		t.Fatalf("setup: the open connection should still be in use: %v", err)
	}
	transport.RecheckConnections()
	if err := get(); err == nil {
		t.Fatal("the open connection to a revoked node survived the recheck")
	}
}

func TestRecheckingKeepsConnectionsThatAreStillAcceptableAndTheOnesPinnedForARenewal(t *testing.T) {
	clock := &testClock{now: time.Now().UTC().Add(-100 * 24 * time.Hour)}
	authority := clockedAuthority(t, clock)
	expired := issueAndServe(t, authority)
	clock.now = time.Now().UTC()
	if err := authority.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	healthy := issueAndServe(t, authority)
	authority.Pin([]string{expired.fingerprint})
	transport := newNodeTransport(config.Config{Authority: authority}, nil)
	client := &http.Client{Timeout: 5 * time.Second, Transport: transport}
	for _, node := range []issuedNode{expired, healthy} {
		response, err := client.Get(node.server.URL)
		if err != nil {
			t.Fatal(err)
		}
		drain(response)
	}
	transport.connections.mu.Lock()
	before := len(transport.connections.open)
	transport.connections.mu.Unlock()
	transport.RecheckConnections()
	transport.connections.mu.Lock()
	after := len(transport.connections.open)
	transport.connections.mu.Unlock()
	if before != 2 || after != 2 {
		t.Fatalf("connections before %d, after %d", before, after)
	}
	// A pinned certificate that was then unpinned is no longer acceptable.
	authority.Pin(nil)
	transport.RecheckConnections()
	transport.connections.mu.Lock()
	left := len(transport.connections.open)
	transport.connections.mu.Unlock()
	if left != 1 {
		t.Fatalf("after unpinning, %d connections remain", left)
	}
}

func TestClosedConnectionsAreForgotten(t *testing.T) {
	authority := clockedAuthority(t, &testClock{now: time.Now().UTC()})
	node := issueAndServe(t, authority)
	transport := newNodeTransport(config.Config{Authority: authority}, nil)
	client := &http.Client{Timeout: 5 * time.Second, Transport: transport}
	response, err := client.Get(node.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	transport.CloseIdleConnections()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		transport.connections.mu.Lock()
		remaining := len(transport.connections.open)
		transport.connections.mu.Unlock()
		if remaining == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("a closed connection is still remembered")
}

// A node judges the client certificate again on every request. A connection
// that was opened with a certificate the Control Tower has since replaced must
// therefore be closed, or the node refuses it for as long as it is used.
func TestAConnectionOpenedWithAReplacedClientCertificateIsClosedByTheRecheck(t *testing.T) {
	authority := clockedAuthority(t, &testClock{now: time.Now().UTC()})
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	request, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "n1"}}, key)
	chain, leaf, err := authority.IssueServerCertificate(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request}), "n1", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{PrivateKey: key, Leaf: leaf}
	for rest := []byte(chain); ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		certificate.Certificate = append(certificate.Certificate, block.Bytes)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.TLS.PeerCertificates[0].SerialNumber.Text(16)))
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAnyClientCert}
	server.StartTLS()
	t.Cleanup(server.Close)
	authority.Pin([]string{pki.Fingerprint(leaf)})
	transport := newNodeTransport(config.Config{Authority: authority}, nil)
	client := &http.Client{Timeout: 5 * time.Second, Transport: transport}
	seen := func() string {
		response, err := client.Get(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return string(body)
	}
	first := seen()
	if err := authority.RotateIntermediate(context.Background(), true, "leaked"); err != nil {
		t.Fatal(err)
	}
	current, _ := authority.ClientCertificate()
	if current.Leaf.SerialNumber.Text(16) == first {
		t.Fatal("setup: the client certificate was not replaced")
	}
	if got := seen(); got != first {
		t.Fatalf("setup: the open connection should still carry the old certificate, got %s", got)
	}
	transport.RecheckConnections()
	if got := seen(); got != current.Leaf.SerialNumber.Text(16) {
		t.Fatalf("after the recheck the connection carries %s, want the new certificate %s", got, current.Leaf.SerialNumber.Text(16))
	}
}
