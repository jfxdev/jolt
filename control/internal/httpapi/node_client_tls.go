package httpapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/jfxdev/jolt/control/internal/config"
	"github.com/jfxdev/jolt/control/internal/pki"
)

// withAuthority extends the TLS settings used to reach nodes so that the
// Control Tower trusts the nodes its own authority enrolled and presents its
// client certificate to them. Without an authority the settings are returned
// as they are. Whatever the operator configured by hand keeps working beside it:
// the extra CA still trusts, and a client certificate that matches what a node
// asks for is still offered.
func withAuthority(cfg config.Config, base *tls.Config) *tls.Config {
	authority := cfg.Authority
	if authority == nil {
		return base
	}
	var out *tls.Config
	if base != nil {
		out = base.Clone()
	} else {
		out = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	pool := out.RootCAs
	if pool == nil {
		if system, err := x509.SystemCertPool(); err == nil && system != nil {
			pool = system
		} else {
			pool = x509.NewCertPool()
		}
	} else {
		pool = pool.Clone()
	}
	pool.AppendCertsFromPEM(authority.RootPEM())
	out.RootCAs = pool
	manual := out.Certificates
	out.GetClientCertificate = func(request *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		if managed, err := authority.ClientCertificate(); err == nil && request.SupportsCertificate(managed) == nil {
			return managed, nil
		}
		for i := range manual {
			if request.SupportsCertificate(&manual[i]) == nil {
				return &manual[i], nil
			}
		}
		return &tls.Certificate{}, nil
	}
	return out
}

// nodeTransport is the transport the Control Tower reaches nodes with.
type nodeTransport struct {
	*http.Transport
	connections *nodeConnections
}

// RecheckConnections closes every open connection whose node certificate would
// no longer be accepted, because the bundle revoked something in its chain or
// the authority changed, and every one that still presents a client certificate
// the Control Tower has since replaced. A handshake is judged once, and a node
// judges the client certificate again on every request, so a connection left
// open across a revocation would be refused by the node for as long as it is
// used, and would outlive the revocation of a node's certificate.
func (t *nodeTransport) RecheckConnections() {
	if t.connections != nil {
		t.connections.recheck()
	}
}

// nodeConnections remembers the TLS connections to nodes, to judge them again.
type nodeConnections struct {
	mu   sync.Mutex
	open map[*trackedConn]struct{}
	// clientSerial is the serial of the client certificate the Control Tower
	// presents now.
	clientSerial func() string
}

type trackedConn struct {
	*tls.Conn
	owner  *nodeConnections
	verify func(tls.ConnectionState) error
	// presented is the serial of the client certificate this connection was
	// opened with, which the node keeps judging on every request.
	presented string
}

func (c *trackedConn) Close() error {
	c.owner.mu.Lock()
	delete(c.owner.open, c)
	c.owner.mu.Unlock()
	return c.Conn.Close()
}

func (n *nodeConnections) recheck() {
	current := ""
	if n.clientSerial != nil {
		current = n.clientSerial()
	}
	n.mu.Lock()
	var stale []*trackedConn
	for conn := range n.open {
		replaced := current != "" && conn.presented != "" && conn.presented != current
		if replaced || conn.verify(conn.ConnectionState()) != nil {
			stale = append(stale, conn)
		}
	}
	n.mu.Unlock()
	for _, conn := range stale {
		_ = conn.Close()
	}
}

// newNodeTransport builds the transport. With an authority, the certificate of a
// node is checked here and not by the TLS stack, so that the bundle's
// revocations apply and so that a node the authority itself issued can still be
// reached to renew a certificate that ran out. The check needs the name that
// was dialed, which the TLS state does not carry for an IP address, so the
// handshake is made by the dialer. Connections are then HTTP/1.1.
func newNodeTransport(cfg config.Config, tlsConfig *tls.Config) *nodeTransport {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	transport.TLSClientConfig = withAuthority(cfg, tlsConfig)
	authority := cfg.Authority
	if authority == nil {
		return &nodeTransport{Transport: transport}
	}
	connections := &nodeConnections{open: map[*trackedConn]struct{}{}, clientSerial: func() string {
		if pair, err := authority.ClientCertificate(); err == nil && pair.Leaf != nil {
			return pair.Leaf.SerialNumber.Text(16)
		}
		return ""
	}}
	base := transport.TLSClientConfig
	transport.ForceAttemptHTTP2 = false
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		raw, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		verify := verifyNode(authority, base.RootCAs, host, base.InsecureSkipVerify)
		perConnection := base.Clone()
		perConnection.ServerName = host
		perConnection.NextProtos = []string{"http/1.1"}
		perConnection.InsecureSkipVerify = true
		perConnection.VerifyConnection = verify
		presented := ""
		if inner := base.GetClientCertificate; inner != nil {
			perConnection.GetClientCertificate = func(request *tls.CertificateRequestInfo) (*tls.Certificate, error) {
				pair, err := inner(request)
				if err == nil && pair != nil && pair.Leaf != nil {
					presented = pair.Leaf.SerialNumber.Text(16)
				}
				return pair, err
			}
		}
		conn := tls.Client(raw, perConnection)
		handshake, cancel := context.WithTimeout(ctx, transport.TLSHandshakeTimeout)
		defer cancel()
		if err := conn.HandshakeContext(handshake); err != nil {
			_ = raw.Close()
			return nil, err
		}
		tracked := &trackedConn{Conn: conn, owner: connections, verify: verify, presented: presented}
		connections.mu.Lock()
		connections.open[tracked] = struct{}{}
		connections.mu.Unlock()
		return tracked, nil
	}
	return &nodeTransport{Transport: transport, connections: connections}
}

// verifyNode is how the Control Tower decides to talk to a node's API.
//
// A certificate that chains to a root of this authority must not be revoked,
// itself or through an intermediate. One that chains to anything else (a CA the
// operator trusts by hand) is judged as the standard library would. A
// certificate that fails for either reason is still accepted when it is exactly
// one this authority issued to a node (it holds the key), its own serial is not
// revoked and it covers the name that was dialed: that is how a node comes back
// after being away past its expiry, or after the intermediate that signed it
// was replaced, and renews.
func verifyNode(authority *pki.Manager, pool *x509.CertPool, host string, skipVerify bool) func(tls.ConnectionState) error {
	return func(state tls.ConnectionState) error {
		if skipVerify {
			return nil
		}
		if len(state.PeerCertificates) == 0 {
			return errors.New("the node presented no certificate")
		}
		leaf := state.PeerCertificates[0]
		intermediates := x509.NewCertPool()
		for _, cert := range state.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}
		bundle := authority.Bundle()
		// Every root the bundle lists, not only the one the pool was built with:
		// two of them are trusted while a root rotation is under way.
		rootCerts, _, _ := bundle.Certificates()
		roots := pool.Clone()
		for _, cert := range rootCerts {
			roots.AddCert(cert)
		}
		chains, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
		if err == nil {
			authorityRoots := map[string]bool{}
			for _, cert := range rootCerts {
				authorityRoots[pki.Fingerprint(cert)] = true
			}
			for _, chain := range chains {
				if !authorityRoots[pki.Fingerprint(chain[len(chain)-1])] {
					return nil // a CA the operator configured by hand
				}
				if !bundle.ChainRevoked(chain) {
					return nil
				}
			}
			err = errors.New("the node's certificate was revoked")
		}
		if authority.Pinned(pki.Fingerprint(leaf)) && !bundle.Revoked(leaf.SerialNumber.Text(16)) && leaf.VerifyHostname(host) == nil {
			return nil
		}
		return err
	}
}
