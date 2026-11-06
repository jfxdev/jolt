package httpapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
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

// newNodeTransport is the transport the Control Tower reaches nodes with. With
// an authority, the certificate of a node is checked here and not by the TLS
// stack, so that the bundle's revocations apply and so that a node the
// authority itself issued can still be reached to renew a certificate that ran
// out. The check needs the name that was dialed, which the TLS state does not
// carry for an IP address, so the handshake is made by the dialer.
func newNodeTransport(cfg config.Config, tlsConfig *tls.Config) *http.Transport {
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
		return transport
	}
	base := transport.TLSClientConfig
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		raw, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		perConnection := base.Clone()
		perConnection.ServerName = host
		perConnection.NextProtos = []string{"h2", "http/1.1"}
		perConnection.InsecureSkipVerify = true
		perConnection.VerifyConnection = verifyNode(authority, base.RootCAs, host, base.InsecureSkipVerify)
		conn := tls.Client(raw, perConnection)
		handshake, cancel := context.WithTimeout(ctx, transport.TLSHandshakeTimeout)
		defer cancel()
		if err := conn.HandshakeContext(handshake); err != nil {
			_ = raw.Close()
			return nil, err
		}
		return conn, nil
	}
	return transport
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
