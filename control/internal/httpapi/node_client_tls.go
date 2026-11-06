package httpapi

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/jfxdev/jolt/control/internal/config"
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
