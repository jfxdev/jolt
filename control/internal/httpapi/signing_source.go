package httpapi

import (
	"crypto/ed25519"
)

// signing returns the key that signs authorization contexts now, with its ID,
// read together so a rotation cannot pair one key's ID with another's secret.
// A fixed key from the configuration is the common case; the Control Tower's
// own authority rotates it while running.
func (s *Server) signing() (string, ed25519.PrivateKey) {
	if s.config.SigningSource != nil {
		return s.config.SigningSource.Current()
	}
	return s.config.AuthorizationSigningKeyID, s.config.AuthorizationSigningKey
}

// signingKey is the signing key alone, for checks that only need to know one
// exists.
func (s *Server) signingKey() ed25519.PrivateKey {
	_, key := s.signing()
	return key
}

// signingKeyID is the ID of the signing key alone, for checks that only need to
// know it is valid.
func (s *Server) signingKeyID() string {
	id, _ := s.signing()
	return id
}

// verificationKeys are the keys a context issued by this Control Tower may
// carry: the active key and any key still in its overlap.
func (s *Server) verificationKeys() map[string]ed25519.PublicKey {
	if s.config.SigningSource != nil {
		return s.config.SigningSource.Public()
	}
	if len(s.config.AuthorizationSigningKey) != ed25519.PrivateKeySize {
		return map[string]ed25519.PublicKey{}
	}
	return map[string]ed25519.PublicKey{s.config.AuthorizationSigningKeyID: s.config.AuthorizationSigningKey.Public().(ed25519.PublicKey)}
}
