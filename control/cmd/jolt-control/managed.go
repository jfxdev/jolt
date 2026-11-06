package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/jfxdev/jolt/control/internal/config"
	"github.com/jfxdev/jolt/control/internal/pki"
	"github.com/jfxdev/jolt/control/internal/store"
)

// authorityInterval is how often the managed authority looks for something to
// renew. Renewal happens at two thirds of a lifetime, so an hour is far finer
// than needed and a missed pass costs nothing.
const authorityInterval = time.Hour

// startAuthority builds the Control Tower's own certificate authority, brings
// it up to date, and wires it in as the source of the signing key. It returns
// nil in manual mode.
func startAuthority(ctx context.Context, cfg *config.Config, storage *store.Store, logger *slog.Logger) (*pki.Manager, error) {
	if cfg.TLSMode != config.TLSManaged {
		return nil, nil
	}
	authority, err := pki.NewManager(storage, pki.Options{Key: cfg.EncryptionKey, Names: cfg.TLSNames, LeafValidity: cfg.CertificateValidity})
	if err != nil {
		return nil, err
	}
	if err := authority.Ensure(ctx); err != nil {
		return nil, err
	}
	cfg.Authority, cfg.SigningSource = authority, authority
	go authority.Run(ctx, authorityInterval, func(err error) {
		if errors.Is(err, pki.ErrRootUnavailable) {
			logger.Warn("the intermediate certificate is due for renewal and the root key is not in the database; restore it to renew")
			return
		}
		logger.Error("certificate authority pass failed", "error", err)
	})
	logger.Info("managed certificate authority ready", "root_sha256", authority.RootFingerprint())
	return authority, nil
}

// withRootDownload lets the HTTPS listener also serve the public root, so a
// client that already reaches the Control Tower can fetch it from there.
func withRootDownload(authority *pki.Manager, next http.Handler) http.Handler {
	public := pki.PublicHandler(authority)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jolt/ca.pem" {
			public.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// publicRootServer is the plain-HTTP listener that serves only the public root
// and its fingerprint. A person needs it before the browser trusts the root.
func publicRootServer(authority *pki.Manager, address string) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           pki.PublicHandler(authority),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
}
