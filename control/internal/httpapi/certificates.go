package httpapi

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jfxdev/jolt/control/internal/pki"
)

const certificateResource = "control-tower/crypto"

// certificateKinds are the series the expiry gauge reports. One series per kind
// keeps a retired certificate that expires as planned from looking like an
// outage, and keeps the label set fixed.
var certificateKinds = []string{"root", "intermediate", "https", "client", "signing_key"}

// authority returns the managed authority or answers that there is none.
func (s *Server) authority(w http.ResponseWriter, r *http.Request) *pki.Manager {
	if s.config.Authority == nil {
		writeError(w, r, http.StatusNotFound, "managed_tls_disabled", "Os certificados gerenciados não estão habilitados neste Control Tower.")
		return nil
	}
	return s.config.Authority
}

type certificateInventory struct {
	Mode               string     `json:"mode"`
	RootFingerprint    string     `json:"root_fingerprint"`
	RootFingerprintFmt string     `json:"root_fingerprint_display"`
	BundleVersion      int64      `json:"bundle_version"`
	Items              []pki.Item `json:"items"`
	// Rotation is where a root rotation stands; NextRootFingerprintFmt is the
	// root people install from /ca before it is promoted.
	Rotation               pki.Rotation  `json:"rotation"`
	NextRootFingerprintFmt string        `json:"next_root_fingerprint_display,omitempty"`
	Nodes                  []nodeCertRow `json:"nodes"`
}

// nodeCertRow is what the inventory says about an enrolled node: which bundle
// it holds, when its certificate ends, how it authenticates the Control Tower
// and what went wrong the last time.
type nodeCertRow struct {
	NodeID        string     `json:"node_id"`
	Name          string     `json:"name"`
	BundleVersion int64      `json:"bundle_version"`
	BundleBehind  int64      `json:"bundle_behind"`
	CertSerial    string     `json:"cert_serial"`
	CertNotAfter  time.Time  `json:"cert_not_after"`
	AuthMode      string     `json:"auth_mode,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
	LastErrorAt   *time.Time `json:"last_error_at,omitempty"`
}

// listCertificates is the inventory: what exists, who issued it and when it
// ends. It never carries a key.
func (s *Server) listCertificates(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, "read", certificateResource) {
		return
	}
	authority := s.authority(w, r)
	if authority == nil {
		return
	}
	fingerprint := authority.RootFingerprint()
	bundle := authority.Bundle()
	rows := []nodeCertRow{}
	managed, err := s.store.ListManagedNodes(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, record := range managed {
		name := record.NodeID
		if node, err := s.store.GetNode(r.Context(), record.NodeID); err == nil {
			name = node.Name
		}
		behind := bundle.Version - record.BundleVersion
		if behind < 0 {
			behind = 0
		}
		rows = append(rows, nodeCertRow{NodeID: record.NodeID, Name: name, BundleVersion: record.BundleVersion, BundleBehind: behind, CertSerial: record.CertSerial,
			CertNotAfter: record.CertNotAfter, AuthMode: record.AuthMode, LastError: record.LastError, LastErrorAt: record.LastErrorAt})
	}
	rotation := authority.Rotation()
	next := ""
	if rotation.Next != "" {
		next = pki.DisplayFingerprint(rotation.Next)
	}
	writeJSON(w, http.StatusOK, certificateInventory{
		Mode: "managed", RootFingerprint: fingerprint, RootFingerprintFmt: pki.DisplayFingerprint(fingerprint),
		BundleVersion: bundle.Version, Items: authority.Inventory(), Rotation: rotation, NextRootFingerprintFmt: next, Nodes: rows,
	})
}

// trustBundle is the signed bundle a node adopts.
func (s *Server) trustBundle(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, "read", certificateResource) {
		return
	}
	authority := s.authority(w, r)
	if authority == nil {
		return
	}
	writeJSON(w, http.StatusOK, authority.Bundle())
}

type authorizationKeyView struct {
	ID       string    `json:"id"`
	Key      string    `json:"key"`
	NotAfter time.Time `json:"not_after"`
}

type authorizationKeys struct {
	SigningKeyID string                 `json:"signing_key_id"`
	Keys         []authorizationKeyView `json:"keys"`
	// NodeYAML is the block a node's YAML takes while it still trusts keys from
	// its own configuration.
	NodeYAML string `json:"node_yaml"`
}

// authorizationKeysSnippet gives the public keys in the form node.yaml takes,
// so no one has to run openssl to configure a node by hand.
func (s *Server) authorizationKeysSnippet(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, "read", certificateResource) {
		return
	}
	authority := s.authority(w, r)
	if authority == nil {
		return
	}
	bundle := authority.Bundle()
	id, _ := authority.Current()
	out := authorizationKeys{SigningKeyID: id}
	var yaml strings.Builder
	yaml.WriteString("authorization_public_keys:\n")
	for _, key := range bundle.SigningKeys {
		out.Keys = append(out.Keys, authorizationKeyView{ID: key.ID, Key: key.Key, NotAfter: key.NotAfter})
		fmt.Fprintf(&yaml, "  - id: %s\n    key: %q\n", key.ID, key.Key)
	}
	out.NodeYAML = yaml.String()
	writeJSON(w, http.StatusOK, out)
}

// refreshCertificateMetrics sets the gauges from the authority's inventory.
func (s *Server) refreshCertificateMetrics(now time.Time) {
	if s.registry == nil || s.config.Authority == nil {
		return
	}
	soonest := map[string]float64{}
	for _, item := range s.config.Authority.Inventory() {
		// A retired or pending entry is expected to end; only what is in use
		// is a reason to alert.
		if item.State != "active" {
			continue
		}
		remaining := item.NotAfter.Sub(now).Seconds()
		if current, ok := soonest[item.Kind]; !ok || remaining < current {
			soonest[item.Kind] = remaining
		}
	}
	for _, kind := range certificateKinds {
		if remaining, ok := soonest[kind]; ok {
			s.registry.SetGauge("jolt_certificate_expiry_seconds", int64(remaining), kind)
		}
	}
	s.registry.SetGauge("jolt_trust_bundle_version", s.config.Authority.Bundle().Version)
	stored := int64(0)
	if s.config.Authority.RootKeyInDatabase() {
		stored = 1
	}
	s.registry.SetGauge("jolt_root_key_in_database", stored)
}

// runCertificateMetrics keeps the gauges current until ctx ends.
func (s *Server) runCertificateMetrics(done <-chan struct{}) {
	s.refreshCertificateMetrics(time.Now())
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case now := <-ticker.C:
			s.refreshCertificateMetrics(now)
		}
	}
}
