package httpapi

import (
	"context"
	"net/url"
	"time"

	"github.com/jfxdev/jolt/control/internal/pki"
	"github.com/jfxdev/jolt/control/internal/store"
)

// managedSyncInterval is how often the Control Tower looks at the nodes it
// enrolled. A bundle or a renewal that waits a minute costs nothing: both are
// planned well ahead of when they matter.
const managedSyncInterval = time.Minute

type nodeTrustStatus struct {
	BundleVersion  int64 `json:"bundle_version"`
	APICertificate struct {
		NotAfter time.Time `json:"not_after"`
		Serial   string    `json:"serial"`
	} `json:"api_certificate"`
}

// runManagedSync keeps every enrolled node current until done is closed: it
// pushes a bundle a node is behind on, renews an API certificate at two thirds
// of its life, and lets enrollments nobody decided expire.
func (s *Server) runManagedSync(done <-chan struct{}) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-done
		cancel()
	}()
	s.syncManagedNodes(ctx, time.Now().UTC())
	ticker := time.NewTicker(managedSyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.syncManagedNodes(ctx, now.UTC())
		}
	}
}

// syncManagedNodes is one pass of runManagedSync. A node that cannot be
// reached or refuses something is recorded and the pass moves on to the next:
// one node must never keep the others from their renewals.
func (s *Server) syncManagedNodes(ctx context.Context, now time.Time) {
	authority := s.config.Authority
	if authority == nil {
		return
	}
	if _, err := s.store.ExpireEnrollments(ctx, now); err != nil {
		s.log.Error("expire enrollments", "error", err)
	}
	managed, err := s.store.ListManagedNodes(ctx)
	if err != nil {
		s.log.Error("list managed nodes", "error", err)
		return
	}
	var lag int64
	soonest := time.Duration(-1)
	for _, record := range managed {
		record = s.syncManagedNode(ctx, authority, record, now)
		if behind := authority.Bundle().Version - record.BundleVersion; behind > lag {
			lag = behind
		}
		if left := record.CertNotAfter.Sub(now); soonest < 0 || left < soonest {
			soonest = left
		}
	}
	if s.registry != nil {
		s.registry.SetGauge("jolt_managed_nodes", int64(len(managed)))
		s.registry.SetGauge("jolt_managed_node_bundle_lag", lag)
		if soonest >= 0 || len(managed) > 0 {
			s.registry.SetGauge("jolt_managed_node_certificate_expiry_seconds", int64(soonest.Seconds()))
		}
	}
}

func (s *Server) syncManagedNode(ctx context.Context, authority *pki.Manager, record store.ManagedNode, now time.Time) store.ManagedNode {
	node, err := s.store.GetNode(ctx, record.NodeID)
	if err != nil {
		return record
	}
	fail := func(step string, err error) store.ManagedNode {
		record.LastError, record.LastErrorAt = step+": "+err.Error(), &now
		if saveErr := s.store.SaveManagedNode(ctx, record); saveErr != nil {
			s.log.Error("record managed node error", "node_id", record.NodeID, "error", saveErr)
		}
		s.log.Warn("managed node sync failed", "node_id", record.NodeID, "step", step, "error", err.Error())
		return record
	}
	correlation := randomID("cor")
	var status nodeTrustStatus
	if err := s.callNodeJSON(ctx, node, "GET", "/api/v1/crypto/trust-bundle", nil, &status, correlation); err != nil {
		return fail("read the node's trust state", err)
	}
	record.BundleVersion = status.BundleVersion
	if bundle := authority.Bundle(); status.BundleVersion < bundle.Version {
		if err := s.callNodeJSON(ctx, node, "PUT", "/api/v1/crypto/trust-bundle", bundle, nil, correlation); err != nil {
			return fail("send the trust bundle", err)
		}
		record.BundleVersion = bundle.Version
	}
	if status.APICertificate.Serial != "" && status.APICertificate.Serial != record.CertSerial {
		// The node holds a certificate this record does not know, such as one
		// installed just before a crash. Believe the node about its own.
		record.CertSerial, record.CertNotAfter = status.APICertificate.Serial, status.APICertificate.NotAfter
		record.CertNotBefore = status.APICertificate.NotAfter.Add(-90 * 24 * time.Hour)
	}
	if pki.RenewalDue(record.CertNotBefore, record.CertNotAfter, now) {
		endpoint, _ := url.Parse(node.Endpoint)
		host := endpoint.Hostname()
		var request struct {
			CSR string `json:"csr_pem"`
		}
		if err := s.callNodeJSON(ctx, node, "POST", "/api/v1/crypto/api-cert/csr", map[string][]string{"names": {host}}, &request, correlation); err != nil {
			return fail("ask the node for a certificate request", err)
		}
		chain, leaf, err := authority.IssueServerCertificate([]byte(request.CSR), node.ID, host)
		if err != nil {
			return fail("issue the node's certificate", err)
		}
		if err := s.callNodeJSON(ctx, node, "PUT", "/api/v1/crypto/api-cert", map[string]string{"certificate_pem": chain}, nil, correlation); err != nil {
			return fail("install the node's certificate", err)
		}
		record.CertSerial, record.CertNotBefore, record.CertNotAfter = leaf.SerialNumber.Text(16), leaf.NotBefore, leaf.NotAfter
		s.store.Audit(ctx, "", "renew", "nodes/"+node.ID+"/api-certificate", "allowed", correlation)
	}
	record.LastError, record.LastErrorAt = "", nil
	if err := s.store.SaveManagedNode(ctx, record); err != nil {
		s.log.Error("save managed node", "node_id", record.NodeID, "error", err)
	}
	return record
}
