package peers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jfxdev/jolt/backend/internal/contracts"
	"github.com/jfxdev/jolt/backend/internal/entities"
	joltcrypto "github.com/jfxdev/jolt/backend/internal/infra/crypto"
	"github.com/jfxdev/jolt/backend/internal/infra/db"
)

type Monitor struct {
	store            contracts.Store
	certificates     *joltcrypto.CertificateManager
	interval         time.Duration
	timeout          time.Duration
	failureThreshold int
	logger           *slog.Logger
	now              func() time.Time
	dialContext      func(context.Context, string, string) (net.Conn, error)
	onPeerOnline     func(context.Context, string)
}

func (m *Monitor) ConfigurePeerOnline(callback func(context.Context, string)) {
	m.onPeerOnline = callback
}

func (m *Monitor) ConfigureDialContext(dial func(context.Context, string, string) (net.Conn, error)) {
	m.dialContext = dial
}

func NewMonitor(store contracts.Store, certificates *joltcrypto.CertificateManager, interval, timeout time.Duration, failureThreshold int, logger *slog.Logger) *Monitor {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if failureThreshold <= 0 {
		failureThreshold = 3
	}
	return &Monitor{
		store: store, certificates: certificates, interval: interval, timeout: timeout,
		failureThreshold: failureThreshold, logger: logger, now: func() time.Time { return time.Now().UTC() },
	}
}

func (m *Monitor) Run(ctx context.Context) {
	m.checkAll(ctx)
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.checkAll(ctx)
		}
	}
}

func (m *Monitor) checkAll(ctx context.Context) {
	items, err := m.store.ListPeers(ctx)
	if err != nil {
		m.logger.Error("list peers for heartbeat", "error", err)
		return
	}
	for _, peer := range items {
		if ctx.Err() != nil {
			return
		}
		if peer.MTLSEndpoint == "" || peer.State == "untrusted" || peer.State == "identity_changed" ||
			peer.State == "revoked" {
			continue
		}
		m.check(ctx, peer)
	}
}

func (m *Monitor) check(parent context.Context, peer entities.Peer) {
	ctx, cancel := context.WithTimeout(parent, m.timeout)
	defer cancel()
	observedNext, err := m.heartbeat(ctx, peer)
	if err == nil {
		now := m.now()
		if observedNext && peer.PreviousFingerprint != "" {
			if confirmErr := m.store.ConfirmPeerIdentityHandover(parent, peer.NodeID,
				peer.IdentityEpoch, peer.Fingerprint); confirmErr != nil && !errors.Is(confirmErr, db.ErrNotFound) {
				m.logger.Error("confirm peer identity handover", "peer_node_id", peer.NodeID, "error", confirmErr)
			}
		}
		if updateErr := m.store.UpdatePeerHealth(parent, peer.NodeID, "online", &now, 0); updateErr != nil {
			m.logger.Error("persist peer heartbeat", "peer_node_id", peer.NodeID, "error", updateErr)
		} else if m.onPeerOnline != nil {
			m.onPeerOnline(parent, peer.NodeID)
		}
		return
	}
	failures := peer.ConsecutiveFailures + 1
	state := "degraded"
	if errors.Is(err, joltcrypto.ErrCertificateInvalid) {
		state = "identity_changed"
	} else if errors.Is(err, joltcrypto.ErrCertificateRevoked) {
		state = "untrusted"
	} else if failures >= m.failureThreshold {
		state = "offline"
	}
	if updateErr := m.store.UpdatePeerHealth(parent, peer.NodeID, state, peer.LastSeenAt, failures); updateErr != nil {
		m.logger.Error("persist failed peer heartbeat", "peer_node_id", peer.NodeID, "error", updateErr)
	}
	m.logger.Warn("peer heartbeat failed", "peer_node_id", peer.NodeID, "state", state, "failures", failures, "error", err)
}

func (m *Monitor) heartbeat(ctx context.Context, peer entities.Peer) (bool, error) {
	endpoint, err := url.Parse(strings.TrimRight(peer.MTLSEndpoint, "/"))
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" {
		return false, fmt.Errorf("invalid peer mTLS endpoint")
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/peer/v1/heartbeat"
	transport := &http.Transport{
		TLSClientConfig:     m.certificates.ClientTLSConfig(peer.NodeID, peer.Fingerprint, peer.PreviousFingerprint),
		DisableCompression:  true,
		IdleConnTimeout:     m.timeout,
		TLSHandshakeTimeout: m.timeout,
	}
	if m.dialContext != nil {
		transport.DialContext = m.dialContext
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return false, err
	}
	response, err := client.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return false, fmt.Errorf("heartbeat returned HTTP %d", response.StatusCode)
	}
	var payload struct {
		Status        string `json:"status"`
		NodeID        string `json:"node_id"`
		Fingerprint   string `json:"fingerprint"`
		IdentityEpoch int    `json:"identity_epoch"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload); err != nil {
		return false, err
	}
	current := payload.Fingerprint == peer.Fingerprint && payload.IdentityEpoch == peer.IdentityEpoch
	previous := peer.PreviousFingerprint != "" && payload.Fingerprint == peer.PreviousFingerprint &&
		payload.IdentityEpoch == peer.IdentityEpoch-1
	if payload.Status != "online" || payload.NodeID != peer.NodeID || (!current && !previous) {
		return false, fmt.Errorf("%w: heartbeat identity payload does not match the trusted identity epoch", joltcrypto.ErrCertificateInvalid)
	}
	return current, nil
}
