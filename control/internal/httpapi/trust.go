package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/jfxdev/jolt/control/internal/store"
)

// Trust status vocabulary. The Control Tower is the only place that can see
// both sides of a pairing, so it classifies the relationship here instead of
// letting every client re-derive it from two peer listings.
const (
	trustConnected        = "connected"
	trustRevokedByPeer    = "revoked_by_peer"
	trustMissingOnPeer    = "missing_on_peer"
	trustIdentityChanged  = "identity_changed"
	trustUnreachable      = "unreachable"
	trustRevokedLocally   = "revoked"
	trustNotRegistered    = "not_registered"
	trustRemoteUnreadable = "remote_unreadable"
)

// trustedPeerState mirrors the node-side predicate in
// node/backend/internal/entities (TrustedPeerState): every state except the
// ones that make the node reject the peer's certificate.
func trustedPeerState(state string) bool {
	switch state {
	case "trusted", "unknown", "online", "offline", "degraded":
		return true
	default:
		return false
	}
}

type trustPeerView struct {
	nodePeer
	RemoteState      string              `json:"remote_state,omitempty"`
	Reciprocal       bool                `json:"reciprocal"`
	TrustStatus      string              `json:"trust_status"`
	AsymmetryReason  string              `json:"asymmetry_reason,omitempty"`
	Registered       bool                `json:"registered"`
	RegisteredNodeID string              `json:"registered_node_id,omitempty"`
	Grants           []nodeTransferGrant `json:"grants"`
}

type trustView struct {
	NodeID string          `json:"node_id"`
	Peers  []trustPeerView `json:"peers"`
	// Invites and Requests are empty when the caller lacks sudo on the node's
	// pairing administration; the flags say so explicitly instead of letting
	// the UI read "none" as "nothing pending".
	Invites        []any              `json:"invites"`
	Requests       []any              `json:"requests"`
	Connections    []store.Connection `json:"connections"`
	CanReadPairing bool               `json:"can_read_pairing"`
	CanListGrants  bool               `json:"can_list_grants"`
}

// classifyTrust turns the two peer rows into a single status. remoteState is
// empty when the peer node is unregistered or its peer listing could not be
// read, and those two cases are deliberately distinct: "the other side dropped
// me" must never be reported as "offline".
func classifyTrust(local nodePeer, remoteState string, registered, remoteReadable bool) (string, string) {
	switch {
	case local.State == "revoked":
		return trustRevokedLocally, trustRevokedLocally
	case local.State == "identity_changed":
		return trustIdentityChanged, trustIdentityChanged
	case local.State == "revoked_by_peer" || local.State == "untrusted":
		return trustRevokedByPeer, trustRevokedByPeer
	case !registered:
		return trustNotRegistered, trustNotRegistered
	case !remoteReadable:
		return trustRemoteUnreadable, trustRemoteUnreadable
	case remoteState == "":
		return trustMissingOnPeer, trustMissingOnPeer
	case remoteState == "revoked":
		return trustRevokedByPeer, trustRevokedByPeer
	case !trustedPeerState(remoteState):
		return trustRevokedByPeer, remoteState
	case local.State == "offline":
		return trustUnreachable, trustUnreachable
	default:
		return trustConnected, ""
	}
}

func (s *Server) nodePeers(ctx context.Context, node store.Node, correlationID string) ([]nodePeer, error) {
	var response struct {
		Items []nodePeer `json:"items"`
	}
	if err := s.callNodeJSON(ctx, node, http.MethodGet, "/api/v1/peers", nil, &response, correlationID); err != nil {
		return nil, err
	}
	return response.Items, nil
}

func (s *Server) nodePairing(ctx context.Context, node store.Node, resource, correlationID string) ([]any, error) {
	var response struct {
		Items []any `json:"items"`
	}
	if err := s.callNodeJSON(ctx, node, http.MethodGet, "/api/v1/pairing/"+resource, nil,
		&response, correlationID); err != nil {
		return nil, err
	}
	if response.Items == nil {
		return []any{}, nil
	}
	return response.Items, nil
}

// nodeTrust is the single source of truth for a node's trust relationships. It
// resolves the counterpart's view server-side, because the Control Tower holds
// both node tokens and the browser cannot be trusted to infer reciprocity from
// two independent listings.
func (s *Server) nodeTrust(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("nodeID")
	if !s.authorize(w, r, "nodes/"+nodeID+"/peers", "list", "permission_denied",
		"A policy atual não permite listar a confiança deste node.") {
		return
	}
	node, err := s.store.GetNode(r.Context(), nodeID)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "node_not_found", "Node não encontrado.")
		return
	}
	correlationID := r.Header.Get("X-Correlation-ID")
	peers, err := s.nodePeers(r.Context(), node, correlationID)
	if err != nil {
		writeError(w, r, http.StatusBadGateway, "node_unavailable", "O node está indisponível.")
		return
	}
	registered, err := s.store.ListNodes(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	nodesByID := make(map[string]store.Node, len(registered))
	for _, item := range registered {
		nodesByID[item.ID] = item
	}
	localNodeID := node.ID
	localIdentityReadable := true
	if len(peers) > 0 {
		if metadata, metadataErr := s.nodeMetadata(r.Context(), node); metadataErr == nil {
			localNodeID = metadata.NodeID
		} else {
			localIdentityReadable = false
		}
	}
	// A persisted registration may predate the node's current ID. Resolve
	// unmatched peer IDs from authenticated metadata, never names or endpoints.
	identitiesResolved := false
	// Composing the view server-side must not widen what the caller may see:
	// grants and pairing material keep their own capability checks.
	canListGrants, err := s.allows(r, "nodes/"+nodeID+"/grants", "list")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	canReadPairing, err := s.allows(r, "nodes/"+nodeID+"/admin/pairing", "sudo")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	grantsByPeer := map[string][]nodeTransferGrant{}
	if canListGrants {
		if grants, grantsErr := s.nodeTransferGrants(r.Context(), node); grantsErr == nil {
			for _, grant := range grants {
				grantsByPeer[grant.PeerNodeID] = append(grantsByPeer[grant.PeerNodeID], grant)
			}
		}
	}
	view := trustView{NodeID: nodeID, Peers: []trustPeerView{}, Invites: []any{}, Requests: []any{}}
	for _, peer := range peers {
		entry := trustPeerView{nodePeer: peer, Grants: grantsByPeer[peer.NodeID]}
		if entry.Grants == nil {
			entry.Grants = []nodeTransferGrant{}
		}
		counterpart, isRegistered := nodesByID[peer.NodeID]
		if !isRegistered && !identitiesResolved {
			for _, item := range registered {
				if metadata, metadataErr := s.nodeMetadata(r.Context(), item); metadataErr == nil {
					nodesByID[metadata.NodeID] = item
				}
			}
			identitiesResolved = true
			counterpart, isRegistered = nodesByID[peer.NodeID]
		}
		entry.Registered = isRegistered
		if isRegistered {
			entry.RegisteredNodeID = counterpart.ID
		}
		remoteReadable := false
		if isRegistered && localIdentityReadable {
			if remotePeers, remoteErr := s.nodePeers(r.Context(), counterpart, correlationID); remoteErr == nil {
				remoteReadable = true
				// The counterpart lists THIS node, so the row to find is
				// keyed by its current authenticated ID, not the peer's ID.
				for _, remote := range remotePeers {
					if remote.NodeID == localNodeID {
						entry.RemoteState = remote.State
						break
					}
				}
			}
		}
		// Nodes retain revoked peer rows to reject their certificates. They
		// are history, not an actionable relationship, once the other node
		// also revoked us or no longer has our row. Keep one-sided and
		// unverifiable revocations visible so removal can still be retried.
		if peer.State == "revoked" && remoteReadable &&
			(entry.RemoteState == "revoked" || entry.RemoteState == "") {
			continue
		}
		entry.Reciprocal = entry.RemoteState != "" && trustedPeerState(entry.RemoteState)
		entry.TrustStatus, entry.AsymmetryReason = classifyTrust(
			peer, entry.RemoteState, isRegistered, remoteReadable)
		view.Peers = append(view.Peers, entry)
	}
	if canReadPairing {
		if invites, inviteErr := s.nodePairing(r.Context(), node, "invites", correlationID); inviteErr == nil {
			view.Invites = invites
		}
		if requests, requestErr := s.nodePairing(r.Context(), node, "requests", correlationID); requestErr == nil {
			view.Requests = requests
		}
	}
	view.CanReadPairing, view.CanListGrants = canReadPairing, canListGrants
	connections, connectionsErr := s.store.ConnectionsForNode(r.Context(), nodeID)
	if connectionsErr != nil {
		s.fail(w, r, connectionsErr)
		return
	}
	view.Connections = connections
	writeJSON(w, http.StatusOK, view)
}

// listConnections exposes the orchestration table that previously had no read
// path at all, which is why a partially_connected connection was invisible.
func (s *Server) listConnections(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "control-tower/connections", "list", "permission_denied",
		"A policy atual não permite listar conexões.") {
		return
	}
	connections, err := s.store.ListConnections(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	allowed := make([]store.Connection, 0, len(connections))
	for _, connection := range connections {
		visible, decisionErr := s.canListBothNodes(r, connection)
		if decisionErr != nil {
			s.fail(w, r, decisionErr)
			return
		}
		if visible {
			allowed = append(allowed, connection)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": allowed})
}

// allows evaluates one capability without writing an error response, for
// composing a view out of parts the caller may only partly be allowed to see.
func (s *Server) allows(r *http.Request, path, capability string) (bool, error) {
	decision, err := s.evaluateAuthorization(r, path, capability)
	if err != nil {
		return false, err
	}
	s.auditAuthorizationDecision(r, decision)
	return decision.Allowed, nil
}

func (s *Server) canListBothNodes(r *http.Request, connection store.Connection) (bool, error) {
	for _, nodeID := range []string{connection.IssuerNodeID, connection.TargetNodeID} {
		decision, err := s.evaluateAuthorization(r, "nodes/"+nodeID, "list")
		if err != nil {
			return false, err
		}
		s.auditAuthorizationDecision(r, decision)
		if !decision.Allowed {
			return false, nil
		}
	}
	return true, nil
}

var reconcilableStatuses = map[string]bool{
	"pending_review":      true,
	"partially_connected": true,
	"connected":           true,
}

// reconcileConnection drives the handshake to completion from whatever state it
// is in. Before this existed, a failed target acceptance left the issuer
// trusting a peer that never trusted it back, and approveConnection answered
// 409 forever.
func (s *Server) reconcileConnection(w http.ResponseWriter, r *http.Request) {
	requestID := r.PathValue("requestID")
	if !s.requireAdmin(w, r, "execute", "control-tower/connections/"+requestID) {
		return
	}
	connection, err := s.store.GetConnection(r.Context(), requestID)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "connection_not_found", "Pedido de conexão não encontrado.")
		return
	}
	if !reconcilableStatuses[connection.Status] {
		writeError(w, r, http.StatusConflict, "connection_not_reconcilable",
			"Este pedido foi rejeitado ou revogado e não pode ser reconciliado.")
		return
	}
	status, approvalErr := s.establishConnection(
		r.Context(), connection, connection.IssuerFingerprint, r.Header.Get("X-Correlation-ID"))
	if approvalErr != nil {
		s.audit(r, "reconcile", "connections/"+connection.RequestID, "denied")
		writeError(w, r, approvalErr.status, approvalErr.code, approvalErr.message)
		return
	}
	s.audit(r, "reconcile", "connections/"+connection.RequestID, "allowed")
	writeJSON(w, http.StatusOK, map[string]any{"status": status, "trust_established": true})
}

type sideResult struct {
	NodeID string `json:"node_id"`
	Done   bool   `json:"done"`
	Error  string `json:"error,omitempty"`
}

// revokeConnection tears trust down on both nodes in one call. The frontend used
// to fire two independent revokePeer calls, so a permission gap or a single
// failure left one side trusting a peer that had already dropped it — exactly
// the asymmetry this endpoint exists to prevent.
func (s *Server) revokeConnection(w http.ResponseWriter, r *http.Request) {
	requestID := r.PathValue("requestID")
	if !s.requireAdmin(w, r, "execute", "control-tower/connections/"+requestID) {
		return
	}
	connection, err := s.store.GetConnection(r.Context(), requestID)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "connection_not_found", "Pedido de conexão não encontrado.")
		return
	}
	issuer, issuerErr := s.store.GetNode(r.Context(), connection.IssuerNodeID)
	target, targetErr := s.store.GetNode(r.Context(), connection.TargetNodeID)
	if issuerErr != nil || targetErr != nil {
		writeError(w, r, http.StatusNotFound, "node_not_found", "Um dos nodes do pedido não está mais cadastrado.")
		return
	}
	issuerMetadata, issuerErr := s.nodeMetadata(r.Context(), issuer)
	targetMetadata, targetErr := s.nodeMetadata(r.Context(), target)
	if issuerErr != nil || targetErr != nil {
		writeError(w, r, http.StatusBadGateway, "node_identity_unavailable",
			"Não foi possível confirmar os IDs atuais dos dois nodes para remover a confiança.")
		return
	}
	correlationID := r.Header.Get("X-Correlation-ID")
	sides := []sideResult{
		s.revokePeerOn(r.Context(), issuer, targetMetadata.NodeID, correlationID),
		s.revokePeerOn(r.Context(), target, issuerMetadata.NodeID, correlationID),
	}
	if sides[0].Done && sides[1].Done {
		if updateErr := s.store.UpdateConnectionStatus(r.Context(), connection.RequestID, "revoked"); updateErr != nil {
			s.fail(w, r, updateErr)
			return
		}
		s.audit(r, "revoke", "connections/"+connection.RequestID, "allowed")
		writeJSON(w, http.StatusOK, map[string]any{"status": "revoked", "sides": sides})
		return
	}
	// A half-done revoke is the dangerous outcome, so it is reported as an
	// error with both sides named instead of a success toast.
	s.audit(r, "revoke", "connections/"+connection.RequestID, "denied")
	writeJSON(w, http.StatusConflict, map[string]any{
		"error": map[string]any{
			"code":    "revoke_incomplete",
			"message": "A confiança não foi removida nos dois nodes. Reconcilie antes de continuar.",
		},
		"sides": sides,
	})
}

// revokePeerOn treats a missing peer row as success: the goal is "this node does
// not trust that node", and a node that never had the row already satisfies it.
func (s *Server) revokePeerOn(ctx context.Context, node store.Node, peerNodeID, correlationID string) sideResult {
	result := sideResult{NodeID: node.ID}
	err := s.callNodeJSON(ctx, node, http.MethodDelete,
		"/api/v1/peers/"+url.PathEscape(peerNodeID), nil, nil, correlationID)
	if err == nil {
		result.Done = true
		return result
	}
	var apiErr *nodeAPIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
		result.Done = true
		return result
	}
	result.Error = err.Error()
	return result
}

func connectionExpired(connection store.Connection) bool {
	return time.Now().UTC().After(connection.ExpiresAt)
}
