package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/jfxdev/jolt/control/internal/filetypes"
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/store"
)

type signedJobAuthorizationStatus struct {
	Revision uint64
	Expiry   time.Time
	Digest   string
}

// signedJobStatus only observes a node's persisted revision. A caller must
// compare it to its own durable pending envelope and recheck the actor's
// current authorization before using it for reconciliation.
func (s *Server) signedJobStatus(r *http.Request, node store.Node, jobID string) (signedJobAuthorizationStatus, error) {
	fail := func() (signedJobAuthorizationStatus, error) {
		return signedJobAuthorizationStatus{}, errSignedJobRegistrationUnavailable
	}
	if !validPathIdentifier(node.ID) || !validPathIdentifier(jobID) {
		return fail()
	}
	var info struct {
		NodeID       string   `json:"node_id"`
		Capabilities []string `json:"capabilities"`
	}
	if err := s.callNodeJSON(r.Context(), node, http.MethodGet, "/api/v1/node", nil, &info, r.Header.Get("X-Correlation-ID")); err != nil {
		return fail()
	}
	supported := false
	for _, capability := range info.Capabilities {
		supported = supported || capability == "signed_job_authorization_status_v1"
	}
	if info.NodeID != node.ID || !supported {
		return fail()
	}
	nodeToken, err := security.Decrypt(s.config.EncryptionKey, node.TokenEncrypted)
	if err != nil {
		return fail()
	}
	request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, node.Endpoint+"/api/v1/jobs/"+url.PathEscape(jobID)+"/authorization", nil)
	if err != nil {
		return fail()
	}
	request.Header.Set("Authorization", "Bearer "+nodeToken)
	request.Header.Set("X-Correlation-ID", r.Header.Get("X-Correlation-ID"))
	response, err := s.client.Do(request)
	if err != nil {
		return fail()
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || len(response.Header.Values("X-Jolt-Job-Authorization-Status")) != 1 || response.Header.Get("X-Jolt-Job-Authorization-Status") != "v1" {
		return fail()
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(body) > 64*1024 || filetypes.ValidateUniqueJSON(body) != nil {
		return fail()
	}
	var result struct {
		Revision         *uint64         `json:"revision"`
		ExpiresAt        json.RawMessage `json:"expires_at"`
		Digest           *string         `json:"envelope_digest"`
		ExecutionEnabled *bool           `json:"execution_enabled"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF || result.Revision == nil || len(result.ExpiresAt) == 0 || result.Digest == nil || result.ExecutionEnabled == nil || r.Context().Err() != nil {
		return fail()
	}
	status := signedJobAuthorizationStatus{Revision: *result.Revision, Digest: *result.Digest}
	if status.Revision == 0 {
		if string(result.ExpiresAt) != "null" || status.Digest != "" {
			return fail()
		}
		return status, nil
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(status.Digest)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != status.Digest || json.Unmarshal(result.ExpiresAt, &status.Expiry) != nil || status.Expiry.IsZero() {
		return fail()
	}
	return status, nil
}

type signedJobReconciliation int

const (
	signedJobSynchronized signedJobReconciliation = iota
	signedJobPendingDelivery
	signedJobConfirmed
	signedJobExpiredResolved
)

// reconcileSignedJobAuthorization never sends or renews a lease. A caller
// must re-evaluate current permissions before any subsequent delivery.
func (s *Server) reconcileSignedJobAuthorization(r *http.Request, node store.Node, jobID string) (signedJobReconciliation, error) {
	status, err := s.signedJobStatus(r, node, jobID)
	if err != nil {
		return 0, errSignedJobRegistrationUnavailable
	}
	link, err := s.store.GetJobAuthorizationLink(r.Context(), node.ID, jobID)
	if err != nil {
		return 0, errSignedJobRegistrationUnavailable
	}
	if link.PendingRevision != 0 && !link.PendingExpiry.After(time.Now().UTC()) {
		if err := s.store.ResolveExpiredJobAuthorization(r.Context(), node.ID, jobID, status.Revision, status.Digest, status.Expiry, time.Now().UTC()); err != nil {
			return 0, errSignedJobRegistrationUnavailable
		}
		return signedJobExpiredResolved, nil
	}
	if link.PendingRevision != 0 && status.Revision == link.PendingRevision && status.Digest == security.Digest(link.PendingEnvelope) && status.Expiry.Equal(link.PendingExpiry) {
		if err := s.store.ConfirmJobAuthorization(r.Context(), node.ID, jobID, status.Revision, status.Digest, status.Expiry, time.Now().UTC()); err != nil {
			return 0, errSignedJobRegistrationUnavailable
		}
		return signedJobConfirmed, nil
	}
	if status.Revision != link.ConfirmedRevision || status.Digest != link.ConfirmedDigest || !status.Expiry.Equal(link.ConfirmedExpiry) {
		return 0, errSignedJobRegistrationUnavailable
	}
	if link.PendingRevision != 0 {
		return signedJobPendingDelivery, nil
	}
	return signedJobSynchronized, nil
}
