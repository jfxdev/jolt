package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

type uploadSessionView struct {
	ID           string  `json:"upload_id"`
	MountID      string  `json:"mount_id"`
	Destination  string  `json:"destination_path"`
	Overwrite    *bool   `json:"overwrite"`
	ActorID      *string `json:"authorization_actor_id"`
	CredentialID *string `json:"authorization_credential_id"`
	Revision     *uint64 `json:"authorization_revision"`
}

// Resolve an upload ID through the node's persisted session, never through a
// client-supplied ?path=. The returned targets are the sole source for RBAC.
func (s *Server) uploadTargets(w http.ResponseWriter, r *http.Request, resource string) (fileTargets, bool, bool) {
	parts := strings.Split(resource, "/")
	if len(parts) < 4 || parts[0] != "mounts" || parts[2] != "files" || parts[3] != "uploads" {
		return fileTargets{}, false, true
	}
	if len(parts) == 4 && r.Method != http.MethodGet {
		return fileTargets{}, false, true
	}
	node, err := s.store.GetNode(r.Context(), r.PathValue("nodeID"))
	if err != nil {
		writeError(w, r, http.StatusNotFound, "node_not_found", "Node não encontrado.")
		return fileTargets{}, true, false
	}
	if len(parts) == 4 {
		var response struct {
			Sessions []json.RawMessage `json:"sessions"`
		}
		if err := s.callNodeJSON(r.Context(), node, http.MethodGet, "/api/v1/"+resource, nil, &response, r.Header.Get("X-Correlation-ID")); err != nil {
			s.writeUploadLookupError(w, r, err)
			return fileTargets{}, true, false
		}
		visible := make([]json.RawMessage, 0, len(response.Sessions))
		for _, raw := range response.Sessions {
			var session uploadSessionView
			if json.Unmarshal(raw, &session) != nil || session.MountID != parts[1] {
				continue
			}
			scope := fileScope("nodes/"+node.ID+"/files/mounts/"+parts[1], session.Destination)
			if scope != "" && s.transferCapabilityAllowed(r, scope, "create") {
				visible = append(visible, raw)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"sessions": visible})
		return fileTargets{}, true, true
	}
	if len(parts) > 6 || len(parts) == 6 && (parts[5] != "complete" && parts[5] != "verification" && parts[5] != "authorize") {
		writeError(w, r, http.StatusNotFound, "resource_not_found", "Recurso não encontrado.")
		return fileTargets{}, true, false
	}
	var session uploadSessionView
	lookup := "/api/v1/mounts/" + url.PathEscape(parts[1]) + "/files/uploads/" + url.PathEscape(parts[4])
	reauthorize := len(parts) == 6 && parts[5] == "authorize" && r.Method == http.MethodPost
	var headers http.Header
	if reauthorize {
		if !s.config.SignedUploads {
			writeError(w, r, http.StatusConflict, "signed_upload_unavailable", "A reautorização de uploads assinados não está habilitada.")
			return fileTargets{}, true, false
		}
		headers = http.Header{"X-Jolt-Internal-Upload-Binding": []string{"1"}}
	}
	if err := s.callNodeJSONWithHeaders(r.Context(), node, http.MethodGet, lookup, nil, &session, r.Header.Get("X-Correlation-ID"), headers); err != nil {
		s.writeUploadLookupError(w, r, err)
		return fileTargets{}, true, false
	}
	if reauthorize && (session.ActorID == nil || session.CredentialID == nil || session.Revision == nil || (*session.ActorID == "") != (*session.CredentialID == "")) {
		writeError(w, r, http.StatusConflict, "node_upgrade_required", "O node não informou o vínculo de autorização. Atualize o node.")
		return fileTargets{}, true, false
	}
	if session.ID != parts[4] || session.MountID != parts[1] || session.Destination == "" {
		writeError(w, r, http.StatusBadGateway, "invalid_upload_session", "O node retornou uma sessão inválida.")
		return fileTargets{}, true, false
	}
	if session.Overwrite == nil && (r.Method == http.MethodPost || r.Method == http.MethodPatch) {
		writeError(w, r, http.StatusConflict, "node_upgrade_required", "O node não informou se o upload sobrescreve o destino. Atualize o node.")
		return fileTargets{}, true, false
	}
	overwrite := session.Overwrite != nil && *session.Overwrite
	targets := fileTargets{Paths: []string{session.Destination}, Overwrite: overwrite}
	if reauthorize {
		targets.PreviousActorID, targets.PreviousCredentialID = *session.ActorID, *session.CredentialID
		targets.AuthorizationRevision = *session.Revision
	}
	return targets, false, true
}

func (s *Server) writeUploadLookupError(w http.ResponseWriter, r *http.Request, err error) {
	var apiErr *nodeAPIError
	if errors.As(err, &apiErr) {
		if apiErr.StatusCode == http.StatusNotFound {
			writeError(w, r, http.StatusNotFound, "upload_not_found", "Upload não encontrado no node.")
			return
		}
		if apiErr.StatusCode == http.StatusGone {
			writeError(w, r, http.StatusGone, "upload_expired", "Este envio expirou. Verifique o destino antes de iniciar um novo envio.")
			return
		}
		if apiErr.StatusCode == http.StatusUnprocessableEntity && apiErr.Code == "upload_content_rejected" {
			writeError(w, r, http.StatusUnprocessableEntity, "upload_content_rejected", "O conteúdo enviado foi recusado pela inspeção.")
			return
		}
	}
	writeError(w, r, http.StatusBadGateway, "node_unavailable", "Não foi possível consultar os uploads deste node.")
}
