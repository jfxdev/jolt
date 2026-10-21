package httpapi

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

type uploadSessionView struct {
	ID          string `json:"upload_id"`
	MountID     string `json:"mount_id"`
	Destination string `json:"destination_path"`
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
			s.writeLogicalTransferNodeError(w, r, err)
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
	if len(parts) > 6 || len(parts) == 6 && parts[5] != "complete" {
		writeError(w, r, http.StatusNotFound, "resource_not_found", "Recurso não encontrado.")
		return fileTargets{}, true, false
	}
	var session uploadSessionView
	lookup := "/api/v1/mounts/" + url.PathEscape(parts[1]) + "/files/uploads/" + url.PathEscape(parts[4])
	if err := s.callNodeJSON(r.Context(), node, http.MethodGet, lookup, nil, &session, r.Header.Get("X-Correlation-ID")); err != nil {
		s.writeLogicalTransferNodeError(w, r, err)
		return fileTargets{}, true, false
	}
	if session.ID != parts[4] || session.MountID != parts[1] || session.Destination == "" {
		writeError(w, r, http.StatusBadGateway, "invalid_upload_session", "O node retornou uma sessão inválida.")
		return fileTargets{}, true, false
	}
	return fileTargets{Paths: []string{session.Destination}}, false, true
}
