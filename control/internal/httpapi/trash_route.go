package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The trash of a mount holds what was deleted there. The Control Tower decides
// by the path an entry had, with the same rules as for the file itself, so
// nobody sees, restores or purges what they could not have read, created or
// deleted at that path. The routes are handled here and never passed through.

type trashEntry struct {
	ID        string          `json:"trash_id"`
	MountID   string          `json:"mount_id"`
	Path      string          `json:"path"`
	Type      string          `json:"type"`
	Size      int64           `json:"size,omitempty"`
	State     string          `json:"state"`
	DeletedAt time.Time       `json:"deleted_at"`
	ExpiresAt time.Time       `json:"expires_at"`
	Raw       json.RawMessage `json:"-"`
}

// trashRoute recognises the trash routes of a mount. A path that names the
// trash but is none of them is reported as unknown, never passed to the node.
func trashRoute(resource, method string) (kind, id string, known, ok bool) {
	parts := strings.Split(resource, "/")
	if len(parts) < 3 || parts[0] != "mounts" || parts[2] != "trash" {
		return "", "", false, false
	}
	switch {
	case len(parts) == 3 && method == http.MethodGet:
		return "list", "", true, true
	case len(parts) == 4 && method == http.MethodGet:
		return "get", parts[3], true, true
	case len(parts) == 4 && method == http.MethodDelete:
		return "purge", parts[3], true, true
	case len(parts) == 5 && parts[4] == "restore" && method == http.MethodPost:
		return "restore", parts[3], true, true
	}
	return "", "", true, false
}

var trashCapability = map[string]string{"list": "read", "get": "read", "restore": "create", "purge": "delete"}

func (s *Server) proxyTrash(w http.ResponseWriter, r *http.Request, resource, kind, trashID string) {
	nodeID, mountID := r.PathValue("nodeID"), mountIDFromResource(resource)
	if r.Context().Value(agentKey) != nil {
		writeError(w, r, http.StatusForbidden, "trash_not_for_agents", "Agentes não acessam a lixeira.")
		return
	}
	if !validPathIdentifier(mountID) || kind != "list" && !validPathIdentifier(trashID) {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "Identificador inválido.")
		return
	}
	node, err := s.store.GetNode(r.Context(), nodeID)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "node_not_found", "Node não encontrado.")
		return
	}
	var info struct {
		NodeID       string   `json:"node_id"`
		Capabilities []string `json:"capabilities"`
	}
	if err := s.callNodeJSON(r.Context(), node, http.MethodGet, "/api/v1/node", nil, &info, r.Header.Get("X-Correlation-ID")); err != nil {
		writeError(w, r, http.StatusBadGateway, "node_unavailable", "Não foi possível consultar o node.")
		return
	}
	supported := false
	for _, capability := range info.Capabilities {
		supported = supported || capability == "trash_v1"
	}
	if info.NodeID != node.ID || !supported {
		writeError(w, r, http.StatusConflict, "node_upgrade_required", "Atualize o node para usar a lixeira.")
		return
	}
	base := "/api/v1/mounts/" + url.PathEscape(mountID) + "/trash"
	scopeBase := "nodes/" + node.ID + "/files/mounts/" + mountID
	allowed := func(entry trashEntry, capability string) bool {
		scope := fileScope(scopeBase, entry.Path)
		return scope != "" && s.transferCapabilityAllowed(r, scope, capability)
	}
	correlation := r.Header.Get("X-Correlation-ID")
	if kind == "list" {
		var answer struct {
			Items []json.RawMessage `json:"items"`
		}
		if err := s.callNodeJSON(r.Context(), node, http.MethodGet, base, nil, &answer, correlation); err != nil {
			s.writeTrashError(w, r, err)
			return
		}
		visible := make([]json.RawMessage, 0, len(answer.Items))
		for _, raw := range answer.Items {
			var entry trashEntry
			if json.Unmarshal(raw, &entry) == nil && entry.MountID == mountID && allowed(entry, "read") {
				visible = append(visible, raw)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": visible})
		return
	}
	var raw json.RawMessage
	var entry trashEntry
	if err := s.callNodeJSON(r.Context(), node, http.MethodGet, base+"/"+url.PathEscape(trashID), nil, &raw, correlation); err != nil {
		s.writeTrashError(w, r, err)
		return
	}
	if json.Unmarshal(raw, &entry) != nil || entry.ID != trashID || entry.MountID != mountID || entry.State != "stored" {
		writeError(w, r, http.StatusBadGateway, "invalid_trash_entry", "O node devolveu uma entrada inválida.")
		return
	}
	capability := trashCapability[kind]
	scope := fileScope(scopeBase, entry.Path)
	if scope == "" {
		writeError(w, r, http.StatusBadGateway, "invalid_trash_entry", "O node devolveu uma entrada inválida.")
		return
	}
	// Reading an entry the caller may not see answers as if it were not there.
	if kind == "get" && !allowed(entry, "read") {
		s.audit(r, "read", scope, "denied")
		writeError(w, r, http.StatusNotFound, "trash_not_found", "Entrada da lixeira não encontrada.")
		return
	}
	if kind != "get" && !s.authorize(w, r, scope, capability, "permission_denied", "A policy atual não permite esta operação na lixeira.") {
		return
	}
	if kind == "get" {
		writeJSON(w, http.StatusOK, raw)
		return
	}
	method, path := http.MethodDelete, base+"/"+url.PathEscape(trashID)
	if kind == "restore" {
		method, path = http.MethodPost, path+"/restore"
	}
	var result json.RawMessage
	if err := s.callNodeJSON(r.Context(), node, method, path, nil, &result, correlation); err != nil {
		s.writeTrashError(w, r, err)
		return
	}
	s.audit(r, kind, "nodes/"+node.ID+"/"+resource, "allowed")
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) writeTrashError(w http.ResponseWriter, r *http.Request, err error) {
	var apiErr *nodeAPIError
	if errors.As(err, &apiErr) {
		switch apiErr.StatusCode {
		case http.StatusNotFound:
			writeError(w, r, http.StatusNotFound, "trash_not_found", "Entrada da lixeira não encontrada, ou a pasta onde ela estava não existe mais.")
			return
		case http.StatusConflict:
			if apiErr.Code == "trash_unavailable" {
				writeError(w, r, http.StatusConflict, "trash_unavailable", "A lixeira não pode guardar esta entrada.")
				return
			}
			writeError(w, r, http.StatusConflict, "conflict", "Já existe algo com o nome original. Renomeie ou remova antes de restaurar.")
			return
		case http.StatusForbidden:
			if apiErr.Code == "mount_locked" {
				writeError(w, r, http.StatusForbidden, "mount_locked", lockedMountMessage)
				return
			}
			writeError(w, r, http.StatusForbidden, "mount_read_only", "O mount não permite alterações.")
			return
		case http.StatusUnprocessableEntity:
			writeError(w, r, http.StatusUnprocessableEntity, "hidden_name", "O nome original agora é oculto por configuração do mount.")
			return
		}
	}
	writeError(w, r, http.StatusBadGateway, "node_unavailable", "Não foi possível consultar a lixeira do node.")
}
