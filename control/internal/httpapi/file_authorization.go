package httpapi

import (
	"net/http"
	"strings"
)

// The node executes whole trees without knowing the operator's policies. Fail
// closed if any descendant is denied, on both read and mutation paths.
func (s *Server) authorizeFileTree(w http.ResponseWriter, r *http.Request, scope, capability string) bool {
	if scope == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_path", "Caminho inválido.")
		return false
	}
	if !s.authorize(w, r, scope, capability, "permission_denied", "A policy atual não permite esta operação de arquivo.") {
		return false
	}
	return s.authorizeTreeContents(w, r, scope)
}

func (s *Server) authorizeTreeContents(w http.ResponseWriter, r *http.Request, scope string) bool {
	denied, err := s.deniesWithinScope(r, scope)
	if err != nil {
		s.fail(w, r, err)
		return false
	}
	if denied {
		s.audit(r, "access", scope, "denied")
		writeError(w, r, http.StatusForbidden, "deny_rule_within_scope", "Há regras de negação dentro desta pasta. Selecione uma subpasta permitida.")
		return false
	}
	return true
}

func treeMutationResource(resource, method string) bool {
	segments := strings.Split(strings.Trim(resource, "/"), "/")
	if len(segments) < 3 || segments[0] != "mounts" || segments[2] != "files" {
		return false
	}
	return method == http.MethodDelete && len(segments) == 3 ||
		method == http.MethodPost && len(segments) >= 4 && (segments[3] == "copy" || segments[3] == "move")
}
