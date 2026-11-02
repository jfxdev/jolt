package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jfxdev/jolt/control/internal/store"
)

func (s *Server) temporaryUserPolicies(w http.ResponseWriter, r *http.Request) {
	s.temporarySubjectPolicies(w, r, "user", r.PathValue("userID"))
}

func (s *Server) temporaryServiceAccountPolicies(w http.ResponseWriter, r *http.Request) {
	s.temporarySubjectPolicies(w, r, "service_account", r.PathValue("serviceAccountID"))
}

func (s *Server) temporarySubjectPolicies(w http.ResponseWriter, r *http.Request, subjectType, subjectID string) {
	resource := subjectPolicyResource(subjectType, subjectID)
	if !s.requireAdmin(w, r, "update", resource) {
		return
	}
	if !s.subjectExists(r.Context(), subjectType, subjectID) {
		writeError(w, r, http.StatusNotFound, "subject_not_found", "Usuário ou conta de serviço não encontrado.")
		return
	}
	switch r.Method {
	case http.MethodGet:
		items, err := s.store.TemporaryPolicies(r.Context(), subjectType, subjectID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	case http.MethodPost:
		var input struct {
			PolicyID        string `json:"policy_id"`
			DurationSeconds *int   `json:"duration_seconds"`
		}
		if !decodeJSON(w, r, &input) {
			return
		}
		duration := 900
		if input.DurationSeconds != nil {
			duration = *input.DurationSeconds
		}
		if !validPathIdentifier(strings.TrimSpace(input.PolicyID)) || duration < 1 || duration > 3600 {
			writeError(w, r, http.StatusBadRequest, "invalid_assignment", "Informe uma policy e duração de 1 a 3600 segundos.")
			return
		}
		assignment, err := s.store.GrantTemporaryPolicy(r.Context(), subjectType, subjectID, strings.TrimSpace(input.PolicyID), currentUser(r).ID, currentActorType(r), r.Header.Get("X-Correlation-ID"), time.Duration(duration)*time.Second)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "assignment_target_not_found", "Usuário, conta de serviço ou policy não encontrado.")
			return
		}
		if err != nil {
			s.fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusCreated, assignment)
	case http.MethodDelete:
		err := s.store.RevokeTemporaryPolicy(r.Context(), subjectType, subjectID, r.PathValue("policyID"), currentUser(r).ID, currentActorType(r), r.Header.Get("X-Correlation-ID"))
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "assignment_not_found", "Atribuição temporária não encontrada.")
			return
		}
		if err != nil {
			s.fail(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
