package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/jfxdev/jolt/control/internal/store"
)

func (s *Server) listWorkloadIdentities(w http.ResponseWriter, r *http.Request) {
	accountID := strings.TrimSpace(r.PathValue("serviceAccountID"))
	resource := "control-tower/service-accounts/" + accountID + "/workload-identities"
	if !s.requireAdmin(w, r, "list", resource) {
		return
	}
	items, err := s.store.ListWorkloadIdentities(r.Context(), accountID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "service_account_not_found", "Conta de serviço não encontrada.")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) createWorkloadIdentity(w http.ResponseWriter, r *http.Request) {
	accountID := strings.TrimSpace(r.PathValue("serviceAccountID"))
	resource := "control-tower/service-accounts/" + accountID + "/workload-identities"
	if !s.requireAdmin(w, r, "create", resource) {
		return
	}
	var input struct {
		ProviderID  string             `json:"provider_id"`
		Issuer      string             `json:"issuer"`
		Subject     string             `json:"subject"`
		Audience    string             `json:"audience"`
		AgentLimits *store.AgentLimits `json:"agent_limits"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if s.config.WorkloadProviders == nil || !s.config.WorkloadProviders.AllowsMapping(input.ProviderID, input.Issuer, input.Subject, input.Audience) {
		writeError(w, r, http.StatusBadRequest, "invalid_workload_mapping", "O mapeamento não corresponde a um provedor configurado.")
		return
	}
	account, err := s.store.GetServiceAccount(r.Context(), accountID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "service_account_not_found", "Conta de serviço não encontrada.")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if account.Kind == "agent" {
		limits, err := normalizeAgentLimits(input.AgentLimits)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_agent_settings", "Limites ou redes permitidas são inválidos.")
			return
		}
		input.AgentLimits = &limits
	} else if input.AgentLimits != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_agent_settings", "Limites de agente exigem uma conta de agente.")
		return
	}
	identity := store.WorkloadIdentity{CredentialID: randomID("wid"), ServiceAccountID: accountID, ProviderID: input.ProviderID, Issuer: input.Issuer, Subject: input.Subject, Audience: input.Audience}
	err = s.store.CreateWorkloadIdentity(r.Context(), identity, input.AgentLimits, currentUser(r).ID, currentActorType(r), r.Header.Get("X-Correlation-ID"))
	if errors.Is(err, store.ErrConflict) {
		writeError(w, r, http.StatusConflict, "workload_mapping_conflict", "O mapeamento já existe ou a conta está desativada.")
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "service_account_not_found", "Conta de serviço não encontrada.")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	identity, err = s.store.GetWorkloadIdentity(r.Context(), accountID, identity.CredentialID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, identity)
}

func (s *Server) updateWorkloadIdentity(w http.ResponseWriter, r *http.Request) {
	accountID, id := strings.TrimSpace(r.PathValue("serviceAccountID")), strings.TrimSpace(r.PathValue("credentialID"))
	resource := "control-tower/service-accounts/" + accountID + "/workload-identities/" + id
	if !s.requireAdmin(w, r, "update", resource) {
		return
	}
	var input struct {
		Enabled *bool `json:"enabled"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.Enabled == nil {
		writeError(w, r, http.StatusBadRequest, "invalid_workload_mapping", "Informe se o mapeamento está ativo.")
		return
	}
	s.agentMu.Lock()
	identity, err := s.store.GetWorkloadIdentity(r.Context(), accountID, id)
	if errors.Is(err, store.ErrNotFound) {
		s.agentMu.Unlock()
		writeError(w, r, http.StatusNotFound, "workload_mapping_not_found", "Mapeamento não encontrado.")
		return
	}
	if err != nil {
		s.agentMu.Unlock()
		s.fail(w, r, err)
		return
	}
	if *input.Enabled && (identity.Revoked || s.config.WorkloadProviders == nil || !s.config.WorkloadProviders.AllowsMapping(identity.ProviderID, identity.Issuer, identity.Subject, identity.Audience)) {
		s.agentMu.Unlock()
		writeError(w, r, http.StatusConflict, "workload_mapping_unavailable", "O mapeamento foi revogado ou seu provedor não está configurado.")
		return
	}
	err = s.store.SetWorkloadIdentityEnabled(r.Context(), accountID, id, *input.Enabled, currentUser(r).ID, currentActorType(r), r.Header.Get("X-Correlation-ID"))
	if err == nil && !*input.Enabled {
		s.cancelAgentLocked(accountID, id)
	}
	s.agentMu.Unlock()
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "workload_mapping_not_found", "Mapeamento não encontrado.")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
