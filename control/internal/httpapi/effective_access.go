package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/jfxdev/jolt/control/internal/rbac"
	"github.com/jfxdev/jolt/control/internal/store"
)

const maxEffectiveAccessChecks = 50

var effectiveCapabilities = []string{"read", "list", "create", "update", "delete", "write", "execute", "sudo"}

type effectiveAccessRequest struct {
	Checks []effectiveAccessCheck `json:"checks"`
}

type effectiveAccessCheck struct {
	Path string `json:"path"`
	// EntryType is what the node would find at the path. Typed rules treat
	// files and directories differently, so the answer is only exact for a
	// known type.
	EntryType string `json:"entry_type"`
}

type effectiveCapability struct {
	Allowed bool `json:"allowed"`
	Denied  bool `json:"denied"`
	// Outcome is allowed, denied (no grant or a path denial), hidden (a typed
	// rule makes the entry disappear) or blocked (shown but unusable).
	Outcome   string   `json:"outcome"`
	PolicyIDs []string `json:"policy_ids"`
	Typed     bool     `json:"typed"`
}

type effectiveAccessResult struct {
	Path         string                         `json:"path"`
	EntryType    string                         `json:"entry_type"`
	Capabilities map[string]effectiveCapability `json:"capabilities"`
	// Reason explains a result that does not come from policy rules.
	Reason string `json:"reason,omitempty"`
}

// effectiveAccess answers what an identity can do at concrete paths, with the
// evaluator the Control Tower and the node use for real requests. It is a
// read-only diagnostic for administrators who manage policies.
func (s *Server) effectiveAccess(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, "list", "control-tower/policies") {
		return
	}
	actorType, subjectID := r.PathValue("actorType"), r.PathValue("subjectID")
	var input effectiveAccessRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	if len(input.Checks) == 0 || len(input.Checks) > maxEffectiveAccessChecks {
		writeError(w, r, http.StatusBadRequest, "invalid_checks", "Informe entre 1 e 50 caminhos.")
		return
	}
	checks := make([]effectiveAccessCheck, 0, len(input.Checks))
	for _, check := range input.Checks {
		path := rbac.NormalizePath(check.Path)
		if !rbac.ValidResourcePath(path) {
			writeError(w, r, http.StatusBadRequest, "invalid_path", "Um dos Node Paths é inválido.")
			return
		}
		if check.EntryType != "file" && check.EntryType != "directory" {
			writeError(w, r, http.StatusBadRequest, "invalid_entry_type", "O tipo da entrada deve ser file ou directory.")
			return
		}
		checks = append(checks, effectiveAccessCheck{Path: path, EntryType: check.EntryType})
	}

	subject := map[string]any{"actor_type": actorType, "id": subjectID}
	builtinAdmin, enabled := false, true
	var groupIDs []string
	switch actorType {
	case "user":
		user, err := s.store.GetUser(r.Context(), subjectID)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "subject_not_found", "Identidade não encontrada.")
			return
		}
		if err != nil {
			s.fail(w, r, err)
			return
		}
		subject["name"], subject["role"] = user.Username, user.Role
		builtinAdmin, enabled = user.Role == "admin", user.Enabled
	case "service_account":
		account, err := s.store.GetServiceAccount(r.Context(), subjectID)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "subject_not_found", "Identidade não encontrada.")
			return
		}
		if err != nil {
			s.fail(w, r, err)
			return
		}
		subject["name"] = account.Name
		enabled = account.Enabled
		if groupIDs, err = s.store.ServiceAccountGroupIDs(r.Context(), account.ID, true); err != nil {
			s.fail(w, r, err)
			return
		}
	default:
		writeError(w, r, http.StatusBadRequest, "invalid_actor_type", "O tipo de identidade deve ser user ou service_account.")
		return
	}
	subject["enabled"] = enabled

	policies, err := s.store.RBACPoliciesForSubject(r.Context(), actorType, subjectID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	policies = rbac.ExpandCompatibilityRules(policies)

	notes := []string{}
	if !enabled {
		notes = append(notes, "A identidade está desativada: nenhuma requisição dela é aceita, qualquer que seja o resultado abaixo.")
	}
	if builtinAdmin {
		notes = append(notes, "Administrador de fato: a role admin permite tudo, sem depender de policies.")
	}
	if actorType == "service_account" {
		notes = append(notes, "O teto de capabilities de cada credencial de agente e os filtros de CIDR não entram nesta consulta.")
	}
	if !s.config.TypedPolicies && hasTypedRules(policies) {
		notes = append(notes, "Políticas por tipo estão desativadas neste Control Tower: regras tipadas valem como regras por caminho, e uma negação tipada nega tudo no caminho.")
	}

	results := make([]effectiveAccessResult, 0, len(checks))
	for _, check := range checks {
		result := effectiveAccessResult{Path: check.Path, EntryType: check.EntryType, Capabilities: make(map[string]effectiveCapability, len(effectiveCapabilities))}
		outside := false
		if actorType == "service_account" {
			if segments := strings.Split(check.Path, "/"); len(segments) >= 2 && segments[0] == "nodes" {
				member := false
				for _, groupID := range groupIDs {
					in, err := s.store.NodeInAccessGroup(r.Context(), groupID, segments[1])
					if err != nil {
						s.fail(w, r, err)
						return
					}
					member = member || in
				}
				outside = !member
			}
		}
		if outside {
			result.Reason = "node_not_in_group"
		}
		for _, capability := range effectiveCapabilities {
			switch {
			case builtinAdmin:
				result.Capabilities[capability] = effectiveCapability{Allowed: true, Outcome: "allowed", PolicyIDs: []string{"builtin-admin"}}
			case outside:
				result.Capabilities[capability] = effectiveCapability{Outcome: "denied", PolicyIDs: []string{}}
			default:
				result.Capabilities[capability] = s.effectiveCapability(policies, check, capability)
			}
		}
		results = append(results, result)
	}
	s.audit(r, "effective_access", "subjects/"+actorType+"/"+subjectID, "allowed")
	writeJSON(w, http.StatusOK, map[string]any{
		"subject":        subject,
		"typed_policies": s.config.TypedPolicies,
		"notes":          notes,
		"results":        results,
	})
}

func (s *Server) effectiveCapability(policies []rbac.Policy, check effectiveAccessCheck, capability string) effectiveCapability {
	var decision rbac.EntryDecision
	if s.config.TypedPolicies {
		decision = rbac.EvaluateEntry(policies, check.Path, capability, check.EntryType)
	} else {
		decision = rbac.EntryDecision{Decision: rbac.Evaluate(policies, check.Path, capability)}
	}
	ids := decision.PolicyIDs
	if ids == nil {
		ids = []string{}
	}
	outcome := "allowed"
	switch {
	case decision.Allowed:
	case decision.Visibility == "hidden":
		outcome = "hidden"
	case decision.Visibility == "visible":
		outcome = "blocked"
	default:
		outcome = "denied"
	}
	return effectiveCapability{Allowed: decision.Allowed, Denied: decision.Denied, Outcome: outcome, PolicyIDs: ids, Typed: decision.Typed}
}

func hasTypedRules(policies []rbac.Policy) bool {
	for _, policy := range policies {
		for _, rule := range policy.Rules {
			if rule.FileTypes != nil || rule.Visibility != "" {
				return true
			}
		}
	}
	return false
}
