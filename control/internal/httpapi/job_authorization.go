package httpapi

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/jfxdev/jolt/control/internal/store"
)

func jobActionNeedsRevalidation(resource, method string) bool {
	parts := strings.Split(strings.Trim(resource, "/"), "/")
	if method != http.MethodPost || len(parts) < 3 || parts[0] != "jobs" {
		return false
	}
	return len(parts) == 3 && (parts[2] == "resume" || parts[2] == "retry") ||
		len(parts) == 5 && parts[2] == "items" && parts[4] == "override"
}

// Recheck the acting user's current permissions against persisted job paths.
// Remote jobs cannot yet prove the creator's authorization at both nodes or
// during later resumptions, so they cannot be resumed through this interface.
func (s *Server) revalidateJobAction(w http.ResponseWriter, r *http.Request, node store.Node, resource string) bool {
	parts := strings.Split(strings.Trim(resource, "/"), "/")
	if !validPathIdentifier(parts[1]) {
		writeError(w, r, http.StatusBadRequest, "invalid_job", "Job inválido.")
		return false
	}
	var job struct {
		ID             string `json:"job_id"`
		Type           string `json:"type"`
		MountID        string `json:"mount_id"`
		Source         string `json:"source_path"`
		Destination    string `json:"destination_path"`
		ConflictPolicy string `json:"conflict_policy"`
		Overwrite      bool   `json:"overwrite"`
	}
	if err := s.callNodeJSON(r.Context(), node, http.MethodGet, "/api/v1/jobs/"+url.PathEscape(parts[1]), nil, &job, r.Header.Get("X-Correlation-ID")); err != nil {
		writeError(w, r, http.StatusBadGateway, "job_validation_unavailable", "Não foi possível validar as permissões atuais do job no node.")
		return false
	}
	if job.ID != parts[1] || !validPathIdentifier(job.MountID) {
		writeError(w, r, http.StatusConflict, "job_validation_unavailable", "O job não contém os dados necessários para validar suas permissões.")
		return false
	}
	base := "mounts/" + job.MountID + "/files"
	targets := fileTargets{Source: job.Source, Destination: job.Destination, ConflictPolicy: job.ConflictPolicy}
	if job.Overwrite && (job.Type == "move_local" || targets.ConflictPolicy == "") {
		targets.ConflictPolicy = "overwrite"
	}
	var requirements []authorizationRequirement
	switch job.Type {
	case "copy_local":
		// Overrides can persist overwrite and rename actions even when the
		// original conflict policy was fail or skip. The job metadata does not
		// expose a complete, stable view of those item actions, and an override
		// can apply to following items. Require the enclosing destination scope
		// and update on every resume, retry and override until renewable job
		// authorization can validate all persisted items at execution time.
		targets.ConflictPolicy = "ask"
		requirements = nodeAuthorizationRequirements(node.ID, base+"/copy", http.MethodPost, targets)
	case "move_local":
		requirements = nodeAuthorizationRequirements(node.ID, base+"/move", http.MethodPost, targets)
	case "delete":
		requirements = nodeAuthorizationRequirements(node.ID, base, http.MethodDelete, fileTargets{Paths: []string{job.Source}})
	case "mkdir", "upload":
		requirements = nodeAuthorizationRequirements(node.ID, base, http.MethodPut, fileTargets{Paths: []string{job.Destination}})
		if job.Overwrite {
			scope := fileScope("nodes/"+node.ID+"/files/mounts/"+job.MountID, job.Destination)
			requirements = append(requirements, authorizationRequirement{Path: scope, Capability: "update"})
		}
	default:
		writeError(w, r, http.StatusConflict, "job_authorization_upgrade_required", "Este job exige autorização verificável entre nodes; atualize os nodes e aguarde o suporte a essa operação.")
		return false
	}
	if len(requirements) == 0 {
		writeError(w, r, http.StatusConflict, "job_validation_unavailable", "O job contém caminhos inválidos.")
		return false
	}
	for _, requirement := range requirements {
		// The job action itself was authorized before loading its metadata.
		if requirement.Path == "nodes/"+node.ID+"/jobs" {
			continue
		}
		if !s.authorizeFileTree(w, r, requirement.Path, requirement.Capability) {
			return false
		}
	}
	return true
}
