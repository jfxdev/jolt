package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/jfxdev/jolt/control/internal/signedauth"
	"github.com/jfxdev/jolt/control/internal/store"
)

// A delete or move of a directory tree changes many entries at once, so with
// signed local jobs enabled it needs a plan the operator confirms. The node
// inspects the tree; the confirmation consumes a one-use token and creates a
// job that runs under a renewed authorization and revalidates the tree.

func nodeAPIErrorResponse(w http.ResponseWriter, r *http.Request, err error) bool {
	var apiErr *nodeAPIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode < 400 || apiErr.StatusCode > 599 {
		return false
	}
	code := apiErr.Code
	if code == "" {
		code = "node_rejected"
	}
	writeError(w, r, apiErr.StatusCode, code, apiErr.Error())
	return true
}

// nodeHasCapabilities checks the node confirms every named capability.
func (s *Server) nodeHasCapabilities(r *http.Request, node store.Node, required ...string) bool {
	var info struct {
		NodeID       string   `json:"node_id"`
		Capabilities []string `json:"capabilities"`
	}
	if err := s.callNodeJSON(r.Context(), node, http.MethodGet, "/api/v1/node", nil, &info, r.Header.Get("X-Correlation-ID")); err != nil || info.NodeID != node.ID {
		return false
	}
	for _, name := range required {
		found := false
		for _, capability := range info.Capabilities {
			found = found || capability == name
		}
		if !found {
			return false
		}
	}
	return true
}

// authorizeDestructive applies the same permission checks as the direct delete
// and move routes, including the refusal when a deny rule sits inside the tree.
func (s *Server) authorizeDestructive(w http.ResponseWriter, r *http.Request, nodeID, mountID, operation, source, destination string, overwrite bool) bool {
	resource, method := "mounts/"+mountID+"/files", http.MethodDelete
	targets := fileTargets{Paths: []string{source}}
	if operation == "move" {
		resource, method = resource+"/move", http.MethodPost
		targets = fileTargets{Source: source, Destination: destination, Overwrite: overwrite}
		if overwrite {
			targets.ConflictPolicy = "overwrite"
		}
	}
	requirements := nodeAuthorizationRequirements(nodeID, resource, method, targets)
	if len(requirements) == 0 {
		writeError(w, r, http.StatusBadRequest, "invalid_path", "Caminho inválido.")
		return false
	}
	for _, requirement := range requirements {
		if !s.authorize(w, r, requirement.Path, requirement.Capability, "permission_denied", "A policy atual não permite esta operação no node.") {
			return false
		}
		if strings.Contains(requirement.Path, "/files/mounts/") && !s.authorizeTreeContents(w, r, requirement.Path) {
			return false
		}
	}
	return true
}

func (s *Server) destructiveRouteNode(w http.ResponseWriter, r *http.Request) (store.Node, bool) {
	if r.Context().Value(agentKey) != nil {
		writeError(w, r, http.StatusForbidden, "permission_denied", "Agentes não podem alterar arquivos.")
		return store.Node{}, false
	}
	nodeID := r.PathValue("nodeID")
	if !validPathIdentifier(nodeID) || !validPathIdentifier(r.PathValue("mountID")) {
		writeError(w, r, http.StatusBadRequest, "invalid_path", "Caminho inválido.")
		return store.Node{}, false
	}
	node, err := s.store.GetNode(r.Context(), nodeID)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "node_not_found", "Node não encontrado.")
		return store.Node{}, false
	}
	return node, true
}

func readStrictBody(w http.ResponseWriter, r *http.Request, target any) bool {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024+1))
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err != nil || len(body) > 64*1024 || decoder.Decode(target) != nil || decoder.Decode(new(any)) != io.EOF {
		writeError(w, r, http.StatusBadRequest, "invalid_json", "A solicitação não é um JSON válido.")
		return false
	}
	return true
}

// createDestructivePlanRoute authorizes the operation, then asks the node to
// inspect the tree and record a plan for the current actor.
func (s *Server) createDestructivePlanRoute(w http.ResponseWriter, r *http.Request) {
	node, ok := s.destructiveRouteNode(w, r)
	if !ok {
		return
	}
	mountID := r.PathValue("mountID")
	var request struct {
		Operation       string `json:"operation"`
		SourcePath      string `json:"source_path"`
		DestinationPath string `json:"destination_path"`
		Overwrite       bool   `json:"overwrite"`
	}
	if !readStrictBody(w, r, &request) {
		return
	}
	if request.Operation != "delete" && request.Operation != "move" {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "A operação deve ser delete ou move.")
		return
	}
	if !s.authorizeDestructive(w, r, node.ID, mountID, request.Operation, request.SourcePath, request.DestinationPath, request.Overwrite) {
		return
	}
	if !s.nodeHasCapabilities(r, node, "destructive_plans_v1", "signed_local_copy_execution_v1") {
		writeError(w, r, http.StatusConflict, "node_upgrade_required", "Atualize o node para usar planos de operações destrutivas.")
		return
	}
	actor := currentUser(r)
	payload := map[string]any{"subject_type": currentActorType(r), "subject_id": actor.ID, "operation": request.Operation, "source_path": request.SourcePath, "destination_path": request.DestinationPath, "overwrite": request.Overwrite}
	var plan json.RawMessage
	if err := s.callNodeJSON(r.Context(), node, http.MethodPost, "/api/v1/mounts/"+url.PathEscape(mountID)+"/files/destructive-plans", payload, &plan, r.Header.Get("X-Correlation-ID")); err != nil {
		if !nodeAPIErrorResponse(w, r, err) {
			writeError(w, r, http.StatusBadGateway, "node_unavailable", "O node está indisponível.")
		}
		return
	}
	s.audit(r, "plan_"+request.Operation, "nodes/"+node.ID+"/mounts/"+mountID+"/"+request.SourcePath, "allowed")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(plan)
}

// confirmDestructivePlanRoute consumes the confirmation token, binds the
// resulting job to the caller's authorization and delivers its first lease.
// The permission checks run when the lease is issued: if the caller lost
// access since the plan, the job is canceled instead of left waiting.
func (s *Server) confirmDestructivePlanRoute(w http.ResponseWriter, r *http.Request) {
	node, ok := s.destructiveRouteNode(w, r)
	if !ok {
		return
	}
	mountID, planID := r.PathValue("mountID"), r.PathValue("planID")
	idempotency := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if !validPathIdentifier(planID) || !signedauth.ValidKeyID(idempotency) {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "Informe o plano e uma chave de idempotência válida.")
		return
	}
	var request struct {
		Token string `json:"token"`
	}
	if !readStrictBody(w, r, &request) {
		return
	}
	if request.Token == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "Informe o token do plano.")
		return
	}
	if !s.nodeHasCapabilities(r, node, "destructive_plans_v1", "signed_local_copy_execution_v1", "signed_job_authorization_registration_v1", "signed_job_options_binding_v1") {
		writeError(w, r, http.StatusConflict, "node_upgrade_required", "Atualize o node para usar planos de operações destrutivas.")
		return
	}
	actor := currentUser(r)
	body, err := json.Marshal(map[string]any{"subject_type": currentActorType(r), "subject_id": actor.ID, "token": request.Token})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	response, err := s.signedCopyNodeRequest(r, node, "/api/v1/mounts/"+url.PathEscape(mountID)+"/files/destructive-plans/"+url.PathEscape(planID)+"/accept", body, "", idempotency)
	if err != nil {
		writeError(w, r, http.StatusBadGateway, "node_unavailable", "O node está indisponível.")
		return
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(data) > 64*1024 {
		writeError(w, r, http.StatusBadGateway, "node_unavailable", "Resposta inválida do node.")
		return
	}
	if response.StatusCode != http.StatusAccepted && response.StatusCode != http.StatusOK {
		var payload struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(data, &payload)
		if response.StatusCode >= 400 && response.StatusCode <= 599 && payload.Error.Code != "" {
			writeError(w, r, response.StatusCode, payload.Error.Code, payload.Error.Message)
			return
		}
		writeError(w, r, http.StatusBadGateway, "node_unavailable", "Resposta inválida do node.")
		return
	}
	var job signedLocalJob
	if err := json.Unmarshal(data, &job); err != nil || !validPathIdentifier(job.ID) || (job.Type != "delete" && job.Type != "move_local") || job.MountID != mountID {
		writeError(w, r, http.StatusBadGateway, "node_unavailable", "Resposta inválida do node.")
		return
	}
	if _, err := s.store.GetJobAuthorizationLink(r.Context(), node.ID, job.ID); errors.Is(err, store.ErrNotFound) {
		if err := s.bindSignedLocalJob(r, node.ID, job.ID); err != nil {
			// The plan is consumed; do not leave the job waiting for a lease
			// that the caller's current permissions would never earn.
			if cancel, cancelErr := s.signedCopyNodeRequest(r, node, "/api/v1/jobs/"+url.PathEscape(job.ID)+"/cancel", nil, "", ""); cancelErr == nil {
				_, _ = io.Copy(io.Discard, cancel.Body)
				cancel.Body.Close()
			}
			s.audit(r, "confirm_"+strings.TrimSuffix(job.Type, "_local"), "nodes/"+node.ID+"/jobs/"+job.ID, "denied")
			writeError(w, r, http.StatusForbidden, "permission_denied", "A policy atual não permite esta operação. O plano foi descartado.")
			return
		}
	} else if err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "confirm_"+strings.TrimSuffix(job.Type, "_local"), "nodes/"+node.ID+"/jobs/"+job.ID, "allowed")
	// Deliver the first lease now; a failure is retried by the renewal loop.
	_, _ = s.renewSignedLocalJobLease(r.Context(), node.ID, job.ID)
	var current json.RawMessage
	if err := s.callNodeJSON(r.Context(), node, http.MethodGet, "/api/v1/jobs/"+url.PathEscape(job.ID), nil, &current, r.Header.Get("X-Correlation-ID")); err != nil {
		writeError(w, r, http.StatusBadGateway, "node_unavailable", "A operação foi confirmada, mas o estado do job não pôde ser lido.")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", "/api/v1/nodes/"+url.PathEscape(node.ID)+"/jobs/"+url.PathEscape(job.ID))
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write(current)
}

// refuseUnplannedTreeOperation stops a direct recursive delete or move of a
// directory, which must go through a plan. Files and empty-directory removal
// keep their direct routes. It reports whether it answered the request.
func (s *Server) refuseUnplannedTreeOperation(w http.ResponseWriter, r *http.Request, node store.Node, resource string, targets fileTargets) bool {
	segments := strings.Split(strings.Trim(resource, "/"), "/")
	source := ""
	switch {
	case r.Method == http.MethodDelete && len(segments) == 3 && segments[0] == "mounts" && segments[2] == "files" && r.URL.Query().Get("recursive") == "true":
		if len(targets.Paths) == 1 {
			source = targets.Paths[0]
		}
	case r.Method == http.MethodPost && len(segments) == 4 && segments[0] == "mounts" && segments[2] == "files" && segments[3] == "move":
		source = targets.Source
	}
	if source == "" {
		return false
	}
	var metadata struct {
		Type string `json:"type"`
	}
	path := "/api/v1/mounts/" + url.PathEscape(segments[1]) + "/files/metadata?path=" + url.QueryEscape(source)
	if err := s.callNodeJSON(r.Context(), node, http.MethodGet, path, nil, &metadata, r.Header.Get("X-Correlation-ID")); err != nil {
		var apiErr *nodeAPIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
			return false // the node answers a missing source itself
		}
		writeError(w, r, http.StatusBadGateway, "node_unavailable", "Não foi possível verificar o tipo do item no node.")
		return true
	}
	if metadata.Type != "directory" {
		return false
	}
	writeError(w, r, http.StatusConflict, "plan_required", "Excluir ou mover uma pasta exige um plano de operação destrutiva e a sua confirmação.")
	return true
}

// refuseUnplannedTransferMove stops a node-to-node move that would delete a
// directory on the source, which today has no plan to confirm. A copy followed
// by a planned delete achieves the same result. Moving files is unaffected.
// It reports whether it answered the request.
func (s *Server) refuseUnplannedTransferMove(w http.ResponseWriter, r *http.Request, sourceNode store.Node, mountID string, paths []string) bool {
	for _, source := range paths {
		var metadata struct {
			Type string `json:"type"`
		}
		path := "/api/v1/mounts/" + url.PathEscape(mountID) + "/files/metadata?path=" + url.QueryEscape(source)
		if err := s.callNodeJSON(r.Context(), sourceNode, http.MethodGet, path, nil, &metadata, r.Header.Get("X-Correlation-ID")); err != nil {
			var apiErr *nodeAPIError
			if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
				continue // the transfer reports a missing source itself
			}
			writeError(w, r, http.StatusBadGateway, "node_unavailable", "Não foi possível verificar o tipo dos itens no node de origem.")
			return true
		}
		if metadata.Type == "directory" {
			writeError(w, r, http.StatusConflict, "plan_required", "Mover uma pasta entre nodes apaga a origem e ainda não tem plano de confirmação. Copie a pasta e, depois, remova a origem com um plano.")
			return true
		}
	}
	return false
}
